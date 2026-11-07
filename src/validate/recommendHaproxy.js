'use strict';
/**
 * Version-aware recommendations for a HAProxy configuration.
 * Each rule only fires when the recommended feature exists in the target version (checked against the KB),
 * and the advice changes with the version (e.g. `ssl-min-ver` on 1.8+, `no-tlsv10` before).
 * Finding ids are prefixed `rec-`; category is always "recommendation".
 */
const IPISH = /^(\*|\[?[0-9a-f:.]+\]?|localhost|(?:ip[46]|ipv[46])@.*|unix@.*|abns@.*|fd@.*|\$\{.*\}|["']?\$.*)$/i;

function recommendHaproxy({ sections, target, add, kb, V }) {
  const has = (table, name) => kb[table] && kb[table][name] && V.gte(target, kb[table][name].s) && !(kb[table][name].r && V.lt(kb[table][name].r, target));
  const rec = (f) => add({ category: 'recommendation', severity: 'info', ...f });
  const items = (type, kw) => sections.filter((s) => !type || s.type === type || (Array.isArray(type) && type.includes(s.type)))
    .flatMap((s) => s.items.filter((i) => !kw || i.kw === kw).map((i) => ({ ...i, sec: s })));
  const globalItems = (kw) => items('global', kw);
  const proxies = sections.filter((s) => ['frontend', 'backend', 'listen', 'defaults'].includes(s.type));
  const modeOf = (s) => {
    const own = s.items.find((i) => i.kw === 'mode'); if (own) return own.args[0];
    const defs = sections.filter((x) => x.type === 'defaults' && x.line < s.line).pop();
    const d = defs && defs.items.find((i) => i.kw === 'mode'); return d ? d.args[0] : 'tcp';
  };
  const defaultsHas = (s, pred) => { const d = sections.filter((x) => x.type === 'defaults' && x.line < s.line).pop(); return !!(d && d.items.some(pred)); };

  // ---- TLS ---------------------------------------------------------------------------------------------------
  for (const b of items(['frontend', 'listen'], 'bind')) {
    if (!b.args.includes('ssl') || modeOf(b.sec) === 'tcp' && false) continue;
    // 1. HTTP/2 + ALPN
    if (!b.args.includes('alpn') && modeOf(b.sec) === 'http' && has('bind', 'alpn')) {
      rec({ id: 'rec-alpn-h2', title: `Enable HTTP/2 on ${b.sec.name}: add "alpn h2,http/1.1"`, detail: `This TLS listener does not negotiate ALPN, so browsers fall back to HTTP/1.1. HAProxy ${target} supports HTTP/2 on bind lines with ALPN.`, fix: 'bind ... ssl crt <file> alpn h2,http/1.1', section: b.sec.name, line: b.line, category: 'performance' });
    }
    // 2. ciphers
    const ci = b.args.indexOf('ciphers');
    if (ci >= 0 && /(RC4|3DES|DES-CBC|MD5|EXPORT|NULL|aNULL|eNULL|ADH)/i.test(b.args[ci + 1] || '') && !/!(RC4|3DES|MD5|aNULL)/i.test(b.args[ci + 1] || '')) {
      rec({ id: 'rec-weak-ciphers', severity: 'warning', category: 'security', title: 'Weak cipher families enabled on a bind line', detail: 'RC4, 3DES, MD5, EXPORT and NULL ciphers are broken or deprecated (RFC 7465 / SWEET32).', fix: 'Use a modern list, e.g. ECDHE+AESGCM:ECDHE+CHACHA20, and `ciphersuites` for TLS 1.3.', section: b.sec.name, line: b.line });
    }
  }
  for (const g of [...globalItems('ssl-default-bind-ciphers'), ...globalItems('ssl-default-server-ciphers')]) {
    if (/(RC4|3DES|DES-CBC|MD5|EXPORT|NULL|aNULL|eNULL|ADH)/i.test(g.args[0] || '') && !/!(RC4|3DES|MD5|aNULL)/i.test(g.args[0] || '')) {
      rec({ id: 'rec-weak-ciphers', severity: 'warning', category: 'security', title: `Weak cipher families in ${g.kw}`, detail: 'RC4, 3DES, MD5, EXPORT and NULL ciphers are broken or deprecated.', fix: 'Use ECDHE+AESGCM:ECDHE+CHACHA20 and set `ssl-default-bind-ciphersuites` for TLS 1.3.', section: 'global', line: g.line });
    }
  }
  for (const g of globalItems('tune.ssl.default-dh-param')) {
    const n = Number(g.args[0]);
    if (n && n < 2048) rec({ id: 'rec-dh-param', severity: 'warning', category: 'security', title: `tune.ssl.default-dh-param ${n} is too small`, detail: 'DH parameters below 2048 bits are considered weak (Logjam).', fix: 'Set `tune.ssl.default-dh-param 2048` or better, or prefer ECDHE-only ciphers.', section: 'global', line: g.line });
  }
  for (const g of globalItems('ssl-server-verify')) {
    if (g.args[0] === 'none') rec({ id: 'rec-ssl-verify-none', severity: 'warning', category: 'security', title: 'Server certificate verification disabled globally', detail: '`ssl-server-verify none` makes every TLS connection to servers vulnerable to man-in-the-middle attacks.', fix: 'Remove it, set `ca-file` on servers, or use `verify required ca-file ...`.', section: 'global', line: g.line });
  }
  for (const s of items(['backend', 'listen', 'defaults'], 'server').concat(items(['backend', 'listen', 'defaults'], 'default-server'))) {
    const i = s.args.indexOf('verify');
    if (s.args.includes('ssl') && i >= 0 && s.args[i + 1] === 'none') rec({ id: 'rec-ssl-verify-none', severity: 'warning', category: 'security', title: `Server "${s.args[0]}" uses TLS without certificate verification`, detail: '`verify none` accepts any certificate, so the connection is encrypted but not authenticated.', fix: 'Use `verify required ca-file <file>` (plus `verifyhost` / `sni`).', section: s.sec.name, line: s.line });
  }

  // ---- process model ----------------------------------------------------------------------------------------
  for (const g of globalItems('nbproc')) {
    if (has('global', 'nbthread')) rec({ id: 'rec-nbproc', severity: 'warning', category: 'performance', title: 'nbproc starts separate processes; prefer threads', detail: 'Each process has its own stick-tables, stats, health checks and rate limits. Threads share all of them and are the supported model.', fix: 'Replace `nbproc N` with `nbthread N` (and `thread-groups` on 2.7+ for large NUMA machines).', section: 'global', line: g.line });
  }
  if (has('global', 'cpu-policy') && (globalItems('nbthread').length || globalItems('cpu-map').length)) {
    const g = globalItems('cpu-map')[0] || globalItems('nbthread')[0];
    rec({ id: 'rec-cpu-policy', title: 'Let HAProxy pick the CPU topology with cpu-policy', detail: `HAProxy ${target} can group threads by CPU cluster/core automatically, so hand-written cpu-map / nbthread lines usually become unnecessary.`, fix: 'Set `cpu-policy performance` (or `efficiency`) and drop manual `cpu-map` / `nbthread`.', section: 'global', line: g.line, category: 'performance' });
  }
  if (!globalItems('user').length && !globalItems('uid').length && !globalItems('chroot').length) {
    const g = sections.find((s) => s.type === 'global');
    if (g) rec({ id: 'rec-drop-privileges', category: 'security', title: 'HAProxy is not configured to drop privileges', detail: 'Without `user`/`group` (and ideally `chroot`) it keeps the privileges of the account that starts it. Container images that already run as non-root can ignore this.', fix: 'Add `user haproxy`, `group haproxy` and, on bare metal, `chroot /var/empty` in the global section.', section: 'global', line: g.line });
  }
  for (const g of globalItems('stats')) {
    if (g.args[0] !== 'socket') continue;
    const addr = g.args[1] || '';
    if (!addr.startsWith('/') && !/^(unix|abns|fd|sockpair)@/.test(addr) && !/^(ip4@|ipv4@)?127\.0\.0\.1/.test(addr)) {
      rec({ id: 'rec-stats-socket-network', severity: 'warning', category: 'security', title: 'Runtime API socket is reachable over the network', detail: `\`stats socket ${addr}\` exposes the HAProxy runtime API (including admin commands when level admin is set) on a TCP address.`, fix: 'Use a UNIX socket with `mode 600`, or bind to 127.0.0.1 only and keep `level user` unless an admin is required.', section: 'global', line: g.line });
    } else if (addr.startsWith('/') && !g.args.includes('mode') && !g.args.includes('user') && !g.args.includes('group')) {
      rec({ id: 'rec-stats-socket-mode', title: 'Runtime API socket has no explicit permissions', detail: 'The socket inherits the process umask; other local users may be able to talk to it.', fix: 'Add `mode 660 user haproxy group haproxy` (or `mode 600`).', section: 'global', line: g.line, category: 'security' });
    }
  }

  // ---- HTTP behaviour -----------------------------------------------------------------------------------------
  for (const o of items(['frontend', 'backend', 'listen', 'defaults'], 'option')) {
    if (o.args[0] === 'httpchk') {
      const joined = o.args.join(' ');
      if (has('proxy', 'http-check send') && (/HTTP\/1\.[01]/i.test(joined) || /\\r\\n/.test(joined))) {
        rec({ id: 'rec-httpchk-style', title: 'Express the HTTP health check with http-check send', detail: `The inline "option httpchk <method> <uri> <version>\\r\\nHeader: ..." form is fragile. HAProxy ${target} has structured health-check rules.`, fix: 'option httpchk\n  http-check send meth GET uri /health ver HTTP/1.1 hdr Host example.com\n  http-check expect status 200', section: o.sec.name, line: o.line, category: 'hygiene' });
      }
      const sec = o.sec;
      const hasExpect = sec.items.some((i) => i.kw === 'http-check' && i.args[0] === 'expect') || defaultsHas(sec, (i) => i.kw === 'http-check' && i.args[0] === 'expect');
      if (!hasExpect && has('proxy', 'http-check expect')) {
        rec({ id: 'rec-httpchk-expect', title: `Health check in "${sec.name}" accepts any 2xx/3xx answer`, detail: 'Without `http-check expect`, a redirect or a generic error page served with 200 keeps the server in rotation.', fix: 'Add `http-check expect status 200` (or `rstring` for a body match).', section: sec.name, line: o.line, category: 'reliability' });
      }
    }
    if (o.args[0] === 'httpclose' || o.args[0] === 'forceclose') {
      rec({ id: 'rec-keepalive', severity: 'warning', category: 'performance', title: `option ${o.args[0]} disables HTTP keep-alive`, detail: 'Every request pays a new TCP (and TLS) handshake towards the client, which is slow and CPU hungry.', fix: 'Remove it, or use `option http-server-close` if you need per-request balancing.', section: o.sec.name, line: o.line });
    }
  }
  for (const s of items(['backend', 'listen', 'defaults'], 'server')) {
    const host = (s.args[1] || '').replace(/^(?:ipv?[46]@)/, '').replace(/:\d*$/, '').replace(/^\[|\]$/g, '');
    if (host && !IPISH.test(host) && !host.includes('${') && has('server', 'resolvers')) {
      const withRes = s.args.includes('resolvers') || s.args.includes('init-addr');
      const dflt = s.sec.items.some((i) => i.kw === 'default-server' && (i.args.includes('resolvers') || i.args.includes('init-addr')));
      if (!withRes && !dflt) {
        rec({ id: 'rec-dns-resolvers', category: 'reliability', title: `Server "${s.args[0]}" uses a hostname without a resolvers section`, detail: 'The name is resolved once at startup. If DNS is down HAProxy fails to start (or keeps a stale address) and never follows DNS changes.', fix: 'Define a `resolvers` section and add `resolvers <name> init-addr last,libc,none check` to the server (or default-server).', section: s.sec.name, line: s.line });
      }
    }
  }
  // security headers
  const sslFes = sections.filter((s) => ['frontend', 'listen'].includes(s.type) && s.items.some((i) => i.kw === 'bind' && i.args.includes('ssl')));
  for (const fe of sslFes) {
    if (modeOf(fe) !== 'http') continue;
    const hasHsts = (list) => list.some((i) => /^(http-response|http-after-response)$/.test(i.kw) && /set-header|add-header/.test(i.args[0] || '') && /strict-transport-security/i.test(i.args.join(' ')));
    if (!hasHsts(fe.items) && !sections.some((d) => d.type === 'defaults' && hasHsts(d.items))) {
      const after = has('proxy', 'http-after-response');
      rec({ id: 'rec-hsts', title: `Frontend "${fe.name}" serves HTTPS without HSTS`, detail: 'Browsers keep trying plain HTTP first without Strict-Transport-Security, which allows downgrade attacks on the first request.', fix: after ? 'http-after-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"   # applies to errors and redirects too' : 'http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"', section: fe.name, line: fe.line, category: 'security' });
    }
  }
  // forwarding the client address
  const noFwd = sections.filter((s) => ['backend', 'listen'].includes(s.type) && modeOf(s) === 'http' && s.items.some((i) => i.kw === 'server') && !s.items.some((i) => (i.kw === 'option' && /^forward(ed|for)$/.test(i.args[0])) || (i.kw === 'http-request' && /X-Forwarded-For|Forwarded/i.test(i.args.join(' ')))) && !sections.some((d) => d.type === 'defaults' && d.items.some((i) => i.kw === 'option' && /^forward(ed|for)$/.test(i.args[0]))));
  if (noFwd.length) {
    const first = noFwd[0];
    rec({ id: 'rec-forwardfor', title: `${noFwd.length} HTTP ${noFwd.length === 1 ? 'backend does' : 'backends do'} not pass the client address on`, detail: `Servers behind "${first.name}"${noFwd.length > 1 ? ` (and ${noFwd.length - 1} more)` : ''} only see HAProxy's IP. Logs, rate limits and geo rules downstream lose the real client.`, fix: has('proxy', 'option forwarded') ? 'option forwarded          # RFC 7239 "Forwarded" header\noption forwardfor         # classic X-Forwarded-For' : 'option forwardfor', section: first.name, line: first.line, category: 'hygiene' });
  }
  // logging
  const anyLog = sections.some((s) => s.items.some((i) => i.kw === 'log'));
  if (sections.length && !anyLog) {
    rec({ id: 'rec-logging', category: 'reliability', title: 'No logging is configured', detail: 'Without a `log` target HAProxy writes no access or error logs, which makes outages and attacks hard to investigate.', fix: 'global: `log stdout format raw local0` (containers) or `log /dev/log local0`; frontends: `option httplog`.', section: 'global', line: (sections.find((s) => s.type === 'global') || sections[0]).line });
  }
}

module.exports = { recommendHaproxy };

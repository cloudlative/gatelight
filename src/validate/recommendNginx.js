'use strict';
/**
 * Version-aware recommendations for an NGINX configuration (ids prefixed `rec-nginx-`, category "recommendation").
 * Advice depends on the target version: e.g. upstream keep-alive needs explicit HTTP/1.1 before 1.29.7 but is the default after.
 */
const INHERIT_ARRAYS = ['add_header', 'proxy_set_header', 'proxy_hide_header', 'proxy_pass_header', 'fastcgi_param', 'uwsgi_param', 'scgi_param', 'grpc_set_header', 'fastcgi_hide_header'];
const SAFE_IN_IF = new Set(['return', 'rewrite', 'set', 'break', 'break;', 'last', 'access_log', 'error_page', 'add_header', 'proxy_pass_header', 'log_not_found', 'internal']);

function recommendNginx({ ast, target, add, V, kb }) {
  const rec = (f) => add({ category: 'recommendation', severity: 'info', ...f });
  const exists = (name) => kb.directives[name] && kb.directives[name].some((e) => !e.since || V.gte(target, e.since));

  // flat list with ancestor chains
  const all = [];
  (function flat(nodes, chain) {
    for (const n of nodes) {
      all.push({ node: n, chain });
      if (n.children) flat(n.children, [...chain, n]);
    }
  })(ast, []);
  const label = (chain) => { const b = chain.filter((c) => ['server', 'location', 'upstream'].includes(c.name)).pop(); return b ? `${b.name}${b.args && b.args[0] ? ` ${b.args[0]}` : ''}` : 'main'; };
  const at = (x) => ({ file: x.node.file, line: x.node.line, section: label(['server', 'location', 'upstream'].includes(x.node.name) ? [...x.chain, x.node] : x.chain) });
  const dirs = (name) => all.filter((x) => x.node.name === name);
  /** Effective value of a single-value directive: nearest enclosing block that sets it. */
  const effective = (chain, block, name) => {
    for (let i = chain.length; i >= 0; i--) {
      const holder = i === chain.length ? block : chain[i];
      const kids = (holder.children || []).filter((c) => c.name === name);
      if (kids.length) return kids;
    }
    return null;
  };

  // ---- 1. array-type directives are NOT inherited once an inner block defines one ---------------------------------
  const blocks = all.filter((x) => x.node.children && ['http', 'server', 'location', 'if', 'limit_except'].includes(x.node.name));
  for (const b of blocks) {
    for (const name of INHERIT_ARRAYS) {
      const mine = b.node.children.filter((c) => c.name === name);
      if (!mine.length) continue;
      const parent = [...b.chain].reverse().find((p) => p.children.some((c) => c.name === name));
      if (!parent) continue;
      const lost = parent.children.filter((c) => c.name === name);
      const names = [...new Set(lost.map((l) => (name === 'add_header' || name === 'proxy_set_header' ? l.args[0] : l.args[0])).filter(Boolean))].slice(0, 4);
      rec({ id: 'rec-nginx-inherit', severity: 'warning', category: 'correctness', title: `"${name}" in ${b.node.name}${b.node.args[0] ? ` ${b.node.args[0]}` : ''} hides ${lost.length} inherited ${name} line${lost.length > 1 ? 's' : ''}`, detail: `nginx inherits ${name} from the enclosing block only if the inner block defines none. Here ${parent.name} (line ${lost[0].line}) sets ${names.join(', ')}${lost.length > 4 ? ', …' : ''}, and they silently stop applying inside this block.`, fix: `Repeat those ${name} lines here, or move all of them into one include file used in both places.`, ...at({ node: mine[0], chain: [...b.chain, b.node] }) });
      break;
    }
  }

  // ---- 2. upstream keep-alive needs HTTP/1.1 before 1.29.7 ------------------------------------------------------------
  const keepalive = new Map();
  for (const u of all.filter((x) => x.node.name === 'upstream' && x.node.children)) {
    if (u.node.children.some((c) => c.name === 'keepalive')) keepalive.set(u.node.args[0], u.node);
  }
  if (V.lt(target, '1.29.7')) {
    for (const p of dirs('proxy_pass')) {
      const m = (p.node.args[0] || '').match(/^https?:\/\/([^/:$]+)/);
      if (!m || !keepalive.has(m[1])) continue;
      const holder = p.chain[p.chain.length - 1] || { children: [] };
      const ver = effective(p.chain.slice(0, -1), holder, 'proxy_http_version');
      const okVer = ver && ver[0].args[0] === '1.1';
      const hdrs = [];
      for (let i = p.chain.length - 1; i >= 0; i--) hdrs.push(...(p.chain[i].children || []).filter((c) => c.name === 'proxy_set_header' && /^connection$/i.test(c.args[0])));
      const clears = hdrs.some((h) => h.args[1] === '' || h.args[1] === 'close' ? h.args[1] === '' : true);
      if (!okVer) rec({ id: 'rec-nginx-keepalive-http11', severity: 'warning', category: 'performance', title: `Upstream "${m[1]}" has keepalive but requests are sent as HTTP/1.0`, detail: `Before nginx 1.29.7 proxy_http_version defaults to 1.0, which closes the connection after every request, so the "keepalive" pool in the upstream block is never used (target ${target}).`, fix: 'proxy_http_version 1.1;\nproxy_set_header Connection "";', ...at(p) });
      else if (!clears) rec({ id: 'rec-nginx-keepalive-http11', title: `Clear the Connection header towards upstream "${m[1]}"`, detail: 'With HTTP/1.1 and a keepalive pool, nginx should not forward "Connection: close" from the client.', fix: 'proxy_set_header Connection "";', ...at(p) });
    }
  } else {
    for (const p of dirs('proxy_http_version')) {
      if (p.node.args[0] === '1.1' && p.node.children === null && dirs('proxy_set_header').some((h) => /^connection$/i.test(h.node.args[0]) && h.node.args[1] === '' && h.chain[h.chain.length - 1] === p.chain[p.chain.length - 1])) {
        rec({ id: 'rec-nginx-defaults-1297', title: 'proxy_http_version 1.1 and Connection "" are the defaults since nginx 1.29.7', detail: `Since 1.29.7 nginx proxies with HTTP/1.1, keep-alive on by default and no Connection header. Your target (${target}) already does this, so the lines are redundant.`, fix: 'Remove them (keep them only if this config must also run on older nginx).', ...at(p) });
        break;
      }
    }
  }

  // ---- 3. TLS ---------------------------------------------------------------------------------------------------
  for (const c of dirs('ssl_ciphers')) {
    const v = c.node.args[0] || '';
    if (/(RC4|3DES|MD5|EXPORT|NULL|aNULL|eNULL|ADH|DES-CBC)/i.test(v.replace(/!(RC4|3DES|MD5|EXPORT|NULL|aNULL|eNULL|ADH|DES)\b/gi, ''))) {
      rec({ id: 'rec-nginx-weak-ciphers', severity: 'warning', category: 'security', title: 'Weak cipher families in ssl_ciphers', detail: 'RC4, 3DES, MD5, EXPORT and NULL ciphers are broken or deprecated (RFC 7465, SWEET32).', fix: 'Use the Mozilla "intermediate" list or leave the default (modern since 1.0.5 defaults to HIGH:!aNULL:!MD5).', ...at(c) });
    }
  }
  const sslServers = all.filter((x) => x.node.name === 'server' && x.node.children && x.node.children.some((c) => c.name === 'listen' && c.args.includes('ssl')));
  const insideHttp = (x) => x.chain.length && x.chain.some((n) => n.name === 'http');
  for (const s of sslServers) {
    const ancestors = s.chain;
    const find = (name, test) => [...s.node.children, ...ancestors.flatMap((a) => a.children)].some((c) => c.name === name && (!test || test(c)));
    if (!find('ssl_session_cache') && !find('ssl_session_cache', () => true)) {
      rec({ id: 'rec-nginx-ssl-session-cache', category: 'performance', title: 'TLS session cache is not configured', detail: 'Without a shared session cache every returning client performs a full TLS handshake.', fix: 'ssl_session_cache shared:SSL:10m;\nssl_session_timeout 1d;', ...at(s) });
    }
    const hsts = [...s.node.children, ...ancestors.flatMap((a) => a.children), ...all.filter((x) => x.chain.includes(s.node)).map((x) => x.node)].some((c) => c.name === 'add_header' && /strict-transport-security/i.test(c.args[0] || ''));
    if (!hsts) rec({ id: 'rec-nginx-hsts', category: 'security', title: `Server ${((s.node.children.find((c) => c.name === 'server_name') || { args: [] }).args[0]) || `at line ${s.node.line}`} serves HTTPS without HSTS`, detail: 'Without Strict-Transport-Security browsers try plain HTTP first, which allows downgrade attacks.', fix: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', ...at(s) });
  }
  if (V.gte(target, '1.25.0') && sslServers.length && !all.some((x) => x.node.name === 'listen' && x.node.args.includes('quic'))) {
    rec({ id: 'rec-nginx-http3', category: 'performance', title: 'HTTP/3 (QUIC) is available on this version', detail: `nginx ${target} can serve HTTP/3 next to HTTP/2 (needs --with-http_v3_module and an OpenSSL/QuicTLS build with QUIC support).`, fix: 'listen 443 quic reuseport;\nadd_header Alt-Svc \'h3=":443"; ma=86400\' always;', ...at(sslServers[0]) });
  }

  // ---- 4. process / http level ---------------------------------------------------------------------------------------
  for (const w of dirs('worker_processes')) {
    if (/^\d+$/.test(w.node.args[0] || '') && V.gte(target, '1.3.8')) rec({ id: 'rec-nginx-worker-auto', category: 'performance', title: `worker_processes ${w.node.args[0]} is hard-coded`, detail: '"auto" (nginx 1.3.8+) follows the number of CPU cores, so the config stays right when the machine or container is resized.', fix: 'worker_processes auto;', ...at(w) });
  }
  const wc = dirs('worker_connections')[0];
  if (wc && Number(wc.node.args[0]) > 1024 && !dirs('worker_rlimit_nofile').length) {
    rec({ id: 'rec-nginx-nofile', category: 'reliability', title: 'worker_connections is above 1024 but worker_rlimit_nofile is not set', detail: 'Each connection (and each proxied connection) uses a file descriptor. With the default limit nginx logs "worker_connections exceed open file resource limit".', fix: `worker_rlimit_nofile ${Math.max(Number(wc.node.args[0]) * 2, 4096)};`, ...at(wc) });
  }
  for (const g of dirs('gzip')) {
    if (g.node.args[0] !== 'on') continue;
    const scope = g.chain[g.chain.length - 1] || { children: [] };
    if (!scope.children.some((c) => c.name === 'gzip_types') && !dirs('gzip_types').length) {
      rec({ id: 'rec-nginx-gzip-types', category: 'performance', title: 'gzip is on but gzip_types is not set', detail: 'Only text/html is compressed by default, so JSON, CSS and JavaScript responses are sent uncompressed.', fix: 'gzip_types text/plain text/css application/json application/javascript image/svg+xml;', ...at(g) });
    }
    break;
  }
  for (const r of dirs('rewrite')) {
    if (/^\^?(\(\.\*\)|\.\*|\/\(\.\*\))\$?$|^\^$|^\^\(\.\*\)\$$/.test(r.node.args[0] || '') && /^https?:\/\//.test(r.node.args[1] || '') && /permanent|redirect/.test(r.node.args[2] || '')) {
      rec({ id: 'rec-nginx-return-redirect', category: 'performance', title: 'Use "return" instead of "rewrite" for a whole-site redirect', detail: '"return" ends processing immediately and needs no regular expression, which is faster and clearer.', fix: `return ${/permanent/.test(r.node.args[2]) ? 301 : 302} ${(r.node.args[1] || '').replace(/\$1/g, '$request_uri')};`, ...at(r) });
      break;
    }
  }
  for (const i of dirs('if')) {
    if (i.chain.some((c) => c.name === 'location')) {
      const bad = (i.node.children || []).filter((c) => !SAFE_IN_IF.has(c.name));
      if (bad.length) rec({ id: 'rec-nginx-if-is-evil', severity: 'warning', category: 'correctness', title: `"if" in location contains ${bad[0].name}`, detail: 'Only "return" and "rewrite ... last" are reliably safe inside "if" within a location; other directives can behave unexpectedly because "if" creates an implicit nested location ("If is Evil").', fix: 'Use "map" + variables, separate locations, or "try_files" instead of branching with "if".', ...at(i) });
    }
  }
  void exists; void insideHttp;
}

module.exports = { recommendNginx };

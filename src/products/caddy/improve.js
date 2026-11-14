'use strict';
/**
 * Config Doctor for Caddyfiles: rule-based rewrites applied as line edits to the original files, so comments, blank
 * lines and formatting are kept. Every rule checks the import-expanded configuration first (a header set in an imported
 * snippet counts), edits the file the directive really lives in (a snippet is edited once, not per site), respects the
 * target version (src/kb/caddy.json) and never proposes what is already there, so improve() on its own output proposes
 * no further automatic change.
 */
const C = require('./caddyfile');
const { structure, parseAddress, parseUpstream } = require('./model');
const { kb, V, target: resolveTarget, available, DOCS } = require('./kb');
const { isJson } = require('./json');

const LOOPBACK = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|unix\/.*)(:\d+)?$/i;

function indentUnit(text) {
  const lines = String(text).split('\n');
  if (lines.some((l) => /^\t/.test(l))) return '\t';
  const sp = lines.map((l) => /^( +)\S/.exec(l)).filter(Boolean).map((m) => m[1].length);
  const min = sp.length ? Math.min(...sp) : 4;
  return ' '.repeat(min || 4);
}
const leading = (line) => /^[ \t]*/.exec(line || '')[0];

function improve({ files, version } = {}) {
  const list = (Array.isArray(files) ? files : [{ name: 'Caddyfile', content: String(files || '') }]).map((f) => ({ name: String(f.name || 'Caddyfile'), content: String(f.content || '').replace(/\r\n?/g, '\n') }));
  const tgt = resolveTarget(version);
  const T = tgt.version;
  const changes = []; let seq = 0;
  const original = list.map((f) => ({ name: f.name, content: f.content }));
  const render = (enabled) => applyEdits(list, changes.filter((c) => c.auto && enabled(c)));
  const out = { target: T, targetInfo: tgt, changes, render, product: 'caddy' };
  if (!list.some((f) => f.content.trim()) || isJson(list[0].content)) {
    if (list[0] && isJson(list[0].content)) changes.push({ key: 'caddy-json:1', rule: 'caddy-json', category: 'hygiene', severity: 'info', title: 'Config Doctor works on Caddyfiles', why: 'This is a Caddy JSON configuration. Convert from a Caddyfile (caddy adapt) to get rewrite suggestions.', section: 'global', line: 1, auto: false, on: false, ops: [] });
    return out;
  }
  let loaded;
  try { loaded = C.loadFiles(list); } catch { return out; }
  const byName = new Map(list.map((f) => [f.name.replace(/^\/+/, ''), f]));
  const linesOf = (file) => (byName.get(file) ? byName.get(file).content.split('\n') : []);
  const lineText = (file, line) => linesOf(file)[line - 1] || '';
  const unitOf = (file) => indentUnit(byName.get(file) ? byName.get(file).content : '\t');
  const { global, sites } = structure(loaded.nodes);
  const add = (c) => changes.push({ key: `${c.rule}:${++seq}`, auto: true, on: true, severity: 'medium', ...c, ops: c.ops || [] });
  const advice = (c) => add({ ...c, auto: false, on: false });
  const has = (name) => kb.directives[name] && available(kb.directives[name], T);
  const subOk = (dir, sub) => { const e = kb.directives[dir] && kb.directives[dir].sub && kb.directives[dir].sub[sub]; return Boolean(e) && available(e, T); };

  // ---- op builders (lines are 1-based, in the file the node lives in)
  const opAdd = (file, after, lines, extra = {}) => ({ kind: 'add', text: lines.map((l) => l.trim()).join(' / '), file, after, lines, ...extra });
  const opMod = (file, line, fn, label) => { const before = lineText(file, line); return { kind: 'mod', before: before.trim(), text: fn(before).trim(), file, line, fn, label }; };
  const opDel = (file, line) => ({ kind: 'del', before: lineText(file, line).trim(), file, line });
  /** Lines added inside a directive's block; a one-line directive gets a block (once, even if several rules add). */
  const opInside = (nd, lines) => {
    const ind = leading(lineText(nd.file, nd.line)) + unitOf(nd.file);
    return opAdd(nd.file, nd.block ? nd.line : nd.line, lines.map((l) => `${ind}${l}`), { inside: nd.block ? null : { file: nd.file, line: nd.line, indent: leading(lineText(nd.file, nd.line)) } });
  };
  const flat = (nodes, out = [], within = []) => { for (const n of nodes) { out.push({ n, within }); if (n.block) flat(n.block, out, [...within, n]); } return out; };
  const siteLabel = (s) => s.keys.join(', ');

  // ---- global options
  const g = global;
  const gkid = (name) => (g ? (g.block || []).find((n) => n.name === name) : null);
  const adminNd = gkid('admin');
  if (adminNd && adminNd.args[0] && adminNd.args[0] !== 'off' && !LOOPBACK.test(adminNd.args[0].replace(/^tcp\//, ''))) {
    add({ rule: 'caddy-admin-local', category: 'security', severity: 'high', on: false, title: 'Keep the admin API on localhost', section: 'global options', line: adminNd.line, why: `\`admin ${adminNd.args[0]}\` lets anyone who reaches the port replace the whole configuration without authentication. Bind it to localhost and use an SSH tunnel; if GateLight polls the admin API remotely, put a reverse_proxy with basic_auth in front instead (disabled by default for that reason).`, docs: `${DOCS}/caddyfile/options#admin`, ops: [opMod(adminNd.file, adminNd.line, (l) => l.replace(adminNd.args[0], 'localhost:2019'))] });
  }
  if (sites.length) {
    const servers = g ? (g.block || []).filter((n) => n.name === 'servers') : [];
    const anyTimeouts = servers.some((s) => (s.block || []).some((c) => c.name === 'timeouts'));
    const optOk = kb.options.servers && available(kb.options.servers, T);
    if (!anyTimeouts && optOk) {
      const u = g ? unitOf(g.file) : '\t';
      const tbody = ['read_body 30s', 'read_header 10s', 'idle 2m'];
      const why = 'Caddy sets no read timeouts by default, so a slow client (slowloris) can hold a connection open indefinitely while sending its request. 10 s for headers and 30 s for the body are generous for real browsers; `idle` closes unused keep-alive connections.';
      if (!g) {
        const mainFile = loaded.files[0] ? loaded.files[0].name : list[0].name;
        add({ rule: 'caddy-server-timeouts', category: 'security', severity: 'medium', title: 'Set read timeouts for client connections', section: 'global options', line: 1, why, docs: `${DOCS}/caddyfile/options#timeouts`, ops: [opAdd(mainFile, 0, ['{', `${u}servers {`, `${u}${u}timeouts {`, ...tbody.map((t) => `${u}${u}${u}${t}`), `${u}${u}}`, `${u}}`, '}', ''])] });
      } else if (!servers.length) {
        const ind = leading(lineText(g.file, g.line)) + u;
        add({ rule: 'caddy-server-timeouts', category: 'security', severity: 'medium', title: 'Set read timeouts for client connections', section: 'global options', line: g.line, why, docs: `${DOCS}/caddyfile/options#timeouts`, ops: [opAdd(g.file, g.line, [`${ind}servers {`, `${ind}${u}timeouts {`, ...tbody.map((t) => `${ind}${u}${u}${t}`), `${ind}${u}}`, `${ind}}`])] });
      } else {
        const s = servers[0]; const ind = leading(lineText(s.file, s.line)) + u;
        add({ rule: 'caddy-server-timeouts', category: 'security', severity: 'medium', title: 'Set read timeouts for client connections', section: 'global options', line: s.line, why, docs: `${DOCS}/caddyfile/options#timeouts`, ops: [opInside(s, ['timeouts {', ...tbody.map((t) => `${u}${t}`), '}'])] });
      }
    }
  }

  // ---- sites
  const seenNodes = new Set();
  const once = (nd) => { const k = `${nd.file}:${nd.line}`; if (seenNodes.has(k)) return false; seenNodes.add(k); return true; };
  const siteLogs = sites.map((s) => flat(s.body).some(({ n }) => n.name === 'log'));
  sites.forEach((site, si) => {
    if (site.unbraced) return;
    const all = flat(site.body);
    const label = siteLabel(site);
    const addrs = site.keys.map((k) => parseAddress(k));
    const https = addrs.some((a) => a.tls);
    const u = unitOf(site.file);
    const ind = leading(lineText(site.file, site.line)) + u;
    const serves = all.some(({ n }) => ['reverse_proxy', 'file_server', 'php_fastcgi', 'respond', 'templates'].includes(n.name));
    const top = [];
    if (serves && !all.some(({ n }) => n.name === 'encode') && has('encode')) top.push({ rule: 'caddy-encode', category: 'performance', severity: 'low', title: 'Compress responses (zstd, gzip)', why: 'Caddy does not compress by default. `encode zstd gzip` shrinks text responses by 70-90 %; clients without zstd get gzip.', docs: `${DOCS}/caddyfile/directives/encode`, lines: ['encode zstd gzip'] });
    if (https && serves) {
      const names = new Set();
      for (const { n } of all) if (n.name === 'header') {
        const args = n.args.filter((a, i) => !(i === 0 && /^[@/*]/.test(a)));
        if (args[0]) names.add(args[0].replace(/^[+?>]/, '').toLowerCase());
        for (const c of n.block || []) names.add(c.name.replace(/^[+?>]/, '').toLowerCase());
      }
      const want = [['strict-transport-security', 'Strict-Transport-Security "max-age=31536000"'], ['x-content-type-options', 'X-Content-Type-Options "nosniff"'], ['referrer-policy', 'Referrer-Policy "strict-origin-when-cross-origin"'], ['-server', '-Server']].filter(([k]) => !names.has(k));
      if (want.length) top.push({ rule: 'caddy-security-headers', category: 'security', severity: 'medium', title: `Send security headers (${want.map((w) => w[1].split(' ')[0]).join(', ')})`, why: 'HSTS keeps browsers on HTTPS for a year (Caddy already redirects, HSTS also protects the first request after that); nosniff stops content-type guessing; Referrer-Policy keeps full URLs from leaking to other sites; `-Server` removes the "Caddy" banner.', docs: `${DOCS}/caddyfile/directives/header`, lines: ['header {', ...want.map((w) => `${u}${w[1]}`), '}'] });
    }
    if (serves && !siteLogs[si] && has('log')) top.push({ rule: 'caddy-log', category: 'observability', severity: 'low', on: siteLogs.some(Boolean), title: 'Log requests of this site', why: `Caddy writes no access log unless a site has a \`log\` directive${siteLogs.some(Boolean) ? '; other sites in this file already do' : ''}. JSON access logs feed GateLight's Traffic Stats.`, docs: `${DOCS}/caddyfile/directives/log`, lines: ['log'] });
    for (const t of top) add({ rule: t.rule, category: t.category, severity: t.severity, on: t.on !== undefined ? t.on : true, title: t.title, why: t.why, docs: t.docs, section: label, line: site.line, ops: [opAdd(site.file, site.line, t.lines.map((l) => `${ind}${l}`))] });

    for (const { n } of all) {
      if (n.name === 'basicauth' && V.gte(T, '2.8.0') && once(n)) add({ rule: 'caddy-basic-auth-rename', category: 'compatibility', severity: 'low', title: 'Rename basicauth to basic_auth', section: label, line: n.line, why: 'Caddy 2.8 renamed the directive; the old name logs a deprecation warning and will be removed.', docs: `${DOCS}/caddyfile/directives/basic_auth`, ops: [opMod(n.file, n.line, (l) => l.replace(/\bbasicauth\b/, 'basic_auth'))] });
      if (n.name === 'encode' && n.args.includes('gzip') && !n.args.includes('zstd') && once(n)) add({ rule: 'caddy-zstd', category: 'performance', severity: 'low', title: 'Prefer zstd, fall back to gzip', section: label, line: n.line, why: 'zstd is faster and smaller than gzip; Caddy picks the best encoding the client accepts.', docs: `${DOCS}/caddyfile/directives/encode`, ops: [opMod(n.file, n.line, (l) => l.replace(/\bgzip\b/, 'zstd gzip'))] });
      if (n.name === 'file_server' && once(n)) {
        if (n.args.includes('browse')) add({ rule: 'caddy-file-browse', category: 'security', severity: 'medium', title: 'Turn directory listings off', section: label, line: n.line, why: '`browse` lets anyone list the files under the site root and find backups, dumps and keys left there.', docs: `${DOCS}/caddyfile/directives/file_server`, ops: [opMod(n.file, n.line, (l) => l.replace(/\s+browse\b/, ''))] });
        for (const c of n.block || []) if (c.name === 'browse' && !c.block) add({ rule: 'caddy-file-browse', category: 'security', severity: 'medium', title: 'Turn directory listings off', section: label, line: c.line, why: '`browse` lets anyone list the files under the site root.', docs: `${DOCS}/caddyfile/directives/file_server`, ops: [opDel(c.file, c.line)] });
      }
      if (n.name === 'reverse_proxy' && once(n)) {
        const mt = n.toks[1] && !n.toks[1].quoted && /^[@/*]/.test(n.toks[1].text);
        const ups = [...n.args.slice(mt ? 1 : 0), ...(n.block || []).filter((c) => c.name === 'to').flatMap((c) => c.args)].flatMap(parseUpstream);
        const subs = new Map((n.block || []).map((c) => [c.name, c]));
        if (ups.length > 1 && !ups.some((x) => x.dynamic)) {
          if (!subs.has('lb_try_duration') && !subs.has('lb_retries') && subOk('reverse_proxy', 'lb_try_duration')) add({ rule: 'caddy-lb-retry', category: 'reliability', severity: 'low', title: 'Retry another upstream for up to 5 s', section: label, line: n.line, why: 'Without lb_try_duration a request that is sent to a dead upstream fails at once, even though other upstreams are fine. With it, Caddy retries the next upstream (only while the request body can be replayed).', docs: `${DOCS}/caddyfile/directives/reverse_proxy#lb_try_duration`, ops: [opInside(n, ['lb_try_duration 5s'])] });
          if (!subs.has('fail_duration') && subOk('reverse_proxy', 'fail_duration')) add({ rule: 'caddy-passive-health', category: 'reliability', severity: 'medium', title: 'Remember failing upstreams (passive health checks)', section: label, line: n.line, why: 'With `fail_duration`, an upstream that fails a request is avoided for that long (max_fails 1 by default), so one dead upstream stops costing every n-th request.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#passive-health-checks`, ops: [opInside(n, ['fail_duration 30s'])] });
          if (!subs.has('health_uri') && !subs.has('health_port') && !subs.has('health_path') && subOk('reverse_proxy', 'health_uri')) add({ rule: 'caddy-active-health', category: 'reliability', severity: 'medium', on: false, title: 'Probe the upstreams (active health checks)', section: label, line: n.line, why: 'Active checks take an upstream out before users hit it. Disabled by default because the path depends on your application: set it to a cheap endpoint that answers 2xx.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#active-health-checks`, ops: [opInside(n, ['health_uri /health', 'health_interval 10s', ...(subOk('reverse_proxy', 'health_passes') ? ['health_passes 2', 'health_fails 3'] : [])])] });
        }
        for (const c of n.block || []) {
          if (c.name === 'header_up' && /^\+?x-forwarded-(for|proto|host)$/i.test(c.args[0] || '')) add({ rule: 'caddy-header-up-default', category: 'hygiene', severity: 'low', title: `Drop header_up ${c.args[0]} (Caddy sets it)`, section: label, line: c.line, why: 'reverse_proxy sets X-Forwarded-For / -Proto / -Host itself and keeps values from trusted proxies only; overriding them loses the chain or trusts spoofed values.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#defaults`, ops: [opDel(c.file, c.line)] });
          if (c.name === 'transport') for (const t of c.block || []) if (t.name === 'tls_insecure_skip_verify') advice({ rule: 'caddy-tls-verify', category: 'security', severity: 'medium', title: 'Verify the upstream\'s certificate', section: label, line: t.line, why: 'tls_insecure_skip_verify encrypts without authenticating. Trust the upstream CA instead (tls_trust_pool file /etc/caddy/upstream-ca.pem on 2.8+, tls_trusted_ca_certs before) and remove the line. Not changed automatically: the CA file must exist.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#tls_insecure_skip_verify` });
        }
      }
    }
  });

  const catRank = { security: 0, reliability: 1, compatibility: 2, performance: 3, observability: 4, hygiene: 5 };
  changes.sort((a, b) => (catRank[a.category] ?? 9) - (catRank[b.category] ?? 9));
  out.original = original;
  return out;
}

/** Apply the ops of the chosen changes to fresh copies of the files. */
function applyEdits(list, chosen) {
  const ops = chosen.flatMap((c) => c.ops.map((o, i) => ({ ...o, seq: `${c.key}:${i}` })));
  return list.map((f) => {
    const name = f.name.replace(/^\/+/, '');
    const mine = ops.filter((o) => o.file === name);
    if (!mine.length) return { name: f.name, content: f.content };
    const lines = f.content.split('\n');
    const mods = new Map(); const dels = new Set(); const adds = new Map(); const blockify = new Map();
    for (const o of mine) {
      if (o.kind === 'mod') { const l = mods.get(o.line) || []; l.push(o.fn); mods.set(o.line, l); }
      if (o.kind === 'del') dels.add(o.line);
      if (o.kind === 'add') {
        if (o.inside) { const b = blockify.get(o.inside.line) || { indent: o.inside.indent, lines: [] }; b.lines.push(...o.lines); blockify.set(o.inside.line, b); } else { const l = adds.get(o.after) || []; l.push(...o.lines); adds.set(o.after, l); }
      }
    }
    const out = [...(adds.get(0) || [])];
    lines.forEach((text, idx) => {
      const ln = idx + 1;
      if (dels.has(ln)) return;
      let t = text;
      for (const fn of mods.get(ln) || []) t = fn(t);
      if (blockify.has(ln)) {
        const b = blockify.get(ln);
        const m = /^(.*?)(\s+#.*)?$/.exec(t);
        out.push(`${m[1].replace(/\s+$/, '')} {${m[2] || ''}`); out.push(...b.lines); out.push(`${b.indent}}`);
      } else out.push(t);
      out.push(...(adds.get(ln) || []));
    });
    return { name: f.name, content: out.join('\n') };
  });
}

module.exports = { improve, applyEdits, indentUnit };

'use strict';
/**
 * Config Forge, NGINX side: parse the files into an AST (directives, blocks, comments), run the rules, and print a clean,
 * rewritten configuration. Rules respect NGINX inheritance (a level that defines proxy_set_header / add_header replaces
 * the one above it), the target version (kb), and never propose what is already there.
 */
const { tokens, unq } = require('./common');
const V = require('../validate/version');
const kb = require('../kb/nginx.json');

const IND = '    ';
const CIPHERS = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const WEAK = /(RC4|3DES|DES-CBC|MD5|EXPORT|NULL|aNULL|eNULL|ADH|\bDES\b)/i;
const OLD_PROTO = /^(SSLv2|SSLv3|TLSv1|TLSv1\.1)$/i;
const SEC_HEADERS = new Set(['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'content-security-policy', 'permissions-policy']);
const LUA_BLOCK = /_by_lua_block$|^(lua_|perl_)/;

// ------------------------------------------------------------------------------------------------ parse / print
const collapse = (s) => {
  let out = ''; let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { out += c; if (c === '\\' && i + 1 < s.length) out += s[++i]; else if (c === q) q = null; } else if (c === '"' || c === "'") { q = c; out += c; } else if (/\s/.test(c)) { if (out && !/\s$/.test(out)) out += ' '; } else out += c;
  }
  return out.trim();
};
function parse(text) {
  const src = String(text).replace(/^﻿/, '').replace(/\r\n?/g, '\n'); const n = src.length;
  const root = { children: [], root: true }; const stack = [root]; let i = 0; let line = 1; let blank = false;
  const top = () => stack[stack.length - 1];
  const push = (node) => { node.blank = blank; blank = false; top().children.push(node); return node; };
  while (i < n) {
    const c = src[i];
    if (c === '\n') { line++; i++; if (/^[ \t]*\n/.test(src.slice(i, i + 80))) blank = true; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (c === '#') {
      let j = i; while (j < n && src[j] !== '\n') j++;
      const t = src.slice(i, j).trimEnd(); const kids = top().children; const prev = kids[kids.length - 1];
      if (prev && prev.t === 'dir' && prev.endLine === line && !prev.trail && !(prev.block && !prev.closed)) prev.trail = t; else push({ t: 'comment', text: t, line });
      i = j; continue;
    }
    if (c === '}') { if (stack.length > 1) { const b = stack.pop(); b.closed = true; b.endLine = line; } i++; continue; }
    // a statement: up to ; or { (quotes and ${var} respected)
    const startLine = line; let j = i; let q = null; let buf = '';
    for (; j < n; j++) {
      const d = src[j];
      if (q) { buf += d; if (d === '\\' && j + 1 < n) buf += src[++j]; else if (d === q) q = null; if (d === '\n') line++; continue; }
      if (d === '"' || d === "'") { q = d; buf += d; continue; }
      if (d === '$' && src[j + 1] === '{') { const e = src.indexOf('}', j); const seg = src.slice(j, e < 0 ? n : e + 1); buf += seg; j += seg.length - 1; continue; }
      if (d === '#' && (j === i || /\s/.test(src[j - 1]))) { while (j < n && src[j] !== '\n') j++; j--; continue; }
      if (d === ';' || d === '{' || d === '}') break;
      if (d === '\n') line++;
      buf += d;
    }
    const stmt = buf.trim(); const m = /^(\S+)\s*([\s\S]*)$/.exec(stmt);
    if (!m) { i = j + (src[j] === '}' ? 0 : 1); continue; }
    const name = m[1]; const lines = m[2].split('\n').map(collapse).filter(Boolean);
    const node = { t: 'dir', name, argLines: lines, line: startLine, endLine: line };
    if (src[j] === '{') {
      node.block = true; node.children = [];
      if (LUA_BLOCK.test(name)) { // opaque code is kept as written
        let depth = 1; let k = j + 1; let endLine = line;
        while (k < n && depth) { if (src[k] === '{') depth++; else if (src[k] === '}') depth--; if (src[k] === '\n') endLine++; k++; }
        node.raw = src.slice(j + 1, k - 1); node.closed = true; line = endLine; node.endLine = endLine; push(node); i = k; continue;
      }
      push(node); stack.push(node); i = j + 1; continue;
    }
    push(node); i = j + (src[j] === ';' ? 1 : 0);
  }
  return root;
}
const argsOf = (nd) => nd.argLines.join(' ');
const toks = (nd) => tokens(argsOf(nd));
function printNode(nd, depth, out) {
  const ind = IND.repeat(depth);
  if (nd.blank && out.length && out[out.length - 1] !== '') out.push('');
  if (nd.t === 'comment') { out.push(`${ind}${nd.text}`); return; }
  const head = `${nd.name}${nd.argLines.length ? ` ${nd.argLines[0]}` : ''}`;
  const rest = nd.argLines.slice(1).map((l) => `${ind}${IND}${l}`);
  const closer = nd.block ? ' {' : ';';
  const trail = nd.trail ? ` ${nd.trail}` : '';
  if (!rest.length) out.push(`${ind}${head}${closer}${trail}`);
  else { out.push(`${ind}${head}`); rest.forEach((l, k) => out.push(k === rest.length - 1 ? `${l}${closer}${trail}` : l)); }
  if (nd.block) {
    if (nd.raw != null) {
      const body = nd.raw.replace(/^\s*\n/, '').replace(/\s+$/, '');
      if (body.includes('\n')) { const ls = body.split('\n'); const pad = Math.min(...ls.filter((l) => l.trim()).map((l) => /^\s*/.exec(l)[0].length)); ls.forEach((l) => out.push(l.trim() ? `${ind}${IND}${l.slice(pad)}` : '')); } else if (body.trim()) out.push(`${ind}${IND}${body.trim()}`);
      out.push(`${ind}}`); return;
    }
    nd.children.forEach((c) => printNode(c, depth + 1, out)); out.push(`${ind}}`);
  }
}
function print(root) { const out = []; root.children.forEach((c) => printNode(c, 0, out)); return `${out.join('\n').replace(/\n{3,}/g, '\n\n')}\n`; }

const D = (name, args = '') => ({ t: 'dir', name, argLines: args ? [args] : [], blank: false, _new: true });
const B = (name, args, children) => ({ t: 'dir', name, argLines: args ? [args] : [], block: true, children, closed: true, blank: true, _new: true });
const parseStmt = (text) => { const m = /^(\S+)\s*([\s\S]*?);?$/.exec(text.trim()); return D(m[1], collapse(m[2])); };

// ------------------------------------------------------------------------------------------------ analysis
const globToRe = (p) => new RegExp(`${p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);

function analyze(files, opts = {}) {
  const parsed = files.map((f) => ({ name: f.name, root: parse(f.content) }));
  const normalized = parsed.map((f) => ({ name: f.name, content: print(f.root) }));
  const target = V.detect(opts.version) || opts.version || kb.latest; const versionKnown = Boolean(opts.version);
  const gte = (v) => V.gte(target, v);
  const exists = (name) => { const e = kb.directives[name]; return Boolean(e && e.some((x) => !x.since || gte(x.since))); };
  const changes = []; let seq = 0;

  // ---- scopes: which nodes are the http level, and which files are included where
  const mainFile = parsed.find((f) => f.root.children.some((c) => c.name === 'http' && c.block)) || null;
  const httpNode = mainFile ? mainFile.root.children.find((c) => c.name === 'http' && c.block) : null;
  const walk = (nodes, fn, path = []) => nodes.forEach((nd) => { if (nd.t !== 'dir') return; fn(nd, path); if (nd.block && !nd.raw) walk(nd.children, fn, [...path, nd]); });
  const includeScope = new Map(); // file name -> 'http' | 'stream' | 'server' | 'location'
  parsed.forEach((f) => walk(f.root.children, (nd, path) => {
    if (nd.name !== 'include') return; const pat = unq(toks(nd)[0] || ''); if (!pat) return;
    const scope = path.some((p) => p.name === 'stream') ? 'stream' : path.some((p) => p.name === 'location') ? 'location' : path.some((p) => p.name === 'server') ? 'server' : path.some((p) => p.name === 'http') ? 'http' : null;
    if (!scope) return; const re = globToRe(pat.split('/').slice(-2).join('/'));
    parsed.forEach((g) => { if (g !== f && re.test(g.name) && !includeScope.has(g.name)) includeScope.set(g.name, scope); });
  }));
  const guessScope = (f) => {
    if (f === mainFile) return null; if (includeScope.has(f.name)) return includeScope.get(f.name);
    const names = f.root.children.map((c) => c.name); return names.includes('server') || names.includes('upstream') || names.includes('map') ? 'http' : null;
  };
  const httpLevel = []; // containers whose children sit directly in the http context
  if (httpNode) httpLevel.push({ container: httpNode, file: mainFile });
  parsed.forEach((f) => { if (guessScope(f) === 'http') httpLevel.push({ container: f.root, file: f }); });
  const hl = (name) => httpLevel.flatMap((h) => h.container.children.filter((c) => c.t === 'dir' && c.name === name));
  const servers = [];
  httpLevel.forEach((h) => h.container.children.forEach((c) => { if (c.t === 'dir' && c.name === 'server' && c.block) servers.push({ node: c, file: h.file, container: h.container }); }));
  const upstreams = httpLevel.flatMap((h) => h.container.children.filter((c) => c.t === 'dir' && c.name === 'upstream' && c.block));
  const kids = (nd, name) => nd.children.filter((c) => c.t === 'dir' && c.name === name);
  const kid = (nd, name) => kids(nd, name)[0];
  const locs = (srv) => { const out = []; const rec = (nd) => nd.children.forEach((c) => { if (c.t === 'dir' && c.name === 'location' && c.block) { out.push(c); rec(c); } }); rec(srv); return out; };
  const listens = (srv) => kids(srv, 'listen').map((l) => ({ node: l, t: toks(l) }));
  const isSsl = (l) => l.t.includes('ssl') || l.t.includes('quic');
  const hasSslOn = (s) => { const x = kid(s.node, 'ssl'); return Boolean(x && toks(x)[0] === 'on'); };
  const sslServers = servers.filter((s) => hasSslOn(s) || listens(s.node).some(isSsl));
  const sslUsed = sslServers.length > 0 || servers.some((s) => kid(s.node, 'ssl_certificate'));
  const secName = (s) => { const sn = kid(s.node, 'server_name'); return `server ${sn ? toks(sn).slice(0, 2).join(' ') : (listens(s.node)[0] ? `:${listens(s.node)[0].t[0]}` : '')}`.trim(); };
  const namesOf = (s) => (kid(s.node, 'server_name') ? toks(kid(s.node, 'server_name')) : []);

  // ---- ops (same shape as the HAProxy side): each one can be run later, when the user has chosen what to apply
  const ops = {
    ins: (container, at, nodeOrText) => ({ kind: 'add', text: typeof nodeOrText === 'string' ? nodeOrText : `${nodeOrText.name} ${argsOf(nodeOrText)}${nodeOrText.block ? ' { … }' : ''}`.trim(), run() {
      const nd = typeof nodeOrText === 'string' ? parseStmt(nodeOrText) : nodeOrText; const k = container.children; let idx;
      if (at === 'end' || !at) idx = k.length;
      else if (at === 'start') { idx = 0; while (k[idx] && k[idx]._start) idx++; nd._start = true; }
      else if (at.before) idx = k.indexOf(at.before);
      else if (at.after) { idx = k.indexOf(at.after) + 1; while (k[idx] && k[idx]._after === at.after) idx++; nd._after = at.after; }
      else if (at.beforeFirst) { idx = k.findIndex((c) => c.t === 'dir' && at.beforeFirst.includes(c.name)); if (idx < 0) idx = k.length; }
      k.splice(idx < 0 ? k.length : idx, 0, nd);
    } }),
    upd: (nd, fn) => ({ kind: 'mod', before: `${nd.name} ${argsOf(nd)}`.trim(), text: `${nd.name} ${fn(argsOf(nd))}`.trim(), run() { nd.argLines = [fn(argsOf(nd))]; } }),
    rep: (nd, args) => ({ kind: 'mod', before: `${nd.name} ${argsOf(nd)}`.trim(), text: `${nd.name} ${args}`.trim(), run() { nd.argLines = args ? [args] : []; } }),
    to: (nd, name, args) => ({ kind: 'mod', before: `${nd.name} ${argsOf(nd)}`.trim(), text: `${name} ${args}`.trim(), run() { nd.name = name; nd.argLines = args ? [args] : []; } }),
    del: (nd, container) => ({ kind: 'del', before: `${nd.name} ${argsOf(nd)}`.trim(), run() { const i = container.children.indexOf(nd); if (i >= 0) container.children.splice(i, 1); } }),
  };
  const add = (c) => changes.push({ key: `${c.rule}:${++seq}`, auto: true, on: true, severity: 'medium', ...c, ops: c.ops || [] });
  const advice = (c) => add({ ...c, auto: false, on: false });
  const SRV_TOP = { beforeFirst: ['location', 'if'] }; // server-level directives sit above the locations
  const httpAdd = (text) => ops.ins(httpNode, { beforeFirst: ['server', 'include', 'upstream', 'map'] }, text);

  // ---- main context
  if (mainFile) {
    const rootNodes = mainFile.root;
    if (!kid(rootNodes, 'worker_processes')) add({ rule: 'ngx-workers', category: 'performance', severity: 'low', title: 'Run one worker per CPU core', section: 'main', line: 1, why: 'Without `worker_processes` NGINX uses a single worker and one core, no matter how big the machine is. `auto` matches the core count.', ops: [ops.ins(rootNodes, 'start', 'worker_processes auto;')] });
    const ev = kid(rootNodes, 'events');
    if (ev && !kid(ev, 'worker_connections')) add({ rule: 'ngx-conn', category: 'performance', severity: 'low', title: 'Raise worker_connections', section: 'events', line: ev.line, why: 'The default of 512 connections per worker limits a busy server (each proxied request uses two). Keep it below the open-files limit (`worker_rlimit_nofile`).', ops: [ops.ins(ev, 'end', 'worker_connections 4096;')] });
    if (!kid(rootNodes, 'error_log')) add({ rule: 'ngx-error-log', category: 'observability', severity: 'info', on: false, title: 'Set the error log explicitly', section: 'main', line: 1, why: 'Without `error_log` the destination is a compile-time path that differs between builds. In a container point it at /dev/stderr.', ops: [ops.ins(rootNodes, ev ? { before: ev } : 'end', 'error_log /var/log/nginx/error.log warn;')] });
  }

  // ---- http context
  if (httpNode) {
    const tok = hl('server_tokens')[0];
    if (!tok) add({ rule: 'ngx-tokens', category: 'security', severity: 'medium', title: 'Hide the NGINX version', section: 'http', line: httpNode.line, why: '`server_tokens` is on by default: every response and error page advertises the exact NGINX version, which tells attackers which exploits to try.', ops: [httpAdd('server_tokens off;')] });
    else if (toks(tok)[0] === 'on') add({ rule: 'ngx-tokens', category: 'security', severity: 'medium', title: 'Hide the NGINX version', section: 'http', line: tok.line, why: '`server_tokens on` advertises the exact NGINX version on every response and error page.', ops: [ops.rep(tok, 'off')] });
    servers.forEach((s) => { const t = kid(s.node, 'server_tokens'); if (t && toks(t)[0] === 'on') add({ rule: 'ngx-tokens', category: 'security', severity: 'medium', title: 'Hide the NGINX version', section: secName(s), line: t.line, why: '`server_tokens on` advertises the exact NGINX version.', ops: [ops.rep(t, 'off')] }); });
    const eff1 = [['sendfile', 'on'], ['tcp_nopush', 'on'], ['tcp_nodelay', 'on']].filter(([n]) => !hl(n).length && exists(n));
    if (eff1.length) add({ rule: 'ngx-sendfile', category: 'performance', severity: 'low', title: 'Efficient file and socket handling', section: 'http', line: httpNode.line, why: '`sendfile` serves files in the kernel without copying them through NGINX; `tcp_nopush` fills packets before sending; `tcp_nodelay` flushes small responses immediately on keep-alive connections.', ops: eff1.map(([n, v]) => httpAdd(`${n} ${v};`)) });
    const slow = [['client_header_timeout', '15s'], ['client_body_timeout', '15s'], ['send_timeout', '30s']].filter(([n]) => !hl(n).length);
    if (slow.length) add({ rule: 'ngx-timeouts', category: 'security', severity: 'medium', title: 'Shorten slow-client timeouts', section: 'http', line: httpNode.line, why: 'The 60 second defaults let a slow client (slowloris) hold a connection while sending a request. 15-30 seconds is plenty for real browsers.', ops: slow.map(([n, v]) => httpAdd(`${n} ${v};`)) });
    const gz = hl('gzip')[0];
    if ((!gz || toks(gz)[0] === 'off') && !servers.some((s) => kid(s.node, 'gzip') && toks(kid(s.node, 'gzip'))[0] === 'on')) {
      const lines = ['gzip_vary on;', 'gzip_proxied any;', 'gzip_comp_level 5;', 'gzip_min_length 1024;', 'gzip_types text/plain text/css text/xml application/json application/javascript application/xml image/svg+xml;'].filter((l) => !hl(l.split(' ')[0]).length);
      add({ rule: 'ngx-gzip', category: 'performance', severity: 'low', title: 'Compress text responses', section: 'http', line: gz ? gz.line : httpNode.line, why: 'gzip shrinks HTML, CSS, JS and JSON by 70-90 %. `gzip_vary` keeps caches correct and level 5 is the sweet spot for CPU versus size. (HTML is always compressed once gzip is on.)', ops: [gz ? ops.rep(gz, 'on') : httpAdd('gzip on;'), ...lines.map(httpAdd)] });
    }
    if (sslUsed) {
      const tls = `TLSv1.2${gte('1.13.0') ? ' TLSv1.3' : ''}`;
      const prot = hl('ssl_protocols')[0];
      if (!prot) add({ rule: 'ngx-tls-protocols', category: 'security', severity: 'high', title: 'Allow only TLS 1.2 and 1.3', section: 'http', line: httpNode.line, why: 'Older NGINX defaults still allow TLS 1.0 and 1.1, which are deprecated (RFC 8996) and fail PCI DSS. Every current browser speaks TLS 1.2.', ops: [httpAdd(`ssl_protocols ${tls};`)] });
      const cip = hl('ssl_ciphers')[0];
      if (!cip) add({ rule: 'ngx-tls-ciphers', category: 'security', severity: 'low', title: 'Use modern TLS 1.2 ciphers', section: 'http', line: httpNode.line, why: 'The built-in list includes CBC suites. This is the Mozilla “intermediate” ECDHE-only AEAD list: forward secrecy for every client that supports TLS 1.2.', ops: [httpAdd(`ssl_ciphers ${CIPHERS};`)] });
      if (!hl('ssl_session_cache')[0]) add({ rule: 'ngx-tls-cache', category: 'performance', severity: 'medium', title: 'Share the TLS session cache between workers', section: 'http', line: httpNode.line, why: 'The default per-worker cache means a returning client often lands on a worker without its session and pays a full handshake. A 10 MB shared cache holds about 40,000 sessions.', ops: [httpAdd('ssl_session_cache shared:SSL:10m;'), ...(!hl('ssl_session_timeout')[0] ? [httpAdd('ssl_session_timeout 1d;')] : [])] });
      if (!hl('ssl_session_tickets')[0]) add({ rule: 'ngx-tls-tickets', category: 'security', severity: 'low', title: 'Turn off TLS session tickets', section: 'http', line: httpNode.line, why: 'Tickets are encrypted with a key that is never rotated unless you do it, which defeats forward secrecy. The shared session cache gives the same performance.', ops: [httpAdd('ssl_session_tickets off;')] });
      if (!hl('ssl_stapling')[0] && !servers.some((s) => kid(s.node, 'ssl_stapling'))) advice({ rule: 'ngx-stapling', category: 'performance', severity: 'info', title: 'Consider OCSP stapling', section: 'http', line: httpNode.line, why: '`ssl_stapling on; ssl_stapling_verify on;` plus a `resolver` saves clients an OCSP round trip. Not added automatically because it needs a resolver that works in your network, and some CAs (Let\'s Encrypt) have retired OCSP.' });
    }
    { // legacy protocols / weak ciphers are wrong wherever they are set, even in a snippet without a TLS server
      const prot = hl('ssl_protocols')[0]; const cip = hl('ssl_ciphers')[0];
      if (prot && toks(prot).some((t) => OLD_PROTO.test(t))) add({ rule: 'ngx-tls-protocols', category: 'security', severity: 'high', title: 'Drop legacy TLS versions', section: 'http', line: prot.line, why: 'SSLv3, TLS 1.0 and 1.1 are deprecated and broken (POODLE, BEAST).', ops: [ops.rep(prot, `TLSv1.2${gte('1.13.0') ? ' TLSv1.3' : ''}`)] });
      if (cip && WEAK.test(argsOf(cip))) add({ rule: 'ngx-tls-ciphers', category: 'security', severity: 'high', title: 'Replace weak ciphers', section: 'http', line: cip.line, why: 'RC4, 3DES, MD5, NULL and EXPORT suites are broken or deprecated.', ops: [ops.rep(cip, CIPHERS)] });
    }
    // rate limiting (opt-in: the numbers depend on the application)
    if (!hl('limit_req_zone').length && exists('limit_req_zone')) {
      const proxied = servers.filter((s) => locs(s.node).some((l) => kid(l, 'proxy_pass')) || kid(s.node, 'proxy_pass'));
      if (proxied.length) add({ rule: 'ngx-ratelimit', category: 'security', severity: 'low', on: false, title: 'Rate-limit each client IP', section: 'http', line: httpNode.line, why: 'A per-IP limit of 10 requests per second with a burst of 20 (answering 429) stops trivial floods and scrapers. Tune the numbers to your busiest legitimate client before enabling.',
        ops: [httpAdd('limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;'), httpAdd('limit_req_status 429;'), ...proxied.filter((s) => !kid(s.node, 'limit_req')).map((s) => ops.ins(s.node, SRV_TOP, 'limit_req zone=perip burst=20 nodelay;'))] });
    }
    const al = hl('access_log').find((a) => { const t = toks(a); return t[0] && t[0] !== 'off' && !/^syslog:/.test(t[0]) && !t.some((x) => /^buffer=/.test(x)); });
    if (al) add({ rule: 'ngx-log-buffer', category: 'performance', severity: 'info', on: false, title: 'Buffer the access log', section: 'http', line: al.line, why: 'Writing one log line per request costs a syscall each. `buffer=32k flush=5s` batches them (lines can lag by up to 5 s).', ops: [ops.rep(al, `${argsOf(al)}${toks(al).length < 2 ? ' combined' : ''} buffer=32k flush=5s`)] });
    const kaDefault = (kb.changes || []).find((c) => c.kind === 'default' && c.names && c.names.includes('keepalive') && c.names.includes('upstream'));
    upstreams.forEach((u) => {
      if (kid(u, 'keepalive') || (kaDefault && gte(kaDefault.ver)) || !kids(u, 'server').length) return;
      add({ rule: 'ngx-upstream-keepalive', category: 'performance', severity: 'medium', title: `Keep connections to upstream ${toks(u)[0] || ''} open`, section: `upstream ${toks(u)[0] || ''}`, line: u.line, why: 'Without `keepalive`, every proxied request opens a new TCP connection to the backend (and exhausts ephemeral ports under load). Needs `proxy_http_version 1.1` and an empty Connection header, which this tool also sets on proxying servers.', ops: [ops.ins(u, { after: kids(u, 'server').slice(-1)[0] }, 'keepalive 32;')] });
    });
  }

  // ---- servers
  const needHdrs = [['Host', '$host'], ['X-Real-IP', '$remote_addr'], ['X-Forwarded-For', '$proxy_add_x_forwarded_for'], ['X-Forwarded-Proto', '$scheme']];
  const ports = new Map();
  servers.forEach((s) => {
    const ls = listens(s.node); const sslL = hasSslOn(s) ? ls : ls.filter(isSsl);
    ls.forEach((l) => {
      const key = (l.t[0] || '').replace(/^\*:/, '').replace(/^\[::\]:/, '').replace(/^0\.0\.0\.0:/, ''); const p = /^\d+$/.test(key) ? key : null; if (!p) return;
      const e = ports.get(p) || { servers: [], def: false, ssl: false, v6: false }; e.servers.push(s);
      if (l.t.includes('default_server') || l.t.includes('default')) e.def = true; if (isSsl(l) || hasSslOn(s)) e.ssl = true; if (/^\[/.test(l.t[0])) e.v6 = true; ports.set(p, e);
    });
    if (namesOf(s).includes('_') && (kid(s.node, 'ssl_reject_handshake') || kids(s.node, 'return').some((r) => toks(r)[0] === '444'))) return; // a catch-all that drops unknown hosts needs no hardening
    const sslOn = kid(s.node, 'ssl');
    if (sslOn && toks(sslOn)[0] === 'on') add({ rule: 'ngx-ssl-on', category: 'compatibility', severity: 'high', title: 'Replace the removed "ssl on;" directive', section: secName(s), line: sslOn.line, why: '`ssl on;` was deprecated in 1.15.0 and later removed; the `ssl` parameter of `listen` replaces it.', ops: [ops.del(sslOn, s.node), ...ls.filter((l) => !isSsl(l)).map((l) => ops.upd(l.node, (a) => `${a} ssl`))] });
    sslL.forEach((l) => {
      if (l.t.includes('http2') && gte('1.25.1')) add({ rule: 'ngx-http2-syntax', category: 'compatibility', severity: 'low', title: 'Use "http2 on;" instead of the listen parameter', section: secName(s), line: l.node.line, why: 'The `http2` parameter of `listen` is deprecated since NGINX 1.25.1; the `http2` directive replaces it (and applies to the whole server).', ops: [ops.upd(l.node, (a) => a.split(' ').filter((x) => x !== 'http2').join(' ')), ...(kid(s.node, 'http2') ? [] : [ops.ins(s.node, { after: ls[ls.length - 1].node }, 'http2 on;')])] });
    });
    if (sslL.length && !ls.some((l) => l.t.includes('http2')) && !kid(s.node, 'http2') && !hl('http2')[0] && !ls.some((l) => l.t.includes('quic'))) {
      if (gte('1.25.1')) add({ rule: 'ngx-http2', category: 'performance', severity: 'low', title: 'Enable HTTP/2', section: secName(s), line: sslL[0].node.line, why: 'HTTP/2 multiplexes requests over one connection and compresses headers, so pages with many assets load faster. Browsers use it only over TLS.', ops: [ops.ins(s.node, { after: ls[ls.length - 1].node }, 'http2 on;')] });
      else if (gte('1.9.5')) add({ rule: 'ngx-http2', category: 'performance', severity: 'low', title: 'Enable HTTP/2', section: secName(s), line: sslL[0].node.line, why: 'HTTP/2 multiplexes requests over one connection, so pages with many assets load faster.', ops: sslL.map((l) => ops.upd(l.node, (a) => `${a} http2`)) });
    }
    const sp = kid(s.node, 'ssl_protocols');
    if (sp && toks(sp).some((t) => OLD_PROTO.test(t))) add({ rule: 'ngx-tls-protocols', category: 'security', severity: 'high', title: 'Drop legacy TLS versions', section: secName(s), line: sp.line, why: 'SSLv3, TLS 1.0 and 1.1 are deprecated and broken.', ops: [ops.rep(sp, `TLSv1.2${gte('1.13.0') ? ' TLSv1.3' : ''}`)] });
    const sc = kid(s.node, 'ssl_ciphers');
    if (sc && WEAK.test(argsOf(sc))) add({ rule: 'ngx-tls-ciphers', category: 'security', severity: 'high', title: 'Replace weak ciphers', section: secName(s), line: sc.line, why: 'RC4, 3DES, MD5, NULL and EXPORT suites are broken or deprecated.', ops: [ops.rep(sc, CIPHERS)] });
    // security headers on TLS servers
    const headerNames = (nd) => kids(nd, 'add_header').map((a) => ({ n: a, name: String(toks(a)[0] || '').toLowerCase(), always: toks(a).includes('always') }));
    const have = new Set([...headerNames(s.node).map((h) => h.name), ...hl('add_header').map((a) => String(toks(a)[0]).toLowerCase())]);
    if (sslL.length) {
      const hdrs = [
        ['strict-transport-security', 'Strict-Transport-Security "max-age=31536000" always', 'ngx-hsts', 'medium', true, 'Send HSTS (Strict-Transport-Security)', 'Tells browsers to use HTTPS only for this host for a year, defeating downgrade and cookie-stripping attacks. Add `includeSubDomains` / `preload` only once every subdomain is HTTPS.'],
        ['x-content-type-options', 'X-Content-Type-Options "nosniff" always', 'ngx-nosniff', 'low', true, 'Send X-Content-Type-Options: nosniff', 'Stops browsers guessing a different content type than the server sent, which blocks a class of XSS via uploaded files.'],
        ['referrer-policy', 'Referrer-Policy "strict-origin-when-cross-origin" always', 'ngx-referrer', 'info', false, 'Send Referrer-Policy', 'Stops full URLs (which can contain tokens) leaking to other sites in the Referer header.'],
        ['x-frame-options', 'X-Frame-Options "SAMEORIGIN" always', 'ngx-xfo', 'info', false, 'Send X-Frame-Options', 'Prevents other sites from framing yours (clickjacking). Only enable it if you do not embed your pages elsewhere.'],
      ];
      for (const [name, val, rule, sev, on, title, why] of hdrs) if (!have.has(name)) add({ rule, category: 'security', severity: sev, on, title, section: secName(s), line: sslL[0].node.line, why, ops: [ops.ins(s.node, SRV_TOP, `add_header ${val};`)] });
      headerNames(s.node).filter((h) => SEC_HEADERS.has(h.name) && !h.always).forEach((h) => add({ rule: 'ngx-header-always', category: 'security', severity: 'low', title: `Add "always" to ${toks(h.n)[0]}`, section: secName(s), line: h.n.line, why: 'Without `always`, `add_header` only applies to 2xx/3xx responses, so error pages go out without the security header.', ops: [ops.rep(h.n, `${argsOf(h.n)} always`)] }));
      if (locs(s.node).some((l) => kid(l, 'add_header'))) advice({ rule: 'ngx-header-inherit', category: 'security', severity: 'info', title: 'Locations with their own add_header drop the server-level headers', section: secName(s), line: s.node.line, why: 'In NGINX, `add_header` in a location replaces (does not extend) the headers from the server block. Repeat the security headers in those locations, or use the headers-more module.' });
    }
    // http -> https redirect
    const names = namesOf(s);
    const plainOnly = ls.length && ls.every((l) => !isSsl(l)) && ls.some((l) => /(^|:)80$/.test(l.t[0] || ''));
    if (plainOnly && names.length && sslServers.some((o) => namesOf(o).some((x) => names.includes(x)))) {
      const redirectsAlready = kids(s.node, 'return').some((r) => /^30[1-8]$/.test(toks(r)[0])) || kids(s.node, 'rewrite').some((r) => /^https:\/\//.test(unq(toks(r)[1] || ''))) || locs(s.node).some((l) => kid(l, 'return') && /^30\d$/.test(toks(kid(l, 'return'))[0]));
      const rw = kids(s.node, 'rewrite').find((r) => /^https?:\/\/\$(host|server_name)/.test(unq(toks(r)[1] || '')) && /permanent|redirect/.test(argsOf(r)));
      if (rw) add({ rule: 'ngx-redirect-return', category: 'hygiene', severity: 'low', title: 'Use return 301 for the HTTPS redirect', section: secName(s), line: rw.line, why: '`return` stops processing immediately and needs no regular expression; `rewrite ... permanent` is slower and easier to get wrong.', ops: [ops.to(rw, 'return', '301 https://$host$request_uri')] });
      else if (!redirectsAlready && !locs(s.node).length && !kid(s.node, 'proxy_pass')) add({ rule: 'ngx-https-redirect', category: 'security', severity: 'medium', title: 'Redirect HTTP to HTTPS', section: secName(s), line: ls[0].node.line, why: 'This name is served over TLS elsewhere, but its plain-HTTP server does not redirect, so users and bots can use the site unencrypted.', ops: [ops.ins(s.node, 'end', 'return 301 https://$host$request_uri;')] });
      else if (!redirectsAlready) advice({ rule: 'ngx-https-redirect', category: 'security', severity: 'medium', title: 'Plain HTTP server does not redirect to HTTPS', section: secName(s), line: ls[0].node.line, why: 'This name is served over TLS, but its port-80 server also has locations. Add `return 301 https://$host$request_uri;` in a catch-all `location /` and keep only the ACME challenge location on HTTP.' });
    }
    // static content hygiene
    const rootSet = kid(s.node, 'root') || locs(s.node).some((l) => kid(l, 'root')) || kid(s.node, 'try_files');
    locs(s.node).forEach((l) => { const a = kid(l, 'autoindex'); if (a && toks(a)[0] === 'on') add({ rule: 'ngx-autoindex', category: 'security', severity: 'medium', title: 'Turn directory listings off', section: secName(s), line: a.line, why: '`autoindex on` lets anyone browse the folder and find backups, dumps and source files. Remove it (or protect the location) unless listing is the purpose of the site.', ops: [ops.del(a, l)] }); });
    const ai = kid(s.node, 'autoindex');
    if (ai && toks(ai)[0] === 'on') add({ rule: 'ngx-autoindex', category: 'security', severity: 'medium', title: 'Turn directory listings off', section: secName(s), line: ai.line, why: '`autoindex on` exposes directory contents.', ops: [ops.del(ai, s.node)] });
    const dotBlocked = locs(s.node).some((l) => /\\\./.test(argsOf(l)) && kids(l, 'deny').length + kids(l, 'return').length > 0);
    if (rootSet && !dotBlocked) add({ rule: 'ngx-dotfiles', category: 'security', severity: 'medium', title: 'Block access to dotfiles (.git, .env, .htaccess)', section: secName(s), line: s.node.line, why: 'Deploys often leave `.git/`, `.env` or `.htpasswd` inside the web root, and a plain static server will happily serve them. `.well-known` stays open for ACME and other standards.', ops: [ops.ins(s.node, 'end', B('location', '~ /\\.(?!well-known)', [D('deny', 'all')]))] });
    locs(s.node).forEach((l) => {
      const status = kid(l, 'stub_status') || kid(l, 'api');
      if (status && !kid(l, 'allow') && !kid(l, 'auth_basic') && !kid(l, 'auth_request')) add({ rule: 'ngx-status-open', category: 'security', severity: 'high', title: 'Status endpoint is open to everyone', section: secName(s), line: l.line, why: '`stub_status` and the API reveal traffic numbers and, for the Plus API, can change the configuration. Restrict them to localhost or your monitoring network.', ops: [ops.ins(l, 'start', 'allow 127.0.0.1;'), ops.ins(l, 'start', 'deny all;')] });
    });
    // proxying
    const proxyLocs = [...locs(s.node).filter((l) => kid(l, 'proxy_pass')), ...(kid(s.node, 'proxy_pass') ? [s.node] : [])];
    if (proxyLocs.length) {
      const defs = (blk) => (blk === httpNode ? hl('proxy_set_header') : kids(blk, 'proxy_set_header'));
      const definer = (l) => (kid(l, 'proxy_set_header') ? l : kid(s.node, 'proxy_set_header') ? s.node : (hl('proxy_set_header')[0] && httpNode ? httpNode : null));
      const missingBy = new Map();
      proxyLocs.forEach((l) => {
        const d = definer(l); const have2 = new Set((d ? defs(d) : []).map((h) => String(toks(h)[0]).toLowerCase()));
        const wantConn = !have2.has('upgrade') && !have2.has('connection');
        const want = [...needHdrs, ...(wantConn ? [['Connection', '""']] : [])].filter(([n]) => !have2.has(n.toLowerCase()));
        if (!want.length) return;
        const blk = d || s.node; const cur = missingBy.get(blk) || [];
        want.forEach((w) => { if (!cur.some((x) => x[0] === w[0])) cur.push(w); }); missingBy.set(blk, cur);
      });
      for (const [blk, want] of missingBy) {
        const sectionName = blk === httpNode ? 'http' : blk === s.node ? secName(s) : `${secName(s)} location ${toks(blk).slice(0, 2).join(' ')}`;
        const existing = defs(blk);
        add({ rule: 'ngx-proxy-headers', category: 'reliability', severity: 'medium', title: 'Pass the original host, client IP and scheme to the upstream', section: sectionName, line: blk.line || s.node.line, why: 'Without these, the application sees NGINX\'s address and an internal host name: wrong client IPs in logs, broken absolute links and redirect loops behind TLS. `proxy_set_header` in a location replaces (not extends) the list from the level above, so the headers are added where they take effect. `Connection ""` is needed for upstream keep-alive.',
          ops: want.map(([n, v]) => ops.ins(blk, existing.length ? { after: existing[existing.length - 1] } : (blk === s.node ? SRV_TOP : 'end'), `proxy_set_header ${n} ${v};`)) });
      }
      if (proxyLocs.some((l) => !(kid(l, 'proxy_http_version') || kid(s.node, 'proxy_http_version') || hl('proxy_http_version')[0]))) add({ rule: 'ngx-proxy-http11', category: 'performance', severity: 'medium', title: 'Talk HTTP/1.1 to upstreams', section: secName(s), line: s.node.line, why: 'NGINX proxies with HTTP/1.0 by default, which cannot keep connections open or stream chunked responses and WebSockets.', ops: [ops.ins(s.node, SRV_TOP, 'proxy_http_version 1.1;')] });
      if (proxyLocs.some((l) => !(kid(l, 'proxy_connect_timeout') || kid(s.node, 'proxy_connect_timeout') || hl('proxy_connect_timeout')[0]))) add({ rule: 'ngx-proxy-connect', category: 'reliability', severity: 'low', title: 'Fail fast when an upstream is unreachable', section: secName(s), line: s.node.line, why: 'The default 60 s connect timeout holds the client for a minute before NGINX tries the next upstream. 5 s is generous inside a network.', ops: [ops.ins(s.node, SRV_TOP, 'proxy_connect_timeout 5s;')] });
      proxyLocs.forEach((l) => {
        const pp = kid(l, 'proxy_pass'); const to = unq(toks(pp)[0] || '');
        if (/^https:\/\//.test(to) && !(kid(l, 'proxy_ssl_verify') || kid(s.node, 'proxy_ssl_verify') || hl('proxy_ssl_verify')[0])) advice({ rule: 'ngx-proxy-ssl-verify', category: 'security', severity: 'medium', title: 'Upstream TLS certificates are not verified', section: secName(s), line: pp.line, why: 'NGINX does not verify the certificate of an HTTPS upstream unless `proxy_ssl_verify on;` and `proxy_ssl_trusted_certificate` are set, so the connection is encrypted but not authenticated.' });
        if (l !== s.node && l.children.some((c) => c.t === 'dir' && c.name === 'if')) advice({ rule: 'ngx-if-evil', category: 'reliability', severity: 'low', title: '"if" inside a proxying location', section: secName(s), line: l.line, why: '`if` in a location is evaluated in the rewrite phase and interacts badly with other directives (“if is evil”). Prefer `map`, `try_files` or separate locations.' });
      });
    }
  });
  // a catch-all server for unknown Host headers
  if (httpNode) {
    const firstServer = httpNode.children.find((c) => c.t === 'dir' && c.name === 'server');
    for (const [port, e] of ports) {
      const named = e.servers.every((s) => { const t = namesOf(s); return t.length && t.every((x) => x !== '_' && x !== '""' && x !== "''"); });
      if (e.def || !named || !firstServer) continue;
      if (e.ssl && !(exists('ssl_reject_handshake') && gte('1.19.4'))) { advice({ rule: 'ngx-default-server', category: 'security', severity: 'low', title: `No default_server on port ${port} (TLS)`, section: 'http', line: firstServer.line, why: 'Unknown host names fall through to your first site. A catch-all `default_server` with `ssl_reject_handshake on;` needs NGINX 1.19.4 or newer.' }); continue; }
      const body = [D('listen', `${port}${e.ssl ? ' ssl' : ''} default_server`), ...(e.v6 ? [D('listen', `[::]:${port}${e.ssl ? ' ssl' : ''} default_server`)] : []), D('server_name', '_'), ...(e.ssl ? [D('ssl_reject_handshake', 'on')] : [D('return', '444')])];
      add({ rule: 'ngx-default-server', category: 'security', severity: 'low', title: `Add a catch-all default server on port ${port}`, section: 'http', line: firstServer.line, why: 'Requests whose Host header matches none of your sites (scanners hitting the IP, typo domains) currently fall through to your first site. A default server answers them with nothing (444) so other sites are not exposed under the wrong name.', ops: [ops.ins(httpNode, { before: firstServer }, B('server', '', body))] });
    }
  }
  const catRank = { security: 0, reliability: 1, compatibility: 2, performance: 3, observability: 4, hygiene: 5 };
  changes.sort((a, b) => catRank[a.category] - catRank[b.category]);
  return {
    product: 'nginx', target, versionKnown, normalized, changes,
    render(enabled) { changes.forEach((c) => { if (c.auto && enabled(c)) c.ops.forEach((o) => o.run()); }); return parsed.map((f) => ({ name: f.name, content: print(f.root) })); },
  };
}

module.exports = { analyze, parse, print };

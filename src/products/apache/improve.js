'use strict';
/**
 * Config Doctor, Apache side. The files are kept as logical lines (comments, blank lines and indentation untouched);
 * rules look at the include-expanded tree (parse.js) and record edits against those lines: insert before / after a
 * line, at the end of a section or file, replace a directive, delete a line. Nothing is proposed that is already there,
 * so running improve() on the output proposes no new automatic change.
 *
 * Every rule is based on the httpd 2.4 documentation (https://httpd.apache.org/docs/2.4/) and the Mozilla
 * "intermediate" TLS profile for cipher choice.
 */
const V = require('../../validate/version');
const kb = require('../../kb/apache.json');
const { lex, astFromFiles, flat, LAYOUT, STATIC_MODULES } = require('./parse');
const { sslProtocols } = require('./audit');

const CIPHERS = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const WEAK_CIPHER = /(RC4|3DES|DES-CBC|\bDES\b|MD5|EXPORT|\bNULL\b|eNULL|ADH|^ALL$|^DEFAULT$|^HIGH$|^MEDIUM|:MEDIUM|^HIGH:!aNULL(:!MD5)?$)/i;
const STATUS_HANDLERS = /^(server-status|balancer-manager|server-info)$/i;

// ------------------------------------------------------------------------------------------------ file model
function itemsOf(name, content) {
  const src = String(content).replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  const phys = src.split('\n'); const trailingNl = src.endsWith('\n'); if (trailingNl) phys.pop();
  const items = lex(src).map((L) => ({ L, raw: phys.slice(L.line - 1, L.endLine).join('\n'), file: name }));
  // section tree: open item -> { close, children }
  const stack = [{ children: [], open: null }]; const root = stack[0];
  for (const it of items) {
    it.parent = stack[stack.length - 1];
    if (it.L.kind === 'open') { const sec = { open: it, children: [], close: null, parent: stack[stack.length - 1] }; it.sec = sec; stack[stack.length - 1].children.push(it); stack.push(sec); continue; }
    if (it.L.kind === 'close' && stack.length > 1 && stack[stack.length - 1].open.L.name.toLowerCase() === it.L.name.toLowerCase()) { stack[stack.length - 1].close = it; it.parent = stack[stack.length - 2]; stack.pop(); continue; }
    stack[stack.length - 1].children.push(it);
  }
  const byLine = new Map(items.map((it) => [it.L.line, it]));
  const tab = items.some((it) => /^\t/.test(it.L.indent));
  return { name, items, root, byLine, tab, trailingNl };
}

function render(file, edits) {
  const out = [];
  const before = new Map(); const after = new Map(); const rep = new Map(); const del = new Set(); const end = [];
  for (const e of edits) {
    if (e.kind === 'before') (before.get(e.item) || before.set(e.item, []).get(e.item)).push(e.text);
    else if (e.kind === 'after') (after.get(e.item) || after.set(e.item, []).get(e.item)).push(e.text);
    else if (e.kind === 'rep') rep.set(e.item, e.text);
    else if (e.kind === 'del') del.add(e.item);
    else if (e.kind === 'end') end.push(e.text);
  }
  for (const it of file.items) {
    (before.get(it) || []).forEach((t) => out.push(t));
    if (!del.has(it)) out.push(rep.has(it) ? rep.get(it) : it.raw);
    (after.get(it) || []).forEach((t) => out.push(t));
  }
  if (end.length) { if (out.length && out[out.length - 1].trim() !== '') out.push(''); out.push('# Server-wide settings added by the GateLight Config Doctor'); end.forEach((t) => out.push(t)); }
  return `${out.join('\n')}${file.trailingNl || end.length ? '\n' : ''}`;
}

// ------------------------------------------------------------------------------------------------ analysis
function improve({ files, version } = {}) {
  const input = (Array.isArray(files) ? files : [{ name: 'httpd.conf', content: String(files || '') }]).map((f) => ({ name: String(f.name).replace(/\\/g, '/').replace(/^\/+/, ''), content: String(f.content || '') }));
  const models = new Map(input.map((f) => [f.name, itemsOf(f.name, f.content)]));
  const versionKnown = Boolean(version);
  const target = (V.parse(version) && V.parse(version)[0] === 2 && V.parse(version)[1] === 4) ? V.parse(version).join('.') : kb.latest;
  const gte = (v) => V.gte(target, v);
  let parsed;
  try { parsed = astFromFiles(input); } catch (e) { parsed = { ast: [], main: input[0], layout: 'unknown', files: [] }; }
  const { ast } = parsed;
  const layout = parsed.layout || 'unknown'; const Lay = LAYOUT[layout] || LAYOUT.unknown;
  // astFromFiles may strip a shared top folder from names; map back to our models
  const modelOf = (fileName) => models.get(fileName) || [...models.values()].find((m) => m.name.endsWith(`/${fileName}`) || fileName.endsWith(`/${m.name}`));
  const mainModel = modelOf(parsed.main ? parsed.main.name : input[0].name) || models.get(input[0].name);
  const itemOf = (n) => { const m = modelOf(n.file); return m ? m.byLine.get(n.line) : null; };

  const loaded = new Set(STATIC_MODULES[layout] || []); let hasLoad = false;
  const all = [];
  (function w(nodes, chain) { for (const n of nodes) { if (n.inactive) continue; if (n.lname === 'loadmodule') { hasLoad = true; loaded.add(n.args[0]); } all.push({ n, chain }); if (n.children) w(n.children, n.cond ? chain : [...chain, n]); } })(ast, []);
  const modOk = (id) => !hasLoad || loaded.has(id);
  const enable = (m) => (layout === 'debian' ? `\`a2enmod ${m}\`` : `LoadModule ${m}_module modules/mod_${m}.so${layout === 'rhel' ? ' (in /etc/httpd/conf.modules.d/)' : ''}`);
  const topLevel = (x) => !x.chain.length;
  const dirs = (lname, pred = () => true) => all.filter((x) => x.n.lname === lname && pred(x));
  const vhosts = all.filter((x) => x.n.lname === 'virtualhost' && x.n.section);
  const kidsOf = (node) => flat(node.children || []);
  const kid = (node, lname) => kidsOf(node).filter((c) => c.lname === lname);
  const sslOn = (vh) => { const s = kid(vh.n, 'sslengine').pop(); if (s) return /^on$/i.test(s.args[0] || ''); const g = dirs('sslengine', topLevel).pop(); return Boolean(g && /^on$/i.test(g.n.args[0] || '')); };
  const sslVh = vhosts.filter(sslOn);
  const vhName = (vh) => { const s = kid(vh.n, 'servername').pop(); return `<VirtualHost ${vh.n.args.join(' ')}>${s ? ` ${s.args[0]}` : ''}`; };

  const changes = []; let seq = 0;
  const add = (c) => { changes.push({ key: `${c.rule}:${++seq}`, auto: true, on: true, severity: 'medium', ...c, ops: (c.ops || []).filter(Boolean) }); };
  const advice = (c) => add({ ...c, auto: false, on: false, ops: [] });

  // ---- edit helpers (ops carry what the UI shows plus what render() applies)
  const indentIn = (sec, model) => {
    const child = sec.children.find((c) => c.L.kind !== 'blank' && c.L.kind !== 'comment');
    if (child) return child.L.indent;
    const base = sec.open ? sec.open.L.indent : '';
    return base + (model.tab ? '\t' : '    ');
  };
  const ops = {
    /** insert at the end of a section (before its closing tag), or at the end of the file for the top level */
    inSection: (node, text) => {
      const it = itemOf(node); const model = modelOf(node.file);
      if (!it || !it.sec || !it.sec.close) return null;
      return { kind: 'add', text, _m: model, _e: { kind: 'before', item: it.sec.close, text: `${indentIn(it.sec, model)}${text}` } };
    },
    /** insert right after a directive, same indentation */
    after: (node, text) => { const it = itemOf(node); if (!it) return null; return { kind: 'add', text, _m: modelOf(node.file), _e: { kind: 'after', item: it, text: `${it.L.indent}${text}` } }; },
    /** server level: at the end of the main file (later directives win for single-value server settings) */
    server: (text) => ({ kind: 'add', text, _m: mainModel, _e: { kind: 'end', text } }),
    rep: (node, text) => { const it = itemOf(node); if (!it || it.L.endLine !== it.L.line) return null; return { kind: 'mod', before: it.L.text, text, _m: modelOf(node.file), _e: { kind: 'rep', item: it, text: `${it.L.indent}${text}` } }; },
    /** append arguments to a one-line directive, keeping its original spelling and quotes */
    append: (node, extra) => { const it = itemOf(node); if (!it || it.L.endLine !== it.L.line) return null; const text = `${it.L.text} ${extra}`; return { kind: 'mod', before: it.L.text, text, _m: modelOf(node.file), _e: { kind: 'rep', item: it, text: `${it.L.indent}${text}` } }; },
    del: (node) => { const it = itemOf(node); if (!it) return null; return { kind: 'del', before: it.L.text, _m: modelOf(node.file), _e: { kind: 'del', item: it } }; },
  };
  const at = (x) => ({ line: x.n.line, file: x.n.file });
  const q = (s) => (/[\s"]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s);

  // ---------------- server-wide hardening
  const lastTop = (lname) => dirs(lname, (x) => !x.chain.some((c) => c.lname === 'virtualhost' || /^(location|directory|files|proxy)/.test(c.lname))).pop();
  const tok = lastTop('servertokens');
  if (!tok) add({ rule: 'ap-server-tokens', category: 'security', severity: 'medium', title: 'Hide the httpd version (ServerTokens Prod)', section: 'server', line: null, why: 'The default `ServerTokens Full` puts the httpd version, OS and modules into every Server header, which makes matching the server against known vulnerabilities trivial.', ops: [ops.server('ServerTokens Prod')] });
  else if (!/^prod(uctonly)?$/i.test(tok.n.args[0] || '')) add({ rule: 'ap-server-tokens', category: 'security', severity: 'medium', title: 'Hide the httpd version (ServerTokens Prod)', section: 'server', ...at(tok), why: `\`ServerTokens ${tok.n.args[0]}\` reveals version details in every response header.`, ops: [ops.rep(tok.n, 'ServerTokens Prod')] });
  const sigs = dirs('serversignature');
  sigs.filter((x) => !/^off$/i.test(x.n.args[0] || '')).forEach((x) => add({ rule: 'ap-server-signature', category: 'security', severity: 'low', title: 'Turn the server signature off', section: x.chain.length ? `<${x.chain[x.chain.length - 1].name}>` : 'server', ...at(x), why: 'With `ServerSignature On` error pages and listings end with the server version and name.', ops: [ops.rep(x.n, 'ServerSignature Off')] }));
  if (!sigs.length) add({ rule: 'ap-server-signature', category: 'security', severity: 'low', title: 'Turn the server signature off', section: 'server', line: null, why: 'The default is Off, but distribution configs often turn it on in an included file; stating it explicitly keeps error pages free of version information.', on: false, ops: [ops.server('ServerSignature Off')] });
  const trace = lastTop('traceenable');
  if (!trace) add({ rule: 'ap-trace', category: 'security', severity: 'low', title: 'Disable the TRACE method', section: 'server', line: null, why: 'TraceEnable defaults to On; TRACE echoes requests (including cookies added by proxies) back to the client and is only useful for debugging.', ops: [ops.server('TraceEnable Off')] });
  else if (!/^off$/i.test(trace.n.args[0] || '')) add({ rule: 'ap-trace', category: 'security', severity: 'low', title: 'Disable the TRACE method', section: 'server', ...at(trace), why: 'TRACE echoes requests back to the client.', ops: [ops.rep(trace.n, 'TraceEnable Off')] });
  for (const x of dirs('proxyrequests')) if (/^on$/i.test(x.n.args[0] || '')) add({ rule: 'ap-open-proxy', category: 'security', severity: 'high', title: 'Close the open forward proxy (ProxyRequests Off)', section: 'server', ...at(x), why: '`ProxyRequests On` lets clients use this server to reach any host. Reverse proxying (ProxyPass) does not need it.', ops: [ops.rep(x.n, 'ProxyRequests Off')] });

  // ---------------- TLS
  const tlsUsed = sslVh.length > 0 || dirs('sslcertificatefile').length > 0;
  if (tlsUsed) {
    const goodProto = `-all +TLSv1.2${gte('2.4.36') ? ' +TLSv1.3' : ''}`;
    const protos = dirs('sslprotocol');
    protos.forEach((x) => {
      const on = sslProtocols(x.n.args);
      if (on.some((p) => /^(SSLv3|TLSv1|TLSv1\.1)$/.test(p))) add({ rule: 'ap-ssl-protocol', category: 'security', severity: 'high', title: 'Allow only TLS 1.2 and 1.3', section: x.chain.length ? vhName({ n: x.chain[x.chain.length - 1] }) : 'server', ...at(x), why: `\`SSLProtocol ${x.n.args.join(' ')}\` still enables ${on.filter((p) => /^(SSLv3|TLSv1|TLSv1\.1)$/.test(p)).join(', ')}, deprecated by RFC 8996. ${gte('2.4.36') ? 'TLS 1.3 needs httpd 2.4.36+ and OpenSSL 1.1.1+.' : 'Your target is older than 2.4.36, so TLS 1.3 is left out.'}`, ops: [ops.rep(x.n, `SSLProtocol ${goodProto}`)] });
    });
    if (!protos.length) add({ rule: 'ap-ssl-protocol', category: 'security', severity: 'high', title: 'Allow only TLS 1.2 and 1.3', section: 'server', line: null, why: 'Without SSLProtocol the default "all -SSLv3" also enables TLS 1.0 and 1.1 where OpenSSL allows them.', ops: [ops.server(`SSLProtocol ${goodProto}`)] });
    const ciphers = dirs('sslciphersuite').filter((x) => !/^TLSv1\.3$/i.test(x.n.args[0] || '') && x.n.args.length);
    ciphers.forEach((x) => { const v = x.n.args[x.n.args.length - 1]; if (v !== CIPHERS && WEAK_CIPHER.test(v)) add({ rule: 'ap-ssl-ciphers', category: 'security', severity: 'medium', title: 'Use modern AEAD cipher suites', section: 'server', ...at(x), why: `\`${v}\` lets clients negotiate CBC-mode (or weaker) ciphers. The Mozilla "intermediate" list keeps compatibility with every current client and only offers forward-secret AEAD suites.`, ops: [ops.rep(x.n, `SSLCipherSuite ${CIPHERS}`)] }); });
    if (!ciphers.length) add({ rule: 'ap-ssl-ciphers', category: 'security', severity: 'medium', title: 'Use modern AEAD cipher suites', section: 'server', line: null, why: 'The compiled-in default cipher list depends on the OpenSSL build and may include CBC suites.', ops: [ops.server(`SSLCipherSuite ${CIPHERS}`)] });
    dirs('sslhonorcipherorder').filter((x) => /^on$/i.test(x.n.args[0] || '')).forEach((x) => add({ rule: 'ap-ssl-honor-order', category: 'security', severity: 'low', on: true, title: 'Let clients pick among the (all strong) ciphers', section: 'server', ...at(x), why: 'With only AEAD suites enabled, client preference (e.g. ChaCha20 on phones without AES hardware) is faster and as safe; Mozilla recommends SSLHonorCipherOrder off for the intermediate profile.', ops: [ops.rep(x.n, 'SSLHonorCipherOrder off')] }));
    dirs('sslcompression').filter((x) => /^on$/i.test(x.n.args[0] || '')).forEach((x) => add({ rule: 'ap-ssl-compression', category: 'security', severity: 'high', title: 'Disable TLS compression (CRIME)', section: 'server', ...at(x), why: 'TLS compression leaks secrets from encrypted traffic (CRIME attack).', ops: [ops.rep(x.n, 'SSLCompression off')] }));
    if (gte('2.4.11') && !dirs('sslsessiontickets').length) add({ rule: 'ap-ssl-tickets', category: 'security', severity: 'low', on: false, title: 'Turn TLS session tickets off', section: 'server', line: null, why: 'httpd only rotates the ticket key on restart, which weakens forward secrecy for long-running servers. Session-cache resumption keeps working.', ops: [ops.server('SSLSessionTickets off')] });
    if (gte('2.4.17') && !dirs('protocols').some((x) => x.n.args.includes('h2'))) {
      const c = { rule: 'ap-http2', category: 'performance', severity: 'low', title: 'Enable HTTP/2 (Protocols h2 http/1.1)', section: 'server', line: null, why: `HTTP/2 multiplexes all requests of a page over one TLS connection (httpd 2.4.17+, mod_http2; not with mpm_prefork).${modOk('http2_module') ? '' : ` mod_http2 is not loaded: enable it with ${enable('http2')} first.`}` };
      if (modOk('http2_module')) add({ ...c, ops: [ops.server('Protocols h2 http/1.1')] }); else advice(c);
    }
  }

  // ---------------- headers (mod_headers needed)
  const headersOk = modOk('headers_module');
  const headerSet = (node, name) => kidsOf(node).some((c) => /^header$/i.test(c.name) && c.args.some((a) => a.toLowerCase() === name));
  const anyHeader = (name) => all.some((x) => /^header$/i.test(x.n.name) && x.n.args.some((a) => a.toLowerCase() === name));
  const topHeader = (name) => dirs('header', (x) => !x.chain.length && x.n.args.some((a) => a.toLowerCase() === name)).length > 0;
  for (const vh of sslVh) {
    if (!headerSet(vh.n, 'strict-transport-security') && !topHeader('strict-transport-security')) {
      const c = { rule: 'ap-hsts', category: 'security', severity: 'medium', title: 'Send HSTS (Strict-Transport-Security)', section: vhName(vh), line: vh.n.line, file: vh.n.file, why: `Tells browsers to use HTTPS for this site from now on, so the first plain-HTTP request (and SSL stripping) is avoided.${headersOk ? '' : ` Needs mod_headers: ${enable('headers')}.`}` };
      if (headersOk) add({ ...c, ops: [ops.inSection(vh.n, 'Header always set Strict-Transport-Security "max-age=63072000"')] }); else advice(c);
    }
  }
  if (vhosts.length || dirs('proxypass').length) {
    const hdrs = [['x-content-type-options', 'Header always set X-Content-Type-Options "nosniff"', 'ap-nosniff', 'low', true, 'Send X-Content-Type-Options: nosniff', 'Stops browsers from guessing content types (MIME sniffing), which can turn uploads into scripts.'],
      ['referrer-policy', 'Header always set Referrer-Policy "strict-origin-when-cross-origin"', 'ap-referrer', 'info', false, 'Send a Referrer-Policy', 'Limits how much of your URLs is sent to other sites.'],
      ['x-frame-options', 'Header always set X-Frame-Options "SAMEORIGIN"', 'ap-xfo', 'info', false, 'Send X-Frame-Options', 'Prevents other sites from framing yours (clickjacking). Only enable it if you do not embed your pages elsewhere.']];
    for (const [name, text, rule, sev, on, title, why] of hdrs) {
      if (anyHeader(name)) continue;
      const c = { rule, category: 'security', severity: sev, on, title, section: 'server', line: null, why: `${why} Set at server level, mod_headers merges it into every virtual host.${headersOk ? '' : ` Needs mod_headers: ${enable('headers')}.`}` };
      if (headersOk) add({ ...c, ops: [ops.server(text)] }); else advice(c);
    }
  }

  // ---------------- per virtual host: proxy headers, ProxyPassReverse, redirect
  const sslNames = new Set(sslVh.flatMap((v) => [...kid(v.n, 'servername'), ...kid(v.n, 'serveralias')].flatMap((d) => d.args.map((a) => a.replace(/:\d+$/, '').toLowerCase()))));
  const topPP = dirs('proxypreservehost', (x) => !x.chain.length).length > 0;
  for (const vh of vhosts) {
    const inside = all.filter((x) => x.chain.includes(vh.n));
    const pps = inside.filter((x) => (x.n.lname === 'proxypass' || x.n.lname === 'proxypassmatch') && x.n.args.some((a) => /^(https?|balancer|h2c?):\/\//i.test(a)));
    const rwP = inside.filter((x) => x.n.lname === 'rewriterule' && /\[[^\]]*\bP\b/i.test(x.n.args[2] || ''));
    const proxies = pps.length + rwP.length > 0;
    if (proxies && !kid(vh.n, 'proxypreservehost').length && !topPP) add({ rule: 'ap-preserve-host', category: 'reliability', severity: 'medium', title: 'Pass the original Host header to the backend', section: vhName(vh), line: vh.n.line, file: vh.n.file, why: 'By default httpd sends the backend\'s own host name, so applications build wrong absolute URLs and redirects, and name-based backends serve the wrong site.', ops: [ops.inSection(vh.n, 'ProxyPreserveHost On')] });
    if (proxies && sslOn(vh) && !inside.some((x) => x.n.lname === 'requestheader' && x.n.args.some((a) => /^x-forwarded-proto$/i.test(a))) && !dirs('requestheader', (x) => !x.chain.length && x.n.args.some((a) => /^x-forwarded-proto$/i.test(a))).length) {
      const c = { rule: 'ap-forwarded-proto', category: 'reliability', severity: 'medium', title: 'Tell the backend the request came over HTTPS', section: vhName(vh), line: vh.n.line, file: vh.n.file, why: `mod_proxy adds X-Forwarded-For/-Host/-Server but not the scheme, so applications behind TLS termination generate http:// links and redirect loops.${headersOk ? '' : ` Needs mod_headers: ${enable('headers')}.`}` };
      if (headersOk) add({ ...c, ops: [ops.inSection(vh.n, 'RequestHeader set X-Forwarded-Proto "https"')] }); else advice(c);
    }
  }
  // ProxyPassReverse for every ProxyPass to http(s)/balancer (server or vhost level, or inside <Location>)
  for (const x of dirs('proxypass')) {
    const inLoc = x.chain.some((c) => c.lname === 'location');
    const url = inLoc ? x.n.args[0] : x.n.args[1];
    if (!url || url === '!' || !/^(https?|balancer):\/\//i.test(url)) continue;
    const scope = inLoc ? x.chain[x.chain.length - 1] : (x.chain.find((c) => c.lname === 'virtualhost') || null);
    const sibl = scope ? kidsOf(scope) : flat(ast);
    const p = inLoc ? null : x.n.args[0];
    const has = sibl.some((c) => c.lname === 'proxypassreverse' && (inLoc ? true : c.args[0] === p)) || (inLoc && all.some((y) => y.n.lname === 'proxypassreverse' && y.n.args[0] === scope.args[0]));
    if (has) continue;
    const rurl = url.replace(/(\/\/)[^/@]*@/, '$1'); // Location headers never carry the credentials
    add({ rule: 'ap-proxypassreverse', category: 'reliability', severity: 'medium', title: `Add ProxyPassReverse for ${inLoc ? scope.args[0] : p}`, section: scope ? `<${scope.name} ${scope.args.join(' ')}>` : 'server', ...at(x), why: 'Redirects from the backend (Location headers) would otherwise point clients at the internal address. ProxyPassReverse rewrites them back to this server.', ops: [ops.after(x.n, inLoc ? `ProxyPassReverse ${q(rurl)}` : `ProxyPassReverse ${q(p)} ${q(rurl)}`)] });
  }
  // HTTP -> HTTPS redirect for plain virtual hosts of names that have a TLS virtual host
  for (const vh of vhosts.filter((v) => !sslOn(v))) {
    const names = [...kid(vh.n, 'servername'), ...kid(vh.n, 'serveralias')].flatMap((d) => d.args.map((a) => a.replace(/:\d+$/, '').toLowerCase()));
    if (!names.some((n) => sslNames.has(n))) continue;
    const inside = all.filter((x) => x.chain.includes(vh.n));
    const redirects = inside.some((x) => /^redirect(match|permanent)?$/.test(x.n.lname) && x.n.args.some((a) => /^https:\/\//i.test(a))) || inside.some((x) => x.n.lname === 'rewriterule' && /^https:\/\//i.test(x.n.args[1] || '') && /\bR\b|R=/i.test(x.n.args[2] || ''));
    if (redirects) continue;
    const primary = (kid(vh.n, 'servername')[0] || { args: [names[0]] }).args[0].replace(/:\d+$/, '');
    const c = { rule: 'ap-https-redirect', category: 'security', severity: 'medium', title: 'Redirect HTTP to HTTPS', section: vhName(vh), line: vh.n.line, file: vh.n.file, why: 'This name is served over TLS by another virtual host, but plain HTTP still serves content, so users and bots can use the site unencrypted.' };
    const proxied = inside.some((x) => /^proxypass(match)?$/.test(x.n.lname) || (x.n.lname === 'rewriterule'));
    if (!proxied) add({ ...c, ops: [ops.inSection(vh.n, `Redirect permanent "/" "https://${primary}/"`)] });
    else advice({ ...c, why: `${c.why} ProxyPass / RewriteRule run before mod_alias, so replace them with \`Redirect permanent "/" "https://${primary}/"\` in this virtual host.` });
  }

  // ---------------- directory listings, status endpoints, 2.2 access control
  for (const x of dirs('options')) {
    const a = x.n.args;
    if (!a.some((t) => /^\+?indexes$/i.test(t))) { if (a.some((t) => /^all$/i.test(t))) advice({ rule: 'ap-indexes', category: 'security', severity: 'medium', title: 'Options All includes directory listings', section: x.chain.length ? `<${x.chain[x.chain.length - 1].name} ${x.chain[x.chain.length - 1].args.join(' ')}>` : 'server', ...at(x), why: 'Replace `All` with the options you need (usually `FollowSymLinks`).' }); continue; }
    const rest = a.filter((t) => !/^\+?indexes$/i.test(t));
    add({ rule: 'ap-indexes', category: 'security', severity: 'medium', title: 'Turn directory listings off', section: x.chain.length ? `<${x.chain[x.chain.length - 1].name} ${x.chain[x.chain.length - 1].args.join(' ')}>` : 'server', ...at(x), why: 'With `Indexes`, a folder without an index file is listed, exposing backups, dumps and source files.', ops: [ops.rep(x.n, `Options ${rest.length ? rest.join(' ') : (a.some((t) => /^[+-]/.test(t)) ? '-Indexes' : 'None')}`)] });
  }
  for (const x of dirs('sethandler')) {
    if (!STATUS_HANDLERS.test(x.n.args[0] || '')) continue;
    const sec = x.chain[x.chain.length - 1]; if (!sec) continue;
    const ks = kidsOf(sec);
    const restricted = ks.some((c) => c.lname === 'require' && !(/^all$/i.test(c.args[0] || '') && /^granted$/i.test(c.args[1] || ''))) || ks.some((c) => c.lname === 'authtype') || ks.some((c) => (c.section && /^require(all|any)$/.test(c.lname)));
    const open = ks.filter((c) => c.lname === 'require' && /^all$/i.test(c.args[0] || '') && /^granted$/i.test(c.args[1] || ''));
    if (restricted && !open.length) continue;
    add({ rule: 'ap-status-restrict', category: 'security', severity: 'high', title: `Restrict ${x.n.args[0]} to the local machine`, section: `<${sec.name} ${sec.args.join(' ')}>`, ...at(x), why: /balancer-manager/i.test(x.n.args[0]) ? 'balancer-manager can disable, drain and re-weight members with plain HTTP requests.' : 'The status page reveals client addresses, URLs and load. `Require local` allows only connections from this host; add `Require ip` lines for your monitoring network.', ops: open.length ? open.map((c) => ops.rep(c, 'Require local')) : [ops.after(x.n, 'Require local')] });
  }
  // the two classic 2.2 idioms convert 1:1 (upgrading.html#access)
  const blocks = new Map();
  for (const x of all) if (['order', 'allow', 'deny', 'satisfy'].includes(x.n.lname)) { const s = x.chain[x.chain.length - 1] || null; (blocks.get(s) || blocks.set(s, []).get(s)).push(x); }
  for (const [sec, list] of blocks) {
    const text = list.map((x) => `${x.n.lname} ${x.n.args.join(' ').toLowerCase()}`).sort().join('|');
    const label = sec ? `<${sec.name} ${sec.args.join(' ')}>` : 'server';
    const hasRequire = sec && kidsOf(sec).some((c) => c.lname === 'require');
    let repl = null;
    if (!hasRequire && text === ['allow from all', 'order allow,deny'].sort().join('|')) repl = 'Require all granted';
    if (!hasRequire && text === ['deny from all', 'order deny,allow'].sort().join('|')) repl = 'Require all denied';
    if (!hasRequire && text === ['allow from all', 'order deny,allow'].sort().join('|')) repl = 'Require all granted';
    const first = list.sort((a, b) => a.n.line - b.n.line)[0];
    const c = { rule: 'ap-access-compat', category: 'compatibility', severity: 'medium', title: 'Replace Order/Allow/Deny with Require', section: label, ...at(first), why: 'Order / Allow / Deny come from httpd 2.2 and only work through mod_access_compat; mixed with Require they give surprising results. httpd 2.4 uses `Require` (mod_authz_host).' };
    if (repl) add({ ...c, ops: [ops.rep(first.n, repl), ...list.filter((x) => x !== first).map((x) => ops.del(x.n))] });
    else advice({ ...c, why: `${c.why} Rewrite this block by hand, e.g. \`Require ip 10.0.0.0/8\` or \`Require host example.org\`.` });
  }

  // ---------------- proxy reliability
  const proxying = dirs('proxypass').length + dirs('proxypassmatch').length + dirs('balancermember').length > 0;
  if (proxying && !dirs('proxytimeout').length) add({ rule: 'ap-proxy-timeout', category: 'reliability', severity: 'low', title: 'Set an explicit backend timeout (ProxyTimeout)', section: 'server', line: null, why: `Without ProxyTimeout a hung backend holds the client until the core Timeout (${layout === 'debian' ? '300 s in the Debian apache2.conf' : '60 s by default'}). One explicit value makes failures predictable.`, ops: [ops.server('ProxyTimeout 60')] });
  if (!dirs('limitrequestbody').length && (vhosts.length || proxying)) add({ rule: 'ap-limit-body', category: 'reliability', severity: gte('2.4.54') ? 'low' : 'medium', on: !gte('2.4.54'), title: 'Limit the request body size', section: 'server', line: null, why: gte('2.4.54') ? 'Since 2.4.54 the default is 1 GiB; a lower limit protects backends from huge uploads.' : 'Before 2.4.54 request bodies are unlimited by default (LimitRequestBody 0), so one client can stream gigabytes into a backend.', ops: [ops.server('LimitRequestBody 10485760')] });
  // health checks on balancer members
  const hcOk = modOk('proxy_hcheck_module') && gte('2.4.21');
  for (const x of dirs('balancermember')) {
    if (x.n.args.some((a) => /^hc(method|template)=/i.test(a)) || x.n.args.some((a) => /^status=.*H/i.test(a))) continue;
    const c = { rule: 'ap-hcheck', category: 'reliability', severity: 'low', title: `Health-check ${x.n.args.find((a) => /:\/\//.test(a)) || 'member'}`, section: x.chain.length ? `<${x.chain[x.chain.length - 1].name} ${x.chain[x.chain.length - 1].args.join(' ')}>` : 'server', ...at(x), why: 'Without active checks a dead member is noticed only when real requests fail. mod_proxy_hcheck (2.4.21+) probes members in the background; adjust hcuri to a cheap endpoint that answers 2xx without authentication.' };
    if (hcOk) add({ ...c, on: false, ops: [ops.append(x.n, 'hcmethod=GET hcuri=/ hcinterval=10 hcpasses=2 hcfails=3')] });
    else advice({ ...c, why: `${c.why} ${gte('2.4.21') ? `Enable the module with ${enable('proxy_hcheck')}.` : 'Your target is older than 2.4.21.'}` });
  }
  // sticky sessions without the cookie
  const cookieSet = all.some((x) => /^header$/i.test(x.n.name) && /set-cookie/i.test(x.n.args.join(' ')) && /BALANCER_WORKER_ROUTE/.test(x.n.args.join(' ')));
  for (const x of dirs('proxyset')) {
    const sv = x.n.args.find((a) => /^stickysession=ROUTEID/i.test(a)); if (!sv || cookieSet) continue;
    advice({ rule: 'ap-sticky-cookie', category: 'reliability', severity: 'medium', title: 'Set the ROUTEID cookie for sticky sessions', section: 'server', ...at(x), why: 'httpd does not create the ROUTEID cookie; add `Header add Set-Cookie "ROUTEID=.%{BALANCER_WORKER_ROUTE}e; path=/" env=BALANCER_ROUTE_CHANGED` to the virtual host and give every member a `route=`.' });
  }

  const catRank = { security: 0, reliability: 1, compatibility: 2, performance: 3, observability: 4, hygiene: 5 };
  changes.sort((a, b) => catRank[a.category] - catRank[b.category]);
  for (const c of changes) { if (c.auto && !c.ops.length) { c.auto = false; c.on = false; } }
  const pub = (o) => { const x = { kind: o.kind, text: o.text }; if (o.before) x.before = o.before; return x; };
  const internal = new Map(changes.map((c) => [c, c.ops]));
  for (const c of changes) c.ops = internal.get(c).map((o) => Object.assign(pub(o), { _m: o._m, _e: o._e }));
  for (const c of changes) for (const o of c.ops) { Object.defineProperty(o, '_m', { enumerable: false }); Object.defineProperty(o, '_e', { enumerable: false }); }
  return {
    product: 'apache', target, versionKnown, layout, changes,
    normalized: input.map((f) => ({ name: f.name, content: f.content })),
    notes: [`Layout: ${Lay.name}. Check the result with \`${Lay.test}\` and apply it with \`${Lay.reload}\`.`],
    render(enabled = (c) => c.on) {
      const edits = new Map();
      for (const c of changes) if (c.auto && enabled(c)) for (const o of c.ops) { const list = edits.get(o._m) || []; list.push(o._e); edits.set(o._m, list); }
      return input.map((f) => { const m = models.get(f.name); return { name: f.name, content: edits.has(m) ? render(m, edits.get(m)) : f.content }; });
    },
  };
}

module.exports = { improve, itemsOf, render, CIPHERS };

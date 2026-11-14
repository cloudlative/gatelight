'use strict';
/**
 * Version-aware validation of a Caddyfile against the knowledge base built from Caddy's source at every release tag
 * (src/kb/caddy.json, tools/kb/caddy.js):
 *
 *   1. syntax: unbalanced braces, "{" not at the end of its line, unterminated quotes / backticks / heredocs
 *   2. global options: unknown (with did-you-mean), newer than the target, removed; sub-options of servers / log / admin ...
 *   3. site addresses: scheme, port, host syntax
 *   4. directives: unknown (did-you-mean), newer than the target or removed, deprecated spellings, handler directives that
 *      are not in the directive order (plugins) used outside `route` without an `order` global option (Caddy refuses
 *      them: "directive 'x' is not an ordered HTTP handler"), undefined named matchers, unknown / too new matcher types,
 *      subdirectives of reverse_proxy (+ transport http / fastcgi), tls, log, encode, file_server, request_body ...,
 *      lb_policy names
 *   5. recommendations that depend on the target version
 */
const { kb, V, target: resolveTarget, orderFor, available, directiveDocs, optionDocs, matcherDocs, DOCS } = require('./kb');
const { suggest } = require('../../validate/suggest');
const C = require('./caddyfile');
const { structure, parseAddress, applyOrder } = require('./model');
const { isJson } = require('./json');

const NON_HANDLER = new Set(['bind', 'tls', 'log', 'handle_errors', 'import']);
const CONTAINERS = new Set(['handle', 'handle_path', 'route', 'handle_errors']);
const SUB_CHECKED = new Set(['reverse_proxy', 'tls', 'log', 'encode', 'file_server', 'request_body', 'php_fastcgi', 'acme_server', 'templates', 'push', 'metrics', 'intercept', 'timeouts', 'tracing']);
const KNOWN_PLUGINS = { rate_limit: 'github.com/mholt/caddy-ratelimit', crowdsec: 'github.com/hslatman/caddy-crowdsec-bouncer', cache: 'github.com/caddyserver/cache-handler', replace: 'github.com/caddyserver/replace-response', cgi: 'github.com/aksdb/caddy-cgi', webdav: 'github.com/mholt/caddy-webdav', jwtauth: 'github.com/ggicci/caddy-jwt', authorize: 'github.com/greenpau/caddy-security', authenticate: 'github.com/greenpau/caddy-security', coraza_waf: 'github.com/corazawaf/coraza-caddy', sablier: 'github.com/acouvreur/sablier', geoip2_vars: 'github.com/zhangjiayin/caddy-geoip2', exec: 'github.com/abiosoft/caddy-exec', cors: 'github.com/(various)', realip: 'github.com/kirsch33/realip', ntlm_transport: 'github.com/caddyserver/ntlm-transport', layer4: 'github.com/mholt/caddy-l4', dynamic_dns: 'github.com/mholt/caddy-dynamicdns', souin: 'github.com/darkweak/souin', waf: '(WAF plugin)' };
const PLUGIN_SUB = { reverse_proxy: new Set(['@']), encode: new Set(['br', 'brotli']) };

function syntaxCheck(files) {
  const out = [];
  for (const f of files) {
    if (isJson(f.content)) continue;
    const { tokens, errors } = C.lex(f.content, f.name);
    for (const e of errors) out.push({ id: 'syntax-caddy', severity: 'error', category: 'syntax', file: f.name, line: e.line, section: 'syntax', title: e.msg, detail: 'Caddy stops while lexing the Caddyfile.', fix: 'Close the quote / heredoc.', docs: `${DOCS}/caddyfile/concepts#tokens-and-quotes` });
    for (const e of C.parseTree(tokens).errors) out.push({ id: 'syntax-caddy', severity: 'error', category: 'syntax', file: e.file || f.name, line: e.line, section: 'syntax', title: e.msg, detail: /Unclosed/.test(e.msg) ? 'Caddy reports: "unexpected EOF" / "expected \'}\'".' : /after "\{"/.test(e.msg) ? 'Caddy reports: "Unexpected next token after \'{\' on same line".' : 'Caddy reports: "unexpected \'}\' because no matching opening brace".', fix: /after "\{"/.test(e.msg) ? 'Put the block content on its own lines.' : 'Balance the braces; every "{" ends its line and every "}" stands on its own line.', docs: `${DOCS}/caddyfile/concepts#blocks` });
    // "}" followed by more tokens on the same line
    tokens.forEach((t, i) => { if (!t.quoted && t.text === '}' && tokens[i + 1] && !tokens[i + 1].nl && !(tokens[i + 1].text === '}' && !tokens[i + 1].quoted)) out.push({ id: 'syntax-caddy', severity: 'error', category: 'syntax', file: f.name, line: t.line, section: 'syntax', title: 'Unexpected token after "}" on the same line', detail: 'A closing brace must be the only token on its line.', fix: 'Move the following text to the next line.', docs: `${DOCS}/caddyfile/concepts#blocks` }); });
  }
  return out;
}

function validate({ files, version } = {}) {
  const list = (Array.isArray(files) ? files : [{ name: 'Caddyfile', content: String(files || '') }]).map((f) => ({ name: String(f.name || 'Caddyfile'), content: String(f.content || '') }));
  const tgt = resolveTarget(version);
  const T = tgt.version;
  const findings = [];
  const add = (f) => findings.push({ category: 'compat', detail: '', fix: '', ...f });
  const kbOut = { generated: kb.generated, source: kb.source, latest: kb.latest };
  const done = () => { findings.sort((a, b) => (String(a.file) === String(b.file) ? (a.line || 0) - (b.line || 0) : String(a.file).localeCompare(String(b.file)))); return { target: tgt, kb: kbOut, findings }; };
  if (!list.some((f) => f.content.trim())) return done();
  const { main } = C.normalizeUpload(list);
  if (main.content.trim().startsWith('{') && /^\s*\{\s*"/.test(main.content)) {
    try { JSON.parse(main.content); add({ id: 'compat-json', severity: 'info', category: 'compat', file: main.name, line: 1, section: 'global', title: 'Caddy JSON configuration: only the JSON syntax was validated', detail: 'Directive-level checks apply to Caddyfiles.', fix: '', docs: `${DOCS}/json/` }); } catch (e) { add({ id: 'syntax-caddy', severity: 'error', category: 'syntax', file: main.name, line: Number((/line (\d+)/.exec(e.message) || [])[1]) || 1, section: 'syntax', title: `Invalid JSON: ${e.message}`, detail: 'Caddy cannot load the file.', fix: 'Fix the JSON syntax.' }); }
    return done();
  }
  findings.push(...syntaxCheck(list));
  let loaded;
  try { loaded = C.loadFiles(list); } catch (e) { add({ id: 'syntax-caddy', severity: 'error', category: 'syntax', section: 'syntax', file: main.name, line: 1, title: `Could not parse: ${e.message}` }); return done(); }
  for (const m of loaded.importsMissing) if (!m.glob) add({ id: 'compat-import-missing', severity: 'error', category: 'correctness', file: m.file, line: m.line, section: 'import', title: `import "${m.pattern}": no such snippet or file`, detail: 'Caddy stops with: File to import not found. Snippets must be defined before they are imported.', fix: 'Define the snippet, or upload the imported file.', docs: `${DOCS}/caddyfile/directives/import` });
  const { global, sites, stray } = structure(loaded.nodes);
  const allDirectives = Object.keys(kb.directives);
  const order = orderFor(T);
  const orderRules = [];

  // ---- global options
  if (global) {
    for (const nd of global.block || []) {
      const base = { file: nd.file, line: nd.line, section: 'global options' };
      const e = kb.options[nd.name];
      if (!e) {
        const near = suggest(nd.name, Object.keys(kb.options));
        add({ ...base, id: 'compat-unknown-option', severity: 'error', title: `Unknown global option "${nd.name}"`, detail: `Not a standard global option (up to ${kb.latest}). Caddy stops with: unrecognized global option: ${nd.name}. Options of plugins (e.g. layer4) need a build that includes the plugin.`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Check the spelling, or build Caddy with the plugin (xcaddy).', docs: `${DOCS}/caddyfile/options` });
        continue;
      }
      lifecycle(nd.name, e, T, base, 'global option', optionDocs(nd.name), add);
      if (nd.name === 'order') {
        orderRules.push({ dir: nd.args[0], pos: nd.args[1], ref: nd.args[2] });
        if (!['first', 'last', 'before', 'after'].includes(nd.args[1])) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: 'order needs first, last, before <directive> or after <directive>', detail: `Syntax: order <dir1> first|last|[before|after <dir2>]`, fix: `e.g. order ${nd.args[0] || 'rate_limit'} before basic_auth`, docs: optionDocs('order') });
        else if ((nd.args[1] === 'before' || nd.args[1] === 'after') && !order.includes(nd.args[2]) && !orderRules.some((r) => r.dir === nd.args[2])) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `order ${nd.args[1]} "${nd.args[2] || ''}": not an ordered directive`, detail: `The reference must be a directive in the order of Caddy ${T}.`, fix: `Pick one of: ${order.slice(0, 8).join(', ')}, …`, docs: optionDocs('order') });
      }
      if (nd.name === 'admin' && nd.args[0] && nd.args[0] !== 'off') { const a = nd.args[0].replace(/^tcp\//, ''); if (!/^(unix\/.+|[^\s]*:\d+)$/.test(a)) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `admin "${nd.args[0]}" is not a network address`, detail: 'Expected host:port (e.g. localhost:2019), unix/<path> or off.', fix: 'admin localhost:2019', docs: optionDocs('admin') }); }
      if (nd.block && e.sub) checkSubs(nd, e.sub, T, base, `global option ${nd.name}`, optionDocs(nd.name), add);
    }
  }
  const effOrder = applyOrder(order, orderRules);

  for (const s of stray) {
    if (s.name === 'import') continue;
    add({ id: 'syntax-caddy', severity: 'error', category: 'syntax', file: s.file, line: s.line, section: 'syntax', title: `"${s.name}" outside of a site block`, detail: 'Every directive belongs inside a site block; only the global options block, snippets and named routes may stand alone. The global options block must be the first block in the file.', fix: 'Move it into a site block (or into the global options block if it is a global option).', docs: `${DOCS}/caddyfile/concepts#structure` });
  }

  // ---- sites
  for (const site of sites) {
    const label = site.keys.join(', ');
    const g = { httpPort: 80, httpsPort: 443 };
    for (const k of site.keys) {
      const a = parseAddress(k, g);
      if (a.error) add({ id: 'caddy-bad-address', severity: 'error', category: 'correctness', file: site.file, line: site.line, section: label, title: `Malformed site address "${k}": ${a.error}`, detail: 'Caddy fails to adapt the config while parsing the site address.', fix: 'Use [scheme://]host[:port][/path], e.g. example.com, http://example.com:8080 or :8080.', docs: `${DOCS}/caddyfile/concepts#addresses` });
    }
    if (!site.keys.length) add({ id: 'caddy-bad-address', severity: 'error', category: 'correctness', file: site.file, line: site.line, section: label, title: 'Site block without an address', detail: 'Only the first block of the file may omit the address (it is then the global options block).', fix: 'Add the site address, or move this block to the top of the file.', docs: `${DOCS}/caddyfile/concepts#structure` });
    const defs = new Map();
    const collectDefs = (nodes) => { for (const nd of nodes) { if (nd.name.startsWith('@')) defs.set(nd.name, nd); else if (nd.block && CONTAINERS.has(nd.name)) collectDefs(nd.block); } };
    collectDefs(site.body);
    checkDirectives(site.body, { site: label, inRoute: false, defs, T, effOrder, allDirectives, orderRules, add, namedRoutes: loaded.namedRoutes });
  }
  for (const [name, nd] of loaded.namedRoutes || new Map()) {
    if (V.lt(T, '2.7.0')) add({ id: 'compat-too-new', severity: 'error', file: nd.file, line: nd.line, section: `&(${name})`, title: 'Named routes need Caddy 2.7+', detail: `You are validating against ${T}.`, fix: 'Use a snippet instead, or upgrade.', since: '2.7.0', docs: `${DOCS}/caddyfile/concepts#named-routes` });
    const defs = new Map(); for (const x of nd.block || []) if (x.name.startsWith('@')) defs.set(x.name, x);
    checkDirectives(nd.block || [], { site: `&(${name})`, inRoute: false, defs, T, effOrder, allDirectives, orderRules, add, namedRoutes: loaded.namedRoutes });
  }
  recommend({ sites, global, T, add });
  return done();
}

/** since / until / deprecation of one KB entry. */
function lifecycle(name, e, T, base, what, docs, add) {
  if (V.lt(T, e.since)) add({ ...base, id: 'compat-too-new', severity: 'error', title: `${what} "${name}" needs Caddy ${e.since}+`, detail: `It first appears in Caddy ${e.since}; ${T} does not know it and stops with an "unrecognized" error.`, fix: `Upgrade to ${e.since} or newer, or remove it.`, since: e.since, docs });
  else if (e.until && V.cmp(T, e.until) > 0) add({ ...base, id: 'compat-removed', severity: 'error', title: `${what} "${name}" was removed after Caddy ${e.until}`, detail: `It exists up to ${e.until}; ${T} rejects it.`, fix: 'Remove it or use its replacement (see the documentation).', until: e.until, docs });
}

function checkSubs(nd, subs, T, base0, owner, docs, add, prefix = '') {
  const tops = new Map();
  for (const [k, v] of Object.entries(subs)) {
    const parts = k.split('>');
    if (prefix ? parts.length === 2 && parts[0] === prefix : parts.length === 1) tops.set(prefix ? parts[1] : parts[0], v);
  }
  if (!tops.size) return;
  for (const c of nd.block || []) {
    if (!c.name || c.name.startsWith('@') || c.name === 'import') continue;
    const base = { ...base0, file: c.file, line: c.line };
    const e = tops.get(c.name);
    if (!e) {
      if (PLUGIN_SUB[owner.replace(/^directive /, '')] && (PLUGIN_SUB[owner.replace(/^directive /, '')].has(c.name) || PLUGIN_SUB[owner.replace(/^directive /, '')].has(c.name[0]))) continue;
      const near = suggest(c.name, [...tops.keys()]);
      add({ ...base, id: 'compat-unknown-subdirective', severity: 'error', title: `Unknown subdirective "${c.name}" in ${owner}`, detail: `Caddy stops with: unrecognized subdirective ${c.name}.`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : `Valid here: ${[...tops.keys()].filter((k) => available(tops.get(k), T)).slice(0, 14).join(', ')}${tops.size > 14 ? ', …' : ''}`, docs });
      continue;
    }
    lifecycle(c.name, e, T, base, `${owner} subdirective`, docs, add);
    if (c.block && !prefix) {
      const nestedKey = c.name === 'transport' ? `transport ${c.args[0] || 'http'}` : c.name;
      if ([...Object.keys(subs)].some((k) => k.startsWith(`${nestedKey}>`))) checkSubs(c, subs, T, base, `${owner} › ${nestedKey}`, docs, add, nestedKey);
    }
  }
}

function checkDirectives(nodes, ctx) {
  const { T, add, defs, effOrder, allDirectives, orderRules } = ctx;
  const ordered = new Set(effOrder);
  for (const nd of nodes) {
    if (!nd.name) continue;
    const base = { file: nd.file, line: nd.line, section: ctx.site };
    if (nd.name.startsWith('@')) { checkMatcherDef(nd, base, T, add); continue; }
    if (nd.name === 'import') continue;
    const e = kb.directives[nd.name];
    const docs = directiveDocs(nd.name);
    // matcher token
    const mt = nd.toks[1] && !nd.toks[1].quoted ? nd.toks[1].text : '';
    if (mt.startsWith('@') && !NON_HANDLER.has(nd.name) && !defs.has(mt)) add({ ...base, id: 'caddy-undefined-matcher', severity: 'error', category: 'correctness', title: `Named matcher ${mt} is not defined in this site`, detail: `Caddy stops with: unrecognized matcher name: ${mt}. Named matchers are scoped to their site block.`, fix: `Define it: ${mt} { path /... }`, docs: matcherDocs('named-matchers') });
    if (!e) {
      const near = suggest(nd.name, allDirectives);
      const plugin = KNOWN_PLUGINS[nd.name];
      if (plugin) add({ ...base, id: 'compat-third-party', severity: 'warning', title: `"${nd.name}" is a plugin directive (${plugin})`, detail: 'It is not part of standard Caddy; the binary must be built with the plugin (xcaddy build --with ...).', fix: 'Make sure your Caddy build includes the plugin (caddy list-modules).', docs: `${DOCS}/caddyfile/directives` });
      else add({ ...base, id: 'compat-unknown-directive', severity: 'error', title: `Unknown directive "${nd.name}"`, detail: `Not a standard Caddy directive (up to ${kb.latest}). Caddy stops with: unrecognized directive: ${nd.name}.`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Check the spelling; a plugin directive needs a Caddy build that includes the plugin.', docs: `${DOCS}/caddyfile/directives` });
      if (!near.length && !ctx.inRoute && !ordered.has(nd.name)) {
        add({ ...base, id: 'compat-unordered-directive', severity: 'error', title: `"${nd.name}" has no place in the directive order`, detail: `Directives from plugins are not in Caddy's default directive order, so outside a route block Caddy stops with: directive '${nd.name}' is not an ordered HTTP handler, so it cannot be used here - try placing within a route block or using the order global option.`, fix: `Add "order ${nd.name} before basic_auth" (or another position) to the global options, or wrap it in route { ... }.`, docs: `${DOCS}/caddyfile/directives#directive-order` });
      }
      if (nd.block && CONTAINERS.has(nd.name)) checkDirectives(nd.block, { ...ctx, inRoute: ctx.inRoute || nd.name === 'route' });
      continue;
    }
    lifecycle(nd.name, e, T, base, 'directive', docs, add);
    if (!available(e, T)) { if (nd.block && CONTAINERS.has(nd.name)) checkDirectives(nd.block, { ...ctx, inRoute: ctx.inRoute || nd.name === 'route' }); continue; }
    if (nd.name === 'basicauth' && V.gte(T, '2.8.0')) add({ ...base, id: 'compat-deprecated', severity: 'warning', title: '"basicauth" is deprecated since Caddy 2.8 (renamed to "basic_auth")', detail: 'It still works but logs a warning on every start.', fix: 'Rename it to basic_auth.', since: '2.8.0', docs: directiveDocs('basic_auth') });
    if (nd.name === 'skip_log' && V.gte(T, '2.8.0')) add({ ...base, id: 'compat-deprecated', severity: 'warning', title: '"skip_log" is deprecated since Caddy 2.8 (renamed to "log_skip")', detail: '', fix: 'Rename it to log_skip.', since: '2.8.0', docs: directiveDocs('log_skip') });
    if (!ctx.inRoute && !NON_HANDLER.has(nd.name) && !ordered.has(nd.name) && !['copy_response', 'copy_response_headers'].includes(nd.name)) add({ ...base, id: 'compat-unordered-directive', severity: 'error', title: `"${nd.name}" is not in the directive order of Caddy ${T}`, detail: `Caddy stops with: directive '${nd.name}' is not an ordered HTTP handler, so it cannot be used here.`, fix: `Wrap it in route { ... } or add an "order ${nd.name} ..." global option.`, docs: `${DOCS}/caddyfile/directives#directive-order` });
    if (nd.name === 'invoke' && nd.args[0] && !(ctx.namedRoutes && ctx.namedRoutes.has(nd.args[0]))) add({ ...base, id: 'caddy-undefined-route', severity: 'error', category: 'correctness', title: `invoke ${nd.args[0]}: no named route &(${nd.args[0]})`, detail: 'Caddy stops with: cannot invoke named route, which was not defined.', fix: `Define &(${nd.args[0]}) { ... } at the top level.`, docs: directiveDocs('invoke') });
    if (nd.name === 'handle_path' && !(mt.startsWith('/'))) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: 'handle_path needs a path matcher', detail: `Caddy stops with: path matcher must begin with '/'${mt ? `, got ${mt}` : ''}.`, fix: 'handle_path /prefix/* { ... }', docs });
    if ((nd.name === 'basic_auth' || nd.name === 'basicauth') && V.lt(T, '2.6.0')) for (const c of nd.block || []) if ((c.args[0] || '').startsWith('$')) add({ ...base, line: c.line, file: c.file, id: 'compat-bad-arguments', severity: 'error', title: `Caddy ${T} expects base64-encoded password hashes`, detail: 'Plain bcrypt hashes ($2a$...) are accepted since Caddy 2.6.0; older releases base64-decode the value and fail to start.', fix: 'Encode the hash with base64, or upgrade to 2.6+.', since: '2.6.0', docs: directiveDocs('basic_auth') });
    if (nd.block && SUB_CHECKED.has(nd.name) && e.sub) checkSubs(nd, e.sub, T, base, `directive ${nd.name}`, docs, add);
    if (nd.name === 'reverse_proxy' || nd.name === 'php_fastcgi') {
      for (const c of nd.block || []) {
        if (c.name === 'lb_policy' && c.args[0]) {
          const p = kb.lbPolicies[c.args[0]];
          if (!p) { const near = suggest(c.args[0], Object.keys(kb.lbPolicies)); add({ ...base, line: c.line, file: c.file, id: 'compat-bad-arguments', severity: 'error', title: `Unknown lb_policy "${c.args[0]}"`, detail: `Valid on Caddy ${T}: ${Object.keys(kb.lbPolicies).filter((k) => available(kb.lbPolicies[k], T)).join(', ')}.`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Use one of the listed policies.', docs: `${docs}#lb_policy` }); } else lifecycle(c.args[0], p, T, { ...base, line: c.line, file: c.file }, 'lb_policy', `${docs}#lb_policy`, add);
        }
        if (c.name === 'transport' && c.args[0] && !['http', 'fastcgi'].includes(c.args[0])) add({ ...base, line: c.line, file: c.file, id: 'compat-third-party', severity: 'info', title: `transport ${c.args[0]} is not a standard transport`, detail: 'Only http and fastcgi ship with Caddy.', fix: 'Make sure the plugin is in your build.', docs: `${docs}#transports` });
      }
    }
    if (nd.name === 'encode') for (const a of nd.args.filter((x) => !x.startsWith('@') && !x.startsWith('/') && x !== '*')) if (!kb.encoders[a] && !/^(br|brotli)$/.test(a)) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `encode: unknown encoding "${a}"`, detail: `Standard encodings: ${Object.keys(kb.encoders).join(', ')}.`, fix: 'encode zstd gzip', docs });
    if (nd.block && CONTAINERS.has(nd.name)) {
      const inner = new Map(defs); for (const x of nd.block) if (x.name.startsWith('@')) inner.set(x.name, x);
      checkDirectives(nd.block, { ...ctx, defs: inner, inRoute: ctx.inRoute || nd.name === 'route' });
    }
  }
}

function checkMatcherDef(nd, base, T, add) {
  const parts = nd.block ? nd.block.map((c) => ({ type: c.name, args: c.args, line: c.line, file: c.file, block: c.block })) : nd.toks[1] && nd.toks[1].quoted ? [{ type: 'expression', args: [], line: nd.line }] : nd.args.length ? [{ type: nd.args[0], args: nd.args.slice(1), line: nd.line }] : [];
  if (!parts.length) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `Named matcher ${nd.name} is empty`, detail: 'A named matcher needs at least one matcher (path, host, method, header, ...).', fix: `${nd.name} path /...`, docs: matcherDocs('named-matchers') });
  for (const p of parts) {
    if (!p.type || p.type === 'import') continue;
    const e = kb.matchers[p.type];
    if (!e) { const near = suggest(p.type, Object.keys(kb.matchers)); add({ ...base, line: p.line, file: p.file || base.file, id: 'compat-unknown-matcher', severity: 'error', title: `Unknown matcher "${p.type}" in ${nd.name}`, detail: `Caddy stops with: unrecognized matcher: ${p.type}.`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : `Standard matchers: ${Object.keys(kb.matchers).join(', ')}.`, docs: `${DOCS}/caddyfile/matchers` }); continue; }
    lifecycle(p.type, e, T, { ...base, line: p.line }, 'matcher', matcherDocs(p.type), add);
    if (p.type === 'not' && p.block) checkMatcherDef({ ...nd, name: `${nd.name} › not`, block: p.block, args: [], toks: [] }, base, T, add);
    else if (p.type === 'not' && p.args && p.args[0]) checkMatcherDef({ ...nd, name: `${nd.name} › not`, block: [{ name: p.args[0], args: p.args.slice(1), line: p.line, file: p.file || base.file, block: null }], args: [], toks: [] }, base, T, add);
  }
}

/** Version-dependent advice (ids rec-caddy-*). */
function recommend({ sites, global, T, add }) {
  const rec = (f) => add({ category: 'recommendation', severity: 'info', ...f });
  const walk = (nodes, fn, within = []) => nodes.forEach((n) => { fn(n, within); if (n.block) walk(n.block, fn, [...within, n]); });
  for (const site of sites) {
    const label = site.keys.join(', ');
    walk(site.body, (n, within) => {
      const rp = within.slice().reverse().find((w) => w.name === 'reverse_proxy');
      if (n.name === 'header_up' && rp && /^\+?host$/i.test(n.args[0] || '') && /^\{(upstream_hostport|http\.reverse_proxy\.upstream\.hostport)\}$/.test(n.args[1] || '') && V.gte(T, '2.11.0')) rec({ id: 'rec-caddy-host-header', file: n.file, line: n.line, section: label, title: 'header_up Host {upstream_hostport} is automatic for HTTPS upstreams since Caddy 2.11', detail: 'Caddy 2.11 sets the Host header to the upstream\'s host when proxying to HTTPS.', fix: 'Remove the line if the upstream is HTTPS (keep it for HTTP upstreams that need it).', docs: `${DOCS}/caddyfile/directives/reverse_proxy#https`, since: '2.11.0' });
      if (n.name === 'health_path' && V.gte(T, '2.4.0')) rec({ id: 'rec-caddy-health-uri', severity: 'warning', file: n.file, line: n.line, section: label, title: 'health_path is deprecated: use health_uri', detail: 'health_uri (2.4+) accepts a path and a query string.', fix: `health_uri ${n.args[0] || '/health'}`, docs: `${DOCS}/caddyfile/directives/reverse_proxy#health_uri`, since: '2.4.0' });
      if (n.name === 'reverse_proxy') {
        const subs = new Set((n.block || []).map((c) => c.name));
        const ups = n.args.filter((a) => !/^[@/*]/.test(a)).length + (n.block || []).filter((c) => c.name === 'to').reduce((a, c) => a + c.args.length, 0);
        if (ups > 1 && !subs.has('lb_try_duration') && !subs.has('lb_retries')) rec({ id: 'rec-caddy-retries', file: n.file, line: n.line, section: label, title: 'Retry another upstream when one fails', detail: 'Without lb_try_duration (or lb_retries, 2.6+), a request that hits a dead upstream fails even though others are healthy.', fix: 'lb_try_duration 5s', docs: `${DOCS}/caddyfile/directives/reverse_proxy#lb_try_duration` });
      }
      if (n.name === 'encode' && !n.args.includes('zstd') && n.args.includes('gzip')) rec({ id: 'rec-caddy-zstd', file: n.file, line: n.line, section: label, title: 'Offer zstd before gzip', detail: 'zstd compresses faster and better than gzip; browsers that do not support it still get gzip.', fix: 'encode zstd gzip', docs: `${DOCS}/caddyfile/directives/encode` });
    });
  }
  if (global) for (const n of global.block || []) {
    if (n.name === 'servers') for (const c of n.block || []) if (c.name === 'protocol') rec({ id: 'rec-caddy-protocols', severity: 'warning', file: c.file, line: c.line, section: 'global options', title: 'servers { protocol { ... } } was replaced by protocols / strict_sni_host', detail: 'The protocol block exists up to 2.7.6.', fix: 'protocols h1 h2 h3', docs: `${DOCS}/caddyfile/options#protocols` });
  }
}

module.exports = { validate, syntaxCheck };

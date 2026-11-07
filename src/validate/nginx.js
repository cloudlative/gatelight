'use strict';
/**
 * Version-aware validation of an NGINX configuration against the knowledge base built from nginx.org
 * (src/kb/nginx.json, see tools/kb/nginx.js).
 *
 *   1. strict syntax pass (unbalanced braces, missing ";", unterminated quotes) per file
 *   2. context-aware walk of the include-expanded tree: every directive is checked for
 *      existence, allowed context, availability in the target version, removal/deprecation, arity,
 *      block-vs-statement form, NGINX Plus-only status and (optionally) the modules compiled into the binary
 *   3. semantic checks that only make sense across the whole file (zones, duplicates, inheritance, proxy_pass rules)
 *   4. version-aware recommendations (recommendNginx.js)
 */
const kb = require('../kb/nginx.json');
const V = require('./version');
const { suggest } = require('./suggest');
const { NGINX_PARAM_SINCE } = require('./curated');
const { astFromFiles } = require('../nginxConfig');
const { recommendNginx } = require('./recommendNginx');

const THIRD_PARTY = /^(lua_|.*_by_lua|more_|brotli|modsecurity|pagespeed|vhost_traffic|vts_|testcookie_|upload_|echo_|redis2?_|srcache_|set_misc|encrypted_session|array_var|form_input|iconv_|rds_|xss_|dav_ext|fancyindex|geoip2_|auth_ldap|ldap_|vod_|rtmp|application|play|record|push_stream|nchan|naxsi|subs_filter|substitutions|sorted_args|opentracing|otel_|zstd|auth_pam|shib_|ajp_|ngx_|jwt_|ssl_ct|sticky|dynamic_etag|cache_purge|proxy_cache_purge|accounting|auth_digest|bot_|captcha|clojure|cookie_flag|dns_|drizzle|eval|fips|geoip_|graphite|hmac|http_|js_|keyval|lower|mp4_|njs|perl_|process_|recaptcha|replace_filter|secure_token|session_log|shibboleth|sts_|upstream_|waf_|zone_sync)/;
const DUPLICATE_SENSITIVE = new Set(['root', 'alias', 'client_max_body_size', 'keepalive_timeout', 'sendfile', 'tcp_nopush', 'tcp_nodelay', 'default_type', 'server_tokens', 'ssl_protocols', 'ssl_ciphers', 'ssl_prefer_server_ciphers', 'ssl_session_timeout', 'proxy_pass', 'proxy_http_version', 'proxy_read_timeout', 'proxy_connect_timeout', 'proxy_send_timeout', 'worker_processes', 'worker_connections', 'user', 'pid', 'gzip', 'charset', 'resolver_timeout', 'error_log_tag', 'client_body_timeout', 'client_header_timeout', 'send_timeout', 'sendfile_max_chunk', 'types_hash_max_size', 'server_names_hash_bucket_size', 'underscores_in_headers']);
const NO_CHILD_CHECK = new Set(['map', 'geo', 'split_clients', 'types', 'charset_map', 'keyval_zone', 'perl', 'js_content']);
const BLOCK_CTX = { events: 'events', http: 'http', stream: 'stream', mail: 'mail', upstream: 'upstream', limit_except: 'limit_except', map: 'map', geo: 'geo', split_clients: 'split_clients', types: 'types', match: 'match', charset_map: 'charset_map' };
const MODULE_SCOPE = (mod) => (/^ngx_stream_/.test(mod) ? 'stream' : /^ngx_mail_/.test(mod) ? 'mail' : /^ngx_http_/.test(mod) ? 'http' : 'core');
const CORE_MODULE_PAGES = new Set(['ngx_core_module', 'ngx_events_module']);

const docsUrl = (name, e) => {
  const mod = e.mod; const dir = MODULE_SCOPE(mod) === 'core' ? '' : `${MODULE_SCOPE(mod)}/`;
  return `https://nginx.org/en/docs/${dir}${mod}.html#${name}`;
};

// ------------------------------------------------------------------------------------------- strict syntax pass
function syntaxCheck(files) {
  const out = [];
  for (const f of files) {
    const text = f.content; const n = text.length;
    let i = 0; let line = 1; const stack = []; let words = 0; let wordLine = 0; let firstWord = '';
    const err = (l, title, detail, fix) => out.push({ id: 'syntax-nginx', severity: 'error', category: 'syntax', file: f.name, line: l, section: 'syntax', title, detail, fix });
    while (i < n) {
      const ch = text[i];
      if (ch === '\n') { line++; i++; continue; }
      if (/\s/.test(ch)) { i++; continue; }
      if (ch === '#') { while (i < n && text[i] !== '\n') i++; continue; }
      if (ch === ';') { if (!words) err(line, 'Unexpected ";"', 'A semicolon with no directive before it.', 'Remove the stray ";".'); words = 0; i++; continue; }
      if (ch === '{' && words === 1 && /_block$/.test(firstWord)) {
        // OpenResty / njs style raw code blocks: skip to the matching brace without interpreting the content
        let depth = 0;
        for (; i < n; i++) {
          const c = text[i];
          if (c === '\n') line++;
          else if (c === '"' || c === "'") { const q = c; i++; while (i < n && text[i] !== q) { if (text[i] === '\\') i++; if (text[i] === '\n') line++; i++; } }
          else if (c === '{') depth++;
          else if (c === '}') { depth--; if (depth === 0) { i++; break; } }
        }
        words = 0; firstWord = ''; continue;
      }
      if (ch === '{') { if (!words) err(line, 'Unexpected "{"', 'A block needs a directive name before the brace (e.g. "server {").', 'Add the directive name or remove the brace.'); stack.push(wordLine || line); words = 0; i++; continue; }
      if (ch === '}') {
        if (words) err(wordLine, 'Missing ";" before "}"', 'The last directive of a block is not terminated with a semicolon; nginx stops with "unexpected }".', 'Add ";" at the end of the directive.');
        if (!stack.length) err(line, 'Unexpected "}"', 'There is no open block to close; check for an extra brace above.', 'Remove the brace or add the missing opening one.'); else stack.pop();
        words = 0; i++; continue;
      }
      if (!words) { wordLine = line; firstWord = ''; }
      words++;
      if (words === 1) { let j = i; while (j < n && !/[\s;{}]/.test(text[j])) j++; firstWord = text.slice(i, j); }
      if (ch === '"' || ch === "'") {
        const q = ch; const start = line; i++;
        while (i < n && text[i] !== q) { if (text[i] === '\\') i++; else if (text[i] === '\n') line++; i++; }
        if (i >= n) { err(start, 'Unterminated quoted string', `A ${q} quote opened here is never closed.`, 'Close the quote.'); break; }
        i++; continue;
      }
      while (i < n && !/[\s;{}]/.test(text[i])) { if (text[i] === '$' && text[i + 1] === '{') { while (i < n && text[i] !== '}') i++; } i++; }
    }
    if (words) err(wordLine, 'Unexpected end of file, expecting ";" or "}"', 'The last directive in the file is not terminated.', 'Add ";" at the end of the directive.');
    for (const l of stack) err(l, 'Unclosed block: missing "}"', 'This block is never closed; nginx reports "unexpected end of file, expecting }".', 'Add the closing brace.');
  }
  return out;
}

// ------------------------------------------------------------------------------------------- syntax strings
const parsedSyntax = new Map();
/** Min/max argument counts derived from a syntax string such as "proxy_set_header field value;". */
function arity(syntax) {
  if (parsedSyntax.has(syntax)) return parsedSyntax.get(syntax);
  const body = syntax.replace(/;$/, '').replace(/\{\s*\.\.\.\s*\}\s*$/, '').trim();
  const parts = []; let depth = 0; let cur = '';
  for (const c of body) {
    if (c === '[') depth++; if (c === ']') depth--;
    if (/\s/.test(c) && depth === 0) { if (cur) parts.push(cur); cur = ''; } else cur += c;
  }
  if (cur) parts.push(cur);
  const toks = parts.slice(1);
  let min = 0; let exact = true; let max = 0;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t === '|') { exact = false; continue; }
    if (t.startsWith('[')) { exact = false; max += 1; continue; }
    if (t === '...') { exact = false; max = Infinity; continue; }
    if (toks[i + 1] === '|') { // alternatives collapse to one required slot
      while (toks[i + 1] === '|') i += 2;
      min += 1; max += 1; exact = false; continue;
    }
    if (/^\(|\)$|\.\.\./.test(t) || /[|]/.test(t)) exact = false;
    min += 1; max += 1;
  }
  const res = { min, max: exact ? max : Infinity, block: /\{\s*\.\.\.\s*\}\s*$/.test(syntax.replace(/;$/, '').trim()) };
  parsedSyntax.set(syntax, res);
  return res;
}

// ------------------------------------------------------------------------------------------- build flags (nginx -V)
function parseBuild(text) {
  if (!text) return null;
  const withs = new Set([...String(text).matchAll(/--with-([a-z0-9_]+)/g)].map((m) => `--with-${m[1]}`));
  const without = new Set([...String(text).matchAll(/--without-([a-z0-9_]+)/g)].map((m) => m[1]));
  return { withs, without, text: String(text).slice(0, 4000) };
}

// ------------------------------------------------------------------------------------------- main
function analyzeNginx(input, { version, build, notes: loadNotes } = {}) {
  const files = Array.isArray(input) ? input : [{ name: 'nginx.conf', content: String(input || '') }];
  const requested = version || null;
  const parsed = V.parse(requested);
  const target = parsed ? parsed.join('.') : kb.latest;
  let note = null;
  if (requested && !parsed) note = `Could not read "${requested}" as a version; validating against the latest documented release (${kb.latest}).`;
  else if (parsed && V.cmp(parsed, kb.latest) > 0) note = `${requested} is newer than the newest documented release (${kb.latest}); newer directives may be reported as unknown.`;
  const buildInfo = parseBuild(build);

  const findings = [];
  const add = (f) => findings.push({ category: 'compat', detail: '', fix: '', ...f });
  for (const s of syntaxCheck(files)) findings.push(s);
  const hasSyntaxErrors = findings.some((f) => f.id === 'syntax-nginx');

  let ast = []; let loaded = [];
  try { const r = astFromFiles(files); ast = r.ast; loaded = r.files; (loadNotes || []).push(...r.notes); } catch (e) { add({ id: 'syntax-nginx', severity: 'error', category: 'syntax', title: `Could not parse: ${e.message}`, section: 'syntax' }); }
  const missingIncludes = (loadNotes || []).some((n) => /not found|matched no files/i.test(n.msg));

  // ---- definitions collected up-front (zones, variables, upstreams) so forward references work
  const defs = { limitReq: new Set(), limitConn: new Set(), cache: new Set(), vars: new Set(), upstreams: new Set(), sslCache: new Set(), resolverSeen: false, http: false };
  const collect = (nodes) => {
    for (const n of nodes) {
      const a = n.args || [];
      if (n.name === 'http' || n.name === 'stream') defs.http = true;
      if (n.name === 'limit_req_zone') { const z = a.find((x) => x.startsWith('zone=')); if (z) defs.limitReq.add(z.slice(5).split(':')[0]); }
      if (n.name === 'limit_conn_zone') { const z = a.find((x) => x.startsWith('zone=')); if (z) defs.limitConn.add(z.slice(5).split(':')[0]); }
      if (/_cache_path$/.test(n.name)) { const z = a.find((x) => x.startsWith('keys_zone=')); if (z) defs.cache.add(z.slice(10).split(':')[0]); }
      if (n.name === 'ssl_session_cache') for (const x of a) { const m = x.match(/^shared:([^:]+):/); if (m) defs.sslCache.add(m[1]); }
      if (n.name === 'proxy_cache_path' || n.name === 'fastcgi_cache_path') defs.cachePath = true;
      if (n.name === 'upstream' && a[0]) defs.upstreams.add(a[0]);
      if (n.name === 'resolver') defs.resolverSeen = true;
      if (['set', 'auth_request_set', 'perl_set', 'js_set', 'set_by_lua', 'set_by_lua_block', 'set_by_lua_file', 'set_unescape_uri', 'set_escape_uri', 'set_md5', 'set_sha1', 'set_quote_sql_str', 'set_if_empty', 'set_real_ip_from_var', 'set_hashed_upstream', 'set_random', 'set_encode_base64', 'set_decode_base64', 'set_hmac_sha1', 'set_formatted_gmt_time', 'set_formatted_local_time', 'set_misc', 'js_var', 'uninitialized_variable_warn'].includes(n.name) && a[0] && a[0].startsWith('$')) defs.vars.add(a[0].slice(1));
      if (['map', 'geo', 'split_clients'].includes(n.name)) { const v = a.find((x) => x.startsWith('$') && x !== a[0]) || (n.name === 'split_clients' ? a[1] : a[a.length - 1]); const target_ = n.name === 'map' ? a[1] : n.name === 'geo' ? a[a.length - 1] : a[a.length - 1]; if (target_ && target_.startsWith('$')) defs.vars.add(target_.slice(1)); if (v && v.startsWith('$')) defs.vars.add(v.slice(1)); }
      if (['keyval'].includes(n.name) && a[1] && a[1].startsWith('$')) defs.vars.add(a[1].slice(1));
      for (const m of [n.name, ...a].join(' ').matchAll(/\(\?P?<([a-zA-Z_][a-zA-Z0-9_]*)>/g)) defs.vars.add(m[1]);
      if (n.children) collect(n.children);
    }
  };
  collect(ast);

  const entriesFor = (name) => kb.directives[name] || null;
  const embedded = kb.variables;
  const PREFIX_VARS = /^(arg_|http_|sent_http_|upstream_http_|cookie_|upstream_cookie_|sent_trailer_|upstream_trailer_|ssl_client_|jwt_|geoip_|geoip2_|secure_link|session_log|fastcgi_|uwsgi_|scgi_|grpc_|proxy_|realip_remote|upstream_|ssl_|cert_|server_|request_|remote_|http2|limit_|mqtt_|memcached_|mail_|pid|msec|nginx_version|hostname|time_|uri|args|document_|is_args|query_string|binary_|body_|bytes_|connection|content_|host|invalid_referer|gzip_ratio|slice_range|sent_|status|tcp_info|scheme|realip|amp_|cache_|cookie|stream_|sticky_|ancient_browser|modern_browser|msie|date_|apache_|uid_|spdy|if_modified|ajp_|ssi_|trace_|prefix|ssl_|upstream)/;
  const knownVar = (name) => /^\d+$/.test(name) || defs.vars.has(name) || embedded[name] || embedded[`${name.split('_')[0]}_`] || Object.keys(embedded).some((k) => k.endsWith('_') && name.startsWith(k));

  const scopeOfCtx = (ctxStack) => { for (let i = ctxStack.length - 1; i >= 0; i--) { if (['http', 'stream', 'mail'].includes(ctxStack[i].name)) return ctxStack[i].name; } return 'main'; };

  /** Context name of a block opened by `node` inside `parent`. */
  const childCtx = (node, parent) => {
    if (node.name === 'if') return parent.name === 'location' || parent.name === 'if in location' || parent.name === 'limit_except' ? 'if in location' : 'if in server';
    if (BLOCK_CTX[node.name]) return BLOCK_CTX[node.name];
    return node.name; // server, location, or an unknown (third-party) block
  };

  /** Allowed-context test with nginx's naming ("if" means both ifs; "location" also matches nested). */
  const ctxMatches = (listed, cur) => listed.some((c) => c === cur || (c === 'if' && /^if in /.test(cur)) || (cur === 'if in location' && c === 'if in location'));

  const seen = []; // per block: directive name -> first node (duplicates, inheritance)
  const inheritArrays = new Set(['add_header', 'proxy_set_header', 'proxy_hide_header', 'fastcgi_param', 'uwsgi_param', 'scgi_param', 'grpc_set_header', 'fastcgi_hide_header', 'proxy_pass_header']);
  const zonesNeedingDef = [];

  function lifecycleFor(name, node, e, where) {
    // changelog events: renamed / removed / deprecated
    for (const ev of kb.changes) {
      if (ev.names[0] !== name && !(ev.kind === 'removed' && ev.names.includes(name) && !entriesFor(name))) continue;
      // only events about the directive itself, not about one of its parameters
      if (!new RegExp(`(?:deprecated )?"${name}" directive`).test(ev.note) || new RegExp(`"${name}" (?:parameter|option|flag)`).test(ev.note) && !new RegExp(`"${name}" directive (?:is|was|has been) (?:now )?(?:deprecated|obsolete)`).test(ev.note)) continue;
      if (ev.kind === 'deprecated' && ev.names[0] === name && V.gte(target, ev.ver)) {
        add({ id: 'compat-deprecated', severity: 'warning', title: `"${name}" is deprecated since nginx ${ev.ver}`, detail: ev.note, fix: 'See the replacement mentioned above.', section: where, file: node.file, line: node.line, since: ev.ver });
      }
    }
  }

  function walk(nodes, ctxStack) {
    const cur = ctxStack[ctxStack.length - 1];
    const scope = scopeOfCtx(ctxStack);
    const local = new Map();
    seen.push(local);
    for (const node of nodes) {
      const name = node.name; const args = node.args || [];
      const where = describe(ctxStack);
      const base = { section: where, file: node.file, line: node.line };
      const entries = entriesFor(name);

      // ----- unknown directive
      if (!entries) {
        if (node.children && THIRD_PARTY.test(name)) continue;
        const removed = kb.changes.find((ev) => (ev.kind === 'removed' && ev.names.includes(name)) || (ev.kind === 'renamed' && ev.names[0] === name));
        const curated = REMOVED[name];
        if (removed && V.gte(target, removed.ver) || (curated && V.gte(target, curated.ver))) {
          const rv = curated ? curated.ver : removed.ver;
          add({ ...base, id: 'compat-removed', severity: 'error', title: `"${name}" was removed in nginx ${rv}`, detail: curated ? curated.note : removed.note, fix: curated ? curated.fix : (removed.kind === 'renamed' ? `Use "${removed.names[1]}" instead.` : 'Remove it or migrate to the replacement named above.'), until: rv });
        } else if (removed || curated) {
          const rv = curated ? curated.ver : removed.ver;
          add({ ...base, id: 'compat-deprecated', severity: 'info', title: `"${name}" still works on nginx ${target} but is removed in ${rv}`, detail: curated ? curated.note : removed.note, fix: curated ? curated.fix : 'Migrate before upgrading.' });
        } else if (THIRD_PARTY.test(name)) {
          add({ ...base, id: 'compat-third-party', severity: 'info', title: `"${name}" is not in the official nginx documentation`, detail: 'It probably comes from a third-party / dynamic module that this validator cannot check.', fix: 'Make sure the module is loaded (load_module) in your build.' });
        } else {
          const near = suggest(name, Object.keys(kb.directives));
          add({ ...base, id: 'compat-unknown-directive', severity: 'error', title: `Unknown directive "${name}"`, detail: `Not found in the nginx documentation (up to ${kb.latest}). nginx stops with: unknown directive "${name}".`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Check the spelling, or load the module that provides it.' });
        }
        if (node.children && !NO_CHILD_CHECK.has(name)) walk(node.children, [...ctxStack, { name: childCtx(node, cur), unknown: true }]);
        continue;
      }

      // ----- removed for the target version even though older docs still list it
      if (REMOVED[name] && V.gte(target, REMOVED[name].ver)) {
        add({ ...base, id: 'compat-removed', severity: 'error', title: `"${name}" was removed in nginx ${REMOVED[name].ver}`, detail: REMOVED[name].note, fix: REMOVED[name].fix, until: REMOVED[name].ver, docs: docsUrl(name, entries[0]) });
        if (node.children && !NO_CHILD_CHECK.has(name)) walk(node.children, [...ctxStack, { name: childCtx(node, cur) }]);
        continue;
      }
      // ----- candidates for this scope + context
      const inScope = entries.filter((e) => { const s = MODULE_SCOPE(e.mod); return s === 'core' || scope === 'main' || s === scope || CORE_MODULE_PAGES.has(e.mod); });
      let cands = inScope.filter((e) => ctxMatches(e.ctx, cur.name));
      if (cur.unknown) cands = inScope; // inside a third-party block: anything goes
      if (!cands.length) {
        const where2 = [...new Set(inScope.length ? inScope.flatMap((e) => e.ctx) : entries.flatMap((e) => e.ctx))];
        const scopeNote = !inScope.length ? ` It belongs to the ${[...new Set(entries.map((e) => MODULE_SCOPE(e.mod)))].join('/')} modules, which are not available in the ${scope} context.` : '';
        add({ ...base, id: 'compat-wrong-context', severity: 'error', title: `"${name}" is not allowed in ${cur.name === 'main' ? 'the main context' : `${cur.name}`}`, detail: `nginx stops with: "${name}" directive is not allowed here. It may only appear in: ${where2.join(', ')}.${scopeNote}`, fix: `Move it into ${where2.slice(0, 3).join(' / ')}.`, docs: docsUrl(name, entries[0]) });
        if (node.children && !NO_CHILD_CHECK.has(name)) walk(node.children, [...ctxStack, { name: childCtx(node, cur) }]);
        continue;
      }
      const e0 = cands[0];
      const docs = docsUrl(name, e0);

      // ----- version availability
      const sinces = cands.map((e) => e.since).filter(Boolean);
      if (cands.every((e) => e.since) && sinces.length) {
        const oldest = sinces.sort(V.cmp)[0];
        if (V.lt(target, oldest)) add({ ...base, id: 'compat-too-new', severity: 'error', title: `"${name}" needs nginx ${oldest}+`, detail: `Appeared in ${oldest}; you are validating against ${target}, which stops with: unknown directive "${name}".`, fix: `Upgrade to ${oldest} or newer, or use an older equivalent.`, since: oldest, docs });
      }
      lifecycleFor(name, node, e0, where);
      if (cands.every((e) => e.plus)) add({ ...base, id: 'compat-plus-only', severity: 'error', title: `"${name}" is only available in NGINX Plus`, detail: 'The documentation marks it as part of the commercial subscription; open-source nginx rejects it as unknown.', fix: 'Remove it or use NGINX Plus.', docs });
      if (buildInfo && !cur.unknown) {
        const flagged = cands.filter((e) => e.flag);
        const noFlag = cands.some((e) => !e.flag);
        if (!noFlag && flagged.length && !flagged.some((e) => buildInfo.withs.has(e.flag))) add({ ...base, id: 'compat-module-missing', severity: 'error', title: `"${name}" needs ${flagged[0].flag}`, detail: `The module ${flagged[0].mod} is not built by default and your "nginx -V" output does not list ${flagged[0].flag}.`, fix: `Use a build with ${flagged[0].flag}, or remove the directive.`, docs });
        const off = cands.every((e) => { const m = e.mod.replace(/^ngx_/, '').replace(/_module$/, ''); return buildInfo.without.has(`${m}_module`) || buildInfo.without.has(m); });
        if (off) add({ ...base, id: 'compat-module-missing', severity: 'error', title: `"${name}" is provided by a module that your build disables`, detail: `${e0.mod} is excluded by a --without-... flag in your "nginx -V" output.`, fix: 'Use a build that includes the module.', docs });
      }

      // ----- statement vs block, arity
      const wantsBlock = cands.some((e) => arity(e.syntax).block);
      const wantsStmt = cands.some((e) => !arity(e.syntax).block);
      if (node.children && !wantsBlock) add({ ...base, id: 'syntax-nginx', severity: 'error', category: 'syntax', title: `"${name}" does not take a block`, detail: `nginx stops with: unexpected "{" — "${name}" must end with ";".`, fix: `Write "${name} ...;"`, docs });
      else if (!node.children && !wantsStmt) add({ ...base, id: 'syntax-nginx', severity: 'error', category: 'syntax', title: `"${name}" needs a block`, detail: `nginx stops with: directive "${name}" has no opening "{".`, fix: `Write "${name} ... { ... }".`, docs });
      else if (!['if', 'location', 'map', 'geo', 'types', 'limit_except', 'upstream', 'match', 'split_clients', 'server', 'events', 'http', 'stream', 'mail'].includes(name) || args.length === 0) {
        const ar = cands.map((e) => arity(e.syntax));
        const min = Math.min(...ar.map((x) => x.min)); const max = Math.max(...ar.map((x) => x.max));
        if (args.length < min) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `"${name}" has too few arguments`, detail: `Syntax: ${cands[0].syntax}`, fix: 'Add the missing argument(s) — nginx reports: invalid number of arguments.', docs });
        else if (args.length > max) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `"${name}" has too many arguments`, detail: `Syntax: ${cands[0].syntax}`, fix: 'Quote values that contain spaces, or remove the extra argument(s).', docs });
      }

      // ----- parameters introduced / deprecated in specific versions
      checkParams(name, node, args, base, docs);

      // ----- duplicates / inheritance bookkeeping
      if (DUPLICATE_SENSITIVE.has(name) && local.has(name) && !node.children) add({ ...base, id: 'compat-duplicate', severity: 'error', title: `"${name}" is duplicated in this block`, detail: `Already set at line ${local.get(name).line}. nginx stops with: "${name}" directive is duplicate.`, fix: 'Keep one of the two lines.', docs });
      if (!local.has(name)) local.set(name, node);
      if (name === 'location' && node.children) {
        const key = args.join(' ');
        const dupKey = `__loc:${key}`;
        if (local.has(dupKey)) add({ ...base, id: 'compat-duplicate', severity: 'error', title: `Duplicate location "${key}"`, detail: `The same location is already defined at line ${local.get(dupKey).line} in this block; nginx stops with: duplicate location.`, fix: 'Merge the two blocks or change one of the paths.', docs });
        else local.set(dupKey, node);
      }
      if (name === 'proxy_pass' || name === 'fastcgi_pass' || name === 'grpc_pass') checkPass(name, node, args, base, ctxStack, docs);
      checkReferences(name, node, args, base);
      checkVariables(name, node, args, base);

      if (node.children && !NO_CHILD_CHECK.has(name)) walk(node.children, [...ctxStack, { name: childCtx(node, cur), node }]);
    }
    seen.pop();
  }

  function describe(stack) {
    const parts = stack.filter((s) => s.node).map((s) => `${s.node.name}${s.node.args && s.node.args[0] ? ` ${s.node.args[0]}` : ''}`);
    return parts.length ? parts[parts.length - 1] : 'main';
  }

  const REMOVED = {
    ssl: { ver: '1.25.1', note: 'The "ssl" directive was deprecated in 1.15.0 and removed in 1.25.1.', fix: 'Use the "ssl" parameter of the "listen" directive: listen 443 ssl;' },
    http2_push: { ver: '1.25.1', note: 'HTTP/2 server push support was removed in 1.25.1.', fix: 'Remove it; use "Link: <...>; rel=preload" headers (103 Early Hints) instead.' },
    http2_push_preload: { ver: '1.25.1', note: 'HTTP/2 server push support was removed in 1.25.1.', fix: 'Remove it; use 103 Early Hints.' },
    limit_zone: { ver: '1.7.6', note: 'The "limit_zone" directive was removed in 1.7.6.', fix: 'Use "limit_conn_zone".' },
    spdy_headers_comp: { ver: '1.9.5', note: 'SPDY support was replaced by HTTP/2 in 1.9.5.', fix: 'Use HTTP/2.' },
    http2_recv_timeout: { ver: '1.19.7', note: 'Removed in 1.19.7.', fix: 'Use "client_header_timeout" / "client_body_timeout".' },
    http2_idle_timeout: { ver: '1.19.7', note: 'Removed in 1.19.7.', fix: 'Use "keepalive_timeout".' },
    http2_max_requests: { ver: '1.19.7', note: 'Removed in 1.19.7.', fix: 'Use "keepalive_requests".' },
    http2_max_field_size: { ver: '1.19.7', note: 'Removed in 1.19.7.', fix: 'Use "large_client_header_buffers".' },
    http2_max_header_size: { ver: '1.19.7', note: 'Removed in 1.19.7.', fix: 'Use "large_client_header_buffers".' },
    optimize_host_names: { ver: '0.3.26', note: 'Renamed in 0.3.26.', fix: 'Use "optimize_server_names" (itself obsolete: remove it).' },
  };

  // ---- parameters
  const kbParams = {};
  for (const p of kb.params) { (kbParams[p.directive] = kbParams[p.directive] || {})[p.param] = p.ver; }
  function checkParams(name, node, args, base, docs) {
    const table = { ...(kbParams[name] || {}), ...(NGINX_PARAM_SINCE[name] || {}) };
    for (const a of args) {
      const key = a.replace(/=.*$/, '');
      const v = table[key];
      if (v && V.lt(target, v) && name !== 'ssl_protocols') add({ ...base, id: 'compat-too-new', severity: 'error', title: `"${key}" parameter of "${name}" needs nginx ${v}+`, detail: `Introduced in ${v}; you are validating against ${target}.`, fix: `Upgrade to ${v}+ or drop the parameter.`, since: v, docs });
    }
    if (name === 'listen' && args.includes('http2') && V.gte(target, '1.25.1')) {
      add({ ...base, id: 'compat-deprecated', severity: 'warning', title: 'The "http2" parameter of "listen" is deprecated (since nginx 1.25.1)', detail: 'HTTP/2 is now enabled per server with the separate "http2" directive; the listen parameter still works but warns at startup.', fix: 'Remove "http2" from listen and add `http2 on;` to the server block.', since: '1.25.1', docs });
    }
    if (name === 'ssl_protocols') {
      for (const a of args) {
        if (a === 'TLSv1.3' && V.lt(target, '1.13.0')) add({ ...base, id: 'compat-too-new', severity: 'error', title: 'TLSv1.3 in ssl_protocols needs nginx 1.13.0+', detail: `Your target is ${target}; older versions reject the unknown protocol name (and also need OpenSSL 1.1.1+).`, fix: 'Upgrade nginx, or drop TLSv1.3.', since: '1.13.0', docs });
        if (a === 'TLSv1.1' && V.lt(target, '1.1.13')) add({ ...base, id: 'compat-too-new', severity: 'error', title: 'TLSv1.1/1.2 in ssl_protocols need nginx 1.1.13+', detail: 'Older releases only know SSLv2, SSLv3 and TLSv1.', fix: 'Upgrade nginx.', since: '1.1.13', docs });
      }
    }
  }

  // ---- proxy_pass rules
  function checkPass(name, node, args, base, ctxStack, docs) {
    const a = args[0] || '';
    const cur = ctxStack[ctxStack.length - 1];
    if (name === 'proxy_pass' && /^https?:\/\/[^/$]+\/.*$/.test(a) && !/\$/.test(a)) {
      const loc = [...ctxStack].reverse().find((s) => s.node && s.node.name === 'location');
      const lm = loc && loc.node.args[0];
      const regex = lm === '~' || lm === '~*' || (loc && loc.node.args.length === 1 && loc.node.args[0].startsWith('@'));
      if (regex || cur.name === 'if in location' || cur.name === 'limit_except' || ctxStack.some((s) => s.name === 'if in location' || s.name === 'limit_except')) {
        add({ ...base, id: 'compat-proxy-pass-uri', severity: 'error', title: 'proxy_pass has a URI part inside a regex / named / if / limit_except location', detail: 'nginx stops with: "proxy_pass" cannot have URI part in location given by regular expression, or inside named location, inside "if" statement, or inside "limit_except" block.', fix: 'Remove the path from proxy_pass (use only scheme://host:port) and rewrite the URI with "rewrite" or capture groups.', docs });
      }
    }
    if (/\$/.test(a) && /^(https?:\/\/)?\$/.test(a) && !defs.resolverSeen && !defs.upstreams.has(a.replace(/^https?:\/\//, '').replace(/^\$/, ''))) {
      add({ ...base, id: 'compat-no-resolver', severity: 'warning', category: 'correctness', title: `${name} uses a variable host but no "resolver" is configured`, detail: 'When the upstream address comes from a variable, nginx resolves it at request time and needs a "resolver"; otherwise requests fail with 502 "no resolver defined to resolve ...".', fix: 'Add `resolver 127.0.0.11 valid=30s;` (or your DNS server) to http/server.', docs });
    }
  }

  // ---- zone / cache references
  function checkReferences(name, node, args, base) {
    const unresolved = (kind, z, defsSet, how) => {
      if (!defs.http || defsSet.has(z)) return;
      add({ ...base, id: 'compat-undefined-zone', severity: missingIncludes ? 'info' : 'error', category: 'correctness', title: `${name} refers to undefined ${kind} "${z}"`, detail: `nginx stops with: ${how}${missingIncludes ? ' (an include was not found, so it may be defined there)' : ''}.`, fix: `Declare it first: ${kind === 'limit_req zone' ? `limit_req_zone $binary_remote_addr zone=${z}:10m rate=10r/s;` : kind === 'limit_conn zone' ? `limit_conn_zone $binary_remote_addr zone=${z}:10m;` : `proxy_cache_path /var/cache/nginx keys_zone=${z}:10m;`}` });
    };
    if (name === 'limit_req') { const z = args.find((x) => x.startsWith('zone=')); if (z) unresolved('limit_req zone', z.slice(5).split(':')[0], defs.limitReq, 'zero size shared memory zone / unknown limit_req zone'); }
    if (name === 'limit_conn' && args[0] && !args[0].startsWith('$')) unresolved('limit_conn zone', args[0], defs.limitConn, 'unknown limit_conn_zone');
    if ((name === 'proxy_cache' || name === 'fastcgi_cache' || name === 'uwsgi_cache' || name === 'scgi_cache') && args[0] && args[0] !== 'off' && !args[0].startsWith('$')) unresolved('cache zone', args[0], defs.cache, 'unknown cache zone / zero size shared memory zone');
  }

  // ---- variables
  const NO_VAR_CHECK = new Set(['location', 'server_name', 'map', 'geo', 'split_clients', 'set', 'types', 'rewrite_log', 'return_', 'perl_set', 'js_set', 'auth_request_set', 'lua_shared_dict', 'log_format', 'if']);
  const reported = new Set();
  function checkVariables(name, node, args, base) {
    if (NO_VAR_CHECK.has(name) && name !== 'set' && name !== 'log_format' && name !== 'if') return;
    let scan = args;
    if (name === 'rewrite') scan = args.slice(1);
    if (name === 'if') scan = args.filter((x) => /^\(?\$[A-Za-z_]\w*\)?$/.test(x));
    if (name === 'set') scan = args.slice(1);
    if (name === 'location' || name === 'server_name') return;
    for (const a of scan) {
      for (const m of a.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
        const v = m[1];
        if (knownVar(v)) {
          const meta = embedded[v];
          if (meta && meta.since && V.lt(target, meta.since) && !reported.has(`${v}@${node.line}`)) { reported.add(`${v}@${node.line}`); add({ ...base, id: 'compat-too-new', severity: 'error', title: `Variable $${v} needs nginx ${meta.since}+`, detail: `Introduced in ${meta.since}; your target is ${target}. nginx stops with: unknown "${v}" variable.`, fix: 'Upgrade nginx or avoid the variable.', since: meta.since }); }
          continue;
        }
        const key = `${v}@${node.file}:${node.line}`;
        if (reported.has(key)) continue; reported.add(key);
        add({ ...base, id: 'compat-unknown-variable', severity: 'warning', title: `Unknown variable $${v}`, detail: `Not an embedded nginx variable and not defined by set / map / geo / split_clients / a regex capture in this configuration. nginx stops with: unknown "${v}" variable — unless a third-party module defines it.`, fix: `Define it (set $${v} ...; or map ... $${v}) before use, or check the spelling.` });
      }
    }
  }

  const rootCtx = { name: 'main' };
  // fragments (conf.d snippets without http{}) are validated as if included into http / server
  const top = ast.map((n) => n.name);
  let startCtx = rootCtx;
  const isFragment = ast.length && !top.some((n) => ['http', 'stream', 'mail', 'events', 'worker_processes', 'user', 'pid', 'error_log', 'load_module'].includes(n));
  if (isFragment) {
    startCtx = top.some((n) => ['location', 'listen', 'server_name', 'root', 'return', 'rewrite', 'proxy_pass', 'try_files', 'index', 'if', 'add_header'].includes(n)) && !top.some((n) => ['server', 'upstream', 'map', 'geo', 'limit_req_zone', 'proxy_cache_path'].includes(n)) ? { name: 'server', node: { name: 'server', args: [], children: [] } } : { name: 'http', node: { name: 'http', args: [], children: [] } };
    startCtx = { ...startCtx, fragment: true };
  }
  if (ast.length) walk(ast, [startCtx]);

  const model = { ast, files: loaded, defs };
  recommendNginx({ ast, target, add, kb, V, defs, buildInfo, model });
  findings.sort((a, b) => (a.file === b.file ? (a.line || 0) - (b.line || 0) : String(a.file).localeCompare(String(b.file))));
  return { findings, model: { files: loaded.map((f) => f.name) }, target: { requested, version: target, note }, kb: { generated: kb.generated, source: kb.source, latest: kb.latest }, hasSyntaxErrors };
}

module.exports = { analyzeNginx, syntaxCheck, arity, parseBuild };

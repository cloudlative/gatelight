'use strict';
/**
 * Version-aware validation of an Apache httpd 2.4 configuration against src/kb/apache.json (built from the official
 * documentation source at release tags by tools/kb/apache.js).
 *
 *   1. syntax pass per file: unclosed / mismatched / stray section tags, "<Section" without ">", dangling "\"
 *   2. context walk of the include-expanded tree: unknown directive (did-you-mean), removed / renamed (upgrading.html),
 *      allowed context (server config / virtual host / directory / .htaccess / proxy section), section-vs-directive form,
 *      availability in the target 2.4.x release, deprecation, module not loaded (when the config has LoadModule lines),
 *      argument count / On|Off values where the documented syntax allows checking, worker parameters by version
 *   3. version-aware recommendations (rec-apache-*)
 */
const kb = require('../../kb/apache.json');
const V = require('../../validate/version');
const { suggest } = require('../../validate/suggest');
const { lex, astFromFiles, flat, LAYOUT, STATIC_MODULES } = require('./parse');

const LOWER = new Map(Object.keys(kb.directives).map((k) => [k.toLowerCase(), k]));
const ALL_NAMES = Object.keys(kb.directives);
const CTX_NAME = { s: 'server config', v: 'virtual host', d: 'directory', h: '.htaccess', p: 'proxy section' };
const DIR_CTX = new Set(['directory', 'directorymatch', 'location', 'locationmatch', 'files', 'filesmatch', 'if', 'elseif', 'else']);
const TRANSPARENT = new Set(['ifmodule', 'ifdefine', 'ifversion', 'iffile', 'ifdirective', 'ifsection', 'limit', 'limitexcept', 'requireall', 'requireany', 'requirenone']);
const OPAQUE = new Set(['macro', 'authnprovideralias', 'authzprovideralias', 'mdomainset', 'mdomain']); // bodies use their own rules
// Directives of well-known third-party modules (not in the httpd documentation): reported as info, not as unknown.
const THIRD_PARTY = /^(Sec[A-Z]|WSGI|php_(value|flag|admin_value|admin_flag)|Perl|Jk[A-Z]|Mellon|OIDC|DOS[A-Z]|ModPagespeed|Passenger|QS_|RPAF|Fcgid|FcgidWrapper|XSendFile|Shib|GeoIP|MaxMindDB|RMode|RUid|RGroups|AssignUserId|MaxClientsVHost|CloudFlare|Auth(Kerb|GSSAPI|PAM|Radius|MySQL|CAS)|Krb|GssapiS|CAS|Wsgi|Python|Mono|Security2|LimitIPConn|Bandwidth|ProxyHTMLExtended_|Evasive|Mod[A-Z]|Upload|Dav[A-Z]+Ext|Cluster|Manager|Balancer(Member)?Ext|Advertise|EnableMCPMReceive|MemManager|ServerAdvertise|ManagerBalancerName|ExtendedPersistance|AllowDisplay|Remoteip)/;
// Deprecated aliases and removed directives not caught by the upgrading.xml extractor (texts from upgrading.html).
const CURATED = {
  MaxClients: { kind: 'renamed', repl: 'MaxRequestWorkers', note: 'MaxClients has been renamed to MaxRequestWorkers in 2.4; the old name is still supported.' },
  MaxRequestsPerChild: { kind: 'renamed', repl: 'MaxConnectionsPerChild', note: 'MaxRequestsPerChild has been renamed to MaxConnectionsPerChild in 2.4; the old name is still supported.' },
};
// Worker parameters whose availability is described outside the parameter table (mod_proxy.html#wsupgrade).
const PARAM_SINCE = { loadfactor: { mod: 'mod_proxy' }, upgrade: { since: '2.4.47', mod: 'mod_proxy', note: 'Websocket Upgrade (2.4.47 and later)' } };

const docsOf = (e) => e.docs || `${kb.docsBase}${e.mod}.html#${String(e.name || '').toLowerCase()}`;

// ------------------------------------------------------------------------------------------- syntax
function syntaxCheck(files) {
  const out = [];
  for (const f of files) {
    const err = (line, title, detail, fix) => out.push({ id: 'syntax-apache', severity: 'error', category: 'syntax', file: f.name, line, section: 'syntax', title, detail, fix });
    const lines = lex(f.content); const stack = [];
    const raw = String(f.content).replace(/\r\n?/g, '\n').split('\n');
    if (raw.length && /\\\s*$/.test(raw[raw.length - 1] || raw[raw.length - 2] || '') && !/^\s*#/.test(raw[raw.length - 1])) err(raw.length, 'Line continuation at end of file', 'The last line ends with "\\", so httpd joins it with nothing.', 'Remove the trailing backslash.');
    for (const L of lines) {
      if (L.kind === 'open') {
        if (L.unterminated) err(L.line, `Section <${L.name} is missing ">"`, 'httpd stops with: "<Section> directive missing closing \'>\'".', 'Close the tag with ">".');
        stack.push(L);
      } else if (L.kind === 'close') {
        if (!stack.length) { err(L.line, `</${L.name}> without matching <${L.name}>`, 'httpd stops with: "</' + L.name + '> without matching <' + L.name + '> section".', 'Remove the stray closing tag or add the opening one.'); continue; }
        const top = stack[stack.length - 1];
        if (top.name.toLowerCase() !== L.name.toLowerCase()) {
          err(L.line, `</${L.name}> closes <${top.name}> (line ${top.line})`, `httpd stops with: "Expected </${top.name}> but saw </${L.name}>".`, `Close <${top.name}> first.`);
          const i = stack.map((x) => x.name.toLowerCase()).lastIndexOf(L.name.toLowerCase());
          if (i >= 0) stack.length = i; else continue;
        } else stack.pop();
      } else if (L.kind === 'dir' && /^</.test(L.name)) err(L.line, 'Malformed section tag', '', 'Write sections as <Name args> ... </Name>.');
    }
    for (const s of stack) err(s.line, `<${s.name}> is never closed`, `httpd stops with: "${f.name}: <${s.name}> was not closed."`, `Add </${s.name}>.`);
  }
  return out;
}

// ------------------------------------------------------------------------------------------- arity
const arityCache = new Map();
/** Argument counts from a documented syntax ("ProxyPreserveHost On|Off", "Header [condition] add|set header [value]"). */
function arity(syntax) {
  if (arityCache.has(syntax)) return arityCache.get(syntax);
  const body = String(syntax).replace(/^<\S+\s*/, '').replace(/>.*$/, '');
  const parts = []; let depth = 0; let cur = '';
  for (const c of body) { if (c === '[' || c === '{') depth++; if (c === ']' || c === '}') depth--; if (/\s/.test(c) && depth === 0) { if (cur) parts.push(cur); cur = ''; } else cur += c; }
  if (cur) parts.push(cur);
  const toks = parts.slice(1);
  let min = 0; let max = 0; let exact = true;
  for (const t of toks) {
    if (t === '|') { min -= 1; max -= 1; exact = false; continue; } // "disabled | local-url": alternatives share one slot
    if (t.startsWith('[') || t.startsWith('{')) { exact = false; max += 1; continue; }
    if (/\.\.\.|…/.test(t)) { exact = false; max = Infinity; continue; }
    min += 1; max += 1;
  }
  const r = { min, max: exact ? max : Infinity };
  arityCache.set(syntax, r); return r;
}

// ------------------------------------------------------------------------------------------- main
function validate({ files, version, build } = {}) {
  const input = Array.isArray(files) ? files : [{ name: 'httpd.conf', content: String(files || '') }];
  const requested = version || null;
  const parsed = V.parse(requested);
  let target = parsed ? parsed.join('.') : kb.latest;
  let note = null;
  if (requested && !parsed) note = `Could not read "${requested}" as a version; validating against the latest documented release (${kb.latest}).`;
  else if (parsed && (parsed[0] !== 2 || parsed[1] !== 4)) { note = `${requested} is not an httpd 2.4.x release; validating against ${kb.latest}.`; target = kb.latest; }
  else if (parsed && V.cmp(parsed, kb.latest) > 0) note = `${requested} is newer than the newest documented release (${kb.latest}); newer directives may be reported as unknown.`;
  else if (parsed && !kb.versions.includes(target)) note = `${target} was never released (the tag exists only in the source repository); results use the documentation as of ${kb.latest} with ${target} as the version limit.`;

  const findings = [];
  const add = (f) => findings.push({ category: 'compat', detail: '', fix: '', ...f });
  for (const s of syntaxCheck(input)) findings.push(s);
  const hasSyntaxErrors = findings.some((f) => f.category === 'syntax');

  let ast = []; let loadedFiles = []; let layout = 'unknown'; let notes = [];
  try { const r = astFromFiles(input); ast = r.ast; loadedFiles = r.files; layout = r.layout; notes = r.notes; } catch (e) { add({ id: 'syntax-apache', severity: 'error', category: 'syntax', title: `Could not parse: ${e.message}`, section: 'syntax' }); }
  const L = LAYOUT[layout] || LAYOUT.unknown;
  const loaded = new Set();
  (function collect(nodes) { for (const n of nodes) { if (n.lname === 'loadmodule' && n.args[0]) loaded.add(n.args[0]); if (n.children && !n.inactive) collect(n.children); } })(ast);
  const hasLoad = loaded.size > 0;
  (STATIC_MODULES[layout] || []).forEach((m) => loaded.add(m));
  if (build) for (const m of String(build).matchAll(/\b(mod_[a-z0-9_]+)\.c\b/g)) loaded.add(`${m[1].replace(/^mod_/, '')}_module`); // `httpd -l` output
  const modLoaded = (mod) => {
    const meta = kb.modules[mod]; if (!meta) return true;
    if (/^(Core|MPM)$/i.test(meta.status) || mod === 'mpm_common' || mod === 'core') return true;
    return !meta.id || loaded.has(meta.id);
  };
  const enableHint = (mod) => (layout === 'debian' ? `\`a2enmod ${mod.replace(/^mod_/, '')}\`` : `\`LoadModule ${(kb.modules[mod] || {}).id || `${mod.replace(/^mod_/, '')}_module`} modules/${mod}.so\`${layout === 'rhel' ? ' in /etc/httpd/conf.modules.d/' : ''}`);

  const lifecycle = { ...kb.lifecycle, ...CURATED };
  const reportedMissing = new Set();

  function ctxOf(stack) {
    // innermost meaningful context: d (or p inside <Proxy>), v, s; .htaccess files are 'h'
    for (let i = stack.length - 1; i >= 0; i--) {
      const n = stack[i].lname;
      if (n === 'proxy' || n === 'proxymatch') return 'p';
      if (DIR_CTX.has(n)) return 'd';
      if (n === 'virtualhost') return 'v';
    }
    return 's';
  }
  const where = (stack) => { const s = [...stack].reverse().find((x) => !TRANSPARENT.has(x.lname)); return s ? `<${s.name}${s.args[0] ? ` ${s.args[0]}` : ''}>` : 'main'; };

  function check(node, stack, htaccess) {
    const name = node.name; const lname = node.lname;
    const base = { section: where(stack), file: node.file, line: node.line };
    const key = LOWER.get(lname);
    if (!key) {
      const lc = Object.keys(lifecycle).find((k) => k.toLowerCase() === lname);
      const gone = Object.keys(kb.removedFromDocs).find((k) => k.toLowerCase() === lname);
      if (lc) {
        const e = lifecycle[lc];
        if (e.kind === 'renamed') add({ ...base, id: 'compat-deprecated', severity: 'warning', title: `"${name}" is the 2.2 name of ${e.repl}`, detail: e.note, fix: `Rename it to ${e.repl}.`, docs: `${kb.docsBase.replace(/mod\/$/, '')}upgrading.html#misc` });
        else if (e.kind === 'noeffect') add({ ...base, id: 'compat-deprecated', severity: 'warning', title: `"${name}" has no effect in httpd 2.4`, detail: e.note, fix: 'Remove it.', docs: `${kb.docsBase.replace(/mod\/$/, '')}upgrading.html#misc` });
        else add({ ...base, id: 'compat-removed', severity: 'error', title: `"${name}" was removed in httpd 2.4`, detail: `${e.note} httpd stops with: Invalid command '${name}'.`, fix: e.repl ? `Use ${e.repl}.` : 'Remove it.', docs: `${kb.docsBase.replace(/mod\/$/, '')}upgrading.html#run-time` });
      } else if (gone) {
        const g = kb.removedFromDocs[gone];
        const sev = V.gte(target, g.goneBy) ? 'error' : 'warning';
        add({ ...base, id: 'compat-removed', severity: sev, title: `"${name}" (${g.mod}) is no longer documented after httpd ${g.lastDocumented}`, detail: `It disappeared from the ${g.mod} documentation by ${g.goneBy}.${sev === 'error' ? ` Your target ${target} probably rejects it (Invalid command '${name}').` : ''}`, fix: 'Check the module documentation of your release; migrate to the current directives.', docs: `${kb.docsBase}${g.mod}.html` });
      } else if (THIRD_PARTY.test(name)) {
        add({ ...base, id: 'compat-third-party', severity: 'info', title: `"${name}" is not in the httpd documentation`, detail: 'It probably comes from a third-party module (mod_security, mod_wsgi, mod_php, mod_jk ...) that this validator cannot check.', fix: 'Make sure the module is loaded.' });
      } else {
        const near = suggest(name, ALL_NAMES);
        add({ ...base, id: 'compat-unknown-directive', severity: 'error', title: `Unknown directive "${name}"`, detail: `Not found in the httpd ${kb.latest} documentation. httpd stops with: Invalid command '${name}', perhaps misspelled or defined by a module not included in the server configuration.`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Check the spelling, or load the module that provides it.' });
      }
      return;
    }
    const entries = kb.directives[key].map((e) => ({ ...e, name: key }));
    const e0 = entries[0]; const docs = docsOf(e0);
    if (node.section && !entries.some((e) => e.section)) { add({ ...base, id: 'syntax-apache', severity: 'error', category: 'syntax', title: `"${key}" is a directive, not a section`, detail: `Write it as a single line: ${e0.syntax}`, fix: `Remove the <${name}> ... </${name}> tags.`, docs }); return; }
    if (!node.section && entries.every((e) => e.section)) { add({ ...base, id: 'syntax-apache', severity: 'error', category: 'syntax', title: `"${key}" is a section and needs <${key} ...> ... </${key}>`, detail: `Syntax: ${e0.syntax}`, fix: `Write <${key} ...> ... </${key}>.`, docs }); return; }
    // context
    const ctx = htaccess ? 'h' : ctxOf(stack);
    const inOpaque = stack.some((s) => OPAQUE.has(s.lname));
    if (!inOpaque) {
      const ok = entries.some((e) => e.ctx.includes(ctx) || (ctx === 'p' && e.ctx.includes('d')));
      if (!ok) {
        const allowed = [...new Set(entries.flatMap((e) => [...e.ctx]))].map((c) => CTX_NAME[c] || c);
        add({ ...base, id: 'compat-wrong-context', severity: 'error', title: `"${key}" is not allowed in ${CTX_NAME[ctx]} context${base.section !== 'main' ? ` (${base.section})` : ''}`, detail: `httpd stops with: ${key} not allowed here. Allowed context: ${allowed.join(', ')}.`, fix: `Move it to ${allowed.join(' / ')} level.`, docs });
      } else if (ctx === 'p' && entries.every((e) => !e.ctx.includes('p') && e.ctx.includes('d')) && entries.some((e) => /proxy section context is allowed in httpd ([\d.]+)/.test(e.compat || ''))) {
        const v = entries.map((e) => (/proxy section context is allowed in httpd ([\d.]+)/.exec(e.compat || '') || [])[1]).find(Boolean);
        if (v && V.lt(target, v)) add({ ...base, id: 'compat-too-new', severity: 'error', title: `"${key}" inside <Proxy> needs httpd ${v}+`, detail: e0.compat, fix: `Upgrade to ${v}+ or move it out of the <Proxy> section.`, since: v, docs });
      }
    }
    // version
    const sinces = entries.map((e) => e.since).filter(Boolean);
    if (sinces.length === entries.length) {
      const oldest = sinces.sort(V.cmp)[0];
      if (V.lt(target, oldest)) add({ ...base, id: 'compat-too-new', severity: 'error', title: `"${key}" needs httpd ${oldest}+`, detail: `${e0.compat || `Available in ${oldest} and later.`} You are validating against ${target}, which stops with: Invalid command '${key}'.`, fix: `Upgrade to ${oldest} or newer, or remove it.`, since: oldest, docs });
    } else if (entries.every((e) => e.docSince) && V.lt(target, entries[0].docSince)) {
      add({ ...base, id: 'compat-maybe-too-new', severity: 'info', title: `"${key}" is first documented in httpd ${entries[0].docSince}`, detail: `The ${target} documentation does not list it; it may not exist in that release.`, fix: 'Check `httpd -L` on the target server.', docs });
    }
    // deprecation
    const dep = entries.find((e) => e.dep);
    if (dep) add({ ...base, id: 'compat-deprecated', severity: 'warning', title: `"${key}" is deprecated`, detail: dep.dep, fix: /SSLCertificateChainFile/i.test(key) ? 'Append the intermediate certificates to the SSLCertificateFile instead.' : /SSLRequire/i.test(key) ? 'Use `Require expr ...`.' : 'Remove it or use the replacement named in the documentation.', docs });
    else if (e0.mod === 'mod_access_compat') add({ ...base, id: 'compat-deprecated', severity: 'warning', title: `"${key}" is a 2.2-style access control directive (mod_access_compat)`, detail: 'mod_access_compat is provided only for compatibility with old configurations; httpd 2.4 uses Require (mod_authz_host). Mixing both gives surprising results.', fix: key === 'Order' || key === 'Allow' || key === 'Deny' ? 'Replace with Require (e.g. `Require all granted`, `Require ip 10.0.0.0/8`, `Require host example.org`).' : 'Use RequireAll / RequireAny.', docs: `${kb.docsBase.replace(/mod\/$/, '')}upgrading.html#access` });
    // module loaded?
    if (hasLoad && !entries.some((e) => modLoaded(e.mod)) && !stack.some((s) => s.lname === 'ifmodule')) {
      const k = `${e0.mod}`;
      add({ ...base, id: 'compat-module-not-loaded', severity: reportedMissing.has(k) ? 'info' : 'warning', title: `"${key}" needs ${e0.mod}, which has no LoadModule line`, detail: `The configuration loads modules explicitly but not ${(kb.modules[e0.mod] || {}).id || e0.mod}. Unless it is compiled in (check \`httpd -l\`), httpd stops with: Invalid command '${key}'.`, fix: `Enable it: ${enableHint(e0.mod)}.`, docs: `${kb.docsBase}${e0.mod}.html` });
      reportedMissing.add(k);
    }
    // arguments
    if (!node.section) {
      const ar = entries.map((e) => arity(e.syntax));
      // <Proxy> supplies the url of ProxySet / BalancerMember, <Location> the path of ProxyPass / ProxyPassReverse
      const implied = ((/^(ProxySet|BalancerMember)$/.test(key) && stack.some((x) => x.lname === 'proxy' || x.lname === 'proxymatch')) || (/^(ProxyPass|ProxyPassMatch|ProxyPassReverse|ProxyPassReverseCookiePath|ProxyPassReverseCookieDomain)$/.test(key) && stack.some((x) => /^location/.test(x.lname)))) ? 1 : 0;
      const min = Math.max(0, Math.min(...ar.map((a) => a.min)) - implied); const max = Math.max(...ar.map((a) => a.max));
      const args = node.args;
      if (args.length < min) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `"${key}" has too few arguments`, detail: `Syntax: ${e0.syntax}`, fix: 'Add the missing argument(s).', docs });
      else if (args.length > max) add({ ...base, id: 'compat-bad-arguments', severity: 'error', title: `"${key}" has too many arguments`, detail: `Syntax: ${e0.syntax}. httpd stops with: ${key} takes ${max === 1 ? 'one argument' : `${max} arguments`}.`, fix: 'Quote values that contain spaces, or remove the extra argument(s).', docs });
      else if (entries.length === 1 && e0.vals && args.length === 1 && !/\$\{/.test(args[0]) && !e0.vals.includes(args[0].toLowerCase())) add({ ...base, id: 'compat-bad-value', severity: 'error', title: `"${key} ${args[0]}" is not a valid value`, detail: `Syntax: ${e0.syntax}`, fix: `Use one of: ${e0.vals.join(', ')}.`, docs });
      checkParams(key, node, base);
    }
  }

  function checkParams(key, node, base) {
    if (!/^(ProxyPass|ProxyPassMatch|BalancerMember|ProxySet)$/.test(key)) return;
    for (const a of node.args) {
      const m = /^([a-z][a-z0-9_]*)=/i.exec(a); if (!m) continue;
      const p = m[1].toLowerCase();
      const meta = PARAM_SINCE[p] || kb.params[p];
      if (!meta) { if (key !== 'ProxySet' || !/^(lbmethod|maxattempts|nofailover|stickysession|stickysessionsep|scolonpathdelim|timeout|failonstatus|failontimeout|nonce|growth|forcerecovery)$/.test(p)) add({ ...base, id: 'compat-unknown-parameter', severity: 'warning', title: `Unknown ${key} parameter "${p}"`, detail: 'Not a documented worker / balancer parameter; httpd stops with: unknown Worker parameter / unknown Balancer parameter.', fix: (() => { const near = suggest(p, [...Object.keys(kb.params), ...Object.keys(PARAM_SINCE)]); return near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Check the parameter table in the mod_proxy documentation.'; })(), docs: `${kb.docsBase}mod_proxy.html#proxypass` }); continue; }
      if (meta.since && V.lt(target, meta.since)) add({ ...base, id: 'compat-too-new', severity: 'error', title: `Parameter "${p}" of ${key} needs httpd ${meta.since}+`, detail: `${meta.note || `Documented as available in ${meta.since} and later (${meta.mod}).`} You are validating against ${target}.`, fix: p === 'upgrade' ? 'Use mod_proxy_wstunnel with a ws:// URL on older releases.' : `Upgrade to ${meta.since}+ or remove the parameter.`, since: meta.since, docs: meta.mod === 'mod_proxy_hcheck' ? `${kb.docsBase}mod_proxy_hcheck.html` : `${kb.docsBase}mod_proxy.html#proxypass` });
      if (meta.mod === 'mod_proxy_hcheck' && hasLoad && !loaded.has('proxy_hcheck_module') && !reportedMissing.has('hc')) { reportedMissing.add('hc'); add({ ...base, id: 'compat-module-not-loaded', severity: 'warning', title: `"${p}" needs mod_proxy_hcheck, which has no LoadModule line`, detail: 'Without the module the health-check parameters are rejected (unknown Worker parameter).', fix: `Enable it: ${enableHint('mod_proxy_hcheck')}.`, docs: `${kb.docsBase}mod_proxy_hcheck.html` }); }
    }
  }

  function walkTree(nodes, stack) {
    for (const n of nodes) {
      if (n.inactive) continue;
      const htaccess = /(^|\/)\.htaccess$/.test(n.file);
      if (n.lname === 'else' || n.lname === 'elseif' || n.lname === 'if') { /* expression sections are core directives */ }
      check(n, stack, htaccess);
      if (n.section && n.children && !OPAQUE.has(n.lname)) walkTree(n.children, [...stack, n]);
    }
  }
  walkTree(ast, []);
  recommend({ ast, target, add, loaded, hasLoad, layout, L });

  findings.sort((a, b) => (a.file === b.file ? (a.line || 0) - (b.line || 0) : String(a.file).localeCompare(String(b.file))));
  return { target: { requested, version: target, note }, kb: { generated: kb.generated, source: kb.source, latest: kb.latest }, findings, hasSyntaxErrors, layout, model: { files: loadedFiles.map((f) => f.name), notes } };
}

// ------------------------------------------------------------------------------------------- recommendations
function recommend({ ast, target, add, loaded, hasLoad, layout }) {
  const rec = (f) => add({ category: 'recommendation', severity: 'info', ...f });
  const all = [];
  (function w(nodes, chain) { for (const n of nodes) { if (n.inactive) continue; all.push({ n, chain }); if (n.children) w(n.children, [...chain, n]); } })(ast, []);
  const dirs = (lname) => all.filter((x) => x.n.lname === lname);
  const inVhost = (x) => x.chain.find((c) => c.lname === 'virtualhost');
  const at = (x) => ({ file: x.n.file, line: x.n.line, section: inVhost(x) ? `<VirtualHost ${inVhost(x).args.join(' ')}>` : 'main' });
  const docs = (mod, name) => `${kb.docsBase}${mod}.html#${name.toLowerCase()}`;
  const vhosts = dirs('virtualhost').filter((x) => x.n.section);
  const sslVh = vhosts.filter((v) => flat(v.n.children).some((c) => c.lname === 'sslengine' && /^on$/i.test(c.args[0] || '')));
  const gte = (v) => V.gte(target, v);

  // HTTP/2 (Protocols since 2.4.17)
  const proto = dirs('protocols');
  if (sslVh.length && gte('2.4.17') && !proto.some((p) => p.n.args.includes('h2'))) rec({ id: 'rec-apache-http2', title: 'Enable HTTP/2 for the TLS virtual hosts', detail: `httpd ${target} supports HTTP/2 through mod_http2 (Protocols since 2.4.17). Browsers multiplex all requests over one connection.`, fix: `Add \`Protocols h2 http/1.1\` at server level${hasLoad && !loaded.has('http2_module') ? ` and enable mod_http2 (${layout === 'debian' ? 'a2enmod http2' : 'LoadModule http2_module modules/mod_http2.so'})` : ''}. mpm_prefork does not support h2.`, ...at(sslVh[0]), docs: docs('core', 'Protocols') });
  for (const p of proto) if (p.n.args.includes('h2') && hasLoad && !loaded.has('http2_module')) rec({ id: 'rec-apache-http2-module', severity: 'warning', title: 'Protocols lists h2 but mod_http2 is not loaded', detail: 'Without mod_http2 the h2 protocol is ignored and clients stay on HTTP/1.1.', fix: layout === 'debian' ? 'Run `a2enmod http2`.' : 'Add `LoadModule http2_module modules/mod_http2.so`.', ...at(p), docs: `${kb.docsBase}mod_http2.html` });
  // TLS
  for (const s of dirs('sslcompression')) if (/^on$/i.test(s.n.args[0] || '')) rec({ id: 'rec-apache-ssl-compression', severity: 'warning', category: 'security', title: 'SSLCompression on enables the CRIME attack', detail: 'TLS-level compression leaks secrets from encrypted requests (CRIME). It is off by default since 2.4.4.', fix: 'Remove it or set `SSLCompression off`.', ...at(s), docs: docs('mod_ssl', 'SSLCompression') });
  for (const s of dirs('sslprotocol')) {
    const a = s.n.args.map((x) => x.replace(/^[+-]/, '').toLowerCase());
    if (a.includes('tlsv1.3') && V.lt(target, '2.4.36')) add({ id: 'compat-too-new', severity: 'error', title: 'TLSv1.3 in SSLProtocol needs httpd 2.4.36+', detail: 'TLSv1.3 support (with OpenSSL 1.1.1) arrived in httpd 2.4.36 (CHANGES); older releases reject the protocol name.', fix: 'Upgrade httpd or drop TLSv1.3.', since: '2.4.36', ...at(s), docs: docs('mod_ssl', 'SSLProtocol') });
  }
  if (sslVh.length && gte('2.4.11') && !dirs('sslsessiontickets').length) rec({ id: 'rec-apache-session-tickets', title: 'Consider SSLSessionTickets off', detail: 'Session ticket keys are rarely rotated by httpd (only on restart), which weakens forward secrecy. Available since 2.4.11.', fix: 'Add `SSLSessionTickets off` at server level.', ...at(sslVh[0]), docs: docs('mod_ssl', 'SSLSessionTickets') });
  for (const s of dirs('sslhonorcipherorder')) if (/^on$/i.test(s.n.args[0] || '') && dirs('sslprotocol').some((p) => /-all/.test(p.n.args.join(' ')) && /\+TLSv1\.2/.test(p.n.args.join(' ')) && !/TLSv1\.1|\bTLSv1\b/.test(p.n.args.join(' ').replace(/\+TLSv1\.[23]/g, '')))) rec({ id: 'rec-apache-honor-cipher-order', title: 'SSLHonorCipherOrder is not needed with a modern-only cipher list', detail: 'With TLS 1.2+ AEAD ciphers only, letting clients choose (e.g. ChaCha20 on mobile) is recommended.', fix: 'Set `SSLHonorCipherOrder off`.', ...at(s), docs: docs('mod_ssl', 'SSLHonorCipherOrder') });
  // WebSockets: upgrade=websocket (2.4.47) vs mod_proxy_wstunnel
  for (const p of [...dirs('proxypass'), ...dirs('proxypassmatch')]) {
    const url = p.n.args.find((a) => /^wss?:\/\//i.test(a));
    if (url && gte('2.4.47')) rec({ id: 'rec-apache-websocket-upgrade', title: 'Proxy WebSockets with upgrade=websocket', detail: 'Since 2.4.47 mod_proxy_http tunnels WebSocket upgrades itself; ws:// URLs through mod_proxy_wstunnel are the older mechanism.', fix: `Use the http(s):// URL with \`upgrade=websocket\` (e.g. ProxyPass "${p.n.args[0]}" "${url.replace(/^ws/i, 'http')}" upgrade=websocket).`, ...at(p), docs: `${kb.docsBase}mod_proxy.html#wsupgrade` });
  }
  // LimitRequestBody: default was unlimited before 2.4.54
  if (V.lt(target, '2.4.54') && vhosts.length && !dirs('limitrequestbody').length) rec({ id: 'rec-apache-limit-body', title: 'Request bodies are unlimited on this release', detail: 'Before 2.4.54 the LimitRequestBody default was 0 (unlimited); 2.4.54 changed it to 1 GiB.', fix: 'Set `LimitRequestBody 10485760` (10 MiB) or what your application needs.', ...at(vhosts[0]), docs: docs('core', 'LimitRequestBody') });
  // mod_md: terms of service
  if (dirs('mdomain').length && !dirs('mdcertificateagreement').some((x) => /^accepted$/i.test(x.n.args[0] || ''))) rec({ id: 'rec-apache-md-agreement', severity: 'warning', title: 'MDomain without "MDCertificateAgreement accepted"', detail: 'Let\'s Encrypt requires accepting its terms of service; without it mod_md cannot get certificates.', fix: 'Add `MDCertificateAgreement accepted`.', ...at(dirs('mdomain')[0]), docs: docs('mod_md', 'MDCertificateAgreement') });
  // ProxyPass without timeouts
  if ((dirs('proxypass').length || dirs('balancermember').length) && !dirs('proxytimeout').length && !dirs('proxypass').some((p) => p.n.args.some((a) => /^timeout=/i.test(a)))) rec({ id: 'rec-apache-proxy-timeout', title: 'No ProxyTimeout', detail: 'Backend reads then wait for the core Timeout (60 s by default; 300 s in the Debian apache2.conf) before httpd gives up.', fix: 'Set `ProxyTimeout 60` (or what your slowest endpoint needs).', ...at(dirs('proxypass')[0] || dirs('balancermember')[0]), docs: `${kb.docsBase}mod_proxy.html#proxytimeout` });
}

module.exports = { validate, syntaxCheck, arity };

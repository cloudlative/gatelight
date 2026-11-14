'use strict';
/**
 * Version-aware validation of a Traefik configuration against the knowledge base built from the official docs
 * (src/kb/traefik.json, tools/kb/traefik.js):
 *   1. YAML / TOML syntax (line numbers)
 *   2. every option path of static files, CLI flags, dynamic files and docker labels: known? available in the target
 *      version (added later / removed)? deprecated per the migration guides? value of the documented type?
 *   3. router rules: syntax, matchers of the router's rule syntax (v2 / v3) and target version, arity, regex syntax
 *   4. a few value checks (TLS versions, addresses, URLs, paths) and version-aware recommendations
 */
const { suggest } = require('../../validate/suggest');
const K = require('./kb');
const M = require('./model');
const rules = require('./rules');
const YAML = require('./yaml');

const { getCI, isObj, arr } = M;
const GO_DURATION = /^-?(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/;
const TLS_VERSIONS = ['VersionTLS10', 'VersionTLS11', 'VersionTLS12', 'VersionTLS13'];

/** Leaves of a parsed document: [{ segs, value, line }]. Arrays of scalars are one leaf; arrays of objects recurse. */
function leaves(data, lines, base = []) {
  const out = [];
  const lineOf = (segs) => { for (let n = segs.length; n > 0; n--) { const l = YAML.lineOf(lines, segs.slice(0, n)); if (l) return l; } return 1; };
  const walk = (v, segs) => {
    if (Array.isArray(v) && v.length && v.every((x) => isObj(x))) { v.forEach((x, i) => walk(x, [...segs, i])); return; }
    if (isObj(v) && Object.keys(v).length) { for (const [k, x] of Object.entries(v)) walk(x, [...segs, k]); return; }
    out.push({ segs, value: v, line: lineOf(segs) });
  };
  walk(data, base);
  return out;
}

function typeProblem(t, v) {
  if (!t || v === null || v === undefined) return null;
  const scalar = (x) => typeof x !== 'object';
  if (t === 'bool') return typeof v === 'boolean' || /^(true|false)$/i.test(String(v)) ? null : 'a boolean (true / false)';
  if (t === 'int') return (typeof v === 'number' && Number.isInteger(v)) || /^-?\d+$/.test(String(v)) ? null : 'an integer';
  if (t === 'float') return typeof v === 'number' || /^-?\d+(\.\d+)?$/.test(String(v)) ? null : 'a number';
  if (t === 'duration') return typeof v === 'number' || GO_DURATION.test(String(v)) || /^\d+$/.test(String(v)) ? null : 'a duration such as 10s, 1m30s or 500ms (a bare number means seconds)';
  if (t.startsWith('list')) return Array.isArray(v) ? null : 'a list';
  if (t === 'string') return scalar(v) ? null : 'a single value (string)';
  if (t === 'object') return v === true || isObj(v) || (Array.isArray(v) && !v.length) ? null : 'a section (mapping)';
  return null;
}

function validate({ files, version } = {}) {
  const tv = K.resolveVersion(version);
  const target = { requested: tv.requested, version: tv.version, note: tv.note };
  const kbInfo = { generated: K.kb.generated, source: K.kb.source, latest: K.kb.latest };
  const findings = [];
  const add = (f) => findings.push({ category: 'compat', detail: '', fix: '', ...f });
  const major = tv.major; const minor = tv.minor;
  const docs = (topic, anchor) => K.docsUrl(topic, major, anchor);
  let list;
  try { list = M.normalizeFiles(files || []); } catch (e) { add({ id: 'traefik-syntax', severity: 'error', category: 'syntax', title: e.message, section: 'syntax', file: null, line: null }); return { target, kb: kbInfo, findings }; }

  const parsed = list.map((f) => ({ name: f.name, ...M.parseText(f.name, f.content) }));
  const cfg = M.load(list);
  for (const p of parsed) {
    if (p.error) add({ id: 'traefik-syntax', severity: 'error', category: 'syntax', section: 'syntax', file: p.name, line: p.error.line, title: `${p.format.toUpperCase()} syntax error: ${p.error.msg}`, detail: 'Traefik cannot read this file (the file provider skips it and keeps the previous configuration; a static file stops Traefik from starting).', fix: 'Fix the line (indentation, quotes, missing ":" or "=").' });
  }
  const staticData = cfg.static ? cfg.static.data : null;
  const defaultSyntax = String((staticData && getCI(getCI(staticData, 'core') || {}, 'defaultRuleSyntax')) || (major === '2' ? 'v2' : 'v3'));

  // ---- option paths -------------------------------------------------------------------------------------------
  const checkLeaves = (kind, ls, file, opts = {}) => {
    const reported = new Set();
    const otherKind = kind === 'static' ? 'dynamic' : 'static';
    for (const { segs, value, line } of ls) {
      const s = segs;
      const shown = s.filter((x) => typeof x !== 'number').join('.');
      const r = K.lookup(kind, s);
      if (r.missingAt !== undefined) {
        const prefix = s.slice(0, r.missingAt + 1).join('.');
        if (reported.has(prefix)) continue; reported.add(prefix);
        const word = String(s[r.missingAt]);
        // docker labels: the provider's own shortcut for the one server of a service (loadbalancer.server.port|scheme|url)
        if (opts.label && /^server$/i.test(word) && /loadBalancer$/i.test(String(s[r.missingAt - 1])) && /^(port|scheme|url|weight|preservePath)$/i.test(String(s[r.missingAt + 1] || ''))) continue;
        const where = s.slice(0, r.missingAt).filter((x) => typeof x !== 'number').join('.');
        const other = K.lookup(otherKind, s);
        if (other.missingAt === undefined && r.missingAt === 0) {
          add({ id: 'traefik-wrong-place', severity: 'error', section: shown, file, line, title: `"${s[0]}" is ${kind === 'static' ? 'dynamic' : 'static'} configuration, not ${kind}`, detail: kind === 'static' ? 'Routers, services, middlewares and TLS options are dynamic configuration: Traefik ignores them in the static file.' : 'entryPoints, providers, api, log, metrics and certificatesResolvers are static configuration: the file provider ignores them.', fix: kind === 'static' ? 'Move this part to a file loaded by providers.file (filename or directory).' : 'Move this part to traefik.yml (the static configuration).', docs: docs(kind === 'static' ? 'file' : 'staticReference') });
          continue;
        }
        const cands = K.childNames(r.parent);
        const sug = suggest(word, cands, 3);
        add({ id: 'traefik-unknown-option', severity: 'error', section: where || shown, file, line, title: `Unknown ${kind} option "${word}"${where ? ` in ${where}` : ''}`, detail: `${opts.label ? 'The label' : 'The option'} ${shown} is not in the Traefik ${tv.version} ${kind} configuration reference.${sug.length ? ` Did you mean ${sug.map((x) => `"${x}"`).join(' or ')}?` : ''}`, fix: sug.length ? `Use ${sug[0]}.` : `Valid here: ${cands.slice(0, 12).join(', ')}${cands.length > 12 ? ', ...' : ''}`, docs: docs(kind === 'static' ? 'staticReference' : 'dynamicReference') });
        continue;
      }
      if (r.open) continue;
      const kbPath = r.kbPath; const e = r.node.e;
      for (const c of r.caseMismatch || []) {
        if (opts.label) break;
        const key = `case|${s.slice(0, c.at + 1).join('.')}`;
        if (reported.has(key)) continue; reported.add(key);
        add({ id: 'traefik-option-case', severity: 'info', category: 'hygiene', section: shown, file, line, title: `"${c.written}" is documented as "${c.canonical}"`, detail: 'Traefik matches option names case-insensitively, so this works, but the documented spelling is easier to search and review.', fix: `Write ${c.canonical}.` });
      }
      // availability in the target version: report the outermost unavailable node only
      const segsKb = kbPath.split('.');
      let unavailable = null;
      for (let n = 1; n <= segsKb.length; n++) {
        const pth = segsKb.slice(0, n).join('.');
        const ent = (K.kb[kind] || {})[pth];
        if (ent && !K.available(ent, minor)) { unavailable = { path: pth, e: ent }; break; }
      }
      if (unavailable) {
        const key = `ver|${unavailable.path}`;
        if (!reported.has(key)) {
          reported.add(key);
          const u = unavailable.e;
          const newer = K.MINORS.indexOf(u.s) > K.MINORS.indexOf(minor);
          const dep = K.deprecation(unavailable.path);
          add({ id: newer ? 'traefik-option-too-new' : 'traefik-option-removed', severity: 'error', section: shown, file, line, title: newer ? `${unavailable.path.replace(/<name>\./g, '').replace(/\[\]/g, '')} needs Traefik ${u.s} or newer (target ${tv.version})` : `${unavailable.path.replace(/<name>\./g, '').replace(/\[\]/g, '')} was removed in Traefik ${u.u || '?'} (target ${tv.version})`, detail: newer ? 'Traefik refuses unknown options in the static configuration and ignores the router / middleware / service that uses them in the dynamic configuration.' : `It is not part of the ${tv.version} configuration reference.${dep && dep.use ? ` Use ${dep.use} instead.` : ''}${dep ? ` (${dep.title})` : ''}`, fix: newer ? `Upgrade Traefik to ${u.s}+ or remove the option.` : (dep && dep.use ? `Replace it with ${dep.use}.` : 'Remove the option.'), docs: dep ? dep.docs : docs(kind === 'static' ? 'staticReference' : 'dynamicReference'), since: u.s, until: u.u });
        }
        continue;
      }
      const dep = K.deprecation(kbPath);
      if (dep && K.MINORS.indexOf(minor) >= K.MINORS.indexOf(dep.dep)) {
        const key = `dep|${dep.re}|${s.slice(0, 4).join('.')}`;
        if (!reported.has(key)) {
          reported.add(key);
          const removedPerGuide = dep.removed && K.MINORS.indexOf(minor) >= K.MINORS.indexOf(dep.removed);
          add({ id: 'traefik-option-deprecated', severity: 'warning', section: shown, file, line, title: `${kbPath.replace(/<name>\./g, '').split('.').slice(-2).join('.')} is deprecated${dep.use ? `: use ${dep.use}` : ''}`, detail: `Deprecated since ${dep.dep}${removedPerGuide ? `; the migration guide lists it as removed in ${dep.removed} (Traefik logs a deprecation warning while it still accepts it)` : ''}. ${dep.title}.`, fix: dep.use ? `Replace with ${dep.use}.` : 'Remove it.', docs: dep.docs, since: dep.dep });
        }
      }
      // value type (labels are strings by nature and converted by the model)
      const want = typeProblem(e && e.t, value);
      if (want && !(opts.label && typeof value === 'string')) add({ id: 'traefik-option-type', severity: 'warning', section: shown, file, line, title: `${shown} should be ${want}`, detail: `Found ${JSON.stringify(value).slice(0, 60)}. The reference documents this option as ${e.t}.`, fix: `Write ${want}.`, docs: docs(kind === 'static' ? 'staticReference' : 'dynamicReference') });
    }
  };

  for (const p of parsed) {
    if (p.error) continue;
    const kind = M.classify(p.data);
    if (kind === 'static') checkLeaves('static', leaves(p.data, p.lines), p.name);
    else if (kind === 'dynamic') checkLeaves('dynamic', leaves(p.data, p.lines), p.name);
    else if (kind === 'mixed') {
      const st = {}; const dy = {};
      for (const [k, v] of Object.entries(p.data)) (/^(http|tcp|udp|tls)$/i.test(k) ? dy : st)[k] = v;
      checkLeaves('static', leaves(st, p.lines), p.name);
      checkLeaves('dynamic', leaves(dy, p.lines), p.name);
    } else if (kind === 'compose') {
      for (const c of M.composeLabels(p.data, p.lines)) {
        const { cfg: lc, where } = M.labelsToConfig(c.labels);
        const lineFor = (segs) => { const d = segs.filter((x) => typeof x !== 'number').join('.').toLowerCase(); const k = Object.keys(where).find((w) => w.toLowerCase() === d); return k ? c.labelLine[where[k]] : c.baseLine; };
        checkLeaves('dynamic', leaves(lc, new Map()).map((l) => ({ ...l, line: lineFor(l.segs) })), p.name, { label: true });
      }
      if (cfg.static && cfg.static.fromFlags && cfg.static.file === p.name) checkLeaves('static', leaves(cfg.static.data, cfg.static.lines), p.name, { label: true });
    }
  }

  // ---- values -------------------------------------------------------------------------------------------------
  const items = (k) => [...(cfg.items[k] || new Map()).values()];
  for (const o of cfg.tls.options.values()) for (const k of ['minVersion', 'maxVersion']) {
    const v = getCI(o.def, k);
    if (v != null && !TLS_VERSIONS.includes(String(v))) { const sug = suggest(String(v), TLS_VERSIONS, 1); add({ id: 'traefik-bad-value', severity: 'error', section: `tls.options.${o.name}`, file: o.file, line: o.lineOf([k]) || o.line, title: `tls.options.${o.name}.${k}: "${v}" is not a TLS version`, detail: `Valid values: ${TLS_VERSIONS.join(', ')}.`, fix: `Use ${sug[0] || 'VersionTLS12'}.`, docs: docs('tls') }); }
  }
  if (staticData && isObj(getCI(staticData, 'entryPoints'))) {
    for (const [n, ep] of Object.entries(getCI(staticData, 'entryPoints'))) {
      const a = getCI(ep || {}, 'address');
      if (a != null && !/^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]*):\d{1,5}(\/(tcp|udp))?$/.test(String(a))) add({ id: 'traefik-bad-value', severity: 'error', section: `entryPoints.${n}`, file: cfg.static.file, line: YAML.lineOf(cfg.static.lines, ['entryPoints', n, 'address']) || 1, title: `entryPoints.${n}.address "${a}" is not [host]:port[/tcp|/udp]`, detail: 'An entryPoint address is a port with an optional host and protocol, e.g. ":443" or "127.0.0.1:8080" or ":443/udp".', fix: 'Write the address as ":<port>".', docs: docs('entrypoints') });
    }
  }
  for (const it of items('http.services')) {
    const lb = getCI(it.def, 'loadBalancer'); if (!isObj(lb)) continue;
    arr(getCI(lb, 'servers')).forEach((s, i) => { const u = getCI(s || {}, 'url'); if (u != null && !/^[a-z][a-z0-9+.-]*:\/\/[^/\s]+/i.test(String(u))) add({ id: 'traefik-bad-value', severity: 'error', section: `http.services.${it.name}`, file: it.file, line: it.lineOf(['loadBalancer', 'servers', i]) || it.line, title: `Server URL "${u}" of service "${it.name}" needs a scheme`, detail: 'loadBalancer.servers[].url is a full URL such as http://10.0.0.1:8080.', fix: `Write http://${u}.`, docs: docs('services') }); });
    const hc = getCI(lb, 'healthCheck');
    if (isObj(hc) && getCI(hc, 'path') != null && !String(getCI(hc, 'path')).startsWith('/')) add({ id: 'traefik-bad-value', severity: 'warning', section: `http.services.${it.name}`, file: it.file, line: it.lineOf(['loadBalancer', 'healthCheck', 'path']) || it.line, title: `healthCheck path "${getCI(hc, 'path')}" should start with /`, detail: '', fix: 'Write the path starting with /.', docs: docs('services', 'health-check') });
  }

  // ---- router rules -------------------------------------------------------------------------------------------
  for (const [proto, kind] of [['http', 'http.routers'], ['tcp', 'tcp.routers']]) {
    for (const it of items(kind)) {
      const rule = getCI(it.def, 'rule');
      const line = it.lineOf(['rule']) || it.line;
      if (rule == null) { if (proto === 'http' && !it.def._defaultRule) add({ id: 'traefik-rule', severity: 'error', category: 'syntax', section: `${kind}.${it.name}`, file: it.file, line: it.line, title: `Router "${it.name}" has no rule`, detail: 'HTTP routers need a rule.', fix: 'Add rule: Host(`example.com`).', docs: docs('routers') }); continue; }
      const syntax = String(getCI(it.def, 'ruleSyntax') || defaultSyntax);
      if (major === '2' && syntax === 'v3' && !getCI(it.def, 'ruleSyntax')) { /* v2 target: v2 syntax only */ }
      const effSyntax = major === '2' ? 'v2' : syntax;
      const available = (e) => (effSyntax === 'v2' && major === '3' ? true : K.available(e, minor));
      const probs = rules.checkRule(String(rule), { syntax: effSyntax, kbMatchers: K.kb.matchers[proto], available, proto });
      for (const pr of probs) {
        const v3only = major === '2' && pr.code === 'other-syntax';
        add({
          id: 'traefik-rule', severity: pr.severity, category: pr.severity === 'error' ? 'syntax' : 'compat', section: `${kind}.${it.name}`, file: it.file, line,
          title: `Router "${it.name}": ${v3only ? `${pr.matcher}() is v3 rule syntax, not available in Traefik ${tv.version}` : pr.msg}`,
          detail: v3only ? `Traefik v2 only knows the v2 matchers (${Object.keys(K.kb.matchers[proto].v2).join(', ')}).` : (pr.code === 'other-syntax' && major === '3' ? `This router is parsed with the ${effSyntax} rule syntax${getCI(it.def, 'ruleSyntax') ? ' (ruleSyntax)' : getCI(getCI(staticData || {}, 'core') || {}, 'defaultRuleSyntax') ? ' (core.defaultRuleSyntax)' : ' (the v3 default)'}.` : ''),
          fix: v3only ? `Use ${({ Header: 'Headers', HeaderRegexp: 'HeadersRegexp', PathRegexp: 'Path(`{name:regex}`)', QueryRegexp: 'Query' })[pr.matcher] || 'a v2 matcher'} or upgrade to v3.` : pr.code === 'other-syntax' ? (effSyntax === 'v3' ? `Rewrite with the v3 matchers${rules.migrateRule(String(rule)) ? `: ${rules.migrateRule(String(rule))}` : ''}, or set ruleSyntax: v2 on the router.` : 'Use the v2 matchers or set ruleSyntax: v3.') : '',
          docs: pr.code === 'other-syntax' ? K.docsUrl('migrationV3', '3') : docs(proto === 'tcp' ? 'tcpRouters' : 'routers'), since: pr.since, until: pr.until,
        });
      }
      const pri = getCI(it.def, 'priority');
      if (pri != null && !(Number.isInteger(Number(pri)))) add({ id: 'traefik-bad-value', severity: 'error', section: `${kind}.${it.name}`, file: it.file, line: it.lineOf(['priority']) || it.line, title: `priority "${pri}" is not an integer`, detail: '', fix: 'Use a whole number (higher wins).', docs: docs('routers', 'priority') });
    }
  }

  // ---- middleware types available in the target (labels and files) ---------------------------------------------
  // (covered by the option path check: http.middlewares.<name>.<type> is versioned in the KB)

  // ---- recommendations ---------------------------------------------------------------------------------------
  const rec = (f) => add({ category: 'recommendation', severity: 'info', ...f });
  if (major === '3') {
    const v2Routers = [...items('http.routers'), ...items('tcp.routers')].filter((it) => String(getCI(it.def, 'ruleSyntax') || defaultSyntax) === 'v2');
    if (v2Routers.length) rec({ id: 'rec-traefik-rule-syntax', section: 'http.routers', file: v2Routers[0].file, line: v2Routers[0].lineOf(['rule']) || v2Routers[0].line, title: `${v2Routers.length} router${v2Routers.length > 1 ? 's use' : ' uses'} the deprecated v2 rule syntax`, detail: 'Traefik v3 still parses v2 rules (ruleSyntax: v2 / core.defaultRuleSyntax: v2), but that support is deprecated and goes away in the next major release.', fix: 'Rewrite the rules with the v3 matchers (Header, HeaderRegexp, one value per matcher, Go regexps) and drop ruleSyntax.', docs: K.docsUrl('migrationV3', '3') });
  }
  if (K.MINORS.indexOf(minor) >= K.MINORS.indexOf('2.2') && staticData) {
    const eps = getCI(staticData, 'entryPoints') || {};
    const redirectMws = items('http.middlewares').filter((it) => getCI(it.def, 'redirectScheme'));
    const used = redirectMws.filter((m) => items('http.routers').some((r) => arr(getCI(r.def, 'middlewares')).some((x) => String(x).replace(/@.*$/, '') === m.name)));
    if (used.length && !Object.values(eps).some((ep) => M.pick(ep || {}, 'http', 'redirections'))) rec({ id: 'rec-traefik-ep-redirect', section: 'entryPoints', file: used[0].file, line: used[0].line, title: 'Redirect to HTTPS on the entryPoint instead of per-router redirectScheme', detail: 'Since v2.2 `entryPoints.web.http.redirections.entryPoint` redirects every request of the entryPoint, so no router can forget it.', fix: 'Add http.redirections.entryPoint { to: websecure, scheme: https } to the HTTP entryPoint.', docs: docs('entrypoints', 'redirection') });
  }
  for (const it of items('http.services')) {
    const ck = M.pick(it.def, 'loadBalancer', 'sticky', 'cookie');
    if (isObj(ck) || ck === true || ck === '') {
      const c = isObj(ck) ? ck : {};
      if (!getCI(c, 'secure') || !getCI(c, 'httpOnly')) rec({ id: 'rec-traefik-sticky-cookie', section: `http.services.${it.name}`, file: it.file, line: it.lineOf(['loadBalancer', 'sticky']) || it.line, title: `Sticky cookie of "${it.name}" without ${[!getCI(c, 'secure') && 'secure', !getCI(c, 'httpOnly') && 'httpOnly'].filter(Boolean).join(' and ')}`, detail: 'The affinity cookie reveals backend choice; secure keeps it off plain HTTP and httpOnly away from scripts.', fix: 'Set sticky.cookie.secure: true and httpOnly: true.', docs: docs('services', 'sticky-sessions') });
    }
  }
  if (cfg.static && !cfg.static.fromFlags && cfg.tls.options.size === 0 && items('http.routers').some((r) => getCI(r.def, 'tls') !== undefined)) rec({ id: 'rec-traefik-tls-options', section: 'tls.options', file: cfg.static.file, line: 1, title: 'No tls.options: the TLS defaults depend on the Traefik / Go version', detail: 'An explicit `default` TLS option with minVersion VersionTLS12 and sniStrict documents the policy and keeps it stable across upgrades.', fix: 'Add tls.options.default { minVersion: VersionTLS12, sniStrict: true } to a dynamic file.', docs: docs('tls') });

  const SEVR = { error: 0, warning: 1, info: 2 };
  findings.sort((a, b) => (a.file === b.file ? (a.line || 0) - (b.line || 0) : String(a.file).localeCompare(String(b.file))) || SEVR[a.severity] - SEVR[b.severity]);
  return { target, kb: kbInfo, findings };
}

module.exports = { validate, leaves, typeProblem };

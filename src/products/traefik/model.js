'use strict';
/**
 * Traefik configuration -> GateLight's shared section model.
 *
 * Inputs (any mix, YAML or TOML):
 *   - static configuration (traefik.yml / traefik.toml): entryPoints, providers, api, log, accessLog, metrics, ...
 *   - dynamic configuration of the file provider (one or many files): http / tcp / udp / tls
 *   - docker-compose.yml with `traefik.*` container labels (docker provider)
 *
 * Model (why: an entryPoint is what listens - like an HAProxy frontend / NGINX listen - and routers are its routing rules):
 *   entryPoint -> frontend   (binds from `address`, ssl when it terminates TLS, serverNames = Host()/HostSNI() of its routers)
 *   router     -> route(s)   (one per OR branch of the rule, in Traefik's evaluation order: priority, then name)
 *   service    -> backend    (loadBalancer servers; weighted / mirroring / failover services list their child services)
 * Routers without `entryPoints` attach to the default entryPoints (all, or those with `asDefault: true`).
 */
const fs = require('fs');
const path = require('path');
const YAML = require('./yaml');
const TOML = require('./toml');
const rules = require('./rules');
const kb = require('../../kb/traefik.json');

const MAX_FILES = 500;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const STATIC_KEYS = new Set(['global', 'core', 'serversTransport', 'tcpServersTransport', 'entryPoints', 'providers', 'api', 'metrics', 'ping', 'log', 'accessLog', 'tracing', 'hostResolver', 'certificatesResolvers', 'experimental', 'pilot', 'spiffe', 'ocsp']);
const DYNAMIC_KEYS = new Set(['http', 'tcp', 'udp', 'tls']);
const INTERNAL = new Set(['api', 'dashboard', 'noop', 'prometheus', 'ping', 'rest']);
const MAX_PRIORITY = 2147483646; // entryPoint redirection router: MaxInt32 - 1 (routing/entrypoints "redirections.entryPoint.priority")

// ------------------------------------------------------------------------------------------------ helpers
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : v == null || v === '' ? [] : [v]);
const lc = (s) => String(s).toLowerCase();
/** Case-insensitive property read (Traefik option names are case-insensitive in files and labels). */
function getCI(o, key) {
  if (!isObj(o)) return undefined;
  if (Object.prototype.hasOwnProperty.call(o, key)) return o[key];
  const k = Object.keys(o).find((x) => lc(x) === lc(key));
  return k === undefined ? undefined : o[k];
}
const pick = (o, ...keys) => keys.reduce((cur, k) => getCI(cur, k), o);
const realKey = (o, key) => (isObj(o) ? Object.keys(o).find((x) => lc(x) === lc(key)) : undefined);
const truthy = (v) => v === true || /^(true|1)$/i.test(String(v));

/** Split "name@provider". */
function qualify(ref, defaultProvider) {
  const s = String(ref || '');
  const i = s.lastIndexOf('@');
  return i > 0 ? { name: s.slice(0, i), provider: s.slice(i + 1) } : { name: s, provider: defaultProvider };
}

/** Go templates in file-provider files: keep line numbers, replace the template actions so the document parses. */
function neutralizeTemplates(text) {
  if (!/\{\{/.test(text)) return { text, templated: false };
  const out = text.split('\n').map((l) => {
    if (/^\s*\{\{[^}]*\}\}\s*$/.test(l)) return `#${l.slice(1)}`; // {{ range ... }} / {{ end }} on their own line
    return l.replace(/\{\{.*?\}\}/g, (m) => 'T'.repeat(Math.max(1, m.length)).replace(/^T/, 'X'));
  });
  return { text: out.join('\n'), templated: true };
}

/** Parse one file by its extension (YAML or TOML; other names: try YAML, then TOML). */
function parseText(name, content) {
  const tpl = neutralizeTemplates(String(content || ''));
  const ext = path.extname(name).toLowerCase();
  const attempt = (fmt) => {
    const r = fmt === 'toml' ? TOML.parse(tpl.text) : YAML.parse(tpl.text);
    return { format: fmt, data: r.data, lines: r.lines, warnings: r.warnings || [] };
  };
  try {
    if (ext === '.toml') return { ...attempt('toml'), templated: tpl.templated };
    if (ext === '.yml' || ext === '.yaml') return { ...attempt('yaml'), templated: tpl.templated };
    try { return { ...attempt('yaml'), templated: tpl.templated }; } catch (e) { try { return { ...attempt('toml'), templated: tpl.templated }; } catch { throw e; } }
  } catch (e) {
    return { format: ext === '.toml' ? 'toml' : 'yaml', data: null, lines: new Map(), warnings: [], error: { msg: e.reason || e.message, line: e.line || 1 }, templated: tpl.templated };
  }
}

/** What a parsed file is: 'static' | 'dynamic' | 'compose' | 'mixed' | 'unknown'. */
function classify(data) {
  if (!isObj(data)) return 'unknown';
  const keys = Object.keys(data);
  const svc = getCI(data, 'services');
  if (isObj(svc) && Object.values(svc).some((s) => isObj(s) && (getCI(s, 'image') !== undefined || getCI(s, 'labels') !== undefined || getCI(s, 'build') !== undefined))) return 'compose';
  const st = keys.filter((k) => STATIC_KEYS.has(k) || [...STATIC_KEYS].some((s) => lc(s) === lc(k))).length;
  const dy = keys.filter((k) => DYNAMIC_KEYS.has(lc(k))).length;
  if (st && dy) return 'mixed';
  if (st) return 'static';
  if (dy) return 'dynamic';
  return 'unknown';
}

// ------------------------------------------------------------------------------------------------ docker labels
/** Canonical option names from the KB (dynamic paths), for case-insensitive labels. */
const CANON = (() => {
  const children = new Map(); // parent path -> Map(lc child -> child)
  for (const p of Object.keys(kb.dynamic)) {
    const segs = p.split('.'); let parent = '';
    for (const s of segs) { if (!children.has(parent)) children.set(parent, new Map()); children.get(parent).set(lc(s.replace(/\[\]$/, '')), s.replace(/\[\]$/, '')); parent = parent ? `${parent}.${s}` : s; }
  }
  return children;
})();
const TYPE_OF = (kbPath) => (kb.dynamic[kbPath] || kb.dynamic[`${kbPath}[]`] || {}).t;

/**
 * Convert `traefik.*` labels of one container into dynamic configuration (docker provider rules, routing/providers/docker):
 * option names are case-insensitive, list values are comma-separated, `loadbalancer.server.port/scheme/url` define the one server.
 */
function labelsToConfig(labels) {
  const cfg = {}; const where = {}; const extra = {};
  for (const [k0, v] of Object.entries(labels)) {
    const k = k0.trim();
    if (!/^traefik\./i.test(k)) continue;
    const rest = k.slice(8);
    if (/^(enable|docker\.|tags$|constraint)/i.test(rest)) { extra[lc(rest)] = v; continue; }
    const segs = rest.split('.');
    // canonicalise each segment along the KB tree; user names (routers, services, middlewares, headers) stay as written
    const canon = []; let kp = '';
    for (let i = 0; i < segs.length; i++) {
      const kids = CANON.get(kp);
      const c = kids && kids.get(lc(segs[i]));
      let seg = segs[i]; let kseg;
      if (c) { seg = c; kseg = c; } else if (kids && kids.has('<name>')) { kseg = '<name>'; } else kseg = segs[i];
      // the docker provider defines one server per service: loadbalancer.server.port|scheme|url
      if (lc(seg) === 'server' && /loadbalancer$/i.test(canon[canon.length - 1] || '')) { seg = 'server'; kseg = 'servers[]'; }
      canon.push(seg); kp = kp ? `${kp}.${kseg}` : kseg;
    }
    let val = v == null ? '' : String(v);
    const t = TYPE_OF(kp);
    let value = val;
    if (t && t.startsWith('list')) value = val.split(',').map((x) => x.trim()).filter(Boolean);
    else if (t === 'bool') value = /^true$/i.test(val) ? true : /^false$/i.test(val) ? false : val;
    else if (t === 'int') value = /^-?\d+$/.test(val) ? Number(val) : val;
    let o = cfg;
    canon.forEach((s, i) => { if (i === canon.length - 1) o[s] = value; else { if (!isObj(o[s])) o[s] = {}; o = o[s]; } });
    where[canon.join('.')] = k0;
    val = null;
  }
  return { cfg, where, extra };
}
const normalizeName = (s) => String(s).replace(/[^a-zA-Z0-9-]+/g, '-').replace(/^-+|-+$/g, ''); // provider.Normalize

/** Canonical static option names from the KB, for case-insensitive CLI flags / env. */
const CANON_STATIC = (() => {
  const children = new Map();
  for (const p of Object.keys(kb.static)) {
    const segs = p.split('.'); let parent = '';
    for (const s0 of segs) { const s1 = s0.replace(/\[\]$/, ''); if (!children.has(parent)) children.set(parent, new Map()); children.get(parent).set(lc(s1), s1); parent = parent ? `${parent}.${s0}` : s0; }
  }
  return children;
})();
/**
 * Static configuration from CLI flags (`--entryPoints.web.address=:80`, reference/static-configuration/cli):
 * returns { data, lines: Map } with option names in their documented case. `items` = [{ text, line }].
 */
function flagsToStatic(items) {
  const data = {}; const lines = new Map();
  for (const { text, line } of items) {
    const m = /^--([A-Za-z0-9_.-]+)(?:[= ](.*))?$/.exec(String(text).trim());
    if (!m) continue;
    const segs = m[1].split('.'); const canon = []; let kp = '';
    for (const sg of segs) {
      const kids = CANON_STATIC.get(kp); const c = kids && kids.get(lc(sg));
      let kseg;
      if (c) { canon.push(c); kseg = c; } else { canon.push(sg); kseg = kids && kids.has('<name>') ? '<name>' : sg; }
      kp = kp ? `${kp}.${kseg}` : kseg;
    }
    const t = (kb.static[kp] || {}).t;
    let v = m[2] === undefined ? true : String(m[2]).replace(/^(["'])(.*)\1$/, '$2');
    if (t && t.startsWith('list') && typeof v === 'string') v = v.split(',').map((x) => x.trim()).filter(Boolean);
    else if (t === 'bool' && typeof v === 'string') v = /^true$/i.test(v) ? true : /^false$/i.test(v) ? false : v;
    else if (t === 'int' && /^-?\d+$/.test(v)) v = Number(v);
    else if (!t && m[2] === undefined && /^(api|ping|accessLog|metrics\.prometheus|api\.dashboard|api\.insecure)$/i.test(m[1])) v = m[1].includes('.') ? true : {};
    let o = data;
    canon.forEach((k, i) => {
      if (i === canon.length - 1) { if (isObj(o[k]) && v === true) { /* --api plus --api.x */ } else o[k] = v; } else { if (!isObj(o[k])) o[k] = {}; o = o[k]; }
      lines.set(YAML.keyOf(canon.slice(0, i + 1)), lines.get(YAML.keyOf(canon.slice(0, i + 1))) || line);
    });
  }
  return { data, lines };
}

/** Labels of every compose service: [{ svcName, svc, labels: {key: value}, labelLine: {key: line}, baseLine }]. */
function composeLabels(data, lines) {
  const out = [];
  const services = getCI(data, 'services') || {};
  for (const [svcName, svc] of Object.entries(services)) {
    if (!isObj(svc)) continue;
    const labelsRaw = getCI(svc, 'labels');
    const labels = {}; const labelLine = {};
    const baseLine = YAML.lineOf(lines, ['services', svcName]) || 1;
    if (Array.isArray(labelsRaw)) labelsRaw.forEach((l, i) => { const t = String(l); const eq = t.indexOf('='); const k = eq < 0 ? t : t.slice(0, eq); labels[k] = eq < 0 ? '' : t.slice(eq + 1); labelLine[k] = YAML.lineOf(lines, ['services', svcName, realKey(svc, 'labels'), i]) || baseLine; });
    else if (isObj(labelsRaw)) for (const [k, v] of Object.entries(labelsRaw)) { labels[k] = v == null ? '' : String(v); labelLine[k] = YAML.lineOf(lines, ['services', svcName, realKey(svc, 'labels'), k]) || baseLine; }
    out.push({ svcName, svc, labels, labelLine, baseLine });
  }
  return out;
}

/** docker-compose.yml -> per-container dynamic configs (provider "docker"). */
function composeToDynamic(file, data, lines, staticCfg, notes) {
  const docker = pick(staticCfg || {}, 'providers', 'docker');
  const exposedByDefault = docker && getCI(docker, 'exposedByDefault') !== undefined ? truthy(getCI(docker, 'exposedByDefault')) : true;
  const out = [];
  for (const { svcName, svc, labels, labelLine, baseLine } of composeLabels(data, lines)) {
    const hasTraefik = Object.keys(labels).some((k) => /^traefik\./i.test(k));
    const enable = labels['traefik.enable'] !== undefined ? truthy(labels['traefik.enable']) : exposedByDefault;
    if (!enable) { if (hasTraefik) notes.push({ file, line: baseLine, msg: `container "${svcName}" has traefik labels but is not enabled (traefik.enable=true is required when exposedByDefault is false)` }); continue; }
    if (!hasTraefik && !exposedByDefault) continue;
    const container = normalizeName(getCI(svc, 'container_name') || svcName);
    const { cfg, where } = labelsToConfig(labels);
    const lineFor = (dotted) => { const d = lc(dotted); const k = Object.keys(where).find((w) => lc(w) === d || lc(w).startsWith(`${d}.`)); return k ? labelLine[where[k]] : null; };
    // implicit port: loadbalancer.server.port label, else the single exposed / published port
    const ports = [...arr(getCI(svc, 'expose')), ...arr(getCI(svc, 'ports')).map((p) => String(isObj(p) ? getCI(p, 'target') : p).split(':').pop().split('/')[0])].map(String).filter((p) => /^\d+$/.test(p));
    for (const proto of ['http', 'tcp']) {
      const sect = getCI(cfg, proto) || {};
      const routers = getCI(sect, 'routers') || {}; const svcs = getCI(sect, 'services') || {};
      if (proto === 'tcp' && !Object.keys(routers).length && !Object.keys(svcs).length) continue;
      if (proto === 'http' && !Object.keys(routers).length && !Object.keys(svcs).length && !hasTraefik && !exposedByDefault) continue;
      // default service = the container, with its single port
      if (!Object.keys(svcs).length) {
        if (proto === 'http' && !hasTraefik && !ports.length) continue;
        svcs[container] = { loadBalancer: { server: {} } };
      }
      for (const [sn, s] of Object.entries(svcs)) {
        const lb = getCI(s, 'loadBalancer');
        if (!isObj(lb)) continue;
        const server = getCI(lb, 'server') || {};
        const port = getCI(server, 'port') || (ports.length === 1 ? ports[0] : null);
        if (!port && !getCI(server, 'url')) notes.push({ file, line: baseLine, msg: `container "${svcName}": service "${sn}" has no loadbalancer.server.port and the container does not expose exactly one port; Traefik needs the port label` });
        const host = svcName;
        if (proto === 'http') lb.servers = [{ url: getCI(server, 'url') || `${getCI(server, 'scheme') || 'http'}://${host}:${port || '80'}` }];
        else lb.servers = [{ address: `${host}:${port || '?'}` }];
        delete lb[realKey(lb, 'server')];
      }
      // routers: default rule, default service
      const svcNames = Object.keys(svcs);
      if (!Object.keys(routers).length && proto === 'http') routers[container] = {};
      for (const [rn, r] of Object.entries(routers)) {
        if (getCI(r, 'rule') === undefined && proto === 'http') { r.rule = docker && getCI(docker, 'defaultRule') ? String(getCI(docker, 'defaultRule')).replace(/\{\{\s*normalize\s+\.Name\s*\}\}/, container) : `Host(\`${container}\`)`; r._defaultRule = true; }
        if (getCI(r, 'service') === undefined) {
          if (svcNames.length === 1) { r.service = svcNames[0]; r._defaultService = true; } else notes.push({ file, line: lineFor(`${proto}.routers.${rn}`) || baseLine, msg: `router "${rn}" (container ${svcName}) has no service and the container defines ${svcNames.length} services: Traefik cannot pick one` });
        }
      }
      sect.routers = routers; sect.services = svcs; cfg[proto] = sect;
    }
    out.push({ container: svcName, cfg, lineFor, baseLine });
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ loading
/**
 * Read the file set into one structure:
 * { static: {data, file, lines} | null, items: { 'http.routers': Map(qualifiedName -> item) ... }, files, notes, kinds }
 * item = { name, provider, def, file, line, lineOf(subpath) }.
 */
function load(files) {
  const parsed = files.map((f) => ({ name: f.name, content: f.content, ...parseText(f.name, f.content) }));
  const notes = [];
  for (const p of parsed) {
    p.kind = p.error ? 'error' : classify(p.data);
    if (p.error) notes.push({ file: p.name, line: p.error.line, msg: `${p.format.toUpperCase()} syntax error: ${p.error.msg}`, syntax: true });
    if (p.templated) notes.push({ file: p.name, line: 1, msg: 'Go template syntax ({{ }}) was left as written; templated values are shown as placeholders and loops are not expanded' });
    for (const w of p.warnings) notes.push({ file: p.name, line: w.line, msg: w.msg });
  }
  const statics = parsed.filter((p) => p.kind === 'static' || p.kind === 'mixed');
  if (statics.length > 1) notes.push({ file: statics[1].name, line: 1, msg: `more than one static configuration (${statics.map((s) => s.name).join(', ')}); using ${statics[0].name}` });
  for (const p of parsed.filter((x) => x.kind === 'mixed')) notes.push({ file: p.name, line: 1, msg: 'this file mixes static options (entryPoints, providers, ...) with dynamic ones (http, tcp, tls); Traefik reads them from different places: the dynamic part is ignored unless this file is also loaded by the file provider' });
  let st = statics[0] || null;
  // no static file: a traefik container in docker-compose may carry the static configuration as CLI flags
  if (!st) {
    for (const p of parsed.filter((x) => x.kind === 'compose')) {
      for (const [svcName, svc] of Object.entries(getCI(p.data, 'services') || {})) {
        if (!isObj(svc) || !/(^|\/)traefik(:|$)/i.test(String(getCI(svc, 'image') || ''))) continue;
        const cmd = getCI(svc, 'command'); const ck = realKey(svc, 'command');
        const list = Array.isArray(cmd) ? cmd.map((c, i) => ({ text: String(c), line: YAML.lineOf(p.lines, ['services', svcName, ck, i]) || 1 })) : typeof cmd === 'string' ? cmd.split(/\s+(?=--)/).map((c) => ({ text: c, line: YAML.lineOf(p.lines, ['services', svcName, ck]) || 1 })) : [];
        if (list.some((x) => /^--configFile/i.test(x.text.trim()))) notes.push({ file: p.name, line: list[0].line, msg: `the traefik container reads its static configuration from ${list.find((x) => /^--configFile/i.test(x.text.trim())).text.split('=')[1] || 'a file'}; upload that file too` });
        const flags = list.filter((x) => /^--/.test(x.text.trim()) && !/^--configFile/i.test(x.text.trim()));
        if (flags.length) { const f = flagsToStatic(flags); st = { name: p.name, data: f.data, lines: f.lines, format: 'cli', fromFlags: true }; notes.push({ file: p.name, line: flags[0].line, msg: `static configuration read from the command-line flags of the "${svcName}" container` }); break; }
      }
      if (st) break;
    }
  }
  const staticCfg = st ? st.data : null;

  // file provider: which dynamic files does the static configuration load?
  const fileProv = staticCfg ? pick(staticCfg, 'providers', 'file') : null;
  if (fileProv) {
    const fname = getCI(fileProv, 'filename'); const dir = getCI(fileProv, 'directory');
    const names = parsed.map((p) => p.name);
    if (fname) { const b = path.posix.basename(String(fname)); if (!names.some((n) => n === fname || path.posix.basename(n) === b)) notes.push({ file: st.name, line: YAML.lineOf(st.lines, ['providers', realKey(staticCfg.providers, 'file'), realKey(fileProv, 'filename')]) || 1, msg: `providers.file.filename "${fname}" is not among the uploaded files` }); }
    if (dir) { const b = path.posix.basename(String(dir).replace(/\/+$/, '')); if (!names.some((n) => n.split('/').slice(0, -1).includes(b) || n.startsWith(`${String(dir).replace(/^\/+/, '')}/`))) notes.push({ file: st.name, line: YAML.lineOf(st.lines, ['providers', realKey(staticCfg.providers, 'file'), realKey(fileProv, 'directory')]) || 1, msg: `providers.file.directory "${dir}": no uploaded file is in a folder named "${b}"` }); }
  }

  const items = {};
  const bucket = (k) => { if (!items[k]) items[k] = new Map(); return items[k]; };
  const add = (kind, name, provider, def, file, lineOf) => {
    const key = `${name}@${provider}`;
    if (bucket(kind).has(key)) notes.push({ file, line: lineOf([]), msg: `${kind.replace('.', ' ')} "${name}" is defined more than once (also in ${bucket(kind).get(key).file}); Traefik reports a conflict and drops it` });
    bucket(kind).set(key, { name, provider, def, file, line: lineOf([]), lineOf, kind });
  };
  const tlsCerts = []; const tlsOptions = new Map(); const tlsStores = new Map();
  const ingestDynamic = (data, file, provider, lineOfPath) => {
    for (const proto of ['http', 'tcp', 'udp']) {
      const sect = getCI(data, proto); if (!isObj(sect)) continue;
      const pk = realKey(data, proto);
      for (const kind of ['routers', 'services', 'middlewares', 'serversTransports']) {
        const group = getCI(sect, kind); if (!isObj(group)) continue;
        const gk = realKey(sect, kind);
        for (const [n, def] of Object.entries(group)) add(`${proto}.${kind}`, n, provider, isObj(def) ? def : {}, file, (sub) => lineOfPath([pk, gk, n, ...sub]));
      }
    }
    const tls = getCI(data, 'tls');
    if (isObj(tls)) {
      const tk = realKey(data, 'tls');
      arr(getCI(tls, 'certificates')).forEach((c, i) => tlsCerts.push({ def: c, file, line: lineOfPath([tk, realKey(tls, 'certificates'), i]) }));
      for (const [n, def] of Object.entries(getCI(tls, 'options') || {})) tlsOptions.set(n, { name: n, def: def || {}, file, line: lineOfPath([tk, realKey(tls, 'options'), n]), lineOf: (sub) => lineOfPath([tk, realKey(tls, 'options'), n, ...sub]) });
      for (const [n, def] of Object.entries(getCI(tls, 'stores') || {})) tlsStores.set(n, { name: n, def: def || {}, file, line: lineOfPath([tk, realKey(tls, 'stores'), n]) });
    }
  };
  for (const p of parsed) {
    if (p.kind === 'dynamic' || p.kind === 'mixed') ingestDynamic(p.data, p.name, 'file', (sub) => YAML.lineOf(p.lines, sub) || closestLine(p.lines, sub));
    if (p.kind === 'compose') {
      for (const c of composeToDynamic(p.name, p.data, p.lines, staticCfg, notes)) {
        ingestDynamic(c.cfg, p.name, 'docker', (sub) => c.lineFor(sub.join('.')) || c.lineFor(sub.slice(0, 3).join('.')) || c.baseLine);
      }
    }
    if (p.kind === 'unknown' && !p.error) notes.push({ file: p.name, line: 1, msg: 'not recognised as a Traefik static or dynamic configuration (no entryPoints/providers or http/tcp/tls keys)' });
  }
  return { parsed, static: st ? { data: staticCfg, file: st.name, lines: st.lines, format: st.format, fromFlags: Boolean(st.fromFlags) } : null, items, tls: { certificates: tlsCerts, options: tlsOptions, stores: tlsStores }, notes };
}
/** Line of the nearest existing ancestor of a path. */
function closestLine(lines, sub) { for (let n = sub.length; n > 0; n--) { const l = YAML.lineOf(lines, sub.slice(0, n)); if (l) return l; } return 1; }

/** Guess the rule syntax used by the routers when the version is unknown: v3 unless v2-only matchers appear. */
function guessSyntax(cfg) {
  const def = cfg.static ? pick(cfg.static.data, 'core', 'defaultRuleSyntax') : undefined;
  if (def) return { syntax: String(def), why: 'core.defaultRuleSyntax' };
  let v2 = 0; let v3 = 0;
  for (const kind of ['http.routers', 'tcp.routers']) for (const it of (cfg.items[kind] || new Map()).values()) {
    const r = String(getCI(it.def, 'rule') || '');
    if (/\b(Headers|HeadersRegexp|HostHeader)\(/.test(r) || /\b(Host|Path|PathPrefix|HostRegexp|Method|ClientIP|HostSNI)\(`[^`]*`\s*,/.test(r) || /\b(Path|PathPrefix|HostRegexp)\(`[^`]*\{[a-z]+:/.test(r)) v2++;
    if (/\b(Header|HeaderRegexp|PathRegexp|QueryRegexp)\(/.test(r) || /\bQuery\(`[^`=]*`\s*,/.test(r)) v3++;
  }
  if (v2 > v3) return { syntax: 'v2', why: 'v2-only matchers in the rules' };
  return { syntax: 'v3', why: v3 ? 'v3-only matchers in the rules' : 'default' };
}

// ------------------------------------------------------------------------------------------------ model
function parseAddress(addr) {
  const a = String(addr || '');
  const m = /^(.*?):(\d+)(?:\/(tcp|udp))?$/.exec(a);
  if (!m) return { host: '', port: '', proto: 'tcp' };
  return { host: m[1], port: m[2], proto: m[3] || 'tcp' };
}
function serverFromUrl(url) {
  const s = String(url || '');
  const m = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/]*@)?([^/?#]+)(.*)$/i.exec(s);
  if (!m) return { scheme: 'http', address: s, path: '' };
  const scheme = lc(m[1]); let hostPort = m[2];
  if (!/:\d+$/.test(hostPort) || /^\[[^\]]+\]$/.test(hostPort)) hostPort = `${hostPort}:${scheme === 'https' ? 443 : 80}`;
  return { scheme, address: hostPort, path: m[3] || '' };
}
const redactUrl = (u) => String(u || '').replace(/(:\/\/[^:/@\s]+:)([^@\s]+)(@)/, '$1***$3');

function buildModel(cfg, opts = {}) {
  const notes = cfg.notes;
  const st = cfg.static ? cfg.static.data : null;
  const stLine = (...p) => (cfg.static ? (YAML.lineOf(cfg.static.lines, p) || closestLine(cfg.static.lines, p)) : 1);
  const stFile = cfg.static ? cfg.static.file : null;
  const syntaxInfo = opts.syntax ? { syntax: opts.syntax, why: 'requested' } : guessSyntax(cfg);
  const items = (k) => [...(cfg.items[k] || new Map()).values()];
  const sections = [];

  // ---- names: plain unless two providers define the same name
  const sectionName = (kind, it) => { const same = items(kind).filter((x) => x.name === it.name); return same.length > 1 ? `${it.name}@${it.provider}` : it.name; };
  const resolve = (kind, ref, provider) => {
    const q = qualify(ref, provider);
    if (q.provider === 'internal') return { internal: true, name: q.name, ref: `${q.name}@internal` };
    const it = (cfg.items[kind] || new Map()).get(`${q.name}@${q.provider}`);
    return it ? { item: it, name: sectionName(kind, it) } : { missing: true, name: q.name, provider: q.provider, ref: String(ref) };
  };

  // ---- global
  const directives = [];
  if (st) {
    const walk = (v, p) => {
      if (isObj(v)) { for (const [k, x] of Object.entries(v)) walk(x, [...p, k]); return; }
      directives.push({ keyword: p.join('.'), args: Array.isArray(v) ? v.map((x) => (isObj(x) ? JSON.stringify(x) : String(x))) : [String(v)], line: stLine(...p), file: stFile, raw: `${p.join('.')}: ${Array.isArray(v) ? `[${v.join(', ')}]` : v}` });
    };
    walk(st, []);
  }
  const apiCfg = st ? getCI(st, 'api') : undefined;
  sections.push({
    type: 'global', name: 'global', line: 1, endLine: 1, file: stFile || (cfg.parsed[0] || {}).name || '', mode: null, balance: null, timeouts: {}, binds: [], acls: [], routes: [], servers: [], users: [],
    effective: {}, directives,
    traefik: {
      hasStatic: Boolean(st), ruleSyntax: syntaxInfo.syntax, ruleSyntaxWhy: syntaxInfo.why,
      api: apiCfg === undefined ? null : { insecure: truthy(getCI(apiCfg || {}, 'insecure')), dashboard: getCI(apiCfg || {}, 'dashboard') === undefined ? true : truthy(getCI(apiCfg || {}, 'dashboard')) },
      logLevel: st ? pick(st, 'log', 'level') || null : null, accessLog: st ? getCI(st, 'accessLog') !== undefined : null,
      providers: st && isObj(getCI(st, 'providers')) ? Object.keys(getCI(st, 'providers')) : [],
    },
  });

  // ---- entryPoints
  const eps = new Map(); // name -> { name, address, def, line, file, implicit }
  const epDefs = st ? getCI(st, 'entryPoints') : null;
  if (isObj(epDefs)) for (const [n, def] of Object.entries(epDefs)) eps.set(n, { name: n, address: getCI(def || {}, 'address') || '', def: def || {}, line: stLine(realKey(st, 'entryPoints'), n), file: stFile });
  const internalRoutes = new Map(); // ep -> routes added by Traefik itself
  const addInternal = (ep, r) => { if (!internalRoutes.has(ep)) internalRoutes.set(ep, []); internalRoutes.get(ep).push(r); };
  if (st) {
    // api.insecure / ping / metrics publish on the "traefik" entryPoint (:8080) unless routed manually
    const needsTraefikEp = [];
    if (apiCfg !== undefined && truthy(getCI(apiCfg || {}, 'insecure'))) needsTraefikEp.push('api');
    const ping = getCI(st, 'ping'); if (ping !== undefined && !truthy(getCI(ping || {}, 'manualRouting'))) needsTraefikEp.push('ping');
    const prom = pick(st, 'metrics', 'prometheus'); if (prom !== undefined && !truthy(getCI(prom || {}, 'manualRouting'))) needsTraefikEp.push('prometheus');
    for (const what of needsTraefikEp) {
      const epName = what === 'api' ? 'traefik' : String(getCI((what === 'ping' ? ping : prom) || {}, 'entryPoint') || 'traefik');
      if (!eps.has(epName)) eps.set(epName, { name: epName, address: ':8080', def: {}, line: stLine(what === 'api' ? realKey(st, 'api') : what === 'ping' ? realKey(st, 'ping') : realKey(st, 'metrics')), file: stFile, implicit: true });
      const line = what === 'api' ? stLine(realKey(st, 'api'), realKey(apiCfg, 'insecure')) : what === 'ping' ? stLine(realKey(st, 'ping')) : stLine(realKey(st, 'metrics'), realKey(getCI(st, 'metrics'), 'prometheus'));
      const file = stFile;
      if (what === 'api') {
        addInternal(epName, internalRoute('api@internal', 'PathPrefix(`/api`)', MAX_PRIORITY, line, file, 'API (api.insecure)'));
        if (getCI(apiCfg || {}, 'dashboard') === undefined || truthy(getCI(apiCfg || {}, 'dashboard'))) addInternal(epName, internalRoute('dashboard@internal', 'PathPrefix(`/`)', MAX_PRIORITY - 1, line, file, 'Dashboard (api.insecure)'));
      } else addInternal(epName, internalRoute(`${what}@internal`, what === 'ping' ? 'PathPrefix(`/ping`)' : 'PathPrefix(`/metrics`)', MAX_PRIORITY, line, file, what === 'ping' ? 'Ping (health) endpoint' : 'Prometheus metrics'));
    }
  }
  // entryPoints only named by routers (no static configuration uploaded)
  const routerEps = (it) => arr(getCI(it.def, 'entryPoints'));
  for (const kind of ['http.routers', 'tcp.routers']) for (const it of items(kind)) for (const e of routerEps(it)) if (!eps.has(e)) eps.set(e, { name: e, address: e === 'web' || e === 'http' ? ':80' : e === 'websecure' || e === 'https' ? ':443' : '', def: {}, line: it.line, file: it.file, implicit: true, guessed: true });
  if (!st && eps.size && [...eps.values()].some((e) => e.guessed)) notes.push({ file: (cfg.parsed[0] || {}).name, line: 1, msg: 'no static configuration uploaded: entryPoint addresses are guessed from their names (web :80, websecure :443); upload traefik.yml for the real ones' });
  const anyRouterWithoutEp = ['http.routers', 'tcp.routers'].some((k) => items(k).some((it) => !routerEps(it).length));
  if (!eps.size && anyRouterWithoutEp) eps.set('(default)', { name: '(default)', address: ':80', def: {}, line: 1, file: (cfg.parsed[0] || {}).name, implicit: true, guessed: true });
  const udpEps = new Set([...eps.values()].filter((e) => parseAddress(e.address).proto === 'udp').map((e) => e.name));
  const asDefault = [...eps.values()].filter((e) => truthy(getCI(e.def, 'asDefault'))).map((e) => e.name);
  const defaultEps = (asDefault.length ? asDefault : [...eps.keys()]).filter((n) => !udpEps.has(n) && !internalOnly(n));
  function internalOnly(n) { const e = eps.get(n); return e && e.implicit && !e.guessed && n === 'traefik' && !items('http.routers').some((it) => routerEps(it).includes(n)); }

  // ---- middlewares -> transforms
  const mwTransforms = (refs, provider, epName, depth = 0, seen = new Set()) => {
    const out = []; const list = []; const missing = [];
    for (const ref of refs) {
      const r = resolve('http.middlewares', ref, provider);
      if (r.missing) { missing.push(r.ref); continue; }
      if (r.internal) { list.push({ name: r.ref, type: 'internal' }); continue; }
      const it = r.item; const def = it.def; const type = Object.keys(def)[0] || '?'; const o = def[type] || {};
      const base = { line: it.line, file: it.file, middleware: r.name };
      list.push({ name: r.name, type, line: it.line, file: it.file });
      const t = lc(type);
      if (t === 'chain') {
        if (depth > 8 || seen.has(r.name)) { notes.push({ file: it.file, line: it.line, msg: `middleware chain "${r.name}" refers to itself` }); continue; }
        const sub = mwTransforms(arr(getCI(o, 'middlewares')), it.provider, epName, depth + 1, new Set([...seen, r.name]));
        out.push(...sub.transforms); list.push(...sub.list); missing.push(...sub.missing);
      } else if (t === 'stripprefix') out.push({ action: 'strip-prefix', args: arr(getCI(o, 'prefixes')), text: `StripPrefix ${arr(getCI(o, 'prefixes')).join(' ')}`, ...base });
      else if (t === 'stripprefixregex') out.push({ action: 'strip-prefix-regex', args: arr(getCI(o, 'regex')), text: `StripPrefixRegex ${arr(getCI(o, 'regex')).join(' ')}`, ...base });
      else if (t === 'addprefix') out.push({ action: 'add-prefix', args: [String(getCI(o, 'prefix') || '')], text: `AddPrefix ${getCI(o, 'prefix') || ''}`, ...base });
      else if (t === 'replacepath') out.push({ action: 'replace-path', args: [String(getCI(o, 'path') || '')], text: `ReplacePath ${getCI(o, 'path') || ''}`, ...base });
      else if (t === 'replacepathregex') out.push({ action: 'replace-path-regex', args: [String(getCI(o, 'regex') || ''), String(getCI(o, 'replacement') || '')], text: `ReplacePathRegex ${getCI(o, 'regex') || ''} -> ${getCI(o, 'replacement') || ''}`, ...base });
      else if (t === 'redirectscheme') {
        const scheme = String(getCI(o, 'scheme') || 'https'); const port = getCI(o, 'port');
        const ep = eps.get(epName); const epTls = ep && epIsTls(ep);
        // redirectScheme only redirects requests whose scheme differs (middlewares/http/redirectscheme)
        const applies = !(epTls && scheme === 'https') && !(ep && !epTls && scheme === 'http');
        out.push({ action: 'redirect', args: [truthy(getCI(o, 'permanent')) ? '301' : '302', `${scheme}://{host}${port ? `:${port}` : ''}{path}`], text: `RedirectScheme ${scheme}${port ? `:${port}` : ''}${applies ? '' : ' (no-op here: the request already uses this scheme)'}`, conditional: !applies, ...base });
      } else if (t === 'redirectregex') out.push({ action: 'redirect', args: [String(getCI(o, 'regex') || ''), String(getCI(o, 'replacement') || '')], text: `RedirectRegex ${getCI(o, 'regex') || ''} -> ${getCI(o, 'replacement') || ''}`, conditional: !/^\^?\(?\.\*\)?\$?$|^\^?https?:\/\/\(?[^/]*\)?\/?\(\.\*\)/.test(String(getCI(o, 'regex') || '')), ...base });
      else if (t === 'headers') {
        const req = getCI(o, 'customRequestHeaders') || {};
        for (const [h, v] of Object.entries(req)) out.push({ action: 'set-header', args: [h, /^(authorization|cookie|x-api-key)$/i.test(h) ? '***' : String(v)], text: `${v === '' ? 'Remove' : 'Set'} request header ${h}`, ...base });
      }
    }
    return { transforms: out, list, missing };
  };
  const epIsTls = (ep) => Boolean(pick(ep.def, 'http', 'tls')) || items('http.routers').some((it) => (routerEps(it).includes(ep.name) || (!routerEps(it).length && defaultEps.includes(ep.name))) && getCI(it.def, 'tls') !== undefined && getCI(it.def, 'tls') !== false);

  // ---- routes per entryPoint
  const routesByEp = new Map([...eps.keys()].map((n) => [n, []]));
  const hostsByEp = new Map([...eps.keys()].map((n) => [n, new Set()]));
  for (const [proto, kind] of [['tcp', 'tcp.routers'], ['http', 'http.routers']]) {
    for (const it of items(kind)) {
      const def = it.def; const rule = String(getCI(def, 'rule') || '');
      const syntax = String(getCI(def, 'ruleSyntax') || syntaxInfo.syntax);
      const explicit = Number(getCI(def, 'priority')) || 0;
      const priority = explicit || rules.defaultPriority(rule);
      const epList = routerEps(it).length ? routerEps(it) : defaultEps;
      const svcRef = getCI(def, 'service');
      const svc = svcRef ? resolve(`${proto}.services`, svcRef, it.provider) : null;
      const tlsDef = getCI(def, 'tls');
      const name = sectionName(kind, it);
      for (const epName of epList) {
        if (!routesByEp.has(epName)) continue;
        const ep = eps.get(epName);
        const epMw = proto === 'http' ? arr(pick(ep.def, 'http', 'middlewares')) : [];
        const mw = proto === 'http' ? mwTransforms([...epMw, ...arr(getCI(def, 'middlewares'))], it.provider, epName) : { transforms: [], list: arr(getCI(def, 'middlewares')).map((m) => ({ name: m, type: 'tcp' })), missing: [] };
        const terminalT = mw.transforms.find((t) => t.action === 'redirect' && !t.conditional);
        const b = rule ? rules.branches(rule, syntax) : { branches: [{ matchers: [], hosts: [], paths: [], match: proto === 'tcp' ? 'any connection' : 'no rule (router is invalid)', short: '*', condition: '' }], error: proto === 'http' ? 'missing rule' : null };
        if (proto === 'tcp') b.branches.forEach((x) => { if (!x.matchers.length && !x.unparsable) x.match = 'any connection'; });
        b.branches.forEach((br, bi) => {
          br.hosts.forEach((h) => hostsByEp.get(epName).add(h));
          const internal = svc && svc.internal;
          routesByEp.get(epName).push({
            target: internal ? svc.ref : svc && !svc.missing ? svc.name : svcRef ? String(svcRef).replace(/@.*$/, '') : null,
            type: br.matchers.length || br.unparsable ? 'conditional' : 'default',
            condition: b.branches.length > 1 ? br.condition : rule, rawCondition: rule, match: br.match, short: br.short,
            matchers: br.matchers, hosts: br.hosts, paths: br.paths, priority, explicitPriority: explicit || null,
            transforms: mw.transforms.map((t) => ({ action: t.action, args: t.args, line: t.line, file: t.file, text: t.text, middleware: t.middleware })),
            passUrl: null, terminal: Boolean(internal || terminalT), line: it.lineOf([realKey(def, 'rule') || '']) || it.line, file: it.file,
            commented: false, dynamic: false, external: false,
            router: name, provider: it.provider, proto, entryPoints: epList, tls: tlsDef !== undefined && tlsDef !== false, tlsOptions: isObj(tlsDef) ? getCI(tlsDef, 'options') || null : null,
            certResolver: isObj(tlsDef) ? getCI(tlsDef, 'certResolver') || null : null, middlewares: mw.list, missingMiddlewares: mw.missing,
            missingService: svc && svc.missing ? svc.ref : (!svcRef && !internal ? '(none)' : null), ruleSyntax: syntax, ruleError: b.error || null, branch: b.branches.length > 1 ? bi + 1 : null,
            internal: Boolean(internal), defaultRule: Boolean(def._defaultRule),
          });
        });
      }
    }
  }
  // entryPoint redirections (an internal router with MaxInt32-1 priority, so it wins over every router of the entryPoint)
  for (const ep of eps.values()) {
    const red = pick(ep.def, 'http', 'redirections', 'entryPoint');
    if (red && routesByEp.has(ep.name)) {
      const to = String(getCI(red, 'to') || ''); const scheme = String(getCI(red, 'scheme') || 'https');
      const target = eps.get(to); const port = target ? parseAddress(target.address).port : (/^:?\d+$/.test(to) ? to.replace(':', '') : '');
      const line = stLine(realKey(st, 'entryPoints'), ep.name, realKey(ep.def, 'http'), realKey(getCI(ep.def, 'http'), 'redirections'));
      const pr = Number(getCI(red, 'priority')) || MAX_PRIORITY;
      const permanent = getCI(red, 'permanent') === undefined ? true : truthy(getCI(red, 'permanent'));
      const r = internalRoute(`${ep.name}-to-${to}@internal`, 'PathPrefix(`/`)', pr, line, stFile, `Redirect to ${scheme}://{host}${port && port !== '443' ? `:${port}` : ''}{path}`);
      r.transforms = [{ action: 'redirect', args: [permanent ? '301' : '302', `${scheme}://{host}${port && !((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80')) ? `:${port}` : ''}{path}`], line, file: stFile, text: `EntryPoint redirection to ${to} (${scheme})` }];
      r.target = null; r.redirectTo = to;
      routesByEp.get(ep.name).push(r);
    }
  }
  for (const [ep, list] of internalRoutes) if (routesByEp.has(ep)) routesByEp.get(ep).push(...list);

  for (const ep of eps.values()) {
    const a = parseAddress(ep.address);
    const list = routesByEp.get(ep.name) || [];
    // Traefik's order: TCP routers are matched before HTTP routers on the same entryPoint; then priority (descending)
    list.sort((x, y) => (x.proto === y.proto ? 0 : x.proto === 'tcp' ? -1 : 1) || (y.priority - x.priority) || String(x.router).localeCompare(String(y.router)) || (x.branch || 0) - (y.branch || 0));
    const httpRoutes = list.filter((r) => r.proto === 'http' && !r.internal);
    const tlsOn = epIsTls(ep) || (httpRoutes.length > 0 && httpRoutes.every((r) => r.tls));
    const timeouts = pick(ep.def, 'transport', 'respondingTimeouts') || {};
    const http3 = getCI(ep.def, 'http3') !== undefined;
    const fe = {
      type: 'frontend', name: ep.name, line: ep.line, endLine: ep.line, file: ep.file, mode: list.length && list.every((r) => r.proto === 'tcp') ? 'tcp' : a.proto === 'udp' ? 'udp' : 'http',
      binds: ep.address || !ep.implicit ? [{ address: `${a.host || '*'}:${a.port || '?'}`, addresses: [`${a.host || '*'}:${a.port || '?'}`], port: a.port || null, ssl: tlsOn, options: { ...(http3 ? { http3: true } : {}), ...(a.proto === 'udp' ? { udp: true } : {}), ...(getCI(ep.def, 'proxyProtocol') ? { proxy_protocol: true } : {}) }, line: ep.line, file: ep.file, commented: false, guessed: Boolean(ep.guessed) }] : [],
      serverNames: [...hostsByEp.get(ep.name)], routes: list, acls: [], servers: [], users: [],
      timeouts: Object.fromEntries(Object.entries(timeouts).map(([k, v]) => [k, String(v)])), effective: { mode: 'http', timeouts: Object.fromEntries(Object.entries(timeouts).map(([k, v]) => [k, String(v)])), defaultServer: {} },
      directives: entryPointDirectives(ep, list, st, stLine), locations: [],
      entryPoint: { address: ep.address, implicit: Boolean(ep.implicit), guessed: Boolean(ep.guessed), redirect: pick(ep.def, 'http', 'redirections', 'entryPoint') ? String(pick(ep.def, 'http', 'redirections', 'entryPoint', 'to') || '') : null, tls: Boolean(pick(ep.def, 'http', 'tls')), asDefault: truthy(getCI(ep.def, 'asDefault')), middlewares: arr(pick(ep.def, 'http', 'middlewares')) },
    };
    fe.effective.mode = fe.mode;
    sections.push(fe);
  }

  // ---- inventory for the audit: middlewares (and who uses them), TLS options, servers transports, providers
  const g = sections[0].traefik;
  const usedMw = new Map();
  const markMw = (ref, provider, by) => { const r = resolve('http.middlewares', ref, provider); if (r.item) { const k = `${r.item.name}@${r.item.provider}`; if (!usedMw.has(k)) usedMw.set(k, []); usedMw.get(k).push(by); } };
  for (const it of items('http.routers')) for (const m of arr(getCI(it.def, 'middlewares'))) markMw(m, it.provider, `router ${it.name}`);
  for (const ep of eps.values()) for (const m of arr(pick(ep.def, 'http', 'middlewares'))) markMw(m, 'file', `entryPoint ${ep.name}`);
  for (const it of items('http.middlewares')) { const ch = getCI(it.def, 'chain'); if (ch) for (const m of arr(getCI(ch, 'middlewares'))) markMw(m, it.provider, `chain ${it.name}`); }
  g.middlewares = items('http.middlewares').map((it) => { const type = Object.keys(it.def)[0] || '?'; return { name: sectionName('http.middlewares', it), type, provider: it.provider, file: it.file, line: it.line, usedBy: usedMw.get(`${it.name}@${it.provider}`) || [], options: Object.keys(isObj(it.def[type]) ? it.def[type] : {}) }; });
  g.tcpMiddlewares = items('tcp.middlewares').map((it) => ({ name: it.name, type: Object.keys(it.def)[0] || '?', file: it.file, line: it.line }));
  g.tlsOptions = [...cfg.tls.options.values()].map((o) => ({ name: o.name, minVersion: getCI(o.def, 'minVersion') || null, maxVersion: getCI(o.def, 'maxVersion') || null, sniStrict: truthy(getCI(o.def, 'sniStrict')), cipherSuites: arr(getCI(o.def, 'cipherSuites')), file: o.file, line: o.line, minLine: o.lineOf([realKey(o.def, 'minVersion') || 'minVersion']) || o.line }));
  g.tlsCertificates = cfg.tls.certificates.length;
  g.tlsStores = [...cfg.tls.stores.keys()];
  const stTransport = st ? getCI(st, 'serversTransport') : null;
  g.serversTransports = [
    ...(stTransport ? [{ name: '(static serversTransport)', insecureSkipVerify: truthy(getCI(stTransport, 'insecureSkipVerify')), file: stFile, line: stLine(realKey(st, 'serversTransport'), realKey(stTransport, 'insecureSkipVerify') || ''), static: true }] : []),
    ...items('http.serversTransports').map((it) => ({ name: it.name, insecureSkipVerify: truthy(getCI(it.def, 'insecureSkipVerify')), rootCAs: arr(getCI(it.def, 'rootCAs')).length, file: it.file, line: it.lineOf([realKey(it.def, 'insecureSkipVerify') || '']) || it.line, forwardingTimeouts: getCI(it.def, 'forwardingTimeouts') || null })),
  ];
  const docker = st ? pick(st, 'providers', 'docker') : undefined;
  g.docker = docker === undefined ? (items('http.routers').some((it) => it.provider === 'docker') ? { inferred: true } : null) : { exposedByDefault: getCI(docker || {}, 'exposedByDefault') === undefined ? true : truthy(getCI(docker || {}, 'exposedByDefault')), constraints: getCI(docker || {}, 'constraints') || null, line: stLine(realKey(st, 'providers'), realKey(getCI(st, 'providers'), 'docker')), file: stFile };
  g.certResolvers = st && isObj(getCI(st, 'certificatesResolvers')) ? Object.entries(getCI(st, 'certificatesResolvers')).map(([n, d]) => ({ name: n, acme: Boolean(getCI(d || {}, 'acme')), challenge: ['httpChallenge', 'tlsChallenge', 'dnsChallenge'].find((c) => pick(d || {}, 'acme', c) !== undefined) || null, line: stLine(realKey(st, 'certificatesResolvers'), n), file: stFile })) : [];
  g.accessLogLine = st ? stLine(realKey(st, 'accessLog') || 'accessLog') : null;
  g.logLine = st ? stLine(realKey(st, 'log') || 'log', realKey(getCI(st, 'log') || {}, 'level') || 'level') : null;
  g.apiLine = st && apiCfg !== undefined ? stLine(realKey(st, 'api'), realKey(apiCfg || {}, 'insecure') || '') : null;
  g.file = stFile;
  g.ipWhiteList = [...items('http.middlewares'), ...items('tcp.middlewares')].filter((it) => getCI(it.def, 'ipWhiteList') !== undefined).map((it) => ({ name: it.name, file: it.file, line: it.line, kind: it.kind }));
  g.serviceRefs = [];
  for (const it of [...items('http.services'), ...items('tcp.services')]) {
    const type = Object.keys(it.def)[0] || ''; const o = it.def[type] || {};
    const refs = lc(type) === 'weighted' || lc(type) === 'highestrandomweight' ? arr(getCI(o, 'services')).map((c) => getCI(c, 'name')) : lc(type) === 'mirroring' ? [getCI(o, 'service'), ...arr(getCI(o, 'mirrors')).map((m) => getCI(m, 'name'))] : lc(type) === 'failover' ? [getCI(o, 'service'), getCI(o, 'fallback')] : [];
    const kind = it.kind;
    for (const ref of refs.filter(Boolean)) { const r = resolve(kind, ref, it.provider); g.serviceRefs.push({ from: sectionName(kind, it), to: r.name, missing: Boolean(r.missing), internal: Boolean(r.internal), file: it.file, line: it.line }); }
    const st2 = getCI(o, 'serversTransport');
    if (st2) { const r = resolve('http.serversTransports', st2, it.provider); if (r.missing) g.serviceRefs.push({ from: sectionName(kind, it), transport: String(st2), missing: true, file: it.file, line: it.line }); }
  }

  // ---- services -> backends
  for (const [proto, kind] of [['http', 'http.services'], ['tcp', 'tcp.services'], ['udp', 'udp.services']]) {
    for (const it of items(kind)) {
      const def = it.def; const type = Object.keys(def)[0] || 'loadBalancer'; const o = def[type] || {};
      const name = sectionName(kind, it); const t = lc(type);
      const be = { type: 'backend', name, line: it.line, endLine: it.line, file: it.file, mode: proto, balance: 'roundrobin', implicit: false, servers: [], healthCheck: null, sticky: false, routes: [], binds: [], acls: [], users: [], timeouts: {}, effective: { mode: proto, timeouts: {}, defaultServer: {} }, directives: [], provider: it.provider, serviceType: type };
      if (t === 'loadbalancer') {
        const hc = getCI(o, 'healthCheck');
        be.healthCheck = isObj(hc) ? { path: getCI(hc, 'path') || '/', interval: String(getCI(hc, 'interval') ?? '30s'), timeout: getCI(hc, 'timeout') != null ? String(getCI(hc, 'timeout')) : null, scheme: getCI(hc, 'scheme') || null, hostname: getCI(hc, 'hostname') || null } : null;
        const sticky = getCI(o, 'sticky');
        be.sticky = Boolean(sticky && (proto === 'http' ? getCI(sticky, 'cookie') !== undefined : true));
        if (be.sticky && proto === 'http') be.stickyCookie = getCI(getCI(sticky, 'cookie') || {}, 'name') || '(generated name)';
        be.balance = getCI(o, 'strategy') ? lc(getCI(o, 'strategy')) : 'wrr';
        be.passHostHeader = getCI(o, 'passHostHeader') === undefined ? proto === 'http' : truthy(getCI(o, 'passHostHeader'));
        be.serversTransport = getCI(o, 'serversTransport') || null;
        const sk = realKey(o, 'servers');
        arr(getCI(o, 'servers')).forEach((s, i) => {
          const url = proto === 'http' ? getCI(s, 'url') : null; const address = proto === 'http' ? null : getCI(s, 'address');
          const u = url ? serverFromUrl(url) : { scheme: proto, address: String(address || ''), path: '' };
          const w = getCI(s, 'weight');
          be.servers.push({
            name: url ? redactUrl(url) : String(address || ''), address: u.address, scheme: url ? u.scheme : proto, path: u.path || '', check: Boolean(be.healthCheck), backup: false, disabled: false,
            weight: w == null ? null : Number(w), opts: { ...(getCI(s, 'preservePath') ? { preservePath: true } : {}), ...(getCI(s, 'tls') ? { tls: true } : {}) }, options: '', line: it.lineOf([realKey(def, type), sk, i]) || it.line, file: it.file, commented: false,
          });
        });
        for (const k of ['passHostHeader', 'serversTransport', 'strategy']) if (getCI(o, k) !== undefined) be.directives.push({ keyword: k, args: [String(getCI(o, k))], line: it.lineOf([realKey(def, type), realKey(o, k)]) || it.line, file: it.file, raw: `${k}: ${getCI(o, k)}` });
      } else if (t === 'weighted' || t === 'highestrandomweight') {
        be.balance = t === 'weighted' ? 'weighted' : 'hrw'; be.composite = t === 'weighted' ? 'weighted' : 'highestRandomWeight';
        const sticky = getCI(o, 'sticky'); be.sticky = Boolean(sticky && getCI(sticky, 'cookie') !== undefined);
        arr(getCI(o, 'services')).forEach((c, i) => {
          const r = resolve(kind, getCI(c, 'name'), it.provider);
          be.servers.push({ name: r.internal ? r.ref : r.name, address: r.internal ? r.ref : r.name, scheme: 'service', service: true, missing: Boolean(r.missing), check: false, backup: false, disabled: false, weight: getCI(c, 'weight') == null ? null : Number(getCI(c, 'weight')), opts: { service: true }, options: '', line: it.lineOf([realKey(def, type), realKey(o, 'services'), i]) || it.line, file: it.file, commented: false });
        });
        if (getCI(o, 'healthCheck') !== undefined) be.healthCheck = { path: null, interval: null, propagated: true };
      } else if (t === 'mirroring') {
        be.balance = 'mirroring'; be.composite = 'mirroring';
        const main = resolve(kind, getCI(o, 'service'), it.provider);
        be.servers.push({ name: main.name, address: main.name, scheme: 'service', service: true, missing: Boolean(main.missing), check: false, backup: false, disabled: false, weight: null, opts: { service: true, main: true }, options: '', line: it.lineOf([realKey(def, type), realKey(o, 'service')]) || it.line, file: it.file, commented: false });
        arr(getCI(o, 'mirrors')).forEach((m, i) => {
          const r = resolve(kind, getCI(m, 'name'), it.provider);
          be.servers.push({ name: r.name, address: r.name, scheme: 'service', service: true, missing: Boolean(r.missing), check: false, backup: false, disabled: false, weight: null, opts: { service: true, mirror: true, percent: Number(getCI(m, 'percent') || 0) }, options: `mirror ${getCI(m, 'percent') || 0}%`, line: it.lineOf([realKey(def, type), realKey(o, 'mirrors'), i]) || it.line, file: it.file, commented: false });
        });
      } else if (t === 'failover') {
        be.balance = 'failover'; be.composite = 'failover';
        for (const [k, backup] of [['service', false], ['fallback', true]]) {
          const r = resolve(kind, getCI(o, k), it.provider);
          be.servers.push({ name: r.name, address: r.name, scheme: 'service', service: true, missing: Boolean(r.missing), check: false, backup, disabled: false, weight: null, opts: { service: true }, options: backup ? 'fallback' : '', line: it.lineOf([realKey(def, type), realKey(o, k)]) || it.line, file: it.file, commented: false });
        }
      }
      sections.push(be);
    }
  }
  return { sections, syntax: syntaxInfo };
}

function internalRoute(target, rule, priority, line, file, label) {
  const b = rules.branches(rule, 'v3').branches[0];
  return {
    target, type: 'conditional', condition: rule, rawCondition: rule, match: `${b.match} (${label})`, short: b.short, matchers: b.matchers, hosts: [], paths: b.paths, priority,
    transforms: [], passUrl: null, terminal: true, line, file, commented: false, dynamic: false, external: false,
    router: target, provider: 'internal', proto: 'http', entryPoints: [], tls: false, middlewares: [], missingMiddlewares: [], missingService: null, internal: true, ruleSyntax: 'v3', ruleError: null, branch: null,
  };
}

function entryPointDirectives(ep, routes, st, stLine) {
  const out = [];
  if (st && ep.def) {
    const walk = (v, p) => { if (isObj(v)) { for (const [k, x] of Object.entries(v)) walk(x, [...p, k]); return; } out.push({ keyword: p.slice(2).join('.'), args: arr(v).map(String), line: stLine(...p), file: ep.file, raw: `${p.slice(2).join('.')}: ${arr(v).join(', ')}`, within: [`entryPoint ${ep.name}`] }); };
    walk(ep.def, [realKey(st, 'entryPoints') || 'entryPoints', ep.name]);
  }
  for (const r of routes) if (!r.internal && !r.branch || r.branch === 1) out.push({ keyword: 'rule', args: [r.rawCondition], line: r.line, file: r.file, raw: `rule: ${r.rawCondition}`, within: [`router ${r.router}`] });
  return out;
}

// ------------------------------------------------------------------------------------------------ redaction
const SECRET_KEY = /(password|passwd|secret|token|api[-_]?key|apikey|credentials?|private[-_]?key|access[-_]?key|bearer|hmac|signingkey|clientsecret)/i;
const SAFE_KEY = /(file|path|usersfile|keyfile|certfile|filename|secretname|tokenurl|tokenpath)$/i;
const HEADER_SECRET = /^(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|x-access-token)$/i;
/** Mask passwords, tokens, basic/digest auth hashes, TLS key material and URL credentials in YAML / TOML / labels. */
function redact(text) {
  if (typeof text !== 'string') return '';
  const lines = text.split(/\r?\n/);
  let inUsers = -1; let inPem = false; let pemIndent = null;
  return lines.map((line) => {
    // PEM blocks (inline certificates / keys in tls.certificates or serversTransports)
    if (inPem) { if (/-----END [A-Z ]+-----/.test(line)) { inPem = false; return line.replace(/^(\s*).*?(-----END [A-Z ]+-----.*)$/, '$1$2'); } return line.replace(/^(\s*)\S.*$/, (m, sp) => `${sp || pemIndent || ''}***`); }
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(line) && !/-----END/.test(line)) { inPem = true; pemIndent = (/^\s*/.exec(line) || [''])[0]; return line; }
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----.*-----END/.test(line)) return line.replace(/(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)/, '$1***$2');
    let l = line.replace(/(:\/\/[^:/@\s"'`]+:)([^@\s"'`]+)(@)/g, '$1***$3');
    // user lists of basicAuth / digestAuth (YAML block list after "users:")
    const ind = (/^\s*/.exec(l) || [''])[0].length;
    if (inUsers >= 0) {
      if (/^\s*-\s*/.test(l) && ind >= inUsers) return l.replace(/^(\s*-\s*["']?)([^:"'\s]+):[^"'\s#]+/, '$1$2:***');
      if (l.trim() && !/^\s*#/.test(l)) inUsers = -1;
    }
    if (/^\s*["']?users["']?\s*[:=]\s*$/i.test(l)) { inUsers = ind; return l; }
    // inline user lists: users: ["a:hash", ...] / users = ["a:hash"]
    if (/^\s*["']?users["']?\s*[:=]\s*\[/i.test(l)) return l.replace(/(["'`]?)([^"'`,\s[\]]+):([^"'`,\s\]]+)(["'`]?)/g, (m, q1, u, h, q2) => (/^users$/i.test(u) ? m : `${q1}${u}:***${q2}`));
    // docker labels: ...basicauth.users=admin:$$apr1$$...  (list or map form)
    l = l.replace(/(traefik\.[\w.-]*\.(?:basicauth|digestauth)\.users\s*[=:]\s*["']?)([^"'\s#]+)/i, (m, pre, list) => `${pre}${list.split(',').map((x) => `${x.split(':')[0]}:***`).join(',')}`);
    l = l.replace(/(traefik\.[\w.-]*(?:password|token|secret|apikey|api_key)\s*[=:]\s*["']?)([^"'\s#]+)/i, '$1***');
    // key: value / key = value / KEY=value (env in compose)
    const kv = /^(\s*-?\s*["']?)([A-Za-z0-9_.-]+)(["']?\s*[:=]\s*)(.*)$/.exec(l);
    if (kv) {
      const [, pre, key, sep, rest] = kv;
      const val = rest.replace(/\s+#.*$/, '').trim();
      if (val && !/^[|>]/.test(val) && SECRET_KEY.test(key) && !SAFE_KEY.test(key) && !/^\$\{?[A-Z_]+\}?$/.test(val.replace(/["']/g, '')) && !/^(true|false|null|~)$/i.test(val)) {
        const q = /^["']/.test(val) ? val[0] : '';
        return `${pre}${key}${sep}${q}***${q}`;
      }
      if (HEADER_SECRET.test(key) && val && !/^\$/.test(val)) { const q = /^["']/.test(val) ? val[0] : ''; return `${pre}${key}${sep}${q}***${q}`; }
    }
    return l;
  }).join('\n');
}

// ------------------------------------------------------------------------------------------------ public
function normalizeFiles(input) {
  const list = (input || []).filter((f) => f && typeof f.name === 'string' && typeof f.content === 'string').slice(0, MAX_FILES);
  if (!list.length) throw new Error('No files provided');
  const norm = list.map((f) => ({ name: f.name.replace(/\\/g, '/').replace(/^\/+/, '').replace(/^(\.\/)+/, ''), content: f.content.slice(0, MAX_FILE_BYTES) }));
  const tops = new Set(norm.map((f) => f.name.split('/')[0]));
  if (norm.length > 1 && norm.every((f) => f.name.includes('/')) && tops.size === 1) norm.forEach((f) => { f.name = f.name.split('/').slice(1).join('/'); });
  return norm;
}

function parseFiles(input, opts = {}) {
  const files = normalizeFiles(input);
  const cfg = load(files);
  const { sections, syntax } = buildModel(cfg, opts);
  const notes = cfg.notes.map((n) => ({ file: n.file, line: n.line, msg: n.msg }));
  return { sections, notes, files: files.map((f) => ({ name: f.name, raw: redact(f.content), mtimeMs: 0 })), syntax, cfg };
}

/** Read a static (or dynamic / compose) file from disk and the dynamic files its file provider names, inside rootDir. */
function loadPath(mainPath, rootDir) {
  const main = path.resolve(mainPath);
  const root = path.resolve(rootDir || path.dirname(main));
  const inside = (p) => { const r = path.relative(root, p); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };
  if (!inside(main)) throw new Error(`${mainPath} is outside ${root}`);
  const read = (p) => { const st = fs.statSync(p); if (!st.isFile() || st.size > MAX_FILE_BYTES) throw new Error(`${p} is not a regular file or exceeds ${MAX_FILE_BYTES} bytes`); return { content: fs.readFileSync(p, 'utf8'), mtimeMs: st.mtimeMs }; };
  const rel = (p) => path.relative(root, p) || path.basename(p);
  const out = []; const notes = [];
  const m = read(main); out.push({ name: rel(main), content: m.content, mtimeMs: m.mtimeMs, abs: main });
  const p = parseText(main, m.content);
  if (!p.error && (classify(p.data) === 'static' || classify(p.data) === 'mixed')) {
    const fp = pick(p.data, 'providers', 'file');
    /** Map a configured path into the sandbox: as is when inside, else rebased (/etc/traefik/dynamic -> <root>/dynamic). */
    const rebase = (cfgPath) => {
      const abs = path.isAbsolute(cfgPath) ? cfgPath : path.resolve(path.dirname(main), cfgPath);
      if (inside(abs) && fs.existsSync(abs)) return abs;
      const segs = String(cfgPath).split(/[\\/]+/).filter(Boolean);
      for (let i = 0; i < segs.length; i++) { const cand = path.join(root, ...segs.slice(i)); if (inside(cand) && fs.existsSync(cand)) return cand; }
      return null;
    };
    if (isObj(fp)) {
      const fname = getCI(fp, 'filename'); const dir = getCI(fp, 'directory');
      if (fname) { const f = rebase(String(fname)); if (f && f !== main) { const r = read(f); out.push({ name: rel(f), content: r.content, mtimeMs: r.mtimeMs, abs: f }); } else if (!f) notes.push({ file: rel(main), line: 1, msg: `providers.file.filename "${fname}" was not found inside ${root}` }); }
      if (dir) {
        const d = rebase(String(dir));
        if (!d) notes.push({ file: rel(main), line: 1, msg: `providers.file.directory "${dir}" was not found inside ${root}` });
        else {
          const walk = (x, depth) => {
            if (depth > 6 || out.length >= MAX_FILES) return;
            for (const e of fs.readdirSync(x, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
              const full = path.join(x, e.name);
              if (!inside(full)) continue;
              if (e.isDirectory()) walk(full, depth + 1);
              else if (/\.(ya?ml|toml)$/i.test(e.name) && full !== main) { const r = read(full); out.push({ name: rel(full), content: r.content, mtimeMs: r.mtimeMs, abs: full }); }
            }
          };
          walk(d, 0);
        }
      }
    }
  }
  const r = parseFiles(out.map((f) => ({ name: f.name, content: f.content })));
  r.notes.push(...notes);
  r.files = r.files.map((f, i) => ({ ...f, mtimeMs: out[i] ? out[i].mtimeMs : 0, abs: out[i] ? out[i].abs : undefined }));
  return r;
}

module.exports = { composeLabels, flagsToStatic, parseFiles, loadPath, load, buildModel, classify, parseText, redact, labelsToConfig, composeToDynamic, qualify, getCI, pick, realKey, isObj, arr, truthy, serverFromUrl, parseAddress, normalizeFiles, guessSyntax, neutralizeTemplates, MAX_PRIORITY };

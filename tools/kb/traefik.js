#!/usr/bin/env node
'use strict';
/**
 * Builds src/kb/traefik.json from the official Traefik documentation, read from the docs sources in the traefik
 * repository at each release tag (https://github.com/traefik/traefik/tree/<tag>/docs/content, served by
 * raw.githubusercontent.com; the rendered site is https://doc.traefik.io/traefik/):
 *
 *   - reference/static-configuration/file.yaml   every static option path (generated from the Go structs)
 *   - reference/dynamic-configuration/file.yaml  every dynamic (file provider) option path, incl. middleware types
 *   - routing/routers/index.md (or reference/routing-configuration/{http,tcp}/routing/rules-and-priority.md)
 *                                                 the rule matchers of each version and their arguments
 *   - migration/{v2,v3,v2-to-v3-details}.md (or migrate/...)  deprecations / removals / renames, as notes
 *   - the page that documents each topic (routers, services, each middleware, TLS, ...) for docs links
 *
 * Versions: the latest patch of every stable minor release (v2.0 .. v2.11, v3.0 .. latest v3.x), found with
 * `git ls-remote --tags https://github.com/traefik/traefik` (cached).
 *
 *   node tools/kb/traefik.js [--cache DIR] [--offline]
 *
 * Output (compact):
 *   { product, generated, source, versions: ['2.0.7', ...oldest first], latest,
 *     static: { '<path>': { t: type, s: since, u?: until } }, dynamic: { ... },
 *     matchers: { http: { v2: { Name: { s, u?, args, variadic } }, v3: {...} }, tcp: {...} },
 *     middlewares: { http: { type: { s, u? } }, tcp: {...} }, notes: [...], docs: { v2: {...}, v3: {...} } }
 * Paths use `<name>` for user-chosen names (routers, services, header names, ...) and `[]` for list items;
 * `s`/`u` are minor versions ("2.5"): available since s, gone from u on.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');
const YAML = require('../../src/products/traefik/yaml');
const TOML = require('../../src/products/traefik/toml');

const argv = process.argv.slice(2);
const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : null);
const cacheDir = path.resolve(opt('--cache') || path.join(os.tmpdir(), 'gatelight-kb', 'traefik'));
const offline = argv.includes('--offline');
const OUT = path.join(__dirname, '..', '..', 'src', 'kb', 'traefik.json');
const RAW = 'https://raw.githubusercontent.com/traefik/traefik';
const REPO = 'https://github.com/traefik/traefik';

const get = (url, redirects = 3) => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'User-Agent': 'gatelight-kb-builder' } }, (res) => {
    if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && redirects) { res.resume(); return resolve(get(res.headers.location, redirects - 1)); }
    if (res.statusCode === 404) { res.resume(); return resolve(null); }
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url} -> ${res.statusCode}`)); }
    const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  }).on('error', reject);
});
const MISSING = '\u0000404';
/** A docs source file at a tag (null when the file does not exist at that tag). Cached, including 404s. */
async function load(tag, rel) {
  fs.mkdirSync(cacheDir, { recursive: true });
  const f = path.join(cacheDir, `${tag}__${rel.replace(/[/#]/g, '_')}`);
  if (fs.existsSync(f)) { const b = fs.readFileSync(f, 'utf8'); return b === MISSING ? null : b; }
  if (offline) throw new Error(`missing ${f} (offline)`);
  const body = await get(`${RAW}/${tag}/${rel}`);
  fs.writeFileSync(f, body === null ? MISSING : body);
  return body;
}
async function loadFirst(tag, rels) { for (const r of rels) { const b = await load(tag, r); if (b !== null) return { rel: r, body: b }; } return null; }

/** Stable release tags, latest patch per minor (v2.0 ..). */
function releaseTags() {
  const f = path.join(cacheDir, 'tags.txt');
  let txt;
  if (fs.existsSync(f)) txt = fs.readFileSync(f, 'utf8');
  else {
    if (offline) throw new Error(`missing ${f} (offline)`);
    txt = execFileSync('git', ['ls-remote', '--tags', REPO], { encoding: 'utf8', maxBuffer: 64 << 20 });
    fs.mkdirSync(cacheDir, { recursive: true }); fs.writeFileSync(f, txt);
  }
  const best = new Map();
  for (const m of txt.matchAll(/refs\/tags\/v(\d+)\.(\d+)\.(\d+)$/gm)) {
    const [maj, min, pat] = [+m[1], +m[2], +m[3]];
    if (maj < 2) continue;
    const k = `${maj}.${min}`;
    if (!best.has(k) || best.get(k)[2] < pat) best.set(k, [maj, min, pat]);
  }
  return [...best.values()].sort((a, b) => a[0] - b[0] || a[1] - b[1]).map((v) => v.join('.'));
}

// ------------------------------------------------------------------------------------------------ option paths
const PLACEHOLDER = /^([A-Z][A-Za-z]*\d+|name\d+)$/;
/** Type of a sample value in the generated reference files (foobar / 42 / 42s / true / 42.0). */
function typeOf(v) {
  if (typeof v === 'boolean') return 'bool';
  if (typeof v === 'number') return Number.isInteger(v) ? 'int' : 'float';
  if (typeof v === 'string') { if (/^\d+(\.\d+)?(ns|us|µs|ms|s|m|h)$/.test(v)) return 'duration'; if (/^\d+\.\d+$/.test(v)) return 'float'; return 'string'; }
  return 'object';
}
/** Flatten a reference document into { path: type }. */
function flattenRef(data) {
  const out = {};
  const walk = (v, p) => {
    if (Array.isArray(v)) {
      if (v.length && v.every((x) => x && typeof x === 'object' && !Array.isArray(x))) { out[p] = 'list'; for (const x of v) walk(x, `${p}[]`); }
      else out[p] = `list:${v.length ? typeOf(v[0]) : 'string'}`;
      return;
    }
    if (v && typeof v === 'object') {
      const keys = Object.keys(v);
      if (!keys.length) { out[p] = 'object'; return; }
      if (p) out[p] = out[p] || 'object';
      for (const k of keys) {
        const seg = PLACEHOLDER.test(k) ? '<name>' : k;
        walk(v[k], p ? `${p}.${seg}` : seg);
      }
      return;
    }
    out[p] = typeOf(v);
  };
  walk(data, '');
  return out;
}

// ------------------------------------------------------------------------------------------------ matchers
/** Matchers documented in the "Rule" tables of a routers page: { Name: { args, variadic } }. */
function tableMatchers(md) {
  const out = {};
  for (const line of md.split('\n')) {
    if (!/^\|/.test(line)) continue;
    const first = line.split(/(?<!\\)\|/)[1] || '';
    const m = /```\s*([A-Za-z]+)\(([^)]*(?:\([^)]*\)[^)]*)*)\)\s*```/.exec(first);
    if (!m) continue;
    const args = (m[2].match(/`[^`]*`/g) || []).length;
    out[m[1]] = { args, variadic: /\.\.\./.test(m[2]) };
  }
  return out;
}
function splitHttpTcp(md) {
  const i = md.search(/^##\s+Configuring TCP Routers/m);
  const j = md.search(/^##\s+Configuring UDP Routers/m);
  return { http: i < 0 ? md : md.slice(0, i), tcp: i < 0 ? '' : md.slice(i, j < 0 ? undefined : j) };
}

// ------------------------------------------------------------------------------------------------ notes
/** Deprecation / removal / rename notes from a migration page, one per "### title" section. */
function migrationNotes(md, page, defaultVersion) {
  const notes = [];
  let ver = defaultVersion;
  const sections = md.split(/\n(?=#{2,4} )/);
  for (const sec of sections) {
    const h = /^(#{2,4}) (.+)/.exec(sec);
    if (!h) continue;
    const title = h[2].trim();
    const vm = /^v?(\d+\.\d+)(?:\.\d+)?(?: to v?(\d+\.\d+)(?:\.\d+)?)?$/.exec(title.replace(/^v/, 'v'));
    if (h[1] === '##' && vm) { ver = vm[2] || vm[1]; continue; }
    const body = sec.slice(h[0].length).replace(/```[\s\S]*?```/g, ' ').replace(/\?\?\?[^\n]*/g, ' ').replace(/!!![^\n]*/g, ' ').replace(/\{:[^}]*\}/g, '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/\s+/g, ' ').trim();
    const kind = /\b(has been removed|have been removed|were removed|was removed|is removed|removed|no longer (available|supported)|unsupported)\b/i.test(body) ? 'removed'
      : /\brenamed\b/i.test(body) ? 'renamed' : /\bdeprecat/i.test(body) ? 'deprecated' : /\bdefault\b/i.test(body) ? 'default' : null;
    if (!kind) continue;
    const names = [...new Set([...`${title} ${body}`.matchAll(/`([A-Za-z][\w.-]{2,80})`/g)].map((m) => m[1]))].slice(0, 12);
    const sentence = body.split(/(?<=\.)\s/).filter((s) => /deprecat|remov|renam|default|replace|no longer|unsupported/i.test(s)).slice(0, 2).join(' ') || body;
    notes.push({ v: ver, kind, title: title.replace(/`/g, ''), text: sentence.slice(0, 300), names, page, full: body });
  }
  return notes;
}

// ------------------------------------------------------------------------------------------------ docs pages
const TOPICS = {
  routers: ['reference/routing-configuration/http/routing/rules-and-priority.md', 'routing/routers/index.md'],
  routerOptions: ['reference/routing-configuration/http/routing/router.md', 'routing/routers/index.md'],
  tcpRouters: ['reference/routing-configuration/tcp/routing/rules-and-priority.md', 'routing/routers/index.md'],
  services: ['reference/routing-configuration/http/load-balancing/service.md', 'routing/services/index.md'],
  serversTransport: ['reference/routing-configuration/http/load-balancing/serverstransport.md', 'routing/services/index.md'],
  entrypoints: ['reference/install-configuration/entrypoints.md', 'routing/entrypoints.md'],
  tls: ['reference/routing-configuration/http/tls/tls-options.md', 'https/tls.md'],
  acme: ['reference/install-configuration/tls/certificate-resolvers/acme.md', 'https/acme.md'],
  accessLogs: ['reference/install-configuration/observability/logs-and-accesslogs.md', 'observability/access-logs.md'],
  logs: ['reference/install-configuration/observability/logs-and-accesslogs.md', 'observability/logs.md'],
  metrics: ['reference/install-configuration/observability/metrics.md', 'observability/metrics/prometheus.md'],
  api: ['reference/install-configuration/api-dashboard.md', 'operations/api.md'],
  dashboard: ['reference/install-configuration/api-dashboard.md', 'operations/dashboard.md'],
  docker: ['reference/install-configuration/providers/docker.md', 'providers/docker.md'],
  dockerRouting: ['reference/routing-configuration/other-providers/docker.md', 'routing/providers/docker.md'],
  file: ['reference/install-configuration/providers/others/file.md', 'providers/file.md'],
  staticReference: ['reference/static-configuration/file.md', 'reference/install-configuration/configuration-options.md'],
  dynamicReference: ['reference/dynamic-configuration/file.md', 'reference/routing-configuration/other-providers/file.md'],
  middlewares: ['reference/routing-configuration/http/middlewares/overview.md', 'middlewares/http/overview.md', 'middlewares/overview.md'],
  migrationV3: ['migrate/v2-to-v3-details.md', 'migration/v2-to-v3-details.md'],
  migrationV2: ['migrate/v2.md', 'migration/v2.md'],
  migration3x: ['migrate/v3.md', 'migration/v3.md'],
};
const docUrl = (major, rel) => `https://doc.traefik.io/traefik/${major === '2' ? 'v2.11/' : ''}${rel.replace(/\.md$/, '').replace(/(^|\/)index$/, '')}/`.replace(/\/\/$/, '/');

/**
 * Options the migration guides deprecate or remove. `re` matches KB option paths; `dep` = deprecated since, `removed` =
 * the guide says removed in (the generated v3 reference may still list the field when the code keeps it for
 * compatibility with a deprecation warning, so the validator reports these as deprecated, not unknown).
 */
const DEPRECATIONS = [
  { re: '^http\\.middlewares\\.<name>\\.headers\\.(sslRedirect|sslTemporaryRedirect|sslHost|sslForceHost)$', dep: '2.5', removed: '3.0', use: 'entryPoints.<name>.http.redirections or the redirectScheme middleware', note: /ssl redirect options|sslRedirect/i },
  { re: '^http\\.middlewares\\.<name>\\.headers\\.featurePolicy$', dep: '2.5', removed: '3.0', use: 'headers.permissionsPolicy', note: /featurePolicy/ },
  { re: '^(http|tcp)\\.middlewares\\.<name>\\.ipWhiteList(\\..*)?$', dep: '2.11', use: 'ipAllowList (same options)', note: /IPWhiteList/ },
  { re: '^http\\.middlewares\\.<name>\\.stripPrefix\\.forceSlash$', dep: '2.0', removed: '3.0', note: /forceSlash/ },
  { re: '\\.caOptional$', dep: '2.8', removed: '3.0', note: /caOptional/i },
  { re: '^tls\\.options\\.<name>\\.preferServerCipherSuites$', dep: '2.0', removed: '3.0', note: /preferServerCipherSuites/ },
  { re: '^tracing\\.datadog\\.globalTag$', dep: '2.0', removed: '3.0', use: 'tracing.datadog.globalTags', note: /globaltag/i },
  { re: '^providers\\.docker\\.swarmMode', dep: '3.0', removed: '3.0', use: 'providers.swarm', note: /SwarmMode|Swarm provider/ },
  { re: '^tcp\\.services\\.<name>\\.loadBalancer\\.terminationDelay$', dep: '3.0', use: 'tcp.serversTransports.<name>.terminationDelay', note: /terminationDelay/ },
  { re: '^pilot(\\..*)?$', dep: '2.8', removed: '3.0', note: /Pilot/ },
  { re: '^providers\\.(marathon|rancher)(\\..*)?$', dep: '2.0', removed: '3.0', note: /Marathon provider|Rancher v1/ },
];

const minor = (v) => v.split('.').slice(0, 2).join('.');

async function main() {
  const tags = releaseTags();
  process.stderr.write(`tags: ${tags.join(' ')}\n`);
  const perTag = [];
  for (const v of tags) {
    const tag = `v${v}`;
    process.stderr.write(`${tag} `);
    const ref = async (kind) => { // the YAML reference, or the TOML one when the YAML file of that tag is malformed
      const y = await load(tag, `docs/content/reference/${kind}-configuration/file.yaml`);
      try { if (y) return YAML.parse(y, { allowDuplicateKeys: true }).data; } catch (e) { process.stderr.write(`(${kind} file.yaml: ${e.message}; using file.toml) `); }
      const t = await load(tag, `docs/content/reference/${kind}-configuration/file.toml`);
      try { if (t) return TOML.parse(t).data; } catch (e) { process.stderr.write(`(${kind} file.toml: ${e.message}) `); }
      return null;
    };
    const st = await ref('static'); const dy = await ref('dynamic');
    if (!st || !dy) { process.stderr.write('(no usable reference files, skipped)\n'); continue; }
    const sPaths = flattenRef(st);
    const dPaths = flattenRef(dy);
    // matchers
    let http = {}; let tcp = {};
    const routers = await load(tag, 'docs/content/routing/routers/index.md');
    if (routers) { const s = splitHttpTcp(routers); http = tableMatchers(s.http); tcp = tableMatchers(s.tcp); }
    if (!Object.keys(http).length) { const r = await load(tag, 'docs/content/reference/routing-configuration/http/routing/rules-and-priority.md'); if (r) http = tableMatchers(r); }
    if (!Object.keys(tcp).length) { const r = await load(tag, 'docs/content/reference/routing-configuration/tcp/routing/rules-and-priority.md'); if (r) tcp = tableMatchers(r); }
    delete tcp.Header; delete tcp.Host; // only real TCP matchers
    perTag.push({ v, minor: minor(v), static: sPaths, dynamic: dPaths, http, tcp });
    process.stderr.write(`static ${Object.keys(sPaths).length}, dynamic ${Object.keys(dPaths).length}, matchers ${Object.keys(http).length}/${Object.keys(tcp).length}\n`);
  }
  const minors = perTag.map((p) => p.minor);
  /** since/until over the minors for one key family. */
  const life = (has) => {
    const ranges = []; let start = null;
    perTag.forEach((p, i) => { if (has(p) && start === null) start = i; if (!has(p) && start !== null) { ranges.push([start, i]); start = null; } });
    if (start !== null) ranges.push([start, null]);
    return ranges;
  };
  const lifeEntry = (ranges, extra = {}) => {
    const e = { ...extra, s: minors[ranges[0][0]] };
    const last = ranges[ranges.length - 1];
    if (ranges.length > 1) e.r = ranges.map(([a, b]) => (b === null ? [minors[a]] : [minors[a], minors[b]]));
    if (last[1] !== null) e.u = minors[last[1]];
    return e;
  };
  const pathTable = (kind) => {
    const all = new Set(); perTag.forEach((p) => Object.keys(p[kind]).forEach((k) => all.add(k)));
    const out = {};
    for (const k of [...all].sort()) {
      const ranges = life((p) => Object.prototype.hasOwnProperty.call(p[kind], k));
      const lastWith = [...perTag].reverse().find((p) => p[kind][k]);
      out[k] = lifeEntry(ranges, { t: lastWith[kind][k] });
    }
    return out;
  };
  const staticPaths = pathTable('static');
  const dynamicPaths = pathTable('dynamic');

  // matchers per syntax: v2 syntax = what the v2.x docs list (also accepted by v3 with ruleSyntax: v2), v3 syntax from v3.0
  const matcherTable = (proto) => {
    const out = { v2: {}, v3: {} };
    for (const syntax of ['v2', 'v3']) {
      const tagsOf = perTag.filter((p) => (syntax === 'v2' ? p.v.startsWith('2.') : p.v.startsWith('3.')));
      const names = new Set(); tagsOf.forEach((p) => Object.keys(p[proto]).forEach((n) => names.add(n)));
      for (const n of names) {
        const first = tagsOf.find((p) => p[proto][n]); const lastP = [...tagsOf].reverse().find((p) => p[proto][n]);
        const gone = tagsOf.find((p) => !p[proto][n] && minors.indexOf(p.minor) > minors.indexOf(first.minor));
        const { args } = lastP[proto][n];
        // v2 matchers take a list of values ("Host(`a`, `b`)", "Query(`a=b`, `c=d`)"), except Headers/HeadersRegexp (key, value).
        // v3 matchers take one value; Header/HeaderRegexp/Query/QueryRegexp take two, and Query may take one
        // (migration/v2-to-v3-details "New V3 Syntax Notable Changes").
        const pair = /^(Headers?|HeadersRegexp|HeaderRegexp|QueryRegexp)$/.test(n) || (syntax === 'v3' && n === 'Query');
        const variadic = syntax === 'v2' && !pair;
        out[syntax][n] = { s: first.minor, ...(gone && minors.indexOf(gone.minor) > minors.indexOf(lastP.minor) ? { u: gone.minor } : {}), min: variadic ? 1 : (syntax === 'v3' && n === 'Query' ? 1 : (pair ? 2 : args)), max: variadic ? null : (pair ? 2 : args) };
      }
    }
    return out;
  };
  const matchers = { http: matcherTable('http'), tcp: matcherTable('tcp') };

  // middleware types (keys under http.middlewares.<name>.X / tcp.middlewares.<name>.X)
  const middlewares = { http: {}, tcp: {} };
  for (const proto of ['http', 'tcp']) {
    const re = new RegExp(`^${proto}\\.middlewares\\.<name>\\.([A-Za-z0-9]+)$`);
    for (const [k, e] of Object.entries(dynamicPaths)) { const m = re.exec(k); if (m) middlewares[proto][m[1]] = { s: e.s, ...(e.u ? { u: e.u } : {}) }; }
  }

  // notes from the migration guides (newest docs of each major)
  const latest2 = perTag.filter((p) => p.v.startsWith('2.')).pop();
  const latest3 = perTag.filter((p) => p.v.startsWith('3.')).pop();
  const notes = [];
  if (latest2) { const m = await loadFirst(`v${latest2.v}`, ['docs/content/migration/v2.md']); if (m) notes.push(...migrationNotes(m.body, docUrl('2', m.rel.replace('docs/content/', '')), '2.0')); }
  if (latest3) {
    const d = await loadFirst(`v${latest3.v}`, ['docs/content/migrate/v2-to-v3-details.md', 'docs/content/migration/v2-to-v3-details.md']);
    if (d) notes.push(...migrationNotes(d.body, docUrl('3', d.rel.replace('docs/content/', '')), '3.0').map((n) => ({ ...n, v: '3.0' })));
    const m = await loadFirst(`v${latest3.v}`, ['docs/content/migrate/v3.md', 'docs/content/migration/v3.md']);
    if (m) notes.push(...migrationNotes(m.body, docUrl('3', m.rel.replace('docs/content/', '')), '3.0'));
  }

  // docs pages per major (from the newest tag of that major), incl. one page per middleware type
  const docs = {};
  for (const [major, p] of [['2', latest2], ['3', latest3]]) {
    if (!p) continue;
    const pages = {};
    for (const [topic, cands] of Object.entries(TOPICS)) {
      const f = await loadFirst(`v${p.v}`, cands.map((c) => `docs/content/${c}`));
      if (f) pages[topic] = f.rel.replace('docs/content/', '').replace(/\.md$/, '');
    }
    for (const [proto, list] of Object.entries(middlewares)) {
      for (const type of Object.keys(list)) {
        const lc = type.toLowerCase();
        const cands = proto === 'http'
          ? [`reference/routing-configuration/http/middlewares/${lc}.md`, `middlewares/http/${lc}.md`]
          : [`reference/routing-configuration/tcp/middlewares/${lc}.md`, `middlewares/tcp/${lc}.md`];
        const f = await loadFirst(`v${p.v}`, cands.map((c) => `docs/content/${c}`));
        if (f) pages[`${proto}.mw.${type}`] = f.rel.replace('docs/content/', '').replace(/\.md$/, '');
      }
    }
    docs[`v${major}`] = { base: `https://doc.traefik.io/traefik/${major === '2' ? 'v2.11/' : ''}`, tag: `v${p.v}`, pages: Object.fromEntries(Object.entries(pages).map(([k, v]) => [k, `${v.replace(/(^|\/)index$/, '')}/`])) };
  }

  // deprecations and removals stated in the migration guides; each entry must be backed by a fetched note
  const deprecated = [];
  for (const d of DEPRECATIONS) {
    const note = notes.find((n) => d.note.test(`${n.title} ${n.full}`));
    if (!note) { process.stderr.write(`(no migration note for ${d.re}; skipped)\n`); continue; }
    deprecated.push({ re: d.re, dep: d.dep, ...(d.removed ? { removed: d.removed } : {}), ...(d.use ? { use: d.use } : {}), title: note.title, docs: note.page });
  }

  notes.forEach((n) => { delete n.full; });
  const kb = {
    product: 'traefik', generated: new Date().toISOString().slice(0, 10),
    source: `${REPO}/tree/<tag>/docs/content (rendered at https://doc.traefik.io/traefik/)`,
    versions: perTag.map((p) => p.v), latest: perTag[perTag.length - 1].v,
    static: staticPaths, dynamic: dynamicPaths, matchers, middlewares, deprecated, notes, docs,
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(kb)}\n`);
  console.error(`wrote ${path.relative(process.cwd(), OUT)} (${(fs.statSync(OUT).size / 1024).toFixed(0)} KB): ${perTag.length} releases (${kb.versions[0]} .. ${kb.latest}), ${Object.keys(staticPaths).length} static and ${Object.keys(dynamicPaths).length} dynamic option paths, ${Object.keys(middlewares.http).length} HTTP / ${Object.keys(middlewares.tcp).length} TCP middleware types, ${notes.length} migration notes`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { flattenRef, tableMatchers, splitHttpTcp, migrationNotes, typeOf, docUrl };

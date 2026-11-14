'use strict';
/**
 * Caddy v2 product module (contract: src/products/CONTRACT.md).
 *
 *   caddyfile.js  lexer / tree / snippets + imports / redaction        model.js   Caddyfile -> shared section model
 *   json.js       Caddy JSON config -> shared section model             kb.js      knowledge base helpers (src/kb/caddy.json)
 *   audit.js      structural rules (caddy-*)                            validate.js version-aware validation
 *   improve.js    Config Doctor rewrite rules                           live.js    admin API + Prometheus metrics
 *   logs.js       structured JSON access logs                           build.js   Config Builder -> Caddyfile
 */
const path = require('path');
const C = require('./caddyfile');
const { buildModel } = require('./model');
const { parseJsonConfig, isJson } = require('./json');
const { kb } = require('./kb');

const EXAMPLE = path.join(__dirname, '..', '..', '..', 'examples', 'caddy', 'Caddyfile');

/** 0..1: how strongly a text looks like a Caddyfile or a Caddy JSON config. */
function detect(text) {
  const t = String(text || '');
  if (!t.trim()) return 0;
  if (isJson(t)) { try { const o = JSON.parse(t); if (o.apps && (o.apps.http || o.apps.tls)) return 0.97; if (o.admin && (o.admin.listen || o.admin.disabled !== undefined)) return 0.7; } catch { /* not JSON */ } return 0.3; }
  if (/^\s*[[{]/.test(t) && /"\w+"\s*:/.test(t)) return 0;
  const lines = t.split('\n').map((l) => l.replace(/(^|\s)#.*$/, '').trim()).filter(Boolean);
  if (!lines.length) return 0;
  let caddy = 0; let other = 0;
  const STRONG = /^(reverse_proxy|file_server|handle_path|handle_errors|encode\s+(zstd|gzip)|basic_?auth|php_fastcgi|redir\s|respond\s|tls\s+(internal|\S+@\S+)|header_up|header_down|lb_policy|health_uri|uri\s+(strip_prefix|replace|path_regexp)|import\s+\S+|log_skip|request_header|forward_auth|try_files\s|templates|acme_server|auto_https|admin\s+(off|localhost|\S+:\d+)|order\s+\S+\s+(before|after|first|last)|@\w[\w-]*(\s|\{|$)|\(\S+\)\s*\{$|&\(\S+\)\s*\{$)/;
  const SITE = /^((https?:\/\/)?(\*\.)?[a-z0-9.-]+\.[a-z]{2,}(:\d+)?|:\d+|localhost(:\d+)?|https?:\/\/)(,\s*\S+)*\s*\{$/i;
  for (const l of lines) {
    if (STRONG.test(l) || SITE.test(l) || /\{\$[A-Z_]+(:[^}]*)?\}/.test(l) || /\{(http\.request|upstream_hostport|remote_host|args\[)/.test(l)) caddy++;
    if (/;\s*$/.test(l)) other += 2;                                  // NGINX statements
    if (/^(frontend|backend|listen|defaults|global|server\s+\S+\s+\d|bind\s+[:*]|acl\s|use_backend|default_backend|option\s)/.test(l)) other += 2; // HAProxy
    if (/^<\/?[A-Z][A-Za-z]+/.test(l) || /^(ProxyPass|RewriteRule|ServerName|DocumentRoot|LoadModule)\b/.test(l)) other += 2; // Apache
    if (/^\[[a-zA-Z.]+\]$/.test(l) || /^[a-zA-Z][\w.-]*:\s*(\S.*)?$/.test(l) && !/^[a-z]+:\/\//.test(l) || /^-\s/.test(l) || /^\w+\s*=\s*/.test(l)) other += 1; // YAML / TOML
  }
  if (other > caddy * 2) return Math.min(0.2, caddy / lines.length);
  const ratio = caddy / Math.max(3, Math.min(lines.length, 40));
  return Math.max(0, Math.min(1, ratio * 1.6 - other / lines.length));
}

function result(loaded, files, opts = {}) {
  const model = buildModel(loaded, opts);
  const notes = [...loaded.notes];
  for (const e of loaded.errors) notes.push({ file: e.file, msg: `line ${e.line}: ${e.msg}` });
  for (const s of model.stray) if (s.name !== 'import') notes.push({ file: s.file, msg: `line ${s.line}: "${s.name}" outside of a site block is ignored` });
  const g = model.sections.find((s) => s.type === 'global');
  g.snippets = loaded.snippets; g.importsMissing = loaded.importsMissing; g.namedRoutes = [...(loaded.namedRoutes || new Map()).keys()];
  return { sections: model.sections, files, notes, model };
}

function fromJson(name, content, mtimeMs = 0) {
  const r = parseJsonConfig(content, name);
  return { sections: r.sections, files: [{ name, raw: C.redact(content), mtimeMs }], notes: [], json: true };
}

/** Analyse uploaded files [{ name, content }]; imports are resolved among them (never from disk). */
function parseFiles(files, opts = {}) {
  const { norm, main } = C.normalizeUpload(files);
  if (isJson(main.content)) return fromJson(main.name, main.content);
  const loaded = C.loadFiles(files);
  const used = new Set(loaded.files.map((f) => f.name));
  const out = [...loaded.files.map((f) => ({ name: f.name, raw: C.redact(f.raw), mtimeMs: 0 })), ...norm.filter((f) => !used.has(path.posix.normalize(f.name))).map((f) => ({ name: f.name, raw: C.redact(f.content), mtimeMs: 0, unused: true }))];
  const r = result(loaded, out, opts);
  r.mainFile = main.name;
  return r;
}

/** Same as parseFiles, reading from disk; imports must stay inside rootDir. */
function loadPath(mainPath, rootDir, opts = {}) {
  const fs = require('fs');
  const raw = fs.readFileSync(mainPath, 'utf8');
  if (isJson(raw)) return fromJson(path.basename(mainPath), raw, fs.statSync(mainPath).mtimeMs);
  const loaded = C.loadDisk(mainPath, rootDir);
  return result(loaded, loaded.files.map((f) => ({ name: f.name, raw: C.redact(f.raw), mtimeMs: f.mtimeMs, abs: f.abs })), opts);
}

const audit = (...a) => require('./audit').audit(...a);
const validate = (...a) => require('./validate').validate(...a);
const improve = (...a) => require('./improve').improve(...a);
const build = (...a) => require('./build').build(...a);

module.exports = {
  type: 'caddy',
  name: 'Caddy',
  short: 'Caddy',
  labels: { frontend: 'Site', backend: 'Upstreams', server: 'Upstream' },
  defaultFile: 'Caddyfile',
  example: EXAMPLE,
  fileFormats: ['Caddyfile', '*.caddy', '*.caddyfile', 'caddy.json'],
  detect,
  parseFiles,
  loadPath,
  redact: C.redact,
  audit,
  versions: () => ({ list: kb.versions, latest: kb.latest, generated: kb.generated, source: kb.source }),
  validate,
  improve,
  flow: {
    defaultPort: (scheme) => (String(scheme || '').toLowerCase().replace(/:$/, '') === 'https' || String(scheme || '').toLowerCase() === 'wss' ? 443 : 80),
  },
  live: require('./live'),
  liveSources: ['admin-api', 'metrics'],
  logs: require('./logs'),
  build,
};

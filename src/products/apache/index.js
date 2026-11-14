'use strict';
/**
 * Apache HTTP Server (httpd 2.4) product module — see src/products/CONTRACT.md.
 * Handles the Debian / Ubuntu `apache2` packaging (apache2.conf, mods-enabled, sites-enabled, envvars), the
 * RHEL / Fedora `httpd` layout (conf/httpd.conf, conf.modules.d, conf.d) and upstream builds (/usr/local/apache2).
 */
const path = require('path');
const kb = require('../../kb/apache.json');
const parse = require('./parse');
const { audit } = require('./audit');
const { validate } = require('./validate');
const { improve } = require('./improve');
const live = require('./live');
const logs = require('./logs');
const { build, LAYOUTS } = require('./build');

const KNOWN = new Set(Object.keys(kb.directives).map((k) => k.toLowerCase()));
const SECTION_RE = /^\s*<\/?(VirtualHost|Directory|DirectoryMatch|Location|LocationMatch|Files|FilesMatch|IfModule|IfDefine|IfVersion|Proxy|ProxyMatch|Limit|LimitExcept|RequireAll|RequireAny|Macro)\b[^>]*>\s*$/i;

/** 0..1: how much a text looks like an httpd configuration (NGINX / HAProxy / YAML / TOML stay low). */
function detect(text) {
  const lines = String(text || '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  if (!lines.length) return 0;
  let apache = 0; let sections = 0; let foreign = 0;
  for (const l of lines) {
    if (/[;{]\s*$/.test(l) || /^\}\s*$/.test(l)) { foreign++; continue; }                           // NGINX / Caddy / JSON
    if (/^(frontend|backend|listen|defaults|global|userlist|resolvers|peers)(\s|$)/.test(l) && !/^Listen\s+\d/.test(l)) { foreign++; continue; } // HAProxy sections (lower case)
    if (/^\[[^\]]+\]$/.test(l) || /^[a-zA-Z_][\w.-]*\s*=\s*\S/.test(l) || /^-?\s*[a-zA-Z_][\w-]*:\s*(\S.*)?$/.test(l)) { foreign++; continue; } // TOML / YAML
    if (SECTION_RE.test(l)) { sections++; apache++; continue; }
    const w = l.split(/\s+/)[0];
    if (KNOWN.has(w.toLowerCase()) && /^[A-Z]/.test(w)) apache++;
  }
  let score = apache / lines.length;
  if (sections) score = Math.min(1, score + 0.15);
  if (/^\s*LoadModule\s+\w+_module\s/m.test(text) || /^\s*<VirtualHost\s/m.test(text)) score = Math.min(1, score + 0.1);
  if (foreign / lines.length > 0.3) score *= 0.2;
  return Math.round(Math.max(0, Math.min(1, score)) * 100) / 100;
}

function versions() {
  return { list: [...kb.versions].reverse(), latest: kb.latest, generated: kb.generated, source: kb.source };
}

module.exports = {
  type: 'apache',
  name: 'Apache HTTP Server',
  short: 'Apache',
  labels: { frontend: 'VirtualHost', backend: 'Balancer', server: 'Member' },
  defaultFile: 'httpd.conf',
  example: path.join(__dirname, '..', '..', '..', 'examples', 'apache', 'apache2.conf'),
  examples: {
    debian: path.join(__dirname, '..', '..', '..', 'examples', 'apache', 'apache2.conf'),
    rhel: path.join(__dirname, '..', '..', '..', 'examples', 'apache-rhel', 'conf', 'httpd.conf'),
  },
  fileFormats: ['httpd.conf', 'apache2.conf', '*.conf', '*.load', 'envvars', '.htaccess'],
  layouts: Object.fromEntries(Object.entries(parse.LAYOUT).map(([k, v]) => [k, { name: v.name, main: v.main, siteDir: v.siteDir, test: v.test, reload: v.reload, logDir: v.logDir }])),
  buildLayouts: Object.keys(LAYOUTS),

  detect,
  parseFiles: parse.parseFiles,
  loadPath: parse.loadPath,
  redact: parse.redact,
  audit: (sections, ctx = {}) => audit(sections, ctx),
  versions,
  validate: (o) => validate(o),
  improve: (o) => improve(o),
  flow: { defaultPort: parse.defaultPort },
  live: { hasSource: live.hasSource, sources: live.sources, collect: live.collect },
  logs: { createAggregator: logs.createAggregator, sniff: logs.sniff },
  build: (spec, opts) => build(spec, opts),
};

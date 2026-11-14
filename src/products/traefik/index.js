'use strict';
/**
 * Traefik (v2 and v3) product module: see src/products/CONTRACT.md.
 *
 * Model: one frontend per entryPoint (it is what listens: address -> binds), its routes are the routers attached to it
 * in Traefik's evaluation order (TCP routers first, then priority = explicit or rule length, highest first), one route
 * per OR branch of a rule; services are backends (weighted / mirroring / failover services list child services).
 */
const path = require('path');
const model = require('./model');
const { audit } = require('./audit');
const { validate } = require('./validate');
const { improve } = require('./improve');
const { build } = require('./build');
const live = require('./live');
const logs = require('./logs');
const K = require('./kb');

/** How strongly a text looks like Traefik configuration (static, dynamic, labels or CLI flags). */
function detect(text) {
  const t = String(text || '');
  if (!t.trim()) return 0;
  let s = 0;
  if (/traefik\.(http|tcp|udp)\.(routers|services|middlewares)\./i.test(t)) s += 0.6;
  if (/^\s*(--)?entry[Pp]oints[.:\]]/m.test(t) || /^\s*\[entryPoints[.\]]/m.test(t)) s += 0.35;
  if (/^\s*(certificatesResolvers|providers)\s*[:\]]/m.test(t) || /^\s*\[(certificatesResolvers|providers)[.\]]/m.test(t)) s += 0.2;
  if (/^(http|tcp)\s*:\s*$/m.test(t) && /^\s+(routers|services|middlewares)\s*:/m.test(t)) s += 0.5;
  if (/^\s*\[(http|tcp)\.(routers|services|middlewares)[.\]]/m.test(t)) s += 0.6;
  if (/\b(rule\s*[:=]\s*["']?(Host|PathPrefix|HostSNI|Path|Headers?|ClientIP)\(`)/.test(t)) s += 0.35;
  if (/\bloadBalancer\s*[:\]=]|\bloadbalancer\.server\.port\b/i.test(t)) s += 0.2;
  if (/^\s*(server|location|upstream|frontend|backend|listen)\b[^:\n]*[{;]?\s*$/m.test(t) && /[;{]\s*$/m.test(t)) s -= 0.5; // NGINX / HAProxy
  return Math.max(0, Math.min(1, s));
}

module.exports = {
  type: 'traefik',
  name: 'Traefik Proxy',
  short: 'Traefik',
  labels: { frontend: 'EntryPoint', backend: 'Service', server: 'Server' },
  defaultFile: 'traefik.yml',
  example: path.join(__dirname, '..', '..', '..', 'examples', 'traefik', 'traefik.yml'),
  examples: ['traefik.yml', 'dynamic/routers.yml', 'dynamic/middlewares.yml', 'docker-compose.yml'].map((f) => path.join(__dirname, '..', '..', '..', 'examples', 'traefik', f)),
  fileFormats: ['traefik.yml', 'traefik.toml', 'dynamic/*.yml', '*.toml', 'docker-compose.yml'],
  liveSources: ['Traefik API', 'Prometheus metrics'],

  detect,
  parseFiles: (files) => { const r = model.parseFiles(files); return { sections: r.sections, files: r.files, notes: r.notes }; },
  loadPath: (mainPath, rootDir) => { const r = model.loadPath(mainPath, rootDir); return { sections: r.sections, files: r.files, notes: r.notes }; },
  redact: model.redact,
  audit,
  versions: K.versions,
  validate,
  improve,
  flow: { defaultPort: (scheme) => (/^(https|wss|h2|grpcs|tls)$/i.test(String(scheme || '')) ? 443 : 80) },
  live: { hasSource: live.hasSource, sources: live.sources, collect: live.collect },
  logs: { createAggregator: logs.createAggregator, sniff: logs.sniff },
  build,
};

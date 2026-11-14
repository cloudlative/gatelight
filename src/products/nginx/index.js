'use strict';
/** NGINX as a product module (adapter over the long-standing modules; see ../CONTRACT.md). */
const path = require('path');
const { parseNginxFiles, loadNginxConfig, redactNginx } = require('../../nginxConfig');
const { auditNginx } = require('../../nginxAudit');
const { validateConfig, versions } = require('../../validate');
const { detectProduct } = require('../../improve');
const logs = require('../../logs/nginx');

module.exports = {
  type: 'nginx', name: 'NGINX', short: 'NGINX', defaultFile: 'nginx.conf',
  labels: { frontend: 'Server block', backend: 'Upstream', server: 'Peer' },
  example: path.join(__dirname, '..', '..', '..', 'examples', 'nginx', 'nginx.conf'),
  liveSources: ['stub_status', 'NGINX Plus API', 'TCP probe'],
  detect: (text) => (/^\s*(events|http|stream|upstream|location)(\s[^\n#;{}]*)?\{\s*(#.*)?$/m.test(text) ? 0.8 : detectProduct(text) === 'nginx' ? 0.6 : 0),
  parseFiles(files) { const r = parseNginxFiles(files); return { sections: r.sections, files: r.files.map(({ name, raw }) => ({ name, raw })), notes: r.notes || [] }; },
  loadPath(p, root) { const r = loadNginxConfig(p, root || path.dirname(p)); return { sections: r.sections, files: r.files, notes: r.notes }; },
  redact: redactNginx,
  audit: (sections, { notes = [], rows = [] } = {}) => auditNginx(sections, { notes, rows }),
  versions() { const v = versions().nginx; return { list: v.list || [v.latest], latest: v.latest, generated: v.generated, source: v.source }; },
  validate: ({ files, version, build }) => validateConfig({ product: 'nginx', version, files, build }),
  flow: { defaultPort: (scheme) => (scheme === 'https' || scheme === 'grpcs' ? 443 : 80) },
  logs: { createAggregator: logs.createAggregator, sniff: logs.sniff },
  get build() { try { return require('../../build/nginx').build; } catch { return undefined; } },
};

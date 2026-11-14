'use strict';
/** HAProxy as a product module (adapter over the long-standing modules; see ../CONTRACT.md). */
const path = require('path');
const fs = require('fs');
const { parseConfig, redactConfig } = require('../../haproxyConfig');
const { auditConfig } = require('../../audit');
const { validateConfig, versions } = require('../../validate');
const { detectProduct } = require('../../improve');
const logs = require('../../logs/haproxy');

const pick = (files) => files.find((x) => /haproxy/i.test(x.name)) || files[0];

module.exports = {
  type: 'haproxy', name: 'HAProxy', short: 'HAProxy', defaultFile: 'haproxy.cfg',
  labels: { frontend: 'Frontend', backend: 'Backend', server: 'Server' },
  example: path.join(__dirname, '..', '..', '..', 'examples', 'haproxy', 'haproxy.cfg'),
  liveSources: ['Stats page (CSV)', 'Runtime API socket'],
  detect: (text) => (detectProduct(text) === 'haproxy' ? 0.7 : 0),
  parseFiles(files) {
    const f = pick(files);
    return { sections: parseConfig(f.content), files: [{ name: f.name.split('/').pop(), raw: redactConfig(f.content) }], notes: files.length > 1 ? [{ file: f.name, msg: `Multiple files uploaded; only ${f.name} was analysed (HAProxy configs are single-file).` }] : [] };
  },
  loadPath(p) { const raw = fs.readFileSync(p, 'utf8'); return { sections: parseConfig(raw), files: [{ name: path.basename(p), raw: redactConfig(raw) }], notes: [] }; },
  redact: redactConfig,
  audit: (sections, { rows = [], files = [] } = {}) => auditConfig(sections, { runtime: { rows } }).map((x) => ({ ...x, file: x.file || (files[0] && files[0].name) || '' })),
  versions() { const v = versions().haproxy; return { list: v.list, latest: v.latest, generated: v.generated, source: v.source }; },
  validate: ({ files, version }) => validateConfig({ product: 'haproxy', version, config: pick(files).content }),
  flow: { defaultPort: (scheme) => (scheme === 'https' ? 443 : 80) },
  logs: { createAggregator: logs.createAggregator, sniff: logs.sniff },
  get build() { try { return require('../../build/haproxy').build; } catch { return undefined; } },
};

'use strict';
/**
 * One assessment from three engines: the structural audit (src/audit.js, nginxAudit.js), the version validator
 * (src/validate) and the Forge rewrite rules (src/improve). Where they report the same concern the Forge entry
 * wins (it carries the fix) and remembers who else flagged it, so each problem appears exactly once.
 */
const { improveConfig } = require('./index');
const { score } = require('./common');
const { validateConfig } = require('../validate');
const { parseConfig } = require('../haproxyConfig');
const { parseNginxFiles } = require('../nginxConfig');
const { auditConfig } = require('../audit');
const { auditNginx } = require('../nginxAudit');

/** legacy rule id -> Forge rule ids (or prefixes ending in *) that cover it. `global: true` = Forge reports it once for the whole config. */
const COVERED = {
  // HAProxy: audit
  'server-no-check': ['hap-check'], 'missing-timeout': ['hap-timeout-*'], 'deprecated-directive': ['hap-legacy-*'], 'single-server': ['hap-single-server'],
  'stats-exposed': ['hap-stats-bind'], 'weak-stats-credential': ['hap-stats-weak'], 'tls-min-version': ['hap-tls-options', 'hap-bind-tls'],
  // HAProxy: validate recommendations
  'rec-hsts': ['hap-hsts'], 'rec-alpn-h2': ['hap-alpn'], 'rec-forwardfor': ['hap-forwardfor'], 'rec-nbproc': ['hap-nbproc'], 'rec-weak-ciphers': ['hap-tls-ciphers', 'hap-bind-tls'],
  'rec-dh-param': ['hap-dh-param'], 'rec-logging': ['hap-log', 'hap-httplog', 'hap-tcplog', 'hap-log-global'], 'rec-stats-socket-network': ['hap-stats-socket'],
  // NGINX: audit
  'nginx-server-tokens': ['ngx-tokens'], 'nginx-autoindex': ['ngx-autoindex'], 'nginx-stub-status-open': ['ngx-status-open'], 'nginx-no-http-redirect': ['ngx-https-redirect'],
  'nginx-weak-tls': ['ngx-tls-ciphers', 'ngx-tls-protocols'], 'nginx-no-tls-protocols': ['ngx-tls-protocols'], 'nginx-if-proxy': ['ngx-if-evil'],
  // NGINX: validate recommendations
  'rec-nginx-if-is-evil': ['ngx-if-evil'], 'rec-nginx-return-redirect': ['ngx-redirect-return'], 'rec-nginx-ssl-session-cache': ['ngx-tls-cache'], 'rec-nginx-worker-auto': ['ngx-workers'],
  'rec-nginx-weak-ciphers': ['ngx-tls-ciphers'], 'rec-nginx-hsts': ['ngx-hsts'], 'rec-nginx-keepalive-http11': ['ngx-proxy-http11', 'ngx-upstream-keepalive'],
  'rec-nginx-inherit': ['ngx-header-inherit', 'ngx-proxy-headers'], 'rec-nginx-gzip-types': ['ngx-gzip'],
};
const SEV = { error: 'high', warning: 'medium', info: 'low' };
const CAT = { syntax: 'correctness', compat: 'compatibility', recommendation: 'hygiene' };
const WHOLE = new Set(['http', 'global', 'defaults', 'main', 'events']);
const familyHas = (fam, rule) => fam.some((f) => (f.endsWith('*') ? rule.startsWith(f.slice(0, -1)) : f === rule));
const bare = (s) => String(s || '').replace(/^(frontend|backend|listen|defaults|server|upstream|location)\s+/, '').replace(/:\d+$/, '').trim();
const sameSection = (a, b) => { const x = bare(a); const y = bare(b); return x === y || (x && y && (x.startsWith(y) || y.startsWith(x))); };

function staticAudit(product, files, haText) {
  try {
    if (product !== 'haproxy' && product !== 'nginx') { const m = require('../products').get(product); const p = m.parseFiles(files.map((f) => ({ name: f.name, content: f.original }))); return m.audit(p.sections, { notes: p.notes || [], files: p.files }); }
    if (product === 'nginx') { const p = parseNginxFiles(files.map((f) => ({ name: f.name, content: f.original }))); return auditNginx(p.sections, { notes: p.notes || [] }); }
    return auditConfig(parseConfig(haText), { runtime: { rows: [] } });
  } catch { return []; }
}

/** @param {object} o improveConfig options plus { audit?: Finding[] } (the live audit of an instance, drift included) */
function assessConfig(o) {
  const r = improveConfig(o);
  const forge = r.changes.map((c) => ({ ...c, id: c.rule, detail: c.why, sources: ['forge'], kind: c.auto ? (c.on ? 'auto' : 'optional') : 'input' }));
  const text = r.files.length === 1 ? r.files[0].original : r.files.map((f) => f.original).join('\n');
  const audit = Array.isArray(o.audit) ? o.audit : staticAudit(r.product, r.files, text);
  let val = [];
  try { val = validateConfig({ product: r.product, version: o.version || null, config: r.product === 'haproxy' ? text : undefined, files: r.product !== 'haproxy' ? r.files.map((f) => ({ name: f.name, content: f.original })) : undefined, build: typeof o.build === 'string' ? o.build : undefined }).findings; } catch { /* the validator is advisory here */ }

  const legacy = [...audit.map((f) => ({ ...f, source: 'audit' })), ...val.map((f) => ({ ...f, source: 'validate' }))];
  const kept = [];
  for (const f of legacy) {
    const fam = COVERED[f.id];
    const hit = fam && forge.find((c) => c.kind !== 'optional' && familyHas(fam, c.rule) && (WHOLE.has(String(c.section).split(' ')[0]) || !f.section || /^(location |server$|upstream$|http$|main$)/.test(f.section) || sameSection(c.section, f.section)));
    if (hit) { if (!hit.sources.includes(f.source)) hit.sources.push(f.source); (hit.alsoFlagged = hit.alsoFlagged || []).push(`${f.source}: ${f.id}`); continue; }
    kept.push({ key: `${f.source}:${f.id}:${f.section || ''}:${f.line || ''}`, rule: f.id, id: f.id, category: CAT[f.category] || f.category || 'hygiene', severity: SEV[f.severity] || 'info', title: f.title, detail: f.detail || '', why: f.detail || '', fix: f.fix || '', section: f.section || '', line: f.line || null, file: f.file || null, sources: [f.source], kind: 'problem', auto: false, on: false, applied: false, diff: [], docs: f.docs || null, since: f.since || null, until: f.until || null });
  }
  // the same legacy finding can arrive from both audit and validate: keep one
  const seen = new Set(); const problems = kept.filter((f) => { const k = `${f.rule}|${f.section}|${f.line}`; if (seen.has(k)) return false; seen.add(k); return true; });
  if (o.versionDetected && o.version) r.notes = r.notes.filter((n) => !/No version was given/.test(n)).concat(`Targeting ${require('../products').nameOf(r.product)} ${o.version}, detected from the running server. Choose another version above to change it.`);
  const findings = [...forge, ...problems];
  const open = findings.filter((f) => f.kind !== 'optional');
  const scoreBefore = score(open); const scoreAfter = score(open.filter((f) => f.kind === 'input' || f.kind === 'problem' || (f.kind === 'auto' && !f.applied)));
  const sevCount = (k) => open.filter((f) => f.severity === k).length;
  return {
    ...r, findings, versionDetected: Boolean(o.versionDetected && o.version),
    score: { before: scoreBefore, after: scoreAfter, gradeBefore: gradeOf(scoreBefore), gradeAfter: gradeOf(scoreAfter) },
    summary: { ...r.summary, findings: open.length, problems: problems.length, high: sevCount('high'), medium: sevCount('medium'), low: sevCount('low'), info: sevCount('info'), merged: forge.filter((c) => c.alsoFlagged).length },
  };
}
const gradeOf = (s) => (s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F');

module.exports = { assessConfig, COVERED };

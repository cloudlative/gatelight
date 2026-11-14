'use strict';
/**
 * Config Builder: spec (src/build/spec.js) -> configuration for one product, then checked by that product's own
 * engines: parsed back into the shared model, validated against the documentation of the target version, and audited.
 * Nothing is sent anywhere; the result is text for the user to review and deploy.
 */
const { normalizeSpec, EXAMPLE_SPEC } = require('./spec');
const products = require('../products');
const { validateConfig, summarize } = require('../validate');

const isDataFile = (f) => f.kind === 'data' || /(^|\/)(htpasswd\/|\.htpasswd$|htpasswd$)/.test(f.name) || /\.(htpasswd|users|passwd)$/.test(f.name);

function buildConfig(product, input, { check = true } = {}) {
  const mod = products.get(product);
  if (!mod || typeof mod.build !== 'function') throw Object.assign(new Error(`The Config Builder is not available for "${product}" on this server.`), { status: 400 });
  const spec = normalizeSpec(input);
  const versions = typeof mod.versions === 'function' ? mod.versions() : null;
  const target = spec.version || (versions && versions.latest) || null;
  const out = mod.build({ ...spec, version: target });
  const res = { product, name: products.nameOf(product), target, files: out.files, notes: out.notes || [], unsupported: out.unsupported || [] };
  if (!check) return res;
  // Data files written next to the config (htpasswd files, ...) are not configuration: keep them out of the checks.
  const cfgFiles = out.files.filter((f) => !isDataFile(f));
  try {
    const parsed = mod.parseFiles(cfgFiles);
    const secs = parsed.sections;
    res.model = {
      frontends: secs.filter((s) => s.type === 'frontend').map((s) => ({ name: s.name, ports: [...new Set((s.binds || []).map((b) => b.port))], hosts: s.serverNames || [], routes: (s.routes || []).length })),
      backends: secs.filter((s) => s.type === 'backend' && !s.implicit).map((s) => ({ name: s.name, servers: (s.servers || []).length, balance: s.balance || null })),
    };
    const audit = mod.audit(secs, { notes: parsed.notes || [], rows: [], files: parsed.files });
    res.audit = { summary: summarize(audit), findings: audit };
  } catch (e) { res.model = null; res.audit = { error: e.message }; }
  try {
    const v = validateConfig({ product, version: target, files: cfgFiles, config: product === 'haproxy' ? cfgFiles[0].content : undefined });
    res.validation = { target: v.target, summary: v.summary, findings: v.findings };
  } catch (e) { res.validation = { error: e.message }; }
  return res;
}

module.exports = { buildConfig, EXAMPLE_SPEC, isDataFile };

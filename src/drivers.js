'use strict';
/**
 * A driver adapts one proxy technology to the common pipeline:
 *   loadConfig(inst, cache) -> cache   (parsed model + redacted files; reuses cache when unchanged)
 *   collect(inst, cache)    -> {rows, info}
 *   audit(cache, rows)      -> findings
 */
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { parseConfig, redactConfig } = require('./haproxyConfig');
const { loadNginxConfig, parseNginxFiles } = require('./nginxConfig');
const { auditConfig } = require('./audit');
const { auditNginx } = require('./nginxAudit');
const { fetchStats } = require('./transport');
const { parseStatsCsv, parseInfo } = require('./statsParser');
const { collectNginx } = require('./nginxStats');
const products = require('./products');

const NGINX_RELOAD_CHECK_MS = 30000;

const haproxy = {
  type: 'haproxy',
  labels: { frontend: 'Frontend', backend: 'Backend', server: 'Server' },

  hasSource: (inst) => Boolean(inst.demo || inst.statsUrl || inst.socket),
  sources: (inst) => (inst.demo ? ['demo'] : inst.socket ? ['runtime-api'] : inst.statsUrl ? ['http-stats'] : []),

  loadConfig(inst, cache) {
    if (inst.configFiles && inst.configFiles.length) { // uploaded in the UI: no file on disk
      const f = inst.configFiles.find((x) => /haproxy/i.test(x.name)) || inst.configFiles[0];
      const sig = crypto.createHash('sha1').update(f.content).digest('hex');
      if (cache && cache.sig === sig) return cache;
      return { path: '(uploaded)', sig, loadedAt: Date.now(), sections: parseConfig(f.content), files: [{ name: f.name.split('/').pop(), raw: redactConfig(f.content) }], notes: inst.configFiles.length > 1 ? [{ file: f.name, msg: `Multiple files uploaded; only ${f.name} was analysed (HAProxy configs are single-file).` }] : [], error: null };
    }
    const p = inst.configPath;
    if (!p) return { path: null, error: 'No config uploaded for this instance', sections: [], files: [] };
    try {
      const st = fs.statSync(p);
      if (cache && cache.sig === st.mtimeMs && cache.path === p) return cache;
      const raw = fs.readFileSync(p, 'utf8');
      return { path: p, sig: st.mtimeMs, loadedAt: Date.now(), sections: parseConfig(raw), files: [{ name: path.basename(p), raw: redactConfig(raw) }], notes: [], error: null };
    } catch (e) {
      return { ...(cache || {}), path: p, error: `Cannot read ${p}: ${e.message}`, sections: (cache && cache.sections) || [], files: (cache && cache.files) || [] };
    }
  },

  async collect(inst, _cache, ctx) {
    const res = inst.demo ? ctx.demo.fetch() : await fetchStats(inst);
    const rows = parseStatsCsv(res.csv);
    if (!rows.length) throw new Error('Stats response contained no proxy rows');
    return { rows, info: parseInfo(res.info) };
  },

  audit(cache, rows) {
    const file = cache.files[0] ? cache.files[0].name : '';
    return auditConfig(cache.sections, { runtime: { rows } }).map((f) => ({ ...f, file }));
  },
};

const nginx = {
  type: 'nginx',
  labels: { frontend: 'Server block', backend: 'Upstream', server: 'Peer' },

  hasSource: (inst) => Boolean(inst.demo || inst.statsUrl || inst.plusApiUrl || inst.probe),
  sources: (inst) => (inst.demo ? ['demo'] : [inst.plusApiUrl && 'plus-api', inst.statsUrl && 'stub-status', inst.probe && 'tcp-probe'].filter(Boolean)),

  loadConfig(inst, cache) {
    if (inst.configFiles && inst.configFiles.length) {
      const sig = crypto.createHash('sha1').update(inst.configFiles.map((f) => `${f.name}\0${f.content}`).join('\0')).digest('hex');
      if (cache && cache.sig === sig) return cache;
      try {
        const r = parseNginxFiles(inst.configFiles);
        return { path: '(uploaded)', sig, loadedAt: Date.now(), sections: r.sections, files: r.files.map(({ name, raw }) => ({ name, raw })), notes: r.notes || [], error: null };
      } catch (e) { return { path: '(uploaded)', sig, error: `Could not parse the uploaded config: ${e.message}`, sections: [], files: [], notes: [] }; }
    }
    const p = inst.configPath;
    if (!p) return { path: null, error: 'No config uploaded for this instance', sections: [], files: [] };
    try {
      const stale = !cache || cache.path !== p || Date.now() - cache.loadedAt > NGINX_RELOAD_CHECK_MS
        || cache.files.some((f) => { try { return fs.statSync(f.abs).mtimeMs !== f.mtimeMs; } catch { return true; } });
      if (!stale) return cache;
      const root = inst.includeRoot || path.dirname(p);
      const r = loadNginxConfig(p, root);
      const sig = r.files.map((f) => `${f.name}:${f.mtimeMs}`).join('|');
      return { path: p, sig, loadedAt: Date.now(), sections: r.sections, files: r.files, notes: r.notes, error: null };
    } catch (e) {
      return { ...(cache || {}), path: p, error: `Cannot read ${p}: ${e.message}`, sections: (cache && cache.sections) || [], files: (cache && cache.files) || [] };
    }
  },

  async collect(inst, cache, ctx) {
    if (inst.demo) {
      const res = ctx.demo.fetch();
      return { rows: parseStatsCsv(res.csv), info: { version: 'nginx/1.25-demo', activeConns: 40 + Math.round(Math.random() * 30) } };
    }
    return collectNginx(inst, cache.sections);
  },

  audit(cache, rows) { return auditNginx(cache.sections, { notes: cache.notes || [], rows }); },
};

/**
 * Apache, Caddy and Traefik: one driver built from the product module (src/products/<type>, see CONTRACT.md).
 * Config files are read through the module (includes / imports / file providers stay inside the config's folder),
 * live stats come from its read-only collector, and the demo reuses the synthetic traffic generator.
 */
function productDriver(type) {
  const mod = () => products.get(type);
  const labels = (mod() && mod().labels) || { frontend: 'Frontend', backend: 'Backend', server: 'Server' };
  const live = () => (mod() && mod().live) || null;
  return {
    type, labels,
    hasSource: (inst) => Boolean(inst.demo || (live() && live().hasSource(inst))),
    sources: (inst) => (inst.demo ? ['demo'] : live() && live().hasSource(inst) ? live().sources(inst) : []),

    loadConfig(inst, cache) {
      const m = mod();
      if (!m) return { path: null, error: `${products.nameOf(type)} support is not available on this server`, sections: [], files: [] };
      if (inst.configFiles && inst.configFiles.length) {
        const sig = crypto.createHash('sha1').update(inst.configFiles.map((f) => `${f.name}\0${f.content}`).join('\0')).digest('hex');
        if (cache && cache.sig === sig) return cache;
        try {
          const r = m.parseFiles(inst.configFiles);
          return { path: '(uploaded)', sig, loadedAt: Date.now(), sections: r.sections, files: r.files.map(({ name, raw }) => ({ name, raw })), notes: r.notes || [], error: null };
        } catch (e) { return { path: '(uploaded)', sig, error: `Could not parse the uploaded config: ${e.message}`, sections: [], files: [], notes: [] }; }
      }
      const p = inst.configPath;
      if (!p) return { path: null, error: 'No config uploaded for this instance', sections: [], files: [] };
      try {
        const stale = !cache || cache.path !== p || Date.now() - (cache.loadedAt || 0) > NGINX_RELOAD_CHECK_MS
          || (cache.files || []).some((f) => { try { return f.abs && fs.statSync(f.abs).mtimeMs !== f.mtimeMs; } catch { return true; } });
        if (!stale) return cache;
        const r = m.loadPath(p, inst.includeRoot || path.dirname(p));
        const sig = crypto.createHash('sha1').update(r.files.map((f) => `${f.name}\0${f.raw}`).join('\0')).digest('hex');
        if (cache && cache.sig === sig && cache.path === p) return { ...cache, loadedAt: Date.now() };
        return { path: p, sig, loadedAt: Date.now(), sections: r.sections, files: r.files, notes: r.notes || [], error: null };
      } catch (e) {
        return { ...(cache || {}), path: p, error: `Cannot read ${p}: ${e.message}`, sections: (cache && cache.sections) || [], files: (cache && cache.files) || [] };
      }
    },

    async collect(inst, cache, ctx) {
      if (inst.demo) {
        const res = ctx.demo.fetch();
        return { rows: parseStatsCsv(res.csv), info: { version: `${type}-demo` } };
      }
      const l = live();
      if (!l) throw new Error(`${products.nameOf(type)} has no live statistics source`);
      return l.collect(inst, cache, ctx);
    },

    audit(cache, rows) {
      const m = mod(); if (!m) return [];
      try { return m.audit(cache.sections || [], { notes: cache.notes || [], rows, files: cache.files || [] }); } catch (e) { return [{ id: `${type}-audit-error`, severity: 'info', category: 'hygiene', section: 'global', line: 1, title: 'The audit could not finish', detail: e.message, fix: '' }]; }
    },
  };
}

const DRIVERS = { haproxy, nginx };
for (const t of ['apache', 'caddy', 'traefik']) DRIVERS[t] = productDriver(t);
module.exports = { DRIVERS };

'use strict';
/**
 * Product registry: every proxy technology GateLight understands, behind one interface (see CONTRACT.md).
 * HAProxy and NGINX are thin adapters over their long-standing modules; Apache, Caddy and Traefik are full modules
 * in src/products/<type>/. A module that fails to load is reported once and left out, so one broken product never
 * takes the others down.
 */
const log = require('../logger');

const ORDER = ['haproxy', 'nginx', 'apache', 'caddy', 'traefik'];
const META = {
  haproxy: { name: 'HAProxy', short: 'HAProxy', defaultFile: 'haproxy.cfg' },
  nginx: { name: 'NGINX', short: 'NGINX', defaultFile: 'nginx.conf' },
  apache: { name: 'Apache HTTP Server (httpd / apache2)', short: 'Apache', defaultFile: 'httpd.conf' },
  caddy: { name: 'Caddy', short: 'Caddy', defaultFile: 'Caddyfile' },
  traefik: { name: 'Traefik', short: 'Traefik', defaultFile: 'traefik.yml' },
};

const cache = new Map();
const failed = new Map();
function get(type) {
  if (!ORDER.includes(type)) return null;
  if (cache.has(type)) return cache.get(type);
  if (failed.has(type)) return null;
  try {
    const mod = require(`./${type}`);
    cache.set(type, mod);
    return mod;
  } catch (e) {
    failed.set(type, e.message);
    log.warn(`${META[type].short} support could not be loaded`, { error: String(e.message || e).split('\n')[0] });
    return null;
  }
}

/** Products that loaded, in display order. */
const types = () => ORDER.filter((t) => get(t));
const nameOf = (t) => (META[t] ? META[t].short : t);
const has = (t, fn) => { const p = get(t); return Boolean(p && fn.split('.').reduce((o, k) => (o ? o[k] : undefined), p)); };

/** Which product a text most likely is (the strongest module-reported score above `min`), or null. */
function detect(text, min = 0.5) {
  let best = null; let score = min;
  for (const t of types()) {
    const p = get(t);
    if (typeof p.detect !== 'function') continue;
    let s = 0;
    try { s = Number(p.detect(String(text || ''))) || 0; } catch { s = 0; }
    if (s > score) { score = s; best = t; }
  }
  return best;
}

/** What the UI needs to know about each product. */
function describe() {
  return types().map((t) => {
    const p = get(t);
    let versions = null;
    try { versions = typeof p.versions === 'function' ? p.versions() : null; } catch { versions = null; }
    return {
      type: t, name: p.name || META[t].name, short: p.short || META[t].short, labels: p.labels, defaultFile: p.defaultFile || META[t].defaultFile,
      versions: versions ? { list: (versions.list || []).slice(0, 80), latest: versions.latest, generated: versions.generated, source: versions.source } : null,
      can: { validate: typeof p.validate === 'function', improve: typeof p.improve === 'function', live: Boolean(p.live && p.live.collect), logs: Boolean(p.logs && p.logs.createAggregator), build: typeof p.build === 'function', flow: Boolean(p.flow) },
      sources: p.liveSources || null,
    };
  });
}

module.exports = { get, types, detect, describe, nameOf, has, ORDER, META, failed };

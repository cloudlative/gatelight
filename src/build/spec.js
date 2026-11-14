'use strict';
/**
 * Config Builder: one product-neutral description of a load balancer / reverse proxy, turned into a configuration
 * for HAProxy, NGINX, Apache, Caddy or Traefik by each product's `build(spec)`.
 *
 * normalizeSpec(input) checks and fills defaults, so every generator gets the same clean shape:
 *
 * {
 *   version: '2.4.62' | null,                 // target version of the chosen product (generators stay valid for it)
 *   sites: [{
 *     name: 'shop',                           // [a-z0-9_-], unique
 *     hosts: ['shop.example.com'],            // empty = any host (catch-all)
 *     http: { port: 80 }, https: { port: 443 } | null,
 *     tls: { mode: 'none'|'files'|'acme', cert, key, email, redirectHttp: true, hsts: true, minVersion: '1.2'|'1.3' },
 *     routes: [{ path: '/api', match: 'prefix'|'exact', pool: 'api', stripPrefix: false, rewriteTo: null }],   // evaluated longest path first
 *     defaultPool: 'web' | null,              // where everything else goes (null = 404)
 *     redirectTo: null | 'https://other/',    // a site that only redirects
 *     securityHeaders: true, compression: true,
 *     rateLimit: { rps: 20, burst: 40 } | null,
 *     basicAuth: { realm, users: [{ user, hash }] } | null,   // hash only: bcrypt ($2y$...) or the product's own format
 *     maxBodyMb: 10 | null,
 *     websocket: false,
 *   }],
 *   pools: [{
 *     name: 'api', balance: 'roundrobin'|'leastconn'|'iphash'|'random',
 *     servers: [{ address: '10.0.0.1:8080', weight: 1|null, backup: false }],
 *     scheme: 'http'|'https', verifyTls: true,
 *     healthCheck: { path: '/health', interval: 5, timeout: 2, rise: 2, fall: 3 } | null,
 *     sticky: false,
 *     timeouts: { connect: 5, server: 60 },   // seconds
 *   }],
 *   options: { accessLog: true, logFormat: 'combined'|'json', statusPage: { enabled: false, port: 8404, allow: ['127.0.0.1'] },
 *              clientTimeout: 60, maxConnections: 10000, workers: 'auto' },
 * }
 */

const NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/;
const HOST = /^(\*\.)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$/;
const ADDR = /^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):(\d{1,5})$/;
const PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/;
const BALANCE = ['roundrobin', 'leastconn', 'iphash', 'random'];

class SpecError extends Error { constructor(errors) { super(errors.join('; ')); this.errors = errors; this.status = 400; } }

const num = (v, d, min, max) => { const n = Number(v); return v === undefined || v === null || v === '' || !Number.isFinite(n) ? d : Math.min(max, Math.max(min, Math.round(n))); };
const bool = (v, d) => (v === undefined || v === null ? d : Boolean(v));
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const port = (v, d) => num(v, d, 1, 65535);

function normalizeSpec(input) {
  const errors = [];
  const s = input && typeof input === 'object' ? input : {};
  const pools = (Array.isArray(s.pools) ? s.pools : []).slice(0, 100).map((p, i) => {
    const name = str(p && p.name, 63) || `pool${i + 1}`;
    if (!NAME.test(name)) errors.push(`Pool "${name}": use letters, digits, "-", "_" or "."`);
    const servers = (Array.isArray(p.servers) ? p.servers : []).slice(0, 200).map((x) => (typeof x === 'string' ? { address: x } : x || {})).map((x) => {
      const address = str(x.address, 300);
      if (!ADDR.test(address)) errors.push(`Pool "${name}": "${address}" is not host:port`);
      return { address, weight: x.weight == null || x.weight === '' ? null : num(x.weight, 1, 0, 256), backup: Boolean(x.backup) };
    });
    if (!servers.length) errors.push(`Pool "${name}" has no servers`);
    const hc = p.healthCheck === null || p.healthCheck === false ? null : p.healthCheck || {};
    const hcPath = hc ? str(hc.path, 300) || '/' : null;
    if (hc && !PATH.test(hcPath)) errors.push(`Pool "${name}": health check path must start with /`);
    return {
      name, servers, balance: BALANCE.includes(p.balance) ? p.balance : 'roundrobin',
      scheme: p.scheme === 'https' ? 'https' : 'http', verifyTls: bool(p.verifyTls, true),
      healthCheck: hc ? { path: hcPath, interval: num(hc.interval, 5, 1, 3600), timeout: num(hc.timeout, 2, 1, 600), rise: num(hc.rise, 2, 1, 20), fall: num(hc.fall, 3, 1, 20) } : null,
      sticky: Boolean(p.sticky),
      timeouts: { connect: num(p.timeouts && p.timeouts.connect, 5, 1, 600), server: num(p.timeouts && p.timeouts.server, 60, 1, 86400) },
    };
  });
  const poolNames = new Set(pools.map((p) => p.name));
  if (poolNames.size !== pools.length) errors.push('Pool names must be unique');

  const sites = (Array.isArray(s.sites) ? s.sites : []).slice(0, 100).map((x, i) => {
    const name = str(x && x.name, 63) || `site${i + 1}`;
    if (!NAME.test(name)) errors.push(`Site "${name}": use letters, digits, "-", "_" or "."`);
    const hosts = (Array.isArray(x.hosts) ? x.hosts : String(x.hosts || '').split(/[\s,]+/)).map((h) => str(h, 253).toLowerCase()).filter(Boolean);
    hosts.forEach((h) => { if (!HOST.test(h)) errors.push(`Site "${name}": "${h}" is not a host name`); });
    const t = x.tls || {};
    const mode = ['none', 'files', 'acme'].includes(t.mode) ? t.mode : 'none';
    if (mode === 'files' && (!str(t.cert) || !str(t.key))) errors.push(`Site "${name}": TLS from files needs a certificate and a key path`);
    if (mode === 'acme' && !hosts.length) errors.push(`Site "${name}": automatic certificates (ACME) need at least one host name`);
    if (mode === 'acme' && hosts.some((h) => h.startsWith('*.'))) errors.push(`Site "${name}": wildcard names need a DNS challenge; use certificate files instead`);
    const routes = (Array.isArray(x.routes) ? x.routes : []).slice(0, 200).map((r) => {
      const path = str(r.path, 500) || '/';
      if (!PATH.test(path)) errors.push(`Site "${name}": route path "${path}" must start with / and contain no spaces`);
      if (!poolNames.has(r.pool)) errors.push(`Site "${name}": route ${path} uses unknown pool "${r.pool}"`);
      const rewriteTo = r.rewriteTo ? str(r.rewriteTo, 500) : null;
      if (rewriteTo && !PATH.test(rewriteTo)) errors.push(`Site "${name}": rewrite target "${rewriteTo}" must start with /`);
      return { path, match: r.match === 'exact' ? 'exact' : 'prefix', pool: r.pool, stripPrefix: Boolean(r.stripPrefix) && path !== '/', rewriteTo };
    }).sort((a, b) => (a.match === 'exact' ? 0 : 1) - (b.match === 'exact' ? 0 : 1) || b.path.length - a.path.length); // exact first, then longest prefix
    const defaultPool = x.defaultPool ? str(x.defaultPool, 63) : null;
    if (defaultPool && !poolNames.has(defaultPool)) errors.push(`Site "${name}": unknown default pool "${defaultPool}"`);
    const redirectTo = x.redirectTo ? str(x.redirectTo, 500) : null;
    if (redirectTo && !/^https?:\/\/[^\s]+$/.test(redirectTo)) errors.push(`Site "${name}": redirect target must be an http(s) URL`);
    if (!redirectTo && !defaultPool && !routes.length) errors.push(`Site "${name}" sends traffic nowhere: add a route, a default pool or a redirect`);
    const tlsOn = mode !== 'none';
    const rl = x.rateLimit && Number(x.rateLimit.rps) > 0 ? { rps: num(x.rateLimit.rps, 20, 1, 100000), burst: num(x.rateLimit.burst, 40, 0, 1000000) } : null;
    const ba = x.basicAuth && Array.isArray(x.basicAuth.users) && x.basicAuth.users.length ? {
      realm: str(x.basicAuth.realm, 100).replace(/"/g, '') || 'Restricted',
      users: x.basicAuth.users.slice(0, 100).map((u) => ({ user: str(u.user, 64), hash: str(u.hash, 200) })),
    } : null;
    if (ba) ba.users.forEach((u) => { if (!/^[A-Za-z0-9._@-]+$/.test(u.user)) errors.push(`Site "${name}": bad user name "${u.user}"`); if (!/^\$2[aby]?\$\d\d\$[./A-Za-z0-9]{53}$/.test(u.hash)) errors.push(`Site "${name}": user "${u.user}" needs a bcrypt hash ($2y$...), never a plain password`); });
    return {
      name, hosts,
      http: { port: port(x.http && x.http.port, 80) },
      https: tlsOn ? { port: port(x.https && x.https.port, 443) } : null,
      tls: { mode, cert: str(t.cert), key: str(t.key), email: str(t.email, 254), redirectHttp: tlsOn && bool(t.redirectHttp, true), hsts: tlsOn && bool(t.hsts, true), minVersion: t.minVersion === '1.3' ? '1.3' : '1.2' },
      routes, defaultPool, redirectTo,
      securityHeaders: bool(x.securityHeaders, true), compression: bool(x.compression, true),
      rateLimit: rl, basicAuth: ba, maxBodyMb: x.maxBodyMb == null || x.maxBodyMb === '' ? null : num(x.maxBodyMb, 10, 0, 100000), websocket: Boolean(x.websocket),
    };
  });
  if (!sites.length) errors.push('Add at least one site');
  if (new Set(sites.map((x) => x.name)).size !== sites.length) errors.push('Site names must be unique');

  const o = s.options || {};
  const sp = o.statusPage || {};
  const options = {
    accessLog: bool(o.accessLog, true), logFormat: o.logFormat === 'json' ? 'json' : 'combined',
    statusPage: { enabled: Boolean(sp.enabled), port: port(sp.port, 8404), allow: (Array.isArray(sp.allow) ? sp.allow : ['127.0.0.1']).map((a) => str(a, 64)).filter((a) => /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(a)) },
    // Apache only: where the files go. debian = apache2 (sites-available, a2enmod), rhel = httpd (conf.d), standalone = one httpd.conf
    layout: ['debian', 'rhel', 'standalone'].includes(o.layout) ? o.layout : o.layout === 'upstream' ? 'standalone' : 'debian',
    clientTimeout: num(o.clientTimeout, 60, 1, 86400), maxConnections: num(o.maxConnections, 10000, 1, 10000000), workers: o.workers === undefined || o.workers === 'auto' ? 'auto' : num(o.workers, 1, 1, 1024),
  };
  if (errors.length) throw new SpecError([...new Set(errors)]);
  return { version: s.version ? str(s.version, 32) : null, sites, pools, options };
}

/** A small, complete example spec (also used by tests and as the builder's starting point). */
const EXAMPLE_SPEC = {
  sites: [{
    name: 'shop', hosts: ['shop.example.com', 'www.shop.example.com'],
    tls: { mode: 'files', cert: '/etc/ssl/shop/fullchain.pem', key: '/etc/ssl/shop/privkey.pem' },
    routes: [{ path: '/api/', pool: 'api', stripPrefix: true }, { path: '/static/', pool: 'static' }],
    defaultPool: 'web', rateLimit: { rps: 20, burst: 40 }, maxBodyMb: 10,
  }],
  pools: [
    { name: 'web', balance: 'leastconn', servers: [{ address: '10.0.0.11:8080' }, { address: '10.0.0.12:8080' }], healthCheck: { path: '/healthz' }, sticky: true },
    { name: 'api', servers: [{ address: '10.0.1.21:9000' }, { address: '10.0.1.22:9000' }, { address: '10.0.1.23:9000', backup: true }], healthCheck: { path: '/health' } },
    { name: 'static', servers: [{ address: '10.0.2.31:80' }], healthCheck: null },
  ],
  options: { statusPage: { enabled: true, port: 8404, allow: ['127.0.0.1', '10.0.0.0/8'] } },
};

module.exports = { normalizeSpec, SpecError, EXAMPLE_SPEC, BALANCE };

'use strict';
/** Specs the verifier builds for every product and version: they exercise every Config Builder feature between them. */
const { EXAMPLE_SPEC } = require('../../src/build/spec');

const HASH = `$2y$10$${'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0'.slice(0, 53)}`;

module.exports = {
  example: EXAMPLE_SPEC,
  acme: {
    sites: [{ name: 'app', hosts: ['app.example.com'], tls: { mode: 'acme', email: 'ops@example.com' }, defaultPool: 'app', compression: true }],
    pools: [{ name: 'app', servers: ['10.0.0.5:8080', '10.0.0.6:8080'], healthCheck: { path: '/health' } }],
  },
  plain: {
    sites: [
      { name: 'catchall', hosts: [], tls: { mode: 'none' }, routes: [{ path: '/old/', pool: 'web', rewriteTo: '/new/' }, { path: '/exact', match: 'exact', pool: 'web' }], defaultPool: 'web', securityHeaders: false, compression: false },
      { name: 'moved', hosts: ['old.example.com'], tls: { mode: 'none' }, redirectTo: 'https://new.example.com/' },
    ],
    pools: [{ name: 'web', servers: ['10.0.1.1:80'], healthCheck: null }],
  },
  secure: {
    sites: [{
      name: 'portal', hosts: ['portal.example.com'], tls: { mode: 'files', cert: '/etc/ssl/portal/fullchain.pem', key: '/etc/ssl/portal/privkey.pem', minVersion: '1.3' },
      routes: [{ path: '/ws/', pool: 'realtime' }, { path: '/api/', pool: 'api', stripPrefix: true }], defaultPool: 'api',
      websocket: true, rateLimit: { rps: 10, burst: 20 }, maxBodyMb: 25, basicAuth: { realm: 'Portal', users: [{ user: 'admin', hash: HASH }] },
    }],
    pools: [
      { name: 'api', scheme: 'https', verifyTls: true, servers: ['10.0.2.1:8443', '10.0.2.2:8443'], healthCheck: { path: '/ready', interval: 10 } },
      { name: 'realtime', servers: ['10.0.3.1:9000'], healthCheck: null, timeouts: { connect: 3, server: 3600 } },
    ],
    options: { logFormat: 'json' },
  },
  balancing: {
    sites: [{ name: 'shop', hosts: ['*.shop.example.com', 'shop.example.com'], http: { port: 8080 }, tls: { mode: 'files', cert: '/etc/ssl/shop/fullchain.pem', key: '/etc/ssl/shop/privkey.pem' },
      routes: [{ path: '/a/', pool: 'hash' }, { path: '/b/', pool: 'rand' }, { path: '/c/', pool: 'least' }], defaultPool: 'least' }],
    pools: [
      { name: 'hash', balance: 'iphash', servers: [{ address: '10.0.4.1:80' }, { address: '10.0.4.2:80' }] },
      { name: 'rand', balance: 'random', servers: [{ address: '10.0.5.1:80', weight: 3 }, { address: '10.0.5.2:80', weight: 1 }] },
      { name: 'least', balance: 'leastconn', sticky: true, servers: [{ address: '10.0.6.1:80' }, { address: '10.0.6.2:80', backup: true }], healthCheck: { path: '/' } },
    ],
    options: { statusPage: { enabled: true, port: 8404, allow: ['127.0.0.1'] } },
  },
};

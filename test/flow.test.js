'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseConfig } = require('../src/haproxyConfig');
const { parseNginxFiles } = require('../src/nginxConfig');
const { buildFlows, trace, parseServerAddress, resolvePort } = require('../src/flow');

const HAP = [
  'global', 'defaults', '  mode http',
  'frontend web', '  bind :80', '  bind :443 ssl crt /x.pem', '  bind :8080',
  '  acl api path_beg /api/', '  acl host_a hdr(host) -i a.example.com', '  acl old path_beg /old',
  '  http-request redirect scheme https unless { ssl_fc }',
  '  http-request replace-path ^/api/(.*) /\\1 if api',
  '  use_backend api_pool if host_a api', '  use_backend api_v2 if host_a api', '  use_backend legacy if old',
  '  use_backend everything', '  use_backend never_pool if old',
  '  default_backend app',
  'backend api_pool', '  http-request set-path /v1%[path] if { path_beg /x }', '  server a1 10.0.0.1:9000 check port 9100', '  server a2 10.0.0.2:9000 check',
  'backend api_v2', '  server b1 10.0.0.3:9001',
  'backend legacy', '  server l1 10.0.0.4 check', '  server l2 10.0.0.5:+1000 ssl verify none', '  server l3 127.0.0.1:443',
  'backend everything', '  server e1 ${APP_HOST}:${APP_PORT}', '  server e2 unix@/run/app.sock',
  'backend app', '  server-template web 1-3 app.local:8000 check', '  server w1 10.0.0.9:80 ssl', '  server w2 10.0.0.9 port 81',
].join('\n');

test('server address: explicit port, omitted port follows the listener, +N/-N offsets, env and sockets', () => {
  assert.equal(resolvePort(parseServerAddress('10.0.0.1:8080'), 443), 8080);
  assert.equal(resolvePort(parseServerAddress('10.0.0.1'), 443), 443);
  assert.equal(resolvePort(parseServerAddress('10.0.0.1:+1000'), 8080), 9080);
  assert.equal(resolvePort(parseServerAddress('10.0.0.1:-80'), 443), 363);
  assert.equal(resolvePort(parseServerAddress('[::1]:9000'), 80), 9000);
  assert.equal(parseServerAddress('${H}:${P}').mode, 'env');
  assert.equal(resolvePort(parseServerAddress('${H}:${P}'), 80), null);
  assert.equal(parseServerAddress('unix@/run/a.sock').kind, 'socket');
  assert.equal(parseServerAddress('0.0.0.0').transparent, true);
});

test('HAProxy flows: listener port -> member port, TLS termination, rewrite chain and example', () => {
  const r = buildFlows('haproxy', parseConfig(HAP));
  const api = r.flows.find((f) => f.pool.name === 'api_pool');
  assert.deepEqual(api.ports.sort(), ['443', '80', '8080']);
  assert.deepEqual(api.portMap.find((p) => p.in === '443').out, [9000]);
  assert.equal(api.portMap.find((p) => p.in === '443').tls, 'terminate');
  assert.ok(api.chain.some((s) => s.action === 'replace-path' && s.stage === 'frontend'));
  assert.ok(api.chain.some((s) => s.action === 'set-path' && s.stage === 'backend'));
  const legacy = r.flows.find((f) => f.pool.name === 'legacy');
  // an omitted port follows the listener; +1000 is added to it
  assert.deepEqual(legacy.portMap.find((p) => p.in === '8080').out.sort((a, b) => a - b), [443, 8080, 9080]); // l3 explicit :443, l1 follows the listener, l2 is listener+1000
  assert.deepEqual(r.portMatrix.filter((x) => x.pool === 'legacy').map((x) => x.listener), ['80', '443', '8080']);
});

test('HAProxy findings: shadowed rule, check port differs, TLS to :80, self loop, env port', () => {
  const r = buildFlows('haproxy', parseConfig(HAP));
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('flow-shadowed-rule'));
  const shadowed = r.findings.filter((f) => f.id === 'flow-shadowed-rule').map((f) => f.title).join('|');
  assert.match(shadowed, /api_v2/); // same condition as the rule above it
  assert.match(shadowed, /never_pool/); // after an unconditional use_backend
  assert.ok(r.findings.some((f) => f.id === 'flow-check-port-differs' && /a1/.test(f.title)));
  assert.ok(r.findings.some((f) => f.id === 'flow-tls-to-plain-port' && /w1/.test(f.title)));
  assert.ok(r.findings.some((f) => f.id === 'flow-check-port-ignored' && /w2/.test(f.title)));
  assert.ok(r.findings.some((f) => f.id === 'flow-self-loop' && /l3/.test(f.title)));
  assert.ok(r.findings.some((f) => f.id === 'flow-env-port'));
  assert.ok(!r.findings.some((f) => f.id === 'flow-check-port-differs' && /a2/.test(f.title)));
});

test('HAProxy trace: redirect, first-match rule, rewrite and member ports', () => {
  const s = parseConfig(HAP);
  const plain = trace('haproxy', s, { host: 'a.example.com', path: '/api/users?x=1', port: 80, tls: false });
  assert.equal(plain.response.status, 301); // http -> https redirect fires before backend selection
  const t = trace('haproxy', s, { host: 'a.example.com', path: '/api/users', port: 443, tls: true });
  assert.equal(t.backend, 'api_pool');
  assert.equal(t.rule, 1);
  assert.equal(t.path.out, '/users');
  assert.deepEqual(t.members.map((m) => m.port), [9000, 9000]);
  const other = trace('haproxy', s, { host: 'b.example.com', path: '/api/users', port: 443, tls: true });
  assert.equal(other.backend, 'everything'); // host ACL fails, the unconditional rule is next
  assert.equal(other.path.out, '/users'); // the frontend rewrite only needs the path
  const none = trace('haproxy', s, { host: 'x', path: '/', port: 9999 });
  assert.equal(none.ok, false);
});

test('HAProxy trace: no match and no default is a 503', () => {
  const s = parseConfig(['frontend f', ' bind :80', ' acl a path_beg /a', ' use_backend b if a', 'backend b', ' server s 10.0.0.1:80'].join('\n'));
  const t = trace('haproxy', s, { path: '/zzz', port: 80, tls: false });
  assert.equal(t.response.status, 503);
});

const NGX = [
  'events {}', 'http {',
  ' upstream api_pool { server 10.0.0.1:9000; server 10.0.0.2:9000 backup; }',
  ' upstream tls_pool { server 10.0.1.1:8443; }',
  ' server { listen 443 ssl http2; listen 80; server_name a.example.com *.example.org;',
  '  location /api/ { proxy_pass http://api_pool/v1/; }',
  '  location /slash/ { proxy_pass http://api_pool/v1; }',
  '  location /rw/ { rewrite ^/rw/(.*) /new/$1 break; proxy_pass http://api_pool/ignored/; }',
  '  location ^~ /static/ { proxy_pass http://api_pool; }',
  '  location ~ ^/static/.*\\.png$ { proxy_pass http://api_pool; }',
  '  location = /health { return 204; }',
  '  location /secure/ { proxy_pass https://tls_pool; }',
  ' }',
  ' server { listen 80 default_server; server_name _; location / { return 404; } }',
  '}',
].join('\n');
const ngx = () => parseNginxFiles([{ name: 'nginx.conf', content: NGX }]).sections;

test('NGINX flows: ports, TLS, URI prefix replacement and findings', () => {
  const r = buildFlows('nginx', ngx());
  const api = r.flows.find((f) => f.match.path === '/api/');
  assert.deepEqual(api.portMap.map((p) => `${p.in}>${p.out}:${p.tls}`).sort(), ['443>9000:terminate', '80>9000:plain']);
  assert.deepEqual(api.example, { in: '/api/example', out: '/v1/example', exact: true, changed: true });
  const secure = r.flows.find((f) => f.match.path === '/secure/');
  assert.equal(secure.portMap.find((p) => p.in === '443').tls, 're-encrypt');
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('flow-nginx-slash-mismatch'));
  assert.ok(r.findings.some((f) => f.id === 'flow-nginx-slash-mismatch' && /\/slash\//.test(f.title)));
  assert.ok(!r.findings.some((f) => f.id === 'flow-nginx-slash-mismatch' && /\/api\//.test(f.title)));
  assert.ok(ids.includes('flow-nginx-break-ignores-uri'));
  assert.ok(ids.includes('flow-nginx-regex-blocked'));
});

test('NGINX trace: server by name, location precedence, prefix replacement, break and return', () => {
  const s = ngx();
  const a = trace('nginx', s, { host: 'a.example.com', path: '/api/users', port: 443, tls: true });
  assert.equal(a.backend, 'api_pool');
  assert.equal(a.path.out, '/v1/users');
  assert.deepEqual(a.members.map((m) => m.port), [9000, 9000]);
  const slash = trace('nginx', s, { host: 'a.example.com', path: '/slash/x', port: 80 });
  assert.equal(slash.path.out, '/v1x'); // the classic trailing-slash bug, reproduced
  const rw = trace('nginx', s, { host: 'a.example.com', path: '/rw/foo', port: 80 });
  assert.equal(rw.path.out, '/new/foo'); // `break`: proxy_pass URI ignored
  const png = trace('nginx', s, { host: 'a.example.com', path: '/static/a.png', port: 80 });
  assert.match(png.steps.find((x) => x.type === 'rule').text, /\^~ \/static\//); // ^~ stops the regex
  const hp = trace('nginx', s, { host: 'a.example.com', path: '/health', port: 80 });
  assert.equal(hp.local, true);
  assert.equal(hp.response.status, 204);
  const wild = trace('nginx', s, { host: 'x.example.org', path: '/api/a', port: 80 });
  assert.equal(wild.frontend.startsWith('a.example.com'), true);
  const dflt = trace('nginx', s, { host: 'unknown.test', path: '/zzz', port: 80 });
  assert.equal(dflt.response.status, 404); // default_server
  assert.equal(trace('nginx', s, { host: 'a.example.com', path: '/secure/x', port: 443, tls: true }).tls, 're-encrypt');
});

// ------------------------------------------------------------------------------------------------ API
const { startApp, get, post } = require('./helpers');

test('API: /flow analyses an uploaded config and optionally traces a request', async () => {
  const t = await startApp({});
  try {
    const r = await post(t.base, '/api/flow', { config: HAP, request: { host: 'a.example.com', path: '/api/u', port: 443, tls: true } });
    assert.equal(r.status, 200);
    assert.equal(r.json.product, 'haproxy');
    assert.ok(r.json.flows.length >= 6 && r.json.portMatrix.length);
    assert.equal(r.json.trace.backend, 'api_pool');
    const n = await post(t.base, '/api/flow', { type: 'nginx', files: [{ name: 'nginx.conf', content: NGX }] });
    assert.equal(n.status, 200);
    assert.ok(n.json.findings.some((f) => f.id === 'flow-nginx-slash-mismatch'));
    assert.equal((await post(t.base, '/api/flow', {})).status, 400);
    assert.equal((await post(t.base, '/api/flow', { type: 'apache', config: 'x' })).status, 400);
  } finally { await t.close(); }
});

test('API: /instances/:id/flow and /flow/trace use the instance config', async () => {
  const t = await startApp({ DEMO_MODE: 'true' });
  try {
    for (const p of t.registry.pollers.values()) await p.poll();
    const f = await get(t.base, '/api/instances/demo-haproxy/flow');
    assert.equal(f.status, 200);
    assert.ok(f.json.flows.some((x) => x.pool.name === 'api_pool'));
    const tr = await post(t.base, '/api/instances/demo-haproxy/flow/trace', { host: 'shop.example.com', path: '/api/health', port: 443, tls: true });
    assert.equal(tr.status, 200);
    assert.equal(tr.json.backend, 'api_pool');
    assert.equal((await get(t.base, '/api/instances/nope/flow')).status, 404);
  } finally { await t.close(); }
});

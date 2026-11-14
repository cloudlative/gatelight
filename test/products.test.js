'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const products = require('../src/products');
const { normalizeSpec, EXAMPLE_SPEC, SpecError } = require('../src/build/spec');
const { buildFlows, trace } = require('../src/flow');
const { startApp, post, get } = require('./helpers');

test('registry: HAProxy and NGINX are always available and describe themselves', () => {
  const d = products.describe();
  for (const t of ['haproxy', 'nginx']) {
    const p = d.find((x) => x.type === t);
    assert.ok(p, t);
    assert.ok(p.versions && p.versions.latest, `${t} has a documented latest version`);
    assert.equal(p.can.validate, true);
  }
  assert.equal(products.get('nope'), null);
  assert.equal(products.nameOf('traefik'), 'Traefik');
});

test('spec: defaults, ordering and clear errors', () => {
  const s = normalizeSpec(EXAMPLE_SPEC);
  assert.equal(s.sites[0].https.port, 443);
  assert.deepEqual(s.sites[0].routes.map((r) => r.path), ['/static/', '/api/'], 'longest prefix first');
  assert.equal(s.pools[0].healthCheck.interval, 5);
  assert.throws(() => normalizeSpec({ sites: [{ name: 'a b', routes: [{ path: 'x', pool: 'none' }] }], pools: [] }), (e) => {
    assert.ok(e instanceof SpecError);
    assert.ok(e.errors.some((m) => /must start with \//.test(m)));
    assert.ok(e.errors.some((m) => /unknown pool/.test(m)));
    return true;
  });
  assert.throws(() => normalizeSpec({ sites: [{ name: 's', defaultPool: 'p', basicAuth: { users: [{ user: 'u', hash: 'plain' }] } }], pools: [{ name: 'p', servers: ['10.0.0.1:80'] }] }), /bcrypt/);
  assert.throws(() => normalizeSpec({ sites: [{ name: 's', defaultPool: 'p', tls: { mode: 'acme' } }], pools: [{ name: 'p', servers: ['10.0.0.1:80'] }] }), /at least one host name/);
  const exact = normalizeSpec({ sites: [{ name: 's', routes: [{ path: '/a/b/c/', pool: 'p' }, { path: '/x', match: 'exact', pool: 'p' }] }], pools: [{ name: 'p', servers: ['h:1'] }] });
  assert.equal(exact.sites[0].routes[0].match, 'exact', 'exact matches come first');
});

// A hand-built model in the shared shape (src/products/CONTRACT.md): what the Apache / Caddy / Traefik modules emit.
const MODEL = [
  { type: 'frontend', name: 'websecure', mode: 'http', serverNames: ['shop.example.com'], binds: [{ address: ':443', addresses: [':443'], port: '443', ssl: true, options: {} }], routes: [
    { target: 'api', type: 'conditional', match: 'path begins with /api', matchers: [{ field: 'Host', op: 'is', values: ['shop.example.com'] }, { field: 'Path', op: 'begins with', values: ['/api/'] }], hosts: ['shop.example.com'], transforms: [{ action: 'strip-prefix', args: ['/api'], text: 'strip /api' }], line: 3 },
    { target: 'v2', type: 'conditional', match: 'path begins with /old', matchers: [{ field: 'Path', op: 'glob', values: ['/old/*'] }], transforms: [{ action: 'replace-path-regex', args: ['^/old/(.*)', '/v2/${1}'], text: 'rewrite' }], line: 4 },
    { target: 'redirect', type: 'conditional', terminal: true, match: 'path is /home', matchers: [{ field: 'Path', op: 'is', values: ['/home'] }], transforms: [{ action: 'redirect', args: ['301', 'https://shop.example.com/'], text: 'redir / 301' }], line: 5 },
    { target: 'web', type: 'default', match: '', matchers: [], transforms: [], line: 6 },
    { target: 'web', type: 'conditional', match: 'path begins with /never', matchers: [{ field: 'Path', op: 'begins with', values: ['/never'] }], transforms: [], line: 7 },
  ] },
  { type: 'backend', name: 'api', mode: 'http', servers: [{ name: 'a1', address: 'http://10.0.1.1:9000', check: true }, { name: 'a2', address: 'https://10.0.1.2' }] },
  { type: 'backend', name: 'v2', mode: 'http', servers: [{ name: 'v', address: '10.0.2.1:8080' }] },
  { type: 'backend', name: 'web', mode: 'http', servers: [{ name: 'w', address: 'http://127.0.0.1:443' }] },
];

test('generic routing engine: flows, rewrites, shadowing, ports and loops', () => {
  const r = buildFlows('traefik', MODEL);
  assert.equal(r.flows.length, 5);
  const api = r.flows[0];
  assert.deepEqual(api.example, { in: '/api/example', out: '/example', exact: true, changed: true });
  assert.deepEqual(api.portMap[0].targets.sort(), ['10.0.1.1:9000', '10.0.1.2:443']);
  assert.equal(r.flows[1].example.out, '/v2/example', 'Go-style ${1} replacement');
  assert.equal(r.flows[2].pool.terminal, true);
  assert.ok(r.findings.some((f) => f.id === 'flow-shadowed-rule' && /#5/.test(f.title)), 'a rule after the catch-all can never match');
  assert.ok(r.findings.some((f) => f.id === 'flow-self-loop'), 'web points at our own :443');
});

test('generic tracer: picks the listener, the first matching rule and rewrites the path', () => {
  const a = trace('caddy', MODEL, { host: 'shop.example.com', path: '/api/users', port: 443, tls: true });
  assert.equal(a.ok, true); assert.equal(a.backend, 'api'); assert.equal(a.path.out, '/users');
  assert.deepEqual(a.members.map((m) => m.port), [9000, 443]);
  const red = trace('caddy', MODEL, { host: 'shop.example.com', path: '/home', port: 443, tls: true });
  assert.match(red.response.text, /Redirect|Answered/);
  const any = trace('caddy', MODEL, { host: 'shop.example.com', path: '/anything', port: 443, tls: true });
  assert.equal(any.backend, 'web');
  const none = trace('caddy', MODEL, { host: 'x', path: '/', port: 8080, tls: false });
  assert.equal(none.ok, false);
});

test('API: products in /api/meta, Config Builder errors and HAProxy/NGINX builds', async () => {
  const t = await startApp({ DEMO_MODE: 'true' });
  try {
    const meta = (await get(t.base, '/api/meta')).json;
    assert.ok(meta.products.some((p) => p.type === 'haproxy'));
    const ex = (await get(t.base, '/api/build/example')).json;
    assert.ok(ex.spec.sites.length);
    const bad = await post(t.base, '/api/build', { product: 'nginx', spec: { sites: [] } });
    assert.equal(bad.status, 400); assert.ok(bad.json.errors.includes('Add at least one site'));
    assert.equal((await post(t.base, '/api/build', { product: 'nope', spec: EXAMPLE_SPEC })).status, 400);
    for (const product of ['haproxy', 'nginx']) {
      if (!products.has(product, 'build')) continue; // generator not installed in this checkout
      const r = await post(t.base, '/api/build', { product, spec: EXAMPLE_SPEC });
      assert.equal(r.status, 200, JSON.stringify(r.json).slice(0, 300));
      assert.ok(r.json.files[0].content.length > 100);
      assert.equal(r.json.validation.summary.error, 0, `${product}: ${JSON.stringify(r.json.validation.findings.filter((f) => f.severity === 'error')).slice(0, 400)}`);
      assert.ok(r.json.model.backends.length >= 3);
    }
  } finally { await t.close(); }
});

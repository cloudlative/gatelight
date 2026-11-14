'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startApp, get, post } = require('./helpers');

const EX = path.join(__dirname, '..', 'examples');
const emptyInstances = () => { const f = path.join(fs.mkdtempSync(path.join(require('os').tmpdir(), 'nx-')), 'i.json'); fs.writeFileSync(f, '[]'); return { INSTANCES_FILE: f }; };

async function demo(env = {}) {
  const ctx = await startApp({ DEMO_MODE: 'true', ...env });
  for (const p of ctx.registry.pollers.values()) await p.poll();
  return ctx;
}

test('demo mode serves both technologies with type-specific labels', async () => {
  const t = await demo();
  try {
    const { json } = await get(t.base, '/api/instances');
    const types = json.instances.map((i) => i.type);
    for (const t of ['haproxy', 'nginx']) assert.ok(types.includes(t), t);
    assert.ok(types.every((t) => ['haproxy', 'nginx', 'apache', 'caddy', 'traefik'].includes(t)));
    const ng = (await get(t.base, '/api/instances/demo-nginx/snapshot')).json;
    assert.equal(ng.instance.labels.backend, 'Upstream');
    assert.ok(ng.rows.length > 5 && ng.findings.length > 0);
    const hp = (await get(t.base, '/api/instances/demo-haproxy/snapshot')).json;
    assert.equal(hp.instance.labels.backend, 'Backend');
    assert.equal((await get(t.base, '/api/instances/nope/snapshot')).status, 404);
  } finally { await t.close(); }
});

test('feature switches: either technology can be disabled', async () => {
  const others = { ENABLE_APACHE: 'false', ENABLE_CADDY: 'false', ENABLE_TRAEFIK: 'false' };
  const off = await demo({ ENABLE_NGINX: 'false', ...others });
  try {
    assert.deepEqual((await get(off.base, '/api/instances')).json.instances.map((i) => i.type), ['haproxy']);
    assert.equal((await get(off.base, '/api/meta')).json.features.nginx, false);
    const r = await post(off.base, '/api/analyze', { type: 'nginx', config: 'http { }' });
    assert.equal(r.status, 400); assert.match(r.json.error, /disabled/);
  } finally { await off.close(); }
  const onlyNginx = await demo({ ENABLE_HAPROXY: 'false', ...others });
  try { assert.deepEqual((await get(onlyNginx.base, '/api/instances')).json.instances.map((i) => i.type), ['nginx']); } finally { await onlyNginx.close(); }
});

test('authentication: basic + bearer, healthz open, wrong creds rejected', async () => {
  const t = await demo({ AUTH_USER: 'ops', AUTH_PASS: 'pw', AUTH_TOKEN: 'tok' });
  try {
    assert.equal((await get(t.base, '/api/instances')).status, 401);
    assert.equal((await get(t.base, '/healthz')).status, 200);
    assert.equal((await get(t.base, '/api/instances', { Authorization: `Basic ${Buffer.from('ops:wrong').toString('base64')}` })).status, 401);
    assert.equal((await get(t.base, '/api/instances', { Authorization: `Basic ${Buffer.from('ops:pw').toString('base64')}` })).status, 200);
    assert.equal((await get(t.base, '/metrics', { Authorization: 'Bearer tok' })).status, 200);
    assert.equal((await get(t.base, '/metrics', { Authorization: 'Bearer nope' })).status, 401);
    assert.equal((await get(t.base, '/')).status, 401);
  } finally { await t.close(); }
});

test('static serving is an allowlist: source/config files are never exposed', async () => {
  const t = await demo();
  try {
    for (const p of ['/server.js', '/package.json', '/src/app.js', '/config/haproxy.cfg', '/examples/haproxy/haproxy.cfg', '/../server.js', '/.env', '/docker-compose.yml']) {
      const r = await get(t.base, p);
      assert.equal(r.status, 404, `${p} should be 404, got ${r.status}`);
    }
    assert.equal((await get(t.base, '/vendor/vis-network.min.js')).status, 200);
    const idx = await get(t.base, '/');
    assert.match(idx.headers.get('content-security-policy'), /default-src 'self'/);
    assert.equal(idx.headers.get('x-content-type-options'), 'nosniff');
  } finally { await t.close(); }
});

test('no endpoint fetches client-supplied URLs (no SSRF surface)', async () => {
  const t = await demo();
  try {
    const r = await post(t.base, '/api/live-sync', { statsUrl: 'http://169.254.169.254/' });
    assert.equal(r.status, 404);
    const a = await post(t.base, '/api/analyze', { config: 'frontend f\n bind :80\n', statsUrl: 'http://169.254.169.254/' });
    assert.equal(a.status, 200);
  } finally { await t.close(); }
});

test('snapshots never contain credentials; config output is redacted', async () => {
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'nx-'));
  const cfg = path.join(dir, 'haproxy.cfg');
  fs.writeFileSync(cfg, 'listen stats\n bind :8404\n stats enable\n stats auth admin:SuperSecret123\nuserlist u\n user a insecure-password TopSecretPw\n');
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'x', type: 'haproxy', statsUrl: 'http://127.0.0.1:9/stats', username: 'viewer', password: 'StatsPw999', configPath: cfg }]));
  const t = await startApp({ INSTANCES_FILE: inst });
  try {
    await t.registry.get('x').poll();
    const all = JSON.stringify([(await get(t.base, '/api/instances/x/snapshot')).json, (await get(t.base, '/api/instances')).json, (await get(t.base, '/api/meta')).json]);
    for (const secret of ['SuperSecret123', 'TopSecretPw', 'StatsPw999']) assert.ok(!all.includes(secret), `${secret} leaked`);
    assert.ok(all.includes('admin:***'));
  } finally { await t.close(); }
});

test('analyze: auto-detects type, accepts multi-file NGINX, validates input', async () => {
  const t = await demo();
  try {
    const rd = (p) => fs.readFileSync(path.join(EX, p), 'utf8');
    const ng = await post(t.base, '/api/analyze', { files: [{ name: 'conf/nginx.conf', content: rd('nginx/nginx.conf') }, { name: 'conf/conf.d/app.conf', content: rd('nginx/conf.d/app.conf') }] });
    assert.equal(ng.json.type, 'nginx');
    assert.ok(ng.json.findings.some((f) => f.id === 'nginx-undefined-upstream' && f.file === 'conf.d/app.conf'));
    const hp = await post(t.base, '/api/analyze', { config: rd('haproxy/haproxy.cfg') });
    assert.equal(hp.json.type, 'haproxy');
    const withStats = await post(t.base, '/api/analyze', { files: [{ name: 'haproxy.cfg', content: rd('haproxy/haproxy.cfg') }, { name: 'stat.csv', content: '# pxname,svname,status,type\nwebapp,FRONTEND,OPEN,0\n' }] });
    assert.ok(withStats.json.rows.length === 1);
    assert.equal((await post(t.base, '/api/analyze', {})).status, 400);
    assert.equal((await post(t.base, '/api/analyze', { config: 'x', type: 'apache' })).status, 400);
    const big = await fetch(`${t.base}/api/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: 'x'.repeat(9 * 1024 * 1024) }) });
    assert.equal(big.status, 413);
    const bad = await fetch(`${t.base}/api/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{nope' });
    assert.equal(bad.status, 400);
  } finally { await t.close(); }
});

test('examples endpoint is an allowlist', async () => {
  const t = await demo();
  try {
    assert.ok((await get(t.base, '/api/examples/nginx')).json.files.length >= 3);
    assert.equal((await get(t.base, '/api/examples/..')).status, 404);
    assert.equal((await get(t.base, '/api/examples/etc')).status, 404);
  } finally { await t.close(); }
});

test('prometheus metrics expose health, traffic and audit counters with type label', async () => {
  const t = await demo();
  try {
    const m = (await get(t.base, '/metrics')).text;
    assert.match(m, /gatelight_instance_up\{instance="demo-nginx"\} 1/);
    assert.match(m, /gatelight_server_up\{instance="demo-nginx",type="nginx"/);
    assert.match(m, /gatelight_config_findings\{instance="demo-haproxy",severity="warning"\} [1-9]\d*/);
  } finally { await t.close(); }
});

test('a config file placed on disk is no longer auto-discovered (configs come from the UI)', async () => {
  const t = await startApp({ ...emptyInstances() }); // config/haproxy.cfg may exist in a dev checkout: it must be ignored
  try { assert.equal(t.registry.list().length, 0); } finally { await t.close(); }
});

test('history-all returns instance samples and per-entity history including session rate, sessions and servers', async () => {
  const t = await demo();
  try {
    const p = t.registry.get('demo-haproxy');
    await p.poll(); await new Promise((r) => setTimeout(r, 30)); await p.poll(); await new Promise((r) => setTimeout(r, 30)); await p.poll();
    const h = (await get(t.base, '/api/instances/demo-haproxy/history-all?points=50')).json;
    assert.ok(h.summary.length >= 2, 'instance-level samples');
    const s = h.summary[h.summary.length - 1];
    for (const k of ['rate', 'srate', 'scur', 'e5xx', 'inBps', 'outBps', 'up', 'down', 'degraded', 'total', 'rtime']) assert.ok(k in s, `summary has ${k}`);
    assert.ok(s.total > 0 && s.up + s.down + s.degraded <= s.total);
    const kinds = new Set(h.entities.map((e) => e.kind)); assert.ok(kinds.has('server') && kinds.has('backend') && kinds.has('frontend'));
    const sv = h.entities.find((e) => e.kind === 'server');
    assert.ok(sv.points.length >= 2 && 'srate' in sv.points[0] && 'inBps' in sv.points[0]);
    const only = (await get(t.base, '/api/instances/demo-haproxy/history-all?kinds=server')).json;
    assert.ok(only.entities.every((e) => e.kind === 'server'));
  } finally { await t.close(); }
});

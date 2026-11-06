'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startApp, startStub, get: rawGet, post: rawPost } = require('./helpers');
const { DemoSource } = require('../src/demo');
const { parseConfig } = require('../src/haproxyConfig');

const sections = parseConfig(fs.readFileSync(path.join(__dirname, '..', 'examples', 'haproxy', 'haproxy.cfg'), 'utf8'));
const csv = () => new DemoSource([], () => sections).fetch().csv;
const dataDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nx-data-'));
const emptyInstances = () => { const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'nx-')), 'i.json'); fs.writeFileSync(f, '[]'); return f; };
// Each "browser" is a session cookie; connections are private to the one that added them.
const A = { Cookie: `gl_sid=${'a'.repeat(64)}` }; const B = { Cookie: `gl_sid=${'b'.repeat(64)}` };
const get = (base, p, h) => rawGet(base, p, h || A);
const post = (base, p, body, h) => rawPost(base, p, body, { ...A, ...h });
const send = (base, method, p, body, who = A) => fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...who }, body: body ? JSON.stringify(body) : undefined }).then(async (r) => ({ status: r.status, json: await r.json().catch(() => null) }));

/** A fake HAProxy stats endpoint that insists on basic auth (viewer / s3cret). */
const statsStub = () => startStub((req, res) => {
  const ok = req.headers.authorization === `Basic ${Buffer.from('viewer:s3cret').toString('base64')}`;
  if (!ok) { res.writeHead(401); return res.end(); }
  res.writeHead(200, { 'Content-Type': 'text/csv' });
  return res.end(csv());
});

test('adding instances from the UI is off unless explicitly enabled', async () => {
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DATA_DIR: dataDir() });
  try {
    assert.equal((await get(t.base, '/api/meta')).json.canManage, false);
    const r = await send(t.base, 'POST', '/api/instances', { type: 'haproxy', name: 'x', statsUrl: 'http://127.0.0.1:1/stats' });
    assert.equal(r.status, 403);
  } finally { await t.close(); }
});

test('connect from the UI: test, save, live data, no secret leaks, persists across restart, delete', async () => {
  const stub = await statsStub(); const dir = dataDir(); const env = { INSTANCES_FILE: emptyInstances(), DATA_DIR: dir, ALLOW_UI_INSTANCES: 'true' };
  let t = await startApp(env);
  try {
    const bad = await send(t.base, 'POST', '/api/instances/test', { type: 'haproxy', name: 'lb', statsUrl: `${stub.url}/stats`, username: 'viewer', password: 'wrong' });
    assert.equal(bad.json.ok, false);
    assert.match(bad.json.error, /credentials|401/i);

    const body = { type: 'haproxy', name: 'Edge LB', statsUrl: `${stub.url}/stats`, username: 'viewer', password: 's3cret' };
    const good = await send(t.base, 'POST', '/api/instances/test', body);
    assert.equal(good.json.ok, true);
    assert.ok(good.json.servers > 3 && good.json.backends > 1);

    const created = await send(t.base, 'POST', '/api/instances', body);
    assert.equal(created.status, 201);
    const id = created.json.id; assert.equal(id, 'edge-lb');
    await t.registry.get(id).poll();

    const snap = await get(t.base, `/api/instances/${id}/snapshot`);
    assert.equal(snap.json.ok, true);
    assert.ok(snap.json.rows.length > 5);
    // Nothing the browser can fetch contains the password.
    for (const p of ['/api/instances', `/api/instances/${id}/definition`, `/api/instances/${id}/snapshot`, '/api/meta']) {
      assert.ok(!(await get(t.base, p)).text.includes('s3cret'), `${p} leaked the password`);
    }
    const def = (await get(t.base, `/api/instances/${id}/definition`)).json;
    assert.equal(def.hasPassword, true); assert.equal(def.username, 'viewer'); assert.equal('password' in def, false);

    const file = path.join(dir, 'ui-instances.json');
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    await t.close();

    // Restart: the instance comes back from disk, still authenticating.
    t = await startApp(env);
    assert.ok(t.registry.get(id));
    await t.registry.get(id).poll();
    assert.equal((await get(t.base, `/api/instances/${id}/snapshot`)).json.ok, true);

    // Edit with a blank password keeps it; pointing at another host drops it.
    const keep = await send(t.base, 'PUT', `/api/instances/${id}`, { ...body, password: '', name: 'Edge LB' });
    assert.equal(keep.status, 200);
    await t.registry.get(id).poll();
    assert.equal((await get(t.base, `/api/instances/${id}/snapshot`)).json.ok, true);
    const moved = await send(t.base, 'PUT', `/api/instances/${id}`, { ...body, password: '', statsUrl: 'http://localhost:9/stats' });
    assert.equal((await get(t.base, `/api/instances/${id}/definition`)).json.hasPassword, false);
    assert.equal(moved.status, 200);

    assert.equal((await send(t.base, 'DELETE', `/api/instances/${id}`)).status, 200);
    assert.equal((await get(t.base, '/api/instances')).json.instances.length, 0);
    assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')).instances, []);
  } finally { await t.close(); await stub.close(); }
});

test('UI input is validated: no URL credentials, no unix sockets, no ${VAR} expansion, JSON only', async () => {
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DATA_DIR: dataDir(), ALLOW_UI_INSTANCES: 'true', UI_ALLOWED_HOSTS: 'good.example,*.lb.example', AUTH_TOKEN: 'tok' });
  const H = { Authorization: 'Bearer tok' };
  const tryCreate = async (b) => (await post(t.base, '/api/instances', { type: 'haproxy', name: 'v', ...b }, H));
  try {
    assert.match((await tryCreate({ statsUrl: 'http://u:p@good.example/stats' })).json.error, /credentials/);
    assert.match((await tryCreate({ statsUrl: 'http://evil.example/stats' })).json.error, /UI_ALLOWED_HOSTS/);
    assert.match((await tryCreate({ socket: '/var/run/haproxy.sock' })).json.error, /host:port/);
    assert.match((await tryCreate({ statsUrl: 'ftp://good.example/x' })).json.error, /http/);
    assert.equal((await tryCreate({ name: 'cfg', statsUrl: 'http://good.example/stats', configPath: '/etc/passwd' })).status, 201); // a path from the UI is ignored, never read
    assert.equal(t.registry.get('cfg').instance.configPath, null);
    assert.equal((await tryCreate({})).status, 400);
    // wrong content type (what a cross-site form post would send) is refused
    const form = await fetch(`${t.base}/api/instances`, { method: 'POST', headers: { ...H, 'Content-Type': 'text/plain' }, body: '{}' });
    assert.equal(form.status, 415);
    // env references are never expanded for UI-managed values
    process.env.NX_SECRET_PROBE = 'LEAK';
    const ok = await tryCreate({ name: 'lit', statsUrl: 'http://x.lb.example/stats', username: 'u', password: '${NX_SECRET_PROBE}' });
    assert.equal(ok.status, 201);
    assert.equal(t.registry.get('lit').instance.password, '${NX_SECRET_PROBE}');
    delete process.env.NX_SECRET_PROBE;
  } finally { await t.close(); }
});

test('connections are private to the browser that added them (and shared only when UI_INSTANCES_SHARED=true)', async () => {
  const stub = await statsStub(); const dir = dataDir();
  const env = { INSTANCES_FILE: emptyInstances(), DATA_DIR: dir, ALLOW_UI_INSTANCES: 'true' };
  const t = await startApp(env);
  const body = { type: 'haproxy', name: 'Mine', statsUrl: `${stub.url}/stats`, username: 'viewer', password: 's3cret' };
  try {
    assert.equal((await send(t.base, 'POST', '/api/instances', body, A)).status, 201);
    await t.registry.get('mine').poll();
    assert.ok((await get(t.base, '/api/instances', A)).json.instances.some((i) => i.id === 'mine'));

    // another browser sees nothing and cannot read, edit, test against or delete it
    assert.ok(!(await get(t.base, '/api/instances', B)).json.instances.some((i) => i.id === 'mine'));
    assert.equal((await get(t.base, '/api/instances/mine/snapshot', B)).status, 404);
    assert.equal((await get(t.base, '/api/instances/mine/definition', B)).status, 404);
    assert.equal((await send(t.base, 'PUT', '/api/instances/mine', { ...body, name: 'Hijack' }, B)).status, 404);
    assert.equal((await send(t.base, 'DELETE', '/api/instances/mine', undefined, B)).status, 404);
    // a test that names the instance id must not borrow its stored password
    const borrow = await send(t.base, 'POST', '/api/instances/test', { ...body, id: 'mine', password: '' }, B);
    assert.equal(borrow.json.ok, false);
    // not in the unauthenticated metrics either
    assert.ok(!(await rawGet(t.base, '/metrics', B)).text.includes('mine'));
    assert.equal(t.registry.get('mine').instance.owner.length, 64);
    assert.ok(!fs.readFileSync(path.join(dir, 'ui-instances.json'), 'utf8').includes('gl_sid'), 'raw session secret must not be stored');
  } finally { await t.close(); }

  const shared = await startApp({ ...env, UI_INSTANCES_SHARED: 'true' });
  try { assert.ok((await get(shared.base, '/api/instances', B)).json.instances.some((i) => i.id === 'mine')); } finally { await shared.close(); }
  await stub.close();
});

test('connections saved before ownership existed are assigned to the first browser that opens GateLight', async () => {
  const dir = dataDir();
  fs.writeFileSync(path.join(dir, 'ui-instances.json'), JSON.stringify({ instances: [{ id: 'old', type: 'haproxy', name: 'Old', statsUrl: 'http://127.0.0.1:9/stats' }] }));
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DATA_DIR: dir, ALLOW_UI_INSTANCES: 'true' });
  try {
    assert.equal((await get(t.base, '/api/instances', A)).json.instances.length, 1);
    assert.equal((await get(t.base, '/api/instances', B)).json.instances.length, 0);
  } finally { await t.close(); }
});

test('the pre-rename session cookie (nx_sid) still identifies the same browser', async () => {
  const dir = dataDir();
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DATA_DIR: dir, ALLOW_UI_INSTANCES: 'true' });
  try {
    const body = { type: 'haproxy', name: 'Mine', statsUrl: 'http://127.0.0.1:9/stats', username: 'u', password: 'p' };
    assert.equal((await send(t.base, 'POST', '/api/instances', body, A)).status, 201);
    const legacy = { Cookie: `nx_sid=${'a'.repeat(64)}` };
    const res = await get(t.base, '/api/instances', legacy);
    assert.ok(res.json.instances.some((i) => i.id === 'mine'));
    assert.match(res.headers.get('set-cookie') || '', /gl_sid=a{64}/, 're-issued under the new name with the same value');
  } finally { await t.close(); }
});

const NGINX_FILES = () => ['nginx.conf', 'conf.d/app.conf'].map((n) => ({ name: n, content: fs.readFileSync(path.join(__dirname, '..', 'examples', 'nginx', n), 'utf8') }));

test('upload an NGINX and a HAProxy config as separate, uniquely named instances (no live server needed)', async () => {
  const dir = dataDir(); const env = { INSTANCES_FILE: emptyInstances(), DATA_DIR: dir, ALLOW_UI_INSTANCES: 'true' };
  let t = await startApp(env);
  try {
    const ng = await send(t.base, 'POST', '/api/instances', { type: 'nginx', name: 'Edge web', configFiles: NGINX_FILES() });
    assert.equal(ng.status, 201);
    const hp = await send(t.base, 'POST', '/api/instances', { type: 'haproxy', name: 'Edge LB', configFiles: [{ name: 'haproxy.cfg', content: fs.readFileSync(path.join(__dirname, '..', 'examples', 'haproxy', 'haproxy.cfg'), 'utf8') }] });
    assert.equal(hp.status, 201);
    // names are unique (case-insensitive) within what a browser can see; another browser may reuse them
    assert.equal((await send(t.base, 'POST', '/api/instances', { type: 'haproxy', name: 'edge lb', configFiles: [{ name: 'a.cfg', content: 'frontend x\n bind :80\n' }] })).status, 409);
    assert.equal((await send(t.base, 'POST', '/api/instances', { type: 'haproxy', name: 'edge lb', configFiles: [{ name: 'a.cfg', content: 'frontend x\n bind :80\n' }] }, B)).status, 201);
    for (const id of [ng.json.id, hp.json.id]) await t.registry.get(id).poll();
    const sn = (await get(t.base, `/api/instances/${ng.json.id}/snapshot`)).json;
    assert.equal(sn.instance.source, 'config-only');
    assert.ok(sn.config.sections.some((x) => x.type === 'frontend'), 'nginx server blocks parsed from uploaded files');
    assert.ok(sn.config.files.length >= 2, 'includes resolved from the uploaded set');
    assert.equal(sn.rows.length, 0); // config-only: no TCP probing of hosts named in an uploaded file
    // definition lists file names, never contents
    const def = (await get(t.base, `/api/instances/${ng.json.id}/definition`)).json;
    assert.deepEqual(def.configFiles.sort(), ['conf.d/app.conf', 'nginx.conf'].sort()); assert.equal(def.configOnly, true);
    await t.close();
    // survives a restart, still config-only (probe=false must persist)
    t = await startApp(env);
    await t.registry.get(ng.json.id).poll();
    assert.equal((await get(t.base, `/api/instances/${ng.json.id}/snapshot`)).json.instance.source, 'config-only');
  } finally { await t.close(); }
});

test('uploaded config limits and path hygiene', async () => {
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DATA_DIR: dataDir(), ALLOW_UI_INSTANCES: 'true' });
  try {
    const big = { name: 'x.conf', content: 'a'.repeat(1024 * 1024 + 1) };
    assert.match((await send(t.base, 'POST', '/api/instances', { type: 'nginx', name: 'big', configFiles: [big] })).json.error, /1 MB/);
    assert.match((await send(t.base, 'POST', '/api/instances', { type: 'nginx', name: 'bin', configFiles: [{ name: 'x', content: 'a\u0000b' }] })).json.error, /binary/);
    const r = await send(t.base, 'POST', '/api/instances', { type: 'nginx', name: 'trav', configFiles: [{ name: '../../etc/passwd', content: 'events {}\nhttp { server { listen 80; } }\n' }] });
    assert.equal(r.status, 201);
    assert.equal(t.registry.get('trav').instance.configFiles[0].name, 'etc/passwd'); // only a label; never used as a path
  } finally { await t.close(); }
});

test('re-uploading a config replaces the old one on an existing instance and reports what changed', async () => {
  const dir = dataDir(); const env = { INSTANCES_FILE: emptyInstances(), DATA_DIR: dir, ALLOW_UI_INSTANCES: 'true' };
  const cfg = (extra) => [{ name: 'haproxy.cfg', content: `frontend web\n  bind :80\n  default_backend app\nbackend app\n  server a1 10.0.0.1:80 check\n${extra}` }];
  let t = await startApp(env);
  try {
    const r = await send(t.base, 'POST', '/api/instances', { type: 'haproxy', name: 'Prod', configFiles: cfg('') });
    await t.registry.get(r.json.id).poll();
    const up = await send(t.base, 'PUT', `/api/instances/${r.json.id}/config`, { configFiles: cfg('  server a2 10.0.0.2:80 check\nbackend extra\n  server e1 10.0.0.9:80\n') });
    assert.equal(up.status, 200);
    assert.deepEqual(up.json.added.sort(), ['backend extra', 'server app/a2', 'server extra/e1'].sort());
    assert.deepEqual(up.json.removed, []);
    const snap = (await get(t.base, `/api/instances/${r.json.id}/snapshot`)).json;
    assert.ok(snap.config.sections.some((x) => x.name === 'extra'), 'new config is live without a restart');
    // and shrinking removes the old details
    const down = await send(t.base, 'PUT', `/api/instances/${r.json.id}/config`, { configFiles: cfg('') });
    assert.deepEqual(down.json.removed.sort(), ['backend extra', 'server app/a2', 'server extra/e1'].sort());
    assert.ok(!(await get(t.base, `/api/instances/${r.json.id}/snapshot`)).json.config.sections.some((x) => x.name === 'extra'));
    // wrong technology, empty body and other browsers are refused
    assert.equal((await send(t.base, 'PUT', `/api/instances/${r.json.id}/config`, { configFiles: NGINX_FILES() })).status, 422);
    assert.equal((await send(t.base, 'PUT', `/api/instances/${r.json.id}/config`, {})).status, 400);
    assert.equal((await send(t.base, 'PUT', `/api/instances/${r.json.id}/config`, { configFiles: cfg('') }, B)).status, 404);
    await send(t.base, 'PUT', `/api/instances/${r.json.id}/config`, { configFiles: cfg('backend later\n  server l1 10.0.0.7:80\n') });
    await t.close();
    t = await startApp(env); await t.registry.get(r.json.id).poll();
    assert.ok((await get(t.base, `/api/instances/${r.json.id}/snapshot`)).json.config.sections.some((x) => x.name === 'later'), 'persisted');
  } finally { await t.close(); }
});

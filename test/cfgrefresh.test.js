'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startApp, startStub, get, post } = require('./helpers');
const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'gl-data-'));
const emptyInstances = () => { const f = path.join(tmpDir(), 'i.json'); fs.writeFileSync(f, '[]'); return f; };
const { fetchConfigFiles } = require('../src/transport');
const { validateInput } = require('../src/store');

const A = { Cookie: `gl_sid=${'a'.repeat(64)}` }; // a browser: UI-added connections belong to the one that made them
const HAP1 = 'frontend web\n  bind :80\n  default_backend app\nbackend app\n  server a 10.0.0.1:8080 check\n';
const HAP2 = `${HAP1}  server b 10.0.0.2:8080 check\nbackend extra\n  server c 10.0.0.3:9000\n`;

test('fetch: config URLs are read with GET only, names keep the folder below the shared directory', async () => {
  const files = { '/etc/nginx/nginx.conf': 'events {}\nhttp { include conf.d/*.conf; }\n', '/etc/nginx/conf.d/app.conf': 'server { listen 80; }\n' };
  const stub = await startStub((req, res) => { if (files[req.url.split('?')[0]]) res.end(files[req.url.split('?')[0]]); else { res.statusCode = 404; res.end('no'); } });
  try {
    const got = await fetchConfigFiles({ configUrls: [`${stub.url}/etc/nginx/nginx.conf?token=SECRET`, `${stub.url}/etc/nginx/conf.d/app.conf`], timeoutMs: 3000 });
    assert.deepEqual(got.map((f) => f.name), ['nginx.conf', 'conf.d/app.conf']);
    assert.ok(stub.hits.every((h) => h.method === 'GET'));
    await assert.rejects(fetchConfigFiles({ configUrls: [`${stub.url}/missing.cfg?token=SECRET`], timeoutMs: 3000 }), (e) => /HTTP 404/.test(e.message) && !/SECRET/.test(e.message)); // tokens in the query never reach messages
  } finally { await stub.close(); }
});

test('input: config URLs are validated like the stats URL (http/https, no credentials) and count as a source', () => {
  const ctx = { features: {}, allowedHosts: [] };
  assert.deepEqual(validateInput({ type: 'haproxy', name: 'x', configUrls: 'http://h/a.cfg\n\nhttp://h/a.cfg' }, ctx, null).configUrls, ['http://h/a.cfg']);
  assert.throws(() => validateInput({ type: 'haproxy', name: 'x', configUrls: ['ftp://h/a.cfg'] }, ctx, null), /http/);
  assert.throws(() => validateInput({ type: 'haproxy', name: 'x', configUrls: ['http://u:p@h/a.cfg'] }, ctx, null), /credentials/);
  assert.throws(() => validateInput({ type: 'haproxy', name: 'x', configUrls: ['http://evil/a.cfg'] }, { features: {}, allowedHosts: ['good.example'] }, null), /UI_ALLOWED_HOSTS/);
});

test('API: refresh from server pulls the new config from its URL and reports what changed', async () => {
  let body = HAP1;
  const stub = await startStub((_req, res) => res.end(body));
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DATA_DIR: tmpDir(), ALLOW_UI_INSTANCES: 'true' });
  try {
    const made = await post(t.base, '/api/instances', { type: 'haproxy', name: 'live-cfg', configUrls: [`${stub.url}/haproxy.cfg`] }, A);
    assert.ok([200, 201].includes(made.status), JSON.stringify(made.json));
    const id = made.json.id;
    await t.registry.get(id).poll();
    const first = await get(t.base, `/api/instances/${id}/snapshot`, A); assert.equal(first.status, 200, JSON.stringify(first.json));
    assert.equal(first.json.config.source, 'url');
    assert.deepEqual(first.json.config.sections.filter((s) => s.type === 'backend').map((s) => s.name), ['app']);
    const same = await post(t.base, `/api/instances/${id}/config/refresh`, {}, A);
    assert.equal(same.json.ok, true); assert.equal(same.json.changed, false);
    body = HAP2; // the server's config changed
    const r = await post(t.base, `/api/instances/${id}/config/refresh`, {}, A);
    assert.equal(r.json.changed, true);
    assert.ok(r.json.linesAdded >= 3 && r.json.linesRemoved === 0);
    assert.ok(r.json.added.includes('backend extra') && r.json.added.includes('server app/b'));
    const after = await get(t.base, `/api/instances/${id}/snapshot`, A);
    assert.deepEqual(after.json.config.sections.filter((s) => s.type === 'backend').map((s) => s.name), ['app', 'extra']);
    assert.ok(stub.hits.every((h) => h.method === 'GET')); // read-only
    stub.hits.length = 0; await stub.close(); // server goes away: keep the last good config, report the error
    const down = await post(t.base, `/api/instances/${id}/config/refresh`, {}, A);
    assert.equal(down.json.ok, false);
    assert.equal((await get(t.base, `/api/instances/${id}/snapshot`, A)).json.config.sections.some((s) => s.name === 'extra'), true);
  } finally { await t.close(); try { await stub.close(); } catch { /* already closed */ } }
});

test('API: refresh re-reads a config file on disk immediately; uploaded configs say there is nothing to fetch', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-cfg-'));
  const file = path.join(dir, 'haproxy.cfg'); fs.writeFileSync(file, HAP1);
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify({ instances: [{ id: 'f', type: 'haproxy', name: 'file', configPath: file }] }));
  const t = await startApp({ INSTANCES_FILE: inst, DATA_DIR: tmpDir() });
  try {
    await t.registry.get('f').poll();
    fs.writeFileSync(file, HAP2);
    const r = await post(t.base, '/api/instances/f/config/refresh', {});
    assert.equal(r.json.changed, true); assert.equal(r.json.source, 'file');
    assert.ok(r.json.added.includes('backend extra'));
    assert.equal(fs.readFileSync(file, 'utf8'), HAP2); // never written
  } finally { await t.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

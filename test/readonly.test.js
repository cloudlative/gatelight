'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const net = require('net');
const { httpRequest, runtimeCommand } = require('../src/transport');
const { startStub } = require('./helpers');

test('read-only: HTTP requests to servers must be GET or HEAD and carry no body', async () => {
  const stub = await startStub((_req, res) => res.end('ok'));
  try {
    assert.equal((await httpRequest(`${stub.url}/stats`)).status, 200);
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) await assert.rejects(httpRequest(`${stub.url}/x`, { method }), /read-only/);
    await assert.rejects(httpRequest(`${stub.url}/x`, { body: '{}' }), /read-only/);
    assert.deepEqual(stub.hits.map((h) => h.method), ['GET']); // nothing else reached the server
  } finally { await stub.close(); }
});

test('read-only: the HAProxy Runtime API only ever receives "show stat" and "show info"', async () => {
  const received = [];
  const server = net.createServer((sock) => { sock.on('data', (d) => { received.push(String(d)); sock.end('ok\n'); }); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const target = `127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await runtimeCommand(target, 'show stat')).trim(), 'ok');
    assert.equal((await runtimeCommand(target, 'show info')).trim(), 'ok');
    for (const cmd of ['disable server b/s1', 'set server b/s1 state maint', 'enable server b/s1', 'shutdown sessions server b/s1', 'set weight b/s1 0', 'add server b/s2 1.2.3.4:80', 'del server b/s2',
      'show stat; disable server b/s1', 'show stat\ndisable server b/s1', 'show servers state', 'prepare acl', 'clear counters', '']) {
      await assert.rejects(runtimeCommand(target, cmd), /read-only/, cmd);
    }
    assert.deepEqual(received, ['show stat\n', 'show info\n']);
  } finally { await new Promise((r) => server.close(r)); }
});

test('read-only: the source never writes to configuration files or issues write requests', () => {
  const dir = path.join(__dirname, '..', 'src');
  const files = fs.readdirSync(dir, { recursive: true }).filter((f) => f.endsWith('.js'));
  const writers = /\.(writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rmSync|rm|rename|renameSync|copyFile|copyFileSync|truncate|truncateSync|createWriteStream)\(/;
  // files GateLight may write: its own state only (settings store, sign-in secret, first-run password)
  const own = new Set(['store.js', 'login.js', 'initialAuth.js']);
  for (const f of files) {
    const src = fs.readFileSync(path.join(dir, f), 'utf8');
    if (writers.test(src) && !own.has(path.basename(f))) assert.fail(`${f} writes to the filesystem`);
    if (/child_process|spawn\(|execSync|execFile/.test(src)) assert.fail(`${f} runs external commands`);
    if (/method:\s*['"](POST|PUT|PATCH|DELETE)['"]/.test(src) && path.basename(f) !== 'alerts.js') assert.fail(`${f} sends a write request`);
  }
  const alerts = fs.readFileSync(path.join(dir, 'alerts.js'), 'utf8');
  assert.match(alerts, /notification:\s*true/); // the webhook is the only non-GET caller and says so explicitly
});

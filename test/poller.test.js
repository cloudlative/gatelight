'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startApp, startStub } = require('./helpers');

const csv = (status) => `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,status,type,rate,hrsp_5xx
web,FRONTEND,0,0,1,1,100,10,0,0,OPEN,0,1,0
app,s1,0,0,0,0,10,5,0,0,UP,2,0,0
app,s2,0,0,0,0,10,5,0,0,${status},2,0,0
app,BACKEND,0,0,0,0,10,10,0,0,UP,1,0,0
`;

function setup(statsHandler, extraEnv = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-'));
  const cfg = path.join(dir, 'haproxy.cfg');
  fs.writeFileSync(cfg, 'frontend web\n bind :80\n default_backend app\nbackend app\n server s1 10.0.0.1:80 check\n server s2 10.0.0.2:80 check\n');
  return { dir, cfg, statsHandler, extraEnv };
}

test('server going DOWN then UP produces events and webhook alerts; no alert storm at startup', async () => {
  let state = 'UP';
  const stats = await startStub((req, res) => { res.setHeader('Content-Type', 'text/csv'); res.end(csv(state)); });
  const hook = await startStub((req, res) => { res.statusCode = 200; res.end('ok'); });
  const { dir, cfg } = setup();
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'lb', type: 'haproxy', statsUrl: `${stats.url}/stats`, configPath: cfg }]));
  const t = await startApp({ INSTANCES_FILE: inst, ALERT_WEBHOOK_URL: `${hook.url}/hook`, ALERT_MIN_FAILURES: '1' });
  const p = t.registry.get('lb');
  try {
    await p.poll();                                   // baseline
    assert.deepEqual(p.events.map((e) => e.type), ['monitoring_started'], 'first poll records only the starting point, no transitions');
    assert.equal(hook.hits.length, 0);
    assert.equal(p.snapshot.summary.servers.up, 2);

    state = 'DOWN';
    await p.poll();
    const down = p.events.find((e) => e.type === 'server_state');
    assert.ok(down, 'transition event recorded');
    assert.deepEqual([down.proxy, down.name, down.from, down.to, down.level], ['app', 's2', 'up', 'down', 'warning']);
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(hook.hits.length, 1);
    const body = JSON.parse(hook.hits[0].body);
    assert.match(body.text, /app\/s2/); assert.equal(body.source, 'gatelight');
    assert.equal(p.snapshot.summary.servers.down, 1);

    await p.poll();                                   // still down: no duplicate alert
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(hook.hits.length, 1);

    state = 'UP';
    await p.poll();
    assert.equal(p.events[0].level, 'recovery');
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(hook.hits.length, 2);
  } finally { await t.close(); await stats.close(); await hook.close(); }
});

test('unreachable stats endpoint: alert after N failures, keep stale data, recover', async () => {
  let up = true;
  const stats = await startStub((req, res) => { if (!up) { res.statusCode = 503; return res.end('no'); } return res.end(csv('UP')); });
  const hook = await startStub((req, res) => res.end('ok'));
  const { dir, cfg } = setup();
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'lb', type: 'haproxy', statsUrl: `${stats.url}/stats`, configPath: cfg }]));
  const t = await startApp({ INSTANCES_FILE: inst, ALERT_WEBHOOK_URL: `${hook.url}/h`, ALERT_MIN_FAILURES: '2' });
  const p = t.registry.get('lb');
  try {
    await p.poll();
    up = false;
    await p.poll();
    assert.equal(p.snapshot.ok, false); assert.equal(p.snapshot.stale, true); assert.ok(p.snapshot.rows.length > 0);
    assert.equal(p.events.filter((e) => e.type === 'instance_unreachable').length, 0, 'one failure is below threshold');
    await p.poll();
    assert.equal(p.events.filter((e) => e.type === 'instance_unreachable').length, 1);
    await p.poll();
    assert.equal(p.events.filter((e) => e.type === 'instance_unreachable').length, 1, 'no repeat alerts');
    up = true;
    await p.poll();
    assert.equal(p.snapshot.ok, true);
    assert.equal(p.events[0].type, 'instance_recovered');
  } finally { await t.close(); await stats.close(); await hook.close(); }
});

test('rates and history are derived from counter deltas (reload-safe)', async () => {
  let n = 100;
  const stats = await startStub((req, res) => { n += 50; res.end(`# pxname,svname,scur,stot,status,type,hrsp_5xx\nweb,FRONTEND,1,${n},OPEN,0,0\n`); });
  const { dir, cfg } = setup();
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'lb', type: 'haproxy', statsUrl: `${stats.url}/stats`, configPath: cfg }]));
  const t = await startApp({ INSTANCES_FILE: inst });
  const p = t.registry.get('lb');
  try {
    await p.poll(); await new Promise((r) => setTimeout(r, 120)); await p.poll();
    const fe = p.snapshot.rows.find((r) => r.kind === 'frontend');
    assert.ok(fe.ratePerSec > 100 && fe.ratePerSec < 1000, `rate ${fe.ratePerSec}`);
    n = 5;                                            // counter reset (HAProxy reload)
    await p.poll();
    assert.equal(p.snapshot.rows.find((r) => r.kind === 'frontend').ratePerSec, 0);
    assert.ok(p.getHistory('web/FRONTEND').length >= 3);
  } finally { await t.close(); await stats.close(); }
});

test('nginx: stub_status + TCP probe yields per-peer health and request rate', async () => {
  const net = require('net');
  const alive = net.createServer().listen(0, '127.0.0.1');
  await new Promise((r) => alive.on('listening', r));
  let reqs = 1000;
  const stub = await startStub((req, res) => { reqs += 100; res.end(`Active connections: 7 \nserver accepts handled requests\n 5 5 ${reqs} \nReading: 0 Writing: 1 Waiting: 6 \n`); });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-'));
  fs.writeFileSync(path.join(dir, 'nginx.conf'), `http { upstream app { server 127.0.0.1:${alive.address().port}; server 127.0.0.1:1; } server { listen 80; location / { proxy_pass http://app; } } }`);
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'gw', type: 'nginx', statsUrl: `${stub.url}/nginx_status`, configPath: path.join(dir, 'nginx.conf'), probeTimeoutMs: 400 }]));
  const t = await startApp({ INSTANCES_FILE: inst });
  const p = t.registry.get('gw');
  try {
    await p.poll(); await new Promise((r) => setTimeout(r, 100)); await p.poll();
    const s = p.snapshot;
    assert.equal(s.instance.source, 'stub-status+tcp-probe');
    assert.equal(s.summary.servers.up, 1); assert.equal(s.summary.servers.down, 1);
    assert.equal(s.info.activeConns, 7);
    assert.ok(s.summary.ratePerSec > 0, 'request rate derived from stub_status counters');
    assert.equal(p.events.filter((e) => e.type === 'server_state').length, 0);
  } finally { await t.close(); await stub.close(); alive.close(); }
});

test('request rate uses req_tot (HTTP requests) so keep-alive connections are not undercounted', async () => {
  let req = 0;
  const stats = await startStub((r, res) => { req += 200; res.end(`# pxname,svname,scur,stot,req_tot,status,type\nweb,FRONTEND,1,2,${req},OPEN,0\napp,s1,0,10,,UP,2\n`); });
  const { dir, cfg } = setup();
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'lb', type: 'haproxy', statsUrl: `${stats.url}/stats`, configPath: cfg }]));
  const t = await startApp({ INSTANCES_FILE: inst });
  const p = t.registry.get('lb');
  try {
    await p.poll(); await new Promise((r) => setTimeout(r, 100)); await p.poll();
    const fe = p.snapshot.rows.find((r) => r.kind === 'frontend');
    assert.ok(fe.ratePerSec > 100, `frontend rate should come from req_tot, got ${fe.ratePerSec}`);
    assert.equal(p.snapshot.rows.find((r) => r.kind === 'server').ratePerSec, 0, 'servers fall back to stot (unchanged here)');
  } finally { await t.close(); await stats.close(); }
});

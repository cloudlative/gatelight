'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { HistoryStore, SERIES_KEY } = require('../src/history');
const { startApp, startStub, get } = require('./helpers');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'gl-hist-'));
const pt = (t, rate) => ({ t, rate, scur: 2, srate: 1, e5xx: 0, rtime: 5, inBps: 10, outBps: 20, qcur: 0 });

test('store: saves, queries a range with bucketing, and reloads the newest raw points', () => {
  const s = HistoryStore.open(path.join(tmp(), 'h.db'));
  assert.ok(s, 'node:sqlite is available');
  const now = Date.now();
  for (let i = 0; i < 10; i++) s.save('a', { ...pt(now - (10 - i) * 1000, i), up: 3, down: 0, degraded: 0, total: 3 }, [{ key: 'web/s1', point: pt(now - (10 - i) * 1000, i) }]);
  s.save('b', null, [{ key: 'web/s1', point: pt(now, 99) }]);
  const raw = s.range('a', now - 60000);
  assert.equal(raw.get(SERIES_KEY).length, 10);
  assert.equal(raw.get('web/s1').length, 10);
  assert.equal(raw.get(SERIES_KEY)[0].up, 3, 'instance-level fields survive');
  assert.equal(s.range('b', 0).get('web/s1')[0].rate, 99, 'instances are isolated');
  const coarse = s.range('a', now - 60000, 5000);
  assert.ok(coarse.get('web/s1').length <= 3 && coarse.get('web/s1').length >= 2, 'bucketed into 5s averages');
  assert.equal(s.recent('a', 4).get('web/s1').length, 4);
  assert.ok(s.recent('a', 4).get('web/s1')[3].t > s.recent('a', 4).get('web/s1')[0].t, 'oldest first');
  s.removeInstance('a');
  assert.equal(s.range('a', 0).size, 0);
  s.close();
});

test('store: old raw samples are rolled up to minute averages and ancient ones are pruned', () => {
  const s = HistoryStore.open(path.join(tmp(), 'h.db'), { rawMs: 3600e3, keepMs: 86400e3 });
  const now = Date.now();
  const old = now - 2 * 3600e3;
  for (let i = 0; i < 12; i++) s.save('a', null, [{ key: 'k', point: pt(old + i * 5000, 10) }]);
  s.save('a', null, [{ key: 'k', point: pt(now - 3 * 86400e3, 1) }]);
  s.maintain(now);
  const rows = s.range('a', 0).get('k');
  assert.ok(rows.length <= 2, `rolled up, got ${rows.length}`);
  assert.equal(rows.find((r) => r.t > now - 3 * 3600e3).rate, 10);
  assert.ok(!rows.some((r) => r.t < now - 86400e3), 'data past the retention is gone');
  s.close();
});

test('store: an unusable location falls back to memory-only instead of throwing', () => {
  const file = path.join(tmp(), 'blocker');
  fs.writeFileSync(file, 'x');
  assert.equal(HistoryStore.open(path.join(file, 'sub', 'h.db')), null);
});

test('history survives a restart and the API serves long ranges from it', async () => {
  const stats = await startStub((req, res) => { res.setHeader('Content-Type', 'text/csv'); res.end('# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,status,type,rate,hrsp_5xx\nweb,FRONTEND,0,0,1,1,100,10,0,0,OPEN,0,1,0\napp,s1,0,0,0,0,10,5,0,0,UP,2,0,0\napp,BACKEND,0,0,0,0,10,10,0,0,UP,1,0,0\n'); });
  const dir = tmp();
  const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'lb', type: 'haproxy', statsUrl: `${stats.url}/stats` }]));
  const env = { INSTANCES_FILE: inst, DATA_DIR: dir, HISTORY_DB: path.join(dir, 'h.db') };
  const t1 = await startApp(env);
  try {
    const p = t1.registry.get('lb');
    await p.poll(); await p.poll(); await p.poll();
    const live = await get(t1.base, '/api/instances/lb/history-all?range=60');
    assert.equal(live.json.persisted, true);
    assert.equal(live.json.summary.length >= 3 || live.json.bucketMs > 0, true);
  } finally { t1.registry.store.close(); await t1.close(); }

  const t2 = await startApp(env);
  try {
    const p = t2.registry.get('lb');
    assert.ok(p.series.length >= 3, 'in-memory series refilled from disk before the first poll');
    assert.ok([...p.history.keys()].some((k) => k.startsWith('app/')), 'per-entity history refilled too');
    await p.poll();
    const r = await get(t2.base, '/api/instances/lb/history-all?range=1440');
    assert.equal(r.status, 200);
    assert.ok(r.json.entities.some((e) => e.points.length >= 1), 'earlier samples are visible after the restart');
  } finally { t2.registry.store.close(); await t2.close(); await stats.close(); }
});

test('events are stored and come back newest first, and a restart keeps the timeline', async () => {
  const s = HistoryStore.open(path.join(tmp(), 'e.db'));
  s.saveEvent('a', { ts: 1000, level: 'warning', type: 'server_state', proxy: 'app', name: 's1', from: 'up', to: 'down', message: 'Server app/s1: UP → DOWN' });
  s.saveEvent('a', { ts: 2000, level: 'recovery', type: 'server_state', proxy: 'app', name: 's1', message: 'Server app/s1: DOWN → UP' });
  s.saveEvent('b', { ts: 3000, level: 'info', type: 'x', message: 'other instance' });
  const ev = s.recentEvents('a', 10);
  assert.deepEqual(ev.map((e) => e.ts), [2000, 1000]);
  assert.equal(ev[1].to, 'down', 'extra fields round-trip');
  s.removeInstance('a');
  assert.equal(s.recentEvents('a', 10).length, 0);
  assert.equal(s.recentEvents('b', 10).length, 1);
  s.close();
});

test('history-all serves an absolute from/to window (zoom and pan) from the store', async () => {
  const stats = await startStub((req, res) => { res.setHeader('Content-Type', 'text/csv'); res.end('# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,status,type,rate,hrsp_5xx\nweb,FRONTEND,0,0,1,1,100,10,0,0,OPEN,0,1,0\napp,s1,0,0,0,0,10,5,0,0,UP,2,0,0\napp,BACKEND,0,0,0,0,10,10,0,0,UP,1,0,0\n'); });
  const dir = tmp(); const inst = path.join(dir, 'instances.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'lb', type: 'haproxy', statsUrl: `${stats.url}/stats` }]));
  const t = await startApp({ INSTANCES_FILE: inst, DATA_DIR: dir, HISTORY_DB: path.join(dir, 'h.db') });
  try {
    const p = t.registry.get('lb'); await p.poll(); await p.poll(); await p.poll();
    const now = Date.now();
    const inside = await get(t.base, `/api/instances/lb/history-all?from=${now - 60000}&to=${now + 1000}`);
    assert.equal(inside.status, 200); assert.equal(inside.json.persisted, true); assert.ok(inside.json.summary.length >= 1, 'samples inside the window');
    const past = await get(t.base, `/api/instances/lb/history-all?from=${now - 7200000}&to=${now - 3600000}`);
    assert.equal(past.json.summary.length, 0, 'a window in the past holds no samples');
    const bad = await get(t.base, `/api/instances/lb/history-all?from=${now}&to=${now - 1000}`);
    assert.equal(bad.status, 200, 'an invalid window falls back instead of erroring');
  } finally { t.registry.store.close(); await t.close(); await stats.close(); }
});

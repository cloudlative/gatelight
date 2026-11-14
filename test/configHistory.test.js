'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ConfigVersions, diffLines, diffFiles } = require('../src/configHistory');
const { startApp, get } = require('./helpers');

const apply = (ops) => ({ a: ops.filter((o) => o[0] !== '+').map((o) => o[1]), b: ops.filter((o) => o[0] !== '-').map((o) => o[1]) });

test('diffLines is a correct, minimal edit script', () => {
  const cases = [[[], []], [['a'], []], [[], ['a']], [['a', 'b', 'c'], ['a', 'x', 'c']], [['a', 'b', 'c', 'a', 'b', 'b', 'a'], ['c', 'b', 'a', 'b', 'a', 'c']]];
  for (const [a, b] of cases) {
    const ops = diffLines(a, b);
    assert.deepEqual(apply(ops), { a, b });
  }
  // the classic Myers example has an edit distance of 5
  assert.equal(diffLines([...'abcabba'], [...'cbabac']).filter((o) => o[0] !== '=').length, 5);
  // random round trips
  for (let i = 0; i < 200; i++) {
    const r = () => Array.from({ length: Math.floor(Math.random() * 12) }, () => 'abc'[Math.floor(Math.random() * 3)]);
    const a = r(); const b = r();
    assert.deepEqual(apply(diffLines(a, b)), { a, b });
  }
});

test('diffFiles reports added, removed and modified files with numbered hunks', () => {
  const d = diffFiles([{ name: 'a.conf', raw: 'one\ntwo\nthree\n' }, { name: 'gone.conf', raw: 'x' }], [{ name: 'a.conf', raw: 'one\n2\nthree\n' }, { name: 'new.conf', raw: 'y' }]);
  assert.deepEqual(d.files.map((f) => [f.name, f.status]), [['a.conf', 'modified'], ['gone.conf', 'removed'], ['new.conf', 'added']]);
  const h = d.files[0].hunks[0];
  assert.equal(h.oldStart, 1); assert.equal(h.newStart, 1);
  assert.deepEqual(h.lines.map((l) => `${l.t}${l.text}`), [' one', '-two', '+2', ' three']);
  assert.equal(d.linesAdded, 2); assert.equal(d.linesRemoved, 2);
});

for (const mode of ['memory', 'sqlite']) {
  test(`ConfigVersions (${mode}) dedupes, lists, diffs and trims`, () => {
    let db = null;
    if (mode === 'sqlite') { const { DatabaseSync } = require('node:sqlite'); db = new DatabaseSync(':memory:'); }
    const v = new ConfigVersions(db, { keep: 3 });
    const sec = (names) => names.map((n) => ({ type: 'backend', name: n, servers: [] }));
    const id1 = v.record('i', { files: [{ name: 'h.cfg', raw: 'a\nb' }], sections: sec(['x']), source: 'file' }, 1);
    assert.equal(v.record('i', { files: [{ name: 'h.cfg', raw: 'a\nb' }], sections: sec(['x']) }, 2), null, 'identical content is not saved twice');
    const id2 = v.record('i', { files: [{ name: 'h.cfg', raw: 'a\nc' }], sections: sec(['x', 'y']) }, 3);
    const list = v.list('i');
    assert.deepEqual(list.map((x) => x.id), [id2, id1]);
    assert.deepEqual(list[0].change, { linesAdded: 1, linesRemoved: 1, files: 1, entitiesAdded: 1, entitiesRemoved: 0 });
    const d = v.diff('i', id2);
    assert.equal(d.from.id, id1); assert.deepEqual(d.entitiesAdded, ['backend y']);
    assert.equal(v.diff('i', id2, 999), null); assert.equal(v.diff('i', 999), null);
    v.record('i', { files: [{ name: 'h.cfg', raw: '3' }] }, 4); v.record('i', { files: [{ name: 'h.cfg', raw: '4' }] }, 5);
    assert.equal(v.list('i').length, 3, 'only the newest `keep` versions are kept');
    assert.equal(v.list('other').length, 0);
    v.remove('i'); assert.equal(v.list('i').length, 0);
  });
}

test('API: a config file change becomes a new version with a diff; alerts endpoint lists the rules', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ch-'));
  const cfg = path.join(dir, 'haproxy.cfg');
  fs.writeFileSync(cfg, 'defaults\n    mode http\n\nbackend api\n    server a1 10.0.0.1:80 check\n');
  const inst = path.join(dir, 'i.json');
  fs.writeFileSync(inst, JSON.stringify([{ name: 'edge', configPath: cfg, alertRules: { latencyMs: 250 } }]));
  const t = await startApp({ INSTANCES_FILE: inst, DATA_DIR: dir });
  try {
    const p = t.registry.get('edge');
    await p.poll();
    fs.writeFileSync(cfg, 'defaults\n    mode http\n\nbackend api\n    server a1 10.0.0.1:80 check\n    server a2 10.0.0.2:80 check\n');
    const later = new Date(Date.now() + 5000); fs.utimesSync(cfg, later, later);
    await p.poll();
    const list = (await get(t.base, '/api/instances/edge/config/versions')).json;
    assert.equal(list.versions.length, 2);
    const d = (await get(t.base, `/api/instances/edge/config/versions/${list.versions[0].id}/diff`)).json;
    assert.deepEqual(d.entitiesAdded, ['server api/a2']); assert.equal(d.linesAdded, 1);
    assert.equal((await get(t.base, '/api/instances/edge/config/versions/12345')).status, 404);
    const one = (await get(t.base, `/api/instances/edge/config/versions/${list.versions[1].id}`)).json;
    assert.match(one.files[0].raw, /a1/);
    const al = (await get(t.base, '/api/instances/edge/alerts')).json;
    assert.equal(al.rules.find((r) => r.key === 'latencyMs').threshold, 250);
    assert.deepEqual(al.alerts, []);
    assert.ok(p.events.some((e) => e.type === 'config_changed'));
  } finally { await t.close(); }
});

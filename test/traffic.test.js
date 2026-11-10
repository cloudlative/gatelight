'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { Readable } = require('stream');
const { createAggregator, normPath } = require('../src/logs/haproxy');
const { ingestStream, IngestError } = require('../src/logs/ingest');
const { startApp, get } = require('./helpers');

// ---- synthetic log lines (made-up addresses and names)
const P = 'Nov 10 06:33:22 lb01 haproxy[1147]: ';
const http = (o = {}) => `${o.prefix ?? P}${o.client || '203.0.113.7:51000'} [${o.date || '10/Nov/2026:06:33:22.359'}] ${o.fe || 'web~'} ${o.be || 'app'}/${o.srv || 'app01'} ${o.timers || '0/0/0/165/165'} ${o.status ?? 200} ${o.bytes ?? 453} - - ${o.term || '--VN'} ${o.conns || '10/5/3/2/0'} ${o.q || '0/0'} ${o.cap ?? '{https://shop.example.com}'} "${o.req || 'GET /api/users/12345?x=1 HTTP/1.1'}"`;
const tcp = (o = {}) => `${P}${o.client || '198.51.100.9:40000'} [${o.date || '10/Nov/2026:06:33:01.435'}] ${o.fe || 'mqtt'} ${o.be || 'mq'}/${o.srv || 'mq01'} 1/0/21066 5 ${o.term || 'sD'} 1126/935/934/934/0 0/0`;

function run(lines) { const a = createAggregator(); for (const l of lines) a.push(l); return a.finish({}); }
const sum = (arr) => arr.reduce((x, y) => x + y, 0);

test('parser: HTTP lines (captured host, retried timers, query stripped) and TCP lines', () => {
  const r = run([http(), http({ status: 503, timers: '0/0/0/-1/+2000', term: 'sH--' }), http({ req: 'POST /v1/items/9f1c2d3e-aaaa-bbbb-cccc-1234567890ab HTTP/1.1' }), tcp()]);
  assert.equal(r.stats.http, 3); assert.equal(r.stats.tcp, 1); assert.equal(r.stats.unparsed, 0);
  assert.equal(sum(r.facts.n), 4);
  const byCls = (c) => r.facts.k.map((k, i) => (r.keys[k].cls === c ? r.facts.n[i] : 0));
  assert.equal(sum(byCls('2xx')), 2); assert.equal(sum(byCls('5xx')), 1); assert.equal(sum(byCls('tcp')), 1);
  assert.equal(sum(r.facts.abn), 2); // the 503 ("sH") and the TCP "sD" session ended abnormally
  assert.deepEqual(r.dims.host.values, ['https://shop.example.com']);
  assert.deepEqual(r.dims.method.values.sort(), ['GET', 'POST']);
  assert.ok(r.paths.values.includes('/api/users/:n'));
  assert.ok(r.paths.values.includes('/v1/items/:id')); // numeric and uuid ids are grouped
  assert.equal(r.range.from, Date.UTC(2026, 10, 10, 6, 33, 1, 435));
});

test('parser: IPv6 clients, aborted requests (status -1), no syslog prefix and ISO prefixes', () => {
  const r = run([
    http({ client: '2a00:f28:489:67ce:8c1a:5bff:fe00:b6c:47262', status: -1, bytes: 0, timers: '0/0/0/-1/434', term: 'CDVN' }),
    http({ prefix: '' }), http({ prefix: '2026-11-10T06:33:22+00:00 lb01 haproxy[9]: ' }),
  ]);
  assert.equal(r.stats.http, 3); assert.equal(r.stats.unparsed, 0);
  assert.equal(sum(r.facts.abt), 1);
  assert.ok(r.clients.values.includes('2a00:f28:489:67ce:8c1a:5bff:fe00:b6c'));
  assert.equal(r.errors.length, 1); // the aborted request is an error sample
});

test('parser: connection errors, server events, and unparsed lines with masked samples', () => {
  const r = run([
    `${P}85.115.209.72:64872 [10/Nov/2026:06:42:19.975] web/3: SSL handshake failure`,
    `${P}Server app/app01 is DOWN, reason: Layer4 connection problem, info: "Connection refused", check duration: 0ms. 1 active and 0 backup servers left.`,
    `${P}backend app has no server available!`,
    `${P}Server app/app01 is UP, reason: Layer4 check passed, check duration: 1ms.`,
    `${P}this is not a log line at all, ip 10.1.2.3`,
  ]);
  assert.equal(r.stats.ssl, 1); assert.equal(r.noise.msgs[0][0], 'web: SSL handshake failure');
  assert.deepEqual(r.events.map((e) => e[1]), ['down', 'nosrv', 'up']);
  assert.equal(r.stats.unparsed, 1);
  assert.ok(!/10\.1\.2\.3/.test(r.unparsed[0].sample)); // addresses are masked in the samples shown to the user
});

test('parser: latency histogram, concurrency maxima and the bucket coarsening cap', () => {
  const r = run([http({ timers: '0/0/0/3/3' }), http({ timers: '0/0/0/700/700', conns: '99/7/3/2/0' }), http({ timers: '0/0/0/20000/20000' })]);
  const hist = r.facts.h.reduce((a, h) => a.map((v, i) => v + h[i]), new Array(r.edges.length + 1).fill(0));
  assert.deepEqual([hist[1], hist[8], hist[12]], [1, 1, 1]); // <5ms, <1s, <30s
  assert.equal(Math.max(...r.facts.act), 99);
  assert.equal(normPath('/a/b?c=1#x'), '/a/b'); assert.equal(normPath('/o/1234/x'), '/o/:n/x'); assert.equal(normPath('/o/12/x'), '/o/12/x');
  // many distinct minutes are merged into coarser buckets instead of growing without bound
  const a = createAggregator();
  for (let m = 0; m < 70000; m++) { const d = new Date(Date.UTC(2026, 0, 1) + m * 60000); a.push(http({ date: `${String(d.getUTCDate()).padStart(2, '0')}/${['Jan', 'Feb', 'Mar'][d.getUTCMonth()]}/2026:${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}:00.000` })); }
  const big = a.finish({}); assert.ok(big.facts.t.length <= 60000 && big.bucketMs > 60000 && big.stats.bucketMult > 1);
  assert.equal(sum(big.facts.n), 70000); // nothing is lost by coarsening
});

const stream = (buf, chunk = 1000) => Readable.from((function* () { for (let i = 0; i < buf.length; i += chunk) yield buf.subarray(i, i + chunk); })());
const LOG = Array.from({ length: 300 }, (_, i) => (i % 3 ? http({ status: i % 11 ? 200 : 500 }) : tcp())).join('\n');

test('ingest: plain text, CRLF, gzip, and a log with a few bad lines', async () => {
  const ok = await ingestStream(stream(Buffer.from(LOG)), { maxBytes: 1 << 20, filename: 'a.log' });
  assert.equal(ok.stats.lines, 300); assert.equal(ok.source.filename, 'a.log');
  const crlf = await ingestStream(stream(Buffer.from(LOG.replace(/\n/g, '\r\n'))), { maxBytes: 1 << 20 });
  assert.equal(crlf.stats.http, ok.stats.http);
  const gz = await ingestStream(stream(zlib.gzipSync(Buffer.from(LOG))), { maxBytes: 1 << 20 });
  assert.equal(gz.stats.http, ok.stats.http); assert.equal(gz.source.gzip, true);
  const noisy = await ingestStream(stream(Buffer.from(`${LOG}\ngarbage line that is long enough to count\n\n`)), { maxBytes: 1 << 20 });
  assert.equal(noisy.stats.unparsed, 1); assert.equal(noisy.stats.http, ok.stats.http);
});

test('ingest: rejects empty, binary, non-HAProxy, oversized and corrupt files with clear errors', async () => {
  const bad = (buf, max = 1 << 20) => ingestStream(stream(buf), { maxBytes: max }).then(() => assert.fail('should have been rejected'), (e) => e);
  assert.equal((await bad(Buffer.alloc(0))).code, 'EMPTY');
  assert.equal((await bad(Buffer.concat([Buffer.from('abc'), Buffer.from([0, 1, 2, 3]), Buffer.alloc(200, 65)]))).code, 'NOT_TEXT');
  const web = Array.from({ length: 400 }, (_, i) => `10.0.0.${i % 250} - - [10/Nov/2026:06:33:22 +0000] "GET /x HTTP/1.1" 200 12 "-" "curl"`).join('\n');
  const nx = await bad(Buffer.from(web)); assert.equal(nx.code, 'BAD_FORMAT'); assert.match(nx.message, /does not look like an HAProxy log/);
  const big = await bad(Buffer.from(LOG), 1000); assert.equal(big.code, 'TOO_LARGE'); assert.equal(big.status, 413); assert.match(big.message, /Split it/);
  const gzBad = zlib.gzipSync(Buffer.from(LOG)); gzBad[20] ^= 0xff; gzBad[30] ^= 0xff;
  assert.ok(['BAD_GZIP', 'BAD_FORMAT'].includes((await bad(gzBad.subarray(0, gzBad.length - 8))).code));
  const bomb = zlib.gzipSync(Buffer.alloc(30 * 1024 * 1024, 'x')); // tiny upload that expands to 30 MB
  assert.equal((await ingestStream(stream(bomb), { maxBytes: 1 << 20 }).catch((e) => e)).code, 'TOO_LARGE');
});

// ------------------------------------------------------------------------------------------------ API
const A = { Cookie: `gl_sid=${'c'.repeat(64)}` };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'gl-logs-'));
const emptyInst = () => { const f = path.join(tmp(), 'i.json'); fs.writeFileSync(f, '[]'); return f; };
const put = (base, p, body, headers = {}) => fetch(base + p, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream', ...A, ...headers }, body }).then(async (r) => ({ status: r.status, json: await r.json().catch(() => null) }));

test('API: log-only instance, upload, stats, replace, delete; size limit, bad file and form uploads are refused', async () => {
  const t = await startApp({ INSTANCES_FILE: emptyInst(), DATA_DIR: tmp(), ALLOW_UI_INSTANCES: 'true', LOG_MAX_MB: '1' });
  try {
    const made = await fetch(`${t.base}/api/instances`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...A }, body: JSON.stringify({ type: 'haproxy', name: 'traffic-only', logOnly: true }) });
    const madeJson = await made.json(); assert.ok([200, 201].includes(made.status), JSON.stringify(madeJson)); const id = madeJson.id;
    assert.equal((await get(t.base, '/api/meta')).json.logMaxBytes, 1048576);
    assert.equal((await get(t.base, `/api/instances/${id}/logs`, A)).status, 404); // nothing uploaded yet
    const up = await put(t.base, `/api/instances/${id}/logs?filename=haproxy.log`, LOG);
    assert.equal(up.status, 200, JSON.stringify(up.json)); assert.equal(up.json.stats.http + up.json.stats.tcp, 300);
    const meta = await get(t.base, `/api/instances/${id}/logs?meta=1`, A); assert.equal(meta.json.source.filename, 'haproxy.log');
    const full = await get(t.base, `/api/instances/${id}/logs`, A); assert.equal(full.json.product, 'haproxy'); assert.ok(full.json.facts.t.length > 0);
    // the stored file holds aggregates only: no raw log lines
    const stored = fs.readFileSync(path.join(t.settings.ui.dir, 'logs', `${id}.json`), 'utf8'); assert.ok(!stored.includes('[10/Nov/2026') && !stored.includes('x=1') && !stored.includes('haproxy[1147]'));
    // too large (declared length) -> 413 with guidance, nothing replaced
    const huge = await fetch(`${t.base}/api/instances/${id}/logs`, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream', ...A }, body: Buffer.alloc(2 * 1048576, 'a') }).then(async (r) => ({ status: r.status, json: await r.json() })).catch(() => ({ status: 413, json: { error: 'connection closed early (413)' } }));
    assert.equal(huge.status, 413);
    assert.equal((await put(t.base, `/api/instances/${id}/logs`, 'this is just some text\n'.repeat(50))).status, 422);
    assert.equal((await put(t.base, `/api/instances/${id}/logs`, 'x', { 'Content-Type': 'multipart/form-data; boundary=x' })).status, 415);
    assert.equal((await get(t.base, `/api/instances/${id}/logs?meta=1`, A)).json.source.filename, 'haproxy.log'); // failed uploads never replace the good one
    const other = await put(t.base, `/api/instances/${id}/logs`, LOG, { Cookie: `gl_sid=${'d'.repeat(64)}` }); assert.equal(other.status, 404); // another browser cannot touch it
    const del = await fetch(`${t.base}/api/instances/${id}/logs`, { method: 'DELETE', headers: A }); assert.equal((await del.json()).ok, true);
    assert.equal((await get(t.base, `/api/instances/${id}/logs`, A)).status, 404);
    await put(t.base, `/api/instances/${id}/logs`, LOG);
    await fetch(`${t.base}/api/instances/${id}`, { method: 'DELETE', headers: A }); // deleting the instance deletes its statistics
    assert.ok(!fs.existsSync(path.join(t.settings.ui.dir, 'logs', `${id}.json`)));
  } finally { await t.close(); }
});

test('API: several files are combined, duplicates refused, one file can be removed, replace starts over', async () => {
  const { mergeResults } = require('../src/logs/merge');
  const t = await startApp({ INSTANCES_FILE: emptyInst(), DATA_DIR: tmp(), ALLOW_UI_INSTANCES: 'true', LOG_MAX_MB: '1' });
  try {
    const made = await fetch(`${t.base}/api/instances`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...A }, body: JSON.stringify({ type: 'haproxy', name: 'multi', logOnly: true }) });
    const id = (await made.json()).id; const base = `/api/instances/${id}/logs`;
    const L = String(LOG).split('\n').filter(Boolean); const second = L.slice(0, 120).join('\n');
    const a = await put(t.base, `${base}?filename=a.log`, LOG); assert.equal(a.status, 200);
    const b = await put(t.base, `${base}?filename=b.log`, second); assert.equal(b.status, 200, JSON.stringify(b.json));
    assert.equal(b.json.combined.files, 2); assert.equal(b.json.combined.lines, a.json.stats.lines + b.json.stats.lines);
    const full = (await get(t.base, base, A)).json;
    assert.equal(full.source.files.length, 2); assert.equal(full.stats.http + full.stats.tcp, a.json.stats.http + a.json.stats.tcp + b.json.stats.http + b.json.stats.tcp);
    const sumN = full.facts.n.reduce((x, y) => x + y, 0); assert.equal(sumN, full.stats.http + full.stats.tcp); // facts add up to the combined count
    assert.equal((await put(t.base, `${base}?filename=b.log`, second)).status, 409); // same file again
    const rm = await fetch(`${t.base}${base}?part=${full.source.files[0].part}`, { method: 'DELETE', headers: A }); assert.equal((await rm.json()).ok, true);
    const after = (await get(t.base, base, A)).json; assert.equal(after.source.files.length, 1); assert.equal(after.source.filename, 'b.log');
    const rep = await put(t.base, `${base}?filename=c.log&mode=replace`, LOG); assert.equal(rep.json.combined.files, 1);
    assert.equal((await get(t.base, base, A)).json.source.filename, 'c.log');
  } finally { await t.close(); }
  // merging is order independent for the totals
  const mk = (txt) => { const g = createAggregator(); String(txt).split('\n').forEach((l) => g.push(l)); return JSON.parse(JSON.stringify(g.finish({ source: { filename: 'x', bytes: 1, lines: 1 } }))); };
  const r1 = mk(LOG); const r2 = mk(String(LOG).split('\n').slice(0, 50).join('\n'));
  const ab = mergeResults([r1, r2]); const ba = mergeResults([r2, r1]);
  assert.equal(ab.stats.http, ba.stats.http); assert.equal(ab.facts.n.reduce((x, y) => x + y, 0), ba.facts.n.reduce((x, y) => x + y, 0));
});

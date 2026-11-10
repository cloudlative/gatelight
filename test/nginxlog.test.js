'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { Readable } = require('stream');
const { createAggregator, parseTimeLocal, seconds, lastPeer } = require('../src/logs/nginx');
const { ingestStream, IngestError } = require('../src/logs/ingest');
const { demoNginxLines } = require('../src/logs/demoLog');

const COMBINED = '203.0.113.9 - - [10/Nov/2026:08:15:02 +0000] "GET /products/1234?utm=1 HTTP/1.1" 200 5120 "-" "Mozilla/5.0"';

test('time and number helpers', () => {
  assert.strictEqual(parseTimeLocal('10/Nov/2026:08:15:02 +0000'), Date.UTC(2026, 10, 10, 8, 15, 2));
  assert.strictEqual(parseTimeLocal('10/Nov/2026:10:15:02 +0200'), Date.UTC(2026, 10, 10, 8, 15, 2));
  assert.strictEqual(parseTimeLocal('nonsense'), null);
  assert.strictEqual(seconds('0.012'), 12);
  assert.strictEqual(seconds('0.004, 0.010'), 14);
  assert.strictEqual(seconds('-'), -1);
  assert.strictEqual(lastPeer('10.0.0.5:80, 10.0.0.6:80'), '10.0.0.6:80');
  assert.strictEqual(lastPeer('-'), '-');
});

test('combined format: counted, query stripped, no timing', () => {
  const a = createAggregator();
  assert.ok(a.push(COMBINED));
  assert.ok(a.push('2001:db8::1 - bob [10/Nov/2026:08:16:02 +0000] "POST /api/x HTTP/2.0" 502 0 "https://x/" "curl/8"'));
  const r = a.finish();
  assert.strictEqual(r.product, 'nginx');
  assert.strictEqual(r.stats.http, 2);
  assert.strictEqual(r.stats.timed, 0);
  assert.ok(r.paths.values.includes('/products/:n'));
  assert.ok(!JSON.stringify(r).includes('utm=1'), 'query strings are not stored');
  assert.ok(!JSON.stringify(r).includes('Mozilla'), 'user agents are not stored');
  assert.ok(r.clients.values.includes('2001:db8::1'), 'IPv6 clients are kept whole');
});

test('key=value and bare timing fields, upstream and host', () => {
  const a = createAggregator();
  assert.ok(a.push(`${COMBINED} rt=0.250 urt=0.200 uaddr=10.0.0.5:8080 host=Shop.Example.com`));
  assert.ok(a.push('203.0.113.9 - - [10/Nov/2026:08:15:03 +0000] "GET / HTTP/1.1" 200 10 "-" "ua" 0.100 0.090'));
  const r = a.finish();
  assert.strictEqual(r.stats.timed, 2);
  const k = r.keys.find((x) => x.srv === '10.0.0.5:8080');
  assert.ok(k); assert.strictEqual(k.fe, 'shop.example.com'); assert.strictEqual(k.be, '(upstream)');
  assert.ok(r.facts.tt.some((v) => v >= 250));
});

test('JSON lines and error log lines', () => {
  const a = createAggregator();
  assert.ok(a.push(JSON.stringify({ remote_addr: '198.51.100.7', time_iso8601: '2026-11-10T08:15:02+00:00', request: 'GET /a HTTP/1.1', status: 404, body_bytes_sent: 12, request_time: 0.003, upstream_addr: '10.0.0.9:80', host: 'a.example.com' })));
  assert.ok(a.push('2026/11/10 08:15:02 [error] 1#1: *5 connect() failed (111: Connection refused) while connecting to upstream, client: 198.51.100.7, server: a'));
  assert.ok(!a.push('{"broken":'));
  assert.ok(!a.push('this is not a log line at all, sorry about that'));
  const r = a.finish();
  assert.strictEqual(r.stats.http, 1); assert.strictEqual(r.events.length, 1); assert.strictEqual(r.stats.unparsed, 2);
  assert.ok(/connect\(\) failed/.test(r.events[0][2]) && !/198\.51/.test(r.events[0][2]), 'client addresses are cut from error-log events');
});

test('ingest: a stream is parsed for nginx and a wrong format is refused', async () => {
  const lines = demoNginxLines(3000, 3).join('\n');
  const r = await ingestStream(Readable.from([Buffer.from(lines)]), { maxBytes: 5e6, filename: 'access.log', product: 'nginx' });
  assert.strictEqual(r.product, 'nginx'); assert.strictEqual(r.stats.http, 3000); assert.ok(r.stats.timed > 0);
  await assert.rejects(() => ingestStream(Readable.from([Buffer.from(Array(300).fill('hello world this is not nginx').join('\n'))]), { maxBytes: 5e6, product: 'nginx' }), (e) => e instanceof IngestError && /NGINX access log/.test(e.message));
});

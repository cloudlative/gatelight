'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('stream');
const { ingestStream, IngestError } = require('../src/logs/ingest');

const NGINX = Array.from({ length: 30 }, (_, i) => `10.0.0.${i} - - [17/May/2015:08:05:${String(i).padStart(2, '0')} +0000] "GET /a/${i} HTTP/1.1" 200 512 "-" "curl/8"`).join('\n');
const HAP = Array.from({ length: 30 }, (_, i) => `Nov 10 06:33:${String(i).padStart(2, '0')} lb haproxy[1]: 1.2.3.${i}:5000 [10/Nov/2026:06:33:${String(i).padStart(2, '0')}.359] fe be/s1 0/0/0/16/16 200 453 - - ---- 1/1/0/0/0 0/0 "GET /x HTTP/1.1"`).join('\n');
const run = (text, product = 'auto') => ingestStream(Readable.from([Buffer.from(text)]), { maxBytes: 1 << 20, filename: 'a.log', product });

test('auto-detect: an NGINX access log is read as NGINX, an HAProxy log as HAProxy', async () => {
  assert.equal((await run(NGINX)).product, 'nginx');
  assert.equal((await run(HAP)).product, 'haproxy');
});
test('auto-detect: a short file (under the sniff window) is still detected', async () => {
  assert.equal((await run(NGINX.split('\n').slice(0, 3).join('\n'))).product, 'nginx');
});
test('auto-detect: text that is neither is rejected with a clear message', async () => {
  await assert.rejects(run('hello\nthis is not a log\n'.repeat(30)), (e) => e instanceof IngestError && /HAProxy or an NGINX/.test(e.message));
});

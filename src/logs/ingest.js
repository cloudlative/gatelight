'use strict';
/**
 * Streaming ingest of one uploaded log: validates it, parses it line by line (constant memory) and returns the aggregates.
 *  - size limit on the bytes received, and a cap on what a .gz may expand to
 *  - gzip is detected by its magic bytes, so `haproxy.log.gz` works whatever it is called
 *  - binary files and files that do not look like an HAProxy log are rejected with a clear message
 */
const zlib = require('zlib');
const { pipeline, Readable } = require('stream');
const { StringDecoder } = require('string_decoder');
const haproxy = require('./haproxy');
const nginx = require('./nginx');

class IngestError extends Error { constructor(code, message, status = 422) { super(message); this.code = code; this.status = status; } }

const SNIFF_LINES = 200;
const mb = (b) => `${Math.round(b / 1048576)} MB`;
const NOT_HAPROXY = 'This does not look like an HAProxy log. Expected lines such as "Nov 10 06:33:22 host haproxy[123]: 1.2.3.4:5678 [10/Nov/2026:06:33:22.359] frontend backend/server 0/0/0/165/165 200 453 - - ---- 1/1/0/0/0 0/0 \\"GET / HTTP/1.1\\"" (option httplog or tcplog). ';
const NOT_ANY = 'This does not look like an HAProxy or an NGINX access log. HAProxy: option httplog or tcplog lines. NGINX: the default combined format (optionally followed by $request_time and $upstream_* fields), or one JSON object per line.';
const NOT_NGINX = 'This does not look like an NGINX access log. Expected lines such as \'93.180.71.3 - - [17/May/2015:08:05:32 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0 "-" "Debian APT-HTTP/1.3"\' (the default combined format, optionally followed by $request_time and $upstream_* fields), or one JSON object per line.';

async function ingestStream(readable, { maxBytes, filename = 'upload', onProgress, product = 'haproxy' } = {}) {
  // product 'auto': look at the first lines and pick the parser that understands them (HAProxy or NGINX)
  let agg = null; let NOT_LOG = product === 'nginx' ? NOT_NGINX : product === 'auto' ? NOT_ANY : NOT_HAPROXY; const held = [];
  const start = (prod) => { agg = (prod === 'nginx' ? nginx : haproxy).createAggregator(); if (product !== 'auto') NOT_LOG = prod === 'nginx' ? NOT_NGINX : NOT_HAPROXY; };
  const pick = () => {
    const lines = held.filter((l) => l && l.length >= 12).slice(0, SNIFF_LINES);
    const n = nginx.sniff(lines).ratio; const h = haproxy.sniff ? haproxy.sniff(lines).ratio : (() => { const a = haproxy.createAggregator(); let ok = 0; for (const l of lines) if (a.push(l)) ok++; return lines.length ? ok / lines.length : 0; })();
    start(n > h ? 'nginx' : 'haproxy');
    for (const l of held.splice(0)) agg.push(l);
  };
  if (product !== 'auto') start(product);
  let received = 0; let expanded = 0; let first = true;
  const decoder = new StringDecoder('utf8');
  let tail = ''; let sniffed = 0; let sniffOk = 0; let sniffDone = false;
  const maxExpanded = maxBytes * 12;

  const feedLine = (line) => {
    if (!agg) { held.push(line); if (held.length < SNIFF_LINES) return; pick(); line = null; }
    if (line === null) return; // the held lines (including this one) were replayed by pick()
    const ok = agg.push(line);
    if (!sniffDone && line.length >= 20) {
      sniffed++; if (ok) sniffOk++;
      if (sniffed >= SNIFF_LINES) { sniffDone = true; if (sniffOk / sniffed < 0.2) throw new IngestError('BAD_FORMAT', NOT_LOG); }
    }
  };
  const feedText = (text) => {
    text = tail + text; let from = 0;
    for (;;) {
      const nl = text.indexOf('\n', from); if (nl < 0) break;
      let end = nl; if (end > from && text.charCodeAt(end - 1) === 13) end--;
      feedLine(text.slice(from, end)); from = nl + 1;
    }
    tail = text.slice(from);
    if (tail.length > 65536) { feedLine(tail.slice(0, 200)); tail = ''; } // not a log line: count it as unparsed and move on
  };

  // read the first chunk to tell gzip from plain text, then keep counting the bytes that arrive
  const it = readable[Symbol.asyncIterator]();
  const firstChunk = await it.next();
  if (firstChunk.done || !firstChunk.value.length) throw new IngestError('EMPTY', 'The file is empty.');
  const gz = firstChunk.value.length >= 2 && firstChunk.value[0] === 0x1f && firstChunk.value[1] === 0x8b;
  async function* counted() {
    let n = firstChunk;
    while (!n.done) {
      received += n.value.length;
      if (received > maxBytes) throw new IngestError('TOO_LARGE', `The file is larger than the ${mb(maxBytes)} limit. Split it into smaller parts first (see the instructions next to the upload).`, 413);
      if (onProgress) onProgress(received);
      yield n.value;
      n = await it.next();
    }
  }
  let text = counted();
  if (gz) {
    const gunzip = zlib.createGunzip();
    pipeline(Readable.from(text), gunzip, () => { /* errors surface through the iterator below */ });
    text = gunzip;
  }
  try {
    for await (const buf of text) {
      expanded += buf.length;
      if (expanded > maxExpanded) throw new IngestError('TOO_LARGE', `The file expands to more than ${mb(maxExpanded)}. Split it into smaller parts first.`, 413);
      if (first) { first = false; if (buf.includes(0)) throw new IngestError('NOT_TEXT', 'This looks like a binary file, not a text log. Upload the plain-text log (or a .gz of it).'); }
      feedText(decoder.write(buf));
    }
  } catch (e) {
    if (e instanceof IngestError) throw e;
    if (gz) throw new IngestError('BAD_GZIP', `Could not read the compressed file (${e.message}). Is it a complete .gz file?`);
    throw e;
  }
  feedText(`${decoder.end()}\n`);
  if (tail) { feedLine(tail); tail = ''; }
  if (!agg) pick();
  const stats = agg.stats;
  if (!stats.http && !stats.tcp) throw new IngestError('BAD_FORMAT', NOT_LOG);
  return agg.finish({ source: { filename: String(filename).slice(0, 200), bytes: received, expandedBytes: gz ? expanded : received, lines: stats.lines, gzip: gz } });
}

module.exports = { ingestStream, IngestError };

'use strict';
/**
 * HAProxy traffic log -> compact aggregates.
 *
 * Streaming and bounded: lines are parsed one at a time and folded into
 *   - a per-bucket fact table keyed by (frontend, backend, server, status class), one row per minute and key,
 *   - small per-hour dimension tables (status code, method, HTTP version, termination state, captured host),
 *   - capped top-N tables (paths, clients) and short lists (slowest requests, error samples, events).
 * The raw log is never kept. Memory grows with distinct keys, not with log size.
 *
 * Understood formats (HAProxy `option httplog` / `option tcplog`, with or without the syslog prefix):
 *   HTTP: client:port [accept] frontend backend/server Tq/Tw/Tc/Tr/Tt status bytes cc sc term act/fe/be/srv/retr sq/bq {captured}* "request"
 *   TCP : client:port [accept] frontend backend/server Tw/Tc/Tt bytes term act/fe/be/srv/retr sq/bq
 *   plus: "frontend/N: SSL handshake failure" style connection errors, "Server x/y is DOWN|UP", "backend x has no server available!".
 * Everything else is counted as unparsed and a few masked samples are kept so the user can see what was skipped.
 */

const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const DATE = '(\\d\\d\\/[A-Za-z]{3}\\/\\d{4}:\\d\\d:\\d\\d:\\d\\d\\.\\d{3})';
const T = '(\\+?-?\\d+)';
const HTTP_RE = new RegExp(`^(\\S+) \\[${DATE}\\] (\\S+) (\\S+?)\\/(\\S+) ${T}\\/${T}\\/${T}\\/${T}\\/${T} (-?\\d+) (-?\\d+) (\\S+) (\\S+) (\\S{1,4}) (\\d+)\\/(\\d+)\\/(\\d+)\\/(\\d+)\\/${T} (\\d+)\\/(\\d+)(.*)$`);
const TCP_RE = new RegExp(`^(\\S+) \\[${DATE}\\] (\\S+) (\\S+?)\\/(\\S+) ${T}\\/${T}\\/${T} (\\d+) (\\S{1,4}) (\\d+)\\/(\\d+)\\/(\\d+)\\/(\\d+)\\/${T} (\\d+)\\/(\\d+)\\s*$`);
const CONNERR_RE = new RegExp(`^(\\S+) \\[${DATE}\\] (\\S+?)\\/\\d+: (.*)$`);
const SERVER_RE = /^(?:Server|Health check for server) (\S+?)\/(\S+?)(?:,| is | failed| succeeded)(.*)$/;
const NOSRV_RE = /^(?:backend|Backend|Proxy) (\S+) has no server available!?/;
const SYSLOG_TIME_RE = /^(\w{3})\s+(\d+) (\d\d):(\d\d):(\d\d) /;
const ISO_TIME_RE = /^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)/;

// latency histogram (ms): bin i holds values < EDGES[i]; the last bin is the rest
const EDGES = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, Infinity];
const NB = EDGES.length;
// columns of one fact row. agg: s = summed, m = maximum
const COLS = ['n', 'bytes', 'tt', 'ttmax', 'tr', 'trn', 'tw', 'tc', 'tq', 'act', 'fe', 'be', 'srvc', 'sq', 'bq', 'retr', 'abn', 'abt'];
const COL_AGG = ['s', 's', 's', 'm', 's', 's', 's', 's', 's', 'm', 'm', 'm', 'm', 'm', 'm', 's', 's', 's'];
const C = Object.fromEntries(COLS.map((c, i) => [c, i]));
const NCOL = COLS.length + NB;

const num = (s) => (s.charCodeAt(0) === 43 ? Number(s.slice(1)) : Number(s)); // "+123" marks a retried connection

function parseAccept(s) {
  if (s.charCodeAt(2) !== 47) return null;
  const mon = MON[s.slice(3, 6)]; if (mon === undefined) return null;
  return Date.UTC(+s.slice(7, 11), mon, +s.slice(0, 2), +s.slice(12, 14), +s.slice(15, 17), +s.slice(18, 20), +s.slice(21, 24));
}
function splitClient(c) { // "1.2.3.4:5678" or "2a00:f28::1:47262"
  const i = c.lastIndexOf(':');
  return i > 0 ? c.slice(0, i) : c;
}
const classOf = (status) => (status < 0 || status === 0 ? 'abt' : status < 200 ? '1xx' : status < 300 ? '2xx' : status < 400 ? '3xx' : status < 500 ? '4xx' : status < 600 ? '5xx' : 'oth');
const normalTerm = (t) => t.charCodeAt(0) === 45 || t.charCodeAt(0) === 76; // '-' normal, 'L' local response (stats, redirects)

/** "/api/users/12345?x=1" -> "/api/users/:n": group URLs that only differ by an id. */
function normPath(p) {
  const q = p.indexOf('?'); if (q >= 0) p = p.slice(0, q);
  const h = p.indexOf('#'); if (h >= 0) p = p.slice(0, h);
  if (p.length > 160) p = `${p.slice(0, 157)}…`;
  return p.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, '/:id').replace(/\/\d{3,}(?=\/|$)/g, '/:n');
}
/** Request path without its query string (queries often carry tokens or personal data and are never stored). */
const stripQuery = (p) => { const q = p.indexOf('?'); return q >= 0 ? p.slice(0, q) : p; };
const maskSample = (s) => s.slice(0, 160).replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, 'x.x.x.x').replace(/[0-9a-f]{1,4}(:[0-9a-f]{0,4}){3,}/gi, 'x::x');

/** A Map that keeps the `cap` biggest entries when it grows past 2x cap (heavy hitters survive, the long tail is dropped). */
class TopMap {
  constructor(cap) { this.cap = cap; this.m = new Map(); this.dropped = 0; }
  get(k, make) { let v = this.m.get(k); if (!v) { v = make(); this.m.set(k, v); if (this.m.size > this.cap * 2) this.compact(); } return v; }
  compact() {
    const all = [...this.m.entries()].sort((a, b) => b[1][0] - a[1][0]);
    this.dropped += all.length - this.cap; this.m = new Map(all.slice(0, this.cap));
  }
}

class Interner { // string -> small int, with a hard cap so hostile input cannot grow it without bound
  constructor(cap = 5000) { this.cap = cap; this.m = new Map(); this.list = []; }
  id(s) { let i = this.m.get(s); if (i === undefined) { if (this.list.length >= this.cap) return this.id('(other)'); i = this.list.length; this.m.set(s, i); this.list.push(s); } return i; }
}

function createAggregator(opts = {}) {
  const bucketMs = 60000;
  const keys = new Interner(2048);      // "fe\u0001be\u0001srv\u0001cls\u0001proto"
  const facts = new Map();              // bucket*4096 + keyId -> Float64Array(NCOL)
  const dimNames = ['code', 'method', 'version', 'term', 'host'];
  const dimVals = Object.fromEntries(dimNames.map((d) => [d, new Interner(500)]));
  const dims = Object.fromEntries(dimNames.map((d) => [d, new Map()])); // hour*2^? -> [n, bytes, tt, errs]; key string
  const pathVals = new Interner(1e9);   // unbounded ids but the table below is capped
  const paths = new TopMap(8000);       // "pathId\u0001keyId" -> [n, bytes, tt, ttmax, errs]
  const clientVals = new Interner(1e9);
  const clients = new TopMap(6000);     // "ipId\u0001keyId" -> [n, bytes, errs]
  const uniq = new Set(); let uniqCapped = false;
  const slow = []; const errors = []; const events = []; let eventCount = 0;
  const noise = new Map();              // bucket -> n  (connection-level errors such as SSL handshake failures)
  const noiseMsgs = new Map(); const noiseClients = new TopMap(300);
  const st = { lines: 0, http: 0, tcp: 0, conn: 0, events: 0, unparsed: 0, ssl: 0, bytes: 0 };
  const unparsed = new Map();
  let minT = Infinity; let maxT = -Infinity; let year = new Date().getUTCFullYear();

  const dim = (name, hour, keyId, val, bytes, tt, err) => {
    const k = `${hour}\u0001${keyId}\u0001${dimVals[name].id(val)}`; const m = dims[name];
    let r = m.get(k); if (!r) { r = [0, 0, 0, 0]; m.set(k, r); }
    r[0]++; r[1] += bytes; r[2] += tt; r[3] += err;
  };
  const histBin = (ms) => { for (let i = 0; i < NB - 1; i++) if (ms < EDGES[i]) return i; return NB - 1; };

  function addRequest(r) {
    const cls = r.proto === 'tcp' ? 'tcp' : classOf(r.status);
    const keyId = keys.id(`${r.fe}\u0001${r.be}\u0001${r.srv}\u0001${cls}\u0001${r.proto}`);
    const bucket = Math.floor(r.t / bucketMs); const fk = bucket * 4096 + (keyId & 4095);
    let row = facts.get(fk); if (!row) { row = new Float64Array(NCOL); facts.set(fk, row); }
    const abn = normalTerm(r.term) ? 0 : 1;
    row[C.n]++; row[C.bytes] += r.bytes > 0 ? r.bytes : 0;
    const tt = r.tt > 0 ? r.tt : 0; row[C.tt] += tt; if (tt > row[C.ttmax]) row[C.ttmax] = tt;
    if (r.tr >= 0) { row[C.tr] += r.tr; row[C.trn]++; }
    row[C.tw] += r.tw > 0 ? r.tw : 0; row[C.tc] += r.tc > 0 ? r.tc : 0; row[C.tq] += r.tq > 0 ? r.tq : 0;
    if (r.act > row[C.act]) row[C.act] = r.act; if (r.cfe > row[C.fe]) row[C.fe] = r.cfe; if (r.cbe > row[C.be]) row[C.be] = r.cbe; if (r.csv > row[C.srvc]) row[C.srvc] = r.csv;
    if (r.sq > row[C.sq]) row[C.sq] = r.sq; if (r.bq > row[C.bq]) row[C.bq] = r.bq;
    row[C.retr] += r.retr; row[C.abn] += abn; if (cls === 'abt') row[C.abt]++;
    row[COLS.length + histBin(tt)]++;

    const hour = Math.floor(r.t / 3600000);
    const bytes = r.bytes > 0 ? r.bytes : 0; const err = cls === '5xx' || cls === 'abt' || abn ? 1 : 0;
    dim('term', hour, keyId, r.term, bytes, tt, err);
    if (r.proto === 'http') {
      dim('code', hour, keyId, String(r.status), bytes, tt, err);
      dim('method', hour, keyId, r.method || '-', bytes, tt, err);
      dim('version', hour, keyId, r.version || '-', bytes, tt, err);
      if (r.host) dim('host', hour, keyId, r.host.slice(0, 120), bytes, tt, err);
      if (r.path) {
        const p = paths.get(`${pathVals.id(normPath(r.path))}\u0001${keyId}`, () => [0, 0, 0, 0, 0]);
        p[0]++; p[1] += bytes; p[2] += tt; if (tt > p[3]) p[3] = tt; p[4] += err;
      }
      if (tt > 0 && (slow.length < 300 || tt > slow[slow.length - 1][1])) {
        slow.push([r.t, tt, keyId, r.status, r.method || '-', r.path ? stripQuery(r.path).slice(0, 200) : '-', splitClient(r.client)]);
        slow.sort((a, b) => b[1] - a[1]); if (slow.length > 300) slow.length = 300;
      }
      if ((cls === '5xx' || cls === 'abt') && errors.length < 400) errors.push([r.t, keyId, r.status, r.method || '-', r.path ? stripQuery(r.path).slice(0, 200) : '-', splitClient(r.client), r.term]);
    }
    const ip = splitClient(r.client);
    const c = clients.get(`${clientVals.id(ip)}\u0001${keyId}`, () => [0, 0, 0]);
    c[0]++; c[1] += bytes; c[2] += err;
    if (!uniqCapped) { uniq.add(ip); if (uniq.size > 300000) uniqCapped = true; }
    if (r.t < minT) minT = r.t; if (r.t > maxT) maxT = r.t;
    st.bytes += bytes;
  }

  function addEvent(kind, t, text) {
    st.events++; eventCount++;
    if (events.length < 500) events.push([t, kind, text.slice(0, 300)]);
  }

  /** Feed one log line. Returns true when it was understood. */
  function push(raw) {
    if (!raw || raw.length < 20) { if (raw && raw.trim()) { st.lines++; st.unparsed++; } return false; } // blank lines are not counted
    st.lines++;
    let line = raw;
    let sysT = null;
    const p = line.indexOf('haproxy[');
    let bodyAt = -1;
    if (p >= 0 && p < 120) { const e = line.indexOf(']: ', p); if (e >= 0) bodyAt = e + 3; } else { const q = line.indexOf('haproxy: '); if (q >= 0 && q < 120) bodyAt = q + 9; }
    if (bodyAt > 0) {
      const head = line.slice(0, Math.min(bodyAt, 80));
      const m = SYSLOG_TIME_RE.exec(head);
      if (m && MON[m[1]] !== undefined) sysT = Date.UTC(year, MON[m[1]], +m[2], +m[3], +m[4], +m[5]);
      else { const iso = ISO_TIME_RE.exec(head); if (iso) sysT = Date.UTC(+iso[1], +iso[2] - 1, +iso[3], +iso[4], +iso[5], +iso[6]); }
      line = line.slice(bodyAt);
    }
    let m = HTTP_RE.exec(line);
    if (m) {
      const t = parseAccept(m[2]); if (t === null) return miss(raw);
      const rest = m[23];
      let request = ''; let host = '';
      const q1 = rest.indexOf('"');
      if (q1 >= 0) { const q2 = rest.lastIndexOf('"'); request = rest.slice(q1 + 1, q2 > q1 ? q2 : undefined); }
      const cap = q1 >= 0 ? rest.slice(0, q1) : rest;
      const b1 = cap.indexOf('{'); if (b1 >= 0) { const b2 = cap.indexOf('}', b1); host = cap.slice(b1 + 1, b2 > 0 ? b2 : undefined).split('|')[0].trim(); }
      let method = ''; let path = ''; let version = '';
      if (request) {
        const a = request.indexOf(' '); if (a > 0) { method = request.slice(0, a); const b = request.lastIndexOf(' '); version = b > a ? request.slice(b + 1) : ''; path = request.slice(a + 1, b > a ? b : undefined); } else method = request;
      }
      year = new Date(t).getUTCFullYear();
      st.http++;
      addRequest({ proto: 'http', t, client: m[1], fe: m[3].replace(/[~*]$/, ''), be: m[4], srv: m[5], tq: num(m[6]), tw: num(m[7]), tc: num(m[8]), tr: num(m[9]), tt: num(m[10]), status: +m[11], bytes: +m[12], term: m[15],
        act: +m[16], cfe: +m[17], cbe: +m[18], csv: +m[19], retr: num(m[20]), sq: +m[21], bq: +m[22], method, path, version, host });
      return true;
    }
    m = TCP_RE.exec(line);
    if (m) {
      const t = parseAccept(m[2]); if (t === null) return miss(raw);
      year = new Date(t).getUTCFullYear(); st.tcp++;
      addRequest({ proto: 'tcp', t, client: m[1], fe: m[3].replace(/[~*]$/, ''), be: m[4], srv: m[5], tq: 0, tw: num(m[6]), tc: num(m[7]), tr: -1, tt: num(m[8]), status: 0, bytes: +m[9], term: m[10],
        act: +m[11], cfe: +m[12], cbe: +m[13], csv: +m[14], retr: num(m[15]), sq: +m[16], bq: +m[17] });
      return true;
    }
    m = CONNERR_RE.exec(line);
    if (m) {
      const t = parseAccept(m[2]); if (t === null) return miss(raw);
      st.conn++; if (/SSL/i.test(m[4])) st.ssl++;
      const b = Math.floor(t / bucketMs); noise.set(b, (noise.get(b) || 0) + 1);
      const msg = `${m[3]}: ${m[4].replace(/\d+/g, 'N').slice(0, 120)}`; noiseMsgs.set(msg, (noiseMsgs.get(msg) || 0) + 1);
      noiseClients.get(splitClient(m[1]), () => [0])[0]++;
      if (t < minT) minT = t; if (t > maxT) maxT = t;
      return true;
    }
    const t0 = sysT == null ? (maxT > -Infinity ? maxT : Date.now()) : sysT;
    m = SERVER_RE.exec(line);
    if (m) { const down = /DOWN|failed/.test(line); addEvent(down ? 'down' : 'up', t0, line); return true; }
    m = NOSRV_RE.exec(line);
    if (m) { addEvent('nosrv', t0, line); return true; }
    if (/^(Proxy|Stopping|Pausing|Resuming|Server .* (?:was|has been)|Health check)/.test(line)) { addEvent('info', t0, line); return true; }
    return miss(raw);
  }
  function miss(raw) {
    st.unparsed++;
    const shape = maskSample(raw).replace(/\d+/g, 'N').slice(0, 80);
    if (unparsed.size < 40 || unparsed.has(shape)) { const u = unparsed.get(shape) || { n: 0, sample: maskSample(raw) }; u.n++; unparsed.set(shape, u); }
    return false;
  }

  /** Build the JSON-serialisable result. Coarsens the time buckets when there are too many rows. */
  function finish(meta = {}) {
    let mult = 1; const MAXROWS = 60000;
    while (facts.size / mult > MAXROWS && mult < 1440) mult *= (mult < 5 ? 5 : 2);
    const merged = new Map();
    for (const [fk, row] of facts) {
      const bucket = Math.floor(fk / 4096); const key = fk % 4096;
      const nb = Math.floor(bucket / mult) * mult; const mk = nb * 4096 + key;
      let into = merged.get(mk);
      if (!into) { merged.set(mk, row); continue; }
      for (let i = 0; i < COLS.length; i++) { if (COL_AGG[i] === 'm') { if (row[i] > into[i]) into[i] = row[i]; } else into[i] += row[i]; }
      for (let i = COLS.length; i < NCOL; i++) into[i] += row[i];
    }
    const ordered = [...merged.entries()].sort((a, b) => a[0] - b[0]);
    const f = { t: [], k: [] }; for (const c of COLS) f[c] = []; f.h = [];
    for (const [fk, row] of ordered) {
      f.t.push(Math.floor(fk / 4096) * bucketMs / 1000); f.k.push(fk % 4096);
      for (let i = 0; i < COLS.length; i++) f[COLS[i]].push(Math.round(row[i] * 100) / 100);
      f.h.push(Array.from(row.subarray(COLS.length)));
    }
    const tag = (m, vals, extra) => [...m.entries()].map(([k, v]) => { const [a, b, c] = k.split('\u0001'); return [+a, +b, +c, ...v.map((x) => Math.round(x))]; }).concat(extra || []);
    const dimOut = {}; for (const d of dimNames) dimOut[d] = { values: dimVals[d].list, rows: tag(dims[d], dimVals[d]) };
    const topPaths = [...paths.m.entries()].sort((a, b) => b[1][0] - a[1][0]).slice(0, 8000).map(([k, v]) => { const [a, b] = k.split('\u0001'); return [+a, +b, ...v.map((x) => Math.round(x))]; });
    const topClients = [...clients.m.entries()].sort((a, b) => b[1][0] - a[1][0]).slice(0, 6000).map(([k, v]) => { const [a, b] = k.split('\u0001'); return [+a, +b, ...v]; });
    const usedPaths = new Set(topPaths.map((r) => r[0])); const usedClients = new Set(topClients.map((r) => r[0]));
    const remap = (list, used) => { const map = new Map(); const out = []; for (const i of used) { map.set(i, out.length); out.push(list[i]); } return { map, out }; };
    const pr = remap(pathVals.list, usedPaths); const cr = remap(clientVals.list, usedClients);
    topPaths.forEach((r) => { r[0] = pr.map.get(r[0]); }); topClients.forEach((r) => { r[0] = cr.map.get(r[0]); });
    return {
      version: 1, product: 'haproxy', generated: Date.now(), ...meta,
      range: minT === Infinity ? null : { from: minT, to: maxT }, bucketMs: bucketMs * mult,
      keys: keys.list.map((s) => { const [fe, be, srv, cls, proto] = s.split('\u0001'); return { fe, be, srv, cls, proto }; }),
      cols: COLS, colAgg: COL_AGG, edges: EDGES.slice(0, -1), facts: f,
      dims: dimOut, paths: { values: pr.out, rows: topPaths, dropped: paths.dropped }, clients: { values: cr.out, rows: topClients, dropped: clients.dropped },
      slow, errors, events, eventCount,
      noise: { t: [...noise.keys()].sort((a, b) => a - b).map((b) => b * bucketMs / 1000), n: [...noise.keys()].sort((a, b) => a - b).map((b) => noise.get(b)),
        msgs: [...noiseMsgs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20), clients: [...noiseClients.m.entries()].sort((a, b) => b[1][0] - a[1][0]).slice(0, 30).map(([k, v]) => [k, v[0]]) },
      stats: { ...st, uniqueClients: uniq.size, uniqueApprox: uniqCapped, bucketMult: mult },
      unparsed: [...unparsed.values()].sort((a, b) => b.n - a.n).slice(0, 6),
    };
  }

  return { push, finish, stats: st };
}

/** Does this sample of lines look like an HAProxy log? (share of lines that parse). */
function sniff(lines) {
  const a = createAggregator(); let ok = 0; let tried = 0;
  for (const l of lines) { if (!l || l.length < 20) continue; tried++; if (a.push(l)) ok++; }
  return { tried, ok, ratio: tried ? ok / tried : 0 };
}

module.exports = { createAggregator, sniff, COLS, COL_AGG, EDGES, normPath, classOf, parseAccept };

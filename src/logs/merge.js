'use strict';
/**
 * Combine the aggregates of several uploaded logs into one result of the same shape (see createAggregator().finish).
 * Everything is summed; peaks (max columns) take the maximum. Overlapping periods are simply added together.
 * Unique clients cannot be unioned exactly (only the top clients are stored), so for several files it is an estimate.
 */
const { COLS, COL_AGG } = require('./haproxy');

const NH = (r) => r.edges.length + 1;
const MAXROWS = 60000;

function mergeResults(parts, meta = {}) {
  if (parts.length === 1) return { ...parts[0], ...meta, source: { ...parts[0].source, ...(meta.source || {}) } };
  const bucketMs = Math.max(...parts.map((p) => p.bucketMs));
  const nb = NH(parts[0]);
  // keys: union by tuple
  const keyIdx = new Map(); const keys = [];
  const kmap = parts.map((p) => p.keys.map((k) => { const s = `${k.fe}\u0001${k.be}\u0001${k.srv}\u0001${k.cls}\u0001${k.proto}`; let i = keyIdx.get(s); if (i === undefined) { i = keys.length; keyIdx.set(s, i); keys.push(k); } return i; }));
  // facts, re-bucketed to the coarsest resolution
  const facts = new Map();
  parts.forEach((p, pi) => {
    const F = p.facts; const n = F.t.length;
    for (let i = 0; i < n; i++) {
      const b = Math.floor((F.t[i] * 1000) / bucketMs) * bucketMs; const k = kmap[pi][F.k[i]]; const fk = `${b}:${k}`;
      let row = facts.get(fk);
      if (!row) { row = { b, k, v: new Float64Array(COLS.length), h: new Array(nb).fill(0) }; facts.set(fk, row); }
      for (let c = 0; c < COLS.length; c++) { const x = F[COLS[c]][i]; if (COL_AGG[c] === 'm') { if (x > row.v[c]) row.v[c] = x; } else row.v[c] += x; }
      const h = F.h[i]; for (let j = 0; j < nb; j++) row.h[j] += h[j];
    }
  });
  let mult = 1; while (facts.size / mult > MAXROWS && mult < 1440) mult *= 2; // keep the result bounded
  let rows = [...facts.values()];
  let outBucket = bucketMs;
  if (mult > 1) {
    outBucket = bucketMs * mult; const m2 = new Map();
    for (const r of rows) {
      const b = Math.floor(r.b / outBucket) * outBucket; const fk = `${b}:${r.k}`; const into = m2.get(fk);
      if (!into) { m2.set(fk, { ...r, b }); continue; }
      for (let c = 0; c < COLS.length; c++) { if (COL_AGG[c] === 'm') { if (r.v[c] > into.v[c]) into.v[c] = r.v[c]; } else into.v[c] += r.v[c]; }
      for (let j = 0; j < nb; j++) into.h[j] += r.h[j];
    }
    rows = [...m2.values()];
  }
  rows.sort((a, b) => a.b - b.b || a.k - b.k);
  const f = { t: rows.map((r) => r.b / 1000), k: rows.map((r) => r.k), h: rows.map((r) => r.h) };
  COLS.forEach((c, i) => { f[c] = rows.map((r) => Math.round(r.v[i] * 100) / 100); });

  // small per-hour dimensions: [hour, keyId, valueId, n, bytes, tt, err]
  const dims = {};
  for (const name of Object.keys(parts[0].dims)) {
    const vi = new Map(); const values = []; const acc = new Map();
    parts.forEach((p, pi) => {
      const D = p.dims[name]; if (!D) return;
      const vmap = D.values.map((v) => { let i = vi.get(v); if (i === undefined) { i = values.length; vi.set(v, i); values.push(v); } return i; });
      for (const r of D.rows) {
        const k = `${r[0]}\u0001${kmap[pi][r[1]]}\u0001${vmap[r[2]]}`; let a = acc.get(k); if (!a) { a = [0, 0, 0, 0]; acc.set(k, a); }
        for (let i = 0; i < 4; i++) a[i] += r[3 + i];
      }
    });
    dims[name] = { values, rows: [...acc.entries()].map(([k, v]) => { const [a, b, c] = k.split('\u0001'); return [+a, +b, +c, ...v]; }) };
  }

  // capped top tables: [valueId, keyId, n, bytes, tt, max, err] and [valueId, keyId, n, bytes, err]
  const top = (get, width, maxIdx, cap) => {
    const vi = new Map(); const values = []; const acc = new Map(); let dropped = 0;
    parts.forEach((p, pi) => {
      const T = get(p); dropped += T.dropped || 0;
      const vmap = T.values.map((v) => { let i = vi.get(v); if (i === undefined) { i = values.length; vi.set(v, i); values.push(v); } return i; });
      for (const r of T.rows) {
        const k = `${vmap[r[0]]}\u0001${kmap[pi][r[1]]}`; let a = acc.get(k); if (!a) { a = new Array(width).fill(0); acc.set(k, a); }
        for (let i = 0; i < width; i++) { const x = r[2 + i]; if (i === maxIdx) { if (x > a[i]) a[i] = x; } else a[i] += x; }
      }
    });
    const sorted = [...acc.entries()].sort((a, b) => b[1][0] - a[1][0]); dropped += Math.max(0, sorted.length - cap);
    const used = new Map(); const outVals = [];
    const out = sorted.slice(0, cap).map(([k, v]) => { const [a, b] = k.split('\u0001'); let id = used.get(+a); if (id === undefined) { id = outVals.length; used.set(+a, id); outVals.push(values[+a]); } return [id, +b, ...v]; });
    return { values: outVals, rows: out, dropped };
  };
  const paths = top((p) => p.paths, 5, 3, 8000);
  const clients = top((p) => p.clients, 3, -1, 6000);

  const slow = []; const errors = []; const events = []; let eventCount = 0;
  parts.forEach((p, pi) => {
    for (const r of p.slow) slow.push([r[0], r[1], kmap[pi][r[2]], ...r.slice(3)]);
    for (const r of p.errors) errors.push([r[0], kmap[pi][r[1]], ...r.slice(2)]);
    for (const e of p.events) events.push(e); eventCount += p.eventCount || p.events.length;
  });
  slow.sort((a, b) => b[1] - a[1]); slow.length = Math.min(slow.length, 300);
  errors.sort((a, b) => a[0] - b[0]); if (errors.length > 400) errors.splice(0, errors.length - 400);
  events.sort((a, b) => a[0] - b[0]); events.length = Math.min(events.length, 500);

  const nz = new Map(); const msgs = new Map(); const nc = new Map();
  for (const p of parts) {
    p.noise.t.forEach((t, i) => nz.set(t, (nz.get(t) || 0) + p.noise.n[i]));
    for (const [m, n] of p.noise.msgs) msgs.set(m, (msgs.get(m) || 0) + n);
    for (const [c, n] of p.noise.clients) nc.set(c, (nc.get(c) || 0) + n);
  }
  const nt = [...nz.keys()].sort((a, b) => a - b);
  const noise = { t: nt, n: nt.map((t) => nz.get(t)), msgs: [...msgs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20), clients: [...nc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 30) };

  const st = { lines: 0, http: 0, tcp: 0, conn: 0, events: 0, unparsed: 0, ssl: 0, bytes: 0, timed: 0 };
  for (const p of parts) for (const k of Object.keys(st)) st[k] += p.stats[k] || 0;
  const unionClients = new Set(clients.values).size;
  const uniq = Math.max(unionClients, ...parts.map((p) => p.stats.uniqueClients));
  const un = new Map();
  for (const p of parts) for (const u of p.unparsed || []) { const x = un.get(u.sample); if (x) x.n += u.n; else un.set(u.sample, { ...u }); }
  const ranges = parts.map((p) => p.range).filter(Boolean);
  return {
    version: 1, product: parts[0].product || 'haproxy', generated: Date.now(), ...meta,
    range: ranges.length ? { from: Math.min(...ranges.map((r) => r.from)), to: Math.max(...ranges.map((r) => r.to)) } : null,
    bucketMs: outBucket, keys, cols: COLS, colAgg: COL_AGG, edges: parts[0].edges, facts: f, dims, paths, clients, slow, errors, events, eventCount, noise,
    stats: { ...st, uniqueClients: uniq, uniqueApprox: true, bucketMult: Math.round(outBucket / 60000) },
    unparsed: [...un.values()].sort((a, b) => b.n - a.n).slice(0, 6),
  };
}

module.exports = { mergeResults };

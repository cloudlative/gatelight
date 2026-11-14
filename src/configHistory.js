'use strict';
/**
 * Configuration version history.
 *
 * Every time an instance's configuration changes (first load, file changed on disk, fetched again from its URL,
 * uploaded again), the (already redacted) files are saved as a new version, unless they are identical to the newest
 * one. Versions can be listed and compared: a line diff per file plus the frontends / backends / servers that
 * appeared or disappeared.
 *
 * Stored in the history database (table config_versions) when there is one, otherwise kept in memory.
 * Only redacted text is stored: passwords and keys are masked by the config loaders before they get here.
 */
const crypto = require('node:crypto');

const DEFAULT_KEEP = 50;
const CONTEXT = 3;
const MAX_EDIT = 4000; // beyond this many changed lines a diff is shown as "replaced" (keeps the cost bounded)

const hashFiles = (files) => {
  const h = crypto.createHash('sha256');
  for (const f of files) h.update(`${f.name}\u0000${f.raw}\u0000`);
  return h.digest('hex').slice(0, 16);
};

/** Myers O(ND) line diff. Returns [[op, text]] with op '=', '-', '+'. */
function diffLines(a, b) {
  let s = 0;
  while (s < a.length && s < b.length && a[s] === b[s]) s++;
  let ea = a.length; let eb = b.length;
  while (ea > s && eb > s && a[ea - 1] === b[eb - 1]) { ea--; eb--; }
  const A = a.slice(s, ea); const B = b.slice(s, eb);
  const N = A.length; const M = B.length;
  const head = a.slice(0, s).map((l) => ['=', l]);
  const tail = a.slice(ea).map((l) => ['=', l]);
  const replaced = () => [...A.map((l) => ['-', l]), ...B.map((l) => ['+', l])];
  if (!N || !M) return [...head, ...replaced(), ...tail];

  const MAX = N + M; const off = MAX + 1;
  const v = new Int32Array(2 * MAX + 3);
  const trace = [];
  let D = -1;
  outer: for (let d = 0; d <= Math.min(MAX, MAX_EDIT); d++) {
    trace.push(v.slice(off - d - 1, off + d + 2)); // v as it was before step d, for k in [-d-1, d+1]
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1] < v[off + k + 1]) ? v[off + k + 1] : v[off + k - 1] + 1;
      let y = x - k;
      while (x < N && y < M && A[x] === B[y]) { x++; y++; }
      v[off + k] = x;
      if (x >= N && y >= M) { D = d; break outer; }
    }
  }
  if (D < 0) return [...head, ...replaced(), ...tail];

  const ops = [];
  let x = N; let y = M;
  for (let d = D; d > 0; d--) {
    const t = trace[d]; const at = (k) => t[k + d + 1];
    const k = x - y;
    const prevK = k === -d || (k !== d && at(k - 1) < at(k + 1)) ? k + 1 : k - 1;
    const prevX = at(prevK); const prevY = prevX - prevK;
    while (x > prevX && y > prevY) { ops.push(['=', A[x - 1]]); x--; y--; }
    if (prevK === k + 1) { ops.push(['+', B[y - 1]]); y--; } else { ops.push(['-', A[x - 1]]); x--; }
  }
  while (x > 0 && y > 0) { ops.push(['=', A[x - 1]]); x--; y--; }
  return [...head, ...ops.reverse(), ...tail];
}

/** Unified-diff style hunks with line numbers, `context` lines around each change. */
function hunks(ops, context = CONTEXT) {
  const lines = []; let a = 0; let b = 0;
  for (const [op, text] of ops) {
    // a / b: line number in the old / new file; for a line that exists on one side only, the other is where it would be
    if (op === '=') { a++; b++; lines.push({ t: ' ', a, b, text }); } else if (op === '-') { a++; lines.push({ t: '-', a, b: null, at: b + 1, text }); } else { b++; lines.push({ t: '+', a: null, b, at: a + 1, text }); }
  }
  const changes = lines.map((l, i) => (l.t === ' ' ? -1 : i)).filter((i) => i >= 0);
  const groups = [];
  for (const i of changes) {
    const g = groups[groups.length - 1];
    if (g && i - g.last <= context * 2 + 1) g.last = i; else groups.push({ first: i, last: i });
  }
  return groups.map(({ first, last }) => {
    const slice = lines.slice(Math.max(0, first - context), Math.min(lines.length, last + context + 1));
    const h = slice[0];
    return {
      oldStart: h.a ?? h.at, newStart: h.b ?? h.at,
      lines: slice.map(({ t, a: la, b: lb, text }) => ({ t, a: la, b: lb, text })),
    };
  });
}

const split = (raw) => (raw === '' ? [] : String(raw).replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n'));

/** Compare two lists of files ({name, raw}). */
function diffFiles(before, after) {
  const A = new Map(before.map((f) => [f.name, f.raw])); const B = new Map(after.map((f) => [f.name, f.raw]));
  const names = [...new Set([...A.keys(), ...B.keys()])].sort();
  const files = []; let added = 0; let removed = 0;
  for (const name of names) {
    const ra = A.get(name); const rb = B.get(name);
    if (ra === rb) continue;
    const ops = diffLines(split(ra ?? ''), split(rb ?? ''));
    const plus = ops.filter((o) => o[0] === '+').length; const minus = ops.filter((o) => o[0] === '-').length;
    added += plus; removed += minus;
    files.push({ name, status: ra == null ? 'added' : rb == null ? 'removed' : 'modified', added: plus, removed: minus, hunks: hunks(ops) });
  }
  return { files, linesAdded: added, linesRemoved: removed, unchanged: names.length - files.length };
}

/** "frontend web", "backend api", "server api/s1" keys from parsed sections, to show what appeared or disappeared. */
const entityKeys = (sections) => (sections || []).flatMap((x) => [`${x.type} ${x.name}`, ...(x.servers || []).map((v) => `server ${x.name}/${v.name}`)]);

class ConfigVersions {
  /** @param db a node:sqlite DatabaseSync (the history database) or null for in-memory */
  constructor(db = null, { keep = DEFAULT_KEEP, log = null } = {}) {
    this.db = db; this.keep = keep; this.log = log; this.mem = new Map();
    this.nextId = 1;
    if (db) {
      db.exec(`CREATE TABLE IF NOT EXISTS config_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, inst TEXT NOT NULL, ts INTEGER NOT NULL, hash TEXT NOT NULL,
        source TEXT, reason TEXT, files TEXT NOT NULL, entities TEXT);
        CREATE INDEX IF NOT EXISTS config_versions_i ON config_versions (inst, id);`);
    }
  }

  _rows(inst) {
    if (!this.db) return this.mem.get(inst) || [];
    return this.db.prepare('SELECT * FROM config_versions WHERE inst=? ORDER BY id DESC').all(inst).map((r) => ({
      id: r.id, ts: r.ts, hash: r.hash, source: r.source, reason: r.reason, files: JSON.parse(r.files), entities: r.entities ? JSON.parse(r.entities) : [],
    }));
  }

  /** Newest first, without the file contents. */
  list(inst) {
    const rows = this._rows(inst);
    return rows.map((v, i) => {
      const prev = rows[i + 1];
      const d = prev ? diffFiles(prev.files, v.files) : null;
      const ek = new Set(v.entities); const pk = new Set(prev ? prev.entities : []);
      return {
        id: v.id, ts: v.ts, hash: v.hash, source: v.source, reason: v.reason,
        files: v.files.length, lines: v.files.reduce((n, f) => n + split(f.raw).length, 0),
        change: d ? { linesAdded: d.linesAdded, linesRemoved: d.linesRemoved, files: d.files.length, entitiesAdded: prev ? [...ek].filter((k) => !pk.has(k)).length : 0, entitiesRemoved: prev ? [...pk].filter((k) => !ek.has(k)).length : 0 } : null,
      };
    });
  }

  get(inst, id) { return this._rows(inst).find((v) => v.id === Number(id)) || null; }

  /**
   * Save the configuration as a new version if it differs from the newest one.
   * @returns the new version's id, or null when nothing changed
   */
  record(inst, { files, sections, source, reason }, now = Date.now()) {
    if (!files || !files.length) return null;
    const clean = files.map((f) => ({ name: String(f.name), raw: String(f.raw ?? '') }));
    const hash = hashFiles(clean);
    const latest = this._latestHash(inst);
    if (latest === hash) return null;
    const entities = entityKeys(sections);
    try {
      if (this.db) {
        const r = this.db.prepare('INSERT INTO config_versions (inst,ts,hash,source,reason,files,entities) VALUES (?,?,?,?,?,?,?)').run(inst, now, hash, source || null, reason || null, JSON.stringify(clean), JSON.stringify(entities));
        this.db.prepare('DELETE FROM config_versions WHERE inst=? AND id NOT IN (SELECT id FROM config_versions WHERE inst=? ORDER BY id DESC LIMIT ?)').run(inst, inst, this.keep);
        return Number(r.lastInsertRowid);
      }
      const list = this.mem.get(inst) || [];
      const id = this.nextId++;
      list.unshift({ id, ts: now, hash, source: source || null, reason: reason || null, files: clean, entities });
      if (list.length > this.keep) list.length = this.keep;
      this.mem.set(inst, list);
      return id;
    } catch (e) {
      if (this.log) this.log.warn('Config version write failed', { error: String(e.message || e) });
      return null;
    }
  }

  _latestHash(inst) {
    if (!this.db) { const l = this.mem.get(inst); return l && l.length ? l[0].hash : null; }
    const r = this.db.prepare('SELECT hash FROM config_versions WHERE inst=? ORDER BY id DESC LIMIT 1').get(inst);
    return r ? r.hash : null;
  }

  /** Diff between two versions (from = older, to = newer). `from` defaults to the version before `to`. */
  diff(inst, toId, fromId = null) {
    const rows = this._rows(inst);
    const ti = rows.findIndex((v) => v.id === Number(toId));
    if (ti < 0) return null;
    const to = rows[ti];
    const from = fromId != null ? rows.find((v) => v.id === Number(fromId)) : rows[ti + 1];
    if (fromId != null && !from) return null;
    const d = diffFiles(from ? from.files : [], to.files);
    const fk = new Set(from ? from.entities : []); const tk = new Set(to.entities);
    return {
      from: from ? { id: from.id, ts: from.ts, source: from.source } : null,
      to: { id: to.id, ts: to.ts, source: to.source },
      ...d,
      entitiesAdded: [...tk].filter((k) => !fk.has(k)),
      entitiesRemoved: [...fk].filter((k) => !tk.has(k)),
    };
  }

  remove(inst) {
    if (this.db) { try { this.db.prepare('DELETE FROM config_versions WHERE inst=?').run(inst); } catch { /* ignore */ } } else this.mem.delete(inst);
  }
}

module.exports = { ConfigVersions, diffLines, diffFiles, hunks };

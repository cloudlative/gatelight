'use strict';
/**
 * Optional persistent history (SQLite via the built-in node:sqlite, Node 22.5+).
 * Stores metrics and entity names, never credentials. (src/configHistory.js adds a table of redacted config versions.)
 * Raw samples are kept for `rawMs`, then rolled up into 1-minute averages kept for `keepMs`.
 * If SQLite is unavailable or the file cannot be opened, open() returns null and GateLight runs in memory as before.
 */
const fs = require('node:fs');
const path = require('node:path');

const METRICS = ['scur', 'rate', 'srate', 'e5xx', 'rtime', 'inBps', 'outBps', 'qcur', 'up', 'down', 'degraded', 'total'];
const COLS = { scur: 'scur', rate: 'rate', srate: 'srate', e5xx: 'e5xx', rtime: 'rtime', inBps: 'inb', outBps: 'outb', qcur: 'qcur', up: 'up', down: 'down', degraded: 'degraded', total: 'total' };
const SERIES_KEY = '*';
const MINUTE = 60000;

class HistoryStore {
  /** @returns {HistoryStore|null} */
  static open(file, opts = {}, log = null) {
    let DatabaseSync;
    try { ({ DatabaseSync } = require('node:sqlite')); } catch {
      if (log) log.warn('History persistence disabled: this Node.js has no node:sqlite (needs 22.5+). Charts keep history in memory only.');
      return null;
    }
    try {
      if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      return new HistoryStore(new DatabaseSync(file), opts, log);
    } catch (e) {
      if (log) log.warn('History persistence disabled: could not open the history database', { file, error: String(e.message || e) });
      return null;
    }
  }

  constructor(db, opts, log) {
    this.db = db; this.log = log;
    this.rawMs = opts.rawMs || 6 * 3600e3;
    this.keepMs = opts.keepMs || 14 * 86400e3;
    db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
      CREATE TABLE IF NOT EXISTS samples (
        inst TEXT NOT NULL, key TEXT NOT NULL, t INTEGER NOT NULL, res INTEGER NOT NULL DEFAULT 0,
        scur REAL, rate REAL, srate REAL, e5xx REAL, rtime REAL, inb REAL, outb REAL, qcur REAL,
        up REAL, down REAL, degraded REAL, total REAL,
        PRIMARY KEY (inst, key, t, res)
      ) WITHOUT ROWID;
      CREATE INDEX IF NOT EXISTS samples_t ON samples (t);
      CREATE TABLE IF NOT EXISTS events (inst TEXT NOT NULL, ts INTEGER NOT NULL, level TEXT, type TEXT, proxy TEXT, name TEXT, message TEXT, data TEXT);
      CREATE INDEX IF NOT EXISTS events_i ON events (inst, ts);`);
    this.ins = db.prepare(`INSERT OR REPLACE INTO samples (inst,key,t,res,scur,rate,srate,e5xx,rtime,inb,outb,qcur,up,down,degraded,total) VALUES (?,?,?,0,?,?,?,?,?,?,?,?,?,?,?,?)`);
    this.lastPrune = 0;
  }

  _row(inst, key, p) {
    return [inst, key, Math.round(p.t), ...METRICS.map((m) => (p[m] == null || Number.isNaN(Number(p[m])) ? null : Number(p[m])))];
  }

  /** One poll's worth of samples in a single transaction. `series` is the instance-level point (or null). */
  save(inst, series, entities) {
    try {
      this.db.exec('BEGIN');
      if (series) this.ins.run(...this._row(inst, SERIES_KEY, series));
      for (const e of entities) this.ins.run(...this._row(inst, e.key, e.point));
      this.db.exec('COMMIT');
    } catch (e) {
      try { this.db.exec('ROLLBACK'); } catch { /* not in a transaction */ }
      if (this.log) this.log.warn('History write failed', { error: String(e.message || e) });
    }
    const now = Date.now();
    if (now - this.lastPrune > 10 * MINUTE) { this.lastPrune = now; this.maintain(now); }
  }

  /** Roll old raw rows up to 1-minute averages, then drop what is older than the retention. */
  maintain(now = Date.now()) {
    try {
      const cut = Math.floor((now - this.rawMs) / MINUTE) * MINUTE;
      this.db.exec('BEGIN');
      this.db.prepare(`INSERT OR REPLACE INTO samples (inst,key,t,res,scur,rate,srate,e5xx,rtime,inb,outb,qcur,up,down,degraded,total)
        SELECT inst,key,(t/${MINUTE})*${MINUTE},${MINUTE},AVG(scur),AVG(rate),AVG(srate),AVG(e5xx),AVG(rtime),AVG(inb),AVG(outb),AVG(qcur),AVG(up),AVG(down),AVG(degraded),AVG(total)
        FROM samples WHERE res=0 AND t<? GROUP BY inst,key,t/${MINUTE}`).run(cut);
      this.db.prepare('DELETE FROM samples WHERE res=0 AND t<?').run(cut);
      this.db.prepare('DELETE FROM samples WHERE t<?').run(now - this.keepMs);
      this.db.prepare('DELETE FROM events WHERE ts<?').run(now - this.keepMs);
      this.db.exec('COMMIT');
    } catch (e) {
      try { this.db.exec('ROLLBACK'); } catch { /* ignore */ }
      if (this.log) this.log.warn('History maintenance failed', { error: String(e.message || e) });
    }
  }

  _point(r) {
    const o = { t: r.t };
    for (const m of METRICS) { const v = r[COLS[m]]; if (v != null) o[m] = v; }
    return o;
  }

  /**
   * Samples since `sinceMs`, averaged into buckets of `bucketMs` (0 = as stored).
   * @returns {Map<string, object[]>} key -> points; the instance series is under '*'
   */
  range(inst, sinceMs, bucketMs = 0, untilMs = 9e15) {
    const out = new Map();
    const b = Math.max(0, Math.floor(bucketMs));
    const sql = b > 1000
      ? `SELECT key,(t/${b})*${b} AS t,AVG(scur) scur,AVG(rate) rate,AVG(srate) srate,AVG(e5xx) e5xx,AVG(rtime) rtime,AVG(inb) inb,AVG(outb) outb,AVG(qcur) qcur,AVG(up) up,AVG(down) down,AVG(degraded) degraded,AVG(total) total
         FROM samples WHERE inst=? AND t>=? AND t<=? GROUP BY key,t/${b} ORDER BY key,t`
      : 'SELECT * FROM samples WHERE inst=? AND t>=? AND t<=? ORDER BY key,t';
    for (const r of this.db.prepare(sql).all(inst, Math.round(sinceMs), Math.round(untilMs))) {
      let list = out.get(r.key); if (!list) { list = []; out.set(r.key, list); }
      list.push(this._point(r));
    }
    return out;
  }

  /** Newest `limit` raw points per key, oldest first (used to refill memory after a restart). */
  recent(inst, limit) {
    const out = new Map();
    const rows = this.db.prepare('SELECT * FROM samples WHERE inst=? AND res=0 ORDER BY t DESC').all(inst);
    for (const r of rows) {
      let list = out.get(r.key); if (!list) { list = []; out.set(r.key, list); }
      if (list.length < limit) list.push(this._point(r));
    }
    for (const list of out.values()) list.reverse();
    return out;
  }

  /** State-change events survive restarts too (they are the audit trail of what happened and when). */
  saveEvent(inst, ev) {
    try {
      const { ts, level, type, proxy, name, message, ...rest } = ev; delete rest.instanceId; delete rest.instanceName;
      this.db.prepare('INSERT INTO events (inst,ts,level,type,proxy,name,message,data) VALUES (?,?,?,?,?,?,?,?)').run(inst, ts, level || null, type || null, proxy || null, name || null, message || null, JSON.stringify(rest));
    } catch (e) { if (this.log) this.log.warn('Event write failed', { error: String(e.message || e) }); }
  }

  /** Newest first. */
  recentEvents(inst, limit) {
    return this.db.prepare('SELECT * FROM events WHERE inst=? ORDER BY ts DESC LIMIT ?').all(inst, limit).map((r) => {
      let extra = {}; try { extra = JSON.parse(r.data || '{}'); } catch { /* ignore */ }
      return { ts: r.ts, instanceId: inst, level: r.level, type: r.type, proxy: r.proxy || undefined, name: r.name || undefined, message: r.message, ...extra };
    });
  }

  removeInstance(inst) {
    try { this.db.prepare('DELETE FROM samples WHERE inst=?').run(inst); this.db.prepare('DELETE FROM events WHERE inst=?').run(inst); } catch { /* ignore */ }
  }

  stats() {
    const r = this.db.prepare('SELECT COUNT(*) n, MIN(t) oldest FROM samples').get();
    return { rows: r.n, oldest: r.oldest };
  }

  close() { try { this.db.close(); } catch { /* already closed */ } }
}

module.exports = { HistoryStore, SERIES_KEY };

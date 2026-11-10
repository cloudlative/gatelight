'use strict';
const { statusClass } = require('./statsParser');
const { summarize } = require('./audit');
const { DRIVERS } = require('./drivers');
const { DemoSource } = require('./demo');
const log = require('./logger');
const { SERIES_KEY } = require('./history');
const { fetchConfigFiles } = require('./transport');

const SPARK_POINTS = 60;
const rowKey = (r) => `${r.proxy}/${r.name}`;

/** Polls one HAProxy instance and holds its derived state (snapshot, history, events). */
class InstancePoller {
  constructor(instance, settings, notifier, store = null) {
    this.instance = instance;
    this.store = store;
    this.driver = DRIVERS[instance.type || 'haproxy'];
    this.prevInfo = null;
    this.settings = settings;
    this.notifier = notifier;
    this.snapshot = null;
    this.history = new Map();          // key -> [{t, scur, rate, e5xx, rtime}]
    this.events = [];
    this.series = [];                  // instance-level samples: [{t, rate, srate, scur, e5xx, inBps, outBps, up, down, degraded, total, rtime}]
    this.prev = new Map();             // key -> {t, stot, h5, status}
    this._batch = [];
    this._hydrate();
    this.failures = 0;
    this.lastSuccess = null;
    this.reachable = null;
    this.configCache = { mtimeMs: null, path: null };
    this.fetchedFiles = null;          // config pulled from the server's config URL(s) (GET)
    this.configFetch = { at: null, ok: null, error: null };
    this.timer = null;
    this.inFlight = null;
    this.demo = instance.demo ? new DemoSource([], () => (this.configCache.sections || [])) : null;
    this.alertedUnreachable = false;
  }

  start() {
    const tick = () => this.poll().finally(() => {
      if (this.stopped) return;
      this.timer = setTimeout(tick, this.instance.pollIntervalMs);
      this.timer.unref?.();
    });
    this.stopped = false;
    tick();
  }

  stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
  }

  /** Coalesces concurrent polls (e.g. manual refresh during a scheduled poll). */
  poll() {
    if (this.inFlight) return this.inFlight;
    this.inFlight = this._poll().catch((e) => log.error('poll crashed', { instance: this.instance.id, error: e.stack }))
      .finally(() => { this.inFlight = null; });
    return this.inFlight;
  }

  /** Where the configuration comes from: the server's config URL(s), a file on disk, or text uploaded in the UI. */
  configSource() {
    const i = this.instance;
    if (i.configUrls && i.configUrls.length) return 'url';
    if (i.configFiles && i.configFiles.length) return 'uploaded';
    if (i.configPath) return 'file';
    return 'none';
  }

  _loadConfig() {
    const before = this.configCache.sig;
    const inst = this.instance;
    if (this.configSource() === 'url') {
      if (!this.fetchedFiles) { this.configCache = { ...this.configCache, path: '(from URL)', error: this.configFetch.error || 'Config not fetched yet', sections: this.configCache.sections || [], files: this.configCache.files || [] }; return; }
      this.configCache = this.driver.loadConfig({ ...inst, configFiles: this.fetchedFiles }, this.configCache.sections ? this.configCache : null);
      this.configCache.path = '(from URL)';
    } else this.configCache = this.driver.loadConfig(inst, this.configCache.sections ? this.configCache : null);
    if (before != null && this.configCache.sig != null && before !== this.configCache.sig) {
      this._event({ level: 'info', type: 'config_changed', message: this.configSource() === 'url' ? `Configuration changed on the server and was fetched again (${this.configCache.files.length} file${this.configCache.files.length === 1 ? '' : 's'})` : `Configuration changed on disk and was reloaded (${this.configCache.files.length} file${this.configCache.files.length === 1 ? '' : 's'})` });
    }
  }

  /** Read-only: pull the config from the server's URL(s). Keeps the previous config when the fetch fails. */
  async _fetchConfig() {
    try {
      this.fetchedFiles = await fetchConfigFiles(this.instance);
      this.configFetch = { at: Date.now(), ok: true, error: null };
    } catch (e) {
      this.configFetch = { at: Date.now(), ok: false, error: e.message };
      log.warn('config fetch failed', { instance: this.instance.id, error: e.message });
    }
    return this.configFetch;
  }

  /**
   * "Refresh from server": re-read the configuration right now (GET the config URL(s), or re-read the file) and
   * report what changed. Nothing is ever written to the server.
   */
  async refreshConfig() {
    const source = this.configSource();
    if (source === 'uploaded' || source === 'none') return { ok: true, source, skipped: true, message: 'This configuration was uploaded, so there is nothing to fetch. Use "Update config" to upload a new version, or add a config URL in the connection settings.' };
    const prevFiles = (this.configCache.files || []).map((f) => f.raw).join('\n');
    const prevSections = this.configCache.sections || [];
    if (source === 'url') {
      const r = await this._fetchConfig();
      if (!r.ok) return { ok: false, source, error: r.error };
    } else this.configCache = { ...this.configCache, sig: null }; // force a re-read of the file
    const before = this.configCache.sig;
    this._loadConfig();
    if (this.configCache.error && !(this.configCache.sections || []).length) return { ok: false, source, error: this.configCache.error };
    const nowFiles = (this.configCache.files || []).map((f) => f.raw).join('\n');
    const count = (t) => { const m = new Map(); for (const l of t.split('\n')) m.set(l, (m.get(l) || 0) + 1); return m; };
    const a = count(prevFiles); const b = count(nowFiles);
    let linesAdded = 0; let linesRemoved = 0;
    for (const [l, n] of b) linesAdded += Math.max(0, n - (a.get(l) || 0));
    for (const [l, n] of a) linesRemoved += Math.max(0, n - (b.get(l) || 0));
    const keys = (secs) => new Set((secs || []).flatMap((x) => [`${x.type} ${x.name}`, ...(x.servers || []).map((v) => `server ${x.name}/${v.name}`)]));
    const kb = keys(prevSections); const ka = keys(this.configCache.sections);
    const changed = prevFiles !== nowFiles;
    if (changed && before == null) this._event({ level: 'info', type: 'config_changed', message: `Configuration refreshed from the server: +${linesAdded} −${linesRemoved} lines` });
    await this.poll();
    return { ok: true, source, changed, linesAdded, linesRemoved, added: [...ka].filter((k) => !kb.has(k)), removed: [...kb].filter((k) => !ka.has(k)), loadedAt: this.configCache.loadedAt || Date.now(), files: (this.configCache.files || []).length };
  }

  _event(e) {
    const ev = { ts: Date.now(), instanceId: this.instance.id, instanceName: this.instance.name, ...e };
    this.events.unshift(ev);
    if (this.store) this.store.saveEvent(this.instance.id, ev);
    if (this.events.length > this.settings.eventLimit) this.events.length = this.settings.eventLimit;
    if (e.level !== 'info') this.notifier?.notify(ev);
    return ev;
  }

  async _poll() {
    const inst = this.instance;
    if (this.configSource() === 'url' && (!this.configFetch.at || Date.now() - this.configFetch.at > (inst.configRefreshMs || 300000))) await this._fetchConfig();
    this._loadConfig();
    const now = Date.now();
    let rows = [];
    let info = {};
    let error = null;
    let warnings = [];
    const hasSource = this.driver.hasSource(inst);

    if (hasSource) {
      try {
        const res = await this.driver.collect(inst, this.configCache, { demo: this.demo });
        rows = res.rows; info = res.info || {}; warnings = res.warnings || [];
        this.failures = 0;
        this.lastSuccess = now;
        if (this.reachable === false || this.alertedUnreachable) {
          this._event({ level: 'recovery', type: 'instance_recovered', message: 'Stats endpoint is reachable again' });
        }
        this.reachable = true;
        this.alertedUnreachable = false;
      } catch (e) {
        error = e.message;
        this.failures += 1;
        this.reachable = false;
        if (this.failures >= this.settings.alerts.minFailures && !this.alertedUnreachable) {
          this.alertedUnreachable = true;
          this._event({ level: 'critical', type: 'instance_unreachable', message: `Stats endpoint unreachable: ${error}` });
        }
        log.warn('poll failed', { instance: inst.id, error });
      }
    }

    const previousRows = this.snapshot ? this.snapshot.rows : [];
    const useRows = error ? previousRows : rows;
    if (!error && hasSource) { this._ingest(rows, now); this._deriveInfo(info, now); }

    const findings = this.driver.audit(this.configCache, useRows);
    const info2 = error && this.snapshot ? this.snapshot.info : info;

    this.snapshot = {
      instance: { id: inst.id, name: inst.name, type: inst.type, tags: inst.tags, labels: this.driver.labels, source: this.driver.sources(inst)[0] ? this.driver.sources(inst).join('+') : 'config-only' },
      ts: now,
      ok: !error,
      stale: Boolean(error) && previousRows.length > 0,
      error: error || (hasSource ? null : 'No stats source configured — showing configuration only'),
      warnings,
      failures: this.failures,
      lastSuccess: this.lastSuccess,
      pollIntervalMs: inst.pollIntervalMs,
      info: info2,
      rows: useRows,
      summary: this._summarize(useRows, info2),
      config: {
        path: this.configCache.path,
        error: this.configCache.error,
        loadedAt: this.configCache.loadedAt || null,
        source: this.configSource(), fetchedAt: this.configFetch.at, fetchError: this.configFetch.error,
        urls: (this.instance.configUrls || []).map((u) => { try { const x = new URL(u); return `${x.origin}${x.pathname}`; } catch { return ''; } }),
        files: (this.configCache.files || []).map((f) => ({ name: f.name, raw: f.raw })),
        sections: (this.configCache.sections || []).map(({ directives, ...rest }) => rest),
      },
      findings,
      findingsSummary: summarize(findings),
    };
    if (hasSource && !error) {
      const m = this.snapshot.summary;
      const sp = { t: now, rate: m.ratePerSec, srate: m.sessionRatePerSec, scur: m.sessions, e5xx: m.err5xxPerSec, inBps: m.bytesInPerSec, outBps: m.bytesOutPerSec,
        up: m.servers.up, down: m.servers.down, degraded: m.servers.degraded + m.servers.drain, total: m.servers.total, rtime: m.rtimeAvg };
      if (!this._baselined) { // first good poll: record where we started, so the timeline is never a blank page
        this._baselined = true;
        const sv = m.servers; const parts = [`${sv.up}/${sv.total} servers up`]; if (sv.down) parts.push(`${sv.down} down`); if (sv.degraded + sv.drain) parts.push(`${sv.degraded + sv.drain} degraded`);
        this._event({ level: 'info', type: 'monitoring_started', message: `GateLight started monitoring this instance: ${parts.join(', ')}` });
      }
      this.series.push(sp);
      if (this.series.length > this.settings.historyPoints) this.series.shift();
      if (this.store) this.store.save(this.instance.id, sp, this._batch);
    }
  }

  /** Request rate for sources that only expose cumulative counters (nginx stub_status). */
  _deriveInfo(info, now) {
    if (info.requestsTotal != null && this.prevInfo && now > this.prevInfo.t && this.prevInfo.requestsTotal != null) {
      info.reqPerSec = Math.max(0, (info.requestsTotal - this.prevInfo.requestsTotal) / ((now - this.prevInfo.t) / 1000));
    }
    this.prevInfo = { t: now, requestsTotal: info.requestsTotal };
  }

  /** Refill the in-memory history from the persistent store after a restart. */
  _hydrate() {
    if (!this.store) return;
    try {
      for (const [key, pts] of this.store.recent(this.instance.id, this.settings.historyPoints)) {
        if (key === SERIES_KEY) this.series = pts; else this.history.set(key, pts);
      }
      this.events = this.store.recentEvents(this.instance.id, this.settings.eventLimit).map((e) => ({ ...e, instanceName: this.instance.name }));
    } catch (e) { log.warn('Could not reload history', { instance: this.instance.id, error: String(e.message || e) }); }
  }

  /** Update derived per-row fields, history and detect transitions. */
  _ingest(rows, now) {
    const next = new Map();
    this._batch = [];
    for (const r of rows) {
      const key = rowKey(r);
      const prev = this.prev.get(key);
      r.state = statusClass(r.status);
      let rate = null;
      let e5 = null;
      // HTTP keep-alive makes `stot` (sessions/connections) undercount traffic; `req_tot` counts requests
      // where HAProxy provides it (frontends/backends in http mode). Servers and tcp proxies fall back to stot.
      const counter = r.req_tot != null ? r.req_tot : r.stot;
      if (prev && now > prev.t) {
        const dt = (now - prev.t) / 1000;
        if (counter != null && prev.counter != null) rate = Math.max(0, (counter - prev.counter) / dt);
        if (r.hrsp_5xx != null && prev.h5 != null) e5 = Math.max(0, (r.hrsp_5xx - prev.h5) / dt);
      }
      r.ratePerSec = rate;
      r.err5xxPerSec = e5;
      // new sessions per second, and bytes per second in/out (counters -> rates; reload-safe)
      const dtp = prev && now > prev.t ? (now - prev.t) / 1000 : null;
      const per = (cur, old) => (dtp && cur != null && old != null ? Math.max(0, (cur - old) / dtp) : null);
      r.sratePerSec = per(r.stot, prev && prev.stot); r.binPerSec = per(r.bin, prev && prev.bin); r.boutPerSec = per(r.bout, prev && prev.bout);

      let hist = this.history.get(key);
      if (!hist) { hist = []; this.history.set(key, hist); }
      const point = { t: now, scur: r.scur ?? 0, rate: rate ?? 0, srate: r.sratePerSec ?? 0, e5xx: e5 ?? 0, rtime: r.rtime ?? 0, inBps: r.binPerSec ?? 0, outBps: r.boutPerSec ?? 0, qcur: r.qcur ?? 0 };
      hist.push(point); this._batch.push({ key, point });
      if (hist.length > this.settings.historyPoints) hist.shift();
      r.spark = hist.slice(-SPARK_POINTS).map((h) => Math.round(h.rate * 100) / 100);

      if (prev && prev.state !== r.state) this._transition(r, prev.state);
      next.set(key, { t: now, counter, h5: r.hrsp_5xx, state: r.state, stot: r.stot, bin: r.bin, bout: r.bout });
    }
    // drop history for entities that vanished
    for (const key of this.history.keys()) if (!next.has(key)) this.history.delete(key);
    this.prev = next;
  }

  _transition(r, from) {
    const label = r.kind === 'server' ? `Server ${r.proxy}/${r.name}` : `${r.kind[0].toUpperCase()}${r.kind.slice(1)} ${r.proxy}`;
    const detail = r.check_status ? ` (${r.check_status}${r.last_chk ? `: ${r.last_chk}` : ''})` : '';
    let level = 'info';
    if (r.state === 'down') level = r.kind === 'server' ? 'warning' : 'critical';
    else if (r.state === 'up' && ['down', 'degraded'].includes(from)) level = 'recovery';
    else if (r.state === 'degraded' || r.state === 'drain') level = 'info';
    this._event({
      level, type: `${r.kind}_state`, proxy: r.proxy, name: r.name, from, to: r.state, rawStatus: r.status,
      message: `${label}: ${from.toUpperCase()} → ${r.state.toUpperCase()}${detail}`,
    });
  }

  _summarize(rows, info = {}) {
    const count = () => ({ up: 0, down: 0, maint: 0, drain: 0, degraded: 0, nocheck: 0, unknown: 0, total: 0 });
    const s = { servers: count(), backends: count(), frontends: count(), sessions: 0, ratePerSec: 0, sessionRatePerSec: 0, err5xxPerSec: 0, bytesIn: 0, bytesOut: 0, bytesInPerSec: 0, bytesOutPerSec: 0, rtimeAvg: 0 };
    let rtSum = 0; let rtN = 0;
    for (const r of rows) {
      const bucket = r.kind === 'server' ? s.servers : r.kind === 'backend' ? s.backends : r.kind === 'frontend' ? s.frontends : null;
      if (!bucket) continue;
      bucket[r.state || 'unknown'] += 1;
      bucket.total += 1;
      if (r.kind === 'frontend') {
        s.sessions += r.scur || 0;
        s.ratePerSec += r.ratePerSec || 0;
        s.bytesIn += r.bin || 0;
        s.bytesOut += r.bout || 0;
        s.sessionRatePerSec += r.sratePerSec || 0; s.bytesInPerSec += r.binPerSec || 0; s.bytesOutPerSec += r.boutPerSec || 0;
      }
      if (r.kind === 'server' && r.rtime > 0) { rtSum += r.rtime; rtN += 1; }
      if (r.kind === 'backend') s.err5xxPerSec += r.err5xxPerSec || 0;
    }
    s.rtimeAvg = rtN ? rtSum / rtN : 0;
    if (!rows.some((r) => r.kind === 'frontend' && r.ratePerSec != null)) {
      if (info.reqPerSec != null) s.ratePerSec = info.reqPerSec;
      if (info.activeConns != null) s.sessions = info.activeConns;
    }
    return s;
  }

  /** Everything the Graphs page needs in one request: instance-level samples plus the history of each frontend/backend/server. */
  getAllHistory(kinds, points, rangeMs, win = null, maxPoints = 360) {
    const rows = this.snapshot ? this.snapshot.rows : [];
    if (win) rangeMs = win.to - win.from;
    if (rangeMs && this.store) {
      const to = win ? win.to : Date.now(); const from = to - rangeMs;
      const bucket = Math.max(this.instance.pollIntervalMs || 0, Math.ceil(rangeMs / maxPoints));
      const data = this.store.range(this.instance.id, from, bucket, to);
      const entities = rows.filter((r) => kinds.includes(r.kind)).map((r) => ({ key: rowKey(r), kind: r.kind, proxy: r.proxy, name: r.name, state: r.state, points: data.get(rowKey(r)) || [] }));
      return { summary: data.get(SERIES_KEY) || [], entities, from, to, rangeMs, bucketMs: bucket, persisted: true };
    }
    if (win) { // no database: only what is still in memory
      const inWin = (a) => a.filter((p) => p.t >= win.from && p.t <= win.to);
      const entities = rows.filter((r) => kinds.includes(r.kind)).map((r) => ({ key: rowKey(r), kind: r.kind, proxy: r.proxy, name: r.name, state: r.state, points: inWin(this.history.get(rowKey(r)) || []) }));
      return { summary: inWin(this.series), entities, from: win.from, to: win.to, persisted: false };
    }
    if (rangeMs) points = Math.ceil(rangeMs / Math.max(1000, this.instance.pollIntervalMs || 5000));
    const n = Math.max(1, Math.min(points || this.settings.historyPoints, this.settings.historyPoints));
    const entities = rows.filter((r) => kinds.includes(r.kind)).map((r) => ({ key: rowKey(r), kind: r.kind, proxy: r.proxy, name: r.name, state: r.state, points: this.getHistory(rowKey(r), n) }));
    return { summary: this.series.slice(-n), entities, persisted: false };
  }

  getHistory(key, points) {
    const h = this.history.get(key) || [];
    return h.slice(-Math.max(1, Math.min(points || h.length, this.settings.historyPoints)));
  }
}

class Registry {
  constructor(settings, notifier, store = null) {
    this.settings = settings; this.notifier = notifier; this.store = store;
    this.pollers = new Map();
    for (const inst of settings.instances) this.pollers.set(inst.id, new InstancePoller(inst, settings, notifier, store));
  }

  start() { for (const p of this.pollers.values()) p.start(); }

  stop() { for (const p of this.pollers.values()) p.stop(); }

  get(id) { return this.pollers.get(id); }

  /** Add (or replace) an instance at runtime and start polling it. */
  add(instance) {
    const old = this.pollers.get(instance.id);
    if (old) old.stop();
    const p = new InstancePoller(instance, this.settings, this.notifier, this.store);
    this.pollers.set(instance.id, p);
    p.start();
    return p;
  }

  remove(id) {
    const p = this.pollers.get(id);
    if (!p) return false;
    p.stop();
    if (this.store) this.store.removeInstance(id);
    return this.pollers.delete(id);
  }

  list() {
    return [...this.pollers.values()].map((p) => {
      const s = p.snapshot;
      return {
        id: p.instance.id, name: p.instance.name, tags: p.instance.tags, managed: Boolean(p.instance.managed),
        type: p.instance.type, source: s ? s.instance.source : 'pending', ok: s ? s.ok : null, error: s ? s.error : null, lastSuccess: p.lastSuccess,
        serversDown: s ? s.summary.servers.down : 0, serversTotal: s ? s.summary.servers.total : 0,
        findings: s ? s.findingsSummary : null,
      };
    });
  }
}

module.exports = { InstancePoller, Registry, rowKey };

'use strict';
/**
 * Synthetic HAProxy stats generator so the UI can be explored (and demoed or
 * tested) without a live HAProxy. Traffic shape is derived from the real
 * configuration; one health-checked server flaps periodically.
 */
const { isFrontendLike, isBackendLike } = require('./haproxyConfig');

const HEADER = 'pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,type,rate,rate_max,check_status,check_code,check_duration,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,req_rate,req_tot,qtime,ctime,rtime,ttime';

function hash(str) { let h = 2166136261; for (const c of str) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; }

class DemoSource {
  constructor(sections, getSections) {
    this.getSections = getSections || (() => sections);
    this.counters = new Map();
    this.start = Date.now();
    this.lastTick = Date.now();
  }

  _c(key) {
    if (!this.counters.has(key)) this.counters.set(key, { stot: Math.floor(Math.random() * 50000), bin: 0, bout: 0, h2: 0, h3: 0, h4: 0, h5: 0 });
    return this.counters.get(key);
  }

  fetch() {
    const sections = this.getSections();
    const now = Date.now();
    const dt = Math.max(0.5, (now - this.lastTick) / 1000);
    this.lastTick = now;
    const minute = Math.floor((now - this.start) / 30000);
    const rows = [];

    const traffic = (key, weight) => {
      const c = this._c(key);
      const burst = 0.6 + 0.4 * Math.sin((now / 9000) + (hash(key) % 7));
      const rate = Math.max(0, Math.round(weight * burst * (0.8 + Math.random() * 0.4)));
      const n = Math.round(rate * dt);
      c.stot += n; c.bin += n * 900; c.bout += n * 14000;
      const bad = hash(key) % 5 === 0 ? 0.04 : 0.004;
      const e5 = Math.round(n * bad * (Math.random() < 0.15 ? 6 : 1));
      c.h5 += e5; c.h4 += Math.round(n * 0.03); c.h3 += Math.round(n * 0.05); c.h2 += n - e5;
      return { c, rate };
    };

    const q = (v) => (/[,"]/.test(v) ? `"${String(v).replace(/"/g, '""')}"` : v);
    const line = (o) => [q(o.px), q(o.sv), 0, o.qmax || 0, o.scur, o.smax, o.slim, o.c.stot, o.c.bin, o.c.bout, 0, 0, 0, o.econ || 0, o.eresp || 0,
      o.status, o.weight ?? '', o.act ?? '', o.bck ?? '', o.chkfail ?? '', o.chkdown ?? '', o.lastchg ?? 3600, o.downtime ?? 0, o.type,
      o.rate, o.rateMax, o.cs ?? '', o.cc ?? '', o.cd ?? '', o.c.h2, o.c.h3, o.c.h4, o.c.h5, o.rate, o.c.stot, o.qt ?? '', o.ct ?? '', o.rt ?? '', o.tt ?? ''].join(',');

    const fes = sections.filter(isFrontendLike);
    const routeTargets = new Map();
    for (const fe of fes) for (const r of fe.routes.filter((x) => !x.commented && !x.dynamic)) {
      routeTargets.set(r.target, (routeTargets.get(r.target) || 0) + (r.type === 'default' ? 60 : 8));
    }

    for (const fe of fes) {
      const w = fe.routes.some((r) => !r.commented) || fe.type === 'listen' ? 40 + (hash(fe.name) % 80) : 0;
      const { c, rate } = traffic(`fe:${fe.name}`, w);
      rows.push(line({ px: fe.name, sv: 'FRONTEND', scur: Math.round(rate * 0.3), smax: rate * 2, slim: 10000, c, status: 'OPEN', type: 0, rate, rateMax: rate * 2 }));
    }

    for (const be of sections.filter(isBackendLike)) {
      const servers = be.servers.filter((s) => !s.commented && !s.template);
      const base = be.type === 'listen' ? 4 : (routeTargets.get(be.name) || 0);
      const active = [];
      servers.forEach((s) => {
        // Health-checked, non-backup servers flap: down for 1 of every 6 half-minutes (one server per backend).
        const flaps = s.check && servers.indexOf(s) === servers.length - 1 && servers.length > 1 && (minute + hash(be.name)) % 6 === 0;
        const status = s.disabled ? 'MAINT' : flaps ? 'DOWN' : (s.check ? 'UP' : 'no check');
        const isUp = status === 'UP' || status === 'no check';
        const share = isUp && !s.backup ? base / Math.max(1, servers.filter((x) => !x.backup).length) : 0;
        const { c, rate } = traffic(`srv:${be.name}/${s.name}`, share);
        active.push({ c, rate, isUp });
        rows.push(line({
          px: be.name, sv: s.name, scur: Math.round(rate * 0.2), smax: rate * 3, slim: s.opts.maxconn || '', c, status, weight: s.weight ?? 1,
          act: s.backup ? 0 : 1, bck: s.backup ? 1 : 0, chkfail: flaps ? 3 : 0, chkdown: flaps ? 1 : 0, lastchg: 600, downtime: flaps ? 30 : 0,
          type: 2, rate, rateMax: rate * 3, cs: s.check ? (flaps ? 'L4CON' : 'L7OK') : '', cc: s.check ? (flaps ? '' : 200) : '', cd: s.check ? 3 : '',
          econ: flaps ? 5 : 0, qt: 0, ct: 1, rt: 20 + (hash(s.name) % 80), tt: 40 + (hash(s.name) % 200),
        }));
      });
      const agg = { stot: 0, bin: 0, bout: 0, h2: 0, h3: 0, h4: 0, h5: 0 };
      let rate = 0;
      for (const a of active) { for (const k of Object.keys(agg)) agg[k] += a.c[k]; rate += a.rate; }
      const upCount = servers.filter((_, i) => active[i].isUp).length;
      rows.push(line({
        px: be.name, sv: 'BACKEND', scur: Math.round(rate * 0.2), smax: rate * 3, slim: 10000, c: agg,
        status: servers.length && upCount === 0 ? 'DOWN' : 'UP', weight: servers.length, act: upCount, bck: 0, type: 1, rate, rateMax: rate * 3,
        qt: 0, ct: 1, rt: 50, tt: 120,
      }));
    }

    return { csv: `# ${HEADER}\n${rows.join('\n')}\n`, info: [
      'Version: 2.8.5-demo', `Pid: 1`, `Uptime: ${Math.floor((now - this.start) / 1000)}s`, `Uptime_sec: ${Math.floor((now - this.start) / 1000)}`,
      'Nbthread: 4', 'Maxconn: 500000', `CurrConns: ${Math.round(40 + Math.random() * 30)}`, `ConnRate: ${Math.round(20 + Math.random() * 15)}`,
      'Idle_pct: 96', 'Nbproc: 1', 'Memmax: unlimited', 'Ulimit-n: 1000062', 'Maxsock: 1000062', 'Maxpipes: 0', 'CurrPipes: 0', 'Tasks: 992', 'Run_queue: 1',
    ].join('\n') };
  }
}

module.exports = { DemoSource };

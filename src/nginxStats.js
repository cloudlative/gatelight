'use strict';
/**
 * NGINX runtime data sources, in increasing fidelity:
 *   1. stub_status   (open source)  -> global connection/request counters
 *   2. NGINX Plus API               -> per-zone and per-upstream-peer stats + health
 *   3. active TCP probe (optional)  -> per-upstream-server reachability, works on any NGINX
 * Output rows use the same shape as parseStatsCsv() so the rest of the pipeline is shared.
 */
const net = require('net');
const { httpRequest } = require('./transport');

function parseStubStatus(text) {
  const t = String(text || '');
  const active = t.match(/Active connections:\s*(\d+)/i);
  const counters = t.match(/server accepts handled requests\s*\n\s*(\d+)\s+(\d+)\s+(\d+)/i);
  const rw = t.match(/Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)/i);
  if (!active || !counters) return null;
  return {
    activeConns: Number(active[1]), accepts: Number(counters[1]), handled: Number(counters[2]), requestsTotal: Number(counters[3]),
    reading: rw ? Number(rw[1]) : null, writing: rw ? Number(rw[2]) : null, waiting: rw ? Number(rw[3]) : null,
  };
}

const PEER_STATE = { up: 'UP', down: 'DOWN', draining: 'DRAIN', unavail: 'UNAVAIL', checking: 'CHECKING', unhealthy: 'DOWN' };

const blank = () => ({
  qcur: null, qmax: null, scur: null, smax: null, slim: null, stot: null, bin: null, bout: null, weight: null, lastchg: null, downtime: null,
  hrsp_1xx: null, hrsp_2xx: null, hrsp_3xx: null, hrsp_4xx: null, hrsp_5xx: null, rtime: null, ctime: null, ttime: null, econ: null, eresp: null,
  check_status: '', last_chk: '', check_code: null, mode: '',
});

async function plusGet(base, p, inst) {
  const res = await httpRequest(`${base.replace(/\/+$/, '')}${p}`, { username: inst.username, password: inst.password, timeout: inst.timeoutMs, insecureTls: inst.insecureTls });
  if (res.status !== 200) throw new Error(`NGINX Plus API ${p} returned HTTP ${res.status}`);
  return JSON.parse(res.body);
}

function hr(responses, rows) {
  const r = responses || {};
  rows.hrsp_1xx = r['1xx'] ?? null; rows.hrsp_2xx = r['2xx'] ?? null; rows.hrsp_3xx = r['3xx'] ?? null; rows.hrsp_4xx = r['4xx'] ?? null; rows.hrsp_5xx = r['5xx'] ?? null;
}

/** Collect from the NGINX Plus REST API and map to rows using the parsed config as a naming guide. */
async function collectPlus(inst, sections) {
  const base = inst.plusApiUrl;
  const versions = await plusGet(base, '/api', inst);
  const v = Math.max(...versions.filter(Number.isFinite));
  const ver = Number.isFinite(v) ? v : 9;
  const [nginxInfo, conns, zones, ups, sUps] = await Promise.all([
    plusGet(base, `/api/${ver}/nginx`, inst).catch(() => ({})),
    plusGet(base, `/api/${ver}/connections`, inst).catch(() => ({})),
    plusGet(base, `/api/${ver}/http/server_zones`, inst).catch(() => ({})),
    plusGet(base, `/api/${ver}/http/upstreams`, inst).catch(() => ({})),
    plusGet(base, `/api/${ver}/stream/upstreams`, inst).catch(() => ({})),
  ]);
  const rows = [];
  const zoneToFe = new Map();
  for (const s of sections.filter((x) => x.type === 'frontend' && x.zone)) zoneToFe.set(s.zone, s.name);
  for (const [zone, z] of Object.entries(zones)) {
    const r = { ...blank(), proxy: zoneToFe.get(zone) || zone, name: 'FRONTEND', kind: 'frontend', status: 'OPEN', scur: z.processing ?? null, stot: z.requests ?? null, bin: z.received ?? null, bout: z.sent ?? null };
    hr(z.responses, r); r.hrsp_5xx = z.responses ? z.responses['5xx'] : null;
    rows.push(r);
  }
  const addUpstreams = (obj) => {
    for (const [name, u] of Object.entries(obj)) {
      const agg = { ...blank(), proxy: name, name: 'BACKEND', kind: 'backend', status: 'UP', scur: 0, stot: 0, bin: 0, bout: 0, hrsp_5xx: 0 };
      let anyUp = false;
      for (const p of u.peers || []) {
        const r = {
          ...blank(), proxy: name, name: p.server || p.name, kind: 'server', status: PEER_STATE[p.state] || String(p.state || '').toUpperCase(),
          scur: p.active ?? null, stot: p.requests ?? p.connections ?? null, bin: p.received ?? null, bout: p.sent ?? null, weight: p.weight ?? null,
          downtime: p.downtime != null ? Math.round(p.downtime / 1000) : null, rtime: p.response_time ?? null, ctime: p.connect_time ?? null, ttime: p.header_time ?? null,
          check_status: p.health_checks ? (p.health_checks.last_passed === false ? 'HC failed' : p.health_checks.checks ? 'HC ok' : '') : '', econ: p.fails ?? null,
          qcur: null,
        };
        if (p.selected) r.lastchg = Math.max(0, Math.round((Date.now() - Date.parse(p.selected)) / 1000));
        hr(p.responses, r);
        agg.scur += r.scur || 0; agg.stot += r.stot || 0; agg.bin += r.bin || 0; agg.bout += r.bout || 0; agg.hrsp_5xx += r.hrsp_5xx || 0;
        for (const k of ['hrsp_2xx', 'hrsp_3xx', 'hrsp_4xx']) agg[k] = (agg[k] || 0) + (r[k] || 0);
        if (r.status === 'UP') anyUp = true;
        rows.push(r);
      }
      agg.status = (u.peers || []).length && !anyUp ? 'DOWN' : 'UP';
      agg.qcur = u.queue ? u.queue.size : null;
      rows.push(agg);
    }
  };
  addUpstreams(ups); addUpstreams(sUps);
  return {
    rows,
    info: {
      version: nginxInfo.version || null, uptimeSec: nginxInfo.load_timestamp ? Math.round((Date.now() - Date.parse(nginxInfo.load_timestamp)) / 1000) : null,
      activeConns: conns.active ?? null, requestsTotal: Object.values(zones).reduce((a, z) => a + (z.requests || 0), 0) || null, plus: true, build: nginxInfo.build || null,
    },
  };
}

// ------------------------------------------------------------------ probing
function splitHostPort(addr) {
  if (!addr || /\$/.test(addr)) return null;
  if (addr.startsWith('unix:')) return { socketPath: addr.slice(5) };
  const m = addr.match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
  if (m) return { host: m[1].replace(/^\[|\]$/g, ''), port: Number(m[2]) };
  return { host: addr.replace(/^\[|\]$/g, ''), port: 80 };
}

function tcpProbe(target, timeout) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const sock = net.createConnection(target.socketPath ? { path: target.socketPath } : { host: target.host, port: target.port });
    const done = (ok, msg) => { sock.destroy(); resolve({ ok, ms: Date.now() - t0, msg }); };
    sock.setTimeout(timeout, () => done(false, `timeout ${timeout}ms`));
    sock.once('connect', () => done(true, 'TCP connect ok'));
    sock.once('error', (e) => done(false, e.code || e.message));
  });
}

/** Probe all upstream servers (bounded concurrency). Returns server + backend rows. */
async function probeUpstreams(inst, sections, { limit = 400, concurrency = 25 } = {}) {
  const jobs = [];
  for (const be of sections.filter((s) => s.type === 'backend')) {
    for (const sv of be.servers) { const t = splitHostPort(sv.address); if (t && jobs.length < limit) jobs.push({ be, sv, t }); }
  }
  const results = [];
  let i = 0;
  const worker = async () => {
    while (i < jobs.length) { const j = jobs[i++]; results.push({ ...j, res: await tcpProbe(j.t, inst.probeTimeoutMs || 1500) }); }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, jobs.length) }, worker));

  const rows = [];
  const byBe = new Map();
  for (const { be, sv, res } of results) {
    const r = {
      ...blank(), proxy: be.name, name: sv.name, kind: 'server', weight: sv.weight ?? 1,
      status: sv.disabled ? 'MAINT' : res.ok ? 'UP' : 'DOWN', check_status: res.ok ? 'TCP probe' : 'TCP probe failed', last_chk: res.ok ? `${res.ms} ms` : res.msg, rtime: res.ok ? res.ms : null,
    };
    rows.push(r);
    const b = byBe.get(be.name) || [];
    b.push(r); byBe.set(be.name, b);
  }
  for (const [name, rs] of byBe) {
    const up = rs.filter((r) => r.status === 'UP').length;
    rows.push({ ...blank(), proxy: name, name: 'BACKEND', kind: 'backend', status: up ? 'UP' : 'DOWN', check_status: `${up}/${rs.length} reachable` });
  }
  return rows;
}

/** Combine every enabled source for an NGINX instance. */
async function collectNginx(inst, sections) {
  let rows = []; let info = {};
  const errors = [];
  if (inst.plusApiUrl) {
    try { const p = await collectPlus(inst, sections); rows = p.rows; info = p.info; } catch (e) { errors.push(`Plus API: ${e.message}`); }
  }
  if (inst.statsUrl) {
    try {
      const res = await httpRequest(inst.statsUrl, { username: inst.username, password: inst.password, timeout: inst.timeoutMs, insecureTls: inst.insecureTls });
      if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
      const stub = parseStubStatus(res.body);
      if (!stub) throw new Error('response is not stub_status output');
      const sv = String(res.headers.server || '').match(/^nginx\/(\S+)/i);
      info = { ...stub, ...info, activeConns: stub.activeConns, version: info.version || (sv ? sv[1] : null) };
    } catch (e) { errors.push(`stub_status: ${e.message}`); }
  }
  if (inst.probe) {
    // Plus peers already carry health; probe only upstream servers we have no row for.
    const have = new Set(rows.map((r) => `${r.proxy}/${r.name}`));
    const probed = await probeUpstreams(inst, sections).catch((e) => { errors.push(`probe: ${e.message}`); return []; });
    for (const r of probed) if (!have.has(`${r.proxy}/${r.name}`)) rows.push(r);
  }
  const hasSource = Boolean(inst.plusApiUrl || inst.statsUrl || inst.probe);
  if (hasSource && !rows.length && !Object.keys(info).length) throw new Error(errors.join('; ') || 'no data returned');
  return { rows, info, warnings: errors };
}

module.exports = { parseStubStatus, collectNginx, collectPlus, probeUpstreams, tcpProbe, splitHostPort };

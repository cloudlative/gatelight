'use strict';
/**
 * Caddy runtime data, read-only, from the admin API (https://caddyserver.com/docs/api). inst.statsUrl (or inst.adminUrl)
 * is the admin base URL, e.g. http://127.0.0.1:2019.
 *
 *   GET /reverse_proxy/upstreams  [{ address, num_requests, fails }]  (modules/caddyhttp/reverseproxy/admin.go, since 2.4)
 *       num_requests = requests in flight to that upstream; fails = failures remembered by passive health checks
 *   GET /metrics                  Prometheus text when metrics are enabled: caddy_reverse_proxy_upstreams_healthy{upstream}
 *                                 (active health checks), caddy_http_requests_total, caddy_http_requests_in_flight
 *       (metrics may also be served elsewhere with the `metrics` directive: inst.metricsUrl)
 *   GET /config/                  optional (inst.readConfig), only to report what is running
 *
 * Rows use the HAProxy stats row shape; proxy / name are the backend section and server names of the parsed config so
 * the topology joins them. Upstreams the config does not know go into a backend named "(admin API)".
 * Status: healthy metric 1 -> UP, 0 -> DOWN; otherwise, with health checks configured, fails >= max_fails -> DOWN
 * (passive), fails > 0 -> UP with "N recent failures"; without any health check -> NO CHECK.
 */
const { httpRequest } = require('../../transport');

const blank = () => ({
  qcur: null, qmax: null, scur: null, smax: null, slim: null, stot: null, req_tot: null, bin: null, bout: null, weight: null, lastchg: null, downtime: null,
  hrsp_1xx: null, hrsp_2xx: null, hrsp_3xx: null, hrsp_4xx: null, hrsp_5xx: null, rtime: null, ctime: null, ttime: null, econ: null, eresp: null,
  check_status: '', last_chk: '', check_code: null, mode: 'http', addr: '',
});
const UNKNOWN = '(admin API)';

const base = (inst) => String(inst.statsUrl || inst.adminUrl || '').replace(/\/+$/, '');
const hasSource = (inst) => Boolean(inst && (inst.statsUrl || inst.adminUrl || inst.metricsUrl));
const sources = (inst) => [...((inst && (inst.statsUrl || inst.adminUrl)) ? ['admin-api'] : []), ...((inst && (inst.metricsUrl || inst.statsUrl || inst.adminUrl)) ? ['metrics'] : [])];

async function get(url, inst) {
  const res = await httpRequest(url, { username: inst.username, password: inst.password, timeout: inst.timeoutMs, insecureTls: inst.insecureTls, headers: { Accept: 'application/json, text/plain;q=0.9' } });
  if (res.status !== 200) throw new Error(`${url.replace(/\?.*$/, '')} returned HTTP ${res.status}`);
  return res;
}

/** Prometheus text exposition -> [{ name, labels, value }] (only the families we use). */
function parseMetrics(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!line || line[0] === '#') continue;
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)/.exec(line);
    if (!m || !/^(caddy_|process_start_time_seconds)/.test(m[1])) continue;
    const labels = {};
    if (m[2]) for (const l of m[2].matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g)) labels[l[1]] = l[2].replace(/\\(.)/g, '$1');
    const value = Number(m[3]);
    if (Number.isFinite(value)) out.push({ name: m[1], labels, value });
  }
  return out;
}

/** Normalised forms of an upstream address so admin API keys and config addresses meet. */
function keys(addr) {
  const a = String(addr || '').toLowerCase().replace(/^[a-z0-9+]+:\/\//, '').replace(/\/.*$/, '');
  const out = new Set([a]);
  if (a.startsWith(':')) out.add(`localhost${a}`);
  if (a.startsWith('localhost:')) { out.add(a.slice(9)); out.add(`127.0.0.1${a.slice(9)}`); }
  if (a.startsWith('127.0.0.1:')) out.add(`localhost${a.slice(9)}`);
  if (!/:\d+$/.test(a) && a) out.add(`${a}:80`);
  return [...out];
}

function statusOf({ healthy, fails, server, backend }) {
  if (healthy === 1) return { status: 'UP', check: fails > 0 ? `L7OK, ${fails} recent failure${fails === 1 ? '' : 's'}` : 'L7OK (active health check)' };
  if (healthy === 0) return { status: 'DOWN', check: 'active health check failing' };
  const maxFails = Number(backend && backend.passiveHealth && backend.passiveHealth.max_fails) || 1;
  if (server && server.check) {
    if (backend && backend.passiveHealth && fails >= maxFails) return { status: 'DOWN', check: `passive: ${fails} failure${fails === 1 ? '' : 's'} (max_fails ${maxFails})` };
    return { status: 'UP', check: fails > 0 ? `degraded: ${fails} recent failure${fails === 1 ? '' : 's'}` : 'checked by Caddy' };
  }
  return { status: fails > 0 ? 'UP' : 'NO CHECK', check: fails > 0 ? `${fails} recent failure${fails === 1 ? '' : 's'}` : 'no health check configured' };
}

/**
 * @param inst  instance settings (statsUrl/adminUrl = admin base URL, metricsUrl optional, readConfig optional)
 * @param cache parsed config ({ sections }) used to name rows
 */
async function collect(inst, cache = {}, ctx = {}) {
  const sections = (cache && cache.sections) || (ctx && ctx.sections) || [];
  const errors = []; const info = { source: 'admin-api' };
  const b = base(inst);
  let upstreams = null; let metrics = null; let running = null;
  if (b) {
    try { upstreams = JSON.parse((await get(`${b}/reverse_proxy/upstreams`, inst)).body); if (!Array.isArray(upstreams)) throw new Error('unexpected /reverse_proxy/upstreams response'); } catch (e) { errors.push(`admin API: ${e.message}`); }
    if (inst.readConfig) { try { running = JSON.parse((await get(`${b}/config/`, inst)).body); } catch (e) { errors.push(`config: ${e.message}`); } }
  }
  const mUrl = inst.metricsUrl || (b ? `${b}/metrics` : null);
  if (mUrl) { try { metrics = parseMetrics((await get(mUrl, inst)).body); } catch (e) { if (inst.metricsUrl) errors.push(`metrics: ${e.message}`); } }

  const healthy = new Map();
  if (metrics) {
    for (const m of metrics) if (m.name === 'caddy_reverse_proxy_upstreams_healthy' && m.labels.upstream) for (const k of keys(m.labels.upstream)) healthy.set(k, m.value);
    const req = metrics.filter((m) => m.name === 'caddy_http_requests_total');
    if (req.length) info.requestsTotal = req.reduce((a, m) => a + m.value, 0);
    const codes = metrics.filter((m) => m.name === 'caddy_http_request_duration_seconds_count' && m.labels.code);
    if (codes.length) { info.responses = {}; for (const m of codes) { const cls = `${String(m.labels.code)[0]}xx`; info.responses[cls] = (info.responses[cls] || 0) + m.value; } }
    const inflight = metrics.filter((m) => m.name === 'caddy_http_requests_in_flight');
    if (inflight.length) info.activeRequests = inflight.reduce((a, m) => a + m.value, 0);
    const start = metrics.find((m) => m.name === 'process_start_time_seconds');
    if (start) info.uptimeSec = Math.max(0, Math.round(Date.now() / 1000 - start.value));
    info.metrics = true;
  }
  if (running) {
    const servers = running.apps && running.apps.http && running.apps.http.servers ? Object.keys(running.apps.http.servers) : [];
    info.runningConfig = { servers, listen: servers.flatMap((s) => running.apps.http.servers[s].listen || []), admin: running.admin ? running.admin.listen || 'localhost:2019' : 'localhost:2019' };
  }

  const admin = new Map(); // key -> entry
  for (const u of upstreams || []) for (const k of keys(u.address)) if (!admin.has(k)) admin.set(k, u);
  const seen = new Set();
  const rows = [];
  for (const be of sections.filter((s) => s.type === 'backend')) {
    const srvRows = [];
    for (const sv of be.servers || []) {
      const ks = keys(sv.address).concat(sv.opts && sv.opts.dial ? keys(sv.opts.dial) : []);
      const entry = ks.map((k) => admin.get(k)).find(Boolean);
      const h = ks.map((k) => healthy.get(k)).find((x) => x !== undefined);
      if (entry) seen.add(entry);
      if (!entry && h === undefined && !upstreams) continue;
      const fails = entry ? Number(entry.fails) || 0 : 0;
      const st = statusOf({ healthy: h, fails, server: sv, backend: be });
      srvRows.push({ ...blank(), proxy: be.name, name: sv.name, kind: 'server', status: entry || h !== undefined ? st.status : 'NO CHECK', scur: entry ? Number(entry.num_requests) || 0 : null, econ: entry ? fails : null, weight: sv.weight, check_status: entry || h !== undefined ? st.check : 'not in the admin API (not used since the last config load)', addr: sv.address });
    }
    if (!srvRows.length) continue;
    rows.push(...srvRows);
    const up = srvRows.filter((r) => r.status === 'UP' || r.status === 'NO CHECK').length;
    rows.push({ ...blank(), proxy: be.name, name: 'BACKEND', kind: 'backend', status: up ? 'UP' : 'DOWN', scur: srvRows.reduce((a, r) => a + (r.scur || 0), 0), econ: srvRows.reduce((a, r) => a + (r.econ || 0), 0), check_status: `${up}/${srvRows.length} available`, balance: be.balance });
  }
  const extra = (upstreams || []).filter((u) => !seen.has(u));
  if (extra.length) {
    for (const u of extra) {
      const h = keys(u.address).map((k) => healthy.get(k)).find((x) => x !== undefined);
      const st = statusOf({ healthy: h, fails: Number(u.fails) || 0, server: { check: h !== undefined }, backend: null });
      rows.push({ ...blank(), proxy: UNKNOWN, name: u.address, kind: 'server', status: st.status, scur: Number(u.num_requests) || 0, econ: Number(u.fails) || 0, check_status: st.check, addr: u.address });
    }
    const rs = rows.filter((r) => r.proxy === UNKNOWN);
    rows.push({ ...blank(), proxy: UNKNOWN, name: 'BACKEND', kind: 'backend', status: rs.some((r) => r.status !== 'DOWN') ? 'UP' : 'DOWN', scur: rs.reduce((a, r) => a + (r.scur || 0), 0), check_status: `${rs.length} upstream${rs.length === 1 ? '' : 's'} not in the parsed config` });
  }
  info.upstreams = upstreams ? upstreams.length : null;
  if (!rows.length && !upstreams && !metrics && errors.length) throw new Error(errors.join('; '));
  return { rows, info, warnings: errors };
}

module.exports = { hasSource, sources, collect, parseMetrics, statusOf, keys, UNKNOWN };

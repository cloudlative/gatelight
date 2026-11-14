'use strict';
/**
 * Traefik runtime data (read-only GETs through src/transport.js):
 *   - the API (operations/api: /api/version, /api/overview, /api/entrypoints, /api/http|tcp/routers|services),
 *     paginated with ?page=&per_page= and the X-Next-Page header; services carry serverStatus { url: 'UP'|'DOWN' }
 *   - Prometheus metrics (observability/metrics/prometheus) when enabled: traefik_entrypoint_*, traefik_service_*,
 *     traefik_service_server_up -> request counters, status classes, latency, open connections, bytes
 * inst.statsUrl = the API base (e.g. http://127.0.0.1:8080); inst.metricsUrl overrides <base>/metrics.
 * Rows use the HAProxy stats row shape; proxy / name match the parsed config (provider suffixes stripped).
 */
const { httpRequest } = require('../../transport');

const blank = () => ({
  qcur: null, qmax: null, scur: null, smax: null, slim: null, stot: null, bin: null, bout: null, weight: null, lastchg: null, downtime: null,
  req_tot: null, hrsp_1xx: null, hrsp_2xx: null, hrsp_3xx: null, hrsp_4xx: null, hrsp_5xx: null, rtime: null, ctime: null, ttime: null,
  econ: null, eresp: null, check_status: '', last_chk: '', check_code: null, mode: '', addr: '',
});

const base = (inst) => String(inst.statsUrl || '').replace(/\/+$/, '').replace(/\/api(\/.*)?$/, '').replace(/\/dashboard\/?.*$/, '');
const hasSource = (inst) => Boolean(inst && (inst.statsUrl || inst.metricsUrl));
const sources = (inst) => [inst.statsUrl && 'traefik-api', (inst.metricsUrl || inst.statsUrl) && 'prometheus'].filter(Boolean);

async function getJson(inst, url) {
  const res = await httpRequest(url, { username: inst.username, password: inst.password, timeout: inst.timeoutMs, insecureTls: inst.insecureTls, headers: { Accept: 'application/json' } });
  if (res.status === 401 || res.status === 403) throw new Error(`Traefik API rejected the credentials (HTTP ${res.status})`);
  if (res.status !== 200) throw new Error(`Traefik API ${new URL(url).pathname} returned HTTP ${res.status}`);
  try { return { body: JSON.parse(res.body), headers: res.headers }; } catch { throw new Error(`Traefik API ${new URL(url).pathname} did not return JSON (is the URL the API base, e.g. http://127.0.0.1:8080?)`); }
}
/** All pages of a list endpoint. */
async function getList(inst, b, p) {
  const out = []; let page = 1;
  for (let i = 0; i < 50; i++) {
    const r = await getJson(inst, `${b}${p}?per_page=100&page=${page}`);
    if (!Array.isArray(r.body)) break;
    out.push(...r.body);
    const next = Number(r.headers['x-next-page']);
    if (!next || next <= page) break;
    page = next;
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ Prometheus text
/** Parse the Prometheus text exposition format: [{ name, labels, value }]. */
function parseMetrics(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!line || line[0] === '#') continue;
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+(\S+)/.exec(line);
    if (!m) continue;
    const labels = {};
    if (m[3]) for (const l of m[3].matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g)) labels[l[1]] = l[2].replace(/\\(.)/g, '$1');
    const v = Number(m[4]);
    if (Number.isFinite(v)) out.push({ name: m[1], labels, value: v });
  }
  return out;
}
/** Per-entity totals from the metrics: { [entity]: { req, codes: {2xx..}, durSum, durCount, open, bin, bout } }. */
function aggregate(samples, prefix, label) {
  const agg = {};
  const get = (k) => { if (!agg[k]) agg[k] = { req: 0, codes: {}, durSum: 0, durCount: 0, open: 0, bin: 0, bout: 0, any: false }; return agg[k]; };
  for (const s of samples) {
    if (!s.name.startsWith(prefix)) continue;
    const key = s.labels[label]; if (!key) continue;
    const a = get(key); a.any = true;
    const n = s.name.slice(prefix.length);
    if (n === 'requests_total') { a.req += s.value; const cls = `${String(s.labels.code || '0')[0]}xx`; a.codes[cls] = (a.codes[cls] || 0) + s.value; }
    else if (n === 'request_duration_seconds_sum') a.durSum += s.value;
    else if (n === 'request_duration_seconds_count') a.durCount += s.value;
    else if (n === 'open_connections') a.open += s.value;
    else if (n === 'requests_bytes_total') a.bin += s.value;
    else if (n === 'responses_bytes_total') a.bout += s.value;
  }
  return agg;
}
const applyAgg = (row, a) => {
  if (!a || !a.any) return;
  row.req_tot = Math.round(a.req); row.stot = Math.round(a.req); row.scur = Math.round(a.open);
  for (const c of ['1xx', '2xx', '3xx', '4xx', '5xx']) row[`hrsp_${c}`] = Math.round(a.codes[c] || 0);
  if (a.durCount) row.rtime = Math.round((a.durSum / a.durCount) * 1000);
  if (a.bin) row.bin = Math.round(a.bin); if (a.bout) row.bout = Math.round(a.bout);
};

// ------------------------------------------------------------------------------------------------ name joining
const strip = (n) => String(n || '').replace(/@[^@]*$/, '');
/** Map a runtime name ("api-v2@file", "whoami-myproject@docker") to the config section name. */
function joiner(names) {
  const set = new Set(names);
  return (runtime) => {
    const n = String(runtime || '');
    if (set.has(n)) return n;
    const b = strip(n);
    if (set.has(b)) return b;
    if (/@docker$/.test(n)) { const c = names.find((x) => b.startsWith(`${x}-`)); if (c) return c; } // compose: <service>-<project>
    return b;
  };
}
const hostPort = (url) => { const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/?#]+)/i.exec(String(url || '')); return m ? m[1] : String(url || ''); };
const redactUrl = (u) => String(u || '').replace(/(:\/\/[^:/@\s]+:)([^@\s]+)(@)/, '$1***$3');

async function collect(inst, cache = {}, ctx = {}) {
  void ctx;
  const sections = (cache && cache.sections) || [];
  const b = base(inst);
  const warnings = []; const rows = []; const info = {};
  let services = []; let tcpServices = []; let routers = []; let tcpRouters = []; let entryPoints = []; let overview = null;
  if (inst.statsUrl) {
    try {
      const v = await getJson(inst, `${b}/api/version`).catch(() => null);
      if (v && v.body) { info.version = v.body.Version || v.body.version || null; info.codename = v.body.Codename || null; if (v.body.startDate) info.uptimeSec = Math.max(0, Math.round((Date.now() - Date.parse(v.body.startDate)) / 1000)) || null; }
      [overview, entryPoints, routers, services, tcpRouters, tcpServices] = await Promise.all([
        getJson(inst, `${b}/api/overview`).then((r) => r.body).catch((e) => { warnings.push(`overview: ${e.message}`); return null; }),
        getList(inst, b, '/api/entrypoints').catch(() => []),
        getList(inst, b, '/api/http/routers'),
        getList(inst, b, '/api/http/services'),
        getList(inst, b, '/api/tcp/routers').catch(() => []),
        getList(inst, b, '/api/tcp/services').catch(() => []),
      ]);
    } catch (e) { warnings.push(`api: ${e.message}`); if (!inst.metricsUrl) throw e; }
  }
  let samples = [];
  const metricsUrl = inst.metricsUrl || (b ? `${b}/metrics` : null);
  if (metricsUrl) {
    try {
      const res = await httpRequest(metricsUrl, { username: inst.username, password: inst.password, timeout: inst.timeoutMs, insecureTls: inst.insecureTls });
      if (res.status === 200 && /traefik_/.test(res.body)) samples = parseMetrics(res.body);
      else if (inst.metricsUrl) warnings.push(`metrics: HTTP ${res.status}`);
    } catch (e) { if (inst.metricsUrl) warnings.push(`metrics: ${e.message}`); }
  }
  const epAgg = aggregate(samples, 'traefik_entrypoint_', 'entrypoint');
  const svcAgg = aggregate(samples, 'traefik_service_', 'service');
  const serverUp = new Map(samples.filter((s) => s.name === 'traefik_service_server_up').map((s) => [`${s.labels.service}|${s.labels.url}`, s.value]));

  const feNames = sections.filter((s) => s.type === 'frontend').map((s) => s.name);
  const beSecs = sections.filter((s) => s.type === 'backend');
  const joinBe = joiner(beSecs.map((s) => s.name));

  // frontends: entryPoints (from the API, the config, or the metrics)
  const epNames = [...new Set([...entryPoints.map((e) => e.name), ...feNames.filter((n) => !/^\(/.test(n)), ...Object.keys(epAgg)])];
  for (const ep of epNames) {
    const e = entryPoints.find((x) => x.name === ep);
    const r = { ...blank(), proxy: ep, name: 'FRONTEND', kind: 'frontend', status: 'OPEN', mode: 'http', addr: e ? String(e.address || '') : '' };
    applyAgg(r, epAgg[ep]);
    rows.push(r);
  }

  // backends + servers
  const seen = new Set();
  const svcRows = (list, mode) => {
    for (const s of list) {
      if (/@internal$/.test(s.name)) continue;
      const name = joinBe(s.name);
      if (seen.has(`${mode}|${name}`)) continue; seen.add(`${mode}|${name}`);
      const sec = beSecs.find((x) => x.name === name);
      const hasHc = sec ? Boolean(sec.healthCheck) : Boolean(s.loadBalancer && s.loadBalancer.healthCheck);
      const status = s.serverStatus || {};
      const lbServers = (s.loadBalancer && s.loadBalancer.servers) || [];
      const urls = [...new Set([...lbServers.map((x) => x.url || x.address), ...Object.keys(status)])].filter(Boolean);
      let up = 0; let down = 0;
      for (const url of urls) {
        const st = status[url] || (serverUp.has(`${s.name}|${url}`) ? (serverUp.get(`${s.name}|${url}`) ? 'UP' : 'DOWN') : null);
        const r = { ...blank(), proxy: name, name: redactUrl(url), kind: 'server', mode, addr: hostPort(url), weight: (lbServers.find((x) => (x.url || x.address) === url) || {}).weight ?? null };
        r.status = st === 'DOWN' ? 'DOWN' : hasHc ? (st || 'UP') : (st === 'UP' && mode === 'tcp' ? 'UP' : 'NO CHECK');
        if (hasHc) r.check_status = st === 'DOWN' ? 'HC failed' : 'HC ok';
        if (r.status === 'DOWN') down++; else up++;
        rows.push(r);
      }
      const be = { ...blank(), proxy: name, name: 'BACKEND', kind: 'backend', mode, check_status: urls.length ? `${up}/${urls.length} up` : s.type || '' };
      be.status = s.status === 'disabled' ? 'DOWN' : urls.length && !up ? 'DOWN' : 'UP';
      if (s.status && s.status !== 'enabled') be.check_status = `${s.status}${s.error && s.error.length ? `: ${String(s.error[0]).slice(0, 120)}` : ''}`;
      applyAgg(be, svcAgg[s.name] || svcAgg[strip(s.name)]);
      rows.push(be);
    }
  };
  svcRows(services, 'http'); svcRows(tcpServices, 'tcp');
  // services only seen in the metrics (API off)
  if (!services.length) for (const [svc, a] of Object.entries(svcAgg)) {
    if (/@internal$/.test(svc)) continue;
    const name = joinBe(svc); if (seen.has(`http|${name}`)) continue; seen.add(`http|${name}`);
    const be = { ...blank(), proxy: name, name: 'BACKEND', kind: 'backend', mode: 'http', status: 'UP' };
    applyAgg(be, a); rows.push(be);
    for (const [k, v] of serverUp) { const [sv, url] = k.split('|'); if (sv === svc) rows.push({ ...blank(), proxy: name, name: redactUrl(url), kind: 'server', mode: 'http', addr: hostPort(url), status: v ? 'UP' : 'DOWN', check_status: v ? 'HC ok' : 'HC failed' }); }
  }

  const problems = [...routers, ...tcpRouters, ...services].filter((x) => x.status && x.status !== 'enabled');
  Object.assign(info, {
    routers: routers.length + tcpRouters.length || null, services: services.length + tcpServices.length || null,
    errors: overview ? ['http', 'tcp', 'udp'].reduce((a, p) => a + ['routers', 'services', 'middlewares'].reduce((x, k) => x + (((overview[p] || {})[k] || {}).errors || 0), 0), 0) : null,
    warnings: overview ? ['http', 'tcp', 'udp'].reduce((a, p) => a + ['routers', 'services', 'middlewares'].reduce((x, k) => x + (((overview[p] || {})[k] || {}).warnings || 0), 0), 0) : null,
    features: overview ? overview.features || null : null, providers: overview ? overview.providers || null : null,
    problems: problems.slice(0, 20).map((x) => ({ name: x.name, status: x.status, error: (x.error || []).slice(0, 2) })),
    activeConns: Object.values(epAgg).reduce((a, x) => a + x.open, 0) || null, requestsTotal: Object.values(epAgg).reduce((a, x) => a + x.req, 0) || null, metrics: samples.length > 0,
  });
  if (!rows.length && !info.version) throw new Error(warnings.join('; ') || 'no data returned');
  return { rows, info, warnings };
}

module.exports = { hasSource, sources, collect, parseMetrics, aggregate, joiner };

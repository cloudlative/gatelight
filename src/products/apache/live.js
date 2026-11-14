'use strict';
/**
 * Apache httpd runtime data (read-only, GET only):
 *   - mod_status machine-readable page (server-status?auto): Total Accesses, Total kBytes, BusyWorkers, IdleWorkers,
 *     ReqPerSec, Uptime ... -> `info`   https://httpd.apache.org/docs/2.4/mod/mod_status.html#machinereadable
 *   - balancer-manager HTML page (mod_proxy_balancer): one table per balancer with Worker URL, Route, RouteRedir,
 *     Factor, Set, Status, Elected, Busy, Load, To, From [HC Method ...] -> backend + server rows.
 *     Status strings come from proxy_wstat_tbl in mod_proxy.c ("Init ", "Ign ", "Drn ", "Dis ", "Stop ", "Err ",
 *     "Stby ", "Spar ", "Free ", "HcFl ") followed by "Ok " when the worker is usable (ap_proxy_parse_wstatus).
 * Rows use the HAProxy stats row shape; proxy = balancer name without "balancer://", name = host:port like the parser.
 */
const { httpRequest } = require('../../transport');
const { parseUrl } = require('./parse');

const blank = () => ({
  qcur: null, qmax: null, scur: null, smax: null, slim: null, stot: null, req_tot: null, bin: null, bout: null, weight: null, lastchg: null, downtime: null,
  hrsp_1xx: null, hrsp_2xx: null, hrsp_3xx: null, hrsp_4xx: null, hrsp_5xx: null, rtime: null, ctime: null, ttime: null, econ: null, eresp: null,
  check_status: '', last_chk: '', check_code: null, mode: 'http', addr: '',
});

// ------------------------------------------------------------------------------------------------ mod_status
/** Parse server-status?auto ("Key: value" lines). */
function parseStatusAuto(text) {
  const kv = {};
  const lines = String(text || '').split(/\r?\n/);
  for (const l of lines) { const m = /^([A-Za-z][A-Za-z0-9 _-]*?):\s?(.*)$/.exec(l); if (m) kv[m[1].trim()] = m[2].trim(); }
  if (kv['Total Accesses'] === undefined && kv.BusyWorkers === undefined && kv.Scoreboard === undefined) return null;
  const n = (k) => (kv[k] === undefined || kv[k] === '' || !Number.isFinite(Number(kv[k])) ? null : Number(kv[k]));
  const ver = /Apache\/(\d+\.\d+\.\d+)/.exec(kv.ServerVersion || '');
  const sb = kv.Scoreboard || '';
  const count = (c) => (sb ? sb.split('').filter((x) => x === c).length : null);
  return {
    version: ver ? ver[1] : null, serverVersion: kv.ServerVersion || null, mpm: kv.ServerMPM || null, serverName: lines[0] && !/:/.test(lines[0]) ? lines[0].trim() : null,
    uptimeSec: n('ServerUptimeSeconds') ?? n('Uptime'), requestsTotal: n('Total Accesses'), totalKBytes: n('Total kBytes'), bytesTotal: n('Total kBytes') == null ? null : n('Total kBytes') * 1024,
    reqPerSec: n('ReqPerSec'), bytesPerSec: n('BytesPerSec'), bytesPerReq: n('BytesPerReq'), durationPerReq: n('DurationPerReq'), cpuLoad: n('CPULoad'),
    busyWorkers: n('BusyWorkers'), idleWorkers: n('IdleWorkers'), gracefulWorkers: n('GracefulWorkers'), processes: n('Processes'), stopping: n('Stopping'),
    activeConns: n('ConnsTotal'), connsAsyncKeepAlive: n('ConnsAsyncKeepAlive'), connsAsyncWriting: n('ConnsAsyncWriting'), connsAsyncClosing: n('ConnsAsyncClosing'),
    load1: n('Load1'), load5: n('Load5'), load15: n('Load15'),
    scoreboard: sb ? { waiting: count('_'), reading: count('R'), writing: count('W'), keepalive: count('K'), closing: count('C'), logging: count('L'), graceful: count('G'), idleCleanup: count('I'), open: count('.') } : null,
    raw: kv,
  };
}

// ------------------------------------------------------------------------------------------------ balancer-manager
const ENT = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' };
const text = (s) => String(s || '').replace(/<[^>]+>/g, '').replace(/&(lt|gt|amp|quot|#39|nbsp);/g, (m) => ENT[m]).replace(/\s+/g, ' ').trim();
/** apr_strfsize output ("  0 ", "1.2K", " 12M") -> bytes */
function sizeBytes(s) {
  const m = /^\s*([\d.]+)\s*([KMGTPE])?/i.exec(String(s || ''));
  if (!m) return null;
  const mul = { K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4, P: 1024 ** 5, E: 1024 ** 6 }[(m[2] || '').toUpperCase()] || 1;
  return Math.round(Number(m[1]) * mul);
}
/** "Init Ok", "Init Err", "Init Dis", "Init Stby Ok", "Init Drn Ok", "Init HcFl" -> row status */
function memberStatus(s) {
  const t = ` ${String(s || '').trim()} `;
  const has = (w) => t.includes(` ${w} `);
  const flags = ['Init', 'Ign', 'Drn', 'Gen', 'Shut', 'Dis', 'Stop', 'Err', 'Stby', 'Spar', 'Free', 'HcFl'].filter(has);
  let status = 'UNKNOWN'; let check = '';
  if (has('Dis') || has('Stop') || has('Shut')) { status = 'MAINT'; check = has('Stop') ? 'stopped' : has('Shut') ? 'shutting down' : 'disabled'; }
  else if (has('HcFl')) { status = 'DOWN'; check = 'health check failed'; }
  else if (has('Err')) { status = 'DOWN'; check = 'in error'; }
  else if (has('Drn')) { status = 'DRAIN'; check = 'draining'; }
  else if (has('Ok')) { status = 'UP'; check = has('Stby') ? 'hot standby' : has('Spar') ? 'hot spare' : 'ok'; }
  else if (!has('Init')) { status = 'DOWN'; check = 'not initialised'; }
  return { status, check, flags, backup: has('Stby') || has('Spar') };
}

/** Parse the balancer-manager HTML page into [{ name, sticky, method, timeout, members: [...] }]. */
function parseBalancerManager(html) {
  const out = [];
  const h = String(html || '');
  const parts = h.split(/<h3>\s*LoadBalancer Status for /i).slice(1);
  for (const part of parts) {
    const nm = /^(?:<a [^>]*>)?\s*(balancer:\/\/[^<\s]+)\s*(?:<\/a>)?\s*(?:\[([^\]]*)\])?/i.exec(part);
    if (!nm) continue;
    const tables = [...part.matchAll(/<table[^>]*>([\s\S]*?)<\/table>/gi)].map((t) => t[1]);
    const rowsOf = (t) => [...t.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)].map((r) => r[1]);
    const cells = (r, tag) => [...r.matchAll(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)(?=<${tag}[\\s>]|</tr>|$)`, 'gi'))].map((c) => c[1].replace(new RegExp(`</${tag}>\\s*$`, 'i'), ''));
    const bal = { url: nm[1], name: nm[1].replace(/^balancer:\/\//i, ''), sname: nm[2] || null, sticky: null, method: null, timeout: null, active: null, members: [] };
    for (const t of tables) {
      const trs = rowsOf(t); if (!trs.length) continue;
      const head = cells(trs[0], 'th').map(text);
      if (head.includes('StickySession') && trs[1]) {
        const v = cells(trs[1], 'td').map(text); const g = (k) => v[head.indexOf(k)];
        bal.sticky = g('StickySession') && g('StickySession') !== '(None)' ? g('StickySession') : null; bal.method = g('Method') || null;
        bal.timeout = g('Timeout') != null ? Number(g('Timeout')) : null; bal.active = g('Active') ? g('Active') === 'Yes' : null; bal.path = g('Path') || null;
      }
      if (head.includes('Worker URL')) {
        for (const tr of trs.slice(1)) {
          const v = cells(tr, 'td').map(text); if (!v.length) continue;
          const g = (k) => (head.indexOf(k) >= 0 ? v[head.indexOf(k)] : undefined);
          const url = g('Worker URL') || '';
          const u = parseUrl(url);
          bal.members.push({
            url, name: u ? u.hostPort : url, route: g('Route') || null, redirect: g('RouteRedir') || null, factor: g('Factor') != null ? Number(g('Factor')) : null, lbset: g('Set') != null ? Number(g('Set')) : null,
            statusText: g('Status') || '', elected: Number(g('Elected')) || 0, busy: g('Busy') != null ? Number(g('Busy')) : null, load: g('Load') != null ? Number(g('Load')) : null,
            to: sizeBytes(g('To')), from: sizeBytes(g('From')), hcMethod: g('HC Method') || null, hcInterval: g('HC Interval') || null, hcPasses: g('Passes') || null, hcFails: g('Fails') || null, hcUri: g('HC uri') || null,
          });
        }
      }
    }
    out.push(bal);
  }
  return out;
}

/** Balancers -> stats rows (server rows per member, one backend row per balancer). */
function balancerRows(balancers, sections = []) {
  const rows = [];
  for (const b of balancers) {
    const be = sections.find((s) => s.type === 'backend' && s.name === b.name);
    const agg = { ...blank(), proxy: b.name, name: 'BACKEND', kind: 'backend', status: 'DOWN', scur: 0, stot: 0, req_tot: 0, bin: 0, bout: 0, check_status: b.method ? `lbmethod ${b.method}` : '' };
    let up = 0; let active = 0;
    for (const m of b.members) {
      const st = memberStatus(m.statusText);
      // join with the parsed config: same host:port, or a configured member with the same route
      const cfg = be && (be.servers.find((s) => s.name === m.name) || (m.route && be.servers.find((s) => s.route === m.route)));
      const r = {
        ...blank(), proxy: b.name, name: cfg ? cfg.name : m.name, kind: 'server', status: st.status, scur: m.busy, stot: m.elected, req_tot: m.elected, bin: m.to, bout: m.from,
        weight: m.factor, check_status: st.check, last_chk: m.statusText.trim(), addr: m.name, backup: st.backup, route: m.route, flags: st.flags, lbstatus: m.load,
        hc: m.hcMethod ? { method: m.hcMethod, interval: m.hcInterval, passes: m.hcPasses, fails: m.hcFails, uri: m.hcUri } : null,
      };
      rows.push(r);
      agg.scur += m.busy || 0; agg.stot += m.elected || 0; agg.req_tot += m.elected || 0; agg.bin += m.to || 0; agg.bout += m.from || 0;
      if (st.status === 'UP') { up++; if (!st.backup) active++; }
    }
    agg.status = b.active === false ? 'MAINT' : up ? 'UP' : 'DOWN';
    agg.check_status = `${up}/${b.members.length} usable${active < up ? ` (${up - active} standby)` : ''}${b.method ? `, ${b.method}` : ''}`;
    rows.push(agg);
  }
  return rows;
}

// ------------------------------------------------------------------------------------------------ collection
const sources = (inst) => [inst && inst.statsUrl ? 'server-status' : null, inst && inst.balancerUrl ? 'balancer-manager' : null].filter(Boolean);
const hasSource = (inst) => sources(inst).length > 0;
const autoUrl = (u) => (/[?&]auto\b/.test(u) ? u : `${u}${u.includes('?') ? '&' : '?'}auto`);

async function get(inst, url) {
  const res = await httpRequest(url, { method: 'GET', username: inst.username, password: inst.password, timeout: inst.timeoutMs, insecureTls: inst.insecureTls });
  if (res.status === 401 || res.status === 403) throw new Error(`HTTP ${res.status} (access denied — check Require ip / credentials)`);
  if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
  return res;
}

/**
 * @param inst { statsUrl?: server-status URL, balancerUrl?: balancer-manager URL, username, password, timeoutMs, insecureTls }
 * @param cache unused (kept for the contract)  @param ctx { sections } to align names with the parsed config
 */
async function collect(inst, cache, ctx = {}) {
  const sections = (ctx && ctx.sections) || [];
  let rows = []; let info = {}; const warnings = [];
  if (inst.statsUrl) {
    try {
      const res = await get(inst, autoUrl(inst.statsUrl));
      const st = parseStatusAuto(res.body);
      if (!st) throw new Error('response is not mod_status ?auto output (is the URL the server-status handler?)');
      const sv = /Apache\/(\d+\.\d+\.\d+)/.exec(String(res.headers.server || ''));
      info = { ...st, version: st.version || (sv ? sv[1] : null) };
    } catch (e) { warnings.push(`server-status: ${e.message}`); }
  }
  if (inst.balancerUrl) {
    try {
      const res = await get(inst, inst.balancerUrl);
      const bals = parseBalancerManager(res.body);
      if (!bals.length && !/Load Balancer Manager/i.test(res.body)) throw new Error('response is not a balancer-manager page');
      rows = balancerRows(bals, sections);
      info.balancers = bals.length;
      if (!info.version) { const v = /Server Version:\s*Apache\/(\d+\.\d+\.\d+)/i.exec(res.body); if (v) info.version = v[1]; }
    } catch (e) { warnings.push(`balancer-manager: ${e.message}`); }
  }
  if (hasSource(inst) && !rows.length && !Object.keys(info).length) throw new Error(warnings.join('; ') || 'no data returned');
  return { rows, info, warnings };
}

module.exports = { hasSource, sources, collect, parseStatusAuto, parseBalancerManager, balancerRows, memberStatus, sizeBytes };

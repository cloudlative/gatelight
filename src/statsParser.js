'use strict';
/**
 * Parser for HAProxy `show stat` / `;csv` output and `show info`.
 */

const NUMERIC = [
  'qcur', 'qmax', 'scur', 'smax', 'slim', 'stot', 'bin', 'bout', 'dreq', 'dresp', 'ereq', 'econ',
  'eresp', 'wretr', 'wredis', 'weight', 'act', 'bck', 'chkfail', 'chkdown', 'lastchg', 'downtime',
  'qlimit', 'throttle', 'lbtot', 'rate', 'rate_lim', 'rate_max', 'check_code', 'check_duration',
  'hrsp_1xx', 'hrsp_2xx', 'hrsp_3xx', 'hrsp_4xx', 'hrsp_5xx', 'hrsp_other', 'req_rate',
  'req_rate_max', 'req_tot', 'cli_abrt', 'srv_abrt', 'qtime', 'ctime', 'rtime', 'ttime',
  'conn_rate', 'conn_rate_max', 'conn_tot',
];
const TYPE_BY_CODE = { 0: 'frontend', 1: 'backend', 2: 'server', 3: 'listener' };

/** RFC 4180-ish CSV line splitter (handles quoted fields containing commas). */
function splitCsvLine(line) {
  const out = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQ) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false;
      } else cur += ch;
    } else if (ch === '"') inQ = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

const toInt = (v) => {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

function parseStatsCsv(csv) {
  if (typeof csv !== 'string') return [];
  const lines = csv.split(/\r?\n/).filter((l) => l.trim().length);
  if (lines.length < 2 || !/^#?\s*pxname/.test(lines[0])) return [];
  const headers = splitCsvLine(lines[0].replace(/^#\s*/, '')).map((h) => h.trim());
  const rows = [];
  for (const line of lines.slice(1)) {
    if (line.startsWith('#')) continue;
    const vals = splitCsvLine(line);
    const o = {};
    headers.forEach((h, i) => { if (h) o[h] = vals[i] === undefined ? '' : vals[i]; });
    if (!o.pxname || !o.svname) continue;
    const typeCode = toInt(o.type);
    let kind = TYPE_BY_CODE[typeCode];
    if (!kind) kind = o.svname === 'FRONTEND' ? 'frontend' : o.svname === 'BACKEND' ? 'backend' : 'server';
    const row = { proxy: o.pxname, name: o.svname, kind, status: (o.status || '').trim() || 'UNKNOWN' };
    for (const k of NUMERIC) row[k] = toInt(o[k]);
    row.check_status = o.check_status || '';
    row.last_chk = o.last_chk || '';
    row.last_agt = o.last_agt || '';
    row.mode = o.mode || '';
    row.addr = (o.addr || '').trim(); // server address as HAProxy reports it (ip:port); empty for frontends/backends
    rows.push(row);
  }
  return rows;
}

/**
 * Normalised bucket for a raw HAProxy status such as "UP", "UP 1/3" (check
 * failing, not yet down), "DOWN 2/5", "NOLB", "MAINT (via be/srv)".
 */
function statusClass(status) {
  const s = String(status || '').trim().toUpperCase();
  if (s.startsWith('UP')) {
    const m = s.match(/^UP\s+(\d+)\/(\d+)/);
    return m && m[1] !== m[2] ? 'degraded' : 'up';
  }
  if (s.startsWith('OPEN')) return 'up';
  if (s.startsWith('DOWN') || s.startsWith('STOP')) return 'down';
  if (s.startsWith('MAINT')) return 'maint';
  if (s.startsWith('DRAIN') || s.startsWith('NOLB')) return 'drain';
  if (s.startsWith('NO CHECK')) return 'nocheck';
  return 'unknown';
}

/** Parse `show info` ("Key: value" lines). */
function parseInfo(text) {
  const info = {};
  if (typeof text !== 'string') return info;
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/);
    if (m) info[m[1]] = m[2].trim();
  }
  return {
    version: info.Version || null,
    pid: info.Pid || null,
    uptime: info.Uptime || null,
    uptimeSec: toInt(info.Uptime_sec),
    nbthread: toInt(info.Nbthread),
    maxconn: toInt(info.Maxconn),
    currConns: toInt(info.CurrConns),
    cumConns: toInt(info.CumConns),
    connRate: toInt(info.ConnRate),
    maxConnRate: toInt(info.MaxConnRate),
    sessRate: toInt(info.SessRate),
    idlePct: toInt(info.Idle_pct),
    memMaxMB: toInt(info.Memmax_MB),
    memMax: info.Memmax || (info.Memmax_MB && info.Memmax_MB !== '0' ? `${info.Memmax_MB} MB` : null),
    nbproc: toInt(info.Nbproc),
    ulimitN: toInt(info['Ulimit-n']),
    maxsock: toInt(info.Maxsock),
    maxpipes: toInt(info.Maxpipes),
    currPipes: toInt(info.CurrPipes),
    tasks: toInt(info.Tasks),
    runQueue: toInt(info.Run_queue),
    raw: info,
  };
}

module.exports = { parseStatsCsv, parseInfo, splitCsvLine, statusClass };

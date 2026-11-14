'use strict';
/**
 * Apache httpd access / error logs -> the shared Traffic Stats aggregates (core from src/logs/haproxy.js).
 *
 * Access log formats (mod_log_config, https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats):
 *   common          %h %l %u %t "%r" %>s %b
 *   combined        %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
 *   vhost_combined  %v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"   (Debian other_vhosts_access.log)
 *   + a trailing %D (microseconds, integer) or %T (seconds) / %{ms}T: an integer is read as %D microseconds unless
 *     createAggregator({ timeUnit: 's' | 'ms' }) says otherwise; a decimal number is read as seconds.
 *   + optional key=value extras (rt=, worker=, balancer=, vhost=) and a quoted backend URL ("%{BALANCER_WORKER_NAME}e").
 * Error log (2.4 default ErrorLogFormat): [Mon Nov 10 08:15:02.123456 2026] [proxy:error] [pid 123:tid 456] [client ...] AH01114: ...
 *   -> events (proxy errors about a backend become "down" events).
 * Mapping: frontend = virtual host (%v, or the Host when logged), backend = balancer when logged, server = worker.
 */
const { createAggregator: createCore } = require('../../logs/haproxy');
const { parseTimeLocal } = require('../../logs/nginx');
const { parseUrl } = require('./parse');

const ACCESS_RE = /^(?:(\S+?):(\d+) )?(\S+) \S+ (\S+) \[([^\]]{10,40})\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(.*)$/;
const ERR_RE = /^\[(?:[A-Z][a-z]{2} )?([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d)(?:\.(\d+))? (\d{4})\] \[(?:([a-z0-9_]+):)?(emerg|alert|crit|error|warn|notice|info|debug|trace\d)\] (.*)$/;
const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const METHOD_RE = /^[A-Z]{3,12}$/;
const KV_RE = /(\w+)=("(?:[^"\\]|\\.)*"|\S+)/g;
const NO_BE = '(not logged)';

function splitRequest(request) {
  let method = '-'; let path = ''; let version = '';
  const a = request.indexOf(' ');
  if (a > 0 && METHOD_RE.test(request.slice(0, a))) {
    method = request.slice(0, a); const b = request.lastIndexOf(' ');
    if (b > a && /^HTTP\//.test(request.slice(b + 1))) { version = request.slice(b + 1); path = request.slice(a + 1, b); } else path = request.slice(a + 1);
  }
  return { method, path, version };
}

function createApacheAggregator(opts = {}) {
  const core = createCore();
  const st = core.stats;
  const unit = opts.timeUnit || 'us';
  const toMs = (s) => {
    if (s == null || s === '-' || s === '') return -1;
    if (/^\d+\.\d+$/.test(s)) return Math.round(Number(s) * 1000); // decimal: seconds
    if (!/^\d+$/.test(s)) return -1;
    const n = Number(s);
    return unit === 's' ? n * 1000 : unit === 'ms' ? n : Math.round(n / 1000);
  };

  function pushAccess(m, raw) {
    const t = m.time !== undefined ? m.time : parseTimeLocal(m[5]); if (t === null) return core.miss(raw);
    const vhost = m[1] ? m[1].toLowerCase() : '';
    const { method, path, version } = splitRequest(m[6]);
    const status = +m[7]; const bytes = m[8] === '-' ? 0 : +m[8];
    let rt = -1; let worker = ''; let balancer = ''; let host = '';
    let rest = m[9] || '';
    rest = rest.replace(KV_RE, (all, k, v) => {
      const key = k.toLowerCase(); const val = v.replace(/^"|"$/g, '');
      if (/^(rt|d|time|duration|request_time|us|usec)$/.test(key)) rt = key === 'rt' || key === 'request_time' ? toMs(val) : toMs(val);
      else if (/^(worker|balancer_worker_name|backend|upstream)$/.test(key)) worker = val;
      else if (/^(balancer|balancer_name)$/.test(key)) balancer = val;
      else if (/^(vhost|host|server_name)$/.test(key)) host = val;
      return ' ';
    });
    const quoted = []; rest = rest.replace(/"((?:[^"\\]|\\.)*)"/g, (all, q) => { quoted.push(q); return ' '; });
    const nums = rest.trim().split(/\s+/).filter(Boolean);
    if (rt < 0 && nums.length && /^(\d+(\.\d+)?)$/.test(nums[nums.length - 1])) rt = toMs(nums[nums.length - 1]);
    for (const q of quoted.slice(2)) {
      if (/^balancer:\/\//i.test(q)) balancer = q;
      else if (/^[a-z0-9+]+:\/\/\S+$/i.test(q) && !worker) worker = q;
      else if (!host && /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d+)?$/.test(q)) host = q;
    }
    const u = worker ? parseUrl(worker) : null;
    const srv = u ? u.hostPort : (worker || NO_BE);
    const be = balancer ? balancer.replace(/^balancer:\/\//i, '').replace(/\/.*$/, '') : (u ? '(proxied)' : NO_BE);
    const fe = (vhost || host.replace(/:\d+$/, '') || '(any host)').slice(0, 120);
    const term = status === 502 ? 'SH--' : status === 504 ? 'sH--' : '----';
    st.http++;
    core.addRequest({
      proto: 'http', t, client: `${m[3]}:0`, fe, be, srv, tq: 0, tw: 0, tc: 0, tr: -1, tt: rt >= 0 ? rt : 0, timed: rt >= 0,
      status, bytes, term, act: 0, cfe: 0, cbe: 0, csv: 0, retr: 0, sq: 0, bq: 0, method, path, version, host: vhost || host || '',
    });
    return true;
  }

  function pushError(e) {
    const t = Date.UTC(+e[7], MON[e[1]], +e[2], +e[3], +e[4], +e[5], e[6] ? Math.floor(Number(`0.${e[6]}`) * 1000) : 0);
    const mod = e[8] || ''; const level = e[9];
    let msg = e[10].replace(/^\[pid [^\]]*\] /, '').replace(/^\[client [^\]]*\] /, '').replace(/^\[remote [^\]]*\] /, '');
    const bad = /^(emerg|alert|crit|error)$/.test(level);
    const backendDown = /^proxy/.test(mod) && /(AH00957|AH01114|AH01102|AH00898|AH00940|AH01097|AH02803|AH03251|AH00959|failed to make connection|disabled connection|error reading status line|health check|No healthy|backend)/i.test(msg);
    msg = msg.replace(/, referer: .*$/, '');
    core.addEvent(backendDown && bad ? 'down' : /AH03251|is UP|enabled/i.test(msg) && /^proxy/.test(mod) ? 'up' : bad ? 'down' : 'info', t, `[${mod ? `${mod}:` : ''}${level}] ${msg}`);
    return true;
  }

  /** One JSON object per line (LogFormat "{ \"time\":\"%{%Y-%m-%dT%H:%M:%S%z}t\", ... }"). */
  function pushJson(raw) {
    let o; try { o = JSON.parse(raw); } catch { return core.miss(raw); }
    if (!o || typeof o !== 'object') return core.miss(raw);
    const g = (...ks) => { for (const k of ks) if (o[k] !== undefined && o[k] !== null && o[k] !== '' && o[k] !== '-') return o[k]; return undefined; };
    const tv = g('time', '@timestamp', 'timestamp', 'time_local');
    const t = typeof tv === 'number' ? (tv < 1e12 ? tv * 1000 : tv) : (parseTimeLocal(String(tv || '')) ?? (Number.isNaN(Date.parse(tv)) ? null : Date.parse(tv)));
    const status = Number(g('status', 'response_code'));
    let request = g('request');
    if (!request && g('method') && g('uri', 'path')) request = `${g('method')} ${g('uri', 'path')} ${g('protocol') || 'HTTP/1.1'}`;
    if (t === null || !Number.isInteger(status) || typeof request !== 'string') return core.miss(raw);
    const us = g('duration_us', 'time_us', 'D'); const ms = g('duration_ms'); const sec = g('request_time', 'duration');
    const rt = us !== undefined ? Math.round(Number(us) / 1000) : ms !== undefined ? Math.round(Number(ms)) : sec !== undefined ? Math.round(Number(sec) * 1000) : -1;
    const m = [raw, g('vhost', 'host', 'server_name') ? String(g('vhost', 'host', 'server_name')).replace(/:\d+$/, '') : undefined, undefined, String(g('remote_addr', 'client', 'remote_ip') || '-'), '-', null, request, String(status), String(g('bytes', 'bytes_sent', 'size') || 0), ''];
    const extra = [g('balancer') ? `balancer=${g('balancer')}` : '', g('worker') ? `worker=${g('worker')}` : '', rt >= 0 ? `rt=${(rt / 1000).toFixed(3)}` : ''].join(' ');
    m[9] = ` ${extra}`;
    m.time = t;
    return pushAccess(m, raw);
  }

  /** Feed one log line. Returns true when it was understood. */
  function push(raw) {
    if (!raw || raw.length < 12) { if (raw && raw.trim()) { st.lines++; st.unparsed++; } return false; }
    st.lines++;
    if (raw.charCodeAt(0) === 123) return pushJson(raw);
    const m = ACCESS_RE.exec(raw);
    if (m && (!m[1] || /^[A-Za-z0-9._\-[\]*:]+$/.test(m[1]))) return pushAccess(m, raw);
    const e = ERR_RE.exec(raw);
    if (e && MON[e[1]] !== undefined) return pushError(e);
    return core.miss(raw);
  }

  function finish(meta = {}) { return core.finish({ product: 'apache', ...meta }); }
  return { push, finish, stats: st };
}

/** Share of sample lines this parser understands. */
function sniff(lines) {
  const a = createApacheAggregator(); let ok = 0; let tried = 0;
  for (const l of lines || []) { if (!l || l.length < 12) continue; tried++; if (a.push(l)) ok++; }
  return { tried, ok, ratio: tried ? ok / tried : 0 };
}

module.exports = { createAggregator: createApacheAggregator, sniff, splitRequest };

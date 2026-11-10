'use strict';
/**
 * NGINX access log -> the same compact aggregates as the HAProxy parser (see haproxy.js), so the Traffic dashboard works for both.
 *
 * Understood:
 *   - the default `combined` format:  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
 *   - the older `common` format (no referer / user agent)
 *   - extra fields after the user agent, either `key=value` (rt=0.012 urt=0.010 uaddr=10.0.0.5:8080 host=shop.example.com ...)
 *     or bare numbers in the usual order ($request_time $upstream_response_time)
 *   - one JSON object per line (log_format ... escape=json) with the usual variable names
 *   - lines of the error log ("2026/11/10 08:15:02 [error] ..."), kept as events
 * Without $request_time / $upstream_* the dashboard simply has no timing panels; everything else works.
 *
 * Mapping to the shared model:  frontend = server block ($host), backend = upstream (when the log says which), server = upstream peer address.
 * Query strings and user agents are never stored; clients are kept only as counters (like the HAProxy parser).
 */
const { createAggregator: createCore } = require('./haproxy');

const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const ACCESS_RE = /^(\S+) \S+ (\S+) \[([^\]]{10,40})\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(.*)$/;
const ERRLOG_RE = /^(\d{4})\/(\d\d)\/(\d\d) (\d\d):(\d\d):(\d\d) \[(debug|info|notice|warn|error|crit|alert|emerg)\] (.*)$/;
const KV_RE = /(\w+)=("(?:[^"\\]|\\.)*"|\S+)/g;
const QUOTED_RE = /"((?:[^"\\]|\\.)*)"/g;
const METHOD_RE = /^[A-Z]{3,12}$/;
const NO_UP = '(no upstream)'; // served by NGINX itself (static files, redirects, cache) or the log has no upstream field

/** "17/May/2015:08:05:32 +0000" -> epoch ms (null when it is not a time). */
function parseTimeLocal(s) {
  const m = /^(\d\d)\/([A-Za-z]{3})\/(\d{4}):(\d\d):(\d\d):(\d\d)(?: ([+-])(\d\d)(\d\d))?$/.exec(s);
  if (!m || MON[m[2]] === undefined) return null;
  let t = Date.UTC(+m[3], MON[m[2]], +m[1], +m[4], +m[5], +m[6]);
  if (m[7]) t -= (m[7] === '-' ? -1 : 1) * (+m[8] * 60 + +m[9]) * 60000;
  return t;
}
/** NGINX time variables: "0.004", "-", "0.004, 0.010" (retries) or "0.004 : 0.010" (internal redirect). Returns ms, or -1 when absent. */
function seconds(v) {
  if (v === undefined || v === null || v === '' || v === '-') return -1;
  let sum = 0; let any = false;
  for (const part of String(v).split(/[,:]\s*/)) { const n = Number(part.trim()); if (Number.isFinite(n) && part.trim() !== '' && part.trim() !== '-') { sum += n; any = true; } }
  return any ? Math.round(sum * 1000) : -1;
}
/** "10.0.0.5:8080, 10.0.0.6:8080" -> the last peer that answered. "-" or empty -> '-'. */
function lastPeer(v) {
  if (!v || v === '-') return '-';
  const parts = String(v).split(/[,:]\s+/).map((x) => x.trim()).filter((x) => x && x !== '-');
  return (parts.length ? parts[parts.length - 1] : '-').slice(0, 120);
}
const unq = (s) => (s.length > 1 && s[0] === '"' ? s.slice(1, -1) : s);
const KEY_ALIAS = {
  rt: 'rt', request_time: 'rt', rtime: 'rt', reqtime: 'rt', time: 'rt',
  urt: 'urt', upstream_response_time: 'urt', upstream_time: 'urt', uresponse: 'urt',
  uct: 'uct', upstream_connect_time: 'uct',
  uaddr: 'uaddr', upstream_addr: 'uaddr', upstream: 'uaddr', ua: 'uaddr',
  un: 'un', upstream_name: 'un',
  host: 'host', http_host: 'host', server_name: 'host', vhost: 'host', site: 'host',
};

function splitRequest(request) {
  let method = '-'; let path = ''; let version = '';
  const a = request.indexOf(' ');
  if (a > 0 && METHOD_RE.test(request.slice(0, a))) {
    method = request.slice(0, a); const b = request.lastIndexOf(' ');
    if (b > a) { version = request.slice(b + 1); path = request.slice(a + 1, b); } else path = request.slice(a + 1);
    if (!/^HTTP\//.test(version)) { if (version) path = request.slice(a + 1); version = ''; } // "GET /a b" without a protocol
  }
  return { method, path, version };
}

function createNginxAggregator() {
  const core = createCore();
  const st = core.stats;

  function request(f) {
    const { method, path, version } = splitRequest(f.request);
    const status = f.status;
    const peer = f.peer || '-'; const tt = f.rt;
    // termination state, in HAProxy's vocabulary so the same panel explains it: 499 = the client left, 502/504 = the upstream failed
    const term = status === 499 ? 'CH--' : status === 504 ? 'sH--' : status === 502 ? 'SH--' : '----';
    st.http++;
    core.addRequest({
      proto: 'http', t: f.t, client: `${f.ip}:0`, fe: (f.host || '(any host)').toLowerCase().slice(0, 120), be: f.un || (peer !== '-' ? '(upstream)' : NO_UP), srv: peer === '-' ? NO_UP : peer,
      tq: 0, tw: 0, tc: f.uct > 0 ? f.uct : 0, tr: f.urt >= 0 ? f.urt : -1, tt: tt >= 0 ? tt : 0, timed: tt >= 0,
      status, bytes: f.bytes, term, act: 0, cfe: 0, cbe: 0, csv: 0, retr: 0, sq: 0, bq: 0, method, path, version, host: f.host || '',
    });
    return true;
  }

  function pushJson(raw) {
    let o; try { o = JSON.parse(raw); } catch { return false; }
    if (!o || typeof o !== 'object') return false;
    const g = (...ks) => { for (const k of ks) if (o[k] !== undefined && o[k] !== null && o[k] !== '') return o[k]; return undefined; };
    const tv = g('time_iso8601', 'time_local', 'timestamp', '@timestamp', 'time', 'ts');
    let t = null;
    if (typeof tv === 'number') t = tv < 1e12 ? tv * 1000 : tv;
    else if (typeof tv === 'string') t = parseTimeLocal(tv) ?? (Number.isNaN(Date.parse(tv)) ? null : Date.parse(tv));
    const status = Number(g('status', 'response', 'response_code', 'http_status'));
    let reqStr = g('request');
    if (reqStr === undefined) { const mth = g('request_method', 'method'); const uri = g('request_uri', 'uri', 'path'); if (mth && uri) reqStr = `${mth} ${uri} ${g('server_protocol', 'protocol') || 'HTTP/1.1'}`; }
    if (t === null || !Number.isInteger(status) || status < 100 || status > 599 || typeof reqStr !== 'string') return false;
    const sec = (v) => (typeof v === 'number' ? Math.round(v * 1000) : seconds(v));
    return request({
      ip: String(g('remote_addr', 'remote_ip', 'client', 'clientip', 'ip', 'http_x_forwarded_for') || '-').split(',')[0].trim(), t, request: reqStr, status, bytes: Number(g('body_bytes_sent', 'bytes_sent', 'bytes', 'size')) || 0,
      rt: sec(g('request_time', 'rt')), urt: sec(g('upstream_response_time', 'urt')), uct: sec(g('upstream_connect_time', 'uct')),
      peer: lastPeer(g('upstream_addr', 'upstream')), un: g('upstream_name') ? String(g('upstream_name')).slice(0, 80) : '', host: g('host', 'http_host', 'server_name') ? String(g('host', 'http_host', 'server_name')).slice(0, 120).replace(/:\d+$/, '') : '',
    });
  }

  /** Feed one log line. Returns true when it was understood. */
  function push(raw) {
    if (!raw || raw.length < 12) { if (raw && raw.trim()) { st.lines++; st.unparsed++; } return false; }
    st.lines++;
    if (raw.charCodeAt(0) === 123) return pushJson(raw) || core.miss(raw); // '{'
    const m = ACCESS_RE.exec(raw);
    if (m) {
      const t = parseTimeLocal(m[3]); if (t === null) return core.miss(raw);
      const f = { ip: m[1], t, request: m[4], status: +m[5], bytes: m[6] === '-' ? 0 : +m[6], rt: -1, urt: -1, uct: -1, peer: '-', un: '', host: '' };
      const rest = m[7];
      if (rest.length > 1) {
        // key=value extras first; the rest is [quoted referer, quoted user agent, ...] and bare numbers
        let bare = rest.replace(KV_RE, (all, k, v) => {
          const key = KEY_ALIAS[k.toLowerCase()];
          if (!key) return ' ';
          const val = unq(v);
          if (key === 'rt') f.rt = seconds(val); else if (key === 'urt') f.urt = seconds(val); else if (key === 'uct') f.uct = seconds(val);
          else if (key === 'uaddr') f.peer = lastPeer(val); else if (key === 'un') f.un = val.slice(0, 80); else if (key === 'host') f.host = val.slice(0, 120).replace(/:\d+$/, '');
          return ' ';
        });
        const quoted = []; bare = bare.replace(QUOTED_RE, (all, q) => { quoted.push(q); return ' '; });
        const nums = bare.trim().split(/\s+/).filter(Boolean);
        if (f.rt < 0 && nums.length && /^(\d+(\.\d+)?|-)$/.test(nums[0])) {
          f.rt = seconds(nums[0]);
          if (f.urt < 0 && nums.length > 1) f.urt = seconds(nums[1]);
        }
        // a quoted field that looks like a host name right after the user agent ("$host") is accepted as the server block
        if (!f.host && quoted.length > 2 && /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(quoted[2])) f.host = quoted[2];
      }
      return request(f);
    }
    const e = ERRLOG_RE.exec(raw);
    if (e) {
      const t = Date.UTC(+e[1], +e[2] - 1, +e[3], +e[4], +e[5], +e[6]);
      const bad = e[7] === 'error' || e[7] === 'crit' || e[7] === 'alert' || e[7] === 'emerg';
      core.addEvent(bad ? 'down' : 'info', t, `[${e[7]}] ${e[8].replace(/, (client|server|request|upstream|host|referrer): .*$/, '')}`);
      return true;
    }
    return core.miss(raw);
  }

  function finish(meta = {}) { return core.finish({ product: 'nginx', ...meta }); }
  return { push, finish, stats: st };
}

/** Does this sample of lines look like an NGINX access log? (share of lines that parse). */
function sniff(lines) {
  const a = createNginxAggregator(); let ok = 0; let tried = 0;
  for (const l of lines) { if (!l || l.length < 12) continue; tried++; if (a.push(l)) ok++; }
  return { tried, ok, ratio: tried ? ok / tried : 0 };
}

module.exports = { createAggregator: createNginxAggregator, sniff, parseTimeLocal, seconds, lastPeer };

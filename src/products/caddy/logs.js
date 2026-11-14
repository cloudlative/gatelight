'use strict';
/**
 * Caddy access logs -> the shared Traffic Stats aggregates (core: src/logs/haproxy.js createAggregator).
 *
 * Understood (https://caddyserver.com/docs/caddyfile/directives/log):
 *   - the default structured JSON entries of the "http.log.access[.<name>]" loggers:
 *       {"level":"info","ts":1700000000.123,"logger":"http.log.access.log0","msg":"handled request",
 *        "request":{"remote_ip","remote_port","client_ip","proto","method","host","uri","headers",...},
 *        "bytes_read","user_id","duration":0.0123,"size":512,"status":200,"resp_headers":{...}}
 *     ts may be a float of unix seconds (default), unix millis/nanos or an ISO / wall time string (time_format);
 *     duration is seconds by default (duration_format: also ms, ns integers, or Go strings like "6.31ms").
 *     Caddy before 2.5 logged request.remote_addr ("ip:port") instead of remote_ip, and a "common_log" field.
 *     Fields added with log_append (e.g. upstream_hostport, upstream_duration) are used when present.
 *   - `format console`: "<time>\t<LEVEL>\thttp.log.access...\thandled request\t{json}"
 *   - Common Log Format lines (transform-encoder plugin "{common_log}")
 *   - runtime log entries of the reverse proxy / health checkers, kept as events
 * Query strings and user agents are never stored; clients are counters only.
 */
const { createAggregator: createCore } = require('../../logs/haproxy');
const { parseTimeLocal } = require('../../logs/nginx');

const NO_UP = '(no upstream)';
const CLF_RE = /^(\S+) \S+ (\S+) \[([^\]]{10,40})\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)/;
const CONSOLE_RE = /^(\d{4})\/(\d\d)\/(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?\t(\S+)\t(\S+)\t([^\t]*)\t(\{.*\})\s*$/;

/** Caddy timestamps -> epoch ms. */
function tsOf(v) {
  if (typeof v === 'number') return v > 1e17 ? v / 1e6 : v > 1e14 ? v / 1e3 : v > 1e11 ? v : v * 1000;
  if (typeof v !== 'string' || !v) return null;
  if (/^\d+(\.\d+)?$/.test(v)) return tsOf(Number(v));
  const w = /^(\d{4})\/(\d\d)\/(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d+))?/.exec(v);
  if (w) return Date.UTC(+w[1], +w[2] - 1, +w[3], +w[4], +w[5], +w[6], Number(`0.${w[7] || 0}`) * 1000);
  const clf = parseTimeLocal(v); if (clf !== null) return clf;
  const iso = Date.parse(v.replace(/([+-]\d\d)(\d\d)$/, '$1:$2'));
  return Number.isNaN(iso) ? null : iso;
}
/** Caddy durations -> ms (-1 when absent). */
function durationMs(v) {
  if (v === undefined || v === null || v === '') return -1;
  if (typeof v === 'number') return Number.isInteger(v) && v > 1e5 ? Math.round(v / 1e6) : Math.round(v * 1000); // ns integers vs float seconds
  const s = String(v); let ms = 0; let any = false;
  for (const m of s.matchAll(/(\d+(?:\.\d+)?)(h|ms|m|s|µs|us|ns)/g)) { any = true; ms += Number(m[1]) * { h: 3600000, m: 60000, s: 1000, ms: 1, us: 0.001, µs: 0.001, ns: 1e-6 }[m[2]]; }
  if (any) return Math.round(ms);
  return /^\d+(\.\d+)?$/.test(s) ? Math.round(Number(s) * 1000) : -1;
}
const stripQuery = (u) => { const q = String(u || '').indexOf('?'); return q >= 0 ? String(u).slice(0, q) : String(u || ''); };
const isAccess = (o) => o && typeof o === 'object' && o.request && typeof o.request === 'object' && (o.request.method || o.request.uri) && (o.status !== undefined || /^http\.log\.access/.test(o.logger || ''));

function createCaddyAggregator() {
  const core = createCore();
  const st = core.stats;

  function request(o, tOverride) {
    const r = o.request;
    const t = tOverride != null ? tOverride : tsOf(o.ts);
    const status = Number(o.status);
    if (t === null || !Number.isInteger(status) || status < 0 || status > 599) return false;
    const ip = String(r.client_ip || r.remote_ip || (r.remote_addr ? String(r.remote_addr).replace(/:\d+$/, '').replace(/^\[|\]$/g, '') : '-')).slice(0, 64);
    const up = o.upstream_hostport || o.upstream || o.upstream_addr || (o.resp_headers && o.resp_headers['X-Upstream'] && o.resp_headers['X-Upstream'][0]) || null;
    const tt = durationMs(o.duration);
    const urt = durationMs(o.upstream_duration ?? o.upstream_latency);
    const host = String(r.host || '').toLowerCase().replace(/:\d+$/, '').slice(0, 120);
    // status 0: the client went away before a response was written (Caddy logs these with status 0)
    const term = status === 0 ? 'CH--' : status === 504 ? 'sH--' : status === 502 ? 'SH--' : '----';
    st.http++;
    core.addRequest({
      proto: 'http', t, client: `${ip}:0`, fe: host || (o.logger ? String(o.logger).replace(/^http\.log\.access\.?/, '') || '(any host)' : '(any host)'), be: up ? '(upstream)' : NO_UP, srv: up ? String(up).slice(0, 120) : NO_UP,
      tq: 0, tw: 0, tc: 0, tr: urt, tt: tt >= 0 ? tt : 0, timed: tt >= 0, status, bytes: Number(o.size) || 0, term, act: 0, cfe: 0, cbe: 0, csv: 0, retr: 0, sq: 0, bq: 0,
      method: String(r.method || '-').slice(0, 12), path: stripQuery(r.uri || '').slice(0, 2000), version: String(r.proto || '').slice(0, 12), host,
    });
    return true;
  }

  function runtimeEvent(o, t) {
    const logger = String(o.logger || ''); const msg = String(o.msg || '');
    if (!/reverse_proxy|health_checker|tls|http\.log\.error|admin|^$/.test(logger) && !/^(error|warn|fatal|panic)$/.test(o.level)) return false;
    const down = /unhealthy|host is down|failed|error|dial|refused|timeout/i.test(msg) || /^(error|fatal|panic)$/.test(o.level);
    const up = /healthy|host is up/i.test(msg) && !/unhealthy/i.test(msg);
    const what = o.host || o.upstream || o.address || '';
    core.addEvent(down ? 'down' : up ? 'up' : 'info', t, `[${o.level || 'info'}] ${logger ? `${logger}: ` : ''}${msg}${what ? ` (${String(what).slice(0, 80)})` : ''}`.slice(0, 300));
    return true;
  }

  function pushObject(o, tOverride) {
    if (!o || typeof o !== 'object') return false;
    if (isAccess(o)) return request(o, tOverride);
    const t = tOverride != null ? tOverride : tsOf(o.ts);
    if (t !== null && (o.logger !== undefined || o.msg !== undefined) && o.level) return runtimeEvent(o, t);
    return false;
  }

  function push(raw) {
    if (!raw || raw.length < 12) { if (raw && raw.trim()) { st.lines++; st.unparsed++; } return false; }
    st.lines++;
    if (raw.charCodeAt(0) === 123) { let o; try { o = JSON.parse(raw); } catch { return core.miss(raw); } return pushObject(o) || core.miss(raw); }
    const c = CONSOLE_RE.exec(raw);
    if (c) {
      let o; try { o = JSON.parse(c[11]); } catch { return core.miss(raw); }
      const t = Date.UTC(+c[1], +c[2] - 1, +c[3], +c[4], +c[5], +c[6], Number(`0.${c[7] || 0}`) * 1000);
      return pushObject({ ...o, level: String(c[8]).toLowerCase().replace(/\x1b\[[0-9;]*m/g, ''), logger: c[9], msg: c[10] }, t) || core.miss(raw);
    }
    const m = CLF_RE.exec(raw);
    if (m) {
      const t = parseTimeLocal(m[3]); if (t === null) return core.miss(raw);
      const parts = m[4].split(' ');
      return request({ request: { remote_ip: m[1], method: parts[0], uri: parts.slice(1, -1).join(' ') || parts[1] || '', proto: parts.length > 2 ? parts[parts.length - 1] : '' }, status: Number(m[5]), size: m[6] === '-' ? 0 : Number(m[6]) }, t);
    }
    return core.miss(raw);
  }

  function finish(meta = {}) { return core.finish({ product: 'caddy', ...meta }); }
  return { push, finish, stats: st };
}

/** Share of lines that are Caddy log entries (JSON with a nested request object, or console format). CLF is not counted:
 *  it is NGINX's format too, so it must not make NGINX logs look like Caddy's. */
function sniff(lines) {
  let ok = 0; let tried = 0;
  for (const l of lines) {
    if (!l || l.length < 12) continue; tried++;
    if (l.charCodeAt(0) === 123) { try { const o = JSON.parse(l); if (isAccess(o) || (o && typeof o.logger === 'string' && /^(http|tls|admin|caddy)/.test(o.logger) && o.ts !== undefined)) ok++; } catch { /* not JSON */ } continue; }
    if (CONSOLE_RE.test(l) && /\t(http|tls|admin)\.[\w.]+\t/.test(l)) ok++;
  }
  return { tried, ok, ratio: tried ? ok / tried : 0 };
}

module.exports = { createAggregator: createCaddyAggregator, sniff, tsOf, durationMs };

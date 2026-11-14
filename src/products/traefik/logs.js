'use strict';
/**
 * Traefik access log -> the shared Traffic Stats aggregates (core in src/logs/haproxy.js).
 *
 * Formats (observability/access-logs, source pkg/middlewares/accesslog/logger_formatters.go):
 *   common (Traefik CLF):  <ClientHost> - <ClientUsername> [<StartUTC 02/Jan/2006:15:04:05 -0700>] "<RequestMethod> <RequestPath> <RequestProtocol>"
 *                          <DownstreamStatus> <DownstreamContentSize> "<Referer>" "<User-Agent>" <RequestCount> "<RouterName>" "<ServiceURL>" <Duration>ms
 *   genericCLF (v3):       the same without the last four fields (plain combined format; NGINX's parser reads it as well)
 *   json:                  one object per line with ClientHost, RequestMethod, RequestPath, RequestHost, DownstreamStatus,
 *                          DownstreamContentSize, Duration (ns), OriginDuration (ns), RouterName, ServiceName, ServiceURL / ServiceAddr,
 *                          StartUTC / StartLocal / time, RetryAttempts, ...
 * Mapping: frontend = the router's entryPoint when the parsed config is given ({ sections }), else the router name;
 *          backend = the service; server = ServiceAddr (host:port of the server that answered).
 * Query strings and user agents are never stored.
 */
const { createAggregator: createCore } = require('../../logs/haproxy');

const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
// "<ip> - <user> [time] "<request>" <status> <size> "<ref>" "<ua>" <count> "<router>" "<url>" <dur>ms"
const CLF_RE = /^(\S+) - (\S+) \[([^\]]{10,40})\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\d+|-) "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)" (\d+|-) "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)" (\d+)ms\s*$/;
const NO_SVC = '(no service)';

function parseTime(s) {
  const m = /^(\d\d)\/([A-Za-z]{3})\/(\d{4}):(\d\d):(\d\d):(\d\d)(?: ([+-])(\d\d)(\d\d))?$/.exec(s);
  if (!m || MON[m[2]] === undefined) return null;
  let t = Date.UTC(+m[3], MON[m[2]], +m[1], +m[4], +m[5], +m[6]);
  if (m[7]) t -= (m[7] === '-' ? -1 : 1) * (+m[8] * 60 + +m[9]) * 60000;
  return t;
}
const strip = (n) => String(n || '').replace(/@[^@]*$/, '');
const hostPort = (url) => { const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/?#]+)/i.exec(String(url || '')); return m ? m[1] : ''; };
const noQuery = (p) => { const i = String(p).indexOf('?'); return i >= 0 ? String(p).slice(0, i) : String(p); };

/**
 * @param {{ sections?: object[] }} [opts] parsed config: lets routers be reported under their entryPoint (frontend).
 */
function createAggregator(opts = {}) {
  const core = createCore();
  const st = core.stats;
  const routerEp = new Map(); const routerSvc = new Map();
  for (const fe of (opts.sections || []).filter((s) => s.type === 'frontend')) for (const r of fe.routes || []) if (r.router && !routerEp.has(r.router)) { routerEp.set(r.router, fe.name); if (r.target) routerSvc.set(r.router, r.target); }
  const feOf = (router) => { const r = strip(router); return routerEp.get(r) || routerEp.get(router) || (r && r !== '-' ? r : '(no router)'); };

  function request(f) {
    const [method, path0, version] = (() => {
      const a = f.request.split(' ');
      return a.length >= 3 ? [a[0], a.slice(1, -1).join(' '), a[a.length - 1]] : [a[0] || '-', a[1] || '', ''];
    })();
    const status = f.status;
    const term = status === 499 ? 'CH--' : status === 504 ? 'sH--' : status === 502 ? 'SH--' : '----';
    st.http++;
    core.addRequest({
      proto: 'http', t: f.t, client: `${f.ip}:0`, fe: feOf(f.router).slice(0, 120), be: f.service ? strip(f.service).slice(0, 120) : (f.router && (routerSvc.get(strip(f.router)) || (f.server ? `(service of ${strip(f.router)})` : null))) || NO_SVC, srv: f.server || (f.service ? '(unknown)' : NO_SVC),
      tq: 0, tw: 0, tc: 0, tr: f.origin >= 0 ? f.origin : -1, tt: f.dur >= 0 ? f.dur : 0, timed: f.dur >= 0,
      status, bytes: f.bytes, term, act: 0, cfe: 0, cbe: 0, csv: 0, retr: f.retries || 0, sq: 0, bq: 0, method, path: noQuery(path0), version, host: f.host || '',
    });
    return true;
  }

  function pushJson(raw) {
    let o; try { o = JSON.parse(raw); } catch { return false; }
    if (!o || typeof o !== 'object') return false;
    const status = Number(o.DownstreamStatus ?? o.OriginStatus);
    const tv = o.StartUTC || o.StartLocal || o.time;
    const t = typeof tv === 'string' ? Date.parse(tv) : null;
    if (!Number.isFinite(t) || !Number.isInteger(status) || !o.RequestMethod) return false;
    const ns = (v) => (typeof v === 'number' ? Math.round(v / 1e6) : -1);
    return request({
      ip: String(o.ClientHost || o.ClientAddr || '-').replace(/:\d+$/, ''), t, request: `${o.RequestMethod} ${o.RequestPath || '/'} ${o.RequestProtocol || 'HTTP/1.1'}`, status,
      bytes: Number(o.DownstreamContentSize) || 0, dur: ns(o.Duration), origin: ns(o.OriginDuration), router: o.RouterName || '', service: o.ServiceName || '',
      server: o.ServiceAddr ? String(o.ServiceAddr).slice(0, 120) : hostPort(o.ServiceURL), host: o.RequestHost ? String(o.RequestHost).replace(/:\d+$/, '').slice(0, 120) : '', retries: Number(o.RetryAttempts) || 0,
    });
  }

  function push(raw) {
    if (!raw || raw.length < 12) { if (raw && raw.trim()) { st.lines++; st.unparsed++; } return false; }
    st.lines++;
    if (raw.charCodeAt(0) === 123) return pushJson(raw) || core.miss(raw);
    const m = CLF_RE.exec(raw);
    if (!m) return core.miss(raw);
    const t = parseTime(m[3]); if (t === null) return core.miss(raw);
    const url = m[11] === '-' ? '' : m[11];
    return request({ ip: m[1], t, request: m[4], status: m[5] === '-' ? 0 : +m[5], bytes: m[6] === '-' ? 0 : +m[6], dur: +m[12], origin: -1, router: m[10] === '-' ? '' : m[10], service: '', server: hostPort(url), host: '' });
  }

  function finish(meta = {}) { return core.finish({ product: 'traefik', ...meta }); }
  return { push, finish, stats: st };
}

/** Share of lines in Traefik's CLF (with the router / URL / duration tail) or JSON access log format. */
function sniff(lines) {
  let ok = 0; let tried = 0;
  for (const l of lines) {
    if (!l || l.length < 12) continue;
    tried++;
    if (l[0] === '{') { try { const o = JSON.parse(l); if (o && (o.RouterName !== undefined || o.DownstreamStatus !== undefined) && o.RequestMethod) ok++; } catch { /* not json */ } }
    else if (CLF_RE.test(l) && parseTime((CLF_RE.exec(l) || [])[3] || '') !== null) ok++;
  }
  // `specific`: these lines carry Traefik's own fields (router / service URL / duration tail, or Traefik JSON keys), which a
  // generic combined-format parser (NGINX, Apache) also accepts; a tie should go to Traefik.
  return { tried, ok, ratio: tried ? ok / tried : 0, specific: ok > 0 };
}

module.exports = { createAggregator, sniff, parseTime, CLF_RE };

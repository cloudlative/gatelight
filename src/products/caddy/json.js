'use strict';
/**
 * Caddy's native JSON config (https://caddyserver.com/docs/json/) -> the same shared model as the Caddyfile.
 *
 *   apps.http.servers.<name>.listen                -> binds (TLS when the port is the HTTPS port or the server has
 *                                                     tls_connection_policies; automatic HTTPS redirects as in model.js)
 *   routes[].match (host)                          -> one frontend per host route (the shape the Caddyfile adapter emits),
 *                                                     otherwise one frontend per server
 *   routes[] / handle[] (subroute, rewrite incl. strip_path_prefix / uri_substring / path_regexp, headers, static_response,
 *   file_server, reverse_proxy with upstreams[].dial, load_balancing.selection_policy, health_checks.active / passive,
 *   transport.tls)                                 -> routes in JSON order (JSON routes are never re-sorted)
 * Line numbers point at the first occurrence of a distinctive string in the file (JSON has no other line information).
 */
const { convertPart, parseUpstream, escapeRe } = require('./model');

const isJson = (text) => { const t = String(text || '').trim(); if (!t.startsWith('{')) return false; try { const o = JSON.parse(t); return Boolean(o && typeof o === 'object' && (o.apps || o.admin || o.logging || o.storage)); } catch { return false; } };

function lineFinder(text) {
  const lines = String(text).split('\n');
  return (needle) => { if (!needle) return 1; const s = String(needle); const i = lines.findIndex((l) => l.includes(s)); return i >= 0 ? i + 1 : 1; };
}

const blank = (o) => ({ acls: [], routes: [], servers: [], users: [], timeouts: {}, binds: [], directives: [], effective: { mode: 'http', timeouts: {}, defaultServer: {} }, ...o });

/** A JSON matcher set -> contract matchers (AND). */
function convertSet(set) {
  const out = [];
  for (const [k, v] of Object.entries(set || {})) {
    if (k === 'host' || k === 'path' || k === 'method' || k === 'protocol') out.push(...convertPart({ type: k, args: [].concat(v) }));
    else if (k === 'path_regexp') out.push(...convertPart({ type: 'path_regexp', args: [v.pattern || ''] }));
    else if (k === 'header') for (const [h, vals] of Object.entries(v)) out.push(...convertPart({ type: 'header', args: [h, ...(vals || [])] }));
    else if (k === 'header_regexp') for (const [h, r] of Object.entries(v)) out.push(...convertPart({ type: 'header_regexp', args: [h, r.pattern || ''] }));
    else if (k === 'query') out.push(...convertPart({ type: 'query', args: Object.entries(v).flatMap(([q, vals]) => (vals || ['*']).map((x) => `${q}=${x}`)) }));
    else if (k === 'remote_ip' || k === 'client_ip') out.push(...convertPart({ type: k, args: v.ranges || [] }));
    else if (k === 'not') for (const s of [].concat(v)) out.push(...convertSet(s).map((m) => ({ ...m, negated: !m.negated })));
    else if (k === 'expression') out.push(...convertPart({ type: 'expression', args: [typeof v === 'string' ? v : v.expr || ''] }));
    else out.push({ field: k, op: 'is', values: [JSON.stringify(v).slice(0, 80)], negated: false });
  }
  return out;
}

function parseJsonConfig(text, fileName = 'caddy.json') {
  const cfg = JSON.parse(text);
  const at = lineFinder(text);
  const http = (cfg.apps && cfg.apps.http) || {};
  const httpPort = http.http_port || 80; const httpsPort = http.https_port || 443;
  const sections = [];
  const adminListen = cfg.admin ? (cfg.admin.disabled ? null : cfg.admin.listen || 'localhost:2019') : 'localhost:2019';
  const gdirs = [];
  if (cfg.admin) gdirs.push({ keyword: 'admin', args: [cfg.admin.disabled ? 'off' : adminListen], line: at('"admin"'), file: fileName, raw: `admin ${adminListen}`, within: [] });
  sections.push(blank({ type: 'global', name: 'global', line: 1, endLine: 1, file: fileName, mode: null, directives: gdirs, options: { httpPort, httpsPort, autoHttps: 'on', admin: { listen: adminListen, off: Boolean(cfg.admin && cfg.admin.disabled), explicit: Boolean(cfg.admin) }, servers: [] }, json: true }));
  const backends = new Map(); const beNames = new Set(); const feNames = new Set(); const redirectHosts = [];

  const backendFor = (h, label) => {
    const ups = (h.upstreams || []).flatMap((u) => parseUpstream(u.dial || '').map((x) => ({ ...x, maxRequests: u.max_requests })));
    const tls = Boolean(h.transport && h.transport.tls);
    if (tls) ups.forEach((u) => { if (u.scheme === 'http') u.scheme = 'https'; });
    if (h.transport && h.transport.protocol === 'fastcgi') ups.forEach((u) => { u.scheme = 'fastcgi'; });
    const lb = (h.load_balancing && h.load_balancing.selection_policy && h.load_balancing.selection_policy.policy) || 'random';
    const key = `${ups.map((u) => `${u.scheme}://${u.address}`).sort().join(',')}|${lb}|${h.dynamic_upstreams ? JSON.stringify(h.dynamic_upstreams) : ''}`;
    if (backends.has(key)) return backends.get(key);
    let name = ups.length === 1 ? ups[0].address : label;
    if (beNames.has(name)) name = `${name}#${backends.size + 1}`;
    beNames.add(name);
    const active = h.health_checks && h.health_checks.active; const passive = h.health_checks && h.health_checks.passive;
    const line = at(ups[0] ? `"${ups[0].dial}"` : '"reverse_proxy"');
    const weights = lb === 'weighted_round_robin' ? (h.load_balancing.selection_policy.weights || []) : [];
    const be = blank({
      type: 'backend', name, line, endLine: line, file: fileName, mode: 'http', implicit: false, balance: lb, sticky: ['cookie', 'ip_hash', 'client_ip_hash', 'uri_hash', 'header', 'query'].includes(lb),
      servers: ups.map((u, i) => ({ name: u.address, address: u.address, scheme: u.scheme, check: Boolean(active || (passive && passive.fail_duration)), backup: lb === 'first' && i > 0, disabled: weights.length ? weights[i] === 0 : false, weight: weights.length ? weights[i] ?? 0 : null, opts: { dial: u.dial }, options: '', line: at(`"${u.dial}"`), file: fileName, commented: false })),
      healthCheck: active ? { path: active.uri || active.path || null, port: active.port || null, interval: active.interval || '30s', timeout: active.timeout || null, passes: active.passes || null, fails: active.fails || null } : null,
      passiveHealth: passive && passive.fail_duration ? passive : null,
      dynamic: h.dynamic_upstreams || null, transport: { protocol: (h.transport && h.transport.protocol) || 'http', tls, insecureSkipVerify: Boolean(h.transport && h.transport.tls && h.transport.tls.insecure_skip_verify), versions: (h.transport && h.transport.versions) || null },
      lbTryDuration: h.load_balancing && h.load_balancing.try_duration ? String(h.load_balancing.try_duration) : null, lbRetries: h.load_balancing && h.load_balancing.retries || null,
      directives: [], uses: [{ file: fileName, line }],
    });
    backends.set(key, be);
    return be;
  };

  for (const [srvName, srv] of Object.entries(http.servers || {})) {
    const listen = srv.listen || [];
    const tlsServer = Boolean(srv.tls_connection_policies) || listen.some((l) => String(l).endsWith(`:${httpsPort}`));
    const autoOff = Boolean(srv.automatic_https && srv.automatic_https.disable);
    const noRedirect = autoOff || Boolean(srv.automatic_https && srv.automatic_https.disable_redirects);
    const binds = listen.map((l) => { const s = String(l).replace(/^(tcp|udp)\//, ''); const port = (/:(\d+)(?:-\d+)?$/.exec(s) || [])[1] || ''; const host = s.slice(0, s.lastIndexOf(':')); return { address: `${host || '*'}:${port}`, addresses: [`${host || '*'}:${port}`], port, ssl: tlsServer && (port === String(httpsPort) || Boolean(srv.tls_connection_policies)), options: {}, line: at(`"${l}"`), file: fileName, commented: false }; });
    const groups = [];
    const hostRoutes = (srv.routes || []).filter((r) => (r.match || []).some((m) => m.host));
    if (hostRoutes.length && hostRoutes.length === (srv.routes || []).length) for (const r of srv.routes) groups.push({ hosts: [...new Set((r.match || []).flatMap((m) => m.host || []))], routes: [{ ...r, match: (r.match || []).map(({ host, ...rest }) => rest).filter((m) => Object.keys(m).length) }] });
    else groups.push({ hosts: [], routes: srv.routes || [] });
    for (const grp of groups) {
      let name = grp.hosts.length ? grp.hosts.join(', ') : `${srvName} (${listen.join(' ')})`;
      if (feNames.has(name)) name = `${name}#${srvName}`;
      feNames.add(name);
      const fe = blank({ type: 'frontend', name, line: at(grp.hosts[0] ? `"${grp.hosts[0]}"` : `"${srvName}"`), endLine: 0, file: fileName, mode: 'http', binds, serverNames: grp.hosts.map((h) => h.toLowerCase()), locations: [], directives: [], server: srvName, json: true });
      fe.endLine = fe.line;
      const addRoute = (ctx, extra, h) => {
        const matchers = ctx.matchers;
        const pathM = matchers.find((m) => m.field === 'Path' && !m.negated);
        const line = at(extra.needle || `"handler": "${h.handler}"`);
        fe.routes.push({
          target: null, type: matchers.length ? 'conditional' : 'default', condition: ctx.conds.join(' › ') || 'DEFAULT', rawCondition: ctx.conds.join(' › '),
          match: matchers.length ? matchers.map((m) => `${m.negated ? 'not ' : ''}${m.field.toLowerCase()} ${m.op} ${m.values.join(' or ')}`).join(' and ') : 'any request',
          short: `${grp.hosts[0] || '*'}${pathM ? (pathM.op === 'begins with' ? `${pathM.values[0]}*` : pathM.values[0]) : ''}`, matchers, hosts: fe.serverNames, paths: pathM ? pathM.values : [],
          priority: fe.routes.length + 1, transforms: [...ctx.transforms, ...(extra.own || [])], passUrl: null, terminal: false, line, file: fileName, commented: false, dynamic: false, external: false, directive: h.handler, aclRefs: [], ...extra,
        });
        const last = fe.routes[fe.routes.length - 1]; delete last.needle; delete last.own;
      };
      const walk = (routes, ctx) => {
        for (const r of routes || []) {
          const sets = r.match && r.match.length ? r.match : [null];
          for (const set of sets) {
            const ms = set ? convertSet(set) : [];
            const c = { matchers: [...ctx.matchers, ...ms], conds: [...ctx.conds, ...(set ? [JSON.stringify(set).slice(0, 120)] : [])], transforms: [...ctx.transforms] };
            let stop = false;
            for (const h of r.handle || []) {
              const tl = (action, args, text) => ({ action, args, line: at(`"handler": "${h.handler}"`), file: fileName, text });
              switch (h.handler) {
                case 'subroute': walk(h.routes, c); break;
                case 'rewrite':
                  if (h.strip_path_prefix) c.transforms.push(tl('strip-prefix', [h.strip_path_prefix], `strip_path_prefix ${h.strip_path_prefix}`));
                  if (h.strip_path_suffix) c.transforms.push(tl('replace-path-regex', [`${escapeRe(h.strip_path_suffix)}$`, ''], `strip_path_suffix ${h.strip_path_suffix}`));
                  if (h.uri) c.transforms.push(tl(/^\//.test(h.uri) ? 'set-path' : 'set-query', [h.uri], `rewrite ${h.uri}`));
                  for (const s of h.uri_substring || []) c.transforms.push(tl('replace-path-regex', [escapeRe(s.find || ''), s.replace || ''], `replace ${s.find} ${s.replace}`));
                  for (const s of h.path_regexp || []) c.transforms.push(tl('replace-path-regex', [s.find, s.replace], `path_regexp ${s.find} ${s.replace}`));
                  break;
                case 'headers': if (h.request && h.request.set) for (const [k, v] of Object.entries(h.request.set)) c.transforms.push(tl('set-header', [k, ...[].concat(v)], `request header ${k}`)); break;
                case 'static_response': {
                  const loc = h.headers && (h.headers.Location || h.headers.location);
                  const status = String(h.status_code || 200);
                  if (loc) addRoute(c, { terminal: true, kind: 'redirect', detail: `${status} ${[].concat(loc)[0]}`, own: [tl('redirect', [status, [].concat(loc)[0]], `redirect ${[].concat(loc)[0]}`)] }, h);
                  else addRoute(c, { terminal: true, kind: 'return', detail: status, own: [tl('return', [status], `static_response ${status}`)] }, h);
                  stop = true; break;
                }
                case 'file_server': addRoute(c, { terminal: true, kind: 'static', detail: h.root || null, browse: Boolean(h.browse), needle: '"file_server"', own: [tl('static', h.root ? [h.root] : [], `file_server${h.root ? ` from ${h.root}` : ''}`)] }, h); stop = true; break;
                case 'error': addRoute(c, { terminal: true, kind: 'return', own: [tl('return', [String(h.status_code || 500)], 'error')] }, h); stop = true; break;
                case 'reverse_proxy': {
                  const pathM = c.matchers.find((m) => m.field === 'Path' && !m.negated);
                  const be = backendFor(h, `${grp.hosts[0] || srvName}${pathM ? pathM.values[0].replace(/\/$/, '') || '/' : ''}`);
                  const own = [];
                  const set = h.headers && h.headers.request && h.headers.request.set;
                  if (set && (set.Host || set.host)) own.push(tl('set-header', ['Host', ...[].concat(set.Host || set.host)], 'header_up Host'));
                  if (h.rewrite && h.rewrite.uri) own.push(tl('set-path', [h.rewrite.uri], `rewrite ${h.rewrite.uri}`));
                  addRoute(c, { target: be.name, kind: 'proxy', detail: (h.upstreams || []).map((u) => u.dial).join(' '), own, needle: h.upstreams && h.upstreams[0] ? `"${h.upstreams[0].dial}"` : '"reverse_proxy"' }, h);
                  stop = true; break;
                }
                default: break;
              }
              if (stop) break;
            }
          }
        }
      };
      walk(grp.routes, { matchers: [], conds: [], transforms: [] });
      if (tlsServer && !noRedirect) grp.hosts.forEach((h) => redirectHosts.push({ host: h, line: fe.line }));
      sections.push(fe);
    }
  }
  const plainHosts = new Set(sections.filter((s) => s.type === 'frontend' && s.binds.some((b) => b.port === String(httpPort))).flatMap((s) => s.serverNames));
  const red = redirectHosts.filter((r) => !plainHosts.has(r.host));
  if (red.length) {
    const fe = blank({ type: 'frontend', name: `(auto HTTPS redirects):${httpPort}`, line: red[0].line, endLine: red[0].line, file: fileName, mode: 'http', implicit: true, binds: [{ address: `*:${httpPort}`, addresses: [`*:${httpPort}`], port: String(httpPort), ssl: false, options: { autoHttpsRedirect: true }, line: red[0].line, file: fileName, commented: false }], serverNames: [...new Set(red.map((r) => r.host))], locations: [], directives: [] });
    fe.routes.push({ target: null, type: 'default', condition: 'Automatic HTTPS redirect', rawCondition: '', match: 'any request to a site served over HTTPS', short: 'http://*', matchers: [], hosts: fe.serverNames, paths: [], priority: 1, transforms: [{ action: 'redirect', args: ['308', 'https://{host}{uri}'], line: red[0].line, file: fileName, text: 'redir https://{host}{uri} 308 (automatic)' }], passUrl: null, terminal: true, line: red[0].line, file: fileName, commented: false, dynamic: false, external: false, directive: 'auto_https', kind: 'redirect', aclRefs: [] });
    sections.push(fe);
  }
  sections.push(...backends.values());
  return { sections, config: cfg };
}

module.exports = { parseJsonConfig, isJson, convertSet };

'use strict';
/**
 * Caddyfile tree -> GateLight's shared section model (src/products/CONTRACT.md).
 *
 *   global options block      -> section "global"
 *   site block (address list) -> section "frontend": serverNames from the host names, binds from the addresses and the
 *                                Automatic HTTPS rules (https://caddyserver.com/docs/automatic-https): a site with a host
 *                                name is served over TLS on the HTTPS port, and Caddy adds an HTTP->HTTPS redirect on the
 *                                HTTP port (one extra frontend "(auto HTTPS redirects)") unless `auto_https off` /
 *                                `disable_redirects`, or the site is written with http://
 *   reverse_proxy upstreams   -> section "backend" (one per distinct upstream set + policy)
 *
 * Routes are emitted in Caddy's real evaluation order: directives are sorted by the default directive order of the
 * release (directives.go at each tag, adjusted by the `order` global option), same-named directives by matcher
 * specificity (https://caddyserver.com/docs/caddyfile/directives#sorting-algorithm, sortRoutes() in Caddy), `route`
 * blocks keep their literal order and `handle` / `handle_path` blocks are mutually exclusive and sorted like the rest.
 * A terminal handler (reverse_proxy, file_server, respond, redir, abort, error, php_fastcgi) ends the chain, so the first
 * route that matches wins.
 */
const { orderFor } = require('./kb');

const HANDLER_TERMINAL = new Set(['reverse_proxy', 'php_fastcgi', 'file_server', 'respond', 'redir', 'abort', 'error', 'acme_server', 'metrics', 'copy_response']);
const NON_HANDLER = new Set(['bind', 'tls', 'log', 'handle_errors', 'import', 'invoke_', 'root_']);
const MATCHABLE_FIRST = (t) => t && !t.quoted && (t.text === '*' || t.text.startsWith('/') || t.text.startsWith('@'));
const NO_MATCHER_DIRECTIVES = new Set(['bind', 'tls', 'log', 'handle_errors', 'import', 'invoke', 'map', 'tracing']);

// ------------------------------------------------------------------------------------------------ global options
function globalOptions(node) {
  const g = { node, httpPort: 80, httpsPort: 443, autoHttps: 'on', admin: { listen: 'localhost:2019', off: false, explicit: false }, email: null, order: [], servers: [], defaultBind: [], localCerts: false, debug: false, log: false, metrics: false, directives: [] };
  if (!node) return g;
  for (const d of node.block || []) {
    g.directives.push({ keyword: d.name, args: d.args, line: d.line, file: d.file, raw: [d.name, ...d.args].join(' '), within: [] });
    const a = d.args;
    switch (d.name) {
      case 'http_port': g.httpPort = Number(a[0]) || 80; break;
      case 'https_port': g.httpsPort = Number(a[0]) || 443; break;
      case 'auto_https': g.autoHttps = a[0] || 'on'; break;
      case 'email': g.email = a[0] || null; break;
      case 'debug': g.debug = true; break;
      case 'local_certs': g.localCerts = true; break;
      case 'default_bind': g.defaultBind = a; break;
      case 'log': g.log = true; break;
      case 'metrics': g.metrics = true; break;
      case 'admin': g.admin = { listen: a[0] === 'off' ? null : (a[0] || 'localhost:2019'), off: a[0] === 'off', explicit: true, line: d.line, file: d.file, origins: (d.block || []).filter((x) => x.name === 'origins').flatMap((x) => x.args), enforceOrigin: (d.block || []).some((x) => x.name === 'enforce_origin') }; break;
      case 'order': g.order.push({ dir: a[0], pos: a[1], ref: a[2], line: d.line, file: d.file }); break;
      case 'servers': {
        const s = { listen: a[0] || null, line: d.line, file: d.file, trustedProxies: false, timeouts: {}, protocols: null, metrics: false };
        for (const x of d.block || []) {
          if (x.name === 'trusted_proxies') s.trustedProxies = x.args.length ? x.args : true;
          if (x.name === 'timeouts') for (const t of x.block || []) s.timeouts[t.name] = t.args[0];
          if (x.name === 'protocols') s.protocols = x.args;
          if (x.name === 'metrics') s.metrics = true;
        }
        g.servers.push(s); break;
      }
      default: break;
    }
  }
  return g;
}

/** Apply `order` global options to a directive order. */
function applyOrder(base, rules) {
  const order = [...base];
  for (const r of rules) {
    if (!r.dir) continue;
    const at = order.indexOf(r.dir); if (at >= 0) order.splice(at, 1);
    if (r.pos === 'first') order.unshift(r.dir);
    else if (r.pos === 'last') order.push(r.dir);
    else if ((r.pos === 'before' || r.pos === 'after') && order.includes(r.ref)) order.splice(order.indexOf(r.ref) + (r.pos === 'after' ? 1 : 0), 0, r.dir);
    else order.push(r.dir);
  }
  return order;
}

// ------------------------------------------------------------------------------------------------ addresses
/** Parse a site address: [scheme://]host[:port][/path]. */
function parseAddress(raw, g = { httpPort: 80, httpsPort: 443 }) {
  let s = String(raw).replace(/,$/, '');
  const out = { raw: s, scheme: '', host: '', port: '', path: '', error: null };
  const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s);
  if (m) { out.scheme = m[1].toLowerCase(); s = s.slice(m[0].length); }
  const slash = s.indexOf('/'); if (slash >= 0) { out.path = s.slice(slash); s = s.slice(0, slash); }
  if (/^\[[^\]]*\]/.test(s)) { const b = /^(\[[^\]]*\])(?::(.*))?$/.exec(s); out.host = b ? b[1] : s; out.port = b && b[2] !== undefined ? b[2] : ''; } else {
    const c = s.lastIndexOf(':');
    if (c >= 0 && !/\{[^}]*$/.test(s.slice(0, c))) { out.host = s.slice(0, c); out.port = s.slice(c + 1); } else out.host = s;
  }
  if (out.scheme && !['http', 'https', 'wss', 'ws'].includes(out.scheme)) out.error = `unsupported scheme "${out.scheme}://" (use http:// or https://)`;
  if (out.port && !/^\d{1,5}$/.test(out.port) && !/^\{.*\}$/.test(out.port)) out.error = `invalid port "${out.port}"`;
  else if (out.port && /^\d+$/.test(out.port) && (Number(out.port) < 1 || Number(out.port) > 65535)) out.error = `port ${out.port} is out of range`;
  if (out.host && !/^(\*|\*\.)?[A-Za-z0-9_.*{}$:-]+$/.test(out.host) && !/^\[[0-9a-fA-F:.%a-z]+\]$/.test(out.host)) out.error = out.error || `invalid host name "${out.host}"`;
  if (out.scheme === 'http' && out.port === String(g.httpsPort)) out.error = out.error || `http:// on the HTTPS port ${g.httpsPort} is contradictory`;
  if (out.scheme === 'https' && out.port === String(g.httpPort)) out.error = out.error || `https:// on the HTTP port ${g.httpPort} is contradictory`;
  // effective protocol / port (Automatic HTTPS rules)
  const ip = /^(\d{1,3}\.){3}\d{1,3}$|^\[/.test(out.host);
  if (!out.port) out.port = String(out.scheme === 'http' || out.scheme === 'ws' ? g.httpPort : out.scheme ? g.httpsPort : out.host ? g.httpsPort : g.httpPort);
  out.tls = out.scheme === 'https' || out.scheme === 'wss' ? true : out.scheme ? false : out.port === String(g.httpPort) ? false : Boolean(out.host) || out.port === String(g.httpsPort);
  out.ip = ip;
  out.hostname = out.host && out.host !== '*' ? out.host.toLowerCase() : '';
  return out;
}
const isPublicName = (h) => Boolean(h) && !/^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.home\.arpa|.*\.test|.*\.example|.*\.invalid|\d+\.\d+\.\d+\.\d+|\[.*\]|\{.*\})$/i.test(h) && /\./.test(h);

// ------------------------------------------------------------------------------------------------ matchers
const pathOp = (p) => {
  if (p === '*') return { op: 'begins with', value: '/' };
  const star = p.indexOf('*');
  if (star < 0) return { op: 'is', value: p };
  if (star === p.length - 1 && p.indexOf('*') === p.lastIndexOf('*')) return { op: 'begins with', value: p.slice(0, -1) };
  if (star === 0 && p.lastIndexOf('*') === 0) return { op: 'ends with', value: p.slice(1) };
  return { op: 'matches', value: p };
};
const OP_TEXT = { is: 'is', 'begins with': 'begins with', 'ends with': 'ends with', matches: 'matches', contains: 'contains' };

/** Named matcher definitions in a block list: @name ... */
function matcherDefs(nodes, out = new Map()) {
  for (const nd of nodes) {
    if (nd.name.startsWith('@')) {
      const name = nd.name;
      const parts = [];
      if (nd.block) for (const c of nd.block) parts.push({ type: c.name, args: c.args, block: c.block, line: c.line });
      if (nd.args.length) {
        const first = nd.args[0];
        if (nd.toks[1] && nd.toks[1].quoted) parts.push({ type: 'expression', args: [first], line: nd.line });
        else parts.push({ type: first, args: nd.args.slice(1), line: nd.line });
      }
      const prev = out.get(name);
      if (prev) prev.parts.push(...parts); else out.set(name, { name, parts, line: nd.line, file: nd.file, used: 0 });
    }
  }
  return out;
}

/** One matcher part -> contract matchers (an array: the part's conditions, all must hold). */
function convertPart(part, negated = false) {
  const a = part.args || [];
  const one = (field, op, values, extra = {}) => ({ field, op, values, negated, ...extra });
  switch (part.type) {
    case 'path': {
      const groups = new Map();
      for (const p of a) { const o = pathOp(p); const l = groups.get(o.op) || []; l.push(o.value); groups.set(o.op, l); }
      return [...groups.entries()].map(([op, values]) => one('Path', op, values, groups.size > 1 ? { anyOf: true } : {}));
    }
    case 'path_regexp': return [one('Path', 'matches', [a.length > 1 ? a[1] : a[0]])];
    case 'host': return [one('Host', a.some((h) => h.includes('*')) ? 'matches' : 'is', a)];
    case 'method': return [one('Method', 'is', a.map((x) => x.toUpperCase()))];
    case 'header': {
      const name = (a[0] || '').replace(/^!/, ''); const vals = a.slice(1);
      if (!vals.length) return [one('Header', 'is', ['*'], { name, negated: negated !== (a[0] || '').startsWith('!'), presence: true })];
      const v = vals[0];
      const op = v.startsWith('*') && v.endsWith('*') && v.length > 1 ? 'contains' : v.endsWith('*') ? 'begins with' : v.startsWith('*') ? 'ends with' : 'is';
      return [one('Header', op, vals.map((x) => x.replace(/^\*|\*$/g, '')), { name })];
    }
    case 'header_regexp': return [one('Header', 'matches', [a.length > 2 ? a[2] : a[1]], { name: a.length > 2 ? a[1] : a[0] })];
    case 'query': return [one('Query', 'is', a)];
    case 'remote_ip': case 'client_ip': return [one('ClientIP', 'is', a.filter((x) => x !== 'forwarded'), { name: part.type })];
    case 'protocol': return [one('Protocol', 'is', a)];
    case 'not': {
      const inner = part.block ? part.block.map((c) => ({ type: c.name, args: c.args, block: c.block })) : [{ type: a[0], args: a.slice(1) }];
      return inner.flatMap((p) => convertPart(p, !negated));
    }
    case 'expression': return [one('Expression', 'matches', [a.join(' ')])];
    case 'file': return [one('File', 'is', a.length ? a : ['{path}'])];
    case 'vars': case 'vars_regexp': return [one('Var', part.type === 'vars' ? 'is' : 'matches', a.slice(1), { name: a[0] })];
    case 'tls': return [one('TLS', 'is', a)];
    default: return [one(part.type, 'is', a)];
  }
}
const describe = (m) => `${m.negated ? 'not ' : ''}${m.field === 'Header' || m.field === 'Var' ? `header ${m.name}` : m.field === 'ClientIP' ? (m.name === 'remote_ip' ? 'remote IP' : 'client IP') : m.field.toLowerCase()} ${OP_TEXT[m.op] || m.op} ${m.values.join(' or ')}`.replace(/^header (\S+)/, m.field === 'Var' ? 'var $1' : 'header $1');

// ------------------------------------------------------------------------------------------------ reverse_proxy
function parseUpstream(raw) {
  let s = String(raw); let scheme = 'http';
  if (/^\{.*\}$/.test(s) || s.includes('{')) return [{ raw, dial: s, address: s, scheme: '', dynamic: true }];
  if (/^unix\//.test(s)) return [{ raw, dial: s, address: s, scheme: 'unix' }];
  const m = /^([a-z0-9+]+):\/\//i.exec(s);
  if (m) { scheme = { ws: 'http', wss: 'https', http: 'http', https: 'https', h2c: 'h2c', srv: 'http', 'srv+http': 'http', 'srv+https': 'https', fastcgi: 'fastcgi' }[m[1].toLowerCase()] || m[1].toLowerCase(); s = s.slice(m[0].length); }
  s = s.replace(/\/.*$/, '');
  let host = s; let port = '';
  const v6 = /^(\[[^\]]+\])(?::(.+))?$/.exec(s);
  if (v6) { host = v6[1]; port = v6[2] || ''; } else if (s.lastIndexOf(':') >= 0) { host = s.slice(0, s.lastIndexOf(':')); port = s.slice(s.lastIndexOf(':') + 1); }
  if (!host) host = 'localhost';
  if (!port) port = scheme === 'https' ? '443' : '80';
  const range = /^(\d+)-(\d+)$/.exec(port);
  if (range && Number(range[2]) - Number(range[1]) < 64) {
    const out = [];
    for (let p = Number(range[1]); p <= Number(range[2]); p++) out.push({ raw, dial: `${host}:${p}`, address: `${host}:${p}`, scheme });
    return out;
  }
  return [{ raw, dial: `${host}:${port}`, address: `${host}:${port}`, scheme }];
}

function parseReverseProxy(nd, firstArgIsMatcher) {
  const args = nd.args.slice(firstArgIsMatcher ? 1 : 0);
  const rp = { node: nd, upstreams: [], dynamic: null, lb: 'random', lbArgs: [], health: null, passive: null, transport: { protocol: 'http', tls: false, insecure: false, versions: null, opts: {} }, headerUp: [], headerDown: [], rewrite: null, method: null, retries: null, tryDuration: null, subs: [] };
  args.forEach((a) => rp.upstreams.push(...parseUpstream(a)));
  const hc = {};
  for (const c of nd.block || []) {
    rp.subs.push(c);
    const a = c.args;
    switch (c.name) {
      case 'to': a.forEach((x) => rp.upstreams.push(...parseUpstream(x))); break;
      case 'dynamic': rp.dynamic = { module: a[0], args: a.slice(1), line: c.line }; break;
      case 'lb_policy': rp.lb = a[0] || 'random'; rp.lbArgs = a.slice(1); break;
      case 'lb_retries': rp.retries = Number(a[0]); break;
      case 'lb_try_duration': rp.tryDuration = a[0]; break;
      case 'health_uri': case 'health_path': hc.uri = a[0]; break;
      case 'health_port': hc.port = a[0]; break;
      case 'health_interval': hc.interval = a[0]; break;
      case 'health_timeout': hc.timeout = a[0]; break;
      case 'health_passes': hc.passes = a[0]; break;
      case 'health_fails': hc.fails = a[0]; break;
      case 'health_status': hc.status = a[0]; break;
      case 'max_fails': case 'fail_duration': case 'unhealthy_status': case 'unhealthy_latency': case 'unhealthy_request_count':
        rp.passive = { ...(rp.passive || {}), [c.name]: a.join(' ') }; break;
      case 'header_up': rp.headerUp.push({ args: a, line: c.line, file: c.file }); break;
      case 'header_down': rp.headerDown.push({ args: a, line: c.line, file: c.file }); break;
      case 'rewrite': rp.rewrite = { to: a[0], line: c.line }; break;
      case 'method': rp.method = a[0]; break;
      case 'transport': {
        rp.transport.protocol = a[0] || 'http';
        for (const t of c.block || []) {
          rp.transport.opts[t.name] = t.args.join(' ');
          if (t.name === 'tls' || t.name.startsWith('tls_') && t.name !== 'tls_except_ports') rp.transport.tls = true;
          if (t.name === 'tls_insecure_skip_verify') { rp.transport.insecure = true; rp.transport.insecureLine = t.line; rp.transport.insecureFile = t.file; }
          if (t.name === 'versions') rp.transport.versions = t.args;
        }
        break;
      }
      default: break;
    }
  }
  if (hc.uri || hc.port) rp.health = { interval: '30s', ...hc };
  if (rp.passive && rp.passive.max_fails === undefined && rp.passive.fail_duration !== undefined) rp.passive.max_fails = '1';
  if (rp.passive && rp.passive.fail_duration === undefined) rp.passive.inactive = true; // passive checks need fail_duration > 0
  if (rp.transport.tls) rp.upstreams.forEach((u) => { if (u.scheme === 'http') u.scheme = 'https'; });
  if (rp.transport.protocol === 'fastcgi') rp.upstreams.forEach((u) => { u.scheme = 'fastcgi'; });
  return rp;
}

// ------------------------------------------------------------------------------------------------ sorting (Caddy's sortRoutes)
function sortKey(d, matcherDefsMap) {
  const name = d.dir === 'handle_path' ? 'handle' : d.dir;
  let sets = 0; let paths = null;
  if (d.matcherToken) {
    const t = d.matcherToken;
    if (t === '*') sets = 0;
    else if (t.startsWith('/')) { sets = 1; paths = [t]; } else if (t.startsWith('@')) {
      sets = 1; const def = matcherDefsMap.get(t);
      if (def) { const p = def.parts.filter((x) => x.type === 'path'); if (p.length === 1) paths = p[0].args; }
    }
  }
  return { name, sets, paths };
}
function sortDirectives(list, order, matcherDefsMap) {
  const pos = new Map(order.map((d, i) => [d, i]));
  const keyed = list.map((d) => ({ d, k: sortKey(d, matcherDefsMap) }));
  const less = (a, b) => {
    if (a.k.name !== b.k.name) return (pos.has(a.k.name) ? pos.get(a.k.name) : 1e6) < (pos.has(b.k.name) ? pos.get(b.k.name) : 1e6);
    let i = a; let j = b;
    if (a.k.name === 'vars' || a.k.name === 'log_level') { i = b; j = a; }
    const ip = i.k.sets === 1 && i.k.paths && i.k.paths.length === 1 ? i.k.paths[0] : null;
    const jp = j.k.sets === 1 && j.k.paths && j.k.paths.length === 1 ? j.k.paths[0] : null;
    if (ip && jp) {
      const it = ip.replace(/\*$/, ''); const jt = jp.replace(/\*$/, '');
      if (it === jt) return ip.length < jp.length;
      if (it.length === jt.length) return it < jt;
      return it.length > jt.length;
    }
    return i.k.sets > 0 && j.k.sets === 0;
  };
  // Go's sort.SliceStable: insertion sort on blocks of 20, then symmerge; insertion sort over the whole list matches it
  // for the common case and is stable.
  const arr = [...keyed];
  for (let x = 1; x < arr.length; x++) for (let y = x; y > 0 && less(arr[y], arr[y - 1]); y--) { const t = arr[y]; arr[y] = arr[y - 1]; arr[y - 1] = t; }
  return arr.map((x) => x.d);
}

// ------------------------------------------------------------------------------------------------ the model
function flatDirectives(nodes, within = [], out = []) {
  for (const nd of nodes) {
    out.push({ keyword: nd.name, args: nd.args, line: nd.line, file: nd.file, raw: [nd.name, ...nd.args].join(' '), within, block: Boolean(nd.block), snippet: nd.snippet || null });
    if (nd.block) flatDirectives(nd.block, [...within, `${nd.name} ${nd.args.join(' ')}`.trim()], out);
  }
  return out;
}

/** Split top-level nodes into the global options block, site blocks and stray lines. */
function structure(nodes) {
  let global = null; const sites = []; const stray = [];
  nodes.forEach((nd, i) => {
    if (!nd.toks.length && nd.block) { if (i === 0 && !global) global = nd; else stray.push(nd); return; }
    if (nd.block) sites.push({ keys: nd.toks.map((t) => t.text).join(' ').split(/[,\s]+/).filter(Boolean), node: nd, body: nd.block, line: nd.line, endLine: nd.endLine, file: nd.file });
    else stray.push(nd);
  });
  // a Caddyfile with a single site may omit the braces: the first line holds the addresses
  if (!sites.length && stray.length) {
    const [first, ...rest] = stray;
    sites.push({ keys: first.toks.map((t) => t.text).join(' ').split(/[,\s]+/).filter(Boolean), node: first, body: rest, line: first.line, endLine: (rest[rest.length - 1] || first).endLine, file: first.file, unbraced: true });
    stray.length = 0;
  }
  return { global, sites, stray };
}

const blank = (o) => ({ acls: [], routes: [], servers: [], users: [], timeouts: {}, binds: [], directives: [], effective: { mode: 'http', timeouts: {}, defaultServer: {} }, ...o });

/**
 * @param loaded result of Loader.load(): { nodes, namedRoutes, snippets }
 * @param opts { version }
 */
function buildModel(loaded, opts = {}) {
  const { global, sites, stray } = structure(loaded.nodes);
  const g = globalOptions(global);
  const version = opts.version || null;
  const order = applyOrder(orderFor(version || require('./kb').kb.latest), g.order);
  const sections = [];
  sections.push(blank({ type: 'global', name: 'global', line: global ? global.line : 1, endLine: global ? global.endLine : 1, file: global ? global.file : (loaded.nodes[0] || {}).file || 'Caddyfile', mode: null, directives: g.directives, options: { httpPort: g.httpPort, httpsPort: g.httpsPort, autoHttps: g.autoHttps, admin: g.admin, email: g.email, servers: g.servers, order: g.order } }));
  const backends = new Map(); // key -> section
  const beNames = new Set();
  const feNames = new Set();
  const redirectHosts = [];
  const proxies = [];
  const siteInfo = [];

  const backendFor = (rp, label, nd) => {
    const ups = rp.upstreams.filter((u) => !u.dynamic);
    const key = `${ups.map((u) => `${u.scheme}://${u.address}`).sort().join(',')}|${rp.lb}|${rp.dynamic ? `dyn:${rp.dynamic.module}:${rp.dynamic.args.join(' ')}` : ''}|${rp.upstreams.filter((u) => u.dynamic).map((u) => u.raw).join(',')}`;
    if (backends.has(key)) { const be = backends.get(key); be.uses.push({ file: nd.file, line: nd.line }); return be; }
    let name = ups.length === 1 && !rp.dynamic ? ups[0].address : rp.upstreams.length === 1 && rp.upstreams[0].dynamic ? rp.upstreams[0].raw : label;
    if (!name) name = `proxy@${nd.file}:${nd.line}`;
    if (beNames.has(name)) name = `${name}#${nd.line}`;
    beNames.add(name);
    const check = Boolean(rp.health) || Boolean(rp.passive && !rp.passive.inactive);
    const weights = rp.lb === 'weighted_round_robin' ? rp.lbArgs.map(Number) : [];
    const be = blank({
      type: 'backend', name, line: nd.line, endLine: nd.endLine, file: nd.file, mode: 'http', implicit: false,
      balance: rp.lb, sticky: ['cookie', 'ip_hash', 'client_ip_hash', 'uri_hash', 'header', 'query'].includes(rp.lb),
      servers: ups.map((u, i) => ({ name: u.address, address: u.address, scheme: u.scheme, check, backup: rp.lb === 'first' && i > 0, disabled: weights.length ? weights[i] === 0 : false, weight: weights.length ? (weights[i] ?? 0) : null, opts: { dial: u.dial, raw: u.raw }, options: '', line: nd.line, file: nd.file, commented: false })),
      healthCheck: rp.health ? { path: rp.health.uri || null, port: rp.health.port || null, interval: rp.health.interval, timeout: rp.health.timeout || null, passes: rp.health.passes || null, fails: rp.health.fails || null } : null,
      passiveHealth: rp.passive && !rp.passive.inactive ? rp.passive : null,
      dynamic: rp.dynamic || (rp.upstreams.some((u) => u.dynamic) ? { module: 'placeholder', args: rp.upstreams.filter((u) => u.dynamic).map((u) => u.raw) } : null),
      transport: { protocol: rp.transport.protocol, tls: rp.transport.tls, insecureSkipVerify: rp.transport.insecure, insecureLine: rp.transport.insecureLine || null, insecureFile: rp.transport.insecureFile || null, versions: rp.transport.versions },
      lbTryDuration: rp.tryDuration, lbRetries: rp.retries,
      directives: rp.subs.map((c) => ({ keyword: c.name, args: c.args, line: c.line, file: c.file, raw: [c.name, ...c.args].join(' '), within: [`reverse_proxy ${rp.node.args.join(' ')}`.trim()] })),
      uses: [{ file: nd.file, line: nd.line }],
    });
    backends.set(key, be);
    return be;
  };

  for (const site of sites) {
    const addrs = site.keys.map((k) => parseAddress(k, g));
    const hosts = [...new Set(addrs.map((a) => a.hostname).filter(Boolean))];
    const defs = matcherDefs(site.body);
    (function nested(nodes) { for (const nd of nodes) if (nd.block && !nd.name.startsWith('@')) { matcherDefs(nd.block, defs); nested(nd.block); } })(site.body);
    const tlsDirective = flatDirectives(site.body).find((d) => d.keyword === 'tls' && d.within.length === 0);
    const bindDirective = site.body.find((d) => d.name === 'bind');
    const bindHosts = bindDirective ? bindDirective.args : g.defaultBind;
    const ports = new Map();
    for (const a of addrs) {
      const ssl = a.tls || (Boolean(tlsDirective) && a.port !== String(g.httpPort) && a.scheme !== 'http');
      const k = `${a.port}|${ssl}`;
      if (!ports.has(k)) ports.set(k, { port: a.port, ssl, addresses: [] });
      ports.get(k).addresses.push(a.raw);
    }
    const binds = [...ports.values()].map((p) => {
      const addresses = bindHosts.length ? bindHosts.map((h) => `${h.includes(':') && !h.startsWith('[') ? `[${h}]` : h}:${p.port}`) : [`*:${p.port}`];
      return { address: addresses[0], addresses, port: p.port, ssl: p.ssl, options: { siteAddresses: p.addresses, autoHttps: p.ssl && !tlsDirective }, line: site.line, file: site.file, commented: false };
    });
    let name = site.keys.join(', ') || '(empty address)';
    if (name.length > 120) name = `${site.keys[0]} (+${site.keys.length - 1})`;
    if (feNames.has(name)) name = `${name}#${site.line}`;
    feNames.add(name);
    const fe = blank({
      type: 'frontend', name, line: site.line, endLine: site.endLine, file: site.file, mode: 'http', binds, serverNames: hosts.length === addrs.length || !addrs.some((a) => !a.hostname) ? hosts : [], addresses: addrs,
      directives: flatDirectives(site.body), locations: [], tls: tlsDirective ? { args: tlsDirective.args, line: tlsDirective.line, file: tlsDirective.file } : null,
      matchers: [...defs.values()].map((d) => ({ name: d.name, line: d.line, file: d.file, parts: d.parts.map((p) => ({ type: p.type, args: p.args })) })),
    });
    const sitePath = addrs.find((a) => a.path) ? addrs.find((a) => a.path).path : null;
    const siteLabel = hosts[0] || (addrs[0] ? (addrs[0].host || '') + (addrs[0].port ? `:${addrs[0].port}` : '') : 'site');
    const undefinedMatchers = [];

    // ---- route compilation
    const prepare = (nodes) => nodes.filter((nd) => nd.name && !nd.name.startsWith('@')).map((nd) => {
      const mt = !NO_MATCHER_DIRECTIVES.has(nd.name) && MATCHABLE_FIRST(nd.toks[1]) ? nd.toks[1].text : null;
      if (mt && mt.startsWith('@')) { const def = defs.get(mt); if (def) def.used++; else undefinedMatchers.push({ name: mt, line: nd.line, file: nd.file }); }
      return { dir: nd.name, nd, matcherToken: mt };
    });
    const matchersOf = (mt) => {
      if (!mt || mt === '*') return { list: [], label: '' };
      if (mt.startsWith('/')) return { list: convertPart({ type: 'path', args: [mt] }), label: mt };
      const def = defs.get(mt);
      if (!def) return { list: [{ field: 'Expression', op: 'is', values: [`${mt} (undefined)`], negated: false }], label: mt };
      return { list: def.parts.flatMap((p) => convertPart(p)), label: `${mt} (${def.parts.map((p) => `${p.type} ${p.args.join(' ')}`.trim()).join('; ')})` };
    };
    const addRoute = (ctx, d, extra) => {
      const own = matchersOf(d.matcherToken);
      const matchers = [...ctx.matchers, ...own.list];
      const conds = [...ctx.conds, ...(own.label ? [`${d.dir} ${own.label}`] : [])];
      const pathM = matchers.find((m) => m.field === 'Path' && !m.negated);
      const paths = pathM ? pathM.values.map((v) => (pathM.op === 'begins with' ? `${v}…` : v)) : [];
      const condition = conds.length ? conds.join(' › ') : 'DEFAULT';
      const route = {
        target: null, type: matchers.length ? 'conditional' : 'default', condition, rawCondition: condition,
        match: matchers.length ? matchers.map(describe).join(' and ') : 'any request', short: `${hosts[0] || '*'}${pathM ? (pathM.op === 'begins with' ? `${pathM.values[0]}*` : pathM.values[0]) : ''}`,
        matchers, hosts, paths, priority: fe.routes.length + 1, transforms: ctx.transforms.filter((t) => applies(t, matchers)).map(({ when, ...t }) => t),
        passUrl: null, terminal: false, line: d.nd.line, file: d.nd.file, commented: false, dynamic: false, external: false, directive: d.dir, aclRefs: [],
        ...extra,
      };
      if (route.ownTransforms) { route.transforms.push(...route.ownTransforms); delete route.ownTransforms; }
      fe.routes.push(route);
      fe.locations.push({ path: paths[0] || (pathM ? pathM.values[0] : '/'), modifier: pathM ? pathM.op : '', line: d.nd.line, file: d.nd.file, kind: extra.kind || 'other', target: route.target, detail: extra.detail || null });
      return route;
    };
    // does a sibling transform (with its own matcher) apply to a route with these matchers?
    const applies = (t, matchers) => {
      if (!t.when || !t.when.length) return true;
      return t.when.every((w) => matchers.some((m) => m.field === w.field && m.op === w.op && m.values.join() === w.values.join() && m.negated === w.negated)
        || (w.field === 'Path' && w.op === 'begins with' && matchers.some((m) => m.field === 'Path' && !m.negated && m.values.every((v) => w.values.some((p) => v.startsWith(p))))));
    };
    const tf = (action, args, nd, text, when) => ({ action, args, line: nd.line, file: nd.file, text, when });

    const walk = (nodes, ctx, literal) => {
      const prepared = prepare(nodes);
      const handlers = prepared.filter((d) => !NON_HANDLER.has(d.dir) && d.dir !== 'invoke' || d.dir === 'invoke');
      const list = literal ? handlers : sortDirectives(handlers, order, defs);
      const transforms = [...ctx.transforms];
      for (const d of list) {
        const nd = d.nd; const own = matchersOf(d.matcherToken); const a = nd.args.slice(d.matcherToken ? 1 : 0);
        const cur = { ...ctx, transforms };
        switch (d.dir) {
          case 'handle': case 'handle_path': case 'route': {
            const inner = { matchers: [...ctx.matchers, ...own.list], conds: [...ctx.conds, `${d.dir}${own.label ? ` ${own.label}` : ''}`], transforms: [...transforms] };
            if (d.dir === 'handle_path' && d.matcherToken && d.matcherToken.startsWith('/')) {
              const p = d.matcherToken; const strip = p.endsWith('/*') ? p.slice(0, -2) : p.endsWith('*') ? p.slice(0, -1) : p;
              inner.transforms.push(tf('strip-prefix', [strip], nd, `handle_path strips ${strip}`));
            }
            walk(nd.block || [], inner, d.dir === 'route');
            break;
          }
          case 'invoke': {
            const r = loaded.namedRoutes && loaded.namedRoutes.get(a[0]);
            if (r) walk(r.block || [], { matchers: [...ctx.matchers, ...own.list], conds: [...ctx.conds, `invoke ${a[0]}`], transforms: [...transforms] }, false);
            break;
          }
          case 'rewrite': if (a[0]) transforms.push(tf(/[?]/.test(a[0]) && !/^\//.test(a[0]) ? 'replace-path' : 'set-path', [a[0]], nd, `rewrite to ${a[0]}`, own.list)); break;
          case 'uri': {
            const op = a[0]; const rest = a.slice(1);
            const map = { strip_prefix: 'strip-prefix', strip_suffix: 'replace-path', replace: 'replace-path', path_regexp: 'replace-path-regex', query: 'set-query' };
            if (map[op]) transforms.push(tf(map[op], rest, nd, `uri ${op} ${rest.join(' ')}`, own.list));
            break;
          }
          case 'request_header': if (a[0]) transforms.push(tf(a[0].startsWith('-') ? 'del-header' : 'set-header', a, nd, `request_header ${a.join(' ')}`, own.list)); break;
          case 'method': if (a[0]) transforms.push(tf('set-method', a, nd, `method ${a[0]}`, own.list)); break;
          case 'redir': {
            const to = a[0] || '/'; const code = a[1] || '302';
            addRoute(cur, d, { terminal: true, kind: 'redirect', detail: `${code} ${to}`, ownTransforms: [tf('redirect', [to, code], nd, `redir ${to} ${code}`)] });
            break;
          }
          case 'respond': {
            const status = a.find((x) => /^\d{3}$/.test(x)) || (a.length && !/^\d{3}$/.test(a[0]) ? '200' : a[0] || '200');
            addRoute(cur, d, { terminal: true, kind: 'return', detail: `${status}${a[0] && a[0] !== status ? ` ${String(a[0]).slice(0, 60)}` : ''}`, ownTransforms: [tf('return', [status, ...a.filter((x) => x !== status).slice(0, 1)], nd, `respond ${status}`)] });
            break;
          }
          case 'abort': addRoute(cur, d, { terminal: true, kind: 'return', detail: 'abort', ownTransforms: [tf('deny', [], nd, 'abort (connection closed)')] }); break;
          case 'error': addRoute(cur, d, { terminal: true, kind: 'return', detail: `error ${a.join(' ')}`, ownTransforms: [tf('return', [a.find((x) => /^\d{3}$/.test(x)) || '500'], nd, `error ${a.join(' ')}`)] }); break;
          case 'file_server': {
            const root = (flatDirectives(site.body).find((x) => x.keyword === 'root') || {}).args;
            addRoute(cur, d, { terminal: true, kind: 'static', detail: root ? root[root.length - 1] : null, browse: a.includes('browse') || (nd.block || []).some((c) => c.name === 'browse') });
            break;
          }
          case 'metrics': addRoute(cur, d, { terminal: true, kind: 'metrics', detail: 'Prometheus metrics' }); break;
          case 'acme_server': addRoute(cur, d, { terminal: true, kind: 'other', detail: 'ACME server' }); break;
          case 'reverse_proxy': case 'php_fastcgi': {
            const rp = parseReverseProxy(nd, Boolean(d.matcherToken));
            if (d.dir === 'php_fastcgi') { rp.transport.protocol = 'fastcgi'; rp.upstreams.forEach((u) => { u.scheme = 'fastcgi'; }); }
            const pathM = [...ctx.matchers, ...own.list].find((m) => m.field === 'Path' && !m.negated);
            const label = `${siteLabel}${pathM ? pathM.values[0].replace(/\/$/, '') || '/' : ''}`;
            const be = backendFor(rp, label, nd);
            proxies.push({ rp, be, fe: fe.name });
            const extra = [];
            for (const h of rp.headerUp) {
              const [hn, ...hv] = h.args;
              if (/^\+?host$/i.test(hn || '') && hv.length) extra.push(tf('set-header', ['Host', ...hv], { line: h.line, file: h.file }, `header_up Host ${hv.join(' ')}`));
              else if (hn && hn.startsWith('-')) extra.push(tf('del-header', [hn.slice(1)], { line: h.line, file: h.file }, `header_up ${hn}`));
            }
            if (rp.rewrite) extra.push(tf(/^\//.test(rp.rewrite.to) ? 'set-path' : 'replace-path', [rp.rewrite.to], { line: rp.rewrite.line, file: nd.file }, `reverse_proxy rewrite ${rp.rewrite.to}`));
            if (rp.method) extra.push(tf('set-method', [rp.method], nd, `reverse_proxy method ${rp.method}`));
            const r = addRoute(cur, d, { target: be.name, kind: d.dir === 'php_fastcgi' ? 'fastcgi' : 'proxy', detail: rp.upstreams.map((u) => u.raw).join(' '), ownTransforms: extra, dynamic: Boolean(be.dynamic) && !be.servers.length });
            be.routes = be.routes || [];
            break;
          }
          default: break;
        }
      }
    };
    walk(site.body, { matchers: sitePath ? convertPart({ type: 'path', args: [sitePath] }) : [], conds: sitePath ? [`site path ${sitePath}`] : [], transforms: [] }, false);
    fe.undefinedMatchers = undefinedMatchers;
    fe.unusedMatchers = [...defs.values()].filter((d) => !d.used).map((d) => ({ name: d.name, line: d.line, file: d.file }));
    fe.httpRedirect = false;
    // automatic HTTP->HTTPS redirects
    if (g.autoHttps !== 'off' && g.autoHttps !== 'disable_redirects') {
      for (const a of addrs) if (a.tls && a.hostname && !a.scheme) redirectHosts.push({ host: a.hostname, fe: fe.name, line: site.line, file: site.file });
      else if (a.tls && a.hostname && a.scheme === 'https') redirectHosts.push({ host: a.hostname, fe: fe.name, line: site.line, file: site.file });
    }
    siteInfo.push({ site, fe, addrs });
    sections.push(fe);
  }

  // explicit http:// sites take precedence over the automatic redirect for the same host
  const explicitHttp = new Set(siteInfo.flatMap((s) => s.addrs.filter((a) => !a.tls && a.hostname && a.port === String(g.httpPort)).map((a) => a.hostname)));
  const redirected = redirectHosts.filter((r) => !explicitHttp.has(r.host));
  if (redirected.length) {
    const hostsR = [...new Set(redirected.map((r) => r.host))];
    const first = redirected[0];
    const fe = blank({
      type: 'frontend', name: `(auto HTTPS redirects):${g.httpPort}`, line: first.line, endLine: first.line, file: first.file, mode: 'http', implicit: true,
      binds: [{ address: `*:${g.httpPort}`, addresses: [`*:${g.httpPort}`], port: String(g.httpPort), ssl: false, options: { autoHttpsRedirect: true }, line: first.line, file: first.file, commented: false }],
      serverNames: hostsR, locations: [], directives: [],
    });
    fe.routes.push({ target: null, type: 'default', condition: 'Automatic HTTPS redirect', rawCondition: '', match: 'any request to a site served over HTTPS', short: `http://*`, matchers: [], hosts: hostsR, paths: [], priority: 1, transforms: [{ action: 'redirect', args: [`https://{host}${g.httpsPort !== 443 ? `:${g.httpsPort}` : ''}{uri}`, '308'], line: first.line, file: first.file, text: 'redir https://{host}{uri} 308 (automatic)' }], passUrl: null, terminal: true, line: first.line, file: first.file, commented: false, dynamic: false, external: false, directive: 'auto_https', kind: 'redirect', aclRefs: [] });
    siteInfo.forEach((s) => { if (s.addrs.some((a) => hostsR.includes(a.hostname))) s.fe.httpRedirect = true; });
    sections.push(fe);
  }
  sections.push(...backends.values());
  return { sections, global: g, sites: siteInfo, stray, proxies, order, matcherDefs };
}

module.exports = { buildModel, parseAddress, parseUpstream, parseReverseProxy, globalOptions, applyOrder, sortDirectives, structure, convertPart, pathOp, matcherDefs, isPublicName, flatDirectives, HANDLER_TERMINAL };

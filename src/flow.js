'use strict';
/**
 * Traffic flow: how a request travels from a load-balancer listener to a backend member port, and how its
 * URI changes on the way. Pure functions over the parsed configuration model (src/haproxyConfig.js,
 * src/nginxConfig.js); no I/O.
 *
 *   buildFlows(product, sections) -> { flows, portMatrix, findings, summary }
 *   trace(product, sections, request) -> step-by-step simulation of one request (config only, no traffic)
 *
 * Semantics follow the official documentation:
 *  - HAProxy `server <name> <addr>[:[port]]`: an explicit port is used as is; an omitted port means "the same
 *    port the client connected to"; `+N` / `-N` add to / subtract from the client's port. `port` / `addr`
 *    server parameters only redirect health checks. use_backend rules are first-match, then default_backend.
 *    Frontend `http-request` rules run before backend selection, backend ones after.
 *  - NGINX: `proxy_pass` with a URI replaces the part of the request URI matched by the location prefix;
 *    without a URI the request URI is passed unchanged. Locations: `=`, longest prefix (`^~` stops regex
 *    checks), then regexes in file order. `rewrite ... last` re-searches locations, `break` does not.
 */
const { resolveCondition } = require('./haproxyConfig');

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '0.0.0.0', '*', '']);
const PATH_ACTIONS = new Set(['set-path', 'replace-path', 'set-pathq', 'replace-pathq', 'set-uri', 'replace-uri']);
const HTTP_REQUEST_STEPS = new Set([...PATH_ACTIONS, 'set-header', 'replace-header', 'set-query', 'redirect', 'return', 'deny', 'tarpit', 'reject', 'auth', 'set-dst-port', 'set-dst', 'use-service']);
const TERMINAL = new Set(['redirect', 'return', 'deny', 'tarpit', 'reject', 'auth']);
const isNum = (x) => /^\d+$/.test(String(x));

const portOfAddr = (a) => { const m = String(a || '').match(/:(\d+(?:-\d+)?)$/); return m ? m[1] : null; };

// ------------------------------------------------------------------------------------------------ servers
/** `10.0.0.1:8080`, `10.0.0.1`, `10.0.0.1:+1000`, `[::1]:80`, `unix@/run/x`, `${HOST}:${PORT}` -> structured address. */
function parseServerAddress(raw) {
  const r = String(raw || '');
  if (/^(unix|abns|abnsz|sockpair)@|^\//.test(r)) return { raw: r, kind: 'socket', host: r, mode: 'socket' };
  const bare = r.replace(/^(ipv4|ipv6)@/, '');
  let host = bare; let p = null;
  const br = bare.match(/^(\[[^\]]+\])(?::(.*))?$/);
  if (br) { host = br[1]; p = br[2] == null ? null : br[2]; } else if ((bare.match(/:/g) || []).length === 1) { const i = bare.lastIndexOf(':'); host = bare.slice(0, i); p = bare.slice(i + 1); }
  const out = { raw: r, kind: 'inet', host, transparent: host === '0.0.0.0' || host === '*' };
  if (/\$/.test(bare)) return { ...out, mode: 'env', port: null };
  if (p === null || p === '') return { ...out, mode: 'follows' };
  if (/^[+-]\d+$/.test(p)) return { ...out, mode: 'offset', offset: Number(p) };
  if (isNum(p)) return { ...out, mode: 'explicit', port: Number(p) };
  return { ...out, mode: 'env', port: null };
}

/** The port traffic actually uses for a given listener port. null when it cannot be known statically. */
function resolvePort(addr, listenerPort, defaultPort = null) {
  const lp = isNum(listenerPort) ? Number(listenerPort) : null;
  if (addr.mode === 'explicit') return addr.port;
  if (addr.mode === 'follows') return lp != null ? lp : defaultPort;
  if (addr.mode === 'offset') return lp != null ? lp + addr.offset : null;
  return null;
}

function hapMember(s) {
  const o = s.opts || {};
  const addr = parseServerAddress(s.address);
  const range = s.template && /^(\d+)-(\d+)$/.test(String(s.name)) ? String(s.name).match(/^(\d+)-(\d+)$/) : null;
  return {
    name: s.template ? `${s.template}[${s.name}]` : s.name, address: s.address || '', addr, line: s.line,
    count: range ? Number(range[2]) - Number(range[1]) + 1 : 1,
    ssl: Boolean(o.ssl), verify: typeof o.verify === 'string' ? o.verify : null, sni: typeof o.sni === 'string' ? o.sni : null,
    sendProxy: Object.keys(o).find((k) => /^send-proxy/.test(k)) || null,
    check: Boolean(s.check), checkPort: o.port != null && isNum(o.port) ? Number(o.port) : null, checkAddr: typeof o.addr === 'string' ? o.addr : null, checkSsl: Boolean(o['check-ssl']),
    backup: Boolean(s.backup), disabled: Boolean(s.disabled), weight: s.weight,
  };
}
function ngxMember(s, scheme, stream) {
  const addr = parseServerAddress(String(s.address || '').replace(/^unix:/, 'unix@'));
  const dflt = stream ? null : scheme === 'https' || scheme === 'grpcs' ? 443 : 80;
  const o = s.opts || {};
  return {
    name: s.name, address: s.address || '', addr: addr.kind === 'inet' && addr.mode === 'follows' ? { ...addr, mode: 'explicit', port: dflt, implicitPort: true } : addr, line: s.line, count: 1,
    ssl: scheme === 'https' || scheme === 'grpcs', verify: null, sni: null, sendProxy: null, check: false, checkPort: null, checkAddr: null, checkSsl: false,
    backup: Boolean(o.backup), disabled: Boolean(o.down), weight: s.weight,
  };
}

// ------------------------------------------------------------------------------------------------ listeners
function listenersOf(sec) {
  const out = [];
  for (const b of sec.binds || []) {
    if (b.commented) continue;
    const o = b.options || {};
    for (const a of b.addresses && b.addresses.length ? b.addresses : [b.address || '']) {
      const port = /^(unix|abns)[@:]|^\//.test(a) ? null : (portOfAddr(a) || b.port || null);
      out.push({ address: a, port, tls: Boolean(b.ssl), acceptProxy: Boolean(o['accept-proxy'] || o.proxy_protocol), http2: Boolean(o.http2 || (typeof o.alpn === 'string' && /h2/.test(o.alpn))), line: b.line, socket: port == null });
    }
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ conditions (HAProxy)
const lc = (s) => String(s == null ? '' : s).toLowerCase();
function evalMatcher(m, req) {
  if (m.field === 'ssl_fc') return req.tls == null ? null : Boolean(req.tls);
  let v;
  if (m.field === 'Path') v = req.path;
  else if (m.field === 'URL') v = req.path + (req.query ? `?${req.query}` : '');
  else if (m.field === 'Host' || m.field === 'TLS SNI') v = lc(req.host);
  else if (m.field === 'Method') v = req.method || 'GET';
  else if (m.field === 'dst_port') v = req.port != null ? String(req.port) : null;
  else return null;
  if (v == null) return null;
  const ci = m.caseInsensitive || m.field === 'Host' || m.field === 'TLS SNI';
  const t = (x) => (ci ? lc(x) : String(x));
  const vals = m.values || [];
  switch (m.op) {
    case 'is': return vals.some((x) => t(x) === t(v));
    case 'begins with': return vals.some((x) => t(v).startsWith(t(x)));
    case 'ends with': return vals.some((x) => t(v).endsWith(t(x)));
    case 'contains': return vals.some((x) => t(v).includes(t(x)));
    case 'has directory': return vals.some((x) => `/${t(v)}/`.includes(`/${t(x)}/`));
    case 'has domain': return vals.some((x) => { const a = t(v); const b = t(x); return a === b || a.endsWith(`.${b}`) || a.includes(`.${b}.`); });
    case 'matches': return vals.some((x) => { try { return new RegExp(x, ci ? 'i' : '').test(v); } catch { return null; } });
    default: return null;
  }
}
const and3 = (xs) => (xs.includes(false) ? false : xs.includes(null) ? null : true);
const or3 = (xs) => (xs.includes(true) ? true : xs.includes(null) ? null : false);
/** Tri-state: true / false / null (cannot be decided from host, path, method, port and TLS alone). */
function evalCondition(rawCond, matchers, req) {
  if (!rawCond || !matchers || !matchers.length) return true;
  const groups = []; let cur = [];
  for (const m of matchers) { if (m.join === 'OR' && cur.length) { groups.push(cur); cur = []; } cur.push(m); }
  if (cur.length) groups.push(cur);
  let r = or3(groups.map((g) => and3(g.map((m) => { const x = evalMatcher(m, req); return x == null ? null : m.negated ? !x : x; }))));
  if (/^\s*unless\b/.test(rawCond) && r !== null) r = !r;
  return r;
}

// ------------------------------------------------------------------------------------------------ path rewriting
const hapFmt = (fmt, m) => (m ? String(fmt).replace(/\\(\d)/g, (_x, i) => m[Number(i)] || '') : String(fmt));
/** Apply one HAProxy path-changing action to a path. -> { path, exact } (exact=false when the format is dynamic) */
function applyHapPath(action, args, path) {
  const dyn = (s) => /%\[|%\{|%\(/.test(s || '');
  if (action === 'set-path' || action === 'set-pathq' || action === 'set-uri') { return { path: args[0] || path, exact: !dyn(args[0]) }; }
  if (action === 'replace-path' || action === 'replace-pathq' || action === 'replace-uri') {
    let re;
    try { re = new RegExp(args[0] || ''); } catch { return { path, exact: false }; }
    const m = path.match(re);
    if (!m) return { path, exact: true, unmatched: true };
    const out = path.replace(re, hapFmt(args[1] || '', null).replace(/\\(\d)/g, (_x, i) => `$${i}`));
    return { path: out, exact: !dyn(args[1]) };
  }
  return { path, exact: true };
}
function applyNgxRewrite(args, path) {
  let re;
  try { re = new RegExp(args[0] || '', ''); } catch { return null; }
  const m = path.match(re);
  if (!m) return { matched: false };
  const flag = ['last', 'break', 'redirect', 'permanent'].includes(args[args.length - 1]) ? args[args.length - 1] : null;
  const rep = args[1] || '';
  const redirect = /^(https?:\/\/|\$scheme)/.test(rep) || flag === 'redirect' || flag === 'permanent';
  return { matched: true, path: redirect ? rep : path.replace(re, rep), flag, redirect, status: flag === 'permanent' ? 301 : 302, dynamic: /\$[a-z_]/i.test(rep.replace(/\$\d/g, '')) };
}

// ------------------------------------------------------------------------------------------------ HAProxy flows
function activeDefaultsFor(sections) {
  const map = new Map(); let d = null;
  for (const s of sections) { if (s.type === 'defaults') d = s; else if (['frontend', 'backend', 'listen'].includes(s.type)) map.set(s, d); }
  return map;
}
function hapSteps(sec, scope, acls) {
  const out = [];
  for (const d of sec ? sec.directives || [] : []) {
    if (d.keyword !== 'http-request' && d.keyword !== 'redirect') continue;
    const args = d.keyword === 'redirect' ? ['redirect', ...d.args] : d.args;
    const action = args[0];
    if (!HTTP_REQUEST_STEPS.has(action)) continue;
    const ci = args.findIndex((t, i) => i > 0 && (t === 'if' || t === 'unless'));
    const cond = ci >= 0 ? args.slice(ci).join(' ') : '';
    const body = ci >= 0 ? args.slice(1, ci) : args.slice(1);
    const matchers = resolveCondition(cond, acls);
    out.push({ scope, action, args: body, cond, matchers: matchers.matchers, condText: matchers.match, line: d.line, text: [action, ...body].join(' '), kind: PATH_ACTIONS.has(action) ? 'path' : TERMINAL.has(action) ? 'terminal' : 'header' });
  }
  return out;
}

const pathSample = (match) => {
  if (!match) return null;
  const p = (match.matchers || []).find((m) => m.field === 'Path' && !m.negated && m.values && m.values.length);
  if (p && p.op === 'is') return p.values[0];
  if (p && p.op === 'begins with') { const v = p.values[0]; return v.endsWith('/') ? `${v}example` : `${v}/example`; }
  return null;
};

function hapFlows(sections) {
  const defaultsOf = activeDefaultsFor(sections);
  const byName = new Map(sections.filter((s) => s.type === 'backend' || s.type === 'listen').map((s) => [s.name, s]));
  const flows = [];
  for (const fe of sections.filter((s) => s.type === 'frontend' || s.type === 'listen')) {
    const listeners = listenersOf(fe);
    if (!listeners.length) continue;
    const d = defaultsOf.get(fe);
    const acls = [...fe.acls, ...(d ? d.acls : [])];
    const feSteps = [...hapSteps(d, 'defaults', acls), ...hapSteps(fe, 'frontend', acls)];
    const routes = fe.routes.filter((r) => !r.commented);
    const list = routes.map((r, i) => ({ r, index: i + 1 }));
    if (fe.type === 'listen' && fe.servers.some((s) => !s.commented) && !routes.some((r) => r.type === 'default')) list.push({ r: { target: fe.name, type: 'default', condition: 'DEFAULT', rawCondition: '', matchers: [], paths: [], hosts: [], match: '', self: true }, index: list.length + 1 });
    for (const { r, index } of list) {
      const pool = byName.get(r.target) || null;
      const pd = pool ? defaultsOf.get(pool) : null;
      const beSteps = pool ? [...hapSteps(pd, 'defaults', [...pool.acls, ...(pd ? pd.acls : [])]), ...hapSteps(pool, 'backend', [...pool.acls, ...(pd ? pd.acls : [])])].map((x) => ({ ...x, stage: 'backend' })) : [];
      flows.push(makeFlow('haproxy', {
        fe, listeners, rule: r, index, chain: [...feSteps.map((x) => ({ ...x, stage: 'frontend' })), ...beSteps], pool, mode: fe.effective && fe.effective.mode,
        members: pool ? pool.servers.filter((s) => !s.commented).map(hapMember) : [],
      }));
    }
  }
  return flows;
}

// ------------------------------------------------------------------------------------------------ NGINX flows
function ngxChain(sec, rule) {
  const out = [];
  for (const dd of sec.directives || []) {
    const within = dd.within || [];
    const serverLevel = within.length === 0;
    const inThis = rule.type === 'conditional' && within.length && within[within.length - 1] === rule.condition;
    if (dd.keyword === 'rewrite' && (serverLevel || inThis)) out.push({ scope: serverLevel ? 'server' : 'location', action: 'rewrite', args: dd.args, line: dd.line, text: `rewrite ${dd.args.join(' ')}`, kind: 'path' });
    if (dd.keyword === 'proxy_set_header' && /^host$/i.test(dd.args[0] || '') && (serverLevel || inThis)) out.push({ scope: serverLevel ? 'server' : 'location', action: 'set-header', args: ['Host', dd.args[1]], line: dd.line, text: `proxy_set_header Host ${dd.args[1]}`, kind: 'header' });
  }
  if (rule.passUri != null) out.push({ scope: 'location', action: 'proxy_pass-uri', args: [rule.passUri], line: rule.line, text: `proxy_pass …${rule.passUri}`, kind: 'path', note: rule.rewriteNote });
  return out;
}
function ngxFlows(sections) {
  const byName = new Map(sections.filter((s) => s.type === 'backend').map((s) => [s.name, s]));
  const flows = [];
  for (const fe of sections.filter((s) => s.type === 'frontend')) {
    const listeners = listenersOf(fe).map((l) => ({ ...l, http2: l.http2 || (fe.binds.find((b) => b.address === l.address) || { flags: [] }).flags.some((f) => /^(http2|quic)$/.test(f)), acceptProxy: l.acceptProxy || (fe.binds.find((b) => b.address === l.address) || { flags: [] }).flags.includes('proxy_protocol') }));
    if (!listeners.length) continue;
    const routes = fe.routes.filter((r) => !r.commented);
    routes.forEach((r, i) => {
      const pool = byName.get(r.target) || null;
      const scheme = r.passUrl && /^[a-z]+:\/\//i.test(r.passUrl) ? r.passUrl.match(/^([a-z]+):/i)[1].toLowerCase() : '';
      const tlsUp = scheme === 'https' || scheme === 'grpcs' || (fe.isStream && (fe.directives || []).some((x) => x.keyword === 'proxy_ssl' && x.args[0] === 'on'));
      flows.push(makeFlow('nginx', {
        fe, listeners, rule: r, index: i + 1, chain: ngxChain(fe, r), pool, mode: fe.isStream ? 'tcp' : 'http',
        members: pool ? pool.servers.filter((s) => !s.commented).map((s) => { const m = ngxMember(s, scheme, fe.isStream); if (tlsUp) m.ssl = true; return m; }) : [],
        scheme,
      }));
    });
  }
  return flows;
}

// ------------------------------------------------------------------------------------------------ shared flow assembly
const tlsKind = (listenerTls, memberTls, mode) => (listenerTls && memberTls ? 're-encrypt' : listenerTls ? 'terminate' : memberTls ? 'upgrade' : mode === 'tcp' ? 'passthrough' : 'plain');

function makeFlow(product, { fe, listeners, rule, index, chain, pool, mode, members }) {
  const ports = [...new Set(listeners.map((l) => l.port).filter(Boolean))];
  const portMap = [];
  for (const l of listeners) {
    if (l.port == null) continue;
    const memberOut = members.map((m) => ({ member: m.name, port: m.addr.kind === 'socket' ? null : resolvePort(m.addr, l.port), tls: m.ssl, dynamic: m.addr.mode === 'env' }));
    portMap.push({ in: l.port, listenerTls: l.tls, out: [...new Set(memberOut.map((x) => x.port).filter((x) => x != null))], dynamic: memberOut.some((x) => x.dynamic), socket: members.some((m) => m.addr.kind === 'socket'), tls: tlsKind(l.tls, members.some((m) => m.ssl), mode) });
  }
  const f = {
    id: `${fe.name}#${index}`, product, frontend: fe.name, line: rule.line || fe.line, file: fe.file || null,
    listeners, ports, mode: mode || 'http',
    match: { type: rule.type, index, text: rule.type === 'default' ? 'any request not matched above' : (rule.match || rule.condition || ''), short: rule.short || '', raw: rule.rawCondition || '', hosts: rule.hosts || [], paths: rule.paths || [], matchers: rule.matchers || [], modifier: rule.matchModifier || '', path: (rule.paths && rule.paths[0]) || null, self: Boolean(rule.self) },
    chain,
    pool: pool ? { name: pool.name, type: pool.type, balance: pool.balance || (pool.effective && pool.effective.balance) || null, implicit: Boolean(pool.implicit), mode: pool.mode || mode, line: pool.line } : { name: rule.target, undefined: !rule.dynamic, dynamic: Boolean(rule.dynamic) },
    members, portMap, passUrl: rule.passUrl || null, rewriteNote: rule.rewriteNote || null, commented: false,
    shadowedBy: null,
  };
  f.tls = [...new Set(portMap.map((p) => p.tls))].join(',') || null;
  if (product === 'haproxy') {
    const probe = { host: (f.match.hosts || [])[0] || '', path: pathSample(f.match) || '/', method: 'GET', tls: null, port: null };
    for (const st of chain) st.applies = st.cond ? evalCondition(st.cond, st.matchers, probe) : true;
  }
  const sample = product === 'haproxy' ? pathSample(f.match) : (rule.matchModifier === '=' || !rule.matchModifier || rule.matchModifier === '^~') && rule.paths && rule.paths[0] ? (rule.paths[0].endsWith('/') ? `${rule.paths[0]}example` : rule.matchModifier === '=' ? rule.paths[0] : `${rule.paths[0]}/example`) : null;
  if (sample != null) {
    const out = simulatePath(product, f, sample);
    f.example = { in: sample, out: out.path, exact: out.exact, changed: out.path !== sample };
  } else f.example = null;
  return f;
}

/** Apply a flow's transform chain to a sample path. */
function simulatePath(product, flow, path) {
  let cur = path; let exact = true; let broke = false;
  for (const s of flow.chain) {
    if (s.kind !== 'path') continue;
    if (product === 'haproxy') {
      const ok = evalCondition(s.cond, s.matchers, { host: (flow.match.hosts || [])[0] || '', path: cur, method: 'GET', tls: null, port: null });
      if (ok === false) continue; // its condition cannot hold for this kind of request
      if (ok === null) { exact = false; continue; } // depends on something a host / path test cannot decide
      const r = applyHapPath(s.action, s.args, cur); cur = r.path; exact = exact && r.exact;
    }
    else if (s.action === 'rewrite') {
      const r = applyNgxRewrite(s.args, cur);
      if (!r) { exact = false; continue; }
      if (!r.matched) continue;
      if (r.redirect) { return { path: cur, exact: false, redirect: r.path }; }
      cur = r.path; exact = exact && !r.dynamic;
      if (r.flag === 'break' || r.flag === 'last') { broke = r.flag === 'break'; if (r.flag === 'last') exact = false; break; }
    } else if (s.action === 'proxy_pass-uri' && !broke) {
      const prefix = flow.match.path || '';
      if (flow.match.modifier === '=') cur = s.args[0];
      else if (!/^~/.test(flow.match.modifier) && prefix && cur.startsWith(prefix)) cur = `${s.args[0]}${cur.slice(prefix.length)}`;
      else exact = false;
    }
  }
  return { path: cur, exact };
}

// ------------------------------------------------------------------------------------------------ shadowing + findings
function simpleCover(flow) {
  const ms = flow.match.matchers;
  if (flow.match.type === 'default') return { all: true };
  if (!ms.length) return { all: true };
  if (/^\s*unless\b/.test(flow.match.raw) || ms.some((m) => m.join === 'OR')) return { simple: false };
  const hostT = ms.filter((m) => (m.field === 'Host' || m.field === 'TLS SNI') && !m.negated && m.op === 'is');
  const pathT = ms.filter((m) => m.field === 'Path' && !m.negated && (m.op === 'is' || m.op === 'begins with'));
  const other = ms.filter((m) => !hostT.includes(m) && !pathT.includes(m));
  return { simple: true, hosts: hostT.flatMap((m) => m.values.map(lc)), hostOnly: hostT.length > 0, paths: pathT.flatMap((m) => m.values.map((v) => ({ v, op: m.op }))), hasPath: pathT.length > 0, pure: other.length === 0 };
}
function covers(a, b) {
  if (a.all) return true;
  if (!a.simple || !a.pure || b.all || !b.simple) return false;
  const hostOk = !a.hostOnly || (b.hostOnly && b.hosts.every((h) => a.hosts.includes(h)));
  const pathOk = !a.hasPath || (b.hasPath && b.paths.every((bp) => a.paths.some((ap) => (ap.op === 'is' ? bp.op === 'is' && bp.v === ap.v : bp.v.startsWith(ap.v)))));
  return hostOk && pathOk;
}

function analyse(product, flows, sections) {
  const findings = [];
  const add = (f) => findings.push({ category: 'routing', ...f });
  // listener ports that belong to this load balancer (for self-loop detection)
  const ownPorts = new Set(); const ownHosts = new Set();
  for (const f of flows) for (const l of f.listeners) { if (l.port) ownPorts.add(String(l.port)); const h = String(l.address).replace(/:\d+(-\d+)?$/, ''); if (h && !LOCAL_HOSTS.has(h)) ownHosts.add(h); }

  // shadowed rules (first match wins in HAProxy; NGINX handled separately below)
  if (product === 'haproxy') {
    const byFe = new Map();
    for (const f of flows) (byFe.get(f.frontend) || byFe.set(f.frontend, []).get(f.frontend)).push(f);
    for (const list of byFe.values()) {
      const cov = list.map(simpleCover);
      list.forEach((f, j) => {
        if (f.match.self) return;
        for (let i = 0; i < j; i++) {
          if (!covers(cov[i], cov[j])) continue;
          f.shadowedBy = list[i].match.index;
          add({
            id: 'flow-shadowed-rule', severity: 'warning', section: f.frontend, line: f.line,
            title: f.match.type === 'default' ? `default_backend "${f.pool.name}" is never used` : `Rule #${f.match.index} → "${f.pool.name}" can never match`,
            detail: `Rule #${list[i].match.index} (${list[i].match.type === 'default' ? 'default_backend' : list[i].match.text || 'unconditional'}) → "${list[i].pool.name}" already catches everything this rule matches, and use_backend rules are evaluated in order, first match wins.`,
            fix: 'Move the more specific rule above the broader one, or remove it.',
          });
          break;
        }
      });
    }
  }

  for (const f of flows) {
    const pool = f.pool;
    if (!f.members.length) continue;
    const resolved = f.members.map((m) => ({ m, ports: f.portMap.map((p) => (m.addr.kind === 'socket' ? null : resolvePort(m.addr, p.in))) }));
    for (const { m, ports } of resolved) {
      const first = ports.find((p) => p != null);
      if (product === 'haproxy' && m.checkPort != null && m.check && first != null && m.checkPort !== first) {
        add({ id: 'flow-check-port-differs', severity: 'warning', section: pool.name, line: m.line, title: `Health check of "${m.name}" probes :${m.checkPort} but traffic goes to :${first}`, detail: 'A passing check on a different port does not prove the traffic port works: the server can be marked UP while its application port is down.', fix: `Check the traffic port, or confirm that :${m.checkPort} really reflects the application on :${first}.` });
      }
      if (product === 'haproxy' && m.checkPort != null && !m.check) add({ id: 'flow-check-port-ignored', severity: 'info', section: pool.name, line: m.line, title: `"port ${m.checkPort}" on "${m.name}" has no effect without "check"`, detail: 'The server `port` parameter only redirects health checks, and it is ignored when `check` is not set. It does not change where traffic goes.', fix: 'Add `check`, or remove `port` and put the port in the server address.' });
      if (first != null && m.ssl && first === 80) add({ id: 'flow-tls-to-plain-port', severity: 'warning', section: pool.name, line: m.line, title: `"${m.name}" speaks TLS to :80`, detail: 'The server is configured for TLS, but port 80 normally serves plain HTTP.', fix: 'Use the TLS port (usually 443 / 8443), or remove `ssl` / use http://.' });
      if (first != null && !m.ssl && (first === 443 || first === 8443)) add({ id: 'flow-plain-to-tls-port', severity: 'warning', section: pool.name, line: m.line, title: `"${m.name}" sends plain traffic to :${first}`, detail: `Port ${first} normally expects TLS, but ${product === 'haproxy' ? '`ssl` is not set on this server' : 'proxy_pass does not use https://'}.`, fix: product === 'haproxy' ? 'Add `ssl` (and `verify required ca-file …`).' : 'Use `proxy_pass https://…`.' });
      if (m.addr.kind === 'inet' && first != null && ports.some((p) => p != null && ownPorts.has(String(p))) && (LOCAL_HOSTS.has(m.addr.host.replace(/^\[|\]$/g, '')) || ownHosts.has(m.addr.host)) && !m.addr.transparent) {
        add({ id: 'flow-self-loop', severity: 'error', section: pool.name, line: m.line, title: `"${m.name}" points at this load balancer's own listener (${m.addr.host}:${first})`, detail: 'Requests would be proxied back into the same listener, creating a loop until connections are exhausted.', fix: 'Point the server at the application port, not at a port this proxy listens on.' });
      }
    }
    const distinct = new Set(resolved.map((r) => r.ports.find((p) => p != null)).filter((p) => p != null));
    if (distinct.size > 1) add({ id: 'flow-mixed-ports', severity: 'info', section: pool.name, line: pool.line, title: `Pool "${pool.name}" mixes backend ports (${[...distinct].sort((a, b) => a - b).join(', ')})`, detail: 'Members of one pool normally listen on the same port. Mixed ports are fine for a migration or canary, but easy to leave behind by mistake.', fix: 'Confirm it is intentional.' });
    if (f.members.some((m) => m.addr.mode === 'env')) add({ id: 'flow-env-port', severity: 'info', section: pool.name, line: pool.line, title: `Pool "${pool.name}" uses an environment variable for its address or port`, detail: 'The real port is only known at start-up, so it is shown as unresolved here.', fix: 'Nothing to change. Check the environment of the proxy process.' });
  }

  if (product === 'nginx') {
    for (const f of flows) {
      const mod = f.match.modifier; const p = f.match.path;
      const passUri = f.chain.find((s) => s.action === 'proxy_pass-uri');
      if (passUri && p && !/^~/.test(mod) && mod !== '=') {
        const u = passUri.args[0];
        if (p.endsWith('/') !== u.endsWith('/')) add({ id: 'flow-nginx-slash-mismatch', severity: 'warning', section: f.frontend, line: passUri.line, title: `location ${p} and proxy_pass URI "${u}" disagree about the trailing slash`, detail: `The matched prefix "${p}" is replaced by "${u}". /x${p.endsWith('/') ? '' : '/'}… becomes ${p.endsWith('/') ? `${u}…` : `${u}/…`} with a missing or doubled slash. Example: ${f.example ? `${f.example.in} → ${f.example.out}` : 'a path under the prefix is joined to the URI without a separator'}.`, fix: 'Use a trailing slash on both the location and the proxy_pass URI, or on neither.' });
      }
      if (passUri && f.chain.some((s) => s.action === 'rewrite' && s.scope === 'location' && /\bbreak\s*$/.test(s.args.join(' ')))) add({ id: 'flow-nginx-break-ignores-uri', severity: 'warning', section: f.frontend, line: passUri.line, title: 'proxy_pass URI is ignored because of `rewrite … break`', detail: 'After `rewrite … break` in the same location the rewritten URI is sent as is; the URI part of proxy_pass is not applied.', fix: 'Remove the URI from proxy_pass, or drop the rewrite.' });
    }
    // a regex location that cannot be reached because an earlier ^~ prefix covers it
    for (const sec of sections.filter((s) => s.type === 'frontend' && s.locations)) {
      const stops = sec.locations.filter((l) => l.modifier === '^~' && l.path);
      for (const l of sec.locations.filter((x) => /^~\*?$/.test(x.modifier) && x.path)) {
        const lit = l.path.match(/^\^(\/[A-Za-z0-9_\-/.]*)/);
        const stop = lit && stops.find((s) => lit[1].startsWith(s.path));
        if (stop) add({ id: 'flow-nginx-regex-blocked', severity: 'info', section: sec.name, line: l.line, title: `location ${l.modifier} ${l.path} is never checked for ${stop.path}…`, detail: `The longest matching prefix location "^~ ${stop.path}" stops regular expression checking, so this regex does not apply to URIs under it.`, fix: 'Remove `^~` from the prefix location, or move the logic inside it.' });
      }
    }
  }
  return findings;
}

function portMatrix(flows) {
  const rows = new Map();
  for (const f of flows) {
    for (const pm of f.portMap) {
      const key = `${pm.in}|${f.frontend}|${f.pool.name}`;
      let r = rows.get(key);
      if (!r) { r = { mode: f.mode, listener: pm.in, listenerTls: pm.listenerTls, frontend: f.frontend, pool: f.pool.name, tls: pm.tls, out: [], rules: 0, members: f.members.length, dynamic: pm.dynamic, socket: pm.socket, undefined: Boolean(f.pool.undefined) }; rows.set(key, r); }
      r.rules += 1; for (const o of pm.out) if (!r.out.includes(o)) r.out.push(o);
    }
  }
  return [...rows.values()].sort((a, b) => Number(a.listener) - Number(b.listener) || a.frontend.localeCompare(b.frontend));
}

function buildFlows(product, sections) {
  const flows = product === 'nginx' ? ngxFlows(sections) : hapFlows(sections);
  const findings = analyse(product, flows, sections);
  const strip = (s) => ({ applies: s.applies, stage: s.stage, scope: s.scope, action: s.action, args: s.args, cond: s.cond || '', condText: s.condText || '', line: s.line, text: s.text, kind: s.kind, note: s.note });
  const out = flows.map((f) => ({ ...f, chain: f.chain.map(strip), match: { ...f.match, matchers: undefined, raw: f.match.raw } }));
  return {
    product, flows: out, portMatrix: portMatrix(flows), findings,
    summary: { flows: out.length, listeners: new Set(flows.flatMap((f) => f.ports)).size, rewrites: out.filter((f) => f.chain.some((s) => s.kind === 'path')).length, findings: findings.length },
  };
}

// ------------------------------------------------------------------------------------------------ tracer
const SERVER_NAME_RANK = (pattern, host) => {
  const p = lc(pattern); const h = lc(host);
  if (p === h) return 4;
  if (p.startsWith('*.') && h.endsWith(p.slice(1))) return 3 + p.length / 1000;
  if (p.startsWith('.') && (h === p.slice(1) || h.endsWith(p))) return 3;
  if (p.endsWith('.*') && h.startsWith(p.slice(0, -1))) return 2 + p.length / 1000;
  if (p.startsWith('~')) { try { return new RegExp(p.slice(1), 'i').test(h) ? 1 : 0; } catch { return 0; } }
  return 0;
};

function normaliseRequest(req) {
  let path = String(req.path || '/'); let query = req.query || '';
  const qi = path.indexOf('?'); if (qi >= 0) { query = query || path.slice(qi + 1); path = path.slice(0, qi); }
  if (!path.startsWith('/')) path = `/${path}`;
  const tls = req.tls == null ? null : Boolean(req.tls);
  return { host: lc(req.host || ''), path, query, method: String(req.method || 'GET').toUpperCase(), tls, port: req.port != null && req.port !== '' ? Number(req.port) : null };
}

function memberView(f, port) {
  return f.members.map((m) => ({ name: m.name, address: m.address, port: m.addr.kind === 'socket' ? null : resolvePort(m.addr, port), tls: m.ssl, backup: m.backup, disabled: m.disabled, checkPort: m.checkPort, dynamic: m.addr.mode === 'env', socket: m.addr.kind === 'socket' }));
}

function traceHaproxy(sections, rq) {
  const flows = hapFlows(sections);
  const steps = [];
  const listenerHit = (f) => f.listeners.find((l) => l.port != null && (rq.port == null || String(l.port) === String(rq.port) || (/-/.test(l.port) && rq.port >= Number(l.port.split('-')[0]) && rq.port <= Number(l.port.split('-')[1]))) && (rq.tls == null || l.tls === rq.tls));
  const fe = flows.find((f) => listenerHit(f));
  if (!fe) return { ok: false, response: { status: null, text: 'No frontend listens on that port' }, steps: [{ type: 'listener', text: `No bind matches ${rq.tls ? 'TLS ' : ''}port ${rq.port == null ? '(any)' : rq.port}` }] };
  const l = listenerHit(fe);
  const port = rq.port != null ? rq.port : Number(l.port);
  const req = { ...rq, port, tls: l.tls };
  steps.push({ type: 'listener', text: `Arrives on ${l.address}${l.tls ? ' (TLS)' : ''} → frontend ${fe.frontend}`, line: l.line });
  let path = rq.path; let uncertain = false; let exact = true;
  const runChain = (chain) => {
    for (const s of chain) {
      const r = evalCondition(s.cond, s.matchers, req);
      if (r === false) { steps.push({ type: 'rewrite', text: `${s.text}${s.cond ? ` ${s.cond}` : ''}`, applied: false, note: 'condition not met', line: s.line, scope: s.scope }); continue; }
      if (r === null) { uncertain = true; steps.push({ type: 'rewrite', text: `${s.text} ${s.cond}`, applied: false, unknown: true, note: 'condition depends on something a path/host test cannot decide (not applied)', line: s.line, scope: s.scope }); continue; }
      if (s.kind === 'path') { const o = applyHapPath(s.action, s.args, path); steps.push({ type: 'rewrite', text: s.text, applied: !o.unmatched, from: path, to: o.path, note: o.unmatched ? 'pattern did not match this path' : o.exact ? '' : 'result depends on a dynamic format', line: s.line, scope: s.scope }); path = o.path; exact = exact && o.exact; }
      else if (s.kind === 'terminal') { steps.push({ type: 'response', text: `${s.text}${s.cond ? ` ${s.cond}` : ''}`, applied: true, line: s.line, scope: s.scope }); return { stop: s }; }
      else steps.push({ type: 'rewrite', text: s.text, applied: true, note: s.action === 'set-header' ? 'header change' : '', line: s.line, scope: s.scope });
    }
    return {};
  };
  const feChain = fe.chain.filter((s) => s.stage === 'frontend');
  const stop = runChain(feChain).stop;
  if (stop) return finish(fe, null, { status: stop.action === 'redirect' ? 301 : stop.action === 'deny' ? 403 : null, text: stop.text });
  const siblings = flows.filter((f) => f.frontend === fe.frontend);
  let chosen = null;
  for (const f of siblings) {
    const m = f.match;
    if (m.type === 'default') { chosen = f; steps.push({ type: 'rule', text: f.match.self ? 'Servers in this listen section' : `default_backend → ${f.pool.name}`, index: m.index, line: f.line }); break; }
    const r = evalCondition(m.raw, m.matchers, req);
    if (r === true) { chosen = f; steps.push({ type: 'rule', text: `use_backend ${f.pool.name} ${m.raw || ''}`.trim() + ` — matched: ${m.text || 'always'}`, index: m.index, line: f.line }); break; }
    if (r === null) { uncertain = true; steps.push({ type: 'rule', text: `use_backend ${f.pool.name} ${m.raw}`, index: m.index, skipped: true, note: 'cannot be decided from host/path/method/port alone; assumed not to match', line: f.line }); } else steps.push({ type: 'rule', text: `use_backend ${f.pool.name} ${m.raw}`, index: m.index, skipped: true, note: 'did not match', line: f.line });
  }
  if (!chosen) return finish(fe, null, { status: 503, text: 'No use_backend matched and there is no default_backend → 503 Service Unavailable' });
  const stop2 = runChain(chosen.chain.filter((s) => s.stage === 'backend')).stop;
  if (stop2) return finish(fe, chosen, { status: stop2.action === 'redirect' ? 301 : stop2.action === 'deny' ? 403 : null, text: stop2.text });
  return finish(fe, chosen, null);

  function finish(feFlow, flow, response) {
    const members = flow ? memberView(flow, port) : [];
    if (flow && flow.pool.undefined) response = response || { status: 503, text: `Backend "${flow.pool.name}" is not defined → 503` };
    if (flow && flow.members.length) steps.push({ type: 'members', text: `Forwarded to ${flow.pool.name}: ${members.map((m) => `${m.name} ${m.socket ? m.address : `:${m.port == null ? '?' : m.port}`}`).join(', ')}${flow.pool.balance ? ` (balance ${flow.pool.balance})` : ''}` });
    return { ok: !response, uncertain, response, frontend: feFlow.frontend, rule: flow ? flow.match.index : null, backend: flow ? flow.pool.name : null, path: { in: rq.path, out: path, exact }, members, steps, tls: flow ? tlsKind(l.tls, flow.members.some((m) => m.ssl), flow.mode) : null, listener: { address: l.address, port, tls: l.tls } };
  }
}

function traceNginx(sections, rq) {
  const flows = ngxFlows(sections);
  const steps = [];
  const servers = sections.filter((s) => s.type === 'frontend');
  const matchesPort = (sec) => sec.binds.some((b) => !b.commented && (rq.port == null || String(b.port) === String(rq.port)) && (rq.tls == null || Boolean(b.ssl) === rq.tls));
  const cand = servers.filter(matchesPort);
  if (!cand.length) return { ok: false, response: { status: null, text: 'No server block listens on that port' }, steps: [{ type: 'listener', text: `No listen directive matches ${rq.tls ? 'TLS ' : ''}port ${rq.port == null ? '(any)' : rq.port}` }] };
  let best = null; let rank = 0; let how = '';
  for (const sec of cand) for (const n of sec.serverNames || []) { const r = SERVER_NAME_RANK(n, rq.host); if (r > rank) { rank = r; best = sec; how = `server_name ${n}`; } }
  if (!best) {
    best = cand.find((s) => s.binds.some((b) => (b.flags || []).includes('default_server'))) || cand[0];
    how = cand.length > 1 || rq.host ? `default server for the port (no server_name matched "${rq.host || '(no Host)'}")` : 'only server on that port';
  }
  const lb = best.binds.find((b) => !b.commented && (rq.port == null || String(b.port) === String(rq.port))) || best.binds[0];
  const port = rq.port != null ? rq.port : Number(lb.port);
  steps.push({ type: 'listener', text: `Arrives on ${lb.address}${lb.ssl ? ' (TLS)' : ''} → server ${best.name} — ${how}`, line: best.line });
  let path = rq.path; let exact = true;
  const fnPass = (f) => (f.frontend === best.name ? f : null);
  const mine = flows.filter(fnPass);
  // server-level rewrites (before location search)
  for (const dd of best.directives.filter((x) => x.keyword === 'rewrite' && (x.within || []).length === 0)) {
    const r = applyNgxRewrite(dd.args, path);
    if (!r || !r.matched) { steps.push({ type: 'rewrite', text: `rewrite ${dd.args.join(' ')}`, applied: false, note: r ? 'pattern did not match' : 'could not evaluate pattern', line: dd.line, scope: 'server' }); continue; }
    if (r.redirect) return { ok: false, response: { status: r.status, text: `Redirect to ${r.path}` }, steps: [...steps, { type: 'response', text: `rewrite ${dd.args.join(' ')}`, applied: true, line: dd.line }], frontend: best.name, path: { in: rq.path, out: path, exact: false } };
    steps.push({ type: 'rewrite', text: `rewrite ${dd.args.join(' ')}`, applied: true, from: path, to: r.path, line: dd.line, scope: 'server' }); path = r.path;
    if (r.flag === 'break' || r.flag === 'last') break;
  }
  const pickLocation = (uri) => {
    const locs = (best.locations || []).filter((l) => l.path && !l.path.startsWith('@') && !l.parent);
    const exactHit = locs.find((l) => l.modifier === '=' && l.path === uri);
    if (exactHit) return exactHit;
    const prefixes = locs.filter((l) => !/^~/.test(l.modifier) && l.modifier !== '=' && uri.startsWith(l.path)).sort((a, b) => b.path.length - a.path.length);
    const longest = prefixes[0];
    if (longest && longest.modifier === '^~') return longest;
    for (const l of locs.filter((x) => /^~\*?$/.test(x.modifier))) { try { if (new RegExp(l.path, l.modifier === '~*' ? 'i' : '').test(uri)) return l; } catch { /* unsupported pattern */ } }
    return longest || null;
  };
  let loc = null; let broke = false;
  for (let round = 0; round < 10; round++) {
    loc = pickLocation(path);
    steps.push({ type: 'rule', text: loc ? `location ${loc.modifier ? `${loc.modifier} ` : ''}${loc.path} matched ${path}` : `No location matches ${path}`, line: loc ? loc.line : undefined });
    if (!loc) break;
    const flow = mine.find((f) => f.match.path === loc.path && f.match.modifier === loc.modifier);
    const rws = flow ? flow.chain.filter((s) => s.action === 'rewrite' && s.scope === 'location') : [];
    let again = false;
    for (const s of rws) {
      const r = applyNgxRewrite(s.args, path);
      if (!r || !r.matched) { steps.push({ type: 'rewrite', text: s.text, applied: false, note: r ? 'pattern did not match' : 'could not evaluate pattern', line: s.line, scope: 'location' }); continue; }
      if (r.redirect) return { ok: false, response: { status: r.status, text: `Redirect to ${r.path}` }, steps: [...steps, { type: 'response', text: s.text, applied: true, line: s.line }], frontend: best.name, path: { in: rq.path, out: path, exact: false } };
      steps.push({ type: 'rewrite', text: s.text, applied: true, from: path, to: r.path, line: s.line, scope: 'location' }); path = r.path; exact = exact && !r.dynamic;
      if (r.flag === 'break') { broke = true; break; }
      if (r.flag === 'last') { again = true; break; }
    }
    if (!again) break;
    if (round === 9) return { ok: false, response: { status: 500, text: 'rewrite … last looped more than 10 times → 500' }, steps, frontend: best.name, path: { in: rq.path, out: path, exact: false } };
  }
  if (!loc) return { ok: false, response: { status: 404, text: 'No location matches; the server would answer from its default root (404 if nothing is there)' }, steps, frontend: best.name, path: { in: rq.path, out: path, exact } };
  const flow = mine.find((f) => f.match.path === loc.path && f.match.modifier === loc.modifier);
  if (!flow) {
    const label = loc.kind === 'return' ? `return ${loc.detail || ''}` : loc.kind === 'static' ? `serves static files from ${loc.detail || 'root'}` : `no proxy_pass here (${loc.kind})`;
    steps.push({ type: 'response', text: label, line: loc.line });
    return { ok: true, local: true, frontend: best.name, backend: null, path: { in: rq.path, out: path, exact }, members: [], steps, response: loc.kind === 'return' ? { status: Number((loc.detail || '').split(/\s+/)[0]) || null, text: `return ${loc.detail || ''}` } : null, listener: { address: lb.address, port, tls: Boolean(lb.ssl) } };
  }
  const uriStep = flow.chain.find((s) => s.action === 'proxy_pass-uri');
  if (uriStep && !broke) {
    if (/^~/.test(flow.match.modifier)) { steps.push({ type: 'rewrite', text: uriStep.text, applied: false, note: 'a URI in proxy_pass is not allowed in a regex location (nginx rejects the config)', line: uriStep.line }); exact = false; } else if (/\$/.test(flow.passUrl || '')) { steps.push({ type: 'rewrite', text: uriStep.text, applied: true, from: path, to: uriStep.args[0], note: 'with variables the URI is sent as written', line: uriStep.line }); path = uriStep.args[0]; exact = false; } else {
      const out = flow.match.modifier === '=' ? uriStep.args[0] : `${uriStep.args[0]}${path.startsWith(flow.match.path) ? path.slice(flow.match.path.length) : path}`;
      steps.push({ type: 'rewrite', text: uriStep.text, applied: true, from: path, to: out, note: `matched prefix ${flow.match.path} is replaced by ${uriStep.args[0]}`, line: uriStep.line }); path = out;
    }
  } else if (uriStep && broke) steps.push({ type: 'rewrite', text: uriStep.text, applied: false, note: 'ignored because `rewrite … break` already set the URI', line: uriStep.line });
  const host = flow.chain.find((s) => s.action === 'set-header');
  const members = memberView(flow, port);
  steps.push({ type: 'members', text: `proxy_pass ${flow.passUrl || ''} → ${flow.pool.name}: ${members.map((m) => `${m.name} ${m.socket ? '' : `:${m.port == null ? '?' : m.port}`}`).join(', ')}${flow.pool.balance ? ` (${flow.pool.balance})` : ''}` });
  return { ok: true, frontend: best.name, rule: flow.match.index, backend: flow.pool.name, path: { in: rq.path, out: path, exact }, hostHeader: host ? host.args[1] : null, members, steps, tls: tlsKind(Boolean(lb.ssl), flow.members.some((m) => m.ssl), flow.mode), listener: { address: lb.address, port, tls: Boolean(lb.ssl) } };
}

function trace(product, sections, request) {
  const rq = normaliseRequest(request || {});
  return product === 'nginx' ? traceNginx(sections, rq) : traceHaproxy(sections, rq);
}

module.exports = { buildFlows, trace, parseServerAddress, resolvePort, applyHapPath, applyNgxRewrite, evalCondition };

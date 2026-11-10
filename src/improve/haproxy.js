'use strict';
/**
 * Config Forge, HAProxy side: parse a configuration into a small AST (sections, directives, comments), run the rules,
 * and print a clean, rewritten configuration. Rules are version-aware (checked against the knowledge base) and never
 * touch what is already good, so running the result through the engine again proposes nothing.
 */
const { tokens, unq } = require('./common');
const V = require('../validate/version');
const kb = require('../kb/haproxy.json');

const SECTION_KW = new Set(['global', 'defaults', 'frontend', 'backend', 'listen', 'userlist', 'resolvers', 'peers', 'cache', 'program', 'mailers', 'http-errors', 'ring', 'fcgi-app', 'crt-store', 'acme', 'traces', 'log-forward']);
const IND = '    ';
const WEAK = /(RC4|3DES|DES-CBC|MD5|EXPORT|NULL|aNULL|eNULL|ADH|\bDES\b)/i;
const CIPHERS = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const SUITES = 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';
const COMPRESS_TYPES = 'text/html text/plain text/css text/xml text/javascript application/javascript application/json application/xml image/svg+xml';

// ------------------------------------------------------------------------------------------------ parse / print
function itemFields(text) {
  const t = tokens(text); let neg = null; let i = 0;
  if (t[0] === 'no' || t[0] === 'default') { neg = t[0]; i = 1; }
  return { kw: t[i] || '', args: t.slice(i + 1), neg };
}
function parse(text) {
  const lines = String(text).replace(/^﻿/, '').split(/\r?\n/);
  const ast = { lead: [], sections: [] }; let cur = null; let blank = false; let pending = []; // pending: comments after a blank line, possibly the lead of the next section
  const flushPending = (into) => { into.push(...pending); pending = []; };
  lines.forEach((raw, idx) => {
    const line = raw.replace(/\s+$/, ''); const trimmed = line.trim(); const no = idx + 1;
    if (!trimmed) { blank = true; return; }
    const first = tokens(trimmed)[0];
    const isHeader = !trimmed.startsWith('#') && SECTION_KW.has(first) && (!/^\s/.test(line) || !cur);
    if (isHeader) {
      const sec = { type: first, name: tokens(trimmed).slice(1).join(' '), header: trimmed, line: no, lead: [], items: [], blank };
      if (cur) sec.lead = pending; else ast.lead.push(...pending); pending = []; blank = false;
      ast.sections.push(sec); cur = sec; return;
    }
    if (trimmed.startsWith('#')) {
      const node = { t: 'comment', text: trimmed, line: no, blank };
      if (!cur) ast.lead.push(node);
      else if (blank || pending.length) { pending.push(node); } else cur.items.push(node); // comments after a blank line may belong to the next section
      blank = false; return;
    }
    if (!cur) { ast.lead.push({ t: 'comment', text: `# ${trimmed}`, line: no, blank }); blank = false; return; }
    flushPending(cur.items);
    cur.items.push({ t: 'item', text: trimmed, line: no, blank, ...itemFields(trimmed) }); blank = false;
  });
  if (cur) flushPending(cur.items); else ast.lead.push(...pending);
  return ast;
}
function print(ast) {
  const out = [];
  const node = (n, ind) => { if (n.blank && out.length && out[out.length - 1] !== '') out.push(''); out.push(`${ind}${n.text}`); };
  ast.lead.forEach((n) => node(n, ''));
  ast.sections.forEach((s, i) => {
    if (out.length && out[out.length - 1] !== '' && (i > 0 || s.blank || s._new)) out.push('');
    s.lead.forEach((n) => { node({ ...n, blank: false }, ''); });
    out.push(s.header);
    s.items.forEach((n) => node(n, IND));
  });
  return `${out.join('\n').replace(/\n{3,}/g, '\n\n')}\n`;
}

// ------------------------------------------------------------------------------------------------ analysis
function analyze(text, opts = {}) {
  const ast = parse(text); const normalized = print(ast);
  const target = V.haproxyBranch(V.detect(opts.version) || opts.version, kb.versions) || kb.versions[kb.versions.length - 1];
  const versionKnown = Boolean(opts.version);
  const has = (table, name) => { const e = kb[table] && kb[table][name]; return Boolean(e) && V.gte(target, e.s) && !(e.r && V.gte(target, e.r)); };
  const removed = (name) => { const e = kb.proxy[name]; return Boolean(e && e.r && V.gte(target, e.r)); };
  const secs = ast.sections; const changes = [];
  const items = (sec, kw) => sec.items.filter((n) => n.t === 'item' && n.kw === kw && !n.neg);
  const first = (sec, kw) => items(sec, kw)[0];
  const optOf = (sec, name) => sec.items.find((n) => n.t === 'item' && n.kw === 'option' && n.args[0] === name && !n.neg);
  const global = secs.find((s) => s.type === 'global');
  const defaultsList = secs.filter((s) => s.type === 'defaults');
  const govMap = new Map(); { let d = null; for (const s of secs) { if (s.type === 'defaults') d = s; else govMap.set(s, d); } }
  const gov = (sec) => govMap.get(sec) || null;
  const eff = (sec, f) => f(sec) || (gov(sec) && f(gov(sec))) || null;
  const modeOf = (sec) => { const m = eff(sec, (s) => first(s, 'mode')); return m ? m.args[0] : 'tcp'; };
  const isFe = (s) => s.type === 'frontend' || s.type === 'listen';
  const isBe = (s) => s.type === 'backend' || s.type === 'listen';
  const fronts = secs.filter((s) => isFe(s) && items(s, 'bind').length);
  const backs = secs.filter((s) => isBe(s) && (items(s, 'server').length || items(s, 'server-template').length));
  const proxies = secs.filter((s) => isFe(s) || s.type === 'backend');
  const sslBinds = secs.flatMap((s) => (isFe(s) ? items(s, 'bind').filter((b) => b.args.includes('ssl') || b.args.includes('crt')).map((b) => ({ b, s })) : []));
  const nm = (s) => `${s.type} ${s.name}`.trim();

  // ---- ops
  const mk = (t) => ({ t: 'item', text: t, _new: true, blank: false, ...itemFields(t) });
  const ops = {
    ins: (sec, at, t) => ({ kind: 'add', text: t, run() {
      const n = mk(t); let idx;
      if (at === 'start') idx = 0;
      else if (at && at.before) idx = sec.items.indexOf(at.before);
      else if (at && at.after) { idx = sec.items.indexOf(at.after) + 1; while (sec.items[idx] && sec.items[idx]._after === at.after) idx++; n._after = at.after; }
      else { let last = -1; sec.items.forEach((x, i) => { if (x.t === 'item') last = i; }); idx = last + 1; while (sec.items[idx] && sec.items[idx]._end) idx++; n._end = true; }
      sec.items.splice(Math.max(0, idx), 0, n);
    } }),
    rep: (node, t) => ({ kind: 'mod', before: node.text, text: t, run() { node.text = t; Object.assign(node, itemFields(t)); } }),
    del: (node) => ({ kind: 'del', before: node.text, run() { const s = secs.find((x) => x.items.includes(node)); if (s) s.items.splice(s.items.indexOf(node), 1); } }),
  };
  let seq = 0;
  const add = (c) => changes.push({ key: `${c.rule}:${++seq}`, auto: true, on: true, severity: 'medium', ...c, ops: c.ops || [] });
  const advice = (c) => add({ ...c, auto: false, on: false });
  const lineOf = (n) => (n && n.line) || null;
  // where to put a line: end of the section by default
  const addLine = (sec, t, at) => ops.ins(sec, at || 'end', t);

  // ---- global ---------------------------------------------------------------------------------------------
  if (global) {
    if (!items(global, 'log').length && !items(global, 'log-send-hostname').length) {
      add({ rule: 'hap-log', category: 'observability', severity: 'medium', title: 'Send logs to syslog', section: 'global', line: global.line,
        why: 'Without a global `log` line HAProxy writes no access or error logs, so outages and attacks leave no trace. (In a container use `log stdout format raw local0` instead.)',
        ops: [ops.ins(global, 'start', 'log /dev/log local1 notice'), ops.ins(global, 'start', 'log /dev/log local0')] });
    }
    if (!items(global, 'maxconn').length) add({ rule: 'hap-maxconn', category: 'reliability', severity: 'low', title: 'Set an explicit global maxconn', section: 'global', line: global.line,
      why: 'HAProxy derives maxconn from the file-descriptor limit, which differs per host and after upgrades. Setting it explicitly makes capacity predictable (about 16 KB per plain and 32 KB per TLS connection). Tune the value to your RAM.', ops: [addLine(global, 'maxconn 20000')] });
    const nbp = first(global, 'nbproc');
    if (nbp && has('global', 'nbthread')) {
      const nbt = first(global, 'nbthread');
      add({ rule: 'hap-nbproc', category: 'compatibility', severity: removed('nbproc') || (kb.global.nbproc.r && V.gte(target, kb.global.nbproc.r)) ? 'high' : 'medium', title: 'Replace nbproc with nbthread', section: 'global', line: nbp.line,
        why: 'Each process has its own stick-tables, health checks, stats and rate limits; threads share them all. `nbproc` was removed in HAProxy 2.5 and `nbthread` is the supported model.',
        ops: [nbt ? ops.del(nbp) : ops.rep(nbp, `nbthread ${nbp.args[0] || 'auto'}`)] });
    }
    const mm = items(global, 'ssl-server-verify').find((n) => n.args[0] === 'none');
    if (mm) advice({ rule: 'hap-ssl-verify-global', category: 'security', severity: 'high', title: 'Server certificates are not verified (global)', section: 'global', line: mm.line, why: '`ssl-server-verify none` makes every TLS connection to your servers open to man-in-the-middle attacks. Remove it and set `ca-file` on the servers (or `verify required ca-file ...`).' });
    for (const s of items(global, 'stats')) {
      if (s.args[0] !== 'socket') continue;
      const addr = s.args[1] || '';
      if (/^(ipv4@|ipv6@|tcp)/i.test(addr) || /^(\*|0\.0\.0\.0|\[?::\]?):/.test(addr)) advice({ rule: 'hap-stats-socket', category: 'security', severity: 'high', title: 'Runtime API socket is reachable over the network', section: 'global', line: s.line, why: 'The admin socket can disable servers and change weights. Use a unix socket with `mode 660 level admin`, or bind a TCP socket to 127.0.0.1 only.' });
    }
    // TLS defaults, only when something terminates TLS
    if (sslBinds.length) {
      const t = (opt) => ({ opt });
      const bopts = first(global, 'ssl-default-bind-options');
      const modern = has('bind', 'ssl-min-ver');
      const minOf = (args) => { const i = args.indexOf('ssl-min-ver'); return i >= 0 ? args[i + 1] : null; };
      const old = (v) => /^(SSLv3|TLSv1\.0|TLSv1\.1)$/i.test(v || '');
      if (!bopts) {
        add({ rule: 'hap-tls-options', category: 'security', severity: 'high', title: 'Set a TLS floor and disable session tickets', section: 'global', line: global.line,
          why: 'Without `ssl-default-bind-options` HAProxy accepts whatever the TLS library allows, including TLS 1.0/1.1. TLS 1.2 is the safe floor (PCI DSS, NIST, Mozilla); `no-tls-tickets` keeps forward secrecy intact.',
          ops: [addLine(global, `ssl-default-bind-options ${modern ? 'ssl-min-ver TLSv1.2' : 'no-sslv3 no-tlsv10 no-tlsv11'} no-tls-tickets`)] });
      } else {
        const a = bopts.args.slice(); let changed = false;
        const i = a.indexOf('ssl-min-ver');
        if (i >= 0 && old(a[i + 1])) { a[i + 1] = 'TLSv1.2'; changed = true; }
        const bad = a.filter((x) => /^force-(sslv3|tlsv10|tlsv11)$/.test(x)); if (bad.length) { bad.forEach((x) => a.splice(a.indexOf(x), 1)); changed = true; }
        if (i < 0 && !(a.includes('no-tlsv10') && a.includes('no-tlsv11')) && !a.includes('force-tlsv12') && !a.includes('force-tlsv13')) { a.push(...(modern ? ['ssl-min-ver', 'TLSv1.2'] : ['no-sslv3', 'no-tlsv10', 'no-tlsv11'])); changed = true; }
        if (!a.includes('no-tls-tickets')) { a.push('no-tls-tickets'); changed = true; }
        if (changed) add({ rule: 'hap-tls-options', category: 'security', severity: 'high', title: 'Tighten ssl-default-bind-options', section: 'global', line: bopts.line, why: 'Allow TLS 1.2 and newer only, and turn session tickets off (they break forward secrecy unless the ticket key is rotated).', ops: [ops.rep(bopts, `ssl-default-bind-options ${a.join(' ')}`)] });
      }
      const ci = first(global, 'ssl-default-bind-ciphers');
      if (!ci) add({ rule: 'hap-tls-ciphers', category: 'security', severity: 'medium', title: 'Set modern TLS 1.2 ciphers', section: 'global', line: global.line, why: 'The OpenSSL default list changes between builds and may include weak CBC suites. This is the Mozilla “intermediate” ECDHE-only list: forward secrecy and AEAD everywhere, compatible with every client that speaks TLS 1.2.', ops: [addLine(global, `ssl-default-bind-ciphers ${CIPHERS}`)] });
      else if (WEAK.test(ci.args[0] || '') && !/!(RC4|3DES|MD5|aNULL)/i.test(ci.args[0])) add({ rule: 'hap-tls-ciphers', category: 'security', severity: 'high', title: 'Replace weak ciphers', section: 'global', line: ci.line, why: 'RC4, 3DES, MD5, EXPORT and NULL suites are broken or deprecated (RFC 7465, SWEET32).', ops: [ops.rep(ci, `ssl-default-bind-ciphers ${CIPHERS}`)] });
      if (has('global', 'ssl-default-bind-ciphersuites') && !first(global, 'ssl-default-bind-ciphersuites')) add({ rule: 'hap-tls13-suites', category: 'security', severity: 'low', title: 'Pin the TLS 1.3 cipher suites', section: 'global', line: global.line, why: '`ssl-default-bind-ciphers` only governs TLS 1.2 and below; TLS 1.3 suites are set separately. These three are the standard AEAD suites.', ops: [addLine(global, `ssl-default-bind-ciphersuites ${SUITES}`)] });
      const dh = first(global, 'tune.ssl.default-dh-param');
      if (dh && Number(dh.args[0]) < 2048) add({ rule: 'hap-dh-param', category: 'security', severity: 'medium', title: 'DH parameters are too small', section: 'global', line: dh.line, why: 'Diffie-Hellman groups below 2048 bits can be broken (Logjam).', ops: [ops.rep(dh, 'tune.ssl.default-dh-param 2048')] });
    }
    const hasSslServers = secs.some((s) => (s.type === 'backend' || s.type === 'listen' || s.type === 'defaults') && [...items(s, 'server'), ...items(s, 'default-server')].some((x) => x.args.includes('ssl')));
    if (hasSslServers && has('bind', 'ssl-min-ver') && !items(global, 'ssl-default-server-options').length) add({ rule: 'hap-tls-server', category: 'security', severity: 'low', on: false, title: 'Set a TLS floor for connections to servers', section: 'global', line: global.line, why: 'Re-encrypted connections to backends otherwise negotiate any version the server offers. Only enable this if none of your backends is limited to TLS 1.0/1.1.', ops: [addLine(global, 'ssl-default-server-options ssl-min-ver TLSv1.2')] });
  }

  // ---- defaults ---------------------------------------------------------------------------------------------
  const globalLogs = global && items(global, 'log').length > 0;
  const hasLogLine = (s) => Boolean(eff(s, (x) => first(x, 'log') || first(x, 'log-format') || null));
  const needsGlobalLog = () => globalLogs || (global && !items(global, 'log').length); // we add a log line to global, or it exists
  const httpFronts = fronts.filter((s) => modeOf(s) === 'http');
  const allModes = new Set(proxies.map(modeOf));
  if (proxies.length && !defaultsList.length) {
    const http = allModes.size === 1 && allModes.has('http'); const tcp = allModes.size === 1 && allModes.has('tcp');
    const lines = [];
    if (http) lines.push('mode http');
    lines.push('log global');
    if (http) lines.push('option httplog', 'option dontlognull'); else if (tcp) lines.push('option tcplog', 'option dontlognull');
    lines.push('option redispatch', 'timeout connect 5s', 'timeout client 30s', 'timeout server 30s');
    if (http) lines.push('timeout http-request 10s', 'timeout http-keep-alive 10s');
    if (http && backs.length) lines.push('option forwardfor');
    add({ rule: 'hap-defaults-missing', category: 'reliability', severity: 'high', title: 'Add a defaults section', section: 'defaults', line: null,
      why: 'There is no `defaults` section, so every proxy runs with HAProxy\'s built-in values: no timeouts (connections can hang forever and exhaust maxconn), no logging and no retry policy.',
      ops: [{ kind: 'add', text: ['defaults', ...lines.map((l) => IND + l)].join('\n'), run() {
        const sec = { type: 'defaults', name: '', header: 'defaults', line: null, lead: [], blank: true, items: lines.map(mk) };
        const at = global ? secs.indexOf(global) + 1 : 0; secs.splice(at, 0, sec);
      } }] });
  } else if (proxies.length) {
    /** Add `text` once to the governing defaults when all of `targets` share it, otherwise to every target proxy. */
    const place = (rule, targets, text, meta) => {
      if (!targets.length) return;
      const byGov = new Map(); targets.forEach((p) => { const g = gov(p); const k = g || 'none'; (byGov.get(k) || byGov.set(k, []).get(k)).push(p); });
      for (const [g, list] of byGov) {
        const inList = new Set(list);
        const modeOk = !meta.onlyMode || proxies.every((p) => gov(p) !== g || modeOf(p) === meta.onlyMode); // an http-only line in defaults would warn on tcp proxies
        const sharedOk = g !== 'none' && modeOk && proxies.every((p) => gov(p) !== g || !(meta.scope ? meta.scope(p) : true) || inList.has(p));
        if (sharedOk) add({ rule, ...meta, section: `defaults ${g.name || ''}`.trim(), line: g.line, ops: [addLine(g, text)] });
        else list.forEach((p) => add({ rule, ...meta, section: nm(p), line: p.line, ops: [addLine(p, text)] }));
      }
    };
    const LEGACY_T = { client: 'clitimeout', server: 'srvtimeout', connect: 'contimeout' };
    const missingT = (kw, scope) => scope.filter((p) => !eff(p, (x) => items(x, 'timeout').find((t) => t.args[0] === kw) || (LEGACY_T[kw] && first(x, LEGACY_T[kw]))));
    const tm = (kw, val, scope, meta) => place(`hap-timeout-${kw}`, missingT(kw, scope), `timeout ${kw} ${val}`, meta);
    const beAll = proxies.filter((p) => isBe(p) || p.type === 'backend'); const beSet = new Set(beAll); const frontSet = new Set(fronts); const backSet = new Set(backs); const httpFrontSet = new Set(httpFronts);
    tm('connect', '5s', beAll.filter((p) => items(p, 'server').length || items(p, 'server-template').length), { category: 'reliability', severity: 'high', title: 'Set timeout connect', why: 'No connect timeout means HAProxy waits for the kernel (up to minutes) when a server is unreachable, holding the client and a slot. 5 seconds is generous for a LAN.', scope: (p) => beSet.has(p) });
    tm('client', '30s', fronts, { category: 'reliability', severity: 'high', title: 'Set timeout client', why: 'Without `timeout client` idle or half-open client connections never expire and slowly consume maxconn (a cheap denial of service).', scope: (p) => frontSet.has(p) });
    tm('server', '30s', backs, { category: 'reliability', severity: 'high', title: 'Set timeout server', why: 'Without `timeout server` a hung backend ties up a client connection indefinitely. Raise it only for endpoints that really take longer.', scope: (p) => backSet.has(p) });
    tm('http-request', '10s', httpFronts, { category: 'security', severity: 'medium', onlyMode: 'http', title: 'Set timeout http-request (slowloris protection)', why: 'Limits how long a client may take to send a complete request. Without it a slow client can keep a connection open indefinitely.', scope: (p) => httpFrontSet.has(p) });
    tm('http-keep-alive', '10s', httpFronts, { category: 'performance', severity: 'low', onlyMode: 'http', title: 'Set timeout http-keep-alive', why: 'Idle keep-alive connections otherwise live as long as `timeout client`; a short value frees slots sooner without hurting page loads.', scope: (p) => httpFrontSet.has(p) });
    // logging
    const logNeed = fronts.filter((p) => !(eff(p, (x) => optOf(x, 'httplog') || optOf(x, 'tcplog') || first(x, 'log-format') || optOf(x, 'dontlog-normal') && null)));
    for (const mode of ['http', 'tcp']) {
      const list = logNeed.filter((p) => modeOf(p) === mode);
      place(`hap-${mode}log`, list, mode === 'http' ? 'option httplog' : 'option tcplog', { category: 'observability', severity: 'medium', onlyMode: mode, title: mode === 'http' ? 'Use option httplog' : 'Use option tcplog', why: mode === 'http' ? 'The default log format omits the request line, status code, timings and termination state: the data you need to debug a slow or failing request.' : 'The default log format is minimal; `option tcplog` adds timers, byte counts and the termination state.', scope: (p) => frontSet.has(p) });
    }
    place('hap-log-global', fronts.filter((p) => !hasLogLine(p) && (globalLogs || (global && !items(global, 'log').length))), 'log global', { category: 'observability', severity: 'medium', title: 'Inherit the global log destination', why: 'Frontends only log when they have a `log` line or inherit `log global`.', scope: (p) => frontSet.has(p) });
    place('hap-dontlognull', fronts.filter((p) => !eff(p, (x) => optOf(x, 'dontlognull'))), 'option dontlognull', { category: 'observability', severity: 'low', title: 'Do not log empty connections', why: 'Load-balancer probes and port scans open connections that send nothing; `option dontlognull` keeps them out of the logs without hiding real errors.', scope: (p) => frontSet.has(p) });
    place('hap-redispatch', backs.filter((p) => !eff(p, (x) => optOf(x, 'redispatch')) && has('proxy', 'option redispatch') ), 'option redispatch', { category: 'reliability', severity: 'medium', title: 'Retry on another server (option redispatch)', why: 'When a connection attempt fails, HAProxy retries the same server by default. With `option redispatch` the last retry goes to a healthy one, so a server that just died does not cost a request.', scope: (p) => backSet.has(p) });
  }

  // ---- frontends --------------------------------------------------------------------------------------------
  for (const fe of fronts) {
    const http = modeOf(fe) === 'http';
    const binds = items(fe, 'bind'); const sslB = binds.filter((b) => b.args.includes('ssl')); const plainB = binds.filter((b) => !b.args.includes('ssl') && !b.args.includes('crt'));
    const stats = items(fe, 'stats');
    if (stats.length) {
      const authed = stats.some((n) => n.args[0] === 'auth') || items(fe, 'http-request').some((n) => n.args[0] === 'auth');
      const weak = stats.find((n) => n.args[0] === 'auth' && /^(admin|root|haproxy|stats|user|test):(admin|root|password|haproxy|stats|1234|123456|test|changeme|admin123)$/i.test(n.args[1] || ''));
      if (!authed) advice({ rule: 'hap-stats-auth', category: 'security', severity: 'high', title: 'Stats page without authentication', section: nm(fe), line: stats[0].line, why: 'Anyone who can reach this port can read your topology and, with `stats admin`, disable servers. Add `stats auth user:password` (hash it with a userlist) and restrict the bind address.' });
      if (weak) advice({ rule: 'hap-stats-weak', category: 'security', severity: 'high', title: 'Default or guessable stats credentials', section: nm(fe), line: weak.line, why: 'Change this password; credential lists try these first.' });
      const adm = stats.find((n) => n.args[0] === 'admin' && /\bTRUE\b/i.test(n.args.join(' ')));
      if (adm) advice({ rule: 'hap-stats-admin', category: 'security', severity: 'high', title: 'stats admin if TRUE lets anyone administer', section: nm(fe), line: adm.line, why: 'Restrict it with a condition such as `if { src 10.0.0.0/8 }` or `if LOCALHOST`.' });
      const open = binds.find((b) => /^(\*|0\.0\.0\.0|\[?::\]?)?:\d+/.test(b.args[0] || '') && !/^127\./.test(b.args[0]));
      if (open && !adm) advice({ rule: 'hap-stats-bind', category: 'security', severity: 'medium', title: 'Stats page listens on all interfaces', section: nm(fe), line: open.line, why: 'Bind it to 127.0.0.1 or a management network (`bind 127.0.0.1:8404`) and reach it over a tunnel or VPN.' });
    }
    const statsOnly = stats.length > 0 && !items(fe, 'use_backend').length && !first(fe, 'default_backend');
    // per-bind TLS fixes
    for (const b of sslB) {
      const a = b.args.slice(); let changed = false;
      const i = a.indexOf('ssl-min-ver'); if (i >= 0 && /^(SSLv3|TLSv1\.0|TLSv1\.1)$/i.test(a[i + 1])) { a[i + 1] = 'TLSv1.2'; changed = true; }
      for (const x of a.slice()) if (/^force-(sslv3|tlsv10|tlsv11)$/.test(x)) { a.splice(a.indexOf(x), 1); changed = true; }
      const ci = a.indexOf('ciphers'); if (ci >= 0 && WEAK.test(a[ci + 1] || '') && !/!(RC4|3DES|MD5|aNULL)/i.test(a[ci + 1])) { a[ci + 1] = CIPHERS; changed = true; }
      if (changed) add({ rule: 'hap-bind-tls', category: 'security', severity: 'high', title: 'Remove legacy TLS from a bind line', section: nm(fe), line: b.line, why: 'This bind allows TLS before 1.2 or weak ciphers.', ops: [ops.rep(b, `bind ${a.join(' ')}`)] });
      else if (http && !a.includes('alpn') && !a.includes('npn') && V.gte(target, '1.9') && has('bind', 'alpn')) add({ rule: 'hap-alpn', category: 'performance', severity: 'low', title: 'Enable HTTP/2 (alpn)', section: nm(fe), line: b.line, why: 'Without ALPN browsers stay on HTTP/1.1. HTTP/2 multiplexes requests over one connection, which cuts latency for pages with many assets; HAProxy converts it back for your servers.', ops: [ops.rep(b, `${b.text.replace(/\s+#.*$/, '')} alpn h2,http/1.1`)] });
    }
    if (!http || statsOnly) continue;
    const hdr = (kind, name) => items(fe, `http-${kind}`).find((n) => /^(set-header|add-header)$/.test(n.args[0]) && String(n.args[1]).toLowerCase() === name.toLowerCase());
    const redirectsHttps = items(fe, 'http-request').some((n) => n.args[0] === 'redirect') || items(fe, 'redirect').length > 0;
    // legacy `redirect` keyword
    for (const r of items(fe, 'redirect')) add({ rule: 'hap-redirect-legacy', category: 'hygiene', severity: 'low', title: 'Use http-request redirect', section: nm(fe), line: r.line, why: 'The bare `redirect` keyword is the pre-1.6 syntax. `http-request redirect` is evaluated with the other request rules, so the order is visible and predictable.', ops: [ops.rep(r, `http-request ${r.text}`)] });
    if (sslB.length && plainB.length && !redirectsHttps) {
      const firstReq = items(fe, 'http-request')[0];
      add({ rule: 'hap-https-redirect', category: 'security', severity: 'medium', title: 'Redirect HTTP to HTTPS', section: nm(fe), line: plainB[0].line, why: 'This frontend listens on both plain and TLS ports but serves the plain port as is, so users and bots can use the site unencrypted. The rule keeps Let\'s Encrypt HTTP-01 challenges working.', ops: [firstReq ? ops.ins(fe, { before: firstReq }, 'http-request redirect scheme https code 301 unless { ssl_fc } || { path_beg /.well-known/acme-challenge/ }') : addLine(fe, 'http-request redirect scheme https code 301 unless { ssl_fc } || { path_beg /.well-known/acme-challenge/ }')] });
    }
    if (sslB.length) {
      const only = !plainB.length;
      if (!hdr('request', 'X-Forwarded-Proto')) add({ rule: 'hap-xfp', category: 'reliability', severity: 'medium', title: 'Tell servers the original scheme (X-Forwarded-Proto)', section: nm(fe), line: fe.line, why: 'After TLS is terminated here, your applications see plain HTTP and generate http:// links or redirect loops unless they are told the client used HTTPS.',
        ops: only ? [addLine(fe, 'http-request set-header X-Forwarded-Proto https')] : [addLine(fe, 'http-request set-header X-Forwarded-Proto https if { ssl_fc }'), addLine(fe, 'http-request set-header X-Forwarded-Proto http unless { ssl_fc }')] });
      const guard = only ? '' : ' if { ssl_fc }';
      if (!hdr('response', 'Strict-Transport-Security')) add({ rule: 'hap-hsts', category: 'security', severity: 'medium', title: 'Send HSTS (Strict-Transport-Security)', section: nm(fe), line: fe.line, why: 'Tells browsers to use HTTPS only for this host for a year, defeating downgrade and cookie-stripping attacks. Add `includeSubDomains` / `preload` only once every subdomain is HTTPS.', ops: [addLine(fe, `http-response set-header Strict-Transport-Security "max-age=31536000"${guard}`)] });
      if (!hdr('response', 'X-Content-Type-Options')) add({ rule: 'hap-nosniff', category: 'security', severity: 'low', title: 'Send X-Content-Type-Options: nosniff', section: nm(fe), line: fe.line, why: 'Stops browsers from guessing a different content type than the server sent, which blocks a class of XSS via uploaded files.', ops: [addLine(fe, `http-response set-header X-Content-Type-Options nosniff${guard}`)] });
      if (!hdr('response', 'Referrer-Policy')) add({ rule: 'hap-referrer', category: 'security', severity: 'info', on: false, title: 'Send Referrer-Policy', section: nm(fe), line: fe.line, why: 'Stops full URLs (which can contain tokens) leaking to other sites in the Referer header.', ops: [addLine(fe, `http-response set-header Referrer-Policy strict-origin-when-cross-origin${guard}`)] });
      if (!hdr('response', 'X-Frame-Options') && !items(fe, 'http-response').some((n) => /content-security-policy/i.test(n.text))) add({ rule: 'hap-xfo', category: 'security', severity: 'info', on: false, title: 'Send X-Frame-Options', section: nm(fe), line: fe.line, why: 'Prevents other sites from framing yours (clickjacking). Only enable it if you do not embed your pages elsewhere.', ops: [addLine(fe, `http-response set-header X-Frame-Options SAMEORIGIN${guard}`)] });
    }
    if (has('actions', 'del-header')) {
      const dels = items(fe, 'http-response').filter((n) => n.args[0] === 'del-header').map((n) => String(n.args[1]).toLowerCase());
      const need = ['Server', 'X-Powered-By'].filter((h) => !dels.includes(h.toLowerCase()));
      if (need.length && (sslB.length || backs.length)) add({ rule: 'hap-hide-headers', category: 'security', severity: 'low', title: 'Hide server software headers', section: nm(fe), line: fe.line, why: '`Server` and `X-Powered-By` advertise product and version, which helps attackers pick exploits.', ops: need.map((h) => addLine(fe, `http-response del-header ${h}`)) });
    }
    // simple per-IP rate limit (opt-in: the numbers depend on the application)
    if (!items(fe, 'stick-table').length && !items(fe, 'http-request').some((n) => /track-sc/.test(n.args[0])) && has('proxy', 'stick-table')) add({ rule: 'hap-ratelimit', category: 'security', severity: 'low', on: false, title: 'Rate-limit each client IP', section: nm(fe), line: fe.line, why: 'A per-IP request counter that answers 429 above 200 requests per 10 seconds stops trivial floods and scrapers. Tune the number to your busiest legitimate client before enabling.',
      ops: [addLine(fe, 'stick-table type ip size 200k expire 30s store http_req_rate(10s)'), addLine(fe, 'http-request track-sc0 src'), addLine(fe, 'http-request deny deny_status 429 if { sc_http_req_rate(0) gt 200 }')] });
    // advice
    if (items(fe, 'use_backend').length && !eff(fe, (x) => first(x, 'default_backend'))) advice({ rule: 'hap-default-backend', category: 'reliability', severity: 'low', title: 'No default_backend', section: nm(fe), line: fe.line, why: 'Requests matching no `use_backend` rule get a bare 503. Add a `default_backend` (even one that returns a friendly error page) so the behaviour is intentional.' });
  }

  const fwdDone = new Set();
  // ---- backends ---------------------------------------------------------------------------------------------
  for (const be of backs) {
    const http = modeOf(be) === 'http';
    const svs = [...items(be, 'server'), ...items(be, 'server-template')];
    const defSrv = eff(be, (x) => first(x, 'default-server'));
    const defCheck = (x) => items(x, 'default-server').some((d) => d.args.includes('check'));
    const hasDefCheck = defCheck(be) || (gov(be) && defCheck(gov(be)));
    const unchecked = svs.filter((sv) => !sv.args.includes('check') && !sv.args.includes('agent-check') && !sv.args.includes('track') && !sv.args.includes('disabled') && !/^\s*#/.test(sv.text) && !hasDefCheck && !sv.args.includes('check-ssl'));
    if (unchecked.length) {
      const ds = items(be, 'default-server')[0];
      if (unchecked.length === svs.length && svs.length >= 2 && !ds) add({ rule: 'hap-check', category: 'reliability', severity: 'high', title: 'Enable health checks on every server', section: nm(be), line: unchecked[0].line, why: 'Without `check` HAProxy keeps sending traffic to a dead server and users see the errors. `default-server` applies the same check settings to every server (probe every 2 s, down after 3 failures, up after 2 successes).', ops: [ops.ins(be, { before: svs[0] }, 'default-server check inter 2s fall 3 rise 2')] });
      else if (ds && !ds.args.includes('check') && unchecked.length === svs.length) add({ rule: 'hap-check', category: 'reliability', severity: 'high', title: 'Enable health checks on every server', section: nm(be), line: ds.line, why: 'Servers in this backend are never health-checked, so a dead server keeps receiving traffic.', ops: [ops.rep(ds, `${ds.text.replace(/\s+#.*$/, '')} check inter 2s fall 3 rise 2`)] });
      else add({ rule: 'hap-check', category: 'reliability', severity: 'high', title: `Health-check ${unchecked.length === 1 ? 'this server' : 'these servers'}`, section: nm(be), line: unchecked[0].line, why: 'Without `check` HAProxy keeps sending traffic to a dead server and users see the errors.', ops: unchecked.map((sv) => ops.rep(sv, `${sv.text.replace(/\s+#.*$/, '')} check inter 2s fall 3 rise 2`)) });
    }
    if (http && svs.length && (hasDefCheck || svs.some((s) => s.args.includes('check'))) && !eff(be, (x) => optOf(x, 'httpchk') || first(x, 'http-check') || optOf(x, 'ssl-hello-chk') || optOf(x, 'tcp-check'))) advice({ rule: 'hap-httpchk', category: 'reliability', severity: 'low', title: 'Health checks only test the TCP port', section: nm(be), line: svs[0].line, why: 'A TCP connect succeeds even when the application is broken. Add `option httpchk GET /health` (and `http-check expect status 200`) so a failing app is taken out of rotation.' });
    if (svs.length === 1 && be.type === 'backend' && !svs[0].args.includes('backup')) advice({ rule: 'hap-single-server', category: 'reliability', severity: 'info', title: 'Backend has a single server', section: nm(be), line: be.line, why: 'There is no redundancy: if this server fails or restarts, the service is down. Add a second server (or `backup`) when you can.' });
    if (http && !(eff(be, (x) => optOf(x, 'forwardfor'))) && !fronts.some((f) => modeOf(f) === 'http' && (items(f, 'use_backend').some((u) => u.args[0] === be.name) || (first(f, 'default_backend') || { args: [] }).args[0] === be.name) && eff(f, (x) => optOf(x, 'forwardfor'))) && !secs.some((s) => items(s, 'http-request').some((n) => /X-Forwarded-For/i.test(n.text)))) {
      const d = gov(be);
      const dOk = d && secs.filter((b) => gov(b) === d).every((b) => modeOf(b) === 'http') && backs.filter((b) => gov(b) === d).every((b) => !eff(b, (x) => optOf(x, 'forwardfor')));
      if (dOk && fwdDone.has(d)) continue;
      if (dOk) fwdDone.add(d);
      add({ rule: 'hap-forwardfor', category: 'observability', severity: 'medium', title: 'Pass the client IP to servers (option forwardfor)', section: dOk ? `defaults ${d.name || ''}`.trim() : nm(be), line: dOk ? d.line : be.line, why: 'Servers behind HAProxy see HAProxy\'s address as the client. `option forwardfor` adds `X-Forwarded-For` so access logs, rate limits and geo rules work on the real IP.', ops: [addLine(dOk ? d : be, 'option forwardfor')], group: dOk ? 'fwd' : null });
    }
    if (svs.length >= 2 && !items(be, 'default-server').some((d) => d.args.includes('slowstart')) && !svs.some((s) => s.args.includes('slowstart'))) add({ rule: 'hap-slowstart', category: 'reliability', severity: 'info', on: false, title: 'Ramp traffic up on a recovering server (slowstart)', section: nm(be), line: be.line, why: 'A server that just came back (cold caches, JIT) is hit with its full share at once. `slowstart 30s` raises its weight gradually.', ops: [(items(be, 'default-server')[0] ? ops.rep(items(be, 'default-server')[0], `${items(be, 'default-server')[0].text.replace(/\s+#.*$/, '')} slowstart 30s`) : ops.ins(be, { before: svs[0] }, 'default-server slowstart 30s'))] });
  }
  // compression (opt-in)
  const compFronts = fronts.filter((f) => modeOf(f) === 'http' && !items(f, 'compression').length && !eff(f, (x) => first(x, 'compression')) && has('proxy', 'compression'));
  compFronts.slice(0, 1).forEach(() => {
    const g = defaultsList[0]; const target0 = g && secs.filter((x) => gov(x) === g).every((x) => modeOf(x) === 'http') && compFronts.every((f) => gov(f) === g) ? g : null;
    add({ rule: 'hap-compression', category: 'performance', severity: 'low', on: false, title: 'Compress text responses', section: target0 ? 'defaults' : nm(compFronts[0]), line: (target0 || compFronts[0]).line, why: 'gzip shrinks HTML, CSS, JS and JSON by 70-90 %. Skip it if your servers already compress, or if you serve secrets in responses reflecting user input (BREACH).',
      ops: [addLine(target0 || compFronts[0], 'compression algo gzip'), addLine(target0 || compFronts[0], `compression type ${COMPRESS_TYPES}`)] });
  });

  // ---- legacy keywords (removed or deprecated in the target version) ---------------------------------------
  const sever = (kw) => (removed(kw) ? 'high' : 'low');
  const lg = (rule, n, to, why, sec) => add({ rule, category: 'compatibility', severity: sever(n.kw), title: `${n.kw} is ${removed(n.kw) ? 'removed' : 'deprecated'}: ${to ? 'replace it' : 'remove it'}`, section: nm(sec), line: n.line, why, ops: [to ? ops.rep(n, to) : ops.del(n)] });
  const unesc = (s) => unq(s).replace(/\\r\\n$/, '').replace(/\\ /g, ' ').replace(/\\\\/g, '\\');
  for (const sec of proxies.concat(defaultsList)) {
    for (const n of sec.items.filter((x) => x.t === 'item' && !x.neg)) {
      if (n.kw === 'reqadd' || n.kw === 'rspadd') {
        const body = n.text.replace(/^\S+\s+/, ''); let k0 = 0; let hv = '';
        if (/^["']/.test(body)) { const q = body[0]; k0 = body.indexOf(q, 1); k0 = k0 < 0 ? body.length : k0 + 1; hv = unesc(body.slice(0, k0)); } else { while (k0 < body.length && !(/\s/.test(body[k0]) && body[k0 - 1] !== '\\')) k0++; hv = unesc(body.slice(0, k0)); }
        const m = /^([^:]+):\s*(.*)$/.exec(hv); const rest = body.slice(k0).replace(/\s+#.*$/, '').trim();
        if (m) lg('hap-legacy-add', n, `http-${n.kw === 'reqadd' ? 'request' : 'response'} add-header ${m[1]} ${/\s/.test(m[2]) || !m[2] ? `"${m[2]}"` : m[2]}${rest ? ` ${rest}` : ''}`, `\`${n.kw}\` was removed in HAProxy 2.0; \`http-${n.kw === 'reqadd' ? 'request' : 'response'} add-header\` is the replacement (with the same \`if\`/\`unless\` conditions).`, sec);
      } else if (n.kw === 'reqdel' || n.kw === 'rspdel' || n.kw === 'reqidel' || n.kw === 'rspidel') {
        const nameOnly = /^[\w-]+$/.test(unq(n.args[0] || ''));
        if (nameOnly) lg('hap-legacy-del', n, `http-${/^req/.test(n.kw) ? 'request' : 'response'} del-header ${unq(n.args[0])}${n.args.length > 1 ? ` ${n.args.slice(1).join(' ')}` : ''}`, `\`${n.kw}\` was removed in HAProxy 2.0; \`del-header\` is the replacement.`, sec);
      } else if (n.kw === 'block') lg('hap-legacy-block', n, `http-request deny${n.args.length ? ` ${n.args.join(' ')}` : ''}`, '`block` was removed in HAProxy 2.0; `http-request deny` does the same.', sec);
      else if (n.kw === 'redispatch') lg('hap-legacy-redispatch', n, 'option redispatch', 'The bare `redispatch` keyword was replaced by `option redispatch`.', sec);
      else if (/^(clitimeout|srvtimeout|contimeout)$/.test(n.kw)) lg('hap-legacy-timeout', n, `timeout ${{ clitimeout: 'client', srvtimeout: 'server', contimeout: 'connect' }[n.kw]} ${n.args.join(' ')}`, `\`${n.kw}\` was replaced by \`timeout ...\` long ago and is removed.`, sec);
      else if (n.kw === 'option' && n.args[0] === 'forceclose') lg('hap-legacy-forceclose', n, null, '`option forceclose` was removed; HAProxy now manages connection reuse itself (`option http-server-close` / `httpclose` only if you really need them).', sec);
      else if (/^(reqrep|reqirep|rsprep|rspirep|reqdeny|reqideny|reqallow|reqtarpit|reqpass|rspdeny|rspideny|reqitarpit)$/.test(n.kw)) advice({ rule: 'hap-legacy-manual', category: 'compatibility', severity: sever(n.kw), title: `${n.kw} needs a manual rewrite`, section: nm(sec), line: n.line, why: `\`${n.kw}\` was removed in HAProxy 2.0 and has no mechanical replacement: use \`http-request replace-path\` / \`replace-header\` / \`deny\` / \`tarpit\` with an ACL.` });
    }
  }
  // order: security and reliability first, then the rest (stable within a category)
  const catRank = { security: 0, reliability: 1, compatibility: 2, performance: 3, observability: 4, hygiene: 5 };
  changes.sort((a, b) => catRank[a.category] - catRank[b.category]);
  return {
    product: 'haproxy', target, versionKnown, normalized, changes,
    /** Apply the enabled changes (once) and print the result. */
    render(enabled) { changes.forEach((c) => { if (c.auto && enabled(c)) c.ops.forEach((o) => o.run()); }); return print(ast); },
  };
}

module.exports = { analyze, parse, print };

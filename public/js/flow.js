'use strict';
/* GateLight UI: Request Routing (traffic flow). Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- TRAFFIC FLOW: listener port -> backend port, and what happens to the URI on the way ----------
const FLOW = { inst: null, data: null, loading: false, err: null, key: '', req: { host: '', path: '/', port: '', method: 'GET' }, trace: null, traceErr: null, tracing: false, fe: '', tab: 'domains', dq: '', st: '', sel: null };
const TLS_LABEL = { terminate: 'TLS ended here → plain', 're-encrypt': 'TLS → TLS (re-encrypted)', upgrade: 'plain → TLS', plain: 'plain → plain', passthrough: 'TCP passthrough' };
async function flowLoad(force) {
  if (FLOW.loading) return;
  const key = state.current;
  if (!force && FLOW.data && FLOW.key === key) return;
  FLOW.loading = true; FLOW.err = null; renderFlow();
  try {
    let res;
    if (state.mode === 'review' && state.analysisCfg) res = await api('/flow', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: state.analysisCfg.type, files: state.analysisCfg.files }) });
    else res = await api(`/instances/${encodeURIComponent(state.current)}/flow`);
    FLOW.data = res; FLOW.key = key;
  } catch (e) { FLOW.err = e.message; FLOW.data = null; }
  FLOW.loading = false; if (state.view === 'flow') renderFlow(); else if (state.view === 'topology' && FLOW.data) renderTopology();
}
async function flowTrace() {
  const r = FLOW.req; const ports = flowPorts();
  const lis = ports.find((p) => String(p.port) === String(r.port)) || ports[0];
  const body = { host: r.host, path: r.path || '/', method: r.method, port: lis ? Number(lis.port) : null, tls: lis ? lis.tls : null };
  FLOW.tracing = true; FLOW.traceErr = null; renderFlow();
  try {
    if (state.mode === 'review' && state.analysisCfg) FLOW.trace = (await api('/flow', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: state.analysisCfg.type, files: state.analysisCfg.files, request: body }) })).trace;
    else FLOW.trace = await api(`/instances/${encodeURIComponent(state.current)}/flow/trace`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } catch (e) { FLOW.traceErr = e.message; FLOW.trace = null; }
  FLOW.tracing = false; if (state.view === 'flow') renderFlow();
}
function flowPorts() { // distinct listener ports (with TLS) across all entry points
  const m = new Map();
  for (const f of (FLOW.data ? FLOW.data.flows : [])) for (const l of f.listeners) if (l.port && !m.has(`${l.port}|${l.tls}`)) m.set(`${l.port}|${l.tls}`, { port: l.port, tls: l.tls });
  return [...m.values()].sort((a, b) => Number(a.port) - Number(b.port) || Number(a.tls) - Number(b.tls));
}
const portTxt = (p, tls) => `<span class="pt${tls ? ' tls' : ''}">${tls ? '🔒 ' : ''}:${esc(p)}</span>`;
const outPorts = (pm) => (pm.targets && pm.targets.length ? pm.targets.slice(0, 4).map((t) => `<span class="pt">${esc(t)}</span>`).join(' ') + (pm.targets.length > 4 ? ` <span class="muted small" title="${esc(pm.targets.join(', '))}">+${pm.targets.length - 4}</span>` : '') : pm.out.length ? pm.out.map((o) => `<span class="pt">:${o}</span>`).join(' ') : '') + (pm.dynamic ? ' <span class="pt dyn" title="Resolved from an environment variable at start-up">env var</span>' : '') + (pm.socket ? ' <span class="pt">socket</span>' : '');
// Is a relationship live? Judged from runtime stats of the pool it leads to (rules are not counted separately by the proxy).
const FLOW_ST = { active: 'Active', idle: 'Idle', down: 'Down', dead: 'Never used', config: 'Configured' };
function poolStatus(name, undef) {
  if (undef) return { k: 'dead', text: 'Backend is not defined: requests get a 503' };
  const rows = state.snapshot && state.snapshot.rows ? state.snapshot.rows : [];
  if (!rows.length) return { k: 'config', text: 'No runtime data (configuration only)' };
  const r = rows.find((x) => x.proxy === name && x.kind === 'backend') || rows.find((x) => x.proxy === name && x.kind === 'frontend');
  if (!r) return { k: 'config', text: 'Not reported by the load balancer' };
  const srv = rows.filter((x) => x.proxy === name && x.kind === 'server');
  const up = srv.filter((x) => x.state === 'up' || x.state === 'nocheck').length;
  if (srv.length && !up) return { k: 'down', text: `No healthy member (${srv.length} down or in maintenance)` };
  if (r.ratePerSec > 0) return { k: 'active', text: `Traffic now: ${fmtRate(r.ratePerSec)} req/s${srv.length ? ` · ${up}/${srv.length} members up` : ''}` };
  return { k: 'idle', text: (r.stot || 0) > 0 ? 'No traffic right now (has served requests before)' : 'No traffic seen yet' };
}
function flowStatus(f) {
  if (f.shadowedBy) return { k: 'dead', text: `Never used: rule #${f.shadowedBy} above it catches the same requests` };
  return poolStatus(f.pool.name, f.pool.undefined);
}
// Status filter. Alive = has a healthy member (active or idle). Not alive = no healthy member, or the backend is not defined.
// Unused = receives no traffic right now, or can never be reached (shadowed rule).
const FLOW_STF = { '': 'Any status', alive: 'Alive', dead: 'Not alive', unused: 'Unused' };
function statusMatches(k, mode, o = {}) {
  if (!mode) return true;
  if (mode === 'alive') return k === 'active' || k === 'idle';
  if (mode === 'dead') return k === 'down' || (k === 'dead' && Boolean(o.undef));
  if (mode === 'unused') return k === 'idle' || (Boolean(o.shadowed) && (k === 'dead' || k === 'config'));
  return true;
}
const flowPass = (f) => { const st = flowStatus(f); return statusMatches(st.k, FLOW.st, { undef: f.pool.undefined, shadowed: f.shadowedBy }); };
// one server row, judged by its own runtime state (rows exist only when the load balancer reports them)
function serverPass(pool, name) {
  if (!FLOW.st) return true;
  const rows = state.snapshot && state.snapshot.rows ? state.snapshot.rows : []; const r = rows.find((x) => x.proxy === pool && x.kind === 'server' && x.name === name);
  if (!r) return false;
  const up = r.state === 'up' || r.state === 'nocheck';
  return FLOW.st === 'alive' ? up : FLOW.st === 'dead' ? !up : (r.ratePerSec || 0) === 0;
}
const stDot = (k) => `<span class="st-dot st-${k}" title="${esc(FLOW_ST[k])}"></span>`;
// Clicking a card in the diagram keeps only what is connected to it. A listener keeps its own port only; a rule keeps its
// listeners and pool; a pool keeps every rule that leads to it.
function flowNarrow(flows) {
  const sel = FLOW.sel; if (!sel) return { flows, label: '' };
  const [kind, a, b, c] = sel.key.split('|');
  if (kind === 'l') {
    const keep = flows.filter((f) => f.frontend === a && f.listeners.some((l) => String(l.port) === b && (l.tls ? 1 : 0) === Number(c)))
      .map((f) => ({ ...f, listeners: f.listeners.filter((l) => String(l.port) === b && (l.tls ? 1 : 0) === Number(c)), portMap: f.portMap.filter((p) => String(p.in) === b && (p.listenerTls ? 1 : 0) === Number(c)) }));
    return { flows: keep, label: `${Number(c) ? '🔒 ' : ''}:${b} of ${a.replace(/:[\d+]+(#\d+)?$/, '')}` };
  }
  if (kind === 'r') { const keep = flows.filter((f) => f.id === sel.key.slice(2)); return { flows: keep, label: keep[0] ? (keep[0].match.type === 'default' ? 'default rule' : keep[0].match.short || keep[0].match.text) : '' }; }
  if (kind === 'p') return { flows: flows.filter((f) => f.pool.name === sel.key.slice(2)), label: sel.key.slice(2) };
  return { flows, label: '' };
}
function flowSvg(flows) {
  // three columns: listeners -> rules -> pools. One row per rule; listeners and pools are shared rows.
  const lis = []; const lisIdx = new Map(); const pools = []; const poolIdx = new Map();
  flows.forEach((f) => {
    f.listeners.filter((l) => l.port).forEach((l) => { const k = `${f.frontend}|${l.port}|${l.tls}`; if (!lisIdx.has(k)) { lisIdx.set(k, lis.length); lis.push({ k, fe: f.frontend, port: l.port, tls: l.tls }); } });
    if (!poolIdx.has(f.pool.name)) { poolIdx.set(f.pool.name, pools.length); pools.push(f); }
  });
  const RH = 62; const rows = Math.max(flows.length, lis.length, pools.length); const TOP = 30; const H = rows * RH + 36 + TOP; const W = 1080; // TOP: clear space under the column headings
  const ly = (i, n) => 20 + (n <= 1 ? (rows * RH) / 2 : (i * (rows * RH - RH)) / (n - 1)) + RH / 2 - 8;
  const clip = (t, n) => (String(t).length > n ? `${String(t).slice(0, n - 1)}…` : String(t));
  let cid = 0; const clipBox = (x, y, w, h) => { const id = `fsc${cid++}`; return { id, def: `<clipPath id="${id}"><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="7"/></clipPath>` }; };
  let out = `<svg class="flow-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Listener to rule to backend pool map" preserveAspectRatio="xMinYMin meet">`;
  out += `<text x="10" y="14" class="fs-h">LISTENERS</text><text x="360" y="14" class="fs-h">RULES &amp; URI CHANGES</text><text x="770" y="14" class="fs-h">POOLS, BACKEND IPS &amp; PORTS</text><g transform="translate(0,${TOP})">`;
  const edge = (x1, y1, x2, y2, cls, label, tip, st) => { const mx = (x1 + x2) / 2; const d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`; return `<g class="fs-eg"><title>${esc(`${tip || label || ''}${st ? `\n\nStatus: ${FLOW_ST[st.k]}. ${st.text}` : ''}`)}</title><path class="fs-e ${cls || ''} ${st ? `st-${st.k}` : ''}" d="${d}"/><path class="fs-hit" d="${d}"/>${label ? `<text class="fs-pl" x="${mx}" y="${(y1 + y2) / 2 - 4}" text-anchor="middle">${esc(label)}</text>` : ''}${st && label ? `<circle class="fs-dot st-${st.k}" cx="${mx}" cy="${(y1 + y2) / 2 + 5}" r="4.5"/>` : ''}</g>`; };
  flows.forEach((f, i) => {
    const y = ly(i, flows.length); const pi = poolIdx.get(f.pool.name); const py = ly(pi, pools.length); const st = flowStatus(f);
    f.listeners.filter((l) => l.port).forEach((l) => { const li = lisIdx.get(`${f.frontend}|${l.port}|${l.tls}`); out += edge(190, ly(li, lis.length), 360, y, f.shadowedBy ? 'dead' : '', '', `${l.tls ? 'TLS ' : ''}port ${l.port} on ${f.frontend}\n→ ${f.match.type === 'default' ? 'default rule' : f.match.text}`, st); });
    const pm = f.portMap[f.portMap.length - 1];
    const sh = (o) => (!o.length ? '?' : o.length <= 2 ? o.join('/') : `${Math.min(...o)}…${Math.max(...o)}`); // long port lists: first…last
    const label = clip(f.portMap.map((p) => `${p.in}→${sh(p.out)}`).slice(0, 2).join(' · '), 24);
    out += edge(640, y, 770, py, `${f.pool.undefined ? 'bad' : ''} ${f.shadowedBy ? 'dead' : ''} ${pm && pm.tls === 're-encrypt' && (st.k === 'config' || st.k === 'idle') ? 'enc' : ''}`, label, `${f.frontend} → ${f.pool.name}\n${f.portMap.map((p) => `${p.listenerTls ? '🔒' : ''}:${p.in} → ${p.targets.length ? p.targets.join(', ') : '?'}  (${TLS_LABEL[p.tls] || p.tls})`).join('\n')}${f.pool.undefined ? '\nBackend is not defined' : ''}`, st);
  });
  lis.forEach((l, i) => { const y = ly(i, lis.length); const c = clipBox(10, y - 15, 180, 30);
    out += `<g class="fs-pick${FLOW.sel && FLOW.sel.key === `l|${l.fe}|${l.port}|${l.tls ? 1 : 0}` ? ' sel' : ''}" data-fsel="l|${esc(l.fe)}|${esc(l.port)}|${l.tls ? 1 : 0}"><title>${esc(`${l.tls ? 'TLS ' : ''}listener :${l.port} of ${l.fe}\n${flows.filter((f) => f.frontend === l.fe && f.listeners.some((x) => x.port === l.port)).length} routing rule(s)`)}</title>${c.def}<rect class="fs-n fs-l" x="10" y="${y - 15}" width="180" height="30" rx="7"/><text class="fs-t" clip-path="url(#${c.id})" x="20" y="${y + 4}">${l.tls ? '🔒 ' : ''}:${esc(l.port)} · ${esc(clip(l.fe.replace(/:[\d+]+(#\d+)?$/, ''), 20))}</text></g>`; });
  flows.forEach((f, i) => {
    const y = ly(i, flows.length); const ex = f.example; const c = clipBox(360, y - 19, 280, 38);
    const host = f.match.hosts && f.match.hosts.length ? `${f.match.hosts[0]} ` : '';
    out += `<g class="fs-pick${FLOW.sel && FLOW.sel.key === `r|${f.id}` ? ' sel' : ''}" data-fsel="r|${esc(f.id)}"><title>${esc(f.match.text)}${ex ? `\n${ex.in} → ${ex.out}` : ''}</title>${c.def}<rect class="fs-n fs-r${f.shadowedBy ? ' dead' : ''}" x="360" y="${y - 19}" width="280" height="38" rx="7"/>
      <text class="fs-t" clip-path="url(#${c.id})" x="370" y="${y - 3}">${esc(clip(f.match.type === 'default' ? 'default (everything else)' : `${host}${f.match.short || f.match.text}`, 40))}</text>
      <text class="fs-s" clip-path="url(#${c.id})" x="370" y="${y + 12}">${f.shadowedBy ? `⚠ shadowed by rule #${f.shadowedBy}` : ex && ex.changed ? `${esc(clip(ex.in, 20))} → ${esc(clip(ex.out, 20))}` : f.chain.some((s) => s.kind === 'terminal' && s.applies === true) ? 'answers with a redirect / deny' : 'path unchanged'}</text></g>`;
  });
  pools.forEach((f, i) => {
    const y = ly(i, pools.length); const ports = [...new Set(f.portMap.flatMap((p) => p.out))].sort((a, b) => a - b);
    const hosts = [...new Set(f.members.map((m) => (m.addr.kind === 'socket' ? m.address : m.addr.host)))];
    const c = clipBox(770, y - 27, 300, 54);
    // everything lives inside the card: name, then ports, then member IPs; what does not fit is summarised as "+N"
    const fit = (list, fmt, max) => { let t = ''; let n = 0; for (const x of list) { const nx = `${t}${t ? ' ' : ''}${fmt(x)}`; if (nx.length > max - 6 && n < list.length) break; t = nx; n++; } return n < list.length ? `${t} +${list.length - n}` : t; };
    const l1 = f.pool.undefined ? `${f.pool.name} (undefined)` : f.pool.name;
    const l2 = f.pool.undefined ? 'not defined: requests get a 503' : ports.length ? fit(ports, (x) => `:${x}`, 44) : 'no ports';
    const l3 = f.pool.undefined ? '' : hosts.length ? fit(hosts, (x) => x, 44) : 'no members';
    out += `<g class="fs-pick${FLOW.sel && FLOW.sel.key === `p|${f.pool.name}` ? ' sel' : ''}" data-fsel="p|${esc(f.pool.name)}"><title>${esc(f.pool.name)}\n${esc(f.portMap.flatMap((p) => p.targets).filter((t, k, a) => a.indexOf(t) === k).join('\n'))}</title>${c.def}<rect class="fs-n fs-p${f.pool.undefined ? ' bad' : ''}" x="770" y="${y - 27}" width="300" height="54" rx="7"/>
      <text class="fs-t fs-tb" clip-path="url(#${c.id})" x="780" y="${y - 10}">${esc(clip(l1, 40))}</text>
      <text class="fs-s fs-sp" clip-path="url(#${c.id})" x="780" y="${y + 4}">${esc(l2)}</text>
      <text class="fs-s" clip-path="url(#${c.id})" x="780" y="${y + 18}">${esc(l3)}</text></g>`; });
  // <title> tooltips are slow and unreliable: carry the text in data-tip and show it with our own instant tooltip
  return `${out}</g></svg>`.replace(/<g((?: [\w-]+="[^"]*")*)><title>([\s\S]*?)<\/title>/g, (_m, attrs, t) => `<g${attrs} data-tip="${t}">`);
}

// Domain -> listener -> rule -> pool -> server:port. One card per host name.
function flowDomainsHtml(d, hap) {
  const q = FLOW.dq.trim().toLowerCase(); const rows = state.snapshot && state.snapshot.rows ? state.snapshot.rows : [];
  const KIND = { wildcard: 'wildcard', regex: 'regex', catchall: hap ? 'no host condition' : 'catch-all (_)', dynamic: 'resolved at runtime' };
  const hasRows = rows.length > 0;
  const ruleSt = (r) => (r.shadowedBy ? { k: 'dead' } : poolStatus(r.pool, r.undefined));
  const ruleOk = (r) => !FLOW.st || statusMatches(ruleSt(r).k, FLOW.st, { undef: r.undefined, shadowed: r.shadowedBy }) || (hasRows && r.servers.some((v) => serverPass(r.pool, v.name)));
  const srvOk = (r, v) => !FLOW.st || !hasRows || !r.servers.some((x) => serverPass(r.pool, x.name)) || serverPass(r.pool, v.name);
  const list = (d.domains || []).filter((m) => (!FLOW.st || m.rules.some(ruleOk)) && (!FLOW.fe || m.frontends.includes(FLOW.fe)) && (!q || `${m.name} ${m.pools.join(' ')} ${m.targets.join(' ')} ${m.rules.flatMap((r) => r.servers.map((v) => v.name)).join(' ')}`.toLowerCase().includes(q)));
  if (!list.length) return '<div class="panel"><div class="empty">No domains match</div></div>';
  const lis = (m) => m.listeners.slice().sort((a, b) => Number(a.port) - Number(b.port)).map((l) => portTxt(l.port, l.tls)).join(' ');
  const card = (m) => {
    const tags = [KIND[m.kind] ? `<span class="tag">${esc(KIND[m.kind])}</span>` : '', m.isDefault ? '<span class="tag">default server</span>' : '', m.plainOnly && m.rules.length ? '<span class="tag until" title="No TLS listener serves this name">HTTP only</span>' : '', m.local ? '<span class="tag">answers itself (no proxy_pass)</span>' : ''].filter(Boolean).join(' ');
    const rules = m.rules.filter(ruleOk).map((r) => {
      const st = r.shadowedBy ? { k: 'dead' } : poolStatus(r.pool, r.undefined);
      const srv = r.servers.length ? `<table class="grid dom-srv"><thead><tr><th>Server</th><th>Listener port → server address</th><th></th></tr></thead><tbody>${r.servers.filter((v) => srvOk(r, v)).map((v) => {
        const row = rows.find((x) => x.proxy === r.pool && x.kind === 'server' && x.name === v.name);
        return `<tr><td>${row ? stBadge(row.state, row.status) : ''} <b>${esc(v.name)}</b>${v.count > 1 ? ` <span class="muted small">×${v.count}</span>` : ''}</td>
          <td>${v.maps.map((mp) => `<span class="pt${mp.tls ? ' tls' : ''}">${mp.tls ? '🔒 ' : ''}:${esc(mp.in)}</span> → <span class="pt${v.ssl ? ' tls' : ''}">${v.ssl ? '🔒 ' : ''}${esc(mp.target)}</span>`).join('<br>')}</td>
          <td class="small">${v.backup ? '<span class="tag">backup</span> ' : ''}${v.disabled ? '<span class="tag until">disabled</span> ' : ''}${v.checkPort != null ? `<span class="muted">check :${v.checkPort}</span>` : ''}</td></tr>`; }).join('')}</tbody></table>`
        : `<div class="muted small dom-nosrv">${r.undefined ? '<span class="sev-error">Backend not defined</span>: requests get a 503' : r.dynamic ? 'Pool is chosen at runtime from a request value' : 'No servers listed'}</div>`;
      const ex = r.example && r.example.changed ? ` <span class="muted small">backend receives <code>${esc(r.example.in)}</code> → <code>${esc(r.example.out)}</code></span>` : '';
      const tlsK = [...new Set((r.tlsKinds || []).map((x) => TLS_LABEL[x.tls] || x.tls))].join(' · ');
      return `<div class="dom-rule${r.shadowedBy ? ' dim' : ''}"><div class="dom-rt">${stDot(st.k)} <span class="mono">${esc(r.text)}</span> <span class="muted">→</span> <b>${esc(r.pool)}</b> ${tlsK ? `<span class="tag">${esc(tlsK)}</span>` : ''}${r.shadowedBy ? ` <span class="tag until">shadowed by #${r.shadowedBy}</span>` : ''}${ex}</div>${srv}</div>`;
    }).join('');
    const red = (m.redirects || []).map((x) => `<div class="dom-red">↪ ${x.ports.map((p) => `<span class="pt">:${esc(p)}</span>`).join(' ')} <b>${esc(x.code)}</b> redirect to <code>${esc(x.to)}</code> <span class="muted small">(never reaches a backend)</span></div>`).join('');
    const first = m.listeners.find((l) => l.tls) || m.listeners[0];
    return `<div class="panel dom-card"><div class="dom-h"><span class="dom-n mono">${esc(m.name)}</span> ${tags}<span class="spacer"></span><span class="dom-l">${lis(m)}</span>
      <button type="button" class="btn small-btn" data-flow-dom="${esc(m.name)}|${esc(first ? first.port : '')}|${first && first.tls ? 1 : 0}" title="Trace a request for this domain">Trace</button></div>
      ${m.frontends.length ? `<div class="muted small dom-fe">${esc(lbl('frontend'))}: ${m.frontends.map(esc).join(', ')}</div>` : ''}${FLOW.st ? '' : red}${rules}</div>`;
  };
  return `<p class="muted small flow-note">One card per domain (host name): the ports it is served on, what it redirects or routes to, and for each pool every server with the address and port each listener port ends up at.</p>${list.map(card).join('')}`;
}
function flowTraceHtml() {
  const t = FLOW.trace;
  if (FLOW.traceErr) return `<div class="flow-trace"><div class="empty">${esc(FLOW.traceErr)}</div></div>`;
  if (!t) return '';
  const resp = t.response ? `<div class="ft-end bad">${t.response.status ? `<b>${t.response.status}</b> ` : ''}${esc(t.response.text)}</div>` : '';
  const members = (t.members || []).length ? `<div class="ft-end ok"><b>${esc(t.backend)}</b> ${(t.members || []).map((m) => `<span class="pt${m.tls ? ' tls' : ''}" title="${esc(m.address)}">${m.tls ? '🔒 ' : ''}${esc(m.name)} ${m.socket ? esc(m.address) : `:${m.port == null ? '?' : m.port}`}${m.checkPort != null ? ` <i>(check :${m.checkPort})</i>` : ''}${m.backup ? ' <i>backup</i>' : ''}</span>`).join(' ')}</div>` : '';
  const pathLine = t.path ? `<div class="ft-path"><span class="muted small">Backend receives</span> <code>${esc(t.path.out)}</code>${t.path.in !== t.path.out ? ` <span class="muted small">(client sent <code>${esc(t.path.in)}</code>)</span>` : ' <span class="muted small">(unchanged)</span>'}${t.path.exact === false ? ' <span class="tag" title="Depends on a dynamic value or an uncertain condition">approximate</span>' : ''}${t.hostHeader ? ` <span class="muted small">· Host header <code>${esc(t.hostHeader)}</code></span>` : ''}${t.tls ? ` <span class="tag">${esc(TLS_LABEL[t.tls] || t.tls)}</span>` : ''}</div>` : '';
  return `<div class="flow-trace">${(t.steps || []).map((s, i) => `<div class="ft-step ${s.applied === false || s.skipped ? 'off' : ''} ${esc(s.type)}"><span class="ft-n">${i + 1}</span><div><span class="ft-txt mono">${esc(s.text)}</span>${s.from != null ? ` <span class="mono small"><span class="muted">${esc(s.from)}</span> → <b>${esc(s.to)}</b></span>` : ''}${s.note ? `<div class="muted small">${esc(s.note)}</div>` : ''}</div></div>`).join('')}
    ${resp}${members}${pathLine}${t.uncertain ? '<div class="muted small">Some conditions depend on headers, source IP or other values that a host / path / port test cannot decide; they are marked as skipped above.</div>' : ''}</div>`;
}
function renderFlow() {
  const el = $('#view-flow'); if (!el) return;
  const snap = state.snapshot; if (!snap) { el.innerHTML = ''; return; }
  if (FLOW.inst !== state.current) {
    Object.assign(FLOW, { inst: state.current, data: null, err: null, key: '', trace: null, traceErr: null, fe: '', sel: null, req: { host: '', path: '/', port: '', method: 'GET' } });
    if (!FLOW.loading) setTimeout(() => flowLoad(true), 0);
  }
  const d = FLOW.data;
  const intro = `<header class="flow-head val-head"><div><h2>Request Routing</h2><p class="muted">Follow a request from the listener port to the backend port, and see exactly what the backend receives.</p></div><details class="flow-how"><summary>How to read this</summary><p class="muted small">Where each listener port leads, which pool and member port it reaches, whether TLS ends or restarts on the way, and what the backend receives as the URI. ${snap.instance.type === 'haproxy' ? 'An omitted server port follows the port the client used; <code>+N</code> adds to it; the server <code>port</code> option only moves health checks.' : 'A URI in <code>proxy_pass</code> replaces the matched location prefix.'} Everything is read from the configuration; nothing is sent to your servers.</p></details></header>`;
  if (FLOW.loading && !d) { el.innerHTML = `${intro}<div class="skeleton-cards"><i></i><i></i><i></i></div>`; return; }
  if (FLOW.err) { el.innerHTML = `${intro}<div class="panel"><div class="empty">${esc(FLOW.err)}${/no configuration/i.test(FLOW.err) ? '<br>Attach the config (Settings → edit connection) to see how traffic is mapped.' : ''}</div></div>`; return; }
  if (!d) { el.innerHTML = intro; return; }
  const ports = flowPorts(); const hap = d.product === 'haproxy';
  const fes = [...new Set(d.flows.map((f) => f.frontend))];
  const flows = d.flows.filter((f) => (!FLOW.fe || f.frontend === FLOW.fe) && flowPass(f));
  const rq = FLOW.req;
  const form = `<div class="panel flow-try"><h3 class="flow-h">Try a Request</h3>
    <div class="flow-form"><label>Host<input id="flow-host" placeholder="shop.example.com" value="${esc(rq.host)}" autocomplete="off"></label>
      <label>Path<input id="flow-path" placeholder="/api/users?id=1" value="${esc(rq.path)}" autocomplete="off"></label>
      <label>Port<select id="flow-port">${ports.map((p) => `<option value="${esc(p.port)}"${String(rq.port || ports[0].port) === String(p.port) ? ' selected' : ''}>${p.tls ? '🔒 ' : ''}${esc(p.port)}${p.tls ? ' (HTTPS)' : ''}</option>`).join('') || '<option value="">any</option>'}</select></label>
      <label>Method<select id="flow-method">${['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => `<option${rq.method === m ? ' selected' : ''}>${m}</option>`).join('')}</select></label>
      <button class="btn primary" type="button" data-flow-trace>${FLOW.tracing ? 'Tracing…' : 'Trace'}</button></div>${flowTraceHtml()}</div>`;
  const sum = d.summary;
  const stats = `<div class="panel val-sum flow-sum"><div class="val-counts"><span><b>${sum.domains}</b> domain${sum.domains === 1 ? '' : 's'}</span><span><b>${sum.listeners}</b> listener ports</span><span><b>${sum.flows}</b> routing rules</span><span><b>${sum.rewrites}</b> rewrite the URI</span><span><b class="${sum.findings ? 'sev-warning' : ''}">${sum.findings}</b> routing findings</span></div></div>`;
  const tabs = [['domains', 'Domains'], ['ports', 'Port map'], ['uri', 'URI map'], ['diagram', 'Diagram']];
  const chips = `<div class="chips flow-bar">${tabs.map(([k, t]) => `<span class="chip ${FLOW.tab === k ? 'on' : ''}" data-flow-tab="${k}">${t}</span>`).join('')}${FLOW.tab === 'domains' ? `<input id="flow-dq" type="search" placeholder="Filter domains, pools, servers, IPs…" value="${esc(FLOW.dq)}" aria-label="Filter domains" autocomplete="off">` : ''}<span class="muted">|</span><select id="flow-st" aria-label="Filter by status" title="Alive: has a healthy member. Not alive: no healthy member, or the backend is not defined. Unused: no traffic right now, or a rule that can never match. In Domains, servers are filtered one by one by their own state. Needs live stats.">${Object.entries(FLOW_STF).map(([k, t]) => `<option value="${k}"${FLOW.st === k ? ' selected' : ''}>${t}</option>`).join('')}</select>${fes.length > 1 ? `<select id="flow-fe" aria-label="Filter by ${esc(lbl('frontend').toLowerCase())}"><option value="">All ${esc(lbl('frontend').toLowerCase())}s</option>${fes.map((x) => `<option value="${esc(x)}"${FLOW.fe === x ? ' selected' : ''}>${esc(x)}</option>`).join('')}</select>` : ''}<button class="btn small-btn flow-fs" id="flow-fs" data-fs type="button" title="Fill the whole window with this tab (Esc to exit)">${document.body.classList.contains('topo-fs') ? '✕ Exit full screen' : '⛶ Full screen'}</button></div>`;
  let body = '';
  if (FLOW.tab === 'domains') body = flowDomainsHtml(d, hap);
  else if (FLOW.tab === 'ports') {
    const rows = d.portMatrix.filter((r) => (!FLOW.fe || r.frontend === FLOW.fe) && (() => { const st = poolStatus(r.pool, r.undefined); return statusMatches(st.k, FLOW.st, { undef: r.undefined }); })());
    body = `<div class="table-wrap"><table class="grid"><thead><tr><th>Listener</th><th>${esc(lbl('frontend'))}</th><th>→ ${esc(lbl('backend'))}</th><th>Backend address(es)</th><th>Status</th><th>Layer</th><th>What happens to the connection</th><th class="num">Rules</th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td>${portTxt(r.listener, r.listenerTls)}</td><td><b>${esc(r.frontend)}</b></td><td>${r.undefined ? `<span class="sev-error">${esc(r.pool)} (undefined)</span>` : esc(r.pool)} <span class="muted small">${r.members} member${r.members === 1 ? '' : 's'}</span></td><td>${outPorts(r) || '<span class="muted">–</span>'}</td><td>${(() => { const st = poolStatus(r.pool, r.undefined); return `<span class="st-chip" title="${esc(st.text)}">${stDot(st.k)} ${esc(FLOW_ST[st.k])}</span>`; })()}</td><td><span class="tag layer-${r.mode === 'tcp' ? 'l4' : 'l7'}">${r.mode === 'tcp' ? 'L4' : 'L7'}</span></td><td><span class="tag tls-${esc(r.tls)}">${esc(TLS_LABEL[r.tls] || r.tls)}</span></td><td class="num">${r.rules}</td></tr>`).join('') || `<tr><td colspan="8" class="empty">${FLOW.st ? 'Nothing matches the status filter' : 'No listeners found'}</td></tr>`}</tbody></table></div>
      <p class="muted small flow-note">${hap ? 'HAProxy: <code>server s 10.0.0.1</code> (no port) uses the same port the client connected to; <code>10.0.0.1:+1000</code> adds 1000 to it; an explicit port always wins.' : snapshotType() === 'nginx' ? 'NGINX: a <code>proxy_pass</code> or upstream <code>server</code> without a port uses 80 (443 for https://).' : `${esc(TYPE_NAME[snapshotType()] || '')}: an upstream address without a port uses 80 (443 for https://). Rules are listed in the order ${esc(TYPE_NAME[snapshotType()] || '')} evaluates them${snapshotType() === 'traefik' ? ' (highest priority first; by default the longest rule)' : snapshotType() === 'caddy' ? ' (directive order, then matcher specificity inside handle blocks)' : ' (first match wins)'}.`}</p>`;
  } else if (FLOW.tab === 'uri') {
    body = `<div class="table-wrap"><table class="grid"><thead><tr><th>${esc(lbl('frontend'))}</th><th>Host</th><th>Request matches</th><th>URI changes on the way</th><th>Example</th><th>→ ${esc(lbl('backend'))}</th></tr></thead><tbody>
      ${flows.map((f) => { const steps = f.chain.filter((s) => s.applies !== false && (s.kind === 'path' || (s.kind === 'header' && /^Host$/i.test(s.args[0] || '')))); const other = f.chain.filter((s) => s.applies !== false && s.kind === 'terminal').length; const ex = f.example;
      return `<tr class="${f.shadowedBy ? 'dim' : ''}"><td><b>${esc(f.frontend)}</b><div class="muted small mono">${f.listeners.map((l) => `${l.tls ? '🔒' : ''}${esc(l.port || 'socket')}`).join(', ')}</div></td>
        <td class="mono small">${esc((f.match.hosts || []).join(', ')) || '<span class="muted">any</span>'}</td>
        <td class="msg">${f.match.type === 'default' ? '<span class="tag">default</span> <span class="muted">everything else</span>' : `<span class="mono">${esc(f.match.text)}</span>`}${f.shadowedBy ? ` <span class="tag until">shadowed by #${f.shadowedBy}</span>` : ''}</td>
        <td class="msg">${f.mode === 'tcp' ? '<span class="tag layer-l4">L4</span> <span class="muted">TCP: paths and headers are never seen, so there is nothing to rewrite</span>' : ''}${f.mode !== 'tcp' && steps.length ? steps.map((s) => `<div class="mono small" title="${esc(s.condText || s.note || '')}"><span class="tag">${esc(s.stage || s.scope)}</span> ${esc(s.text)}${s.cond ? ` <span class="muted">${esc(s.cond)}</span>` : ''}${s.applies === null ? ' <span class="tag" title="Depends on something a host / path test cannot decide">maybe</span>' : ''}${s.note ? `<div class="muted">${esc(s.note)}</div>` : ''}</div>`).join('') : (f.mode === 'tcp' ? '' : '<span class="muted">none: the backend gets the same URI</span>')}${other ? `<div class="muted small">+ ${other} redirect / deny / auth rule${other === 1 ? '' : 's'} that may answer before this (use Try a request)</div>` : ''}</td>
        <td class="mono small">${ex ? (ex.changed ? `${esc(ex.in)} → <b>${esc(ex.out)}</b>${ex.exact ? '' : ' <span class="tag">approx.</span>'}` : `${esc(ex.in)} <span class="muted">unchanged</span>`) : '<span class="muted">–</span>'}</td>
        <td><b>${esc(f.pool.name)}</b><div class="mono small">${f.portMap.map((p) => `${esc(p.in)}→${p.out.length ? p.out.join('/') : '?'}`).join(' · ')}</div></td></tr>`; }).join('') || `<tr><td colspan="6" class="empty">${FLOW.st ? 'Nothing matches the status filter' : 'No routing rules'}</td></tr>`}</tbody></table></div>`;
  } else {
    const sv = flowNarrow(flows);
    body = `<div class="panel flow-diagram">${FLOW.sel && sv.label ? `<div class="flow-selbar">Showing only the relationships of <b>${esc(sv.label)}</b> <span class="muted small">(${sv.flows.length} rule${sv.flows.length === 1 ? '' : 's'})</span><span class="spacer"></span><button type="button" class="btn small-btn" data-flow-clear>Show all</button></div>` : ''}${sv.flows.length ? flowSvg(sv.flows) : `<div class="empty">${FLOW.st ? 'Nothing matches the status filter' : 'No routing rules'}</div>`}<p class="muted small flow-note">Click a listener, rule or pool to see only its relationships. Lines carry <code>listener→backend</code> ports. Line colour shows whether the relationship is live: <span class="st-dot st-active"></span> active (moving dashes, traffic now) <span class="st-dot st-idle"></span> idle <span class="st-dot st-down"></span> down (no healthy member) <span class="st-dot st-dead"></span> never used (shadowed rule or undefined backend) <span class="st-dot st-config"></span> configured (no runtime data). Traffic is counted per pool, so rules that share a pool share its status.</p></div>`;
  }
  const finds = d.findings.filter((f) => !FLOW.fe || flows.some((x) => x.frontend === FLOW.fe && (f.section === x.frontend || f.section === x.pool.name)));
  const card = (f) => `<div class="finding ${esc(f.severity)}"><div class="ft"><span class="sev-${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span> · ${esc(f.title)}</div><div class="fm">${esc(f.detail || '')} ${f.line ? `<a ${loc(f)}>${esc(f.section || '')}:${f.line}</a>` : ''}</div>${f.fix ? `<div class="fx"><b>Fix</b> ${esc(f.fix)}</div>` : ''}</div>`;
  el.innerHTML = `${intro}${form}${stats}${chips}${body}${finds.length ? `<div class="flow-finds"><h3 class="flow-h flow-fh">Routing Findings</h3>${finds.map(card).join('')}</div>` : ''}`;
}

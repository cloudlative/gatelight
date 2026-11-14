'use strict';
/* GateLight UI: state, helpers, formatting, navigation, data loading, charts, process facts. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
/* HAGateLight UI. No inline handlers (strict CSP); every dynamic string passes through esc(). */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = {
  instances: [], current: null, snapshot: null, events: [], view: 'overview',
  series: [], timer: null, sort: { key: 'default', desc: false }, analysis: null,
  inspected: null, cfgFilter: '', eventFilter: 'all',
  meta: { features: { haproxy: true, nginx: true, apache: true, caddy: true, traefik: true }, types: [] }, cfgFile: null, focus: null, mode: 'landing',
  hiddenTypes: loadPref('gatelight.hiddenTypes', []),
};
function loadPref(k, d) { try { const v = JSON.parse(localStorage.getItem(k)); return v == null ? d : v; } catch { return d; } }
function savePref(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } }
const TYPE_NAME = { haproxy: 'HAProxy', nginx: 'NGINX', apache: 'Apache', caddy: 'Caddy', traefik: 'Traefik' };
const ALL_TYPES = ['haproxy', 'nginx', 'apache', 'caddy', 'traefik'];
const TYPE_ABBR = { haproxy: 'HA', nginx: 'NG', apache: 'AP', caddy: 'CA', traefik: 'TR' };
const DEFAULT_FILE = { haproxy: 'haproxy.cfg', nginx: 'nginx.conf', apache: 'httpd.conf', caddy: 'Caddyfile', traefik: 'traefik.yml' };
/** Products this server can handle (module installed and switched on). */
const availableTypes = () => (state.meta && state.meta.products ? state.meta.products.map((p) => p.type) : ['haproxy', 'nginx']);
const productInfo = (t) => (state.meta && state.meta.products || []).find((p) => p.type === t) || null;
const labelsOf = (t) => (productInfo(t) && productInfo(t).labels) || (t === 'nginx' ? { frontend: 'Server block', backend: 'Upstream', server: 'Peer' } : { frontend: 'Frontend', backend: 'Backend', server: 'Server' });
const proxyList = () => { const n = availableTypes().map((t) => TYPE_NAME[t]); return n.length > 1 ? `${n.slice(0, -1).join(', ')} or ${n[n.length - 1]}` : n[0]; };
/** Hide choices for products this server does not have. */
function syncTypeOptions() { const on = new Set(availableTypes()); $$('[data-type-opt]').forEach((el) => { el.hidden = !on.has(el.dataset.typeOpt); }); }
const labels = () => (state.snapshot && state.snapshot.instance.labels) || { frontend: 'Frontend', backend: 'Backend', server: 'Server' };
const lbl = (kind) => labels()[kind] || kind;

// ---------- formatting ----------
const fmtInt = (n) => (n == null ? '–' : Math.round(n).toLocaleString());
const fmtRate = (n) => (n == null ? '–' : n >= 100 ? Math.round(n).toLocaleString() : n.toFixed(n < 10 ? 2 : 1));
function fmtBytes(b) {
  if (b == null) return '–';
  if (b < 1024) return `${b < 10 ? +b.toFixed(1) : Math.round(b)} B`;
  const u = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let i = -1; let v = b;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  return `${v.toFixed(v < 10 ? 2 : 1)} ${u[i]}`;
}
function fmtDur(sec) {
  if (sec == null || sec < 0) return '–';
  const d = Math.floor(sec / 86400); const h = Math.floor((sec % 86400) / 3600); const m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${Math.floor(sec % 60)}s` : `${Math.floor(sec)}s`;
}
const fmtTime = (ts) => new Date(ts).toLocaleTimeString();
const fmtDateTime = (ts) => new Date(ts).toLocaleString();
const stBadge = (s, raw) => `<span class="st st-${esc(s || 'unknown')}">${esc(raw || s || 'unknown')}</span>`;

async function api(path, opts) {
  const res = await fetch(`/api${path}`, opts);
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON */ }
  if (res.status === 401 && !location.pathname.startsWith('/login')) { // session expired or never signed in
    location.replace(`/login?next=${encodeURIComponent(location.pathname)}${location.hash}`);
    throw new Error('Signing in again…');
  }
  if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
  return body;
}
async function signOut() {
  try { await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch { /* leave anyway */ }
  try { sessionStorage.clear(); } catch { /* storage unavailable */ }
  location.replace('/login');
}

// ---------- derived model ----------
const isProblem = (r) => r.state === 'down' || r.state === 'degraded' || (r.kind === 'backend' && r.state !== 'up' && r.state !== 'maint');
function indexRows(rows) {
  const m = new Map();
  for (const r of rows) m.set(`${r.proxy}/${r.name}`, r);
  return m;
}
const cfgSections = () => (state.snapshot ? state.snapshot.config.sections : []);
const snapshotType = () => (state.snapshot ? state.snapshot.instance.type : 'haproxy');
const feLike = (s) => s.type === 'frontend' || s.type === 'listen';
/** A route the proxy answers itself (redirect, fixed response, Traefik's api@internal / ping@internal ...): no pool behind it. */
const selfAnswered = (rt) => Boolean(rt && (rt.terminal || rt.target == null || /@internal$/.test(String(rt.target))));
const selfLabel = (rt) => { const t = (rt.transforms || []).find((x) => ['redirect', 'return', 'respond', 'static', 'deny'].includes(x.action)); return t ? (t.text || t.action) : rt.target ? String(rt.target) : 'answered by the proxy'; };
const beLike = (s) => s.type === 'backend' || s.type === 'listen';

// ---------- filters reset when you navigate ----------
// Filters belong to the page you are looking at: leaving a page (or switching instance) clears them, so coming back never
// shows a half-filtered list. Pages opened from a link that sets a filter keep it, because only the page being left is reset.
const FILTER_RESETS = {
  topology() { const q = $('#topo-search'); if (q) q.value = ''; const p = $('#topo-problems'); if (p) p.checked = false; const l = $('#topo-layer'); if (l) { l.value = ''; l.dataset.sig = ''; } const u = $('#topo-urls'); if (u) u.checked = true; state.focus = null; state.topoFor = null; const t = $('#topo-sel'); if (t) { t.hidden = true; t.innerHTML = ''; } },
  services() { for (const id of ['svc-search', 'svc-kind', 'svc-state']) { const e = $(`#${id}`); if (e) e.value = ''; } state.sort = { key: 'default', desc: false }; },
  graphs() { gr.q = ''; gr.pool = ''; gr.focus.clear(); gr.sig = ''; gr.from = gr.to = null; gr.metric = 'rate'; const m = $('#gr-metric'); if (m) m.value = 'rate'; const e = $('#gr-search'); if (e) e.value = ''; const pl = $('#gr-pool'); if (pl) pl.value = ''; },
  config() { const e = $('#cfg-search'); if (e) e.value = ''; state.cfgFilter = ''; cfgRendered = null; },
  events() { state.eventFilter = 'all'; },
  forge() { if (typeof FG !== 'undefined') { FG.cat = 'all'; FG.sev = 'all'; FG.kind = 'all'; } },
  traffic() { if (typeof trResetFilters === 'function') trResetFilters(); },
  flow() { FLOW.fe = ''; FLOW.st = ''; FLOW.dq = ''; FLOW.sel = null; FLOW.trace = null; FLOW.traceErr = null; FLOW.req = { host: '', path: '/', port: '', method: 'GET' }; },
};
function resetFilters(view) { try { const f = FILTER_RESETS[view]; if (f) f(); } catch { /* a missing element must never break navigation */ } }
const resetAllFilters = () => Object.keys(FILTER_RESETS).forEach(resetFilters);

// ---------- navigation ----------
let navReady = false; let navFromHistory = false; // push history entries only after start-up, and never while replaying one
const REVIEW_VIEWS = ['topology', 'flow', 'forge', 'builder', 'config'];
const visibleNav = () => $$('#nav button').filter((b) => !b.hidden && b.offsetParent !== null);
const VIEW_ALIAS = { audit: 'forge', validate: 'forge' }; // old links keep working
function switchView(view) {
  if (view === 'infrastructure' || view === 'lbinfra') { const l = $('#topo-layout'); if (l && l.value !== 'network') { l.value = 'network'; if (network) { network.destroy(); network = null; } } view = 'topology'; } // Infrastructure is now a Topology layout
  view = VIEW_ALIAS[view] || view;
  if (view === 'graphs' && state.mode === 'live' && state.snapshot && state.snapshot.instance && state.snapshot.instance.source === 'config-only') view = 'traffic'; // no live statistics: the log is the traffic page
  if (state.mode === 'review' && !REVIEW_VIEWS.includes(view)) view = 'topology';
  if (state.mode === 'live' && !state.snapshot && !state.current && !['overview', 'connect', 'settings', 'forge', 'builder'].includes(view)) view = 'overview';
  if (state.view !== view) resetFilters(state.view); // leaving a page clears its filters
  if (state.view === 'connect' && view !== 'connect') mountConnect(false);
  if (view === 'connect' && state.view !== 'connect') mountConnect(true);
  if (state.view !== view && document.body.classList.contains('topo-fs')) setTopoFs(false);
  if (view === 'detail' && !state.inspected) view = (state.detailFrom && state.detailFrom !== 'detail') ? state.detailFrom : 'overview';
  if (state.view === 'detail' && view !== 'detail') state.inspected = null;
  state.view = view;
  if (view === 'flow' || view === 'topology') setTimeout(() => flowLoad(false), 0);
  if (view === 'traffic') setTimeout(() => trLoad(false), 0);
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${view}`));
  $$('#nav button').forEach((b) => { const on = b.dataset.view === view || (b.dataset.alt || '').split(' ').includes(view); b.classList.toggle('active', on); if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  const dkey = view === 'detail' && state.inspected && state.inspected.key ? `/${encodeURIComponent(state.inspected.key)}` : '';
  const want = state.current && state.current !== '__analysis' && !['settings'].includes(view) ? `#${state.current}/${view}${dkey}` : `#${view}`;
  // Each page the user opens is a real history entry, so the browser's Back/Forward move between pages of the app
  // instead of leaving it. Entries are not added while loading, or while replaying history itself.
  state.detailPushed = false;
  if (location.hash !== want) { if (navReady && !navFromHistory) { history.pushState({ v: view }, '', want); state.detailPushed = view === 'detail'; } else history.replaceState({ v: view }, '', want); }
  renderView(view);
  if (view === 'topology' && network) setTimeout(() => network.fit({ animation: false }), 60);
}
// The "add instance" forms (connect + review a config) live on the start screen first-run, and inside the dashboard as a normal page.
function mountConnect(on) {
  const grid = $('.lp-grid'); const target = on ? $('#connect-slot') : $('#landing .lp-wrap');
  if (grid && target && grid.parentElement !== target) target.appendChild(grid);
  if (on) renderLanding();
}
// First run / nothing connected yet: the Overview itself guides the user (there is no separate start page).
function renderWelcome() {
  const can = state.meta && state.meta.canManage;
  $('#view-overview').innerHTML = `<div class="welcome">
    <img class="welcome-mark" src="logo.svg" alt="" width="64" height="64">
    <h2>Welcome to GateLight</h2>
    <p class="muted welcome-lead">See your ${esc(proxyList())} as a map. Nothing is connected yet, so here is how to start:</p>
    <ol class="welcome-steps">
      <li><span class="n">1</span><div><b>Add your first instance</b><p class="muted">Connect a running ${esc(proxyList())} (URL, user, password), or upload its config and keep it under a name.</p>
        ${can ? '<button class="btn primary" type="button" data-goto="connect">Add an Instance</button>' : '<p class="muted small">Adding from the browser is off. Define servers in <code>config/instances.json</code>, or start GateLight with <code>ALLOW_UI_INSTANCES=true</code>.</p>'}</div></li>
      <li><span class="n">2</span><div><b>Only want to check a config?</b><p class="muted">Drop a file or folder and get the map and audit. Nothing is saved.</p>
        <button class="btn" type="button" data-goto="connect">Review a config</button></div></li>
      <li><span class="n">3</span><div><b>Then explore</b><p class="muted">The overview, topology, URL map, services, audit and events appear here as soon as there is an instance to show.</p></div></li>
    </ol>
    <p class="muted small">Just looking around? Try an example: ${availableTypes().map((t) => `<button class="link" type="button" data-example="${t}">${TYPE_NAME[t]}</button>`).join(' · ')} · or <button class="link" type="button" data-goto="builder">build a new config</button></p>
  </div>`;
}
function renderView(view) {
  if (view === 'connect') return;
  if (view === 'settings') { renderSettings(); return; }
  if (view === 'forge') { renderForge(); return; } // works without an instance: paste or upload any config
  if (view === 'builder') { renderBuilder(); return; } // works without an instance: writes a new config
  if (!state.snapshot) {
    if (view === 'overview') { if (state.current) $('#view-overview').innerHTML = '<div class="skeleton-cards"><i></i><i></i><i></i><i></i><i></i></div>'; else renderWelcome(); }
    return;
  }
  ({ fleet: renderFleet, settings: renderSettings, overview: renderOverview, topology: renderTopology, graphs: renderGraphs, profile: renderProfile, detail: () => { if (state.inspected) refreshInspector(); }, services: renderServices, forge: () => renderForge(), flow: renderFlow, traffic: () => renderTraffic(), events: renderEvents, config: renderConfig }[view] || (() => {}))();
}

// ---------- data loading ----------
async function loadInstances() {
  try { state.meta = await api('/meta'); } catch { /* keep defaults */ }
  syncTypeOptions();
  $$('[data-logout]').forEach((b) => { b.hidden = !(state.meta && state.meta.authUser); });
  { const u = state.meta && state.meta.authUser ? String(state.meta.authUser) : ''; const nu = $('#navuser'); nu.hidden = !u; $('#nu-name').textContent = u; $('#nu-av').textContent = (u[0] || '').toUpperCase(); $('#nu-name').title = u; }
  const { instances } = await api('/instances');
  state.instances = instances;
  const visible = instances.filter((i) => !state.hiddenTypes.includes(i.type));
  const sel = $('#instance-select');
  const keep = state.current;
  const opt = (i) => `<option value="${esc(i.id)}">${esc(i.name)}${i.serversDown ? ` ⚠ ${i.serversDown} down` : ''}</option>`;
  const groups = ALL_TYPES.map((t) => ({ t, list: visible.filter((i) => i.type === t) })).filter((g) => g.list.length);
  sel.innerHTML = (groups.length > 1 ? groups.map((g) => `<optgroup label="${TYPE_NAME[g.t]}">${g.list.map(opt).join('')}</optgroup>`).join('') : visible.map(opt).join(''))
    + (state.analysis ? '<option value="__analysis">📄 Uploaded analysis</option>' : '');
  $('#nav [data-view="fleet"]').hidden = visible.length < 2;
  $('#btn-connect').hidden = !(state.meta && state.meta.canManage);
  { const nb = $('#nav [data-view=connect] span'); if (nb) nb.textContent = state.meta && state.meta.canManage ? 'Add Instance' : 'Review a Config'; }
  if (!visible.length && !state.analysis) return false;
  state.current = keep && [...sel.options].some((o) => o.value === keep) ? keep : (visible[0] || { id: '__analysis' }).id;
  sel.value = state.current;
  iselSync();
  return true;
}

function setBusy(on) { for (const b of [$('#btn-refresh'), $('#gr-refresh')]) { if (!b) continue; b.disabled = on; b.classList.toggle('spin', on); b.textContent = on ? 'Refreshing…' : 'Refresh'; } }
async function poll(force = false) {
  if (state.current === '__analysis') return;
  if (force) setBusy(true);
  try {
    if (force) await api(`/instances/${encodeURIComponent(state.current)}/refresh`, { method: 'POST' });
    const [snap, ev] = await Promise.all([
      api(`/instances/${encodeURIComponent(state.current)}/snapshot`),
      api(`/instances/${encodeURIComponent(state.current)}/events?limit=300`),
    ]);
    state.events = ev.events;
    // Settings/Fleet read state.instances, which was fetched once: refresh it so a one-off failed poll (e.g. DNS right after a restart) does not stay on screen.
    if (['settings', 'fleet'].includes(state.view)) { try { state.instances = (await api('/instances')).instances; } catch { /* keep previous */ } }
    else { const me = state.instances.find((i) => i.id === state.current); if (me) { me.ok = snap.ok; me.error = snap.error; } }
    applySnapshot(snap);
  } catch (e) {
    setConn('bad', 'API unreachable');
    showBanner(`Cannot reach GateLight API: ${e.message}`);
  } finally { if (force) setBusy(false); }
}

function applySnapshot(snap) {
  document.body.classList.remove('no-instance');
  const prevTs = state.snapshot && state.snapshot.ts;
  state.snapshot = snap;
  if (snap.ts !== prevTs && snap.ok) {
    state.series.push({ t: snap.ts, rate: snap.summary.ratePerSec, srate: snap.summary.sessionRatePerSec || 0, sess: snap.summary.sessions, e5: snap.summary.err5xxPerSec });
    if (state.series.length > 360) state.series.shift();
  }
  const src = snap.instance.source;
  if (!snap.ok && src !== 'config-only') { setConn('bad', snap.stale ? 'stats unreachable (stale)' : 'stats unreachable'); showBanner(`Stats endpoint error: ${snap.error}${snap.stale ? ' — showing last known data' : ''}`); }
  else if (src === 'config-only') { setConn('warn', 'config only'); showBanner(snap.error, 'info'); }
  else if (src === 'demo') { setConn('warn', 'demo data'); showBanner('Demo mode: traffic is synthetic, generated from the bundled example configuration.', 'info'); }
  else if (src === 'tcp-probe') { setConn('warn', 'probe only'); showBanner('Health comes from GateLight TCP-probing each upstream (reachability from this host). Add stub_status or the NGINX Plus API for traffic counters.', 'info'); }
  else { setConn('ok', src.includes('stub') && !src.includes('plus') ? 'live (stub_status)' : 'live'); showBanner(snap.warnings && snap.warnings.length ? `Partial data: ${snap.warnings.join('; ')}` : null, 'info'); }
  { const mi = state.instances.find((i) => i.id === state.current); $('#btn-cfgup').hidden = !(mi && mi.managed); }
  $('#last-update').textContent = `updated ${fmtTime(snap.ts)}${refreshSetting() === 'off' ? ' · paused' : ''}`;
  const down = snap.summary.servers.down + snap.summary.backends.down;
  const nd = $('#nav-down'); nd.hidden = !down; nd.textContent = down;
  const na = $('#nav-audit'); const af = snap.findingsSummary; na.hidden = !(af.error + af.warning); na.textContent = af.error + af.warning; na.title = 'Audit errors and warnings. Config Doctor also lists rewrite and validation checks, so its total is higher.';
  iselSync();
  renderView(state.view);
  if (state.inspected) refreshInspector();
  cvRender();
  if (cv.source === 'row' && !$('#chartview').hidden) cvLoadRow();
}

function setConn(kind, text) { const p = $('#conn-pill'); p.className = `pill pill-${kind === 'ok' ? 'ok' : kind === 'bad' ? 'bad' : 'warn'}`; p.textContent = text; }
function showBanner(msg, kind) {
  const b = $('#banner');
  b.hidden = !msg; b.textContent = msg || ''; b.className = `banner${kind === 'info' ? ' info' : ''}`;
}

// Auto-refresh: 'auto' follows the server poll interval, a number is milliseconds, 'off' pauses (Refresh still works).
function refreshSetting() { try { return localStorage.getItem('gatelight.refresh') || 'auto'; } catch { return 'auto'; } }
function schedule() {
  clearTimeout(state.timer);
  const pref = refreshSetting();
  for (const sel of [$('#refresh-every'), $('#gr-refresh-every')]) if (sel && sel.value !== pref) sel.value = pref;
  const lu = $('#last-update'); lu.classList.toggle('paused', pref === 'off');
  lu.textContent = lu.textContent.replace(/ · paused$/, '') + (pref === 'off' && lu.textContent ? ' · paused' : '');
  if (pref === 'off') return;
  const every = pref === 'auto' ? Math.max(2000, (state.snapshot && state.snapshot.pollIntervalMs) || 5000) : Number(pref);
  state.timer = setTimeout(async () => { if (!document.hidden) await poll(); schedule(); }, every);
}

// ---------- charts ----------
function sparkSvg(values, { w = 80, h = 20, color = '#22d3ee' } = {}) {
  if (!values || values.length < 2) return '';
  const max = Math.max(...values, 0.0001);
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * w).toFixed(1)},${(h - 1 - (v / max) * (h - 3)).toFixed(1)}`).join(' ');
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline fill="none" stroke="${color}" stroke-width="1.3" points="${pts}"/></svg>`;
}

const legendHidden = new Map(); // canvas id -> Set of series keys switched off by clicking the legend
function legendAt(canvas, ev) {
  const r = canvas.getBoundingClientRect(); const px = ev.clientX - r.left; const py = ev.clientY - r.top;
  const hit = (canvas._legend || []).find((b) => px >= b.x0 && px <= b.x1 && py >= b.y0 && py <= b.y1);
  return hit ? hit.k : null;
}
function legendClick(canvas, k, multi) {
  const all = (canvas._chart ? canvas._chart.series : []).map((q) => q.k); if (all.length < 2) return;
  let h = legendHidden.get(canvas.id) || new Set();
  if (multi) { if (h.has(k)) h.delete(k); else if (all.length - h.size > 1) h.add(k); } // Ctrl/⌘/Shift-click: switch one series on or off
  else { const only = all.length - h.size === 1 && !h.has(k); h = only ? new Set() : new Set(all.filter((x) => x !== k)); } // click: show only this series; click again: show all
  legendHidden.set(canvas.id, h); paintChart(canvas);
}
const chartHover = new Map(); // canvas id -> hovered timestamp; survives re-renders that replace the canvas
function drawChart(canvas, times, series, domain = null) {
  const prev = canvas._chart && canvas._chart.domain;
  canvas._chart = { times, series, domain };
  if (!canvas._bound) {
    canvas._bound = true;
    const at = (ev) => {
      const c = canvas._chart; if (!c || !c.times.length) return null;
      const r = canvas.getBoundingClientRect(); const px = ev.clientX - r.left;
      const pb = canvas._plot || { l: 6, r: 6 }; const t0 = c.domain ? c.domain[0] : c.times[0]; const t1 = c.domain ? c.domain[1] : (c.times[c.times.length - 1] || t0 + 1);
      const t = t0 + ((px - pb.l) / Math.max(1, r.width - pb.l - pb.r)) * Math.max(1, t1 - t0);
      let best = 0; for (let i = 1; i < c.times.length; i++) if (Math.abs(c.times[i] - t) < Math.abs(c.times[best] - t)) best = i;
      return c.times[best];
    };
    canvas.addEventListener('pointermove', (ev) => { canvas.style.cursor = canvas.id !== 'cv-canvas' && legendAt(canvas, ev) ? 'pointer' : ''; const t = at(ev); if (t != null) { chartHover.set(canvas.id, t); paintChart(canvas); } });
    canvas.addEventListener('click', (ev) => { if (canvas.id === 'cv-canvas') return; const k = legendAt(canvas, ev); if (k != null) legendClick(canvas, k, ev.ctrlKey || ev.metaKey || ev.shiftKey); });
    canvas.addEventListener('pointerleave', () => { chartHover.delete(canvas.id); paintChart(canvas); });
  }
  cancelAnimationFrame(canvas._raf);
  // a big change of the window (zoom, range, step) glides to its new place; small live ticks just slide
  if (domain && prev && !canvas._sel && !document.hidden && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const sp = domain[1] - domain[0];
    if (Math.abs(prev[0] - domain[0]) + Math.abs(prev[1] - domain[1]) > sp * 0.08) {
      const from = [...prev]; const to = [...domain]; const started = performance.now();
      const frame = (now) => {
        const k = Math.min(1, (now - started) / 280); const e = 1 - (1 - k) ** 3;
        if (canvas._chart) canvas._chart.domain = [from[0] + (to[0] - from[0]) * e, from[1] + (to[1] - from[1]) * e];
        paintChart(canvas);
        if (k < 1) canvas._raf = requestAnimationFrame(frame);
      };
      canvas._raf = requestAnimationFrame(frame); return;
    }
  }
  paintChart(canvas);
}

function paintChart(canvas) {
  const { times, series: allSeries, domain } = canvas._chart;
  const hid = canvas.id === 'cv-canvas' ? null : legendHidden.get(canvas.id);
  const series = hid && hid.size && allSeries.some((q) => !hid.has(q.k)) ? allSeries.filter((q) => !hid.has(q.k)) : allSeries; // legend clicks hide series
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth; const H = canvas.clientHeight;
  canvas.width = W * dpr; canvas.height = H * dpr;
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const small = H < 130;
  const pad = { l: 6, r: 8, t: canvas._noLegend ? 8 : 20, b: 18 };
  if (!times.length) { ctx.fillStyle = '#64748b'; ctx.font = '11px system-ui'; ctx.fillText('collecting data…', 10, H / 2); return; }
  if (times.length < 2) { ctx.fillStyle = '#64748b'; ctx.font = '11px system-ui'; ctx.fillText('collecting data… the line appears after the second sample', 10, H / 2); }
  const t0 = domain ? domain[0] : times[0]; const t1 = domain ? domain[1] : (times[times.length - 1] || t0 + 1);
  const css = (n, d) => cssVar(n) || d;
  const gridCol = css('--line', '#243049'); const txtCol = css('--muted', '#8b97ad');
  // y axis: one shared scale when the series share a unit (labels + grid), otherwise each series is normalised to its own peak
  const f0 = series[0] && series[0].fmt;
  const shared = series.length === 1 || (series.length > 1 && f0 && series.every((q) => q.fmt === f0));
  const niceMax = (m) => { if (!(m > 0)) return 1; const e = 10 ** Math.floor(Math.log10(m)); const f = m / e; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * e; };
  const rawMax = (q) => Math.max(...q.values, q.minMax || 0.0001, q.max || 0);
  const sharedMax = shared ? (series.some((q) => q.max) ? Math.max(...series.map(rawMax)) : niceMax(Math.max(...series.map(rawMax)))) : 0;
  const ticks = small ? 2 : 4;
  ctx.font = '10px system-ui';
  const yLabel = (v) => ((series[0] && series[0].fmt) || fmtRate)(v);
  if (shared) pad.l = Math.max(30, Math.ceil(Math.max(...Array.from({ length: ticks + 1 }, (_, k) => ctx.measureText(yLabel((sharedMax * k) / ticks)).width)) + 12));
  canvas._plot = { l: pad.l, r: pad.r };
  const pw = Math.max(1, W - pad.l - pad.r); const ph = Math.max(1, H - pad.t - pad.b);
  const x = (t) => pad.l + ((t - t0) / Math.max(1, t1 - t0)) * pw;
  // horizontal grid (+ value labels)
  ctx.lineWidth = 1; ctx.textBaseline = 'middle'; ctx.textAlign = 'right';
  for (let k = 0; k <= ticks; k++) {
    const gy = Math.round(pad.t + ph - (k / ticks) * ph) + .5;
    ctx.strokeStyle = gridCol; ctx.globalAlpha = k ? .55 : 1; ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(W - pad.r, gy); ctx.stroke(); ctx.globalAlpha = 1;
    if (shared) { ctx.fillStyle = txtCol; ctx.fillText(yLabel((sharedMax * k) / ticks), pad.l - 6, gy); }
  }
  ctx.textAlign = 'left';
  // x axis: "nice" time ticks that move with the window
  const span = Math.max(1, t1 - t0);
  const STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800].map((v) => v * 1000);
  const want = Math.max(2, Math.floor(pw / 86)); const step = STEPS.find((v) => span / v <= want) || STEPS[STEPS.length - 1];
  const off = new Date(t0).getTimezoneOffset() * 60000;
  const dayOf = (t) => new Date(t).toDateString();
  ctx.textBaseline = 'alphabetic'; ctx.textAlign = 'center';
  for (let t = Math.ceil((t0 + off) / step) * step - off; t <= t1; t += step) {
    const gx = Math.round(x(t)) + .5; if (gx < pad.l + 14 || gx > W - pad.r - 40) continue; // keep the label inside the canvas
    ctx.strokeStyle = gridCol; ctx.globalAlpha = .35; ctx.beginPath(); ctx.moveTo(gx, pad.t); ctx.lineTo(gx, pad.t + ph); ctx.stroke(); ctx.globalAlpha = 1;
    const d = new Date(t); const midnight = d.getHours() === 0 && d.getMinutes() === 0 && d.getSeconds() === 0;
    const label = step < 60000 ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : (midnight || span > 36 * 3600e3) ? d.toLocaleString([], { month: 'short', day: 'numeric', hour: step >= 86400000 ? undefined : '2-digit', minute: step >= 86400000 ? undefined : '2-digit' }) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    ctx.fillStyle = txtCol; ctx.fillText(label, gx, H - 4);
  }
  void dayOf; ctx.textAlign = 'left';
  // series: area fill, then the line. Gaps in the data (no samples for a while) break the line instead of joining across it.
  let lx = pad.l; const scales = [];
  const dts = []; for (let i = 1; i < times.length; i++) dts.push(times[i] - times[i - 1]);
  const med = dts.length ? [...dts].sort((u, v) => u - v)[Math.floor(dts.length / 2)] : 0;
  const gap = Math.max(med * 3, 15000);
  const segs = []; let cur = [];
  times.forEach((t, i) => { if (cur.length && t - times[i - 1] > gap) { segs.push(cur); cur = []; } cur.push(i); }); if (cur.length) segs.push(cur);
  ctx.save(); ctx.beginPath(); ctx.rect(pad.l, pad.t - 2, pw, ph + 4); ctx.clip();
  series.forEach((q) => {
    const max = shared ? sharedMax : rawMax(q);
    const y = (v) => pad.t + ph - (Math.min(v, max) / max) * ph;
    scales.push(y);
    for (const sg of segs) {
      if (sg.length === 1) { ctx.fillStyle = q.color; ctx.beginPath(); ctx.arc(x(times[sg[0]]), y(q.values[sg[0]]), sg.length === times.length ? 3 : 2, 0, 7); ctx.fill(); continue; }
      const g = ctx.createLinearGradient(0, pad.t, 0, pad.t + ph); g.addColorStop(0, `${q.color}${series.length > 2 ? '22' : '40'}`); g.addColorStop(1, `${q.color}00`);
      ctx.beginPath(); sg.forEach((i, n) => (n ? ctx.lineTo(x(times[i]), y(q.values[i])) : ctx.moveTo(x(times[i]), y(q.values[i]))));
      ctx.lineTo(x(times[sg[sg.length - 1]]), pad.t + ph); ctx.lineTo(x(times[sg[0]]), pad.t + ph); ctx.closePath(); ctx.fillStyle = g; ctx.fill();
      ctx.strokeStyle = q.color; ctx.lineWidth = 1.8; ctx.lineJoin = 'round'; ctx.beginPath();
      sg.forEach((i, n) => (n ? ctx.lineTo(x(times[i]), y(q.values[i])) : ctx.moveTo(x(times[i]), y(q.values[i])))); ctx.stroke();
    }
  });
  ctx.restore();
  // legend: colour, name, latest value. Clickable: click = show only this series, Ctrl/⌘-click = toggle it.
  ctx.textBaseline = 'top'; ctx.font = '10.5px system-ui'; canvas._legend = [];
  if (!canvas._noLegend) allSeries.forEach((q) => {
    const off = !series.includes(q);
    const last = q.values.length ? q.values[q.values.length - 1] : null; const f = q.fmt || (q.label === 'sessions' ? fmtInt : fmtRate);
    const label = `${q.label}${last == null ? '' : ` ${f(last)}`}${shared ? '' : `  (max ${f(rawMax(q))})`}`;
    const tw = ctx.measureText(label).width;
    ctx.globalAlpha = off ? .38 : 1;
    ctx.fillStyle = q.color; ctx.beginPath(); ctx.arc(lx + 4, 8, 3.5, 0, 7); if (off) { ctx.strokeStyle = q.color; ctx.lineWidth = 1.2; ctx.stroke(); } else ctx.fill();
    ctx.fillStyle = txtCol; ctx.fillText(label, lx + 12, 2);
    if (off) { ctx.strokeStyle = txtCol; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(lx + 12, 8); ctx.lineTo(lx + 12 + tw, 8); ctx.stroke(); }
    ctx.globalAlpha = 1;
    if (allSeries.length > 1) canvas._legend.push({ k: q.k, x0: lx - 2, x1: lx + 14 + tw, y0: 0, y1: 17 });
    lx += tw + 26;
  });
  if (canvas._sel) { // drag-to-zoom selection
    const a = Math.min(canvas._sel.a, canvas._sel.b); const b = Math.max(canvas._sel.a, canvas._sel.b);
    ctx.fillStyle = 'rgba(34,211,238,.16)'; ctx.fillRect(a, pad.t, b - a, H - pad.t - pad.b);
    ctx.strokeStyle = 'rgba(34,211,238,.8)'; ctx.lineWidth = 1; ctx.strokeRect(a + .5, pad.t, b - a, H - pad.t - pad.b);
  }
  // hover: crosshair, a dot per series, and a value tooltip
  const ht = chartHover.get(canvas.id); if (ht == null) return;
  let i = 0; for (let k = 1; k < times.length; k++) if (Math.abs(times[k] - ht) < Math.abs(times[i] - ht)) i = k;
  if (domain && (ht < domain[0] || ht > domain[1] || Math.abs(times[i] - ht) > (domain[1] - domain[0]) / 12)) return; // no sample near the pointer
  const hx = x(times[i]);
  ctx.strokeStyle = '#64748b'; ctx.lineWidth = 1; ctx.setLineDash([3, 3]);
  ctx.beginPath(); ctx.moveTo(hx, pad.t); ctx.lineTo(hx, H - pad.b); ctx.stroke(); ctx.setLineDash([]);
  series.forEach((s, n) => { ctx.fillStyle = s.color; ctx.beginPath(); ctx.arc(hx, scales[n](s.values[i]), 3.5, 0, Math.PI * 2); ctx.fill(); });
  const lines = series.map((s) => ({ c: s.color, t: `${s.label}: ${(s.fmt || (s.label === 'sessions' ? fmtInt : fmtRate))(s.values[i])}` }));
  ctx.font = '11px system-ui'; ctx.textBaseline = 'top';
  const maxTw = Math.max(60, W - 48); // a chart tooltip never grows wider than its chart: long labels are shortened with an ellipsis
  lines.forEach((l) => { while (l.t.length > 6 && ctx.measureText(l.t).width > maxTw) l.t = `${l.t.slice(0, Math.max(3, l.t.length - 4)).trimEnd()}…`; });
  const head = fmtTime(times[i]);
  const bw = Math.max(ctx.measureText(head).width, ...lines.map((l) => ctx.measureText(l.t).width + 14)) + 16;
  const bh = 8 + 14 * (lines.length + 1);
  const bx = hx + 12 + bw > W ? hx - 12 - bw : hx + 12; const by = Math.max(pad.t, Math.min(8, H - bh - 2));
  ctx.fillStyle = cssVar('--bg-3') || '#172033'; ctx.strokeStyle = cssVar('--line') || '#243049';
  ctx.beginPath(); ctx.roundRect(bx, by, bw, bh, 6); ctx.fill(); ctx.stroke();
  ctx.fillStyle = cssVar('--muted') || '#8b97ad'; ctx.fillText(head, bx + 8, by + 5);
  lines.forEach((l, n) => { const ly = by + 5 + 14 * (n + 1); ctx.fillStyle = l.c; ctx.fillRect(bx + 8, ly + 3, 6, 6); ctx.fillStyle = cssVar('--text') || '#e5eaf3'; ctx.fillText(l.t, bx + 20, ly); });
}

// ---------- process information (HAProxy "General process information" / show info) ----------
function processPanel(info) {
  if (!info || (info.pid == null && info.maxconn == null && info.currConns == null && info.idlePct == null)) return '';
  const pct = (a, b) => (a != null && b ? Math.min(100, (a / b) * 100) : null);
  const connPct = pct(info.currConns, info.maxconn);
  const bar = (v, tone) => (v == null ? '' : `<span class="pbar ${tone || ''}" aria-hidden="true"><i style="width:${Math.max(v > 0 ? 2 : 0, v).toFixed(1)}%"></i></span>`);
  const cell = (label, value, sub, extra) => (value == null || value === '' ? '' : `<div class="pcell"><span class="pl">${esc(label)}</span><b>${value}</b>${sub ? `<span class="muted small">${sub}</span>` : ''}${extra || ''}</div>`);
  const threads = info.nbproc != null && info.nbthread != null ? `${info.nbproc} process · ${info.nbthread} thread${info.nbthread === 1 ? '' : 's'}` : (info.nbthread != null ? `${info.nbthread} thread${info.nbthread === 1 ? '' : 's'}` : null);
  const busy = info.idlePct != null ? 100 - info.idlePct : null;
  return `<div class="panel proc" style="margin-bottom:16px"><h2>Process <span class="muted small">${esc(TYPE_NAME[snapshotType()] || '')}${info.version ? ` ${esc(info.version)}` : ''}</span></h2>
    <div class="pgrid">
      ${cell('Process ID', info.pid != null ? esc(info.pid) : null, threads)}
      ${cell('Uptime', info.uptimeSec != null ? esc(fmtDur(info.uptimeSec)) : null, info.uptime && info.uptimeSec == null ? esc(info.uptime) : null)}
      ${cell('Connections', info.currConns != null ? `${fmtInt(info.currConns)}${info.maxconn ? ` <span class="muted small">/ ${fmtInt(info.maxconn)}</span>` : ''}` : null, connPct != null ? `${connPct < 0.1 ? '<0.1' : connPct.toFixed(1)}% of the connection limit` : 'current connections', bar(connPct, connPct > 80 ? 'bad' : connPct > 60 ? 'warn' : ''))}
      ${cell('Connection rate', info.connRate != null ? `${fmtInt(info.connRate)}<span class="muted small"> /s</span>` : null, info.maxConnRate ? `peak ${fmtInt(info.maxConnRate)}/s` : (info.sessRate != null ? `${fmtInt(info.sessRate)} sessions/s` : null))}
      ${cell('Idle', info.idlePct != null ? `${info.idlePct}<span class="muted small"> %</span>` : null, busy != null ? `${busy}% busy` : null, bar(busy, busy > 80 ? 'bad' : busy > 60 ? 'warn' : ''))}
      ${cell('Tasks', info.tasks != null ? `${info.runQueue != null ? `${fmtInt(info.runQueue)} <span class="muted small">running /</span> ` : ''}${fmtInt(info.tasks)}` : null, 'scheduler queue')}
      ${cell('Sockets', info.maxsock != null ? fmtInt(info.maxsock) : null, info.ulimitN != null ? `file-descriptor limit ${fmtInt(info.ulimitN)}` : 'maximum sockets')}
      ${cell('Pipes', info.maxpipes != null ? `${fmtInt(info.currPipes || 0)} <span class="muted small">/ ${fmtInt(info.maxpipes)}</span>` : null, 'kernel splicing')}
      ${cell('Memory limit', info.memMax ? esc(info.memMax) : null, 'memmax')}
    </div></div>`;
}

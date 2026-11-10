'use strict';
/* HAGateLight UI. No inline handlers (strict CSP); every dynamic string passes through esc(). */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = {
  instances: [], current: null, snapshot: null, events: [], view: 'overview',
  series: [], timer: null, sort: { key: 'default', desc: false }, analysis: null,
  inspected: null, cfgFilter: '', eventFilter: 'all',
  meta: { features: { haproxy: true, nginx: true }, types: [] }, cfgFile: null, focus: null, mode: 'landing',
  hiddenTypes: loadPref('gatelight.hiddenTypes', []),
};
function loadPref(k, d) { try { const v = JSON.parse(localStorage.getItem(k)); return v == null ? d : v; } catch { return d; } }
function savePref(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } }
const TYPE_NAME = { haproxy: 'HAProxy', nginx: 'NGINX' };
const labels = () => (state.snapshot && state.snapshot.instance.labels) || { frontend: 'Frontend', backend: 'Backend', server: 'Server' };
const lbl = (kind) => labels()[kind] || kind;

// ---------- formatting ----------
const fmtInt = (n) => (n == null ? '–' : Math.round(n).toLocaleString());
const fmtRate = (n) => (n == null ? '–' : n >= 100 ? Math.round(n).toLocaleString() : n.toFixed(n < 10 ? 2 : 1));
function fmtBytes(b) {
  if (b == null) return '–';
  if (b < 1024) return `${b} B`;
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
const REVIEW_VIEWS = ['topology', 'flow', 'forge', 'config'];
const visibleNav = () => $$('#nav button').filter((b) => !b.hidden && b.offsetParent !== null);
const VIEW_ALIAS = { audit: 'forge', validate: 'forge' }; // old links keep working
function switchView(view) {
  if (view === 'infrastructure' || view === 'lbinfra') { const l = $('#topo-layout'); if (l && l.value !== 'network') { l.value = 'network'; if (network) { network.destroy(); network = null; } } view = 'topology'; } // Infrastructure is now a Topology layout
  view = VIEW_ALIAS[view] || view;
  if (view === 'graphs' && state.mode === 'live' && state.snapshot && state.snapshot.instance && state.snapshot.instance.source === 'config-only') view = 'traffic'; // no live statistics: the log is the traffic page
  if (state.mode === 'review' && !REVIEW_VIEWS.includes(view)) view = 'topology';
  if (state.mode === 'live' && !state.snapshot && !state.current && !['overview', 'connect', 'settings', 'forge'].includes(view)) view = 'overview';
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
    <p class="muted welcome-lead">See your HAProxy and NGINX as a map. Nothing is connected yet, so here is how to start:</p>
    <ol class="welcome-steps">
      <li><span class="n">1</span><div><b>Add your first instance</b><p class="muted">Connect a running HAProxy or NGINX (URL, user, password), or upload its config and keep it under a name.</p>
        ${can ? '<button class="btn primary" type="button" data-goto="connect">Add an instance</button>' : '<p class="muted small">Adding from the browser is off. Define servers in <code>config/instances.json</code>, or start GateLight with <code>ALLOW_UI_INSTANCES=true</code>.</p>'}</div></li>
      <li><span class="n">2</span><div><b>Only want to check a config?</b><p class="muted">Drop a file or folder and get the map and audit. Nothing is saved.</p>
        <button class="btn" type="button" data-goto="connect">Review a config</button></div></li>
      <li><span class="n">3</span><div><b>Then explore</b><p class="muted">The overview, topology, URL map, services, audit and events appear here as soon as there is an instance to show.</p></div></li>
    </ol>
    <p class="muted small">Just looking around? Try an example: <button class="link" type="button" data-example="haproxy">HAProxy</button> · <button class="link" type="button" data-example="nginx">NGINX</button></p>
  </div>`;
}
function renderView(view) {
  if (view === 'connect') return;
  if (view === 'settings') { renderSettings(); return; }
  if (view === 'forge') { renderForge(); return; } // works without an instance: paste or upload any config
  if (!state.snapshot) {
    if (view === 'overview') { if (state.current) $('#view-overview').innerHTML = '<div class="skeleton-cards"><i></i><i></i><i></i><i></i><i></i></div>'; else renderWelcome(); }
    return;
  }
  ({ fleet: renderFleet, settings: renderSettings, overview: renderOverview, topology: renderTopology, graphs: renderGraphs, profile: renderProfile, detail: () => { if (state.inspected) refreshInspector(); }, services: renderServices, forge: () => renderForge(), flow: renderFlow, traffic: () => renderTraffic(), events: renderEvents, config: renderConfig }[view] || (() => {}))();
}

// ---------- data loading ----------
async function loadInstances() {
  try { state.meta = await api('/meta'); } catch { /* keep defaults */ }
  $$('[data-logout]').forEach((b) => { b.hidden = !(state.meta && state.meta.authUser); });
  { const u = state.meta && state.meta.authUser ? String(state.meta.authUser) : ''; const nu = $('#navuser'); nu.hidden = !u; $('#nu-name').textContent = u; $('#nu-av').textContent = (u[0] || '').toUpperCase(); $('#nu-name').title = u; }
  const { instances } = await api('/instances');
  state.instances = instances;
  const visible = instances.filter((i) => !state.hiddenTypes.includes(i.type));
  const sel = $('#instance-select');
  const keep = state.current;
  const opt = (i) => `<option value="${esc(i.id)}">${esc(i.name)}${i.serversDown ? ` ⚠ ${i.serversDown} down` : ''}</option>`;
  const groups = ['haproxy', 'nginx'].map((t) => ({ t, list: visible.filter((i) => i.type === t) })).filter((g) => g.list.length);
  sel.innerHTML = (groups.length > 1 ? groups.map((g) => `<optgroup label="${TYPE_NAME[g.t]}">${g.list.map(opt).join('')}</optgroup>`).join('') : visible.map(opt).join(''))
    + (state.analysis ? '<option value="__analysis">📄 Uploaded analysis</option>' : '');
  $('#nav [data-view="fleet"]').hidden = visible.length < 2;
  $('#btn-connect').hidden = !(state.meta && state.meta.canManage);
  { const nb = $('#nav [data-view=connect] span'); if (nb) nb.textContent = state.meta && state.meta.canManage ? 'Add instance' : 'Review a config'; }
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
  const na = $('#nav-audit'); const af = snap.findingsSummary; na.hidden = !(af.error + af.warning); na.textContent = af.error + af.warning; na.title = 'Audit errors and warnings. Config Forge also lists rewrite and validation checks, so its total is higher.';
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

// ---------- OVERVIEW ----------
/** KPI card: value + live detail + a plain-language "what is this" line; a button that jumps to the matching, pre-filtered view. */
function card(label, value, sub, tone, o = {}) {
  const act = o.go ? ` data-card="${esc(o.go)}"` : '';
  const tag = o.go ? 'button type="button"' : 'div';
  return `<${tag} class="card ${tone || ''}${o.go ? ' clickable' : ''}"${act} title="${esc(o.help || '')}"${o.go ? ` aria-label="${esc(`${label}: ${value}. ${o.help || ''} Click to ${o.cta || 'open'}.`)}"` : ''}>
    <div class="label">${esc(label)}</div><div class="value">${esc(value)}</div><div class="sub">${esc(sub || '')}</div>
    ${o.help && !o.compact ? `<div class="why">${esc(o.help)}</div>` : ''}${o.cta && !o.compact ? `<div class="go">${esc(o.cta)} →</div>` : ''}</${o.go ? 'button' : 'div'}>`;
}
// card id -> { view, filters on the Services table, sort }
const CARD_GO = {
  'servers-up': { view: 'services', kind: 'server', st: 'up', sort: 'default' },
  down: { view: 'services', kind: '', st: 'down', sort: 'default' },
  rate: { view: 'services', kind: 'backend', st: '', sort: 'ratePerSec', desc: true },
  err5xx: { view: 'services', kind: 'backend', st: '', sort: 'err5xxPerSec', desc: true },
  bytes: { view: 'services', kind: 'backend', st: '', sort: 'bout', desc: true },
  findings: { view: 'forge' },
};
function openCard(id) {
  const g = CARD_GO[id]; if (!g) return;
  if (g.view === 'services') {
    $('#svc-search').value = ''; $('#svc-kind').value = g.kind; $('#svc-state').value = g.st;
    state.sort = { key: g.sort, desc: Boolean(g.desc) };
  }
  switchView(g.view);
}

function renderOverview() {
  const s = state.snapshot; const sum = s.summary; const f = s.findingsSummary;
  const hasStats = s.rows.some((r) => r.scur != null || r.stot != null || r.ratePerSec != null);
  const problems = s.rows.filter((r) => r.kind !== 'frontend' && isProblem(r)).sort((a, b) => (a.state === 'down' ? -1 : 1) - (b.state === 'down' ? -1 : 1));
  const hot = s.rows.filter((r) => r.kind === 'backend' && (r.err5xxPerSec || 0) > 0.05 && r.ratePerSec > 0)
    .map((r) => ({ r, pct: (r.err5xxPerSec / Math.max(r.ratePerSec, 0.001)) * 100 })).filter((x) => x.pct >= 1).sort((a, b) => b.pct - a.pct).slice(0, 5);
  const errs = s.findings.filter((x) => x.severity === 'error').slice(0, 5);
  const info = s.info || {};

  const showCta = state.meta.canManage && ['config-only', 'demo'].includes(s.instance.source);
  const cta = showCta ? `<div class="cta"><div><b>${s.instance.source === 'demo' ? 'You are looking at synthetic demo traffic' : 'You are looking at the configuration only'}</b><span class="muted">Connect your ${s.instance.source === 'demo' ? '' : 'live '}HAProxy or NGINX (URL, username, password) to see real health and traffic.</span></div><button class="btn primary" type="button" data-connect>Connect a server</button></div>` : '';
  // ---- level 1: one verdict for the whole instance ----
  const sv = sum.servers; const upN = sv.up + sv.degraded; const downN = hasStats ? sv.down + sum.backends.down : 0;
  const downRows = problems.filter((r) => r.state === 'down');
  const tone = !hasStats ? 'neutral' : downN ? 'bad' : (f.error || hot.length || sv.degraded || sum.err5xxPerSec > 0.5) ? 'warn' : 'ok';
  const since = downRows.length === 1 && downRows[0].lastchg > 0 ? ` for ${fmtDur(downRows[0].lastchg)}` : '';
  const headline = !hasStats ? 'Configuration loaded' : downN ? (downRows.length === 1 && downRows[0].kind === 'server' ? `${downRows[0].proxy} / ${downRows[0].name} is down${since}` : `${downN} item${downN === 1 ? '' : 's'} down`) : tone === 'warn' ? 'Running, with things to look at' : 'Everything is healthy';
  const facts = [
    hasStats ? `${upN} of ${sv.total} servers up${sv.nocheck ? `, ${sv.nocheck} without a health check` : ''}` : null,
    f.error ? `${f.error} critical config issue${f.error === 1 ? '' : 's'}` : (hasStats ? 'no critical config issues' : `${f.warning} config warning${f.warning === 1 ? '' : 's'}`),
    hasStats ? `${fmtRate(sum.ratePerSec)} requests/s${sum.err5xxPerSec > 0 ? `, ${fmtRate(sum.err5xxPerSec)} × 5xx/s` : ', no 5xx'}` : null,
  ].filter(Boolean);
  const segs = [['up', 'Up', 'var(--green)'], ['degraded', 'Degraded', 'var(--amber)'], ['down', 'Down', 'var(--red)'], ['maint', 'Maintenance', 'var(--indigo)'], ['nocheck', 'No health check', 'var(--slate)']].map(([k, t, c]) => ({ t, c, n: sv[k] || 0 })).filter((x) => x.n);
  const ico = { ok: '✓', warn: '!', bad: '✕', neutral: 'i' }[tone];
  const hero = `<section class="ov-hero ${tone}" aria-label="Overall status">
    <div class="ov-verdict"><span class="ov-ico" aria-hidden="true">${ico}</span>
      <div><h2>${esc(headline)}</h2><p class="ov-facts">${facts.map(esc).join('<i></i>')}</p>
        <div class="ov-actions">${downN ? '<button class="btn primary" type="button" data-card="down">Show what is down</button>' : ''}<button class="btn" type="button" data-goto="forge">Config Forge</button><button class="btn" type="button" data-goto="topology">Topology</button></div></div></div>
    ${hasStats && sv.total ? `<div class="ov-servers"><div class="ov-sv-top"><b>${upN}</b><span>/ ${sv.total} servers up</span></div>
      <div class="ov-bar" role="img" aria-label="${esc(segs.map((x) => `${x.n} ${x.t}`).join(', '))}">${segs.map((x) => `<i style="flex:${x.n};background:${x.c}" title="${esc(`${x.n} ${x.t}`)}"></i>`).join('')}</div>
      <div class="ov-legend">${segs.map((x) => `<span><i style="background:${x.c}"></i>${x.n} ${esc(x.t.toLowerCase())}</span>`).join('')}</div></div>` : ''}
  </section>`;
  const proc = processPanel(info);
  const perf = hasStats || info.activeConns != null;
  $('#view-overview').innerHTML = cta + `${hero}
    <div class="ov-lvl"><span>Needs attention</span></div>
    <div class="cols">
      <div class="panel"><h2>Needs attention <span class="tag">${problems.length + hot.length}</span></h2><div class="list">
        ${problems.slice(0, 8).map((r) => `<div class="item" data-inspect="${esc(r.proxy)}/${esc(r.name)}">${stBadge(r.state, r.status)}<div class="t"><b>${esc(r.proxy)}${r.kind === 'server' ? ` / ${esc(r.name)}` : ''}</b>${rowEndpoints(r).addrs.length ? ` <span class="mono small muted">${esc(rowEndpoints(r).addrs.slice(0, 2).join(', '))}</span>` : ''}${r.check_status ? `<div class="muted small">${esc(r.check_status)}${r.last_chk ? ` — ${esc(r.last_chk)}` : ''}${r.lastchg != null ? ` · for ${fmtDur(r.lastchg)}` : ''}</div>` : ''}</div></div>`).join('')
          || (hot.length ? '' : `<div class="empty">${hasStats ? '✓ Everything is healthy' : 'No runtime stats available'}</div>`)}
        ${hot.map(({ r, pct }) => `<div class="item" data-inspect="${esc(r.proxy)}/${esc(r.name)}"><span class="st st-degraded">5xx</span><div class="t"><b>${esc(r.proxy)}</b><div class="muted small">${pct.toFixed(1)}% of responses are 5xx (${fmtRate(r.err5xxPerSec)}/s)</div></div></div>`).join('')}
      </div></div>
      <div class="panel"><h2>Critical config issues <a class="muted small" data-goto="audit" style="cursor:pointer">view all →</a></h2><div class="list">
        ${errs.map((x) => `<div class="item" ${loc(x)}><span class="sev-error">●</span><div class="t"><b>${esc(x.title)}</b><div class="muted small">${esc(x.section)} · line ${x.line}</div></div></div>`).join('') || '<div class="empty">✓ No errors</div>'}
      </div></div>
      <div class="panel"><h2>Recent events <a class="muted small" data-goto="events" style="cursor:pointer">view all →</a></h2><div class="list">
        ${state.events.filter((e) => e.level !== 'info').slice(0, 6).map((e) => `<div class="item"><span class="lv-${esc(e.level)}">●</span><div class="t">${esc(e.message)}<div class="muted small">${fmtDateTime(e.ts)}</div></div></div>`).join('') || '<div class="empty">No state changes recorded</div>'}
      </div></div>
    </div>
    ${perf ? `<div class="ov-lvl"><span>Performance</span></div>
    <div class="cards ov-kpis">
      ${hasStats || info.activeConns != null ? card('Requests / s', fmtRate(sum.ratePerSec), `${fmtInt(sum.sessions)} current ${info.activeConns != null ? 'connections' : 'sessions'}`, '', { go: 'rate', help: 'New HTTP requests per second across all backends, measured over the latest poll. Sessions are connections open right now.', compact: true, cta: 'Busiest backends' }) : ''}
      ${hasStats ? card('5xx / s', fmtRate(sum.err5xxPerSec), sum.ratePerSec > 0 ? `${((sum.err5xxPerSec / sum.ratePerSec) * 100).toFixed(2)}% of traffic` : '', sum.err5xxPerSec > 0.5 ? 'warn' : '', { go: 'err5xx', help: 'Server-side errors (HTTP 500–599) returned per second. A rising value usually means a failing application, not the proxy.', compact: true, cta: 'Backends by errors' }) : ''}
      ${hasStats ? card('Throughput', `${fmtBytes(sum.bytesIn + sum.bytesOut)}`, 'total in+out since start', '', { go: 'bytes', help: 'Bytes received plus sent since the proxy last restarted (a counter, not a rate).', compact: true, cta: 'Backends by traffic' }) : ''}
      ${card('Audit findings', f.error + f.warning, `${f.error} errors · ${f.warning} warnings · ${f.info} info · Config Forge lists more`, f.error ? 'bad' : f.warning ? 'warn' : 'ok', { go: 'findings', help: 'Problems the static audit found in the configuration: errors will break or endanger the proxy, warnings are risky settings, info is advice.', compact: true, cta: 'Review findings' })}
    </div>`  : ''}
    ${hasStats || info.activeConns != null ? `<div class="panel ov-traffic"><h2>Traffic <span class="muted small">${esc(info.version ? `${TYPE_NAME[snapshotType()] || ''} ${info.version}` : '')}${info.uptimeSec != null ? ` · up ${fmtDur(info.uptimeSec)}` : ''}${info.idlePct != null ? ` · idle ${info.idlePct}%` : ''}${info.reading != null ? ` · reading/writing/waiting ${info.reading}/${info.writing}/${info.waiting}` : ''}</span><button class="btn icon chart-expand" type="button" data-cv-expand="overview" title="Pop out: bigger chart, time range, series and stats" aria-label="Pop out traffic chart">⤢</button></h2><canvas id="ov-chart" class="chart" title="Click to pop out"></canvas></div>` : ''}
    ${proc ? `<div class="ov-lvl"><span>System</span></div>${proc}` : ''}`;
  const c = $('#ov-chart');
  if (c) {
    const ser = state.series;
    drawChart(c, ser.map((p) => p.t), [
      { label: 'req/s', color: '#22d3ee', values: ser.map((p) => p.rate) },
      { label: '5xx/s', color: '#f87171', values: ser.map((p) => p.e5), minMax: 1 },
    ]);
  }
}

// ---------- TOPOLOGY ----------
let network = null; let visNodes = null; let visEdges = null;
const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
function isLight() {
  const t = document.documentElement.dataset.theme;
  return t === 'light' || (t !== 'dark' && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
}
// ---------- Layer 7 (HTTP) vs layer 4 (TCP) ----------
// L7 = understands HTTP: routes by host / path / method / header, can rewrite the URI and add headers.
// L4 = forwards TCP connections by address and port (and TLS SNI); it never sees paths or headers.
const layerOf = (sec) => (sec && sec.mode === 'tcp' ? 'L4' : 'L7');
function layerTip(sec) {
  if (!sec) return '';
  const l4 = layerOf(sec) === 'L4';
  const sni = (sec.routes || []).some((r) => !r.commented && (r.matchers || []).some((m) => m.field === 'TLS SNI'));
  const tls = (sec.binds || []).some((b) => b.ssl && !b.commented);
  if (!l4) return `L7 · HTTP: routes by host, path, method and headers; can rewrite the URI, add headers${tls ? ', ends TLS here' : ''} and see status codes.`;
  return `L4 · TCP: forwards connections by address and port${sni ? ' and TLS SNI' : ''}; cannot see paths or headers, so no URI routing or rewriting. ${tls ? 'TLS is ended at this proxy.' : 'TLS (if any) stays encrypted end to end.'}`;
}
const layerTag = (sec) => `<span class="tag layer-${layerOf(sec).toLowerCase()}" title="${esc(layerTip(sec))}">${layerOf(sec)}</span>`;

const DARK_NODES = {
  fe: { background: '#0e7490', border: '#22d3ee' }, be: { background: '#3730a3', border: '#818cf8' },
  up: { background: '#065f46', border: '#34d399' }, degraded: { background: '#78350f', border: '#fbbf24' },
  down: { background: '#7f1d1d', border: '#f87171' }, maint: { background: '#312e81', border: '#818cf8' },
  idle: { background: '#1e293b', border: '#64748b' }, missing: { background: '#450a0a', border: '#f87171' },
};
const LIGHT_NODES = { // solid fills with a darker rim: the label sits outside the shape, so the shape can be bold
  fe: { background: '#0891b2', border: '#0e7490' }, be: { background: '#6366f1', border: '#4338ca' },
  up: { background: '#10b981', border: '#047857' }, degraded: { background: '#f59e0b', border: '#b45309' },
  down: { background: '#ef4444', border: '#b91c1c' }, maint: { background: '#a5b4fc', border: '#4f46e5' },
  idle: { background: '#cbd5e1', border: '#64748b' }, missing: { background: '#fca5a5', border: '#dc2626' },
};
let NODE_COLORS = DARK_NODES;

/** Break long identifiers at a separator so neighbouring labels do not collide. */
function wrapName(name, max = 14) {
  const s = String(name);
  if (s.length <= max) return s;
  const cut = Math.max(s.lastIndexOf('-', max), s.lastIndexOf('_', max), s.lastIndexOf('.', max), s.lastIndexOf(':', max));
  return cut > 3 ? `${s.slice(0, cut + 1)}\n${s.slice(cut + 1)}` : s;
}

/** Selecting a node or link in the map shows a small bar with its summary; "Open details" goes to the full page. */
let topoSel = null;
function topoSelect(node, route) {
  const el = $('#topo-sel'); if (!el) return;
  topoSel = node ? { node } : route ? { route } : null;
  if (!topoSel) { el.hidden = true; el.innerHTML = ''; return; }
  let title; let sub; let st = '';
  if (route) { title = `${route.fe} → ${route.target}`; sub = `Routing rule · ${routeSummary(route)}`; }
  else if (node._key) { const r = indexRows(state.snapshot.rows).get(node._key); title = r && r.kind === 'server' ? node._key.replace('/', ' / ') : node._key.split('/')[0]; sub = `${r ? lbl(r.kind) : node._kind}${r && r.ratePerSec != null ? ` · ${fmtRate(r.ratePerSec)} req/s` : ''}`; st = r ? stBadge(r.state, r.status) : ''; }
  else { title = node.id.slice(8); sub = 'Broken route: not defined'; }
  el.innerHTML = `<div class="ts-t"><b>${esc(title)}</b> ${st}<div class="muted small">${esc(sub)}</div></div>${node && /^(fe|be):/.test(node.id) ? `<button type="button" class="btn" data-topo-toggle="${esc(node.id)}" title="Same as shift-click on the node">${collapsedSet().has(node.id) ? '▸ Expand' : '▾ Collapse'}</button>` : ''}<button type="button" class="btn primary" data-topo-open>Open details →</button><button type="button" class="btn icon" data-topo-sel-x aria-label="Clear selection">✕</button>`;
  el.hidden = false;
}
/** Fold the parts of the map the user collapsed (shift-click a node, or Collapse all): a collapsed entry point hides the pools only it reaches, a collapsed pool hides its members. */
function collapseGraph(nodes, edges) {
  const col = collapsedSet();
  const hidden = new Set(); const srcs = new Map(); const kids = new Map();
  edges.forEach((e) => { if (e.from !== e.to) kids.set(e.from, (kids.get(e.from) || 0) + 1); });
  if (col.size) {
    edges.filter((e) => String(e.id).startsWith('r:')).forEach((e) => (srcs.get(e.to) || srcs.set(e.to, []).get(e.to)).push(e.from));
    for (let changed = true; changed;) {
      changed = false;
      for (const [pool, from] of srcs) if (!hidden.has(pool) && from.every((f) => col.has(f) || hidden.has(f))) { hidden.add(pool); changed = true; }
    }
    const parent = new Map(edges.filter((e) => String(e.id).startsWith('e:sv:')).map((e) => [e.to, e.from]));
    nodes.forEach((n) => { if (n._kind === 'server') { const pa = parent.get(n.id); if (pa && (col.has(pa) || hidden.has(pa))) hidden.add(n.id); } });
  }
  const direct = new Map();
  edges.forEach((e) => { if (col.has(e.from) && hidden.has(e.to)) direct.set(e.from, (direct.get(e.from) || 0) + 1); });
  const out = nodes.filter((n) => !hidden.has(n.id));
  // the arrow under a node says whether it is open (▾, pointing down at what it holds) or folded (▸, pointing right)
  out.forEach((n) => {
    if (!/^(fe|be):/.test(n.id)) return;
    if (col.has(n.id)) { n._collapsed = true; const k = direct.get(n.id) || 0; n.label += `\n▸ ${k ? `${k} hidden` : 'folded'}`; n.borderWidth = 3; }
    else if (kids.get(n.id)) n.label += '\n▾';
  });
  return { nodes: out, edges: edges.filter((e) => !hidden.has(e.from) && !hidden.has(e.to)) };
}
const collapsedSet = () => (state.collapsed || (state.collapsed = new Set()));
function toggleCollapse(id) {
  if (!/^(fe|be):/.test(id)) return;
  const c = collapsedSet(); if (c.has(id)) c.delete(id); else c.add(id);
  renderTopology();
}
function topoCollapseAll(collapse) {
  const c = collapsedSet(); c.clear();
  if (collapse) { cfgSections().forEach((x) => { if (feLike(x) && x.routes.length) c.add(`fe:${x.name}`); else if (beLike(x) && x.type !== 'listen' && x.servers.some((v) => !v.commented)) c.add(`be:${x.name}`); }); }
  else { $('#topo-servers').checked = true; }
  state.focus = null; topoSelect(null); renderTopology();
}
function buildGraph() {
  NODE_COLORS = isLight() ? LIGHT_NODES : DARK_NODES;
  const FG = cssVar('--text') || '#e5eaf3'; const FG2 = cssVar('--muted') || '#cbd5e1'; const BG = cssVar('--bg') || '#0a0f1a';
  const s = state.snapshot; const rows = indexRows(s.rows); const sections = cfgSections();
  const showServers = $('#topo-servers').checked; const q = $('#topo-search').value.trim().toLowerCase();
  const onlyProblems = $('#topo-problems').checked; const urlLabels = $('#topo-urls').checked;
  const mindmap = $('#topo-layout').value === 'mindmap'; // radial: URIs live on the nodes, lines stay clean
  const nodes = []; const edges = []; const ids = new Set();
  const referenced = new Set();
  sections.filter(feLike).forEach((fe) => fe.routes.forEach((r) => { if (!r.commented && !r.dynamic) referenced.add(r.target); }));
  const beNames = new Set(sections.filter(beLike).map((b) => b.name));
  const suspect = new Set();
  sections.filter(feLike).forEach((fe) => fe.routes.forEach((r) => { if (r.maybeUpstream) suspect.add(r.target); }));
  const routeCount = sections.filter(feLike).reduce((n, fe) => n + fe.routes.length, 0);
  const worstOf = (names, prefix) => {
    const st = names.map((n) => (rows.get(`${prefix}/${n}`) || {}).state).filter(Boolean);
    if (!st.length) return null;
    const up = st.filter((x) => x === 'up' || x === 'nocheck').length;
    if (st.every((x) => x === 'down')) return 'down';
    if (st.some((x) => x === 'down' || x === 'degraded')) return 'degraded';
    return up ? 'up' : 'maint';
  };

  sections.filter(feLike).forEach((fe) => {
    const r = rows.get(`${fe.name}/FRONTEND`);
    const id = `fe:${fe.name}`;
    ids.add(id);
    nodes.push({
      id, label: `${wrapName(fe.name)}\n${r && r.ratePerSec != null ? `${fmtRate(r.ratePerSec)}/s` : `${fe.routes.filter((x) => !x.commented).length} route${fe.routes.filter((x) => !x.commented).length === 1 ? '' : 's'}${fe.binds.some((b) => b.ssl && !b.commented) ? ' 🔒' : ''}`} · ${layerOf(fe)}`, shape: 'diamond', size: 24,
      color: NODE_COLORS.fe, borderWidth: 2, shapeProperties: { borderDashes: layerOf(fe) === 'L4' ? [3, 3] : false }, title: layerTip(fe), _layer: layerOf(fe), font: { color: FG, size: 14, face: 'system-ui', vadjust: -2, strokeWidth: 4, strokeColor: BG }, level: 0, _kind: 'frontend', _key: `${fe.name}/FRONTEND`, _section: fe.name, _pool: fe.type === 'listen' && fe.servers.some((x) => !x.commented),
      _problem: Boolean(r && isProblem(r)),
    });
  });

  sections.filter(beLike).forEach((be) => {
    const r = rows.get(`${be.name}/BACKEND`);
    const servers = be.servers.filter((x) => !x.commented);
    const worst = worstOf(servers.map((x) => x.name), be.name) || (r && r.state !== 'up' ? r.state : null);
    const idle = r && (r.stot || 0) === 0;
    const orphan = be.type === 'backend' && !referenced.has(be.name);
    let col = NODE_COLORS.be;
    if (be.implicit && suspect.has(be.name)) col = NODE_COLORS.missing;
    else if (worst === 'down') col = NODE_COLORS.down; else if (worst === 'degraded') col = NODE_COLORS.degraded; else if (idle && s.rows.length) col = NODE_COLORS.idle;
    if (be.type === 'listen') return;
    const id = `be:${be.name}`;
    ids.add(id);
    nodes.push({
      id, label: `${wrapName(be.name)}\n${r ? `${fmtRate(r.ratePerSec)}/s` : `${servers.length} srv`} · ${layerOf(be)}${orphan ? '\n(orphan)' : ''}`, shape: 'hexagon', size: 22,
      color: { ...col, border: orphan ? '#fbbf24' : col.border }, borderWidth: orphan ? 3 : 2, shapeProperties: { borderDashes: orphan ? [5, 4] : layerOf(be) === 'L4' ? [3, 3] : false }, title: layerTip(be), _layer: layerOf(be),
      font: { color: FG, size: 14, face: 'system-ui', strokeWidth: 4, strokeColor: BG }, level: 1, _kind: 'backend', _key: `${be.name}/BACKEND`, _section: be.name,
      _problem: worst === 'down' || worst === 'degraded',
    });
  });

  const serverParent = (be) => (be.type === 'listen' ? `fe:${be.name}` : `be:${be.name}`);
  {
    sections.filter(beLike).forEach((be) => {
      // Members are shown when enabled globally, or for the pool/entry point currently focused.
      // (a focused member counts too: clicking a server must not remove it and its siblings from the graph)
      if (!showServers && state.focus !== `be:${be.name}` && state.focus !== serverParent(be) && !String(state.focus || '').startsWith(`sv:${be.name}/`)) return;
      be.servers.filter((x) => !x.commented && !x.template).forEach((sv) => {
        const r = rows.get(`${be.name}/${sv.name}`);
        const st = r ? r.state : 'idle';
        const col = NODE_COLORS[st] || NODE_COLORS.idle;
        const id = `sv:${be.name}/${sv.name}`;
        ids.add(id);
        nodes.push({
          id, label: `${sv.name}${r && r.ratePerSec != null ? `\n${fmtRate(r.ratePerSec)}/s` : ''}`, shape: 'dot', size: 11 + Math.min(10, Math.log10((r && r.ratePerSec || 0) + 1) * 5),
          color: col, font: { color: FG, size: 12, face: 'system-ui', strokeWidth: 4, strokeColor: BG }, level: 2, _kind: 'server', _key: `${be.name}/${sv.name}`, _section: be.name, _layer: layerOf(be),
          _problem: st === 'down' || st === 'degraded',
        });
        edges.push({ id: `e:${id}`, from: serverParent(be), to: id, color: { color: st === 'down' ? '#f87171' : '#475569' }, width: 1, arrows: { to: { enabled: true, scaleFactor: 0.45 } } });
      });
    });
  }

  const uriBy = new Map(); // node id -> URIs / hosts it handles
  sections.filter(feLike).forEach((fe) => {
    fe.routes.forEach((rt, i) => {
      if (rt.dynamic) return;
      let target = `be:${rt.target}`;
      if (!beNames.has(rt.target)) {
        target = `missing:${rt.target}`;
        if (!ids.has(target) && !rt.commented) {
          ids.add(target);
          nodes.push({ id: target, label: `${rt.target}\n(undefined)`, shape: 'box', color: NODE_COLORS.missing, font: { color: FG, size: 12, strokeWidth: 4, strokeColor: BG }, level: 1, _kind: 'missing', _problem: true });
        }
        if (rt.commented) return;
      } else {
        const be = sections.find((x) => x.name === rt.target && beLike(x));
        if (be && be.type === 'listen') target = `fe:${rt.target}`;
      }
      if (!rt.commented) {
        const u = routeUri(rt);
        (uriBy.get(target) || uriBy.set(target, []).get(target)).push(u);
        (uriBy.get(`fe:${fe.name}`) || uriBy.set(`fe:${fe.name}`, []).get(`fe:${fe.name}`)).push(u);
      }
      const br = rows.get(`${rt.target}/BACKEND`);
      const w = br && br.ratePerSec ? 1.5 + Math.min(6, Math.log10(br.ratePerSec + 1) * 2) : 1.5;
      edges.push({
        id: `r:${fe.name}:${i}`, from: `fe:${fe.name}`, to: target, arrows: { to: { enabled: true, scaleFactor: 0.8 } }, width: rt.commented ? 1 : w,
        dashes: rt.commented || rt.type === 'default', color: { color: rt.commented ? '#94a3b8' : (isLight() ? '#0891b2' : '#22d3ee'), opacity: rt.commented ? 0.5 : 0.75 },
        title: routeTitle(fe, rt),
        label: urlLabels && routeCount <= 60 && !mindmap ? (rt.type === 'default' ? 'default' : (rt.short || rt.condition.replace(/^location /, '')).slice(0, 38)) : undefined, font: { size: 11, color: isLight() ? '#0e7490' : '#67e8f9', strokeWidth: 4, strokeColor: BG, align: 'middle' }, _route: { fe: fe.name, ...rt }, smooth: { type: 'cubicBezier', roundness: 0.4 },
      });
    });
  });

  // What each component handles: shown under the node name in the mind map, and in every node's hover tooltip.
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const clip = (t, n = 30) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);
  for (const [id, list] of uriBy) {
    const n = byId.get(id); const all = [...new Set(list)]; if (!n || !all.length) continue;
    n.title = `${n.title ? `${n.title}\n\n` : ''}${n.id.startsWith('fe:') ? 'Handles' : 'Serves'} ${all.length} URL rule${all.length === 1 ? '' : 's'}:\n${all.slice(0, 20).join('\n')}${all.length > 20 ? `\n+${all.length - 20} more` : ''}`;
    if (mindmap && urlLabels) n.font = { ...n.font, background: BG, size: 12 };
    if (mindmap && urlLabels) n.label += `\n${all.slice(0, 3).map((u) => clip(u)).join('\n')}${all.length > 3 ? `\n+${all.length - 3} more` : ''}`;
  }
  if (mindmap && urlLabels) { // members inherit their pool's URIs
    for (const n of nodes) if (n._kind === 'server') {
      const list = [...new Set(uriBy.get(`be:${n._section}`) || uriBy.get(`fe:${n._section}`) || [])];
      if (list.length) { n.title = `${n._key}\nServes: ${list.slice(0, 10).join(', ')}${list.length > 10 ? ` +${list.length - 10}` : ''}`; if (list.length) n.label += `\n${clip(list[0], 22)}${list.length > 1 ? ` +${list.length - 1}` : ''}`; }
    }
  }

  // Filtering (dim non-matching rather than removing, so layout stays stable)
  const layerSel = ($('#topo-layer') || {}).value || '';
  const match = (n) => (!q || n.label.toLowerCase().includes(q) || (n._section || '').toLowerCase().includes(q)) && (!onlyProblems || n._problem) && (!layerSel || !n._layer || n._layer === layerSel);
  for (const n of nodes) {
    n.opacity = match(n) ? 1 : 0.12;
    if (!match(n)) n.font = { ...n.font, color: 'rgba(148,163,184,.25)' };
  }
  if (state.focus && ids.has(state.focus)) {
    const out = new Map(); const inn = new Map();
    edges.forEach((e) => { (out.get(e.from) || out.set(e.from, []).get(e.from)).push(e.to); (inn.get(e.to) || inn.set(e.to, []).get(e.to)).push(e.from); });
    const keep = new Set([state.focus]);
    const walk = (adj) => { const q = [state.focus]; while (q.length) { const x = q.pop(); for (const y of adj.get(x) || []) if (!keep.has(y)) { keep.add(y); q.push(y); } } };
    walk(out); walk(inn);
    // Focusing a member keeps its pool-mates visible: the point is to see where it sits, not to hide the rest of the pool.
    if (state.focus.startsWith('sv:')) for (const parent of inn.get(state.focus) || []) for (const sib of out.get(parent) || []) keep.add(sib);
    for (const n of nodes) if (!keep.has(n.id)) { n.opacity = 0.1; n.font = { ...n.font, color: 'rgba(148,163,184,.2)' }; }
    for (const e of edges) if (!(keep.has(e.from) && keep.has(e.to))) { e.color = { ...(e.color || {}), opacity: 0.06 }; e.label = undefined; }
  }
  const g = collapseGraph(nodes, edges);
  g.nodes.forEach((n) => applyNodeIcon(n, FG, BG));
  return g;
}

// ---------- topology node icons: a rounded badge with a state-coloured ring and a glyph (drawn on the canvas, so dimming and selection still work) ----------
const ICON_PATHS = {
  frontend: ['M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4', 'M10 17l5-5-5-5', 'M15 12H3'], // an arrow entering a bracket: where traffic comes in
  backend: ['M12 2l10 5-10 5L2 7l10-5z', 'M2 17l10 5 10-5', 'M2 12l10 5 10-5'],       // stacked layers: a pool
  server: ['M5 3h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z', 'M5 13h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z', 'M7 7h.01', 'M7 17h.01'],
  missing: ['M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z', 'M12 9v4', 'M12 17h.01'],
};
const ICON_P2D = {};
function applyNodeIcon(n, FG, BG) {
  const kind = ICON_PATHS[n._kind] ? n._kind : null; if (!kind || typeof Path2D === 'undefined') return;
  const col = n.color || {}; const light = isLight();
  const fill = col.background || '#0e1626'; const ring = col.border || '#22d3ee';
  const dashes = (n.shapeProperties && n.shapeProperties.borderDashes) || null;
  const orphan = /\(orphan\)/.test(n.label || ''); const problem = Boolean(n._problem);
  const r = kind === 'frontend' ? 26 : kind === 'backend' ? 24 : kind === 'missing' ? 21 : Math.round(14 + Math.max(0, (n.size || 11) - 11) * 0.5);
  const label = String(n.label || ''); const alpha = n.opacity == null ? 1 : n.opacity;
  n.shape = 'custom'; n.size = r; n.borderWidth = 0;
  n.ctxRenderer = ({ ctx, x, y, state }) => ({
    drawNode() {
      ctx.save(); ctx.globalAlpha = alpha;
      if (problem) { ctx.shadowColor = ring; ctx.shadowBlur = 16; }
      ctx.beginPath(); ctx.roundRect(x - r, y - r, 2 * r, 2 * r, r * 0.38); ctx.fillStyle = fill; ctx.fill();
      const hg = ctx.createLinearGradient(x, y - r, x, y + r); hg.addColorStop(0, 'rgba(255,255,255,.16)'); hg.addColorStop(0.6, 'rgba(255,255,255,0)'); ctx.fillStyle = hg; ctx.fill();
      ctx.shadowBlur = 0; ctx.lineWidth = orphan ? 3 : 2.5; ctx.strokeStyle = ring; ctx.setLineDash(orphan ? [5, 4] : dashes || []); ctx.stroke(); ctx.setLineDash([]);
      if (state.selected || state.hover) { ctx.beginPath(); ctx.roundRect(x - r - 5, y - r - 5, 2 * r + 10, 2 * r + 10, r * 0.38 + 5); ctx.lineWidth = 2; ctx.strokeStyle = ring; ctx.globalAlpha = alpha * (state.selected ? 0.9 : 0.45); ctx.stroke(); ctx.globalAlpha = alpha; }
      const sc = (r * 1.05) / 24; ctx.translate(x - 12 * sc, y - 12 * sc); ctx.scale(sc, sc);
      ctx.lineWidth = 1.9; ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.strokeStyle = light ? '#fff' : ring;
      for (const d of ICON_PATHS[kind]) { const p = ICON_P2D[d] || (ICON_P2D[d] = new Path2D(d)); ctx.stroke(p); }
      ctx.restore();
    },
    drawExternalLabel() {
      const lines = label.split('\n'); ctx.save(); ctx.globalAlpha = alpha; ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.lineJoin = 'round';
      let yy = y + r + 7;
      lines.forEach((t, i) => { ctx.font = i === 0 ? '600 13px system-ui, sans-serif' : '11px system-ui, sans-serif'; ctx.lineWidth = 4; ctx.strokeStyle = BG; ctx.strokeText(t, x, yy); ctx.fillStyle = i === 0 ? FG : (light ? '#475569' : '#9fb0c8'); ctx.fillText(t, x, yy); yy += i === 0 ? 16 : 14; });
      ctx.restore();
    },
    nodeDimensions: { width: 2 * r, height: 2 * r },
  });
}

function updateLegend() {
  const l = labels();
  $('#topo-legend-fe').textContent = l.frontend; $('#topo-legend-be').textContent = l.backend;
}
function renderUrlMap() {
  const box = $('#urlmap'); const open = Boolean(state.urlmapOpen);
  const net = $('#topo-layout').value === 'network'; box.hidden = !open || net; $('#topo-urlmap').classList.toggle('on', open);
  if (net) { $('#view-topology').classList.remove('um-max'); return; }
  if (!open || !state.snapshot) return;
  const q = $('#topo-search').value.trim().toLowerCase();
  const rows = [];
  cfgSections().filter(feLike).forEach((fe) => fe.routes.forEach((rt, i) => rows.push({ fe, rt, i })));
  const shown = rows.filter(({ fe, rt }) => !q || `${fe.name} ${rt.target} ${routeSummary(rt)} ${(rt.hosts || []).join(' ')} ${rt.passUrl || ''}`.toLowerCase().includes(q));
  const binds = (fe) => { // compact: one entry per port ("80, 443 🔒")
    const seen = new Map();
    fe.binds.filter((b) => !b.commented).forEach((b) => b.addresses.forEach((a) => { const port = String(a).replace(/^.*:/, ''); seen.set(port, seen.get(port) || b.ssl); }));
    return [...seen].map(([port, ssl]) => `${port}${ssl ? ' 🔒' : ''}`).join(', ');
  };
  const mode = state.urlmapMode || 'normal';
  box.className = `urlmap um-${mode}`; $('#view-topology').classList.toggle('um-max', mode === 'max');
  if (mode === 'normal' && state.urlmapH) box.style.height = `${state.urlmapH}px`; else box.style.height = '';
  box.innerHTML = `<div class="urlmap-grip" data-um-grip title="Drag to resize"></div>
    <div class="urlmap-head"><b>URL map</b> <button class="link" type="button" data-flow-uri title="Ports, rewrites and a request tracer">Routing details →</button> <span class="muted small">${shown.length} of ${rows.length} routing rules${mode === 'min' ? '' : ' · click a row to focus it in the graph'}</span><span class="spacer"></span>
      <button class="btn icon" type="button" data-um="min" title="${mode === 'min' ? 'Restore' : 'Minimize'}" aria-label="${mode === 'min' ? 'Restore URL map' : 'Minimize URL map'}">${mode === 'min' ? '▴' : '▁'}</button>
      <button class="btn icon" type="button" data-um="max" title="${mode === 'max' ? 'Restore size' : 'Expand to full height'}" aria-label="${mode === 'max' ? 'Restore URL map size' : 'Expand URL map'}">${mode === 'max' ? '⤡' : '⤢'}</button>
      <button class="btn icon${document.body.classList.contains('fs-urlmap') ? ' on' : ''}" type="button" data-um-fs title="${document.body.classList.contains('fs-urlmap') ? 'Exit full screen (Esc)' : 'Full screen: only the URL map'}" aria-label="Full screen URL map">${document.body.classList.contains('fs-urlmap') ? '✕' : '⛶'}</button>
      <button class="btn icon" type="button" data-um="close" title="Close" aria-label="Close URL map">✕</button></div>
    <div class="urlmap-scroll"><table class="grid urlmap-table"><thead><tr><th>${esc(lbl('frontend'))}</th><th>Host</th><th>URL / path match</th><th>Target</th><th>${snapshotType() === 'nginx' ? 'Upstream URL' : 'Servers'}</th></tr></thead><tbody>
    ${shown.map(({ fe, rt, i }) => {
    const up = rt.passUrl ? `<code>${esc(rt.passUrl)}</code>${rt.rewriteNote ? `<div class="muted small">${esc(rt.rewriteNote)}</div>` : ''}${(rt.rewrites || []).map((r) => `<div class="muted small mono">rewrite ${esc(r)}</div>`).join('')}` : `<span class="mono small">${esc(poolAddresses(rt.target))}</span>`;
    const missing = routeTargetId(rt).startsWith('missing:');
    return `<tr class="${rt.commented ? 'dim' : ''}" data-urlrow="${esc(fe.name)}|${i}">
        <td><b>${esc(fe.name)}</b> ${layerTag(fe)}<div class="muted small mono">${esc(binds(fe))}</div></td>
        <td class="mono small">${esc((rt.hosts || []).join(', ')) || '<span class="muted">any</span>'}</td>
        <td>${rt.type === 'default' ? '<span class="tag">default</span> <span class="muted">everything else</span>' : `<span class="mono">${esc(rt.match || rt.condition)}</span>`}${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}${snapshotType() === 'haproxy' && rt.rawCondition ? `<div class="muted small mono">${esc(rt.rawCondition)}</div>` : ''}</td>
        <td>${missing ? `<span class="sev-error">${esc(rt.target)} (undefined)</span>` : `<b>${esc(rt.target)}</b>`}</td>
        <td>${up}</td></tr>`;
  }).join('') || '<tr><td colspan="5" class="empty">No routing rules</td></tr>'}</tbody></table></div>`;
}
function renderTopology() {
  updateLegend();
  { // layer filter with counts
    const sel = $('#topo-layer');
    if (sel && state.snapshot) {
      const secs = cfgSections().filter((x) => x.type !== 'defaults' && (feLike(x) || beLike(x)));
      const n7 = secs.filter((x) => layerOf(x) === 'L7').length; const n4 = secs.length - n7; const keep = sel.value;
      const html = `<option value="">All layers</option><option value="L7">L7 · HTTP (${n7})</option><option value="L4">L4 · TCP (${n4})</option>`;
      if (sel.dataset.sig !== html) { sel.innerHTML = html; sel.dataset.sig = html; sel.value = keep; }
      sel.hidden = !n7 || !n4; if (sel.hidden) sel.value = '';
    }
  }
  if (state.topoFor !== state.current && state.snapshot) {
    // Many members make the map unreadable once fitted to the screen: start collapsed, expand on focus.
    state.topoFor = state.current; collapsedSet().clear();
    const total = cfgSections().reduce((n, x) => n + x.servers.filter((v) => !v.commented).length, 0);
    $('#topo-servers').checked = total <= 18;
    $('#graph-hint').textContent = total <= 18 ? 'Click a node to focus its path · shift-click to collapse or expand it · double-click or “Open details” for the full page · click empty space to reset · scroll to zoom'
      : `${total} members are collapsed — click a ${lbl('backend').toLowerCase()} to expand it, or tick “Members” to show all · scroll to zoom`;
    $('#graph-hint').style.opacity = 1;
  }
  if (typeof vis === 'undefined') { $('#graph').innerHTML = '<div class="empty">vis-network failed to load</div>'; return; }
  renderUrlMap();
  const mode = $('#topo-layout').value;
  const treeOn = mode === 'tree'; const netOn = mode === 'network'; const alt = treeOn || netOn;
  $('#tree').hidden = !treeOn; $('#infra').hidden = !netOn; $('#graph-wrap').hidden = alt;
  $$('#view-topology [data-graph-only]').forEach((el) => { el.hidden = alt; });
  ['topo-search', 'topo-problems'].forEach((id) => { const e = $(`#${id}`); if (e) (e.closest('label') || e).hidden = netOn; });
  if (netOn && $('#topo-layer')) $('#topo-layer').hidden = true;
  if (netOn) { renderLbInfra(); return; }
  if (treeOn) { renderTree(); return; }
  const { nodes, edges } = buildGraph();
  let layersSig = null;
  if (mode === 'layers') {
    layoutLayers(nodes, edges);
    // Keep positions the user dragged to while nothing structural changed (the poll re-renders every few seconds).
    layersSig = nodes.map((n) => n.id).sort().join('|');
    if (layersSig === state.layersSig && network) nodes.forEach((n) => { delete n.x; delete n.y; });
  } else layerGuides = null;
  state.layersSig = layersSig;
  if (!network) {
    // Tall tiers (many pools/members) read better top-down on a landscape screen than left-to-right.
    const perTier = {};
    nodes.forEach((n) => { perTier[n.level] = (perTier[n.level] || 0) + 1; });
    const dir = Math.max(...Object.values(perTier), 0) > 6 ? 'UD' : 'LR';
    visNodes = new vis.DataSet(nodes); visEdges = new vis.DataSet(edges);
    network = new vis.Network($('#graph'), { nodes: visNodes, edges: visEdges }, graphOptions(mode, dir));
    network.on('beforeDrawing', drawLayerGuides);
    network.on('click', (p) => {
      if (p.nodes.length) {
        const n = visNodes.get(p.nodes[0]); const ev = p.event && p.event.srcEvent;
        if (ev && (ev.shiftKey || ev.ctrlKey || ev.altKey || ev.metaKey) && /^(fe|be):/.test(n.id)) { toggleCollapse(n.id); return; }
        state.focus = n.id; topoSelect(n);
        renderTopology();
      } else if (p.edges.length) { const e = visEdges.get(p.edges[0]); if (e && e._route) topoSelect(null, e._route); }
      else { const had = state.focus; state.focus = null; topoSelect(null); if (had) renderTopology(); }
    });
    network.on('doubleClick', (p) => {
      if (p.nodes.length) { const n = visNodes.get(p.nodes[0]); if (n && n._key) inspect(n._key, n._kind); else if (n && n._kind === 'missing') inspectMissing(n.id.slice(8)); }
      else if (p.edges.length) { const e = visEdges.get(p.edges[0]); if (e && e._route) inspectRoute(e._route); }
    });
    network.once('stabilized', () => { const h = $('#graph-hint'); if (h) setTimeout(() => { h.style.opacity = 0; }, 6000); });
    // The container may not have its final size yet (view just activated): refit once layout settles.
    [80, 400, 1200].forEach((ms) => setTimeout(() => network && network.fit({ animation: false }), ms));
    return;
  }
  const have = new Set(visNodes.getIds());
  const nextIds = new Set(nodes.map((n) => n.id));
  const firstTime = have.size === 0;
  visNodes.update(nodes);
  have.forEach((id) => { if (!nextIds.has(id)) visNodes.remove(id); });
  const haveE = new Set(visEdges.getIds()); const nextE = new Set(edges.map((e) => e.id));
  visEdges.update(edges); haveE.forEach((id) => { if (!nextE.has(id)) visEdges.remove(id); });
  if (firstTime) network.fit({ animation: false });
}

function exportPng() {
  if (!network) return;
  const src = network.canvas.frame.canvas; const c = document.createElement('canvas');
  c.width = src.width; c.height = src.height;
  const x = c.getContext('2d'); x.fillStyle = cssVar('--bg') || '#0a0f1a'; x.fillRect(0, 0, c.width, c.height); x.drawImage(src, 0, 0);
  c.toBlob((b) => { downloadBlob(`${(state.snapshot.instance.name || 'topology').replace(/[^\w.-]+/g, '_')}-topology.png`, b); toast('Diagram saved as PNG', 'ok'); });
}


// ---------- URL / URI mapping details ----------
// Short "what does this rule match" text for node labels: host + path, e.g. "api.example.com /v1/*".
function routeUri(rt) {
  if (rt.type === 'default') return 'default: everything else';
  const hosts = (rt.hosts || []).join(',');
  const path = (rt.short || rt.match || rt.condition || '').replace(/^location /, '');
  return hosts && !path.includes(hosts) ? `${hosts} ${path}`.trim() : path;
}
const routeSummary = (rt) => (rt.type === 'default' ? 'Any request not matched above (default)' : rt.match || rt.condition);
// The traffic-flow analysis (ports, TLS, URI change) for one routing rule, when it has been loaded.
function flowOf(fe, rt) {
  if (!FLOW.data || FLOW.key !== state.current || rt.commented) return null;
  const name = typeof fe === 'string' ? fe : fe.name;
  return FLOW.data.flows.find((f) => f.frontend === name && f.line === rt.line && f.pool.name === rt.target) || null;
}
function flowLines(f) {
  if (!f) return [];
  const l = f.portMap.map((p) => `${p.listenerTls ? '🔒' : ''}:${p.in} → ${p.out.length ? p.out.map((o) => `:${o}`).join(' ') : '?'} (${TLS_LABEL[p.tls] || p.tls})`);
  if (f.example && f.example.changed) l.push(`Backend receives: ${f.example.in} → ${f.example.out}${f.example.exact ? '' : ' (approx.)'}`);
  return l;
}
function routeTitle(fe, rt) {
  const lines = [`${fe.name} → ${rt.target}${rt.commented ? ' (disabled)' : ''}`, `Match: ${routeSummary(rt)}`, ...flowLines(flowOf(fe, rt))];
  if (rt.hosts && rt.hosts.length) lines.push(`Host: ${rt.hosts.join(', ')}`);
  if (rt.passUrl) lines.push(`${rt.passDirective || 'pass'}: ${rt.passUrl}`);
  if (rt.rewriteNote) lines.push(rt.rewriteNote);
  (rt.rewrites || []).forEach((r) => lines.push(`rewrite ${r}`));
  return lines.join('\n');
}
function poolAddresses(name) {
  const sec = cfgSections().find((x) => x.name === name && (x.type === 'backend' || x.type === 'listen' || x.type === 'upstream'));
  const list = sec ? sec.servers.filter((x) => !x.commented).map((x) => x.address || x.name) : [];
  return list.length ? `${list.slice(0, 3).join(', ')}${list.length > 3 ? ` +${list.length - 3}` : ''}` : '';
}
function routeTargetId(rt) {
  const sec = cfgSections().find((x) => x.name === rt.target && (x.type === 'backend' || x.type === 'listen' || x.type === 'upstream'));
  return sec ? (sec.type === 'listen' ? `fe:${sec.name}` : `be:${sec.name}`) : `missing:${rt.target}`;
}
// Full screen: the topology fills the window (sidebar/header hidden). Uses the browser Fullscreen API when allowed, else just fills the tab.
function setTopoFs(on, mode) {
  // mode: 'map' = only the mind map / tree, 'urlmap' = only the URL map table (independent of each other); anything else = the whole page area
  document.body.classList.toggle('topo-fs', on);
  document.body.classList.toggle('fs-map', Boolean(on && mode === 'map'));
  document.body.classList.toggle('fs-urlmap', Boolean(on && mode === 'urlmap'));
  const b = $('#topo-fs'); if (b) { const m = Boolean(on && mode === 'map'); b.textContent = m ? '✕ Exit full screen' : '⛶ Full screen'; b.classList.toggle('on', m); }
  const u = $('[data-um-fs]'); if (u) { const m = Boolean(on && mode === 'urlmap'); u.textContent = m ? '✕' : '⛶'; u.classList.toggle('on', m); u.title = m ? 'Exit full screen (Esc)' : 'Full screen: only the URL map'; }
  $$('[data-fs]').forEach((x) => { x.textContent = on ? '✕ Exit full screen' : '⛶ Full screen'; x.classList.toggle('on', on); x.setAttribute('aria-pressed', String(on)); });
  const g = $('#gr-fs'); if (g) { g.textContent = on ? '✕ Exit full screen' : '⛶ Full screen'; g.classList.toggle('on', on); g.setAttribute('aria-pressed', String(on)); }
  if (state.view === 'graphs') setTimeout(() => { if (typeof grPaintCards === 'function') grPaintCards(); }, 160);
  if (on && document.documentElement.requestFullscreen && !document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => { /* still fills the tab */ });
  if (!on && document.fullscreenElement) document.exitFullscreen().catch(() => {});
  setTimeout(() => { if (network) { network.setSize('100%', '100%'); network.redraw(); network.fit({ animation: false }); } }, 120);
}
function toggleTopoFs() { setTopoFs(!document.body.classList.contains('topo-fs')); }
function toggleMapFs() { setTopoFs(!document.body.classList.contains('fs-map'), 'map'); }
function toggleUrlmapFs() { setTopoFs(!document.body.classList.contains('fs-urlmap'), 'urlmap'); setTimeout(renderUrlMap, 0); }
/** "Relationships" card: who sends traffic here, where this sends it, and its siblings. Uses the config when present,
 *  otherwise falls back to what runtime stats imply (server -> its backend, backend -> its servers). */
function relationsHtml(r, proxy, sec, srv) {
  const rows = state.snapshot.rows; const idx = indexRows(rows);
  const node = (key, label, sub, kindTag) => {
    const row = idx.get(key);
    return `<div class="item" data-inspect="${esc(key)}">${row ? stBadge(row.state, row.status) : '<span class="tag">cfg</span>'}<div class="t"><b>${esc(label)}</b> ${kindTag ? `<span class="tag">${esc(kindTag)}</span>` : ''}${sub ? `<div class="muted small mono">${esc(sub)}</div>` : ''}</div></div>`;
  };
  const group = (title, items, empty) => `<div class="rel-g"><div class="rel-t">${title}</div>${items.length ? `<div class="list">${items.join('')}</div>` : `<div class="muted small">${empty}</div>`}</div>`;
  const feKey = (n) => `${n}/FRONTEND`; const beKey = (n) => `${n}/BACKEND`;
  const poolKey = (n) => { const t = cfgSections().find((x) => x.name === n); return t && t.type === 'listen' ? feKey(n) : beKey(n); };
  const viaRoutes = (target) => cfgSections().filter(feLike).flatMap((fe) => fe.routes.filter((rt) => rt.target === target && fe.name !== target).map((rt) => ({ fe, rt })));
  const ruleText = (rt) => (rt.type === 'default' ? 'default: any other request' : (rt.match || rt.condition || ''));
  const groups = [];
  if (r.kind === 'server' || r.kind === 'backend') {
    const from = sec ? viaRoutes(proxy) : [];
    groups.push(group('Receives traffic from', from.map(({ fe, rt }) => node(feKey(fe.name), fe.name, ruleText(rt), 'frontend')), sec ? 'No frontend routes here (unused, or only reached via default_backend of a defaults block)' : 'Unknown without the config'));
  }
  if (r.kind === 'server') {
    groups.push(group('Member of', [node(beKey(proxy), proxy, sec ? `${sec.servers.filter((x) => !x.commented).length} servers${sec.balance ? ` · ${sec.balance}` : ''}` : '', sec ? sec.type : 'backend')], ''));
    const sib = rows.filter((x) => x.proxy === proxy && x.kind === 'server' && x.name !== r.name);
    if (sib.length) groups.push(group(`Sibling servers (${sib.length})`, sib.map((x) => node(`${proxy}/${x.name}`, x.name, rowEndpoints(x).addrs[0] || '')), ''));
  } else if (r.kind === 'backend') {
    const sv = rows.filter((x) => x.proxy === proxy && x.kind === 'server');
    groups.push(group(`Sends traffic to (${sv.length} servers)`, sv.map((x) => node(`${proxy}/${x.name}`, x.name, rowEndpoints(x).addrs[0] || '', 'server')), 'No servers reported'));
  } else if (r.kind === 'frontend') {
    const routes = sec ? sec.routes.filter((rt) => !rt.commented) : [];
    groups.push(group(`Routes to (${routes.length})`, routes.map((rt) => {
      const missing = !cfgSections().some((x) => x.name === rt.target && x.type !== 'frontend');
      return missing ? `<div class="item" ${loc(rt)}><span class="st st-down">missing</span><div class="t"><b>${esc(rt.target)}</b><div class="muted small mono">${esc(ruleText(rt))}</div></div></div>`
        : node(poolKey(rt.target), rt.target, ruleText(rt), 'backend');
    }), sec ? 'No routing rules' : 'Unknown without the config'));
  }
  const hint = sec ? '' : `<div class="rel-hint">Runtime stats do not say which frontend routes to which backend. Attach the config (Settings → edit connection → config path or paste) to see the full chain.</div>`;
  return `<h4>Relationships</h4>${groups.join('')}${hint}`;
}
// Where a row lives: listening ports (frontend), member endpoints (backend) or its parent pool (server).
function endpointsHtml(r, sec, srv) {
  if (!sec) return '';
  const st = new Map(state.snapshot.rows.filter((x) => x.proxy === sec.name && x.kind === 'server').map((x) => [x.name, x]));
  if (srv) return `<h4>Endpoint</h4>${kv([['Address', `<code>${esc(srv.address || '–')}</code>`], ['Port', esc(portOf(srv.address) || '–')], ['Member of', `<b>${esc(sec.name)}</b> <span class="muted">(${esc(sec.type)})</span>`]])}`;
  let html = '';
  const binds = sec.binds.filter((b) => !b.commented);
  if (binds.length) html += `<h4>Listening on</h4><div class="list">${binds.map((b) => `<div class="item" ${loc(b)}><span class="tag">${esc(portOf(b.addresses[0]) || 'port')}</span><div class="t mono small">${esc(b.addresses.join(', '))}${b.ssl ? ' 🔒 TLS' : ''}</div></div>`).join('')}</div>`;
  const svs = sec.servers.filter((x) => !x.commented);
  if (svs.length) html += `<h4>Servers (${svs.length})</h4><div class="list">${svs.map((x) => { const row = st.get(x.name); return `<div class="item" data-inspect="${esc(sec.name)}/${esc(x.name)}">${row ? stBadge(row.state, row.status) : '<span class="tag">cfg</span>'}<div class="t"><b>${esc(x.name)}</b><div class="mono small muted">${esc(x.address)}</div></div></div>`; }).join('')}</div>`;
  return html;
}
function urlMappingsHtml(sec, reachedOnly) {
  let html = '';
  const item = (rt, text, extra) => `<div class="item" ${loc(rt)}><span class="tag">${rt.type === 'default' ? 'default' : 'match'}</span><div class="t mono small">${text}${extra || ''}</div></div>`;
  if (!reachedOnly && sec.routes && sec.routes.length) {
    html += `<h4>URL mappings</h4><div class="list">${sec.routes.map((rt) => item(rt, `${esc(rt.type === 'default' ? 'any other request' : (rt.match || rt.condition))} → <b>${esc(rt.target)}</b>${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}`,
      `${rt.passUrl ? `<div class="muted">${esc(rt.passUrl)}</div>` : ''}${rt.rewriteNote ? `<div class="muted">${esc(rt.rewriteNote)}</div>` : ''}`)).join('')}</div>`;
  }
  const from = cfgSections().filter(feLike).flatMap((fe) => fe.routes.filter((rt) => rt.target === sec.name && fe.name !== sec.name).map((rt) => ({ fe, rt })));
  if (from.length) html += `<h4>Reached via</h4><div class="list">${from.map(({ fe, rt }) => item(rt, `<b>${esc(fe.name)}</b>: ${esc(rt.type === 'default' ? 'default' : (rt.match || rt.condition))}${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}`)).join('')}</div>`;
  return html;
}

// ---------- "Tree" layout: the whole estate as an outline, like the `tree` command ----------
let treeText = '';
function buildTree() {
  const s = state.snapshot; const rows = indexRows(s.rows); const secs = cfgSections();
  const q = $('#topo-search').value.trim().toLowerCase(); const onlyProblems = $('#topo-problems').checked;
  const mk = (html, text, o = {}) => ({ html, text, children: [], ...o });
  const ports = (r) => { const e = rowEndpoints(r); return e.ports.length ? ` :${e.ports.slice(0, 4).join(',')}${e.ports.length > 4 ? '…' : ''}` : ''; };
  const rate = (r) => (r && r.ratePerSec != null ? ` ${fmtRate(r.ratePerSec)}/s` : '');
  const badge = (r) => (r ? stBadge(r.state, r.status) : '');
  const serverNodes = (sec) => sec.servers.filter((x) => !x.commented).map((sv) => {
    const r = rows.get(`${sec.name}/${sv.name}`);
    return mk(`${badge(r)} <b>${esc(sv.name)}</b> <span class="mono muted">${esc(sv.address || '')}</span>`, `${sv.name}  ${sv.address || ''}${r ? `  [${r.state}]` : ''}`, { key: `${sec.name}/${sv.name}`, kind: 'server', problem: Boolean(r && isProblem(r)) });
  });
  const poolNode = (sec, via) => {
    const r = rows.get(`${sec.name}/BACKEND`) || rows.get(`${sec.name}/FRONTEND`);
    const kids = serverNodes(sec);
    return mk(`${badge(r)} <b>${esc(sec.name)}</b> <span class="tag">${esc(lbl('backend').toLowerCase())}</span> ${layerTag(sec)}${sec.balance ? ` <span class="muted small">${esc(sec.balance)}</span>` : ''}<span class="muted small">${esc(rate(r))}</span>`,
      `${sec.name}  (${lbl('backend').toLowerCase()}, ${layerOf(sec)}${sec.balance ? `, ${sec.balance}` : ''})${r ? `  [${r.state}]` : ''}`, { key: `${sec.name}/BACKEND`, kind: 'backend', children: kids, problem: Boolean(r && isProblem(r)) || kids.some((k) => k.problem), via });
  };
  const fronts = secs.filter(feLike).map((fe) => {
    const r = rows.get(`${fe.name}/FRONTEND`);
    const kids = [];
    fe.routes.forEach((rt) => {
      if (rt.dynamic) return;
      const tgt = secs.find((x) => x.name === rt.target && beLike(x) && x.name !== fe.name);
      const uri = routeUri(rt);
      const rule = mk(`<span class="uri">${esc(uri)}</span>${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}${rt.passUrl ? ` <span class="muted small mono">→ ${esc(rt.passUrl)}</span>` : ''}`, `${uri}${rt.commented ? ' (disabled)' : ''}`, { kind: 'rule', dim: rt.commented });
      rule.children = tgt ? [poolNode(tgt)] : [mk(`<span class="st st-down">undefined</span> <b>${esc(rt.target)}</b>`, `${rt.target}  [undefined]`, { kind: 'missing', problem: true })];
      kids.push(rule);
    });
    if (fe.type === 'listen') kids.push(...serverNodes(fe));
    return mk(`${badge(r)} <b>${esc(fe.name)}</b> <span class="tag">${esc(lbl('frontend').toLowerCase())}</span> ${layerTag(fe)} <span class="mono muted">${esc(ports({ kind: 'frontend', proxy: fe.name }).trim())}</span>${fe.binds.some((b) => b.ssl && !b.commented) ? ' 🔒' : ''}<span class="muted small">${esc(rate(r))}</span>`,
      `${fe.name}  (${lbl('frontend').toLowerCase()}, ${layerOf(fe)}${ports({ kind: 'frontend', proxy: fe.name }) ? `,${ports({ kind: 'frontend', proxy: fe.name })}` : ''})${r ? `  [${r.state}]` : ''}`, { key: `${fe.name}/FRONTEND`, kind: 'frontend', children: kids, problem: Boolean(r && isProblem(r)) });
  });
  const used = new Set(secs.filter(feLike).flatMap((fe) => fe.routes.filter((rt) => !rt.commented).map((rt) => rt.target)));
  const stray = secs.filter((x) => x.type === 'backend' && !used.has(x.name)).map((x) => poolNode(x));
  const root = mk(`<b>${esc(s.instance.name || 'Instance')}</b> <span class="muted small">${esc(TYPE_NAME[snapshotType()] || '')}</span>`, s.instance.name || 'Instance', { kind: 'root' });
  root.children = [...fronts];
  if (stray.length) root.children.push(mk(`<b>Not routed</b> <span class="muted small">no frontend sends traffic here</span>`, 'Not routed (no frontend sends traffic here)', { kind: 'group', children: stray }));
  // filter: keep a node when it or any descendant matches; problems-only keeps branches with a problem
  const keep = (n) => { n.children = n.children.filter(keep); const self = !q || n.text.toLowerCase().includes(q); return (n.kind === 'root') || ((self || n.children.length) && (!onlyProblems || n.problem || n.children.length)); };
  keep(root);
  return root;
}
function treeAscii(n, prefix = '', last = true, top = true) {
  let out = top ? `${n.text}\n` : `${prefix}${last ? '└── ' : '├── '}${n.text}\n`;
  const next = top ? '' : prefix + (last ? '    ' : '│   ');
  n.children.forEach((c, i) => { out += treeAscii(c, next, i === n.children.length - 1, false); });
  return out;
}
function renderTree() {
  const root = buildTree(); treeText = treeAscii(root);
  const li = (n) => `<li class="${n.children.length ? 'has' : ''}${n.dim ? ' dim' : ''}${closedTree.has(n.text) ? ' closed' : ''}"><div class="tn k-${n.kind}"${n.key ? ` data-inspect="${esc(n.key)}"` : ''} data-tk="${esc(n.text)}">${n.children.length ? `<span class="tg" data-tg>${closedTree.has(n.text) ? '▸' : '▾'}</span>` : '<span class="tg lf">•</span>'}${n.html}</div>${n.children.length ? `<ul>${n.children.map(li).join('')}</ul>` : ''}</li>`;
  $('#tree').innerHTML = `<div class="tree-bar"><b>Tree</b> <span class="muted small">${root.children.length ? 'click ▾ to fold · click a name for details' : ''}</span><span class="spacer"></span><button class="btn" type="button" data-tree="open">Expand all</button><button class="btn" type="button" data-tree="close">Collapse all</button><button class="btn" type="button" data-tree="copy">Copy as text</button></div>
    <ul class="tree root">${li(root)}</ul>${root.children.length ? '' : '<div class="empty">Nothing to show. Attach a config to see the structure.</div>'}`;
}
const closedTree = new Set();

// ---------- "Layers" layout: entry points on top, pools below, members under them; unconnected items collected on the left ----------
let layerGuides = null;
const LY = { slot: 170, mem: 66, rowY: 230, strayMemPerRow: 3, strayGap: 150 };

function layoutLayers(nodes, edges) {
  layerGuides = null;
  if (!nodes.length) return;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const routeEdges = edges.filter((e) => String(e.id).startsWith('r:') && !(e._route && e._route.commented) && byId.has(e.from) && byId.has(e.to));
  const members = new Map(); // parent id -> member nodes (sv:)
  edges.filter((e) => String(e.id).startsWith('e:sv:')).forEach((e) => { if (byId.has(e.from) && byId.has(e.to)) (members.get(e.from) || members.set(e.from, []).get(e.from)).push(byId.get(e.to)); });
  const wired = new Set();
  routeEdges.forEach((e) => { wired.add(e.from); wired.add(e.to); });
  nodes.filter((n) => n._pool || n._collapsed).forEach((n) => wired.add(n.id)); // a `listen` with servers is its own pool; a collapsed entry point keeps its place
  const isMember = (n) => n.id.startsWith('sv:');

  const stray = nodes.filter((n) => !isMember(n) && !wired.has(n.id));
  const fes = nodes.filter((n) => n._kind === 'frontend' && !n._pool && wired.has(n.id));
  const pools = nodes.filter((n) => !isMember(n) && wired.has(n.id) && !fes.includes(n));

  // order pools by the position of the entry points that reach them, entry points by name first
  fes.sort((a, b) => a.id.localeCompare(b.id));
  const feIdx = new Map(fes.map((n, i) => [n.id, i]));
  const bary = (n) => { const xs = routeEdges.filter((e) => e.to === n.id && feIdx.has(e.from)).map((e) => feIdx.get(e.from)); return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 1e6; };
  pools.sort((a, b) => bary(a) - bary(b) || a.id.localeCompare(b.id));

  const y0 = 0; const y1 = LY.rowY; const y2 = LY.rowY * 2 - 30;
  const center = new Map(); let cursor = 0;
  for (const n of pools) {
    const mem = members.get(n.id) || [];
    const w = Math.max(LY.slot, mem.length * LY.mem + 20);
    n.x = cursor + w / 2; n.y = y1; center.set(n.id, n.x);
    mem.forEach((m, j) => { m.x = cursor + (w - mem.length * LY.mem) / 2 + (j + 0.5) * LY.mem; m.y = y2 + (j % 2) * 34; });
    cursor += w + 24;
  }
  // entry points sit above the middle of the pools they route to
  const desired = fes.map((n) => {
    const xs = routeEdges.filter((e) => e.from === n.id && center.has(e.to)).map((e) => center.get(e.to));
    return { n, x: xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0 };
  }).sort((a, b) => a.x - b.x);
  let last = -Infinity;
  for (const d of desired) { d.x = Math.max(d.x, last + LY.slot + 20); d.n.x = d.x; d.n.y = y0; last = d.x; }

  const placed = nodes.filter((n) => n.x != null);
  const minX = placed.length ? Math.min(...placed.map((n) => n.x)) : 0;
  placed.forEach((n) => { n.x -= minX - 30; });

  // unconnected items: a column on the left, each with its own members beside it
  let strayW = 0; let sy = y0;
  const strayOrder = [...stray.filter((n) => n._kind === 'frontend'), ...stray.filter((n) => n._kind !== 'frontend')];
  for (const n of strayOrder) {
    const mem = members.get(n.id) || [];
    n.x = 0; n.y = sy;
    mem.forEach((m, j) => { m.x = 120 + (j % LY.strayMemPerRow) * 100; m.y = sy + Math.floor(j / LY.strayMemPerRow) * 56; });
    strayW = Math.max(strayW, mem.length ? 120 + Math.min(mem.length, LY.strayMemPerRow) * 100 : 60);
    sy += Math.max(1, Math.ceil(mem.length / LY.strayMemPerRow)) * 56 + 78;
  }
  const strayShift = -(strayW + LY.strayGap);
  strayOrder.forEach((n) => { n.x += strayShift; (members.get(n.id) || []).forEach((m) => { m.x += strayShift; }); });
  edges.forEach((e) => { e.smooth = { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 }; if (e.label) e.font = { ...(e.font || {}), align: 'horizontal' }; });

  layerGuides = {
    labelX: -44,
    tiers: [fes.length && { y: y0, label: 'ENTRY POINTS' }, pools.length && { y: y1, label: 'POOLS' }, pools.some((n) => (members.get(n.id) || []).length) && { y: y2, label: 'MEMBERS' }].filter(Boolean),
    stray: strayOrder.length ? { x0: strayShift - 70, x1: strayShift + strayW + 40, y0: y0 - 62, y1: Math.max(sy, y0 + 80) - 16, count: strayOrder.length } : null,
    hasMain: fes.length + pools.length > 0,
  };
}

function drawLayerGuides(ctx) {
  const g = layerGuides; if (!g || $('#topo-layout').value !== 'layers') return;
  const muted = cssVar('--muted') || '#8b97ad'; const line = cssVar('--line') || '#243049';
  ctx.save();
  ctx.font = '600 11px system-ui'; ctx.textBaseline = 'middle'; ctx.textAlign = 'right'; ctx.fillStyle = muted; ctx.globalAlpha = 0.7;
  if (g.hasMain) for (const t of g.tiers) ctx.fillText(t.label, g.labelX, t.y);
  if (g.stray) {
    const s = g.stray; ctx.globalAlpha = 1;
    ctx.fillStyle = isLight() ? 'rgba(100,116,139,.07)' : 'rgba(148,163,184,.05)'; ctx.strokeStyle = line; ctx.setLineDash([6, 5]); ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.roundRect(s.x0, s.y0, s.x1 - s.x0, s.y1 - s.y0, 14); ctx.fill(); ctx.stroke(); ctx.setLineDash([]);
    ctx.textAlign = 'left'; ctx.fillStyle = muted; ctx.font = '600 11px system-ui';
    ctx.fillText(`NOT CONNECTED (${s.count})`, s.x0 + 14, s.y0 + 16);
  }
  ctx.restore();
}

function graphOptions(mode, dir = 'LR') {
  const flow = mode === 'flow';
  if (mode === 'layers') return { layout: { hierarchical: false }, physics: { enabled: false }, interaction: { hover: true, tooltipDelay: 150, navigationButtons: false }, nodes: { borderWidth: 2, scaling: { label: { enabled: false } } }, edges: { smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 }, font: { size: 9 } } };
  return {
    layout: flow ? { hierarchical: { enabled: true, direction: dir, sortMethod: 'directed', levelSeparation: dir === 'LR' ? 270 : 150, nodeSpacing: dir === 'LR' ? 104 : 130, treeSpacing: 90, shakeTowards: 'roots' } } : { hierarchical: false },
    physics: flow ? { enabled: false } : { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -150, springLength: 190, avoidOverlap: 0.8 }, stabilization: { iterations: 250 } },
    interaction: { hover: true, tooltipDelay: 150, navigationButtons: false },
    nodes: { borderWidth: 2, scaling: { label: { enabled: false, drawThreshold: 2 } } }, edges: { smooth: { type: 'cubicBezier', roundness: 0.4 }, font: { size: 9 } },
  };
}

// ---------- SERVICES ----------
const SVC_COLS = [
  { k: 'name', t: 'Name', cmp: (a, b) => a.proxy.localeCompare(b.proxy) || a.name.localeCompare(b.name) },
  { k: 'state', t: 'Status', cmp: (a, b) => String(a.state).localeCompare(b.state) },
  { k: 'addr', t: 'IP / address', nosort: 1 },
  { k: 'ports', t: 'Port', nosort: 1 },
  { k: 'frontends', t: 'Frontend(s)', nosort: 1 }, { k: 'targets', t: 'Backend / targets', nosort: 1 },
  { k: 'scur', t: 'Sessions', num: 1 }, { k: 'ratePerSec', t: 'Req/s', num: 1 }, { k: 'spark', t: 'Trend (rate)', nosort: 1 },
  { k: 'err5xxPerSec', t: '5xx/s', num: 1 }, { k: 'stot', t: 'Total', num: 1 }, { k: 'bout', t: 'In / Out', num: 1 },
  { k: 'rtime', t: 'Resp ms', num: 1 },
];
// Ports/endpoints come from the parsed config; runtime stats alone never carry them.
const portOf = (a) => { const m = /:(\d+)(?:\D*)$/.exec(String(a || '').replace(/^[a-z0-9]+@/i, '')); return m ? m[1] : ''; };
const uniq = (a) => [...new Set(a)];
function rowEndpoints(r) { // -> { ports: ['80','443'], addrs: ['10.0.0.1:8080'] }; config first, then what the stats report
  const sec = cfgSections().find((x) => x.name === r.proxy && x.type !== 'userlist');
  let addrs = [];
  if (sec) {
    if (r.kind === 'server') { const sv = sec.servers.find((x) => x.name === r.name); addrs = sv && sv.address ? [sv.address] : []; }
    else if (r.kind === 'frontend') addrs = sec.binds.filter((b) => !b.commented).flatMap((b) => b.addresses);
    else addrs = sec.servers.filter((x) => !x.commented && x.address).map((x) => x.address);
  }
  if (!addrs.length && state.snapshot) { // no config attached: use the address HAProxy reports for each server
    if (r.kind === 'server' && r.addr) addrs = [r.addr];
    else if (r.kind === 'backend') addrs = state.snapshot.rows.filter((x) => x.proxy === r.proxy && x.kind === 'server' && x.addr).map((x) => x.addr);
  }
  return { ports: uniq(addrs.map(portOf).filter(Boolean)), addrs: uniq(addrs) };
}
// Related components for the table: who routes to this row (frontends) and where it leads (targets).
function rowRelations(r) {
  const secs = cfgSections(); const hasCfg = secs.length > 0;
  const frontends = []; const targets = [];
  const via = (name) => secs.filter(feLike).filter((fe) => fe.name !== name && fe.routes.some((rt) => !rt.commented && rt.target === name)).map((fe) => fe.name);
  if (r.kind === 'frontend') {
    const sec = secs.find((x) => x.name === r.proxy && feLike(x));
    if (sec) sec.routes.filter((rt) => !rt.commented).forEach((rt) => targets.push({ key: `${rt.target}/BACKEND`, label: rt.target }));
  } else {
    via(r.proxy).forEach((n) => frontends.push({ key: `${n}/FRONTEND`, label: n }));
    if (r.kind === 'server') targets.push({ key: `${r.proxy}/BACKEND`, label: r.proxy });
  }
  const uq = (a) => a.filter((x, i) => a.findIndex((y) => y.key === x.key) === i);
  return { hasCfg, frontends: uq(frontends), targets: uq(targets) };
}
function relCell(list, hasCfg, extra) {
  if (!list.length) return extra || `<span class="muted" ${hasCfg ? '' : 'title="Attach the config to see routing"'}>–</span>`;
  const chip = (x) => `<span class="chip" data-inspect="${esc(x.key)}">${esc(x.label)}</span>`;
  return list.slice(0, 3).map(chip).join(' ') + (list.length > 3 ? ` <span class="muted" title="${esc(list.slice(3).map((x) => x.label).join(', '))}">+${list.length - 3}</span>` : '');
}
const ipOf = (a) => String(a || '').replace(/^[a-z0-9]+@/i, '').replace(/:\d+(?:\D*)$/, '');
function addrCell(r) {
  const { addrs } = rowEndpoints(r);
  if (!addrs.length) return '<span class="muted">–</span>';
  const ips = uniq(addrs.map(ipOf).filter(Boolean));
  const shown = (r.kind === 'server' ? addrs : ips).slice(0, 2).join(', ') + ((r.kind === 'server' ? addrs : ips).length > 2 ? ` +${(r.kind === 'server' ? addrs : ips).length - 2}` : '');
  return `<span class="mono small" title="${esc(addrs.join('\n'))}">${esc(shown)}</span>`;
}
function portsCell(r) {
  const { ports, addrs } = rowEndpoints(r);
  if (!ports.length) return '<span class="muted">–</span>';
  const shown = ports.slice(0, 4).join(', ') + (ports.length > 4 ? ` +${ports.length - 4}` : '');
  return `<span class="mono" title="${esc(addrs.join('\n'))}">${esc(shown)}</span>`;
}
function filteredRows() {
  const q = $('#svc-search').value.trim().toLowerCase(); const kind = $('#svc-kind').value; const st = $('#svc-state').value;
  return state.snapshot.rows.filter((r) => ['frontend', 'backend', 'server'].includes(r.kind)
    && (!q || `${r.proxy} ${r.name} ${rowEndpoints(r).addrs.join(' ')}`.toLowerCase().includes(q))
    && (!kind || r.kind === kind)
    && (!st || (st === 'problem' ? isProblem(r) : r.state === st)));
}
function renderServices() {
  const rows = filteredRows(); const { key, desc } = state.sort;
  let out = rows;
  if (key !== 'default') {
    const col = SVC_COLS.find((c) => c.k === key);
    const get = (r) => (r[key] == null ? -Infinity : r[key]);
    out = [...rows].sort((a, b) => (col && col.cmp ? col.cmp(a, b) : (get(a) > get(b) ? 1 : get(a) < get(b) ? -1 : 0)) * (desc ? -1 : 1));
  } else {
    const order = { frontend: 0, server: 1, backend: 2 };
    out = [...rows].sort((a, b) => a.proxy.localeCompare(b.proxy) || order[a.kind] - order[b.kind] || a.name.localeCompare(b.name));
    // HAProxy lists servers before the BACKEND aggregate; show aggregate first
    out.sort((a, b) => a.proxy.localeCompare(b.proxy) || ((a.kind === 'server') - (b.kind === 'server')) || a.name.localeCompare(b.name));
  }
  const head = `<thead><tr>${SVC_COLS.map((c) => `<th data-sort="${c.k}" class="${c.num ? 'num' : ''}${state.sort.key === c.k ? ` sorted${desc ? ' desc' : ''}` : ''}">${c.t}</th>`).join('')}</tr></thead>`;
  { const sc = $('#svc-charts'); if (sc) sc.innerHTML = svcCharts(rows); }
  const body = out.map((r) => `<tr class="k-${r.kind}" data-inspect="${esc(r.proxy)}/${esc(r.name)}">
    <td class="${r.kind === 'server' ? 'indent' : ''}"><span class="mono">${esc(r.proxy)}${r.kind === 'server' ? ` / ${esc(r.name)}` : ` <span class="tag">${esc(lbl(r.kind))}</span>`}</span></td>
    <td>${stBadge(r.state, r.status)}${(() => { const d = [r.check_status ? `${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}` : '', r.lastchg != null ? `for ${fmtDur(r.lastchg)}` : '', r.kind === 'server' && r.weight != null ? `weight ${fmtInt(r.weight)}` : ''].filter(Boolean).join(' · '); return d ? `<div class="small ${r.state === 'down' ? 'sev-error' : 'muted'}">${esc(d)}</div>` : ''; })()}</td><td>${addrCell(r)}</td><td>${portsCell(r)}</td>${(() => { const rel = rowRelations(r); const n = r.kind === 'backend' ? state.snapshot.rows.filter((x) => x.proxy === r.proxy && x.kind === 'server').length : 0;
      return `<td>${r.kind === 'frontend' ? '<span class="muted">–</span>' : relCell(rel.frontends, rel.hasCfg)}</td><td>${relCell(rel.targets, rel.hasCfg, n ? `<span class="muted">${n} server${n === 1 ? '' : 's'}</span>` : '')}</td>`; })()}<td class="num">${fmtInt(r.scur)}</td><td class="num">${fmtRate(r.ratePerSec)}</td>
    <td><button type="button" class="spark-btn" data-cv-row="${esc(r.proxy)}/${esc(r.name)}" title="Click for the full chart: zoom, pan, history" aria-label="Open the full traffic chart for ${esc(r.proxy)}${r.kind === 'server' ? ` / ${esc(r.name)}` : ''}">${sparkSvg(r.spark, { color: r.state === 'down' ? '#f87171' : '#22d3ee', w: 52 })}</button></td>
    <td class="num ${(r.err5xxPerSec || 0) > 0.05 ? 'sev-warning' : ''}">${fmtRate(r.err5xxPerSec)}</td><td class="num">${fmtInt(r.stot)}</td>
    <td class="num">${fmtBytes(r.bin)}<div class="muted small">${fmtBytes(r.bout)}</div></td><td class="num">${r.rtime != null ? r.rtime : '–'}</td></tr>`).join('');
  $('#svc-table').innerHTML = head + `<tbody>${body || `<tr><td colspan="13" class="empty">${state.snapshot.rows.length ? 'No rows match the filter' : 'No runtime statistics for this instance'}</td></tr>`}</tbody>`;
}
function exportCsv() {
  const rows = filteredRows().map((r) => { const e = rowEndpoints(r); const rel = rowRelations(r); return { ...r, ports: e.ports.join(' '), endpoints: e.addrs.join(' '), frontends: rel.frontends.map((x) => x.label).join(' '), targets: rel.targets.map((x) => x.label).join(' ') }; });
  const cols = ['proxy', 'name', 'kind', 'status', 'ports', 'endpoints', 'frontends', 'targets', 'scur', 'ratePerSec', 'err5xxPerSec', 'stot', 'bin', 'bout', 'rtime', 'weight', 'lastchg', 'check_status'];
  const q = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  download(`${state.current}-services.csv`, [cols.join(','), ...rows.map((r) => cols.map((c) => q(r[c])).join(','))].join('\n'), 'text/csv');
}
function downloadBlob(name, blob) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function download(name, text, type = 'text/plain') { downloadBlob(name, new Blob([text], { type })); }

// ---------- toasts / theme ----------
function toast(msg, kind = 'info', ms = 3600) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`; el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
}
function applyTheme(pref) {
  if (pref === 'light' || pref === 'dark') document.documentElement.dataset.theme = pref; else delete document.documentElement.dataset.theme;
  if (network) { network.destroy(); network = null; }
  if (state.snapshot) renderView(state.view);
}
function cycleTheme() {
  const order = ['dark', 'light', 'auto']; const cur = loadPref('gatelight.theme', 'dark');
  const next = order[(order.indexOf(cur) + 1) % 3];
  savePref('gatelight.theme', next); applyTheme(next); toast(`Theme: ${next}`);
}

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
  const intro = `<header class="flow-head val-head"><div><h2>Traffic flow</h2><p class="muted">Follow a request from the listener port to the backend port, and see exactly what the backend receives.</p></div><details class="flow-how"><summary>How to read this</summary><p class="muted small">Where each listener port leads, which pool and member port it reaches, whether TLS ends or restarts on the way, and what the backend receives as the URI. ${snap.instance.type === 'haproxy' ? 'An omitted server port follows the port the client used; <code>+N</code> adds to it; the server <code>port</code> option only moves health checks.' : 'A URI in <code>proxy_pass</code> replaces the matched location prefix.'} Everything is read from the configuration; nothing is sent to your servers.</p></details></header>`;
  if (FLOW.loading && !d) { el.innerHTML = `${intro}<div class="skeleton-cards"><i></i><i></i><i></i></div>`; return; }
  if (FLOW.err) { el.innerHTML = `${intro}<div class="panel"><div class="empty">${esc(FLOW.err)}${/no configuration/i.test(FLOW.err) ? '<br>Attach the config (Settings → edit connection) to see how traffic is mapped.' : ''}</div></div>`; return; }
  if (!d) { el.innerHTML = intro; return; }
  const ports = flowPorts(); const hap = d.product === 'haproxy';
  const fes = [...new Set(d.flows.map((f) => f.frontend))];
  const flows = d.flows.filter((f) => (!FLOW.fe || f.frontend === FLOW.fe) && flowPass(f));
  const rq = FLOW.req;
  const form = `<div class="panel flow-try"><h3 class="flow-h">Try a request</h3>
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
      <p class="muted small flow-note">${hap ? 'HAProxy: <code>server s 10.0.0.1</code> (no port) uses the same port the client connected to; <code>10.0.0.1:+1000</code> adds 1000 to it; an explicit port always wins.' : 'NGINX: a <code>proxy_pass</code> or upstream <code>server</code> without a port uses 80 (443 for https://).'}</p>`;
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
  el.innerHTML = `${intro}${form}${stats}${chips}${body}${finds.length ? `<div class="flow-finds"><h3 class="flow-h flow-fh">Routing findings</h3>${finds.map(card).join('')}</div>` : ''}`;
}

// ---------- PROFILE ----------
function renderProfile() {
  const m = state.meta || {}; const u = m.authUser ? String(m.authUser) : '';
  const left = m.authExp ? Math.max(0, m.authExp - Date.now()) : 0; const hrs = Math.floor(left / 3600e3); const mins = Math.floor((left % 3600e3) / 60000);
  const mine = state.instances.filter((i) => i.managed).length;
  const theme = isLight() ? 'Light' : 'Dark';
  $('#view-profile').innerHTML = `
    <div class="panel narrow prof-head"><span class="avatar big" aria-hidden="true">${esc((u[0] || '?').toUpperCase())}</span>
      <div class="prof-id"><h2>${esc(u || 'Not signed in')}</h2><div class="muted">${u ? 'Signed in to GateLight' : 'Sign-in is turned off on this server'}</div></div>
      ${u ? '<button type="button" class="btn" data-logout>Sign out</button>' : ''}</div>
    <div class="panel narrow"><h2>Account</h2>
      <div class="kv"><span>Username</span><span class="mono">${esc(u || '–')}</span><span>Sign-in method</span><span>${m.authEnabled ? 'Password' : 'None (open access)'}</span><span>GateLight version</span><span class="mono">${esc(m.version || '–')}</span></div></div>
    <div class="panel narrow"><h2>Session</h2>
      <div class="kv"><span>Signed in until</span><span>${m.authExp ? esc(fmtDateTime(m.authExp)) : '–'}</span><span>Time left</span><span>${m.authExp ? `${hrs} h ${mins} min` : '–'}</span><span>Session length</span><span>${m.sessionHours ? `${m.sessionHours} h` : '–'}</span></div>
      <p class="muted small">The session lasts for the configured length, then you sign in again. <code>AUTH_SESSION_HOURS</code> sets it on the server. Signing out ends it at once on this browser.</p></div>
    <div class="panel narrow"><h2>This browser</h2>
      <div class="kv"><span>Theme</span><span>${theme} <button type="button" class="link" data-prof-theme>switch</button></span><span>Auto-refresh</span><span>${esc({ auto: 'Auto (follows the server)', off: 'Paused' }[refreshSetting()] || `Every ${Number(refreshSetting()) / 1000} s`)}</span><span>Your private connections</span><span>${mine} <button type="button" class="link" data-goto="settings">manage</button></span></div></div>
    <div class="panel narrow"><h2>Password</h2>
      <p class="muted small">The password is set on the server, not in the browser. To change it, set <code>AUTH_PASS</code> (or a hash in <code>AUTH_PASS_HASH</code>) in <code>.env</code> and restart GateLight. Everyone is signed out when you do.</p></div>`;
}

// ---------- EVENTS ----------
/** "Right now": what is already down or out of rotation. The timeline below only knows about changes seen while GateLight was running, so a server that was down before that would otherwise never appear. */
function eventsNowHtml() {
  const snap = state.snapshot; const rows = snap && snap.rows ? snap.rows : [];
  const bad = rows.filter((r) => (r.kind === 'server' || r.kind === 'backend') && ['down', 'maint', 'drain'].includes(r.state));
  const lab = { down: 'DOWN', maint: 'Maintenance', drain: 'Draining' };
  const sorted = bad.sort((a, b) => (a.state === 'down' ? 0 : 1) - (b.state === 'down' ? 0 : 1) || (b.lastchg || 0) - (a.lastchg || 0));
  const line = (r) => {
    const how = r.lastchg != null && r.lastchg >= 0 ? `for ${fmtDur(r.lastchg)}` : '';
    const why = r.check_status ? `${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}${r.last_chk ? ` · ${r.last_chk}` : ''}` : '';
    const name = r.kind === 'backend' ? `${r.proxy} <span class="tag">pool</span>` : `${esc(r.proxy)} / ${esc(r.name)}`;
    return `<tr data-inspect="${esc(r.proxy)}/${esc(r.name)}"><td><i class="dot ${r.state === 'down' ? 'c-down' : 'c-warn'}"></i></td><td><b>${name}</b></td><td class="lv-${r.state === 'down' ? 'critical' : 'warning'}">${lab[r.state]}${how ? ` <span class="muted">${esc(how)}</span>` : ''}</td><td class="muted small">${esc(why)}</td></tr>`;
  };
  const total = rows.filter((r) => r.kind === 'server').length;
  return `<div class="panel ev-now"><h3 class="flow-h">Right now</h3>${sorted.length
    ? `<p class="muted small">${sorted.length} item${sorted.length === 1 ? '' : 's'} down or out of rotation (of ${total} servers). The duration is how long HAProxy has reported this state. Click a row for details.</p><table class="grid"><tbody>${sorted.map(line).join('')}</tbody></table>`
    : `<p class="ev-ok">✓ Nothing is down or out of rotation${total ? ` (${total} servers checked)` : ''}.</p>`}</div>`;
}
// ---- graphs on the Events page: server health over time, and who is down or flapping ----
const EV = { inst: null, hist: null, loading: false };
async function evLoadHistory() {
  if (EV.loading || !state.current || state.current === '__analysis') return;
  EV.loading = true; const id = state.current;
  try { const d = await api(`/instances/${encodeURIComponent(id)}/history-all?range=1440&max=240`); if (id === state.current) { EV.hist = (d && d.summary) || []; EV.inst = id; } } catch { EV.inst = id; EV.hist = []; }
  EV.loading = false;
  if (state.view === 'events') renderEvents();
}
function eventsChartsHtml(real) {
  const rows = (state.snapshot && state.snapshot.rows) || [];
  const servers = rows.filter((r) => r.kind === 'server');
  const top = (field, color, fmt) => servers.filter((r) => (r[field] || 0) > 0).sort((a, b) => b[field] - a[field]).slice(0, 8)
    .map((r) => ({ label: `${r.proxy} / ${r.name}`, value: r[field], text: fmt(r[field]), color, attrs: `data-inspect="${esc(r.proxy)}/${esc(r.name)}"` }));
  const lv = ['critical', 'warning', 'recovery', 'info'].map((k) => ({ label: k, value: real.filter((e) => e.level === k).length, color: { critical: '#f87171', warning: '#fbbf24', recovery: '#34d399', info: '#22d3ee' }[k] })).filter((x) => x.value);
  const hist = EV.inst === state.current && EV.hist && EV.hist.length > 1;
  const chart = `<div class="bc-card ev-wide"><div class="bc-head"><b>Servers up / down</b><span class="muted small">last 24 hours</span></div>${hist ? '<canvas id="ev-health" class="chart" title="Servers passing or failing their health check over time"></canvas>' : `<p class="muted small bc-empty">${EV.loading || EV.inst !== state.current ? 'Loading history…' : 'Collecting data… the history fills in while GateLight watches this instance.'}</p>`}</div>`;
  return `<div class="svc-charts-grid ev-charts">${chart}
    ${real.length ? donutCard('Changes by level', lv, { big: String(real.length), sub: 'changes' }, 'Recorded state changes, by how serious they were.') : barChart('Changes by level', [], { sub: 'since GateLight started watching', empty: '✓ No state changes recorded yet' })}
    ${barChart('Downtime by server', top('downtime', '#f87171', (v) => fmtDur(v)), { sub: 'time spent DOWN since the proxy started', empty: '✓ No server has been down' })}
    ${barChart('Flapping', top('chkdown', '#fbbf24', (v) => `${fmtInt(v)}×`), { sub: 'times a server went from UP to DOWN', empty: '✓ No server went down' })}
    ${barChart('Failed health checks', top('chkfail', '#818cf8', (v) => fmtInt(v)), { sub: 'failed checks since the proxy started', empty: '✓ No failed checks' })}</div>`;
}
function renderEvents() {
  const f = state.eventFilter;
  const real = state.events.filter((e) => e.type !== 'monitoring_started'); // "GateLight started monitoring" is a restart marker, not a change in your system
  const starts = state.events.filter((e) => e.type === 'monitoring_started');
  const list = real.filter((e) => f === 'all' || e.level === f);
  const startNote = starts.length ? `<p class="muted small ev-starts">GateLight (re)started monitoring ${starts.length} time${starts.length === 1 ? '' : 's'}; last ${esc(fmtDateTime(Math.max(...starts.map((e) => e.ts))))}. Changes before that are not known.</p>` : '';
  if (EV.inst !== state.current && !EV.loading) setTimeout(evLoadHistory, 0);
  $('#view-events').innerHTML = `${eventsNowHtml()}
    ${eventsChartsHtml(real)}
    <div class="chips"><b class="ev-h">History</b>${['all', 'critical', 'warning', 'recovery', 'info'].map((x) => `<span class="chip ${f === x ? 'on' : ''}" data-ev="${x}">${x}</span>`).join('')}
      <span class="muted small">${real.length} change${real.length === 1 ? '' : 's'} recorded</span></div>
    <div class="table-wrap"><table class="grid"><thead><tr><th>Time</th><th>Level</th><th>Event</th></tr></thead><tbody>
    ${list.map((e) => `<tr ${e.proxy ? `data-inspect="${esc(e.proxy)}/${esc(e.name)}"` : ''}><td>${fmtDateTime(e.ts)}</td><td class="lv-${esc(e.level)}">${esc(e.level)}</td><td class="msg">${esc(e.message)}</td></tr>`).join('')
      || `<tr><td colspan="3" class="empty">${real.length ? 'No events at this level' : 'No changes seen yet. A server, pool or the stats endpoint going down or coming back up is recorded here from the moment GateLight started watching. Critical and warning changes also trigger your alert webhook.'}</td></tr>`}</tbody></table></div>${startNote}`;
  const ec = $('#ev-health'); if (ec && EV.hist && EV.hist.length > 1) drawChart(ec, EV.hist.map((p) => p.t), [{ label: 'up', color: '#34d399', values: EV.hist.map((p) => (p.up || 0) + (p.degraded || 0)) }, { label: 'down', color: '#f87171', values: EV.hist.map((p) => p.down || 0), minMax: 1 }]);
}

// ---------- CONFIG ----------
let cfgRendered = null;
const SEC_RE = /^\s*(global|defaults|frontend|backend|listen|userlist|peers|resolvers|mailers|cache|program|http-errors|ring)\b/;
function currentFile() {
  const files = state.snapshot.config.files || [];
  return files.find((f) => f.name === state.cfgFile) || files[0] || null;
}
function renderConfig() {
  const s = state.snapshot; const files = s.config.files || [];
  const file = currentFile(); const raw = file ? file.raw : '';
  const isNginx = s.instance.type === 'nginx';
  const filter = $('#cfg-search').value;
  const fsel = $('#cfg-file');
  fsel.hidden = files.length < 2;
  if (files.length > 1) { fsel.innerHTML = files.map((f) => `<option value="${esc(f.name)}">${esc(f.name)}</option>`).join(''); fsel.value = file.name; }
  { // where the config comes from, and the read-only "Refresh from server" button
    const c = s.config; const btn = $('#cfg-refresh'); const n = (c.urls || []).length;
    const ago = (t) => { const m = Math.max(0, Math.round((Date.now() - t) / 60000)); return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : `${Math.round(m / 60)} h ago`; };
    if (c.source === 'url') $('#cfg-path').innerHTML = `Fetched from <span class="mono">${esc(c.urls[0] || '')}</span>${n > 1 ? ` +${n - 1} more` : ''}${c.fetchedAt ? ` · ${esc(ago(c.fetchedAt))}` : ''}${c.fetchError ? ` · <span class="sev-error" title="${esc(c.fetchError)}">last fetch failed: showing the previous copy</span>` : ''}`;
    else $('#cfg-path').textContent = c.path || '';
    btn.hidden = state.mode === 'review' || !['url', 'file'].includes(c.source);
    btn.title = c.source === 'file' ? 'Read the config file again now (read-only) and show what changed' : 'Fetch the configuration again from the server (GET only) and show what changed';
  }
  const cacheKey = `${state.current}:${file && file.name}:${raw.length}:${s.findings.length}:${filter}`;
  if (cfgRendered === cacheKey) return;
  cfgRendered = cacheKey;
  const here = (f) => !f.file || !file || f.file === file.name;
  const byLine = new Map();
  s.findings.filter(here).forEach((f) => { const o = byLine.get(f.line); if (!o || f.severity === 'error') byLine.set(f.line, f); });
  const kwRe = /^(\s*)([a-z_][\w-]*)/i;
  const re = filter ? new RegExp(filter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi') : null;
  const html = raw.split('\n').map((ln, i) => {
    const n = i + 1; const f = byLine.get(n);
    let text = esc(ln);
    if (/^\s*#/.test(ln)) text = `<span class="cm">${text}</span>`;
    else if (isNginx ? /\{\s*(#.*)?$/.test(ln) : SEC_RE.test(ln)) text = `<span class="sec">${text}</span>`;
    else text = text.replace(kwRe, '$1<span class="kw">$2</span>');
    if (re) text = text.replace(re, (m) => `<mark>${m}</mark>`);
    return `<span class="ln${f ? ` f-${f.severity}` : ''}" id="L${n}"><span class="no">${n}</span>${text}${f ? `<span class="fnote sev-${f.severity}">⚠ ${esc(f.title)}</span>` : ''}</span>`;
  }).join('');
  $('#cfg-code').innerHTML = html || '<span class="empty">No configuration file loaded.</span>';
  renderCfgTree(file);
  cfgFindUpdate(Boolean(filter));
}

// ---- search: count, next / previous, scroll to the match ----
let cfgMatch = -1;
function cfgMarks() { return [...document.querySelectorAll('#cfg-code mark')]; }
function cfgFindUpdate(scrollToFirst) {
  const marks = cfgMarks(); const c = $('#cfg-count'); const q = $('#cfg-search').value;
  cfgMatch = marks.length ? (scrollToFirst ? 0 : Math.min(Math.max(cfgMatch, 0), marks.length - 1)) : -1;
  c.textContent = !q ? '' : marks.length ? `${cfgMatch + 1} of ${marks.length}` : 'no matches';
  c.classList.toggle('none', Boolean(q) && !marks.length);
  marks.forEach((m, i) => m.classList.toggle('cur', i === cfgMatch));
  if (scrollToFirst && marks[0]) marks[0].scrollIntoView({ block: 'center' });
}
function cfgFindStep(d) {
  const marks = cfgMarks(); if (!marks.length) return;
  cfgMatch = (cfgMatch + d + marks.length) % marks.length;
  marks.forEach((m, i) => m.classList.toggle('cur', i === cfgMatch));
  marks[cfgMatch].scrollIntoView({ block: 'center' });
  $('#cfg-count').textContent = `${cfgMatch + 1} of ${marks.length}`;
}

// ---- section tree (replaces the "Jump to section" dropdown) ----
const cfgOpen = new Set(); let cfgOpenInit = false;
const CFG_ORDER = ['defaults', 'frontend', 'listen', 'server', 'backend', 'upstream', 'userlist', 'http', 'stream'];
function renderCfgTree(file) {
  const secs = state.snapshot.config.sections.filter((x) => x.type !== 'global' && (!x.file || !file || x.file === file.name));
  const plural = { frontend: 'Frontends', backend: 'Backends', listen: 'Listen sections', defaults: 'Defaults', userlist: 'User lists', server: 'Server blocks', upstream: 'Upstreams', http: 'HTTP', stream: 'Stream' };
  const groups = new Map(); for (const x of secs) { if (!groups.has(x.type)) groups.set(x.type, []); groups.get(x.type).push(x); }
  const order = [...groups.keys()].sort((a, b) => (CFG_ORDER.indexOf(a) + 100) % 100 - (CFG_ORDER.indexOf(b) + 100) % 100 || a.localeCompare(b));
  if (!cfgOpenInit) { order.forEach((t) => cfgOpen.add(`g:${t}`)); cfgOpenInit = true; }
  const leaf = (label, line, sub, cls = '') => `<li class="tn leaf ${cls}" role="treeitem"><span class="tw"></span><button type="button" class="tl" data-cfg-line="${line}" title="Line ${line}"><span>${label}</span>${sub ? `<span class="ts">${sub}</span>` : ''}</button></li>`;
  const node = (id, label, count, line, kids, cls = '') => {
    const open = cfgOpen.has(id);
    return `<li class="tn ${cls}" role="treeitem" aria-expanded="${open}"><span class="tw"><button type="button" class="tt" data-cfg-toggle="${esc(id)}" aria-label="${open ? 'Collapse' : 'Expand'} ${esc(label)}"></button></span>${line ? `<button type="button" class="tl" data-cfg-line="${line}" title="Line ${line}"><b>${label}</b>${count != null ? `<span class="tc">${count}</span>` : ''}</button>` : `<span class="tl static"><b>${label}</b>${count != null ? `<span class="tc">${count}</span>` : ''}</span>`}<ul role="group"${open ? '' : ' hidden'}>${kids}</ul></li>`;
  };
  const child = (x) => {
    const kids = [];
    for (const sv of x.servers || []) kids.push(leaf(esc(sv.name), sv.line, esc(sv.address || ''), sv.commented ? 'dim' : ''));
    for (const l of x.locations || []) kids.push(leaf(esc(`${l.modifier ? `${l.modifier} ` : ''}${l.path || l.kind}`), l.line, l.target ? `→ ${esc(l.target)}` : ''));
    for (const rt of x.routes || []) if (rt.line && rt.target) kids.push(leaf(`→ ${esc(rt.target)}`, rt.line, rt.type === 'default' ? 'default' : '', rt.commented ? 'dim' : ''));
    return kids.length ? node(`s:${x.type}:${x.name}:${x.line}`, esc(x.name), kids.length, x.line, kids.join(''), 'sec') : leaf(`<b>${esc(x.name)}</b>`, x.line, `L${x.line}`, 'sec');
  };
  const g = state.snapshot.config.sections.find((x) => x.type === 'global' && (!x.file || !file || x.file === file.name));
  const html = (g ? leaf('<b>global</b>', g.line, `L${g.line}`) : '') + order.map((t) => node(`g:${t}`, esc(plural[t] || t), groups.get(t).length, 0, groups.get(t).map(child).join(''), 'grp')).join('');
  $('#cfg-tree').innerHTML = html ? `<div class="tree-head"><span>Sections</span><span class="tree-ctl"><button type="button" data-cfg-all="open" title="Expand all" aria-label="Expand all">+</button><button type="button" data-cfg-all="close" title="Collapse all" aria-label="Collapse all">−</button></span></div><ul class="tree" role="tree">${html}</ul>` : '<div class="muted small tree-empty">No sections found.</div>';
}
function gotoLine(line, file) {
  if (file) state.cfgFile = file;
  cfgRendered = null;
  switchView('config');
  requestAnimationFrame(() => {
    const el = document.getElementById(`L${line}`);
    if (el) { el.scrollIntoView({ block: 'center' }); el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); }
  });
}
const loc = (x) => `data-goto-line="${x.line}" data-goto-file="${esc(x.file || '')}"`;

// ---------- FLEET ----------
function renderFleet() {
  const list = state.instances.filter((i) => !state.hiddenTypes.includes(i.type));
  const tone = (i) => (i.ok === false ? 'bad' : i.serversDown ? 'warn' : i.ok ? 'ok' : '');
  $('#view-fleet').innerHTML = `<h2>All instances</h2><div class="cards fleet">${list.map((i) => `
    <div class="card clickable" data-open-instance="${esc(i.id)}">
      <div class="label"><span class="tag">${esc(TYPE_NAME[i.type] || i.type)}</span> ${esc(i.source)}</div>
      <div class="value" style="font-size:17px;margin:6px 0;color:var(--text)"><i class="dot ${tone(i) === 'bad' ? 'c-down' : tone(i) === 'warn' ? 'c-warn' : tone(i) === 'ok' ? 'c-up' : 'c-idle'}" style="margin-right:8px"></i>${esc(i.name)}</div>
      <div class="sub">${i.ok === false ? `<span class="sev-error">unreachable</span> — ${esc(i.error || '')}` : i.serversTotal ? `${i.serversTotal - i.serversDown}/${i.serversTotal} up${i.serversDown ? ` · <span class="sev-error">${i.serversDown} down</span>` : ''}` : 'no runtime data'}</div>
      <div class="sub">${i.findings ? `${i.findings.error} errors · ${i.findings.warning} warnings` : ''}</div>
    </div>`).join('') || '<div class="empty">No instances</div>'}</div>`;
}

// ---------- SETTINGS ----------
function renderSettings() {
  const f = state.meta.features || {};
  const types = ['haproxy', 'nginx'];
  $('#view-settings').innerHTML = `<div class="set-wrap">
    <header class="set-head"><h2>Settings</h2><p class="muted">Which technologies GateLight loads, what this browser shows, and the instances you manage.</p></header>
    <div class="panel"><div class="panel-h"><h2>Technologies</h2></div>
      <p class="muted">What GateLight loads and polls. Turn a technology off on the server to stop it from being loaded at all.</p>
      <div class="tech-grid">${types.map((t) => {
        const on = f[t] !== false; const mine = state.instances.filter((i) => i.type === t);
        const live = mine.filter((i) => i.ok === true).length; const cfg = mine.filter((i) => i.source === 'config-only').length;
        const bad = mine.filter((i) => i.ok === false && i.source !== 'config-only').length; const down = mine.reduce((n, i) => n + (i.serversDown || 0), 0);
        const reads = t === 'haproxy' ? ['Stats page (CSV)', 'Runtime API', 'haproxy.cfg'] : ['stub_status', 'NGINX Plus API', 'TCP probe of upstreams', 'nginx.conf'];
        const stat = (n, label, cls) => `<div class="tech-stat ${cls || ''}"><b>${n}</b><span>${label}</span></div>`;
        return `<section class="tech ${on ? 'on' : 'off'}" aria-label="${esc(TYPE_NAME[t])}">
          <header><span class="tech-ico t-${t}" aria-hidden="true">${t === 'haproxy' ? 'HA' : 'NG'}</span><b>${esc(TYPE_NAME[t])}</b><span class="st ${on ? 'st-up' : 'st-down'}">${on ? 'enabled' : 'disabled'}</span></header>
          <div class="tech-reads">${reads.map((r) => `<span class="chip">${esc(r)}</span>`).join('')}</div>
          ${on ? `<div class="tech-stats">${stat(mine.length, mine.length === 1 ? 'instance' : 'instances')}${stat(live, 'live')}${stat(cfg, 'config only')}${stat(bad, 'unreachable', bad ? 'bad' : '')}${stat(down, 'servers down', down ? 'bad' : '')}</div>${mine.length ? '' : `<p class="muted small tech-empty">None yet. <button class="link" type="button" data-connect>Add a ${esc(TYPE_NAME[t])} instance</button></p>`}`
            : `<p class="muted small tech-empty">Off on this server, so ${esc(TYPE_NAME[t])} instances are not loaded or polled. Set <code>ENABLE_${t.toUpperCase()}=true</code> and restart to turn it on.</p>`}
          <footer class="muted small"><code>ENABLE_${t.toUpperCase()}=${on ? 'true' : 'false'}</code></footer></section>`;
      }).join('')}</div>
      <details class="tech-how"><summary>How to turn a technology on or off</summary>
        <ul class="small muted"><li>Environment: <code>ENABLE_HAPROXY</code> / <code>ENABLE_NGINX</code> set to <code>true</code> or <code>false</code>.</li><li>Or <code>"features"</code> in <code>instances.json</code>. Use <code>"enabled": false</code> on a single instance to pause just that one.</li><li>A restart applies changes. To only hide a technology for yourself, use <b>Display</b> below.</li></ul></details>
    </div>
    <div class="panel"><div class="panel-h"><h2>Display</h2></div>
      <p class="muted">Per-browser preference: hide a technology from the selector and Fleet view without changing the server.</p>
      <div class="set-checks">${types.filter((t) => f[t] !== false).map((t) => `<label class="check"><input type="checkbox" data-show-type="${t}" ${state.hiddenTypes.includes(t) ? '' : 'checked'}> Show ${TYPE_NAME[t]}</label>`).join('')}</div>
    </div>
    <div class="panel"><div class="panel-h"><h2>Instances</h2>${state.meta.canManage ? '<button class="btn primary" type="button" data-connect>+ Connect a server</button>' : ''}</div>
      ${state.meta.canManage ? '' : '<p class="muted small">Servers are defined in <code>config/instances.json</code> or env vars. To add them from this page, start GateLight with <code>ALLOW_UI_INSTANCES=true</code>.</p>'}
      <div class="table-wrap"><table class="grid"><thead><tr><th>Name</th><th>Type</th><th>Source</th><th>Status</th><th>Findings</th><th></th></tr></thead><tbody>
      ${state.instances.map((i) => `<tr data-open-instance="${esc(i.id)}"><td>${esc(i.name)}</td><td>${esc(TYPE_NAME[i.type] || i.type)}</td><td class="mono small">${esc(i.source)}</td><td>${i.ok === false ? `<span class="st st-down" title="${esc(i.error || '')}">error</span>${i.error ? `<div class="muted small" style="max-width:260px">${esc(String(i.error).slice(0, 120))}</div>` : ''}` : i.ok ? '<span class="st st-up">ok</span>' : '…'}</td><td>${i.findings ? `${i.findings.error}e / ${i.findings.warning}w` : ''}</td><td>${i.managed ? `<div class="row-actions"><button class="btn" type="button" data-cx-up="${esc(i.id)}">Update config</button><button class="btn" type="button" data-cx-edit="${esc(i.id)}">Edit</button><button class="btn" type="button" data-cx-del="${esc(i.id)}">Remove</button></div>` : ''}</td></tr>`).join('')}
      </tbody></table></div>
    </div></div>`;
}

// ---------- INSPECTOR ----------
/** Details open as a page of their own (with Back), not as a panel over the current page. */
function openDetail() { if (state.view !== 'detail') state.detailFrom = state.view; switchView('detail'); window.scrollTo(0, 0); const v = $('#view-detail'); if (v) v.scrollTop = 0; }
function inspect(key, kind) {
  state.inspected = { key, kind };
  openDetail();
  refreshInspector();
  loadInspectorHistory(key);
}
function closeInspector() { state.inspected = null; }
function detailBack() {
  if (state.detailPushed) { history.back(); return; }
  const to = state.detailFrom && state.detailFrom !== 'detail' ? state.detailFrom : 'overview'; state.inspected = null; switchView(to);
}
/** Split a flat run of "<h4>Title</h4>…" sections into cards. */
function detailCards(html) {
  const parts = html.split(/(?=<h4)/).filter((x) => x.trim());
  return parts.map((p, i) => `<section class="dcard${i === 0 && !p.startsWith('<h4') ? ' first' : ''}">${p}</section>`).join('');
}

function kv(pairs) { return `<div class="kv">${pairs.filter(Boolean).map(([k, v]) => `<span>${esc(k)}</span><span>${v}</span>`).join('')}</div>`; }

function refreshInspector() {
  const ins = state.inspected; if (!ins || !state.snapshot) return;
  if (ins.kind === 'route' || ins.kind === 'missing') return;
  const r = indexRows(state.snapshot.rows).get(ins.key);
  const [proxy, name] = ins.key.split('/');
  const sec = cfgSections().find((x) => x.name === proxy && (x.type !== 'userlist'));
  const srv = sec && sec.servers.find((x) => x.name === name);
  $('#insp-kind').textContent = (r ? r.kind : ins.kind || '').toUpperCase();
  $('#insp-title').textContent = r ? (r.kind === 'server' ? `${proxy} / ${name}` : proxy) : ins.key;
  const related = state.snapshot.findings.filter((f) => f.section === proxy).slice(0, 6);
  const events = state.events.filter((e) => e.proxy === proxy && (!r || r.kind !== 'server' || e.name === name)).slice(0, 5);
  let html = '';
  if (r) {
    html += `<div>${stBadge(r.state, r.status)} ${r.check_status ? `<span class="mono small ${r.state === 'down' ? 'sev-error' : 'muted'}">${esc(r.check_status)}${r.check_code ? ` ${r.check_code}` : ''}${r.last_chk ? ` — ${esc(r.last_chk)}` : ''}</span>` : ''}</div>`;
    html += kv([
      ['Current sessions', `${fmtInt(r.scur)} <span class="muted">/ max ${fmtInt(r.smax)}${r.slim ? ` / limit ${fmtInt(r.slim)}` : ''}</span>`],
      ['Requests / s', fmtRate(r.ratePerSec)], ['5xx / s', fmtRate(r.err5xxPerSec)], ['Total sessions', fmtInt(r.stot)],
      ['Bytes in / out', `${fmtBytes(r.bin)} / ${fmtBytes(r.bout)}`],
      ['Responses', `2xx ${fmtInt(r.hrsp_2xx)} · 4xx ${fmtInt(r.hrsp_4xx)} · 5xx ${fmtInt(r.hrsp_5xx)}`],
      r.rtime != null ? ['Avg resp / connect', `${r.rtime} ms / ${r.ctime ?? '–'} ms`] : null,
      r.qcur != null && r.kind !== 'frontend' ? ['Queue', `${fmtInt(r.qcur)} (max ${fmtInt(r.qmax)})`] : null,
      r.kind === 'server' ? ['Weight', fmtInt(r.weight)] : null,
      r.lastchg != null ? ['Status for', fmtDur(r.lastchg)] : null,
      r.downtime ? ['Total downtime', fmtDur(r.downtime)] : null,
      (r.econ || r.eresp) ? ['Conn / resp errors', `${fmtInt(r.econ)} / ${fmtInt(r.eresp)}`] : null,
    ]);
    html += relationsHtml(r, proxy, sec, srv);
    html += '<h4>Trend (last samples) <button class="btn icon chart-expand" type="button" data-cv-expand="inspector" title="Pop out: bigger chart, time range, series and stats" aria-label="Pop out chart">⤢</button></h4><canvas id="insp-chart" class="chart" title="Click to pop out"></canvas>';
  } else html += '<div class="muted">No runtime data for this entry.</div>';
  if (sec) {
    html += '<h4>Configuration</h4>';
    if (srv) {
      html += kv([['Address', `<code>${esc(srv.address)}</code>`], ['Health check', srv.check ? 'enabled' : '<span class="sev-warning">none</span>'], ['Backup', srv.backup ? 'yes' : 'no'],
        ['Options', `<code>${esc(srv.options)}</code>`], ['Defined at', `<a style="color:var(--cyan);cursor:pointer" ${loc(srv)}>line ${srv.line}</a>`]]);
    } else {
      html += kv([['Section', `${esc(sec.type)} (line <a style="color:var(--cyan);cursor:pointer" ${loc(sec)}>${sec.line}</a>)`], ['Mode', esc(sec.mode)], ['Layer', `${layerTag(sec)} <span class="muted small">${esc(layerTip(sec))}</span>`],
        sec.balance ? ['Balance', esc(sec.balance)] : null,
        sec.serverNames && sec.serverNames.length ? ['Server names', sec.serverNames.map((n) => `<code>${esc(n)}</code>`).join('<br>')] : null,
        sec.binds.length ? ['Binds', sec.binds.filter((b) => !b.commented).map((b) => `<code>${esc(b.addresses.join(', '))}${b.ssl ? ' 🔒' : ''}</code>`).join('<br>')] : null,
        sec.zone ? ['Status zone', `<code>${esc(sec.zone)}</code>`] : null,
        sec.servers.length ? ['Servers', `${sec.servers.filter((x) => !x.commented).length} active`] : null,
        sec.routes.length ? ['Routes', `${sec.routes.filter((x) => !x.commented).length} active`] : null,
        Object.keys(sec.timeouts).length ? ['Timeouts', Object.entries(sec.timeouts).map(([k, v]) => `${esc(k)} ${esc(v)}`).join('<br>')] : null]);
    }
  }
  html += endpointsHtml(r, sec, srv);
  if (sec && !srv) html += urlMappingsHtml(sec);
  else if (srv) html += urlMappingsHtml(sec, true);
  if (sec && sec.locations && sec.locations.length) {
    html += `<h4>Locations</h4><div class="list">${sec.locations.map((l) => `<div class="item" ${loc(l)}><span class="tag">${esc(l.kind)}</span><div class="t mono small">${esc(`${l.modifier ? `${l.modifier} ` : ''}${l.path || ''}`)}${l.target ? ` → ${esc(l.target)}` : l.detail ? ` <span class="muted">${esc(l.detail)}</span>` : ''}</div></div>`).join('')}</div>`;
  }
  if (events.length) html += `<h4>Recent events</h4><div class="list">${events.map((e) => `<div class="item"><span class="lv-${esc(e.level)}">●</span><div class="t">${esc(e.message)}<div class="muted small">${fmtDateTime(e.ts)}</div></div></div>`).join('')}</div>`;
  if (related.length) html += `<h4>Audit findings</h4><div class="list">${related.map((f) => `<div class="item" ${loc(f)}><span class="sev-${esc(f.severity)}">●</span><div class="t">${esc(f.title)}<div class="muted small">line ${f.line}</div></div></div>`).join('')}</div>`;
  $('#insp-body').innerHTML = detailCards(html);
  $('#detail-crumb').textContent = $('#insp-title').textContent;
  drawInspectorChart();
}
let inspHistory = [];
async function loadInspectorHistory(key) {
  inspHistory = [];
  try { const h = await api(`/instances/${encodeURIComponent(state.current)}/history?key=${encodeURIComponent(key)}&points=180`); if (state.inspected && state.inspected.key === key) { inspHistory = h.points; drawInspectorChart(); cvRender(); } } catch { /* ignore */ }
}
function drawInspectorChart() {
  const c = $('#insp-chart'); if (!c) return;
  drawChart(c, inspHistory.map((p) => p.t), [
    { label: 'req/s', color: '#22d3ee', values: inspHistory.map((p) => p.rate) },
    { label: '5xx/s', color: '#f87171', values: inspHistory.map((p) => p.e5xx), minMax: 1 },
    { label: 'sessions', color: '#818cf8', values: inspHistory.map((p) => p.scur) },
  ]);
}
// Port mapping and URI transformation of a rule, as rows for the route inspector.
function flowRows(f) {
  if (!f) return [];
  const rows = [['Ports', f.portMap.map((p) => `${portTxt(p.in, p.listenerTls)} → ${p.out.length ? p.out.map((o) => `<span class="pt">:${o}</span>`).join(' ') : '?'} <span class="muted small">${esc(TLS_LABEL[p.tls] || p.tls)}</span>`).join('<br>')]];
  const steps = f.chain.filter((x) => x.applies !== false && (x.kind === 'path' || (x.kind === 'header' && /^Host$/i.test(x.args[0] || ''))));
  if (steps.length) rows.push(['URI changes', steps.map((x) => `<code>${esc(x.text)}</code>${x.cond ? ` <span class="muted small">${esc(x.cond)}</span>` : ''}`).join('<br>')]);
  if (f.example) rows.push(['Backend receives', f.example.changed ? `<code>${esc(f.example.in)}</code> → <code>${esc(f.example.out)}</code>${f.example.exact ? '' : ' <span class="muted small">(approximate)</span>'}` : `<span class="muted">the same path (${esc(f.example.in)})</span>`]);
  return rows;
}
function inspectRoute(r) {
  state.inspected = { kind: 'route' };
  $('#insp-kind').textContent = r.commented ? 'ROUTING RULE (DISABLED)' : 'ROUTING RULE';
  $('#insp-title').textContent = `${r.fe} → ${r.target}`;
  $('#insp-body').innerHTML = kv([['Type', esc(r.type)], ['Match', esc(routeSummary(r))], r.hosts && r.hosts.length ? ['Host', r.hosts.map((h) => `<code>${esc(h)}</code>`).join('<br>')] : null,
    ['Condition', `<code>${esc(r.condition)}</code>`], (r.aclRefs || []).length ? ['ACLs used', esc(r.aclRefs.join(', '))] : null,
    r.passUrl ? [r.passDirective || 'pass', `<code>${esc(r.passUrl)}</code>`] : null, r.rewriteNote ? ['URI rewrite', esc(r.rewriteNote)] : null,
    (r.rewrites || []).length ? ['rewrite rules', r.rewrites.map((x) => `<code>${esc(x)}</code>`).join('<br>')] : null,
    ...flowRows(flowOf(r.fe, r)),
    ['Defined at', `<a style="color:var(--cyan);cursor:pointer" ${loc(r)}>line ${r.line}</a>`]]);
  $('#insp-body').innerHTML = detailCards($('#insp-body').innerHTML); $('#detail-crumb').textContent = $('#insp-title').textContent;
  openDetail();
}
function inspectMissing(name) {
  state.inspected = { kind: 'missing' };
  $('#insp-kind').textContent = 'BROKEN ROUTE'; $('#insp-title').textContent = name;
  $('#insp-body').innerHTML = `<div class="finding error"><div class="ft">Backend “${esc(name)}” is not defined</div><div class="fm">A frontend routes here but no backend/listen section has this name. HAProxy will refuse to start with this configuration.</div></div>`;
  $('#insp-body').innerHTML = detailCards($('#insp-body').innerHTML); $('#detail-crumb').textContent = name;
  openDetail();
}

// ---------- ANALYZE ----------
const AZ_MAX_FILES = 300; const AZ_MAX_BYTES = 1024 * 1024;
const azStatus = (html, kind = '') => {
  const el = $('#az-status'); el.className = `az-status ${kind}`; el.innerHTML = html;
  if (state.mode !== 'landing' && kind === 'err' && html) toast(html.replace(/<[^>]+>/g, ''), 'err');
};
const readText = (file) => new Promise((res, rej) => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.onerror = rej; fr.readAsText(file); });

async function walkEntry(entry, prefix, out) {
  if (out.length >= AZ_MAX_FILES) return;
  if (entry.isFile) { await new Promise((res) => entry.file((f) => { out.push({ name: prefix + entry.name, file: f }); res(); }, res)); return; }
  if (!entry.isDirectory || /^\.(git|svn|hg)$|^node_modules$/.test(entry.name)) return;
  const reader = entry.createReader();
  for (;;) {
    const batch = await new Promise((res) => reader.readEntries(res, () => res([])));
    if (!batch.length) break;
    for (const e of batch) await walkEntry(e, `${prefix}${entry.name}/`, out);
  }
}
async function filesFromDrop(dt) {
  const entries = [...(dt.items || [])].map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null)).filter(Boolean);
  const out = [];
  if (entries.length) for (const e of entries) await walkEntry(e, '', out);
  else [...dt.files].forEach((f) => out.push({ name: f.name, file: f }));
  return out;
}
async function readConfigFiles(list) {
  const files = []; const skipped = [];
  for (const { name, file } of list.slice(0, AZ_MAX_FILES)) {
    if (file.size > AZ_MAX_BYTES) { skipped.push(`${name} (too large)`); continue; }
    let content;
    try { content = await readText(file); } catch { skipped.push(`${name} (unreadable)`); continue; }
    if (content.includes('\u0000')) { skipped.push(`${name} (binary)`); continue; }
    files.push({ name: name || file.name, content });
  }
  return { files, skipped };
}
async function ingestFiles(list) {
  if (!list.length) return;
  azStatus('Reading files…');
  const { files, skipped } = await readConfigFiles(list);
  if (!files.length) { azStatus('No readable text files found.', 'err'); return; }
  await runAnalyze({ files }, `${files.length} file${files.length === 1 ? '' : 's'}${skipped.length ? `, ${skipped.length} skipped` : ''}`);
}

async function runAnalyze(payload, label) {
  azStatus(`Analyzing${label ? ` ${esc(label)}` : ''}…`);
  try {
    const res = await api('/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...payload, type: $('#az-type').value }) });
    const L = res.type === 'nginx' ? { frontend: 'Server block', backend: 'Upstream', server: 'Peer' } : { frontend: 'Frontend', backend: 'Backend', server: 'Server' };
    state.analysis = true;
    state.analysisCfg = { type: res.type, files: payload.files || [{ name: res.type === 'nginx' ? 'nginx.conf' : 'haproxy.cfg', content: payload.config || '' }] };
    $('#btn-save-review').hidden = !(state.meta && state.meta.canManage);
    setMode('review');
    state.analysisSnap = {
      instance: { id: '__analysis', name: `Uploaded ${TYPE_NAME[res.type]} config`, source: 'config-only', type: res.type, labels: L }, ts: Date.now(), ok: true, stale: false,
      error: `Offline analysis of an uploaded ${TYPE_NAME[res.type]} configuration — no live data.`, info: {}, pollIntervalMs: 60000, rows: res.rows,
      summary: summarizeRows(res.rows), config: { path: 'uploaded', files: res.config.files, sections: res.config.sections }, findings: res.findings, findingsSummary: res.findingsSummary,
    };
    state.events = []; state.focus = null;
    await loadInstances();
    $('#instance-select').value = '__analysis'; state.current = '__analysis';
    clearTimeout(state.timer); cfgRendered = null; state.series = []; state.cfgFile = null;
    if (network) { network.destroy(); network = null; }
    applySnapshot(state.analysisSnap);
    const nFe = res.config.sections.filter((x) => x.type === 'frontend' || x.type === 'listen').length;
    const nBe = res.config.sections.filter((x) => x.type === 'backend').length;
    azStatus('');
    switchView('topology');
    toast(`${TYPE_NAME[res.type]}: ${nFe} ${L.frontend.toLowerCase()}s → ${nBe} ${L.backend.toLowerCase()}s · ${res.findingsSummary.error} errors, ${res.findingsSummary.warning} warnings`, res.findingsSummary.error ? 'err' : 'ok', 6000);
    (res.notes || []).filter((n) => !/include|fragment/.test(n.msg)).forEach((n) => toast(n.msg, 'info', 7000));
  } catch (e) { azStatus(`Could not analyze: ${esc(e.message)}`, 'err'); toast(e.message, 'err'); }
}
async function loadExample(type) {
  azStatus(`Loading ${TYPE_NAME[type]} example…`);
  try { const ex = await api(`/examples/${type}`); await runAnalyze({ files: ex.files }, `${TYPE_NAME[type]} example`); } catch (e) { azStatus(esc(e.message), 'err'); }
}
function summarizeRows(rows) {
  const c = () => ({ up: 0, down: 0, maint: 0, drain: 0, degraded: 0, nocheck: 0, unknown: 0, total: 0 });
  const s = { servers: c(), backends: c(), frontends: c(), sessions: 0, ratePerSec: 0, err5xxPerSec: 0, bytesIn: 0, bytesOut: 0 };
  rows.forEach((r) => { const b = r.kind === 'server' ? s.servers : r.kind === 'backend' ? s.backends : r.kind === 'frontend' ? s.frontends : null; if (b) { b[r.state || 'unknown']++; b.total++; } });
  return s;
}

// ---------- command palette ----------
const pal = { open: false, items: [], sel: 0 };
function paletteSource() {
  const items = [];
  visibleNav().forEach((b) => items.push({ grp: 'View', text: b.textContent.trim().replace(/\s+\d+$/, ''), run: () => switchView(b.dataset.view) }));
  if (state.mode === 'live') state.instances.forEach((i) => items.push({ grp: 'Instance', text: `${i.name} (${TYPE_NAME[i.type] || i.type})`, run: () => openInstance(i.id) }));
  if (state.snapshot) {
    state.snapshot.rows.filter((r) => ['frontend', 'backend', 'server'].includes(r.kind)).forEach((r) => items.push({ grp: lbl(r.kind), text: r.kind === 'server' ? `${r.proxy} / ${r.name}` : r.proxy, run: () => { switchView('topology'); inspect(`${r.proxy}/${r.name}`, r.kind); } }));
    state.snapshot.config.sections.filter((x) => x.type !== 'global' && x.type !== 'defaults').forEach((x) => items.push({ grp: 'Config', text: `${x.type} ${x.name}`, run: () => gotoLine(x.line, x.file) }));
    state.snapshot.findings.forEach((f) => items.push({ grp: f.severity, text: `${f.title} — ${f.section}:${f.line}`, run: () => gotoLine(f.line, f.file) }));
  }
  return items;
}
function paletteRender() {
  const q = $('#pal-input').value.trim().toLowerCase();
  const all = paletteSource();
  pal.items = (q ? all.filter((i) => `${i.grp} ${i.text}`.toLowerCase().includes(q)) : all.filter((i) => ['View', 'Instance'].includes(i.grp))).slice(0, 60);
  pal.sel = Math.min(pal.sel, Math.max(0, pal.items.length - 1));
  $('#pal-list').innerHTML = pal.items.map((i, n) => `<div class="pal-item ${n === pal.sel ? 'sel' : ''}" data-pal="${n}" role="option"><span class="grp">${esc(i.grp)}</span><span class="tx">${esc(i.text)}</span></div>`).join('') || '<div class="empty">No matches</div>';
  const sel = $('#pal-list .sel'); if (sel) sel.scrollIntoView({ block: 'nearest' });
}
function paletteOpen() { pal.open = true; pal.sel = 0; $('#palette').hidden = false; $('#pal-input').value = ''; paletteRender(); $('#pal-input').focus(); }
function paletteClose() { pal.open = false; $('#palette').hidden = true; }
function paletteRun(n) { const it = pal.items[n]; if (it) { paletteClose(); it.run(); } }

// ---------- modes: landing / live / review ----------
function setMode(m) {
  state.mode = m;
  ['landing', 'live', 'review'].forEach((x) => document.body.classList.toggle(`mode-${x}`, x === m));
  $('#app').hidden = false;
  $('#btn-start').textContent = m === 'review' ? '✕ Clear' : '← Start over';
  $('#btn-start').title = m === 'review' ? 'Remove the uploaded config from this browser and go back' : 'Back to the Overview';
  $('#btn-home').title = m === 'review' ? 'Back to the topology' : m === 'live' ? 'Back to the Overview' : 'GateLight';
  if (m !== 'live') { clearTimeout(state.timer); }
}
function showLanding() { // no dedicated start page any more: land on the Overview, with a guided welcome when nothing is connected
  setMode('live');
  state.analysis = null; state.analysisSnap = null; state.analysisCfg = null; state.snapshot = null; state.current = null; state.series = []; closeInspector();
  clearTimeout(state.timer);
  if (network) { network.destroy(); network = null; }
  document.body.classList.add('no-instance');
  try { sessionStorage.removeItem('gatelight.entered'); } catch { /* storage unavailable */ }
  history.replaceState(null, '', `${location.pathname}${location.search.replace(/[?&]example=[^&]*/, '')}#overview`);
  azStatus('');
  ['#az-text', '#az-files', '#az-folder'].forEach((q) => { const el = $(q); if (el) el.value = ''; }); // nothing uploaded lingers in the page
  $('#conn-pill').textContent = '';
  showBanner(null);
  state.view = null; switchView('overview');
  window.scrollTo(0, 0);
}
function renderLanding() {
  const can = state.meta && state.meta.canManage;
  const list = state.instances;
  const tone = (i) => (i.ok === false ? 'c-down' : i.serversDown ? 'c-warn' : i.ok ? 'c-up' : 'c-idle');
  $('#lp-saved').innerHTML = list.length ? `<div class="lp-saved-h">${can ? 'Your saved connections <span class="muted">(private to this browser)</span>' : 'Configured servers'}</div>${list.map((i) => `
    <div class="lp-row${cx.editing === i.id ? ' editing' : ''}"><button type="button" class="lp-conn" data-enter="${esc(i.id)}"><i class="dot ${tone(i)}"></i>
      <span class="lp-conn-name">${esc(i.name)}</span><span class="tag">${esc(TYPE_NAME[i.type] || i.type)}</span>
      <span class="lp-conn-src muted small">${esc(i.source === 'demo' ? 'demo data' : i.source === 'config-only' ? 'config only' : i.source)}</span><span class="lp-go" aria-hidden="true">→</span></button>${can ? `<button type="button" class="btn small-btn lp-edit" data-cx-edit="${esc(i.id)}" title="Change this connection: URL, credentials, config or logs">${cx.editing === i.id ? 'Editing…' : 'Modify'}</button>` : ''}</div>`).join('')}${can ? '<div class="lp-or"><span>or connect a new server</span></div>' : ''}` : '';
  $('#lp-nomanage').hidden = Boolean(can);
  if (can) { cxOpen(null, true); $('#cx-name').blur(); }
  else $('#lp-form-slot').innerHTML = '';
}
/** GateLight logo / name: back to the Overview (or the topology while reviewing an unsaved config). First run with nothing to show: start screen. */
function goHome() {
  if (state.mode === 'review') { switchView('topology'); return; }
  if (state.mode === 'live' && state.snapshot) { switchView('overview'); return; }
  showLanding();
}
/** ✕ Clear while reviewing: drop the upload, then back to the dashboard if there is one, else the start screen. */
function leaveReview() {
  const first = state.instances.find((i) => !state.hiddenTypes.includes(i.type));
  showLanding();
  if (first) enterLive(first.id);
}
async function enterLive(id) {
  setMode('live');
  state.analysis = null; state.analysisSnap = null;
  state.current = id; state.snapshot = null; state.series = []; cfgRendered = null; state.cfgFile = null; state.focus = null; state.events = [];
  closeInspector(); clearTimeout(state.timer);
  if (network) { network.destroy(); network = null; }
  const ok = await loadInstances();
  if (!ok || !$$('#instance-select option').some((o) => o.value === id)) { showLanding(); return; }
  $('#instance-select').value = id; state.current = id; iselSync();
  try { sessionStorage.setItem('gatelight.entered', id); localStorage.setItem('gatelight.last', id); } catch { /* storage unavailable */ }
  switchView('overview');
  await poll(true);
  schedule();
  backfillSeries();
  switchView(state.view === 'settings' ? 'settings' : 'overview');
}

// ---------- GRAPHS PAGE: every chart in one place ----------
const gr = { range: (() => { try { const v = Number(localStorage.getItem('gatelight.grRange')); return [5, 15, 30, 60, 360, 1440, 10080].includes(v) ? v : 15; } catch { return 15; } })(), focus: new Set(), loaded: null, from: null, to: null, hand: false, metric: 'rate', pool: '', q: '', data: null, for: null, loading: false, sig: '', cards: new Map(), more: { frontend: false, backend: false, server: false, donut: false } };
const fmtBps = (v) => `${fmtBytes(v)}/s`;
const fmtMs = (v) => `${Math.round(v)} ms`;
const GR_SERIES = { // metric -> series for a list of history points
  rate: (P) => [{ k: 'rate', label: 'req/s', color: '#22d3ee', values: P.map((p) => p.rate || 0) }],
  srate: (P) => [{ k: 'srate', label: 'sessions/s', color: '#34d399', values: P.map((p) => p.srate || 0) }],
  scur: (P) => [{ k: 'scur', label: 'sessions', color: '#818cf8', values: P.map((p) => p.scur || 0), fmt: fmtInt }],
  e5xx: (P) => [{ k: 'e5xx', label: '5xx/s', color: '#f87171', values: P.map((p) => p.e5xx || 0), minMax: 1 }],
  rtime: (P) => [{ k: 'rtime', label: 'resp ms', color: '#fbbf24', values: P.map((p) => p.rtime || 0), fmt: fmtMs }],
  bps: (P) => [{ k: 'inBps', label: 'in', color: '#22d3ee', values: P.map((p) => p.inBps || 0), fmt: fmtBps }, { k: 'outBps', label: 'out', color: '#f472b6', values: P.map((p) => p.outBps || 0), fmt: fmtBps }],
  health: (P) => { const max = Math.max(1, ...P.map((p) => p.total || 0)); const f = (k, label, color) => ({ k, label, color, values: P.map((p) => p[k] || 0), max, fmt: fmtInt }); return [f('up', 'up', '#34d399'), f('degraded', 'degraded', '#fbbf24'), f('down', 'down', '#f87171')]; },
};
const GR_METRICS = [['rate', 'Requests / s'], ['srate', 'Session rate (new sessions / s)'], ['scur', 'Current sessions'], ['e5xx', '5xx / s'], ['rtime', 'Response time'], ['bps', 'Throughput (bytes / s)']];
const GR_TOP = [ // instance-level cards
  ['rate', 'Requests / s', 'How many HTTP requests per second the whole instance serves.'],
  ['srate', 'Session rate', 'New sessions (connections) per second.'],
  ['scur', 'Sessions', 'Connections open right now.'],
  ['e5xx', '5xx errors / s', 'Server-side errors per second.'],
  ['bps', 'Throughput', 'Bytes per second in and out.'],
  ['rtime', 'Response time', 'Average server response time.'],
  ['health', 'Servers up / down', 'How many servers pass their health check over time.'],
];
/** The time window the cards show: the last `range` minutes (live), or an absolute from/to (zoomed or panned, like Grafana). */
function grWindow() {
  if (gr.from != null && gr.to != null) return { t0: gr.from, t1: gr.to, live: false };
  const now = Date.now(); return { t0: now - gr.range * 60000, t1: now, live: true };
}
const GR_PRESETS = [5, 15, 30, 60, 360, 1440, 10080];
function grSlice(arr, full) {
  if (full || !arr.length) return arr;
  const w = grWindow(); return arr.filter((p) => p.t >= w.t0 && p.t <= w.t1);
}
const grLiveAgain = () => { gr.from = gr.to = null; grUi(); grLoad(); };
function grSetWindow(from, to) { // absolute window; touching "now" goes back to live
  const span = Math.max(10000, to - from);
  if (to >= Date.now() - 2000) { gr.range = Math.max(1, Math.round(span / 60000)); gr.from = gr.to = null; } else { gr.from = Math.round(to - span); gr.to = Math.round(to); }
  grUi(); grPaintCards();
}
function grUi() {
  const w = grWindow(); const sel = $('#gr-range'); if (!sel) return;
  const preset = w.live && GR_PRESETS.includes(gr.range);
  const opts = [['5', 'Last 5 min'], ['15', 'Last 15 min'], ['30', 'Last 30 min'], ['60', 'Last hour'], ['360', 'Last 6 hours'], ['1440', 'Last 24 hours'], ['10080', 'Last 7 days']];
  const want = opts.map(([v, t]) => `<option value="${v}"${preset && String(gr.range) === v ? ' selected' : ''}>${t}</option>`).join('') + (preset ? '' : '<option value="custom" selected>Custom</option>');
  if (sel.innerHTML !== want) sel.innerHTML = want;
  const f = (t) => new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: w.t1 - w.t0 < 3600e3 ? '2-digit' : undefined });
  $('#gr-win').textContent = w.live ? 'live' : `${f(w.t0)} → ${f(w.t1)}`;
  $('#gr-win').classList.toggle('hist', !w.live);
  $('#gr-live').hidden = w.live;
  const h = $('#gr-hand'); h.classList.toggle('on', gr.hand); h.setAttribute('aria-pressed', String(gr.hand));
  $('#gr-body').classList.toggle('hand', gr.hand);
}
const grEntity = (key) => (gr.data ? gr.data.entities.find((e) => e.key === key) : null);
function grBuild(id, full) {
  const c = gr.cards.get(id); if (!c || !gr.data) return { title: c ? c.title : '', times: [], series: [] };
  const pts = c.key ? ((grEntity(c.key) || {}).points || []) : gr.data.summary;
  const P = grSlice(pts, full);
  const w = grWindow();
  return { title: c.title, times: P.map((p) => p.t), series: GR_SERIES[c.metric](P), domain: full ? null : [w.t0, w.t1] };
}
/** Clickable legend for a card: chips with the series name and latest value; picking one shows only that series plus its numbers. */
function grLegend(id, canvas, d) {
  const leg = $(`#${id}-leg`); const st = $(`#${id}-stats`); if (!leg) return;
  const hid = legendHidden.get(id) || new Set(); const multi = d.series.length > 1;
  const shown = d.series.filter((q) => !hid.has(q.k));
  const picked = multi ? (shown.length === 1 ? shown[0] : null) : (gr.focus.has(id) ? d.series[0] : null);
  const f = (q) => q.fmt || (q.label === 'sessions' ? fmtInt : fmtRate);
  const html = d.series.map((q) => { const off = hid.has(q.k); const last = q.values.length ? q.values[q.values.length - 1] : null;
    return `<button type="button" class="gr-chip${off ? ' off' : ''}${picked === q ? ' sel' : ''}" data-gr-leg="${id}" data-k="${esc(q.k)}" aria-pressed="${picked === q}" title="${multi ? 'Click: show only this series and its numbers. Click again: show all. Ctrl/⌘-click: switch on or off.' : 'Click to show or hide its numbers'}"><i style="background:${q.color}"></i><span>${esc(q.label)}</span><b>${last == null ? '–' : esc(f(q)(last))}</b></button>`; }).join('');
  if (leg._h !== html) { leg._h = html; leg.innerHTML = html; }
  let sh = '';
  if (picked && picked.values.length) {
    const v = picked.values; const sum = v.reduce((a, b) => a + b, 0); const mx = Math.max(...v); const mn = Math.min(...v); const fx = f(picked);
    sh = `<span><i style="background:${picked.color}"></i><b>${esc(picked.label)}</b></span><span>now <b>${esc(fx(v[v.length - 1]))}</b></span><span>avg <b>${esc(fx(sum / v.length))}</b></span><span>min <b>${esc(fx(mn))}</b></span><span>max <b>${esc(fx(mx))}</b></span><span class="muted">${v.length} samples</span>`;
  }
  if (st._h !== sh) { st._h = sh; st.innerHTML = sh; } st.hidden = !sh;
}
function grPaintCards() {
  gr.cards.forEach((c, id) => {
    const canvas = $(`#${id}`); if (!canvas) return;
    const d = grBuild(id, false);
    canvas._noLegend = true;
    drawChart(canvas, d.times, d.series, d.domain);
    grLegend(id, canvas, d);
    const now = $(`#${id}-now`);
    if (now) { const s = d.series[0]; const last = s && s.values.length ? s.values[s.values.length - 1] : null; now.textContent = last == null ? '' : (s.fmt || fmtRate)(last); }
    if (c.key) { const e = grEntity(c.key); const st = $(`#${id}-st`); if (st && e) st.innerHTML = stBadge(e.state, e.state); }
  });
}
function grCard(id, title, metric, o = {}) {
  gr.cards.set(id, { title, metric, key: o.key || null });
  return `<div class="gr-card${o.big ? ' big' : ''}" data-gr="${id}" title="${esc(o.help || '')}">
    <div class="gr-head"><b>${esc(title)}</b>${o.key ? `<span id="${id}-st"></span>` : ''}<span class="gr-now" id="${id}-now"></span><button type="button" class="gr-exp" data-gr-open="${id}" aria-label="Open ${esc(title)} in a large chart" title="Pop out: zoom, history, export">⤢</button></div><div class="gr-leg" id="${id}-leg"></div><canvas id="${id}" class="chart gr-canvas"></canvas><div class="gr-stats" id="${id}-stats" hidden></div></div>`;
}
function grPaint() {
  const body = $('#gr-body'); if (!gr.data || !body) return;
  const ents = gr.data.entities;
  // filters
  const pools = [...new Set(ents.filter((e) => e.kind !== 'frontend').map((e) => e.proxy))].sort();
  const sel = $('#gr-pool'); const want = ['<option value="">All pools</option>', ...pools.map((p) => `<option value="${esc(p)}"${p === gr.pool ? ' selected' : ''}>${esc(p)}</option>`)].join('');
  if (sel.innerHTML !== want) sel.innerHTML = want;
  const q = gr.q.toLowerCase();
  const pick = (kind) => ents.filter((e) => e.kind === kind && (!gr.pool || e.proxy === gr.pool || (kind === 'frontend' && false)) && (!q || `${e.proxy} ${e.name}`.toLowerCase().includes(q)))
    .sort((a, b) => ((b.state === 'down') - (a.state === 'down')) || ((b.state === 'degraded') - (a.state === 'degraded')) || a.proxy.localeCompare(b.proxy) || a.name.localeCompare(b.name));
  const lists = { frontend: pick('frontend'), backend: pick('backend'), server: pick('server') };
  const LIM = 24;
  const shown = (k) => (gr.more[k] ? lists[k] : lists[k].slice(0, LIM));
  const sig = JSON.stringify([gr.metric, gr.pool, gr.q, gr.more, shown('frontend').map((e) => e.key), shown('backend').map((e) => e.key), shown('server').map((e) => e.key), state.current]);
  if (sig !== gr.sig) {
    gr.sig = sig; gr.cards.clear(); let n = 0; for (const k of [...legendHidden.keys()]) if (k.startsWith('gr')) legendHidden.delete(k); gr.focus.clear();
    const metricLabel = (GR_METRICS.find(([k]) => k === gr.metric) || [])[1] || '';
    const section = (kind, title, hint) => {
      const all = lists[kind]; if (!all.length) return '';
      const cards = shown(kind).map((e) => grCard(`gr${n++}`, kind === 'server' ? `${e.proxy} / ${e.name}` : e.proxy, gr.metric, { key: e.key })).join('');
      const more = all.length > LIM ? `<button class="btn" type="button" data-gr-more="${kind}">${gr.more[kind] ? 'Show fewer' : `Show all ${all.length}`}</button>` : '';
      return `<h3 class="gr-h">${esc(title)} <span class="muted small">${all.length} · ${esc(metricLabel)}${hint ? ` · ${esc(hint)}` : ''}</span></h3><div class="gr-grid">${cards}</div>${more ? `<div class="gr-more">${more}</div>` : ''}`;
    };
    body.innerHTML = `<h3 class="gr-h">Instance <span class="muted small">totals across all frontends</span></h3>
      <div class="gr-grid top">${GR_TOP.map(([m, t, help]) => grCard(`gr${n++}`, t, m, { big: true, help })).join('')}</div>
      <div id="gr-donuts"></div>
      ${section('server', lang_servers(), 'one chart per server; problems first')}${section('backend', lang_backends(), '')}${section('frontend', lang_frontends(), '')}
      ${ents.length ? '' : '<p class="muted">This source reports no per-server data (for example NGINX <code>stub_status</code>), so only the instance totals are charted.</p>'}`;
  }
  const dn = $('#gr-donuts'); if (dn) dn.innerHTML = grDonuts();
  grPaintCards();
  $('#gr-updated').textContent = gr.data.summary.length ? `${gr.data.summary.length} samples · latest ${fmtTime(gr.data.summary[gr.data.summary.length - 1].t)}` : 'collecting data…';
}
const lang_servers = () => `${lbl('server')}s`; const lang_backends = () => `${lbl('backend')}s`; const lang_frontends = () => `${lbl('frontend')}s`;
async function grLoad() {
  if (!state.current || state.current === '__analysis' || gr.loading) return;
  gr.loading = true; const id = state.current;
  const key = gr.from != null ? `${gr.from}-${gr.to}` : String(gr.range);
  const q = gr.from != null ? `from=${gr.from}&to=${gr.to}` : `range=${gr.range}`;
  try { const d = await api(`/instances/${encodeURIComponent(id)}/history-all?${q}&max=480`); if (id === state.current) { gr.data = d; gr.for = id; gr.loaded = key; } } catch { /* keep the previous data */ }
  gr.loading = false;
  const want = gr.from != null ? `${gr.from}-${gr.to}` : String(gr.range);
  if (state.view === 'graphs') { grPaint(); if (gr.loaded !== want) grLoad(); }
}
function renderGraphs() {
  if (gr.for !== state.current) { gr.data = null; gr.sig = ''; gr.pool = ''; }
  $('#gr-metric').value = gr.metric; grUi();
  if (!gr.data) $('#gr-body').innerHTML = '<div class="skeleton-cards"><i></i><i></i><i></i><i></i><i></i></div>'; else grPaint();
  if (grWindow().live) grLoad(); // while looking at the past, leave the data alone
}
function grWire() {
  $('#gr-metric').innerHTML = GR_METRICS.map(([k, t]) => `<option value="${k}">${esc(t)}</option>`).join('');
  $('#gr-range').addEventListener('change', (e) => {
    if (e.target.value === 'custom') return;
    gr.range = Number(e.target.value); gr.from = gr.to = null;
    try { localStorage.setItem('gatelight.grRange', String(gr.range)); } catch { /* private mode */ }
    grUi(); grLoad();
  });
  const shift = (f) => { const w = grWindow(); const d = (w.t1 - w.t0) * f; const to = w.t1 + d; const from = w.t0 + d; if (f > 0 && w.live) return; grSetWindow(from, to); grLoad(); };
  $('#gr-back').addEventListener('click', () => shift(-0.5));
  $('#gr-fwd').addEventListener('click', () => shift(0.5));
  $('#gr-zout').addEventListener('click', () => { const w = grWindow(); const c = (w.t0 + w.t1) / 2; const h = (w.t1 - w.t0); grSetWindow(c - h, c + h); grLoad(); });
  $('#gr-live').addEventListener('click', grLiveAgain);
  $('#gr-fs').addEventListener('click', toggleTopoFs);
  $('#svc-fs').addEventListener('click', toggleTopoFs);
  $('#cfg-fs').addEventListener('click', toggleTopoFs);
  $('#gr-hand').addEventListener('click', () => { gr.hand = !gr.hand; grUi(); });
  $('#gr-metric').addEventListener('change', (e) => { gr.metric = e.target.value; gr.sig = ''; grPaint(); });
  $('#gr-pool').addEventListener('change', (e) => { gr.pool = e.target.value; gr.sig = ''; grPaint(); });
  $('#gr-search').addEventListener('input', (e) => { gr.q = e.target.value.trim(); gr.sig = ''; grPaint(); });
  const gv = $('#view-graphs');
  gv.addEventListener('click', (e) => {
    const m = e.target.closest('[data-gr-more]'); if (m) { gr.more[m.dataset.grMore] = !gr.more[m.dataset.grMore]; gr.sig = ''; grPaint(); return; }
    const o = e.target.closest('[data-gr-open]'); if (o) { cvOpenCustom(o.dataset.grOpen); return; }
    const lg = e.target.closest('[data-gr-leg]');
    if (lg) {
      const cv2 = document.getElementById(lg.dataset.grLeg); if (!cv2 || !cv2._chart) return;
      if (cv2._chart.series.length > 1) legendClick(cv2, lg.dataset.k, e.ctrlKey || e.metaKey || e.shiftKey);
      else if (gr.focus.has(lg.dataset.grLeg)) gr.focus.delete(lg.dataset.grLeg); else gr.focus.add(lg.dataset.grLeg);
      grPaintCards();
    }
  });
  // Grafana-style time navigation on every chart: drag = zoom into that span, hand tool = pan, double-click = reset,
  // and one shared crosshair across all of them.
  let drag = null; let raf = 0;
  const canvasInfo = (c) => { const d = c._chart; const dom = d && d.domain; return dom ? { c, t0: dom[0], t1: dom[1], r: c.getBoundingClientRect() } : null; };
  const plotOf = (c) => c._plot || { l: 6, r: 6 };
  const tAt = (info, clientX) => { const pb = plotOf(info.c); return info.t0 + Math.max(0, Math.min(1, (clientX - info.r.left - pb.l) / Math.max(1, info.r.width - pb.l - pb.r))) * (info.t1 - info.t0); };
  const repaintAll = () => { if (raf) return; raf = requestAnimationFrame(() => { raf = 0; gr.cards.forEach((_c, id) => { const c = document.getElementById(id); if (c && c._chart) paintChart(c); }); }); };
  gv.addEventListener('pointerdown', (e) => {
    const c = e.target.closest('canvas.gr-canvas'); if (!c || e.button !== 0) return;
    if (legendAt(c, e) != null) return; // clicking the legend filters series
    const info = canvasInfo(c); if (!info) return;
    drag = { c, x: e.clientX, info, mode: gr.hand ? 'pan' : 'zoom', w: grWindow(), moved: false };
    c.setPointerCapture(e.pointerId); chartHover.clear();
  });
  gv.addEventListener('pointermove', (e) => {
    if (drag) {
      const dx = e.clientX - drag.x; if (Math.abs(dx) > 3) drag.moved = true;
      if (drag.mode === 'zoom') { const r = drag.info.r; const pb = plotOf(drag.c); const clamp = (v) => Math.max(pb.l, Math.min(r.width - pb.r, v)); drag.c._sel = { a: clamp(drag.x - r.left), b: clamp(e.clientX - r.left) }; paintChart(drag.c); }
      else if (drag.moved) { const span = drag.w.t1 - drag.w.t0; const pb = plotOf(drag.c); const dt = -(dx / Math.max(1, drag.info.r.width - pb.l - pb.r)) * span; const to = Math.min(Date.now(), drag.w.t1 + dt); grSetWindow(to - span, to); }
      return;
    }
    const c = e.target.closest('canvas.gr-canvas'); if (!c) return;
    const info = canvasInfo(c); if (!info) return;
    const t = tAt(info, e.clientX); gr.cards.forEach((_c, id) => chartHover.set(id, t)); repaintAll();
  });
  const finish = () => { if (!drag) return; const d = drag; drag = null; d.c._sel = null; paintChart(d.c); };
  gv.addEventListener('pointerup', (e) => {
    if (!drag) return; const d = drag;
    if (d.mode === 'zoom' && d.moved) {
      const t1 = tAt(d.info, d.x); const t2 = tAt(d.info, e.clientX);
      const a = Math.min(t1, t2); const b = Math.max(t1, t2);
      if (b - a >= 5000) { finish(); grSetWindow(a, b); grLoad(); return; }
    }
    finish(); if (d.mode === 'pan' && d.moved) grLoad();
  });
  gv.addEventListener('pointercancel', finish);
  // while live, the time axis keeps moving: the charts slide left every second, not only when a new sample arrives
  setInterval(() => { if (!drag && state.view === 'graphs' && !document.hidden && grWindow().live && gr.data) grPaintCards(); }, 1000);
  gv.addEventListener('pointerleave', () => { if (!drag) { chartHover.clear(); repaintAll(); } });
  gv.addEventListener('dblclick', (e) => { if (e.target.closest('canvas.gr-canvas')) grLiveAgain(); });
}

// ---- donut charts: HTTP response classes and error counts (counters since the proxy started) ----
const DN_COLORS = { '1xx': '#64748b', '2xx': '#34d399', '3xx': '#22d3ee', '4xx': '#fbbf24', '5xx': '#f87171', other: '#94a3b8', ereq: '#fb923c', econ: '#f472b6', eresp: '#a78bfa' };
const DN_LABELS = { '1xx': '1xx informational', '2xx': '2xx success', '3xx': '3xx redirect', '4xx': '4xx client errors', '5xx': '5xx server errors', other: 'other', ereq: 'request errors', econ: 'connection errors', eresp: 'response errors' };
function donutSvg(segs, total, center) {
  const R = 40; const C = 2 * Math.PI * R; let off = 0;
  const arcs = total > 0 ? segs.filter((s) => s.value > 0).map((s) => {
    const len = (s.value / total) * C; const el = `<circle class="dn-seg" cx="50" cy="50" r="${R}" fill="none" stroke="${s.color}" stroke-width="14" stroke-dasharray="${len.toFixed(3)} ${(C - len).toFixed(3)}" stroke-dashoffset="${(-off).toFixed(3)}" transform="rotate(-90 50 50)"><title>${esc(s.label)}: ${fmtInt(s.value)} (${((s.value / total) * 100).toFixed(1)}%)</title></circle>`;
    off += len; return el;
  }).join('') : '';
  return `<svg class="dn-svg" viewBox="0 0 100 100" role="img" aria-label="${esc(center.sub)}"><circle cx="50" cy="50" r="${R}" fill="none" stroke="var(--line)" stroke-width="14" opacity=".5"/>${arcs}
    <text x="50" y="49" text-anchor="middle" class="dn-big">${esc(center.big)}</text><text x="50" y="62" text-anchor="middle" class="dn-sub">${esc(center.sub)}</text></svg>`;
}
function donutCard(title, segs, center, help) {
  const total = segs.reduce((a, s) => a + s.value, 0);
  const legend = segs.map((s) => `<li class="${s.value ? '' : 'zero'}"><i style="background:${s.color}"></i><span>${esc(s.label)}</span><b>${fmtInt(s.value)}</b><em>${total ? `${((s.value / total) * 100).toFixed(1)}%` : '–'}</em></li>`).join('');
  return `<div class="dn-card" title="${esc(help || '')}"><div class="dn-head"><b>${esc(title)}</b></div><div class="dn-body">${donutSvg(segs, total, center)}<ul class="dn-legend">${legend}</ul></div></div>`;
}
const sumRows = (rows, k) => rows.reduce((a, r) => a + (r[k] || 0), 0);
function grDonuts() {
  const rows = state.snapshot ? state.snapshot.rows : [];
  const fes = rows.filter((r) => r.kind === 'frontend'); const bes = rows.filter((r) => r.kind === 'backend');
  const has = rows.some((r) => r.hrsp_2xx != null || r.hrsp_5xx != null);
  if (!has) return '<h3 class="gr-h">HTTP responses <span class="muted small">response codes</span></h3><p class="muted">This source does not report HTTP response codes (HAProxy in http mode does), so there are no donut charts to show.</p>';
  const cls = (set) => ['1xx', '2xx', '3xx', '4xx', '5xx', 'other'].map((c) => ({ label: DN_LABELS[c], color: DN_COLORS[c], value: sumRows(set, c === 'other' ? 'hrsp_other' : `hrsp_${c}`) }));
  const all = cls(fes.length ? fes : bes); const allTotal = all.reduce((a, s) => a + s.value, 0);
  const errPct = allTotal ? (((all[3].value + all[4].value) / allTotal) * 100) : 0;
  const errs = [
    { label: DN_LABELS['4xx'], color: DN_COLORS['4xx'], value: all[3].value }, { label: DN_LABELS['5xx'], color: DN_COLORS['5xx'], value: all[4].value },
    { label: DN_LABELS.ereq, color: DN_COLORS.ereq, value: sumRows(fes, 'ereq') }, { label: DN_LABELS.econ, color: DN_COLORS.econ, value: sumRows(bes, 'econ') }, { label: DN_LABELS.eresp, color: DN_COLORS.eresp, value: sumRows(bes, 'eresp') },
  ];
  const errTotal = errs.reduce((a, s) => a + s.value, 0);
  const top = `${donutCard('HTTP responses by class', all, { big: allTotal >= 1e6 ? `${(allTotal / 1e6).toFixed(1)}M` : fmtInt(allTotal), sub: 'responses' }, 'All HTTP responses sent by the frontends since the proxy started.')}
    ${donutCard('Errors', errs, { big: errTotal >= 1e6 ? `${(errTotal / 1e6).toFixed(1)}M` : fmtInt(errTotal), sub: 'errors' }, '4xx and 5xx responses plus request, connection and response errors, since the proxy started.')}
    ${donutCard('Healthy vs failing', [{ label: 'Success, redirects', color: '#34d399', value: all[1].value + all[2].value }, { label: '4xx + 5xx errors', color: '#f87171', value: all[3].value + all[4].value }], { big: `${errPct.toFixed(1)}%`, sub: 'error share' }, 'Share of responses that were errors.')}`;
  const withCodes = bes.filter((r) => ['hrsp_2xx', 'hrsp_4xx', 'hrsp_5xx'].some((k) => r[k] > 0));
  const scored = withCodes.map((r) => { const t = ['hrsp_1xx', 'hrsp_2xx', 'hrsp_3xx', 'hrsp_4xx', 'hrsp_5xx', 'hrsp_other'].reduce((a, k) => a + (r[k] || 0), 0); return { r, t, err: (r.hrsp_4xx || 0) + (r.hrsp_5xx || 0) }; })
    .sort((a, b) => ((b.err / (b.t || 1)) - (a.err / (a.t || 1))) || b.t - a.t);
  const LIM = 12; const list = gr.more.donut ? scored : scored.slice(0, LIM);
  const per = list.map(({ r, t }) => donutCard(r.proxy, cls([r]), { big: t >= 1e6 ? `${(t / 1e6).toFixed(1)}M` : fmtInt(t), sub: 'responses' }, `Response classes for ${r.proxy} since the proxy started.`)).join('');
  const more = scored.length > LIM ? `<div class="gr-more"><button class="btn" type="button" data-gr-more="donut">${gr.more.donut ? 'Show fewer' : `Show all ${scored.length}`}</button></div>` : '';
  return `<h3 class="gr-h">HTTP responses and errors <span class="muted small">counted since the proxy started</span></h3><div class="dn-grid top">${top}</div>
    ${scored.length ? `<h3 class="gr-h">By ${esc(lbl('backend').toLowerCase())} <span class="muted small">${scored.length} · highest error share first</span></h3><div class="dn-grid">${per}</div>${more}` : ''}`;
}

// ---------- shared: horizontal bar chart (HTML, no canvas) ----------
/** items: [{label, value, text?, color?, attrs?}] sorted by the caller. attrs is a pre-escaped attribute string (data-inspect, data-cat…). */
function barChart(title, items, o = {}) {
  const list = items.filter((i) => i.value > 0);
  const max = Math.max(...list.map((i) => i.value), 1e-9);
  const rows = list.map((i) => `<li ${i.attrs || ''} class="${i.attrs ? 'clickable' : ''}" title="${esc(`${i.label}: ${i.text || fmtInt(i.value)}`)}"><span class="bc-l">${esc(i.label)}</span><span class="bc-t"><i style="width:${Math.max(2, (i.value / max) * 100).toFixed(1)}%;background:${i.color || 'var(--cyan)'}"></i></span><b>${esc(i.text || fmtInt(i.value))}</b></li>`).join('');
  return `<div class="bc-card"><div class="bc-head"><b>${esc(title)}</b>${o.sub ? `<span class="muted small">${esc(o.sub)}</span>` : ''}</div>${rows ? `<ul class="bc-list">${rows}</ul>` : `<p class="muted small bc-empty">${esc(o.empty || 'Nothing to show yet')}</p>`}</div>`;
}
const topBars = (rows, field, n, color, fmt, name) => rows.filter((r) => (r[field] || 0) > 0).sort((a, b) => b[field] - a[field]).slice(0, n)
  .map((r) => ({ label: name ? name(r) : (r.kind === 'server' ? `${r.proxy} / ${r.name}` : r.proxy), value: r[field], text: fmt(r[field]), color, attrs: `data-inspect="${esc(r.proxy)}/${esc(r.name)}"` }));

// ---------- SERVICES: charts for the rows the filters currently show ----------
function svcCharts(rows) {
  const servers = rows.filter((r) => r.kind === 'server'); const pools = rows.filter((r) => r.kind === 'backend');
  const cnt = (st) => servers.filter((r) => r.state === st).length;
  const segs = [['up', 'Up', '#34d399'], ['degraded', 'Degraded / draining', '#fbbf24'], ['down', 'Down', '#f87171'], ['maint', 'Maintenance', '#818cf8'], ['nocheck', 'No health check', '#64748b']]
    .map(([k, label, color]) => ({ label, color, value: k === 'degraded' ? cnt('degraded') + cnt('drain') : cnt(k) }));
  const total = segs.reduce((a, s) => a + s.value, 0);
  const donut = total ? donutCard('Server status', segs, { big: `${cnt('up')}/${total}`, sub: 'up' }, 'Health of the servers in the current filter.') : '';
  const kinds = donutCard('Entries, pools and servers', [{ label: lbl('frontend') + 's', color: '#22d3ee', value: rows.filter((r) => r.kind === 'frontend').length }, { label: lbl('backend') + 's', color: '#818cf8', value: pools.length }, { label: lbl('server') + 's', color: '#34d399', value: servers.length }],
    { big: String(rows.length), sub: 'rows' }, 'What the table currently lists.');
  const ms = (v) => `${Math.round(v)} ms`;
  const have = (f) => rows.some((r) => (r[f] || 0) > 0);
  return `<div class="svc-charts-grid">${donut}${rows.length ? kinds : ''}
    ${have('ratePerSec') ? barChart('Busiest pools', topBars(pools, 'ratePerSec', 6, '#22d3ee', (v) => `${fmtRate(v)}/s`), { sub: 'requests / s' }) : ''}
    ${have('err5xxPerSec') ? barChart('Most 5xx errors', topBars(rows.filter((r) => r.kind !== 'frontend'), 'err5xxPerSec', 6, '#f87171', (v) => `${fmtRate(v)}/s`), { sub: '5xx / s' }) : ''}
    ${have('scur') ? barChart('Most sessions', topBars(servers, 'scur', 6, '#818cf8', (v) => fmtInt(v)), { sub: 'open connections' }) : ''}
    ${have('rtime') ? barChart('Slowest servers', topBars(servers, 'rtime', 6, '#fbbf24', ms), { sub: 'response time' }) : ''}
    ${have('bout') ? barChart('Most data sent', topBars(pools, 'bout', 6, '#f472b6', (v) => fmtBytes(v)), { sub: 'since start' }) : ''}</div>`;
}

// ---------- LB INFRA: what sits behind the load balancer, and is it alive ----------
const lbi = { by: 'tree', problems: false, alive: false, open: new Set(), init: false };
const LBI_WORD = { up: 'alive', down: 'down', degraded: 'degraded', drain: 'draining', maint: 'maintenance', nocheck: 'unchecked', unknown: 'unknown' };
function lbiRows() { // live server rows, or the servers from the config when nothing is monitored yet
  const s = state.snapshot; const live = s.rows.filter((r) => r.kind === 'server');
  if (live.length) return { rows: live, monitored: true };
  const rows = [];
  for (const sec of cfgSections()) {
    if (sec.type === 'userlist' || !sec.servers) continue;
    for (const sv of sec.servers) if (!sv.commented) rows.push({ kind: 'server', proxy: sec.name, name: sv.name, state: 'unknown', status: 'not monitored', addr: sv.address });
  }
  return { rows, monitored: false };
}
function lbiServer(r) {
  const addr = (rowEndpoints(r).addrs[0]) || r.addr || '';
  const detail = [r.check_status ? `check ${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}` : '', r.lastchg != null ? `${r.state === 'up' ? 'up' : 'since'} ${fmtDur(r.lastchg)}` : '', r.weight != null && r.weight !== 1 ? `weight ${r.weight}` : ''].filter(Boolean).join(' · ');
  return `<button type="button" class="lbi-srv s-${esc(r.state)}" data-inspect="${esc(r.proxy)}/${esc(r.name)}" title="${esc(`${r.proxy} / ${r.name}\n${addr}\n${r.status || ''}`)}">
    <span class="lbi-dot s-${esc(r.state)}" aria-hidden="true"></span><span class="lbi-n"><b>${esc(r.name)}</b><span class="mono small">${esc(addr || 'address unknown')}</span></span>
    <span class="lbi-st"><span class="st st-${esc(r.state)}">${esc(LBI_WORD[r.state] || r.state)}</span>${detail ? `<span class="muted small">${esc(detail)}</span>` : ''}</span></button>`;
}
const lbiAliveText = (list) => { const up = list.filter((r) => r.state === 'up').length; return `${up}/${list.length} alive`; };
function lbiMeter(list) {
  const t = list.length || 1; const part = (st, cls) => { const n = list.filter((r) => (Array.isArray(st) ? st.includes(r.state) : r.state === st)).length; return n ? `<i class="${cls}" style="width:${(n / t) * 100}%"></i>` : ''; };
  return `<span class="lbi-meter" aria-hidden="true">${part('up', 's-up')}${part(['degraded', 'drain'], 's-degraded')}${part('down', 's-down')}${part('maint', 's-maint')}${part(['nocheck', 'unknown'], 's-unknown')}</span>`;
}
function lbiPoolState(list) { return list.some((r) => r.state === 'down') ? (list.every((r) => r.state === 'down') ? 'down' : 'degraded') : list.some((r) => r.state === 'degraded' || r.state === 'drain') ? 'degraded' : list.length && list.every((r) => r.state === 'up') ? 'up' : 'unknown'; }

// ---- hierarchy: load balancer → frontends → networks → hosts → services (with +/- folding) ----
const lbiIpv4 = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
function lbiTree(s, vis, rows, lbState, type, info, fes, binds) {
  const addrOf = (r) => (rowEndpoints(r).addrs[0]) || r.addr || '';
  const hostOf = (r) => ipOf(addrOf(r)) || 'unknown host';
  const nets = new Map();
  for (const r of vis) {
    const h = hostOf(r); const net = lbiIpv4(h) ? `${h.split('.').slice(0, 3).join('.')}.0/24` : (h === 'unknown host' ? 'Unknown' : 'Named hosts');
    if (!nets.has(net)) nets.set(net, new Map()); const hm = nets.get(net); if (!hm.has(h)) hm.set(h, []); hm.get(h).push(r);
  }
  const natural = (a, b) => a.localeCompare(b, undefined, { numeric: true });
  const netKeys = [...nets.keys()].sort(natural);
  if (!lbi.init) { lbi.init = true; lbi.open.add('lb'); netKeys.forEach((n) => { lbi.open.add(`n:${n}`); nets.get(n).forEach((_l, h) => lbi.open.add(`h:${h}`)); }); }
  const allRows = (hm) => [...hm.values()].flat();
  const word = (st) => `<span class="st st-${esc(st)}">${esc(LBI_WORD[st] || st)}</span>`;
  const tog = (id, open) => `<button type="button" class="tt" data-lbt-toggle="${esc(id)}" aria-label="${open ? 'Collapse' : 'Expand'}"></button>`;
  const node = (id, cls, head, kids) => { const open = lbi.open.has(id); return `<li class="lbt-n ${cls}" aria-expanded="${open}"><div class="lbt-row">${tog(id, open)}${head}</div><ul${open ? '' : ' hidden'}>${kids}</ul></li>`; };
  const svc = (r) => { const port = portOf(addrOf(r)); const d = [r.check_status ? `check ${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}` : '', r.lastchg != null ? `${r.state === 'up' ? 'up' : 'since'} ${fmtDur(r.lastchg)}` : ''].filter(Boolean).join(' · ');
    return `<li class="lbt-n svc s-${esc(r.state)}"><button type="button" class="lbt-row lbt-leaf" data-inspect="${esc(r.proxy)}/${esc(r.name)}"><span class="lbi-dot s-${esc(r.state)}" aria-hidden="true"></span><span class="lbt-port mono">${port ? `:${esc(port)}` : '–'}</span><b>${esc(r.name)}</b><span class="chip">${esc(r.proxy)}</span>${word(r.state)}${d ? `<span class="muted small">${esc(d)}</span>` : ''}</button></li>`; };
  const host = (net, h, list) => { const st = lbiPoolState(list); const names = uniq(list.map((r) => r.name)); const pools = uniq(list.map((r) => r.proxy));
    return node(`h:${h}`, `host s-${st}`, `<span class="lbi-dot s-${st}" aria-hidden="true"></span><b class="mono">${esc(h)}</b>${word(st)}<span class="muted small">${esc(lbiAliveText(list))} · ${list.length} service${list.length === 1 ? '' : 's'}</span><span class="lbt-ids muted small" title="${esc(names.join(', '))}">${esc(names.slice(0, 3).join(', '))}${names.length > 3 ? ` +${names.length - 3}` : ''}</span>${lbiMeter(list)}`,
      list.sort((a, b) => natural(portOf(addrOf(a)), portOf(addrOf(b)))).map(svc).join('')); };
  const net = (n) => { const hm = nets.get(n); const list = allRows(hm); const st = lbiPoolState(list);
    return node(`n:${n}`, `net s-${st}`, `<span class="lbt-ico" aria-hidden="true">⌗</span><b class="mono">${esc(n)}</b><span class="muted small">${hm.size} host${hm.size === 1 ? '' : 's'} · ${esc(lbiAliveText(list))}</span>${lbiMeter(list)}`,
      [...hm.keys()].sort(natural).map((h) => host(n, h, hm.get(h))).join('')); };
  const allList = vis; const lbSt = lbState === 'up' ? lbiPoolState(rows) : 'unknown';
  const ports = binds.slice(0, 6).map((b) => `<span class="chip mono">${esc(b)}</span>`).join(' ');
  const root = node('lb', `lb s-${lbSt}`, `<span class="lbi-dot s-${lbState}" aria-hidden="true"></span><b>${esc(s.instance.name || state.current)}</b><span class="muted small">${esc(type)}${info.version ? ` ${esc(info.version)}` : ''}${info.uptimeSec != null ? ` · up ${esc(fmtDur(info.uptimeSec))}` : ''}</span>${word(lbState === 'up' ? lbSt : lbState === 'down' ? 'down' : 'unknown')}<span class="muted small">${nets.size} network${nets.size === 1 ? '' : 's'} · ${new Set(allList.map(hostOf)).size} hosts · ${esc(lbiAliveText(rows))}</span>`,
    `${fes.length || ports ? `<li class="lbt-n front"><div class="lbt-row"><span class="lbt-ico" aria-hidden="true">⇥</span><span class="muted small">Entry points</span>${fes.map((f) => `<button type="button" class="chip" data-inspect="${esc(f.proxy)}/${esc(f.name)}">${esc(f.proxy)}${rowEndpoints(f).ports.length ? ` :${esc(rowEndpoints(f).ports.slice(0, 3).join(', :'))}` : ''}</button>`).join(' ') || ports}</div></li>` : ''}${netKeys.map(net).join('') || '<li class="empty">Nothing to show for this filter</li>'}`);
  return `<div class="lbt"><div class="lbt-ctl"><button type="button" class="btn" data-lbt-all="open">＋ Expand all</button><button type="button" class="btn" data-lbt-all="close">－ Collapse all</button></div><ul class="lbt-root">${root}</ul></div>`;
}
function renderLbInfra() {
  const s = state.snapshot; const el = $('#infra'); if (!s || !el) return;
  const { rows, monitored } = lbiRows();
  const vis = lbi.problems ? rows.filter((r) => r.state !== 'up') : lbi.alive ? rows.filter((r) => r.state === 'up') : rows;
  const count = (st) => rows.filter((r) => r.state === st).length;
  const fes = s.rows.filter((r) => r.kind === 'frontend'); const info = s.info || {};
  const binds = []; for (const sec of cfgSections()) if (feLike(sec)) for (const b of sec.binds || []) if (!b.commented) binds.push(...b.addresses.map((a) => `${sec.name} ${a}`));
  const type = TYPE_NAME[snapshotType()] || 'Load balancer';
  const lbState = s.ok ? 'up' : (s.instance.source === 'config-only' ? 'unknown' : 'down');
  const hosts = new Set(rows.map((r) => ipOf((rowEndpoints(r).addrs[0]) || r.addr || '')).filter(Boolean));
  const pools = [...new Set(rows.map((r) => r.proxy))].sort();
  const bePools = new Map(s.rows.filter((r) => r.kind === 'backend').map((r) => [r.proxy, r]));
  const lb = `<div class="lbi-lb"><div class="lbi-lb-h"><span class="lbi-dot s-${lbState}" aria-hidden="true"></span><b>${esc(s.instance.name || state.current)}</b><span class="st st-${lbState}">${lbState === 'up' ? 'alive' : lbState === 'down' ? 'unreachable' : 'config only'}</span></div>
    <div class="muted small">${esc(type)}${info.version ? ` ${esc(info.version)}` : ''}${info.uptimeSec != null ? ` · up ${esc(fmtDur(info.uptimeSec))}` : ''}</div>
    ${fes.length ? `<h4>${esc(lbl('frontend'))}s</h4><ul class="lbi-fe">${fes.map((f) => `<li data-inspect="${esc(f.proxy)}/${esc(f.name)}" class="clickable"><span class="lbi-dot s-${esc(f.state)}" aria-hidden="true"></span><b>${esc(f.proxy)}</b>${(rowEndpoints(f).ports.length ? `<span class="mono small muted">:${esc(rowEndpoints(f).ports.join(', :'))}</span>` : '')}</li>`).join('')}</ul>` : (binds.length ? `<h4>Listening</h4><ul class="lbi-fe">${binds.slice(0, 8).map((b) => `<li><span class="mono small">${esc(b)}</span></li>`).join('')}</ul>` : '')}
    <div class="lbi-sum"><div><b>${count('up')}</b><span>alive</span></div><div class="${count('down') ? 'bad' : ''}"><b>${count('down')}</b><span>down</span></div><div><b>${count('degraded') + count('drain')}</b><span>degraded</span></div><div><b>${hosts.size}</b><span>hosts</span></div></div></div>`;

  let body = '';
  if (lbi.by === 'host') {
    const groups = new Map();
    for (const r of vis) { const h = ipOf((rowEndpoints(r).addrs[0]) || r.addr || '') || 'unknown host'; if (!groups.has(h)) groups.set(h, []); groups.get(h).push(r); }
    body = [...groups].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true })).map(([h, list]) => {
      const st = lbiPoolState(list);
      return `<section class="lbi-pool s-${st}"><header><span class="lbi-dot s-${st}" aria-hidden="true"></span><b class="mono">${esc(h)}</b><span class="st st-${st}">${esc(LBI_WORD[st] || st)}</span><span class="muted small">${esc(lbiAliveText(list))} · ${list.length} service${list.length === 1 ? '' : 's'}</span>${lbiMeter(list)}</header>
        <div class="lbi-srvs">${list.map((r) => lbiServer(r)).join('')}</div><div class="muted small lbi-from">serves: ${esc(uniq(list.map((r) => r.proxy)).join(', '))}</div></section>`;
    }).join('');
  } else {
    body = pools.map((p) => {
      const all = rows.filter((r) => r.proxy === p); const list = vis.filter((r) => r.proxy === p); if (!list.length) return '';
      const st = bePools.get(p) && bePools.get(p).state === 'down' ? 'down' : lbiPoolState(all);
      const from = rowRelations({ kind: 'backend', proxy: p, name: 'BACKEND' }).frontends;
      return `<section class="lbi-pool s-${st}"><header><span class="lbi-dot s-${st}" aria-hidden="true"></span><b class="clickable" data-inspect="${esc(p)}/BACKEND">${esc(p)}</b><span class="st st-${st}">${esc(LBI_WORD[st] || st)}</span><span class="muted small">${esc(lbiAliveText(all))}</span>${lbiMeter(all)}</header>
        ${from.length ? `<div class="muted small lbi-from">reached from: ${from.map((f) => `<span class="chip" data-inspect="${esc(f.key)}">${esc(f.label)}</span>`).join(' ')}</div>` : ''}
        <div class="lbi-srvs">${list.map((r) => lbiServer(r)).join('')}</div></section>`;
    }).join('');
  }
  el.innerHTML = `<div class="lbi-bar"><div class="seg" role="group" aria-label="Group by"><button type="button" class="${lbi.by === 'tree' ? 'on' : ''}" data-lbi-by="tree">Hierarchy</button><button type="button" class="${lbi.by === 'pool' ? 'on' : ''}" data-lbi-by="pool">By pool</button><button type="button" class="${lbi.by === 'host' ? 'on' : ''}" data-lbi-by="host">By host</button></div>
    <label class="gr-ctl"><input type="checkbox" id="lbi-alive"${lbi.alive ? ' checked' : ''}> Only show what is alive</label>
    <label class="gr-ctl"><input type="checkbox" id="lbi-problems"${lbi.problems ? ' checked' : ''}> Only show what is not alive</label><span class="spacer"></span>
    <span class="muted small lbi-key"><i class="lbi-dot s-up"></i>alive <i class="lbi-dot s-degraded"></i>degraded <i class="lbi-dot s-down"></i>down <i class="lbi-dot s-maint"></i>maintenance <i class="lbi-dot s-unknown"></i>unchecked</span></div>
    ${monitored ? '' : '<div class="banner info lbi-note">No live statistics for this instance, so aliveness is unknown. Connect the stats endpoint to see live status; the layout below comes from the config.</div>'}
    ${rows.length && lbi.by === 'tree' ? lbiTree(s, vis, rows, lbState, type, info, fes, binds) : rows.length ? `<div class="lbi-layout">${lb}<div class="lbi-pools">${body || (lbi.alive ? '<div class="empty">Nothing is alive right now</div>' : '<div class="empty">✓ Everything is alive</div>')}</div></div>` : '<div class="empty">Nothing behind this load balancer yet. Attach a config or connect the stats endpoint.</div>'}`;
}
// ---------- CHART POP-OUT ----------
const cv = { source: null, span: 0, end: null, hidden: new Set(), hand: true }; // span 0 = all history; end null = follow the newest sample
const CV_WINDOWS = [['5 min', 5], ['15 min', 15], ['30 min', 30], ['1 hour', 60], ['All data', 0]];
function cvData() {
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
  let title; let times; let series;
  if ((cv.source === 'inspector' && state.inspected) || cv.source === 'row') {
    const key = cv.source === 'row' ? cv.rowKey : state.inspected.key; const hist = cv.source === 'row' ? cv.rowHist : inspHistory;
    title = key.replace('/', ' / '); times = hist.map((p) => p.t);
    series = [{ k: 'rate', label: 'req/s', color: '#22d3ee', values: hist.map((p) => num(p.rate)) }, { k: 'e5', label: '5xx/s', color: '#f87171', values: hist.map((p) => num(p.e5xx)), minMax: 1 }, { k: 'sess', label: 'sessions', color: '#818cf8', values: hist.map((p) => num(p.scur)) }, { k: 'srate', label: 'sessions/s', color: '#34d399', values: hist.map((p) => num(p.srate)) }];
    if (hist.some((p) => p.rtime != null)) series.push({ k: 'rt', label: 'resp ms', color: '#fbbf24', values: hist.map((p) => num(p.rtime)) });
  } else {
    const inst = state.instances.find((i) => i.id === state.current);
    title = `Traffic${inst ? `: ${inst.name}` : ''}`; times = state.series.map((p) => p.t);
    series = [{ k: 'rate', label: 'req/s', color: '#22d3ee', values: state.series.map((p) => num(p.rate)) }, { k: 'e5', label: '5xx/s', color: '#f87171', values: state.series.map((p) => num(p.e5)), minMax: 1 }, { k: 'sess', label: 'sessions', color: '#818cf8', values: state.series.map((p) => num(p.sess)) }, { k: 'srate', label: 'sessions/s', color: '#34d399', values: state.series.map((p) => num(p.srate)) }];
  }
  if (cv.source === 'custom' && cv.custom) { const c = cv.custom(); title = c.title; times = c.times; series = c.series; }
  const full = { times, series };
  if (cv.span && times.length) {
    const last = times[times.length - 1]; const t1 = cv.end == null ? last : Math.min(cv.end, last); const t0 = t1 - cv.span;
    let from = times.findIndex((t) => t >= t0); if (from < 0) from = times.length;
    let to = times.length; for (let k = times.length - 1; k >= 0; k--) { if (times[k] <= t1) { to = k + 1; break; } }
    times = times.slice(from, to); series = series.map((x) => ({ ...x, values: x.values.slice(from, to) }));
    return { title, times, series, full, view: { t0, t1 } };
  }
  return { title, times, series, full, view: times.length ? { t0: times[0], t1: times[times.length - 1] } : null };
}
function cvOpenCustom(id) { cv.custom = () => grBuild(id, true); cvOpen('custom'); }
function cvOpen(source) {
  cv.source = source; cv.hidden = new Set(); cv.span = 0; cv.end = null;
  $('#chartview').hidden = false; cvRender();
}
async function cvLoadRow() {
  try { const h = await api(`/instances/${encodeURIComponent(state.current)}/history?key=${encodeURIComponent(cv.rowKey)}&points=360`); if (cv.source === 'row') { cv.rowHist = h.points; cvRender(); } } catch { /* keep what we have */ }
}
function cvOpenRow(key) { cv.rowKey = key; cv.rowHist = []; cvOpen('row'); cvLoadRow(); }
function cvClose() { $('#chartview').hidden = true; cv.source = null; }
function cvSetView(span, end) {
  const { full } = cvData(); const all = full.times;
  const fullSpan = all.length > 1 ? all[all.length - 1] - all[0] : 0;
  if (!span || span >= fullSpan) { cv.span = 0; cv.end = null; return; }
  const last = all[all.length - 1]; const first = all[0];
  let e = end == null ? last : Math.max(first + span, Math.min(end, last));
  cv.span = span; cv.end = e >= last ? null : e;
}
function cvZoom(factor, u = 0.5) {
  const { full, view } = cvData(); const all = full.times; if (all.length < 2 || !view) return;
  const fullSpan = all[all.length - 1] - all[0]; const span = view.t1 - view.t0;
  const next = Math.max(Math.min(fullSpan, span * factor), Math.min(fullSpan, 20000));
  const tc = view.t0 + u * span; const t0 = tc - u * next;
  cvSetView(next, t0 + next); cvRender();
}
function cvRender() {
  if ($('#chartview').hidden) return;
  const { title, times, series, full, view } = cvData();
  $('#cv-title').textContent = title;
  // range menu: presets, or "Custom" once zoomed/panned
  const preset = CV_WINDOWS.find(([, m]) => m * 60000 === cv.span);
  const opts = CV_WINDOWS.map(([t, m]) => `<option value="${m}"${preset && preset[1] === m ? ' selected' : ''}>${esc(t)}</option>`);
  if (!preset) opts.push('<option value="custom" selected>Custom</option>');
  $('#cv-win').innerHTML = opts.join('');
  $('#cv-hand').classList.toggle('on', cv.hand); $('#cv-hand').setAttribute('aria-pressed', String(cv.hand));
  $('#cv-canvas').style.cursor = cv.hand ? (cv._drag ? 'grabbing' : 'grab') : 'crosshair';
  const shown = series.filter((x) => !cv.hidden.has(x.k));
  const fmt = (x, v) => (x.fmt ? x.fmt(v) : x.label === 'sessions' ? fmtInt(v) : fmtRate(v));
  $('#cv-legend').innerHTML = series.map((x) => `<button type="button" class="cv-chip${cv.hidden.has(x.k) ? ' off' : ''}" data-cv-toggle="${x.k}" aria-pressed="${!cv.hidden.has(x.k)}"><i style="background:${x.color}"></i>${esc(x.label)}</button>`).join('');
  const total = full.times.length ? full.times[full.times.length - 1] - full.times[0] : 0;
  const mins = (ms) => (ms >= 90000 ? `${Math.round(ms / 60000)} min` : `${Math.round(ms / 1000)} s`);
  $('#cv-stats').innerHTML = times.length ? `<table class="grid"><thead><tr><th>Series</th><th class="num">Now</th><th class="num">Average</th><th class="num">Peak</th><th class="num">Lowest</th></tr></thead><tbody>${series.map((x) => {
    const v = x.values; const avg = v.reduce((a, b) => a + b, 0) / v.length;
    return `<tr class="${cv.hidden.has(x.k) ? 'dim' : ''}"><td><i class="cv-dot" style="background:${x.color}"></i>${esc(x.label)}</td><td class="num">${fmt(x, v[v.length - 1])}</td><td class="num">${fmt(x, avg)}</td><td class="num">${fmt(x, Math.max(...v))}</td><td class="num">${fmt(x, Math.min(...v))}</td></tr>`;
  }).join('')}</tbody></table><div class="muted small">Showing ${times.length} of ${full.times.length} samples · ${fmtTime(times[0])} to ${fmtTime(times[times.length - 1])} · history available: ${mins(total)}${cv.end != null ? ' · <b>not following live</b>' : ''}</div>` : '<div class="muted">Collecting data… the chart fills in as samples arrive.</div>';
  drawChart($('#cv-canvas'), times, shown);
  cvMini(full, view);
}
/** Overview strip of ALL available history, with the visible window highlighted. Click or drag on it to jump around. */
function cvMini(full, view) {
  const c = $('#cv-mini'); if (!c) return;
  const dpr = window.devicePixelRatio || 1; const W = c.clientWidth; const H = c.clientHeight;
  c.width = W * dpr; c.height = H * dpr; const ctx = c.getContext('2d'); ctx.scale(dpr, dpr); ctx.clearRect(0, 0, W, H);
  const t = full.times; if (t.length < 2) return;
  const t0 = t[0]; const t1 = t[t.length - 1]; const x = (v) => 4 + ((v - t0) / Math.max(1, t1 - t0)) * (W - 8);
  const first = full.series.find((s) => !cv.hidden.has(s.k)) || full.series[0];
  const max = Math.max(...first.values, first.minMax || 0.0001);
  ctx.strokeStyle = first.color; ctx.globalAlpha = .8; ctx.lineWidth = 1.2; ctx.beginPath();
  first.values.forEach((v, i) => { const yy = H - 4 - (v / max) * (H - 8); if (i) ctx.lineTo(x(t[i]), yy); else ctx.moveTo(x(t[i]), yy); }); ctx.stroke(); ctx.globalAlpha = 1;
  if (view) {
    const a = x(Math.max(t0, view.t0)); const b = x(Math.min(t1, view.t1));
    ctx.fillStyle = 'rgba(34,211,238,.16)'; ctx.fillRect(a, 1, Math.max(3, b - a), H - 2);
    ctx.strokeStyle = '#22d3ee'; ctx.lineWidth = 1.5; ctx.strokeRect(a + .75, 1.75, Math.max(3, b - a) - 1.5, H - 3.5);
  }
  c._map = { t0, t1, W };
}
function cvCsv() {
  const { times, series } = cvData();
  const rows = [['time', ...series.map((x) => x.label)].join(','), ...times.map((t, i) => [new Date(t).toISOString(), ...series.map((x) => x.values[i])].join(','))];
  download(`gatelight-${cv.source === 'inspector' ? 'entity' : 'traffic'}.csv`, rows.join('\n'), 'text/csv');
}

// ---------- UPDATE CONFIG (re-upload) ----------
const cu = { id: null, files: [], review: false };
const cuResult = (m, k) => { const r = $('#cu-result'); r.className = `cx-result ${k || ''}`; r.textContent = m || ''; };
function cuSync() {
  const hasText = $('#cu-text').value.trim().length > 0;
  $('#cu-save').disabled = !(cu.files.length || hasText);
  $('#cu-note').textContent = cu.files.length ? `${cu.files.length} file${cu.files.length === 1 ? '' : 's'} ready: ${cu.files.slice(0, 4).map((f) => f.name).join(', ')}${cu.files.length > 4 ? ` +${cu.files.length - 4}` : ''}` : '';
}
function cuOpen() {
  const review = state.mode === 'review';
  const inst = state.instances.find((i) => i.id === state.current);
  if (!review && !(inst && inst.managed)) { toast('Only connections you added in this browser can have their config updated here.', 'info'); return; }
  cu.id = review ? null : inst.id; cu.review = review; cu.files = [];
  $('#cu-form').reset(); cuResult(''); cuSync();
  $('#cu-title').textContent = review ? 'Update the config under review' : `Update config: ${inst.name}`;
  $('#cu-lead').textContent = review ? 'Upload the new version to re-run the analysis. Nothing is saved.' : 'Upload the new version. It replaces the stored config: the map, URL map, audit and config view are rebuilt from it, and anything that no longer exists is dropped.';
  $('#cfgup').hidden = false; $('#cu-drop').focus();
}
function cuClose() { $('#cfgup').hidden = true; cu.files = []; $('#cu-text').value = ''; }
async function cuPick(list) {
  const arr = [...list].map((f) => (f && f.file ? f : { name: f.webkitRelativePath || f.name, file: f }));
  if (!arr.length) return;
  const { files, skipped } = await readConfigFiles(arr);
  cu.files = files; $('#cu-text').value = ''; cuSync(); cuResult(skipped.length ? `Skipped: ${skipped.join(', ')}` : '', skipped.length ? 'err' : '');
}
async function cuSave(ev) {
  ev.preventDefault();
  const files = cu.files.length ? cu.files : null; const text = $('#cu-text').value;
  cuResult('Updating…', 'busy'); $('#cu-save').disabled = true;
  try {
    if (cu.review) {
      cuClose();
      await runAnalyze(files ? { files } : { config: text }, 'updated config');
      return;
    }
    const r = await api(`/instances/${encodeURIComponent(cu.id)}/config`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(files ? { configFiles: files } : { configText: text }) });
    cuClose();
    cfgRendered = null; state.cfgFile = null; state.focus = null; closeInspector();
    if (network) { network.destroy(); network = null; }
    await poll(true);
    const add = r.added.length; const rem = r.removed.length;
    toast(add || rem ? `Config updated: ${add} added, ${rem} removed${add + rem <= 4 ? ` (${[...r.added.map((x) => `+ ${x}`), ...r.removed.map((x) => `− ${x}`)].join(', ')})` : ''}` : `Config updated (${r.files} file${r.files === 1 ? '' : 's'}): no structural changes`, 'ok', 6000);
  } catch (e) { cuResult(`✗ ${e.message}`, 'err'); cuSync(); }
}

// ---------- CONNECT A SERVER ----------
const cx = { editing: null, hadPassword: false, hadConfig: false, files: [], logFiles: [] };
const cxType = () => document.querySelector('input[name="cx-type"]:checked').value;
function cxSync() {
  const t = cxType();
  $$('#cx-form [data-cx-for]').forEach((el) => { el.hidden = el.dataset.cxFor !== t; });
  $('#cx-url-label').textContent = t === 'nginx' ? 'Status URL (stub_status)' : 'Stats URL';
  $('#cx-url').placeholder = t === 'nginx' ? 'http://host/nginx_status' : 'http://host:8404/stats';
  const hasCfg = cx.files.length > 0 || $('#cx-cfgtext').value.trim() || $('#cx-cfgurls').value.trim() || cx.hadConfig || cx.logFiles.length;
  const live = $('#cx-url').value.trim() || ($('#cx-socket').value || '').trim() || ($('#cx-plus').value || '').trim();
  const configOnly = Boolean(hasCfg && !live);
  $('#cx-test').hidden = configOnly;
  $('#cx-url-opt').hidden = !hasCfg;
  const logOnly = configOnly && cx.logFiles.length && !(cx.files.length || $('#cx-cfgtext').value.trim() || $('#cx-cfgurls').value.trim() || cx.hadConfig);
  $('#cx-save').textContent = cx.editing ? (cx.logFiles.length ? `Save & upload ${cx.logFiles.length > 1 ? 'logs' : 'log'}` : 'Save changes') : logOnly ? 'Save & analyse logs' : configOnly ? 'Save config' : cx.inline ? 'Connect' : 'Save & connect';
  { const lp = $('#cx-logprod'); if (lp) lp.textContent = t === 'nginx' ? 'NGINX access' : 'HAProxy'; const lh = $('#cx-loghelp'); if (lh && lh.dataset.prod !== t) { lh.dataset.prod = t; lh.innerHTML = logHelpHtml(t); } }
  $('#cx-logmax').textContent = fmtBytes((state.meta && state.meta.logMaxBytes) || 50 * 1048576);
}
function cxFilesNote() {
  cxAttachStatus();
  $('#cx-cfgclear').hidden = !cx.files.length;
  $('#cx-cfgnote').textContent = cx.files.length ? `${cx.files.length} file${cx.files.length === 1 ? '' : 's'} ready: ${cx.files.slice(0, 4).map((f) => f.name).join(', ')}${cx.files.length > 4 ? ` +${cx.files.length - 4}` : ''}`
    : (cx.hadConfig ? `A config is already stored (${cx.hadNames}). Choose files or paste to replace it.` : '');
}
function cxAttachStatus() {
  const el = $('#cx-cfgstatus'); if (!el) return;
  const n = cx.files.length, txt = $('#cx-cfgtext').value.trim();
  el.className = 'cx-attach ' + (n || txt || cx.hadConfig ? 'on' : 'off');
  el.textContent = n ? `✓ ${n} file${n === 1 ? '' : 's'} attached: ${cx.files.slice(0, 2).map((f) => f.name).join(', ')}${n > 2 ? ` +${n - 2}` : ''}`
    : txt ? '✓ Pasted config will be used' : cx.hadConfig ? `✓ Stored config kept (${cx.hadNames})` : 'No file attached';
}
async function cxPickFiles(fileList) {
  const list = [...fileList].map((f) => ({ name: f.webkitRelativePath || f.name, file: f }));
  if (!list.length) return;
  const { files, skipped } = await readConfigFiles(list);
  cx.files = files; $('#cx-cfgtext').value = '';
  cxFilesNote(); cxSync(); cxResult(skipped.length ? `Skipped: ${skipped.join(', ')}` : '', skipped.length ? 'err' : '');
}
function cxResult(msg, kind) { const r = $('#cx-result'); r.className = `cx-result ${kind || ''}`; r.textContent = msg || ''; }
function cxBody() {
  const t = cxType();
  const b = {
    type: t, name: $('#cx-name').value, statsUrl: $('#cx-url').value, username: $('#cx-user').value, password: $('#cx-pass').value,
    insecureTls: $('#cx-insecure').checked,
  };
  if (cx.files.length) b.configFiles = cx.files; else if ($('#cx-cfgtext').value.trim()) b.configText = $('#cx-cfgtext').value; else b.keepConfig = cx.hadConfig;
  b.configUrls = $('#cx-cfgurls').value;
  if (cx.logFiles.length) b.logOnly = true;
  if (t === 'haproxy') b.socket = $('#cx-socket').value;
  else { b.plusApiUrl = $('#cx-plus').value; if ($('#cx-url').value.trim() || $('#cx-plus').value.trim() || !(cx.files.length || $('#cx-cfgtext').value.trim() || cx.hadConfig)) b.probe = $('#cx-probe').checked; }
  if (cx.editing) b.id = cx.editing;
  return b;
}
/** Saved-connections list: highlight the row being modified, and show Cancel while editing. */
function cxMarkEditing() {
  $$('.lp-row').forEach((r) => { const b = r.querySelector('.lp-edit'); const on = Boolean(b) && b.dataset.cxEdit === cx.editing; r.classList.toggle('editing', on); if (b) b.textContent = on ? 'Editing…' : 'Modify'; });
  const c = $('#cx-cancel'); if (c) c.hidden = !(cx.editing && cx.inline);
}
async function cxOpen(id, inline = false) {
  if (!state.meta.canManage) return;
  cx.inline = inline;
  const form = $('#cx-form');
  if (inline) { $('#lp-form-slot').appendChild(form); form.classList.add('inline'); }
  else { $('#connect').appendChild(form); form.classList.remove('inline'); }
  cx.editing = id || null; cx.hadPassword = false; cx.hadConfig = false; cx.hadNames = ''; cx.files = []; cx.logFiles = []; cxLogNote();
  $('#cx-form').reset();
  $('#cx-title').textContent = id ? 'Edit connection' : 'Connect a server';
  cxResult('');
  const warn = $('#cx-warn');
  warn.hidden = state.meta.authEnabled;
  warn.textContent = state.meta.authEnabled ? '' : 'Authentication is off: anyone who can open this page can add servers and see their data. Set AUTH_USER / AUTH_PASS before exposing GateLight beyond this machine.';
  if (id) {
    try {
      const d = await api(`/instances/${encodeURIComponent(id)}/definition`);
      document.querySelector(`input[name="cx-type"][value="${d.type}"]`).checked = true;
      $('#cx-name').value = d.name || ''; $('#cx-url').value = d.statsUrl || ''; $('#cx-user').value = d.username || '';
      $('#cx-insecure').checked = Boolean(d.insecureTls); $('#cx-socket').value = d.socket || ''; $('#cx-plus').value = d.plusApiUrl || '';
      $('#cx-probe').checked = d.probe !== false; $('#cx-cfgurls').value = (d.configUrls || []).join('\n');
      cx.hadPassword = d.hasPassword; cx.hadConfig = (d.configFiles || []).length > 0; cx.hadNames = (d.configFiles || []).slice(0, 3).join(', ') + ((d.configFiles || []).length > 3 ? '…' : '');
      $('#cx-pass').placeholder = d.hasPassword ? '•••••••• (unchanged)' : '';
      if (d.socket || d.plusApiUrl) $('#cx-form details.adv').open = true;
    } catch (e) { toast(e.message, 'bad'); return; }
  } else { $('#cx-pass').placeholder = ''; $('#cx-form details.adv').open = false; }
  cxFilesNote(); cxSync(); cxMarkEditing();
  if (!inline) { $('#connect').hidden = false; $('#cx-name').focus(); }
}
function cxClose() { $('#connect').hidden = true; $('#cx-pass').value = ''; }
async function cxPost(path, method) {
  return api(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cxBody()) });
}
async function cxTest() {
  cxResult('Connecting…', 'busy'); $('#cx-test').disabled = true;
  try {
    const r = await cxPost('/instances/test', 'POST');
    if (r.ok) cxResult(`✓ Connected${r.version ? ` — ${r.version}` : ''} · ${r.frontends} frontend${r.frontends === 1 ? '' : 's'} · ${r.backends} backend${r.backends === 1 ? '' : 's'} · ${r.servers} server${r.servers === 1 ? '' : 's'}`, 'ok');
    else cxResult(`✗ ${r.error}`, 'err');
  } catch (e) { cxResult(`✗ ${e.message}`, 'err'); }
  $('#cx-test').disabled = false;
}
// ---- traffic log upload (shared by the Add instance form and the Traffic statistics page) ----
const LOG_BAD_EXT = /\.(zip|tar|tgz|7z|rar|bz2|xz|zst|pdf|png|jpe?g|gif|xlsx?|docx?|pptx?|exe|dll|bin|iso|db|sqlite)$/i;
/** null when the file may be uploaded, otherwise the message to show. */
function logFileProblem(f) {
  const max = (state.meta && state.meta.logMaxBytes) || 50 * 1048576;
  if (!f) return null;
  if (LOG_BAD_EXT.test(f.name)) return `“${f.name}” is not a text log. Upload the plain-text log (.log or .txt) or a gzip of it (.gz).`;
  if (f.size === 0) return `“${f.name}” is empty.`;
  if (f.size > max) return `“${f.name}” is ${fmtBytes(f.size)}, over the ${fmtBytes(max)} limit. Split it first with the commands below, then select the parts together.`;
  return null;
}
/** PUT the file as the raw request body (streamed by the browser, parsed as a stream by the server). */
function uploadLog(id, file, onProgress, mode) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open('PUT', `/api/instances/${encodeURIComponent(id)}/logs?filename=${encodeURIComponent(file.name)}${mode ? `&mode=${mode}` : ''}`);
    x.setRequestHeader('Content-Type', 'application/octet-stream');
    x.upload.onprogress = (e) => { if (onProgress && e.lengthComputable) onProgress(e.loaded, e.total, false); };
    x.upload.onload = () => { if (onProgress) onProgress(file.size, file.size, true); };
    x.onload = () => {
      let j = null; try { j = JSON.parse(x.responseText); } catch { /* not JSON */ }
      if (x.status >= 200 && x.status < 300) resolve(j);
      else if (x.status === 401) { location.replace(`/login?next=${encodeURIComponent(location.pathname)}${location.hash}`); reject(new Error('Signing in again…')); }
      else reject(new Error((j && j.error) || `Upload failed (HTTP ${x.status})`));
    };
    x.onerror = () => reject(new Error('The upload was interrupted. If the file is larger than the server limit, split it into smaller parts first.'));
    x.send(file);
  });
}
function logProgressUi(box, loaded, total, done, prefix = '') {
  box.hidden = false;
  const pct = total ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
  box.querySelector('.tr-bar i').style.width = `${done ? 100 : pct}%`;
  box.querySelector('.tr-bar').classList.toggle('busy', Boolean(done));
  box.querySelector('span').textContent = done ? `${prefix}uploaded. Processing…` : `${prefix}uploading ${fmtBytes(loaded)} of ${fmtBytes(total)} (${pct}%)`;
}
function cxLogNote() {
  const n = $('#cx-lognote'); const c = $('#cx-logclear'); if (!n) return;
  c.hidden = !cx.logFiles.length;
  n.className = 'small';
  n.innerHTML = cx.logFiles.map((f, i) => `<span class="tr-chip">${esc(f.name)} <span class="muted">${esc(fmtBytes(f.size))}</span><button type="button" data-cx-logrm="${i}" title="Remove" aria-label="Remove ${esc(f.name)}">×</button></span>`).join('');
}
/** Add the chosen files to the list; files that cannot be uploaded are reported and skipped. */
function cxPickLog(files) {
  const list = [...(files || [])]; const problems = [];
  for (const f of list) {
    const bad = logFileProblem(f);
    if (bad) problems.push(bad); else if (cx.logFiles.some((x) => x.name === f.name && x.size === f.size)) problems.push(`“${f.name}” is already in the list.`); else cx.logFiles.push(f);
  }
  cxLogNote();
  if (problems.length) { const n = $('#cx-lognote'); const e = document.createElement('div'); e.className = 'small sev-error'; e.innerHTML = problems.map((x) => esc(x)).join('<br>'); n.appendChild(e); }
  cxSync();
}
/** Upload files one after the other (the server takes one file per request) and add them to the combined statistics. */
async function uploadLogs(id, files, onStatus, replaceFirst) {
  const done = []; const failed = [];
  for (let i = 0; i < files.length; i++) {
    const f = files[i]; const tag = files.length > 1 ? `File ${i + 1} of ${files.length}: ` : '';
    try { done.push({ name: f.name, res: await uploadLog(id, f, (l, t, d) => onStatus(tag, f, l, t, d), replaceFirst && i === 0 ? 'replace' : 'add') }); } catch (e) { failed.push({ name: f.name, error: e.message }); }
  }
  return { done, failed };
}
const logSummaryToast = (r) => {
  const lines = r.done.reduce((a, d) => a + d.res.stats.lines, 0); const skipped = r.done.reduce((a, d) => a + d.res.stats.unparsed, 0);
  if (r.done.length) toast(`${r.done.length} log${r.done.length > 1 ? 's' : ''} processed: ${fmtInt(lines)} lines${skipped ? `, ${fmtInt(skipped)} skipped` : ''}${r.failed.length ? `; ${r.failed.length} failed` : ''}`, r.failed.length ? 'err' : 'ok', 6000);
};
async function cxSave(ev) {
  ev.preventDefault();
  cxResult('Saving…', 'busy'); $('#cx-save').disabled = true;
  try {
    const r = await cxPost(cx.editing ? `/instances/${encodeURIComponent(cx.editing)}` : '/instances', cx.editing ? 'PUT' : 'POST');
    const wasEditing = cx.editing; const configOnly = $('#cx-test').hidden;
    let logRes = null; let logErr = null;
    if (cx.logFiles.length) { // the instance exists now: send the logs one by one, with progress. A failed log never undoes the saved instance.
      cxResult('Saved. Uploading the logs…', 'busy');
      logRes = await uploadLogs(r.id, cx.logFiles, (tag, f, l, t, d) => logProgressUi($('#cx-logprog'), l, t, d, `${tag}${f.name}: `), false);
      $('#cx-logprog').hidden = true; if (!logRes.done.length) { logErr = logRes.failed.map((x) => `${x.name}: ${x.error}`).join(' · '); logRes = null; }
    }
    cxClose();
    await enterLive(r.id);
    if (logRes) { logSummaryToast(logRes); if (typeof TR !== 'undefined') { TR.inst = null; TR.data = null; TR.upErr = logRes.failed.length ? logRes.failed.map((x) => `${x.name}: ${x.error}`).join(' · ') : null; } switchView('traffic'); }
    else if (logErr) { toast(`Saved, but the logs were not processed: ${logErr}`, 'err', 9000); if (typeof TR !== 'undefined') { TR.inst = null; TR.data = null; TR.upErr = logErr; } switchView('traffic'); }
    else toast(wasEditing ? 'Instance updated' : configOnly ? 'Config saved as an instance (no live data)' : 'Connected: live data will appear in a few seconds', 'ok');
  } catch (e) { cxResult(`✗ ${e.message}`, 'err'); }
  $('#cx-save').disabled = false;
}
async function saveReviewAsInstance() {
  const cfg = state.analysisCfg; if (!cfg) return;
  const name = await confirmDialog({ title: 'Save as an instance', message: `Keeps this ${TYPE_NAME[cfg.type]} config on the server as a config-only instance in your dashboard (private to this browser). The name must be unique.`, confirmText: 'Save instance', icon: '💾', input: { value: `${TYPE_NAME[cfg.type]} config`, placeholder: 'e.g. Production edge' } });
  if (!name) return;
  try {
    const r = await api('/instances', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: cfg.type, name, configFiles: cfg.files }) });
    state.analysis = null; state.analysisSnap = null; state.analysisCfg = null;
    await enterLive(r.id);
    toast(`Saved “${name}”. It is in your dashboard now.`, 'ok', 4000);
  } catch (e) { toast(e.message, 'err', 6000); }
}
/** In-app replacement for window.confirm(): resolves true/false. Esc / backdrop / Cancel = false. */
function confirmDialog({ title, message, confirmText = 'Confirm', danger = false, icon = '⚠', input = null }) {
  return new Promise((resolve) => {
    const prev = document.activeElement;
    const ov = document.createElement('div'); ov.className = 'overlay confirm-ov';
    ov.innerHTML = `<div class="palette confirm" role="alertdialog" aria-modal="true" aria-labelledby="cf-t" aria-describedby="cf-m">
      <div class="cf-body"><div class="cf-ico ${danger ? 'danger' : ''}" aria-hidden="true">${esc(icon)}</div>
        <div><h3 id="cf-t">${esc(title)}</h3><p id="cf-m" class="muted">${esc(message)}</p>${input ? `<input id="cf-in" class="cf-in" maxlength="60" value="${esc(input.value || '')}" placeholder="${esc(input.placeholder || '')}" autocomplete="off" spellcheck="false">` : ''}</div></div>
      <div class="cf-foot"><button type="button" class="btn" data-cf="no">Cancel</button><button type="button" class="btn ${danger ? 'danger' : 'primary'}" data-cf="yes">${esc(confirmText)}</button></div></div>`;
    const done = (v) => { const val = input && v ? ov.querySelector('#cf-in').value.trim() : v; document.removeEventListener('keydown', key, true); ov.remove(); if (prev && prev.focus) prev.focus(); resolve(input ? (val || null) : v); };
    const key = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(false); }
      else if (e.key === 'Enter' && input) { e.preventDefault(); done(true); }
      else if (e.key === 'Tab') { const b = [...ov.querySelectorAll('button')]; const i = b.indexOf(document.activeElement); e.preventDefault(); b[(i + (e.shiftKey ? -1 : 1) + b.length) % b.length].focus(); }
    };
    ov.addEventListener('click', (e) => { if (e.target === ov) done(false); const b = e.target.closest('[data-cf]'); if (b) done(b.dataset.cf === 'yes'); });
    document.addEventListener('keydown', key, true);
    document.body.appendChild(ov);
    (input ? ov.querySelector('#cf-in') : ov.querySelector(danger ? '[data-cf=no]' : '[data-cf=yes]')).focus(); // destructive actions default to Cancel
  });
}
async function cxDelete(id) {
  const inst = state.instances.find((i) => i.id === id);
  if (!await confirmDialog({ title: `Remove “${inst ? inst.name : id}”?`, message: 'Its saved URL and credentials are deleted from the server. This cannot be undone.', confirmText: 'Remove connection', danger: true, icon: '🗑' })) return;
  try {
    await api(`/instances/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (state.current === id) { state.current = null; state.snapshot = null; clearTimeout(state.timer); }
    const ok = await loadInstances();
    if (!ok) { showLanding(); toast('Removed', 'ok', 1800); return; }
    $('#instance-select').dispatchEvent(new Event('change'));
    renderSettings(); toast('Removed', 'ok', 1800);
  } catch (e) { toast(e.message, 'bad'); }
}


// ---------- instance switcher (header dropdown) ----------
const iselState = { open: false, q: '', idx: 0 };
function iselStatus(i) { return i.source === 'config-only' ? 'unknown' : i.ok === false ? 'down' : i.ok === null ? 'unknown' : (i.serversDown || 0) > 0 ? 'degraded' : 'up'; }
function iselItems() {
  const vis = state.instances.filter((i) => !state.hiddenTypes.includes(i.type));
  const q = iselState.q.toLowerCase();
  const list = vis.filter((i) => !q || `${i.name} ${i.type} ${i.source}`.toLowerCase().includes(q));
  const items = list.map((i) => ({ id: i.id, name: i.name, type: i.type, st: iselStatus(i), source: i.source, down: i.serversDown || 0, total: i.serversTotal || 0 }));
  if (state.analysis && (!q || 'uploaded analysis'.includes(q))) items.push({ id: '__analysis', name: 'Uploaded analysis', type: 'analysis', st: 'unknown', source: 'offline review', down: 0, total: 0 });
  return items;
}
function iselSync() { // the button shows the current instance; the list is built when it opens
  const btn = $('#isel-btn'); if (!btn) return;
  const cur = state.instances.find((i) => i.id === state.current);
  if (state.current === '__analysis') btn.innerHTML = '<span class="lbi-dot s-unknown" aria-hidden="true"></span><span class="isel-name">Uploaded analysis</span><span class="isel-type">offline</span><span class="isel-chev" aria-hidden="true">▾</span>';
  else if (cur) { const st = iselStatus(cur); btn.innerHTML = `<span class="lbi-dot s-${st}" aria-hidden="true"></span><span class="isel-name">${esc(cur.name)}</span><span class="isel-type t-${esc(cur.type)}">${esc(TYPE_NAME[cur.type] || cur.type)}</span>${cur.serversDown ? `<span class="isel-warn" title="${cur.serversDown} server(s) down">⚠ ${cur.serversDown}</span>` : ''}<span class="isel-chev" aria-hidden="true">▾</span>`; }
  else btn.innerHTML = '<span class="isel-name muted">No instance</span><span class="isel-chev" aria-hidden="true">▾</span>';
  btn.setAttribute('aria-label', `Instance: ${cur ? cur.name : state.current === '__analysis' ? 'Uploaded analysis' : 'none'}. Switch instance`);
  if (iselState.open) iselRender();
}
function iselRender() {
  const pop = $('#isel-pop'); const items = iselItems();
  iselState.idx = Math.max(0, Math.min(iselState.idx, items.length - 1));
  const total = state.instances.filter((i) => !state.hiddenTypes.includes(i.type)).length;
  const groups = []; for (const it of items) { let g = groups.find((x) => x.t === it.type); if (!g) { g = { t: it.type, list: [] }; groups.push(g); } g.list.push(it); }
  let n = 0;
  const row = (it) => { const idx = n++; const on = it.id === state.current;
    return `<button type="button" role="option" class="isel-opt${on ? ' cur' : ''}${idx === iselState.idx ? ' hl' : ''}" data-isel="${esc(it.id)}" data-i="${idx}" aria-selected="${on}">
      <span class="lbi-dot s-${it.st}" aria-hidden="true"></span><span class="isel-t"><b>${esc(it.name)}</b><span class="muted small">${esc(it.source || '')}${it.total ? ` · ${it.total - it.down}/${it.total} servers up` : ''}</span></span>
      ${it.down ? `<span class="isel-warn">⚠ ${it.down} down</span>` : ''}${on ? '<span class="isel-check" aria-hidden="true">✓</span>' : ''}</button>`; };
  pop.innerHTML = `${total >= 6 ? `<div class="isel-search"><input id="isel-q" type="search" placeholder="Search ${total} instances…" aria-label="Search instances" value="${esc(iselState.q)}" autocomplete="off"></div>` : ''}
    <div class="isel-list">${groups.map((g) => `<div class="isel-grp">${esc(TYPE_NAME[g.t] || (g.t === 'analysis' ? 'Offline' : g.t))}</div>${g.list.map(row).join('')}`).join('') || '<div class="isel-empty muted small">No instance matches</div>'}</div>
    <div class="isel-foot"><button type="button" class="link" data-isel-add>${state.meta && state.meta.canManage ? '＋ Add instance' : 'Review a config'}</button><button type="button" class="link" data-isel-all>Manage instances</button></div>`;
  const hl = pop.querySelector('.hl'); if (hl) { hl.scrollIntoView({ block: 'nearest' }); if (!pop.querySelector('#isel-q') && pop.contains(document.activeElement) || document.activeElement === document.body) hl.focus(); }
}
function iselOpen(on) {
  iselState.open = on; $('#isel-pop').hidden = !on; $('#isel-btn').setAttribute('aria-expanded', String(on));
  if (on) { iselState.q = ''; const items = iselItems(); iselState.idx = Math.max(0, items.findIndex((i) => i.id === state.current)); iselRender(); const q = $('#isel-q'); (q || $('#isel-pop .hl') || $('#isel-btn')).focus(); }
}
function iselPick(id) {
  iselOpen(false); const sel = $('#instance-select');
  if (id === state.current || ![...sel.options].some((o) => o.value === id)) { $('#isel-btn').focus(); return; }
  sel.value = id; sel.dispatchEvent(new Event('change')); $('#isel-btn').focus();
}
function iselWire() {
  const btn = $('#isel-btn'); const pop = $('#isel-pop');
  btn.addEventListener('click', () => iselOpen(!iselState.open));
  pop.addEventListener('click', (e) => {
    const o = e.target.closest('[data-isel]'); if (o) { iselPick(o.dataset.isel); return; }
    if (e.target.closest('[data-isel-add]')) { iselOpen(false); switchView('connect'); return; }
    if (e.target.closest('[data-isel-all]')) { iselOpen(false); switchView('settings'); }
  });
  pop.addEventListener('input', (e) => { if (e.target.id === 'isel-q') { iselState.q = e.target.value; iselState.idx = 0; const pos = e.target.selectionStart; iselRender(); const q = $('#isel-q'); q.focus(); q.setSelectionRange(pos, pos); } });
  document.addEventListener('mousedown', (e) => { if (iselState.open && !e.target.closest('#isel')) iselOpen(false); });
  $('#isel').addEventListener('keydown', (e) => {
    const items = iselItems();
    if (!iselState.open) { if (['ArrowDown', 'ArrowUp'].includes(e.key) && e.target === btn) { e.preventDefault(); iselOpen(true); } return; }
    if (e.key === 'Escape') { e.preventDefault(); iselOpen(false); btn.focus(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); iselState.idx = Math.min(items.length - 1, iselState.idx + 1); iselRender(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); iselState.idx = Math.max(0, iselState.idx - 1); iselRender(); }
    else if (e.key === 'Enter' && items[iselState.idx] && !e.target.closest('[data-isel-add],[data-isel-all]')) { e.preventDefault(); iselPick(items[iselState.idx].id); }
    else if (e.key === 'Tab') iselOpen(false);
  });
  // Traffic flow diagram: instant tooltip that follows the pointer
  const tipEl = () => { let t = $('#fl-tip'); if (!t) { t = document.createElement('div'); t.id = 'fl-tip'; t.className = 'fl-tip'; t.hidden = true; document.body.appendChild(t); } return t; };
  const tipMove = (e) => {
    const n = e.target.closest && e.target.closest('.flow-svg [data-tip], #view-traffic [data-tip]'); const t = tipEl();
    if (!n) { t.hidden = true; return; }
    if (t.dataset.for !== n.getAttribute('data-tip')) { t.textContent = n.getAttribute('data-tip'); t.dataset.for = n.getAttribute('data-tip'); }
    t.hidden = false;
    const w = t.offsetWidth; const h = t.offsetHeight;
    t.style.left = `${Math.max(8, Math.min(window.innerWidth - w - 8, e.clientX + 14))}px`;
    t.style.top = `${e.clientY + 18 + h > window.innerHeight ? Math.max(8, e.clientY - h - 12) : e.clientY + 18}px`;
  };
  document.addEventListener('mousemove', tipMove);
  document.addEventListener('mouseleave', () => { const t = $('#fl-tip'); if (t) t.hidden = true; });
  // Traffic flow page: keep the form values, filter by entry point, Enter runs the trace
  const flowSync = () => { FLOW.req = { host: ($('#flow-host') || {}).value || '', path: ($('#flow-path') || {}).value || '/', port: ($('#flow-port') || {}).value || '', method: ($('#flow-method') || {}).value || 'GET' }; };
  document.addEventListener('input', (e) => { if (e.target.closest && e.target.closest('.flow-form')) flowSync(); if (e.target.id === 'flow-dq') { FLOW.dq = e.target.value; const pos = e.target.selectionStart; renderFlow(); const n = $('#flow-dq'); if (n) { n.focus(); n.setSelectionRange(pos, pos); } } });
  document.addEventListener('change', (e) => { if (e.target.id === 'flow-st') { FLOW.st = e.target.value; renderFlow(); } else if (e.target.id === 'flow-fe') { FLOW.fe = e.target.value; renderFlow(); } else if (e.target.closest && e.target.closest('.flow-form')) flowSync(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.closest && e.target.closest('.flow-form') && e.target.tagName === 'INPUT') { e.preventDefault(); flowSync(); flowTrace(); } });
  $('#instance-select').addEventListener('change', iselSync);
}

// ---------- wiring ----------
async function openInstance(id) {
  const sel = $('#instance-select');
  if (![...sel.options].some((o) => o.value === id)) return;
  sel.value = id;
  sel.dispatchEvent(new Event('change'));
  switchView('overview');
}

function wire() {
  $('#nav').addEventListener('click', (e) => { const b = e.target.closest('button[data-view]'); if (b) switchView(b.dataset.view); });
  $('#instance-select').addEventListener('change', async (e) => {
    resetAllFilters(); // another server: nothing from the previous one carries over
    state.current = e.target.value; state.snapshot = null; state.series = []; cfgRendered = null; state.cfgFile = null; state.focus = null; closeInspector(); state.events = [];
    if (network) { network.destroy(); network = null; }
    clearTimeout(state.timer);
    switchView(state.view === 'connect' || state.view === 'detail' ? 'overview' : state.view); // new history entry with the new instance in the URL
    if (state.current === '__analysis') applySnapshot(state.analysisSnap);
    else { await poll(); schedule(); backfillSeries(); }
  });
  $('#btn-refresh').addEventListener('click', () => poll(true));
  $('#gr-refresh').addEventListener('click', () => poll(true));
  $('#gr-refresh-every').addEventListener('change', (e) => { const h = $('#refresh-every'); h.value = e.target.value; h.dispatchEvent(new Event('change')); });
  $('#refresh-every').value = refreshSetting();
  $('#gr-refresh-every').value = refreshSetting();
  $('#refresh-every').addEventListener('change', (e) => {
    try { localStorage.setItem('gatelight.refresh', e.target.value); } catch { /* private mode */ }
    schedule(); toast(e.target.value === 'off' ? 'Auto-refresh paused. Use Refresh to update.' : 'Auto-refresh updated', 'ok', 1800);
    if (e.target.value !== 'off') poll();
  });
  $('#btn-connect').addEventListener('click', () => switchView('connect'));
  $('#btn-start').addEventListener('click', leaveReview);
  $('#btn-save-review').addEventListener('click', saveReviewAsInstance);
  $$('[data-logout]').forEach((b) => b.addEventListener('click', signOut));
  $('#btn-cfgup').addEventListener('click', cuOpen);
  $('#cu-form').addEventListener('submit', cuSave);
  $('#cu-close').addEventListener('click', cuClose); $('#cu-cancel').addEventListener('click', cuClose);
  $('#cfgup').addEventListener('mousedown', (e) => { if (e.target.id === 'cfgup') cuClose(); });
  ['#cu-files', '#cu-folder'].forEach((q) => $(q).addEventListener('change', async (e) => { const l = [...e.target.files]; e.target.value = ''; await cuPick(l); }));
  $('#cu-text').addEventListener('input', () => { if ($('#cu-text').value) cu.files = []; cuSync(); });
  $('#cu-drop').addEventListener('dragover', (e) => { e.preventDefault(); $('#cu-drop').classList.add('over'); });
  $('#cu-drop').addEventListener('dragleave', () => $('#cu-drop').classList.remove('over'));
  $('#cu-drop').addEventListener('drop', async (e) => { e.preventDefault(); $('#cu-drop').classList.remove('over'); cuPick(await filesFromDrop(e.dataTransfer)); });
  $('#cu-drop').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#cu-files').click(); });
  document.addEventListener('click', (e) => { if (e.target.closest('[data-cfgup]')) cuOpen(); });
  $('#cfg-refresh').addEventListener('click', async () => {
    const b = $('#cfg-refresh'); if (!state.current || b.disabled) return;
    b.disabled = true; const old = b.textContent; b.textContent = 'Fetching…';
    try {
      const r = await api(`/instances/${encodeURIComponent(state.current)}/config/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (r.skipped) toast(r.message, 'info', 6000);
      else if (!r.ok) toast(`Could not refresh: ${r.error}`, 'bad', 7000);
      else if (!r.changed) toast('Configuration fetched: no changes since the last copy', 'ok');
      else toast(`Configuration refreshed: +${r.linesAdded} −${r.linesRemoved} lines${r.added.length ? ` · new: ${r.added.slice(0, 4).join(', ')}${r.added.length > 4 ? '…' : ''}` : ''}${r.removed.length ? ` · gone: ${r.removed.slice(0, 4).join(', ')}${r.removed.length > 4 ? '…' : ''}` : ''}`, 'ok', 8000);
      cfgRendered = ''; await poll(true);
    } catch (e) { toast(`Could not refresh: ${e.message}`, 'bad', 7000); }
    b.disabled = false; b.textContent = old;
  });
  $('#btn-home').addEventListener('click', goHome);
  // the saved-connections list lives on the start screen and, once mounted, on the Add instance page: listen on the document
  document.addEventListener('click', (e) => { const c = e.target.closest('[data-enter]'); if (c) { e.preventDefault(); enterLive(c.dataset.enter); } });
  $('#cx-form').addEventListener('submit', cxSave);
  $('#cx-test').addEventListener('click', cxTest);
  $('#cx-close').addEventListener('click', cxClose);
  $('#connect').addEventListener('mousedown', (e) => { if (e.target.id === 'connect') cxClose(); });
  $$('input[name="cx-type"]').forEach((r) => r.addEventListener('change', cxSync));
  $('#cx-logfile').addEventListener('change', (e) => { const f = [...e.target.files]; e.target.value = ''; cxPickLog(f); });
  $('#cx-lognote').addEventListener('click', (e) => { const b = e.target.closest('[data-cx-logrm]'); if (b) { cx.logFiles.splice(+b.dataset.cxLogrm, 1); cxLogNote(); cxSync(); } });
  $('#cx-logclear').addEventListener('click', () => { cx.logFiles = []; cxLogNote(); cxSync(); });
  ['#cx-cfgfiles', '#cx-cfgfolder'].forEach((q) => $(q).addEventListener('change', async (e) => { const l = [...e.target.files]; e.target.value = ''; await cxPickFiles(l); }));
  $('#cx-cancel').addEventListener('click', () => cxOpen(null, true));
  $('#cx-cfgclear').addEventListener('click', () => { cx.files = []; $('#cx-cfgtext').value = ''; cxFilesNote(); cxSync(); });
  ['#cx-url', '#cx-socket', '#cx-plus', '#cx-cfgtext', '#cx-cfgurls'].forEach((q) => $(q).addEventListener('input', () => { if (q === '#cx-cfgtext' && $(q).value) cx.files = []; cxFilesNote(); cxSync(); }));
  grWire();
  iselWire();
  $('#view-profile').addEventListener('click', (e) => { if (e.target.closest('[data-prof-theme]')) { $('#btn-theme').click(); renderProfile(); } });
  $('#infra').addEventListener('click', (e) => {
    const b = e.target.closest('[data-lbi-by]'); if (b) { lbi.by = b.dataset.lbiBy; renderLbInfra(); return; }
    const t = e.target.closest('[data-lbt-toggle]');
    if (t) { const id = t.dataset.lbtToggle; if (lbi.open.has(id)) lbi.open.delete(id); else lbi.open.add(id); const li = t.closest('li'); const open = lbi.open.has(id); li.setAttribute('aria-expanded', String(open)); li.querySelector(':scope > ul').hidden = !open; return; }
    const a = e.target.closest('[data-lbt-all]');
    if (a) { const open = a.dataset.lbtAll === 'open'; $$('#infra [data-lbt-toggle]').forEach((x) => { const id = x.dataset.lbtToggle; if (open) lbi.open.add(id); else if (id !== 'lb') lbi.open.delete(id); const li = x.closest('li'); const o = lbi.open.has(id); li.setAttribute('aria-expanded', String(o)); li.querySelector(':scope > ul').hidden = !o; }); }
  });
  $('#infra').addEventListener('change', (e) => { // the two filters exclude each other
    if (e.target.id === 'lbi-problems') { lbi.problems = e.target.checked; if (lbi.problems) lbi.alive = false; renderLbInfra(); }
    else if (e.target.id === 'lbi-alive') { lbi.alive = e.target.checked; if (lbi.alive) lbi.problems = false; renderLbInfra(); }
  });
  $('#detail-back').addEventListener('click', detailBack);
  document.addEventListener('click', (e) => { const b = e.target.closest('[data-cv-row]'); if (b) { e.stopPropagation(); e.preventDefault(); cvOpenRow(b.dataset.cvRow); } }, true);
  $('#cv-close').addEventListener('click', cvClose);
  $('#chartview').addEventListener('mousedown', (e) => { if (e.target.id === 'chartview') cvClose(); });
  $('#cv-win').addEventListener('change', (e) => { if (e.target.value === 'custom') return; const m = Number(e.target.value); cvSetView(m * 60000, null); cvRender(); });
  $('#cv-hand').addEventListener('click', () => { cv.hand = !cv.hand; cvRender(); });
  $('#cv-zin').addEventListener('click', () => cvZoom(1 / 1.5));
  $('#cv-zout').addEventListener('click', () => cvZoom(1.5));
  $('#cv-reset').addEventListener('click', () => { cvSetView(0, null); cvRender(); });
  const cvc = $('#cv-canvas');
  cvc.addEventListener('wheel', (e) => { // plain scrolling is left alone; Ctrl/⌘ + wheel zooms, Shift + wheel (or a sideways wheel) moves through time
    const r = cvc.getBoundingClientRect();
    if (e.ctrlKey || e.metaKey) { e.preventDefault(); cvZoom(e.deltaY < 0 ? 1 / 1.25 : 1.25, Math.max(0, Math.min(1, (e.clientX - r.left - 6) / Math.max(1, r.width - 12)))); return; }
    const dx = e.shiftKey ? (e.deltaY || e.deltaX) : (Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : 0);
    if (dx && cv.span) { e.preventDefault(); const { view } = cvData(); if (view) { cvSetView(view.t1 - view.t0, view.t1 + (dx / Math.max(1, r.width)) * (view.t1 - view.t0)); cvRender(); } }
  }, { passive: false });
  cvc.addEventListener('dblclick', () => { cvSetView(0, null); cvRender(); });
  cvc.addEventListener('pointerdown', (e) => {
    if (!cv.hand) return;
    if (!cv.span) { const { full } = cvData(); if (full.times.length < 3) return; const tot = full.times[full.times.length - 1] - full.times[0]; cvSetView(tot / 2, null); cvRender(); }
    const { view } = cvData(); if (!view) return;
    cv._drag = { x: e.clientX, end: view.t1, span: view.t1 - view.t0 }; cvc.setPointerCapture(e.pointerId); chartHover.delete('cv-canvas'); cvRender();
  });
  cvc.addEventListener('pointermove', (e) => {
    const d = cv._drag; if (!d) return;
    const r = cvc.getBoundingClientRect(); const dt = ((e.clientX - d.x) / Math.max(1, r.width - 12)) * d.span;
    cvSetView(d.span, d.end - dt); chartHover.delete('cv-canvas'); cvRender();
  });
  const endDrag = () => { if (cv._drag) { cv._drag = null; cvRender(); } };
  cvc.addEventListener('pointerup', endDrag); cvc.addEventListener('pointercancel', endDrag);
  const mini = $('#cv-mini'); let miniDrag = false;
  const miniTo = (e) => {
    const m = mini._map; if (!m) return; const r = mini.getBoundingClientRect();
    const tc = m.t0 + Math.max(0, Math.min(1, (e.clientX - r.left - 4) / Math.max(1, r.width - 8))) * (m.t1 - m.t0);
    const { view } = cvData(); const span = cv.span || (view ? view.t1 - view.t0 : 0); if (!cv.span) return; // "All" shows everything already
    cvSetView(span, tc + span / 2); cvRender();
  };
  mini.addEventListener('pointerdown', (e) => { miniDrag = true; mini.setPointerCapture(e.pointerId); miniTo(e); });
  mini.addEventListener('pointermove', (e) => { if (miniDrag) miniTo(e); });
  mini.addEventListener('pointerup', () => { miniDrag = false; });
  $('#cv-csv').addEventListener('click', cvCsv);
  $('#chartview').addEventListener('click', (e) => { const t = e.target.closest('[data-cv-toggle]'); if (t) { const k = t.dataset.cvToggle; if (cv.hidden.has(k)) cv.hidden.delete(k); else cv.hidden.add(k); cvRender(); } });
  document.addEventListener('click', (e) => { // the buttons, or the chart itself
    const b = e.target.closest('[data-cv-expand]'); if (b) { cvOpen(b.dataset.cvExpand); return; }
    const c = e.target.closest('canvas.chart'); if (c && (c.id === 'ov-chart' || c.id === 'insp-chart')) cvOpen(c.id === 'ov-chart' ? 'overview' : 'inspector');
  });
  document.addEventListener('click', (e) => {
    if (e.target.closest('[data-topo-sel-x]')) { state.focus = null; topoSelect(null); renderTopology(); return; }
    if (e.target.closest('[data-topo-open]') && topoSel) { const t = topoSel; if (t.route) inspectRoute(t.route); else if (t.node._key) inspect(t.node._key, t.node._kind); else inspectMissing(t.node.id.slice(8)); return; }
    const cuB = e.target.closest('[data-cx-up]'); if (cuB) { state.current = cuB.dataset.cxUp; cuOpen(); return; }
    const ce = e.target.closest('[data-cx-edit]'); if (ce) { if (state.view !== 'connect') switchView('connect'); cxOpen(ce.dataset.cxEdit, true).then(() => { const f = $('#cx-form'); if (f) f.scrollIntoView({ block: 'start' }); }); return; }
    const cd = e.target.closest('[data-cx-del]'); if (cd) { cxDelete(cd.dataset.cxDel); return; }
    if (e.target.closest('[data-connect]')) { switchView('connect'); return; } // the Add instance page, not a pop-up dialog
    const gl = e.target.closest('[data-goto-line]'); if (gl) { gotoLine(gl.dataset.gotoLine, gl.dataset.gotoFile); return; }
    const oi = e.target.closest('[data-open-instance]'); if (oi) { openInstance(oi.dataset.openInstance); return; }
    const ex = e.target.closest('[data-example]'); if (ex) { setMode('review'); loadExample(ex.dataset.example); return; }
    const kc = e.target.closest('[data-card]'); if (kc) { openCard(kc.dataset.card); return; }
    if (e.target.closest('[data-flow-uri]')) { FLOW.tab = 'uri'; switchView('flow'); return; }
    const gt = e.target.closest('[data-goto]'); if (gt) { switchView(gt.dataset.goto); return; }
    const ur = e.target.closest('[data-urlrow]');
    if (ur) {
      const [feName, idx] = ur.dataset.urlrow.split('|'); const fe = cfgSections().find((x) => x.name === feName && feLike(x)); const rt = fe && fe.routes[Number(idx)];
      if (rt) { state.focus = routeTargetId(rt); inspectRoute({ fe: fe.name, ...rt }); renderTopology(); if (network) network.focus(state.focus, { scale: 1, animation: { duration: 400 } }); }
      return;
    }
    const ins = e.target.closest('[data-inspect]'); if (ins) { const key = ins.dataset.inspect; const r = indexRows(state.snapshot.rows).get(key); inspect(key, r && r.kind); return; }
    if (e.target.closest('[data-flow-trace]')) { FLOW.req = { host: ($('#flow-host') || {}).value || '', path: ($('#flow-path') || {}).value || '/', port: ($('#flow-port') || {}).value || '', method: ($('#flow-method') || {}).value || 'GET' }; flowTrace(); return; }
    if (e.target.closest('[data-flow-clear]')) { FLOW.sel = null; renderFlow(); return; }
    const fp = e.target.closest('.flow-svg [data-fsel]');
    if (fp) { const key = fp.getAttribute('data-fsel'); FLOW.sel = FLOW.sel && FLOW.sel.key === key ? null : { key }; renderFlow(); return; }
    if (FLOW.sel && e.target.closest('.flow-svg') && !e.target.closest('.fs-eg')) { FLOW.sel = null; renderFlow(); return; }
    const fd = e.target.closest('[data-flow-dom]');
    if (fd) { const [name, port, tls] = fd.dataset.flowDom.split('|'); const host = name.startsWith('*.') ? `test${name.slice(1)}` : name.startsWith('.') ? `www${name}` : /^[(_~]/.test(name) || name.endsWith('.*') ? '' : name; FLOW.req = { host, path: '/', port, method: 'GET' }; FLOW.trace = null; flowTrace().then(() => { const el = $('.flow-try'); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }); return; }
    if (e.target.closest('#flow-fs')) { toggleTopoFs(); return; }
    const ft = e.target.closest('[data-flow-tab]'); if (ft) { FLOW.tab = ft.dataset.flowTab; renderFlow(); return; }
    const ev = e.target.closest('[data-ev]'); if (ev) { state.eventFilter = ev.dataset.ev; renderEvents(); return; }
    const th = e.target.closest('th[data-sort]');
    if (th && !SVC_COLS.find((c) => c.k === th.dataset.sort).nosort) {
      state.sort = { key: th.dataset.sort, desc: state.sort.key === th.dataset.sort ? !state.sort.desc : th.dataset.sort !== 'name' }; renderServices(); return;
    }
    if (e.target.matches('[data-show-type]')) {
      const t = e.target.dataset.showType; const set = new Set(state.hiddenTypes);
      if (e.target.checked) set.delete(t); else set.add(t);
      state.hiddenTypes = [...set]; savePref('gatelight.hiddenTypes', state.hiddenTypes); loadInstances().then(() => renderSettings()); return;
    }
  });

  ['topo-search', 'topo-problems', 'topo-servers', 'topo-urls', 'topo-layer'].forEach((id) => $(`#${id}`).addEventListener('input', renderTopology));
  $('#tree').addEventListener('click', (e) => {
    const b = e.target.closest('[data-tree]');
    if (b) {
      e.stopPropagation();
      if (b.dataset.tree === 'copy') { (navigator.clipboard ? navigator.clipboard.writeText(treeText) : Promise.reject()).then(() => toast('Tree copied as text', 'ok', 1500), () => toast('Copy not available here', 'bad')); return; }
      if (b.dataset.tree === 'open') closedTree.clear(); else $$('#tree li.has > .tn').forEach((n) => closedTree.add(n.dataset.tk));
      renderTree(); return;
    }
    const tg = e.target.closest('[data-tg]');
    if (tg) { e.stopPropagation(); const k = tg.parentElement.dataset.tk; if (closedTree.has(k)) closedTree.delete(k); else closedTree.add(k); renderTree(); }
  });
  $('#topo-layout').addEventListener('change', () => { if (network) { network.destroy(); network = null; } renderTopology(); });
  $('#topo-png').addEventListener('click', exportPng);
  state.urlmapOpen = loadPref('gatelight.urlmap', true);
  state.urlmapMode = loadPref('gatelight.urlmapMode', 'normal'); state.urlmapH = loadPref('gatelight.urlmapH', 0);
  const reflow = () => setTimeout(() => { if (network) { network.setSize('100%', '100%'); network.redraw(); network.fit({ animation: false }); } }, 60);
  $('#topo-urlmap').addEventListener('click', () => {
    state.urlmapOpen = !state.urlmapOpen; savePref('gatelight.urlmap', state.urlmapOpen);
    if (state.urlmapOpen && state.urlmapMode === 'min') state.urlmapMode = 'normal';
    if (!state.urlmapOpen) $('#view-topology').classList.remove('um-max');
    renderUrlMap(); reflow();
  });
  $('#urlmap').addEventListener('click', (e) => {
    if (e.target.closest('[data-um-fs]')) { e.stopPropagation(); toggleUrlmapFs(); return; }
    const b = e.target.closest('[data-um]'); if (!b) return;
    e.stopPropagation();
    if (b.dataset.um === 'close') { state.urlmapOpen = false; savePref('gatelight.urlmap', false); $('#view-topology').classList.remove('um-max'); }
    else { const want = b.dataset.um; state.urlmapMode = state.urlmapMode === want ? 'normal' : want; savePref('gatelight.urlmapMode', state.urlmapMode); }
    renderUrlMap(); reflow();
  });
  $('#urlmap').addEventListener('pointerdown', (e) => { // drag the top edge to resize
    const g = e.target.closest('[data-um-grip]'); if (!g) return;
    e.preventDefault(); const box = $('#urlmap'); const startY = e.clientY; const startH = box.getBoundingClientRect().height;
    if (state.urlmapMode !== 'normal') { state.urlmapMode = 'normal'; savePref('gatelight.urlmapMode', 'normal'); renderUrlMap(); }
    const move = (ev) => { const max = $('#view-topology').getBoundingClientRect().height - 140; state.urlmapH = Math.round(Math.max(90, Math.min(max, startH + (startY - ev.clientY)))); box.style.height = `${state.urlmapH}px`; };
    const up = () => { document.removeEventListener('pointermove', move); document.removeEventListener('pointerup', up); savePref('gatelight.urlmapH', state.urlmapH); reflow(); };
    document.addEventListener('pointermove', move); document.addEventListener('pointerup', up);
  });
  $('#topo-fs').addEventListener('click', toggleMapFs);
  document.addEventListener('fullscreenchange', () => { if (!document.fullscreenElement && document.body.classList.contains('topo-fs')) setTopoFs(false); });
  $('#topo-expand').addEventListener('click', () => topoCollapseAll(false));
  $('#topo-collapse').addEventListener('click', () => topoCollapseAll(true));
  document.addEventListener('click', (e) => { const b = e.target.closest('[data-topo-toggle]'); if (b) { toggleCollapse(b.dataset.topoToggle); const n = visNodes && visNodes.get(b.dataset.topoToggle); if (n) topoSelect(n); } });
  $('#topo-fit').addEventListener('click', () => network && network.fit({ animation: { duration: 400 } }));
  ['svc-search', 'svc-kind', 'svc-state'].forEach((id) => $(`#${id}`).addEventListener('input', renderServices));
  $('#svc-export').addEventListener('click', exportCsv);
  $('#cfg-search').addEventListener('input', renderConfig);
  $('#cfg-search').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); cfgFindStep(e.shiftKey ? -1 : 1); }
    else if (e.key === 'Escape' && e.target.value) { e.target.value = ''; renderConfig(); e.stopPropagation(); }
  });
  $('#cfg-next').addEventListener('click', () => cfgFindStep(1));
  $('#cfg-prev').addEventListener('click', () => cfgFindStep(-1));
  $('#cfg-tree-toggle').addEventListener('click', () => { const b = $('#cfg-tree-toggle'); const on = b.getAttribute('aria-pressed') !== 'true'; b.setAttribute('aria-pressed', String(on)); $('#view-config').classList.toggle('no-tree', !on); });
  $('#cfg-tree').addEventListener('click', (e) => {
    const t = e.target.closest('[data-cfg-toggle]');
    if (t) { const id = t.dataset.cfgToggle; if (cfgOpen.has(id)) cfgOpen.delete(id); else cfgOpen.add(id); const li = t.closest('li'); const open = cfgOpen.has(id); li.setAttribute('aria-expanded', String(open)); li.querySelector(':scope > ul').hidden = !open; t.setAttribute('aria-label', `${open ? 'Collapse' : 'Expand'}`); return; }
    const a = e.target.closest('[data-cfg-all]');
    if (a) { const open = a.dataset.cfgAll === 'open'; $$('#cfg-tree [data-cfg-toggle]').forEach((b) => { const id = b.dataset.cfgToggle; if (open) cfgOpen.add(id); else cfgOpen.delete(id); const li = b.closest('li'); li.setAttribute('aria-expanded', String(open)); li.querySelector(':scope > ul').hidden = !open; }); return; }
    const l = e.target.closest('[data-cfg-line]');
    if (l) { const el = document.getElementById(`L${l.dataset.cfgLine}`); if (el) { el.scrollIntoView({ block: 'center' }); el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); } $$('#cfg-tree .tl.cur').forEach((x) => x.classList.remove('cur')); l.classList.add('cur'); }
  });
  $('#cfg-download').addEventListener('click', () => { const f = currentFile(); if (f) download(`${f.name.replace(/[\\/]/g, '_')}.redacted`, f.raw); });
  $('#cfg-file').addEventListener('change', (e) => { state.cfgFile = e.target.value; cfgRendered = null; renderConfig(); });

  // analyze: files, folder, paste, examples, drag & drop anywhere
  $('#az-files').addEventListener('change', (e) => { ingestFiles([...e.target.files].map((f) => ({ name: f.name, file: f }))); e.target.value = ''; });
  $('#az-folder').addEventListener('change', (e) => { ingestFiles([...e.target.files].map((f) => ({ name: f.webkitRelativePath || f.name, file: f }))); e.target.value = ''; });
  $('#az-paste-toggle').addEventListener('click', () => { const p = $('#az-paste'); p.hidden = !p.hidden; if (!p.hidden) $('#az-text').focus(); });
  $('#az-run').addEventListener('click', () => { const t = $('#az-text').value; if (!t.trim()) azStatus('Paste a configuration first.', 'err'); else runAnalyze({ config: t }, 'pasted text'); });
  $('#az-ex-haproxy').addEventListener('click', () => loadExample('haproxy'));
  $('#az-ex-nginx').addEventListener('click', () => loadExample('nginx'));
  const dz = $('#az-drop');
  dz.addEventListener('keydown', (e) => { if (e.target === dz && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); $('#az-files').click(); } });
  let dragDepth = 0;
  const isFileDrag = (e) => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
  const dragOn = (on) => { dz.classList.toggle('drag', on && state.mode === 'landing'); document.body.classList.toggle('dragging', on && state.mode !== 'landing'); };
  window.addEventListener('dragenter', (e) => { if (!isFileDrag(e)) return; e.preventDefault(); dragDepth++; dragOn(true); });
  window.addEventListener('dragover', (e) => { if (isFileDrag(e)) e.preventDefault(); });
  window.addEventListener('dragleave', (e) => { if (!isFileDrag(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) dragOn(false); });
  window.addEventListener('drop', async (e) => { if (!isFileDrag(e)) return; e.preventDefault(); dragDepth = 0; dragOn(false); ingestFiles(await filesFromDrop(e.dataTransfer)); });

  // chrome: theme, help, palette, shortcuts
  $('#btn-theme').addEventListener('click', cycleTheme);
  $('#btn-help').addEventListener('click', () => { $('#help').hidden = false; });
  $('#btn-palette').addEventListener('click', paletteOpen);
  $('#palette').addEventListener('mousedown', (e) => { if (e.target.id === 'palette') paletteClose(); });
  $('#help').addEventListener('mousedown', (e) => { if (e.target.id === 'help') e.currentTarget.hidden = true; });
  $('#pal-list').addEventListener('click', (e) => { const it = e.target.closest('[data-pal]'); if (it) paletteRun(Number(it.dataset.pal)); });
  $('#pal-input').addEventListener('input', () => { pal.sel = 0; paletteRender(); });
  $('#pal-input').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.sel = Math.min(pal.items.length - 1, pal.sel + 1); paletteRender(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.sel = Math.max(0, pal.sel - 1); paletteRender(); }
    else if (e.key === 'Enter') { e.preventDefault(); paletteRun(pal.sel); }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { if (!$('#chartview').hidden) cvClose(); else if (!$('#cfgup').hidden) cuClose(); else if (!$('#connect').hidden) cxClose(); else if (pal.open) paletteClose(); else if (!$('#help').hidden) $('#help').hidden = true; else if (state.view === 'detail') detailBack(); else if (document.body.classList.contains('topo-fs')) setTopoFs(false); return; }
    if (state.mode === 'landing') return;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal.open ? paletteClose() : paletteOpen(); return; }
    if (!$('#connect').hidden) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement && document.activeElement.tagName) || (document.activeElement && document.activeElement.isContentEditable);
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === '/') { e.preventDefault(); paletteOpen(); }
    else if (e.key === '?') $('#help').hidden = false;
    else if (e.key === 'f' && state.view === 'topology') toggleMapFs();
    else if (e.key === 'r') poll(true).then(() => toast('Refreshed', 'ok', 1500));
    else if (e.key === 't') cycleTheme();
    else if (/^[1-9]$/.test(e.key)) { const b = visibleNav()[Number(e.key) - 1]; if (b) switchView(b.dataset.view); }
  });
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    drawInspectorChart();
    // vis-network resizes its canvas in its own resize handler (registered after ours): refit once that has run.
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { if (network && state.view === 'topology') network.fit({ animation: false }); }, 150);
  });
}

async function backfillSeries() {
  const s = state.snapshot; if (!s) return;
  const fes = s.rows.filter((r) => r.kind === 'frontend');
  const hs = await Promise.all(fes.map((r) => api(`/instances/${encodeURIComponent(state.current)}/history?key=${encodeURIComponent(`${r.proxy}/${r.name}`)}&points=360`).catch(() => ({ points: [] }))));
  const byT = new Map();
  hs.forEach((h) => h.points.forEach((p) => { const o = byT.get(p.t) || { t: p.t, rate: 0, sess: 0, e5: 0 }; o.rate += p.rate; o.sess += p.scur; byT.set(p.t, o); }));
  const bes = s.rows.filter((r) => r.kind === 'backend');
  const bh = await Promise.all(bes.map((r) => api(`/instances/${encodeURIComponent(state.current)}/history?key=${encodeURIComponent(`${r.proxy}/${r.name}`)}&points=360`).catch(() => ({ points: [] }))));
  bh.forEach((h) => h.points.forEach((p) => { const o = byT.get(p.t); if (o) o.e5 += p.e5xx; }));
  const merged = [...byT.values()].sort((a, b) => a.t - b.t);
  if (merged.length) { state.series = merged; if (state.view === 'overview') renderOverview(); }
}

function restoreDetail(v, k) { if (v === 'detail' && k && state.snapshot) { const key = decodeURIComponent(k); const r = indexRows(state.snapshot.rows).get(key); inspect(key, r && r.kind); } }
async function init() {
  const qTheme = new URLSearchParams(location.search).get('theme');
  applyTheme(['light', 'dark'].includes(qTheme) ? qTheme : loadPref('gatelight.theme', 'dark')); // dark unless the user chose otherwise
  wire();
  const hash = location.hash.slice(1);
  const [hInst, hViewRaw, hKey] = hash.includes('/') ? hash.split('/') : [null, hash];
  const hView = hViewRaw === 'detail' ? 'overview' : (VIEW_ALIAS[hViewRaw] || hViewRaw); // a deep link to details restores below once data is loaded
  if (hInst) state.current = decodeURIComponent(hInst);
  const params = new URLSearchParams(location.search);
  const ex = params.get('example');
  try { await loadInstances(); } catch { /* API unreachable: landing still works for offline review */ }
  const ids = state.instances.map((i) => i.id);
  let entered = null; try { entered = sessionStorage.getItem('gatelight.entered'); } catch { /* storage unavailable */ }
  if (['haproxy', 'nginx'].includes(ex)) { setMode('review'); await loadExample(ex); return; }
  const hId = hInst ? decodeURIComponent(hInst) : null;
  if (hId && ids.includes(hId)) { await enterLive(hId); if (hView && $(`#view-${hView}`)) switchView(hView); restoreDetail(hViewRaw, hKey); return; }
  if (entered && ids.includes(entered)) { await enterLive(entered); if (hView && $(`#view-${hView}`)) switchView(hView); restoreDetail(hViewRaw, hKey); return; }
  let last = null; try { last = localStorage.getItem('gatelight.last'); } catch { /* storage unavailable */ }
  const open = state.instances.filter((i) => !state.hiddenTypes.includes(i.type)).map((i) => i.id);
  const pick = last && open.includes(last) ? last : open[0];
  if (pick) { await enterLive(pick); if (hView && $(`#view-${hView}`)) switchView(hView); restoreDetail(hViewRaw, hKey); return; }
  showLanding(); // nothing configured: the Overview guides the user from here
}
window.addEventListener('popstate', async () => { // Back / Forward / edited address bar: show the page the URL names
  const h = location.hash.slice(1); const [inst, view] = h.includes('/') ? [h.slice(0, h.indexOf('/')), h.slice(h.indexOf('/') + 1)] : [null, h];
  navFromHistory = true;
  try {
    if (state.mode === 'review') { if (REVIEW_VIEWS.includes(view)) switchView(view); return; }
    const id = inst ? decodeURIComponent(inst) : null;
    if (id && id !== state.current && state.instances.some((i) => i.id === id)) await enterLive(id);
    const vparts = (view || '').split('/'); const vname = VIEW_ALIAS[vparts[0]] || vparts[0];
    if (vname === 'detail' && vparts[1] && state.snapshot) { const k = decodeURIComponent(vparts[1]); const r0 = indexRows(state.snapshot.rows).get(k); inspect(k, r0 && r0.kind); }
    else if (vname && vname !== 'detail' && $(`#view-${vname}`)) switchView(vname); else if (!vname || vname === 'detail') switchView(state.detailFrom && state.view === 'detail' ? state.detailFrom : 'overview');
  } finally { navFromHistory = false; }
});
window.addEventListener('DOMContentLoaded', () => { init().finally(() => { navReady = true; }); });

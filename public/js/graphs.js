'use strict';
/* GateLight UI: Traffic Stats live charts, bar charts, Service Status charts. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
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

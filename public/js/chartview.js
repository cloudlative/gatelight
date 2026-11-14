'use strict';
/* GateLight UI: chart pop-out. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
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

'use strict';
/**
 * Traffic statistics: dashboard over the aggregates of an uploaded HAProxy log (src/logs/haproxy.js).
 * All filtering happens here, on the compact fact table, so changing a filter is instant.
 * To add a panel: write a function returning a card (see CARDS) and add it to the list; the data helpers are shared.
 * (An NGINX log can feed the same dashboard later by producing the same aggregate shape.)
 */
const TR = { mix: null, inst: null, data: null, loading: false, err: null, none: false, upErr: null, up: null, f: null, charts: {}, gen: 0 };
const TR_DEFAULTS = () => ({ range: 'all', from: null, to: null, fe: '', be: '', srv: '', cls: '', proto: '' });
TR.f = TR_DEFAULTS();
function trResetFilters() { TR.f = TR_DEFAULTS(); }

const CLS_COLOR = { '2xx': '#34d399', '3xx': '#22d3ee', '4xx': '#fbbf24', '5xx': '#f87171', abt: '#a78bfa', '1xx': '#94a3b8', oth: '#64748b', tcp: '#818cf8' };
const CLS_LABEL = { '2xx': '2xx success', '3xx': '3xx redirect / cached', '4xx': '4xx client error', '5xx': '5xx server error', abt: 'aborted (no status)', '1xx': '1xx', oth: 'other', tcp: 'TCP session' };
const HTTP_CLASSES = ['2xx', '3xx', '4xx', '5xx', 'abt', '1xx', 'oth'];
const TERM1 = { '-': 'normal', C: 'client aborted', S: 'server aborted', P: 'refused by the proxy', R: 'proxy out of resources', I: 'internal error', D: 'server marked down', K: 'killed by an admin', L: 'local response (stats, redirect)', c: 'client timeout', s: 'server timeout', U: 'no server available', F: 'frontend closed' };
const TERM2 = { '-': '', R: 'while reading the request', Q: 'waiting in the queue', C: 'connecting to the server', H: 'waiting for response headers', D: 'during data transfer', L: 'sending the last data', T: 'tarpitted' };
const trTerm = (t) => { if (!t) return ''; const a = TERM1[t[0]] || t[0]; const b = TERM2[t[1]] || ''; return t[0] === '-' && (!t[1] || t[1] === '-') ? 'completed normally' : `${a}${b ? ` ${b}` : ''}`; };
const LOG_CMDS = [
  ['Last 200,000 lines (the most recent traffic)', 'tail -n 200000 haproxy.log > haproxy-part.log'],
  ['First 200,000 lines', 'head -n 200000 haproxy.log > haproxy-part.log'],
  ['Cut into ~40 MB pieces without breaking a line (haproxy-part-00, -01, …)', 'split -C 40M -d --additional-suffix=.log haproxy.log haproxy-part-'],
  ['Cut into pieces of 200,000 lines', 'split -l 200000 -d --additional-suffix=.log haproxy.log haproxy-part-'],
  ['Keep one day and hour (syslog format “Nov 10 08:…”)', "grep -E '^Nov 10 08:' haproxy.log > haproxy-8am.log"],
  ['Only one frontend (replace the name)', "grep ' my_frontend' haproxy.log > haproxy-fe.log"],
  ['Compress a part (logs shrink about 10×; a .gz is accepted)', 'gzip -k haproxy-part.log'],
  ['Check the size before uploading', 'ls -lh haproxy-part*'],
];
const LOG_CMDS_NGINX = [
  ['Last 200,000 lines (the most recent traffic)', 'tail -n 200000 /var/log/nginx/access.log > access-part.log'],
  ['Cut into ~40 MB pieces without breaking a line (access-part-00, -01, …)', 'split -C 40M -d --additional-suffix=.log access.log access-part-'],
  ['Keep one day and hour (the time looks like [10/Nov/2026:08:15:02 +0000])', "grep -F '[10/Nov/2026:08:' access.log > access-8am.log"],
  ['Only server errors (5xx) from the default combined format', "awk '$9 ~ /^5/' access.log > access-5xx.log"],
  ['Rotated logs (access.log.1, access.log.2.gz …) can be selected together; a .gz is accepted as it is', 'ls -lh /var/log/nginx/access.log*'],
  ['Compress a part (logs shrink about 10×)', 'gzip -k access-part.log'],
];
const trProduct = () => { const i = (state.instances || []).find((x) => x.id === state.current); return i ? i.type : 'haproxy'; }; // the instance's type; uploaded logs are detected on their own
function logHelpHtml(product) {
  const cmds = (product || trProduct()) === 'nginx' ? LOG_CMDS_NGINX : LOG_CMDS;
  const max = fmtBytes((state.meta && state.meta.logMaxBytes) || 50 * 1048576);
  return `<p class="muted small">Maximum <b>${esc(max)}</b> per file; select several files at once and they are shown combined: plain text (<code>.log</code>, <code>.txt</code>) or gzip (<code>.gz</code>, the limit applies to the compressed size). Only the statistics are kept on the server, never the raw log. Run these where the log lives:</p>
    <div class="tr-cmds">${cmds.map(([t, c]) => `<div><span class="muted small">${esc(t)}</span><span class="tr-cmd"><code>${esc(c)}</code><button type="button" class="btn icon" data-copy="${esc(c)}" title="Copy" aria-label="Copy command">⧉</button></span></div>`).join('')}</div>
    <p class="muted small">Select all the pieces together, or add more later: each file is processed on its own and the statistics are shown <b>combined</b>. The same file cannot be added twice; overlapping periods are added together. Remove a file with its × next to the title.</p>`;
}
(function fillAddForm() { const h = document.getElementById('cx-loghelp'); if (h) h.innerHTML = logHelpHtml(); })();

// ------------------------------------------------------------------------------------------------ formatting
const trMs = (v) => (v == null || !isFinite(v) ? '–' : v < 1 ? '<1 ms' : v < 1000 ? `${Math.round(v)} ms` : v < 60000 ? `${(v / 1000).toFixed(v < 10000 ? 2 : 1)} s` : `${(v / 60000).toFixed(1)} min`);
const trPct = (v, d = 1) => (v == null || !isFinite(v) ? '–' : `${(v * 100).toFixed(v > 0 && v < 0.001 ? 3 : d)}%`);
const p2 = (n) => String(n).padStart(2, '0');
const MON3 = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** Log times are wall-clock times without a zone: show them exactly as written. */
function trTime(ms, withDate) { const d = new Date(ms); return `${withDate ? `${p2(d.getUTCDate())} ${MON3[d.getUTCMonth()]} ` : ''}${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`; }
const trTimeS = (ms) => `${trTime(ms, true)}:${p2(new Date(ms).getUTCSeconds())}`;
const sumArr = (a) => a.reduce((x, y) => x + y, 0);
const niceMax = (v) => { if (v <= 0) return 1; const p = 10 ** Math.floor(Math.log10(v)); const f = v / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p; };

// ------------------------------------------------------------------------------------------------ loading
async function trLoad(force) {
  if (TR.loading) return;
  if (!force && TR.inst === state.current && (TR.data || TR.none)) return;
  TR.loading = true; TR.err = null; TR.none = false; renderTraffic();
  const id = state.current;
  try {
    const d = await api(`/instances/${encodeURIComponent(id)}/logs`);
    if (id !== state.current) { TR.loading = false; return; }
    TR.data = trPrepare(d); TR.inst = id; TR.none = false;
  } catch (e) {
    if (/No traffic log/i.test(e.message)) { TR.data = null; TR.none = true; TR.inst = id; } else { TR.err = e.message; TR.data = null; }
  }
  TR.loading = false; if (state.view === 'traffic') renderTraffic();
}
function trPrepare(d) {
  const F = d.facts; d._ts = F.t.map((t) => t * 1000);
  const r0 = d._ts.length ? d._ts[0] : (d.range ? d.range.from : 0);
  const r1 = (d._ts.length ? d._ts[d._ts.length - 1] : (d.range ? d.range.to : 0)) + d.bucketMs;
  d._r0 = r0; d._r1 = r1;
  d._fes = [...new Set(d.keys.map((k) => k.fe))].sort(); d._bes = [...new Set(d.keys.map((k) => k.be))].sort();
  return d;
}
function trCanUpload() {
  const i = (state.instances || []).find((x) => x.id === state.current);
  return Boolean(state.meta && state.meta.canManage && i && i.managed && (i.type === 'haproxy' || i.type === 'nginx'));
}

// ------------------------------------------------------------------------------------------------ data selection and aggregation
function trWindow(d, f) {
  if (f.range === 'custom' && f.from != null) return [f.from, f.to];
  const m = { '15m': 15, '30m': 30, '1h': 60, '3h': 180, '6h': 360, '12h': 720, '24h': 1440 }[f.range];
  return m ? [Math.max(d._r0, d._r1 - m * 60000), d._r1] : [d._r0, d._r1];
}
function trSelect(d, f) {
  const keyOk = d.keys.map((k) => (!f.fe || k.fe === f.fe) && (!f.be || k.be === f.be) && (!f.srv || k.srv === f.srv) && (!f.cls || k.cls === f.cls) && (!f.proto || k.proto === f.proto));
  const [from, to] = trWindow(d, f); const rows = []; const F = d.facts;
  for (let i = 0; i < d._ts.length; i++) { const t = d._ts[i]; if (t >= from && t < to && keyOk[F.k[i]]) rows.push(i); }
  return { rows, keyOk, from, to };
}
function trPercentile(hist, edges, p) {
  const total = sumArr(hist); if (!total) return null;
  const target = total * p; let acc = 0;
  for (let i = 0; i < hist.length; i++) {
    if (acc + hist[i] >= target) {
      const lo = i === 0 ? 0 : edges[i - 1]; const hi = i < edges.length ? edges[i] : edges[edges.length - 1] * 2;
      return lo + ((target - acc) / (hist[i] || 1)) * (hi - lo);
    }
    acc += hist[i];
  }
  return edges[edges.length - 1];
}
function trAggregate(d, sel) {
  const F = d.facts; const nb = d.edges.length + 1;
  const A = { n: 0, http: 0, tcp: 0, bytes: 0, tt: 0, trs: 0, trn: 0, tw: 0, tc: 0, abn: 0, abt: 0, retr: 0, act: 0, fe: 0, be: 0, srv: 0, sq: 0, bq: 0, cls: {}, hHttp: new Array(nb).fill(0), hTcp: new Array(nb).fill(0), ttTcp: 0, byKey: new Map() };
  for (const i of sel.rows) {
    const k = d.keys[F.k[i]]; const n = F.n[i];
    A.n += n; A.cls[k.cls] = (A.cls[k.cls] || 0) + n; A.bytes += F.bytes[i]; A.abn += F.abn[i]; A.abt += F.abt[i]; A.retr += F.retr[i]; A.tw += F.tw[i]; A.tc += F.tc[i];
    if (k.proto === 'http') { A.http += n; A.tt += F.tt[i]; A.trs += F.tr[i]; A.trn += F.trn[i]; const h = F.h[i]; for (let j = 0; j < nb; j++) A.hHttp[j] += h[j]; } else { A.tcp += n; A.ttTcp += F.tt[i]; const h = F.h[i]; for (let j = 0; j < nb; j++) A.hTcp[j] += h[j]; }
    if (F.act[i] > A.act) A.act = F.act[i]; if (F.fe[i] > A.fe) A.fe = F.fe[i]; if (F.be[i] > A.be) A.be = F.be[i]; if (F.srvc[i] > A.srv) A.srv = F.srvc[i]; if (F.sq[i] > A.sq) A.sq = F.sq[i]; if (F.bq[i] > A.bq) A.bq = F.bq[i];
    let g = A.byKey.get(F.k[i]); if (!g) { g = { n: 0, bytes: 0, tt: 0, ttn: 0, err: 0, abn: 0 }; A.byKey.set(F.k[i], g); }
    g.n += n; g.bytes += F.bytes[i]; g.abn += F.abn[i]; if (k.proto === 'http') { g.tt += F.tt[i]; g.ttn += n; } if (k.cls === '5xx' || k.cls === 'abt') g.err += n;
  }
  return A;
}
/** Group the per-key totals by frontend / backend / server. */
function trGroup(d, A, field) {
  const m = new Map();
  for (const [kid, g] of A.byKey) {
    const name = d.keys[kid][field]; let x = m.get(name); if (!x) { x = { name, n: 0, bytes: 0, tt: 0, ttn: 0, err: 0, abn: 0 }; m.set(name, x); }
    x.n += g.n; x.bytes += g.bytes; x.tt += g.tt; x.ttn += g.ttn; x.err += g.err; x.abn += g.abn;
  }
  return [...m.values()].sort((a, b) => b.n - a.n);
}
const TR_STEPS = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400].map((s) => s * 1000);
/** Time series on a step that gives ~100 points for the selected window. */
function trSeries(d, sel) {
  const F = d.facts; const span = sel.to - sel.from;
  const step = TR_STEPS.find((s) => s >= d.bucketMs && s >= span / 110) || TR_STEPS[TR_STEPS.length - 1];
  const start = Math.floor(sel.from / step) * step; const n = Math.max(1, Math.ceil((sel.to - start) / step));
  const mk = () => new Array(n).fill(0); const nb = d.edges.length + 1;
  const S = { step, start, n, xs: Array.from({ length: n }, (_, i) => start + i * step), cls: {}, tcp: mk(), bytes: mk(), tt: mk(), http: mk(), trs: mk(), trn: mk(), tw: mk(), tc: mk(), act: mk(), fe: mk(), be: mk(), sq: mk(), abn: mk(), err: mk(), hist: Array.from({ length: n }, () => new Array(nb).fill(0)), conn: mk() };
  for (const c of HTTP_CLASSES) S.cls[c] = mk();
  for (const i of sel.rows) {
    const b = Math.min(n - 1, Math.max(0, Math.floor((d._ts[i] - start) / step))); const k = d.keys[F.k[i]]; const c = F.n[i];
    if (k.proto === 'http') { S.cls[k.cls][b] += c; S.http[b] += c; S.tt[b] += F.tt[i]; S.trs[b] += F.tr[i]; S.trn[b] += F.trn[i]; const h = F.h[i]; for (let j = 0; j < nb; j++) S.hist[b][j] += h[j]; if (k.cls === '5xx' || k.cls === 'abt') S.err[b] += c; } else S.tcp[b] += c;
    S.bytes[b] += F.bytes[i]; S.tw[b] += F.tw[i]; S.tc[b] += F.tc[i]; S.abn[b] += F.abn[i];
    if (F.act[i] > S.act[b]) S.act[b] = F.act[i]; if (F.fe[i] > S.fe[b]) S.fe[b] = F.fe[i]; if (F.be[i] > S.be[b]) S.be[b] = F.be[i]; if (F.sq[i] > S.sq[b]) S.sq[b] = F.sq[i];
    S.conn[b] += c;
  }
  return S;
}
function trAggDim(d, name, sel) { // small per-hour dimensions: status code, method, version, termination, host
  const D = d.dims[name]; const m = new Map();
  for (const r of D.rows) {
    const hour = r[0] * 3600000; if (hour + 3600000 <= sel.from || hour >= sel.to || !sel.keyOk[r[1]]) continue;
    const v = D.values[r[2]]; let x = m.get(v); if (!x) { x = { v, n: 0, bytes: 0, tt: 0, err: 0 }; m.set(v, x); } x.n += r[3]; x.bytes += r[4]; x.tt += r[5]; x.err += r[6];
  }
  return [...m.values()].sort((a, b) => b.n - a.n);
}

// ------------------------------------------------------------------------------------------------ chart primitives (SVG, sized to the card)
const trTip = (lines) => esc(lines.filter(Boolean).join('\n'));
/** Time chart: stacked bars, lines or areas. `series`: [{label, color, vals}]. Painted after layout, when the width is known. */
function trTimeChart(id, S, series, o = {}) {
  TR.charts[id] = { kind: 'time', S, series, o };
  return `<div class="tr-chart${o.brush ? ' tr-brushable' : ''}" data-ch="${id}" style="height:${o.h || 210}px"></div>${o.legend === false ? '' : `<div class="tr-legend">${series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.label)}</span>`).join('')}</div>`}`;
}
function trPaintTime(el, spec) {
  const { S, series, o } = spec; const W = Math.max(260, el.clientWidth); const H = o.h || 210; const L = 48; const R = 10; const T = 8; const B = 22;
  const n = S.n; const bw = (W - L - R) / n; const fmt = o.fmt || fmtInt; const stacked = o.type === 'stack';
  const totals = Array.from({ length: n }, (_, i) => (stacked ? series.reduce((a, s) => a + (s.vals[i] || 0), 0) : Math.max(...series.map((s) => s.vals[i] || 0))));
  const yMax = o.yMax || niceMax(Math.max(...totals, 0) * 1.05); const y = (v) => T + (H - T - B) * (1 - Math.min(1, v / yMax)); const x = (i) => L + (i + 0.5) * bw;
  let g = '';
  for (let k = 0; k <= 4; k++) { const v = (yMax * k) / 4; g += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="tr-grid-l"/><text x="${L - 6}" y="${y(v) + 3.5}" text-anchor="end" class="tr-ax">${esc(fmt(v))}</text>`; }
  const ticks = Math.min(7, n); const wd = S.xs[n - 1] - S.xs[0] > 36 * 3600000;
  for (let k = 0; k < ticks; k++) { const i = Math.round((k * (n - 1)) / Math.max(1, ticks - 1)); g += `<text x="${Math.max(L, Math.min(W - R - 14, x(i)))}" y="${H - 6}" text-anchor="middle" class="tr-ax">${trTime(S.xs[i], wd)}</text>`; }
  if (o.type === 'stack') {
    for (let i = 0; i < n; i++) { let acc = 0; for (const s of series) { const v = s.vals[i] || 0; if (v <= 0) continue; const y1 = y(acc + v); const y0 = y(acc); g += `<rect x="${(L + i * bw + 0.5).toFixed(2)}" y="${y1.toFixed(2)}" width="${Math.max(1, bw - 1).toFixed(2)}" height="${Math.max(0.6, y0 - y1).toFixed(2)}" fill="${s.color}"/>`; acc += v; } }
  } else {
    for (const s of series) {
      const pts = s.vals.map((v, i) => `${x(i).toFixed(1)},${y(v || 0).toFixed(1)}`);
      if (o.type === 'area') g += `<path d="M${x(0).toFixed(1)},${y(0)} L${pts.join(' L')} L${x(n - 1).toFixed(1)},${y(0)} Z" fill="${s.color}" opacity=".16"/>`;
      g += `<polyline points="${pts.join(' ')}" fill="none" stroke="${s.color}" stroke-width="1.6" stroke-linejoin="round"/>`;
    }
  }
  const tips = S.xs.map((t, i) => `<rect class="tr-hit" x="${(L + i * bw).toFixed(1)}" y="${T}" width="${bw.toFixed(1)}" height="${H - T - B}" data-tip="${trTip([`${trTimeS(t)}${S.step >= 60000 ? ` (${S.step >= 3600000 ? `${S.step / 3600000} h` : `${S.step / 60000} min`})` : ''}`, ...series.map((s) => `${s.label}: ${fmt(s.vals[i] || 0)}`)])}"/>`).join('');
  el.innerHTML = `<svg class="tr-svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" data-l="${L}" data-r="${W - R}" data-t0="${S.xs[0]}" data-step="${S.step}" data-n="${n}" role="img" aria-label="${esc(o.title || 'chart')}">${g}${tips}<rect class="tr-brush" x="0" y="${T}" width="0" height="${H - T - B}" hidden/></svg>`;
}
/** Vertical bars for categories (histograms). items: [{label, value, color, tip}] */
function trColChart(id, items, o = {}) {
  TR.charts[id] = { kind: 'cols', items, o };
  return `<div class="tr-chart" data-ch="${id}" style="height:${o.h || 190}px"></div>`;
}
function trPaintCols(el, spec) {
  const { items, o } = spec; const W = Math.max(240, el.clientWidth); const H = o.h || 190; const L = 40; const R = 6; const T = 8; const B = 34;
  const max = niceMax(Math.max(...items.map((i) => i.value), 0) * 1.05); const bw = (W - L - R) / items.length; const y = (v) => T + (H - T - B) * (1 - v / max);
  let g = '';
  for (let k = 0; k <= 3; k++) { const v = (max * k) / 3; g += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="tr-grid-l"/><text x="${L - 5}" y="${y(v) + 3.5}" text-anchor="end" class="tr-ax">${esc((o.fmt || fmtInt)(v))}</text>`; }
  items.forEach((it, i) => {
    const x0 = L + i * bw; const hgt = Math.max(it.value > 0 ? 1 : 0, (H - T - B) * (it.value / max));
    g += `<rect x="${(x0 + 2).toFixed(1)}" y="${(H - B - hgt).toFixed(1)}" width="${Math.max(2, bw - 4).toFixed(1)}" height="${hgt.toFixed(1)}" rx="2" fill="${it.color || '#818cf8'}"/>`
      + (i % Math.max(1, Math.ceil(40 / bw)) === 0 ? `<text x="${(x0 + bw / 2).toFixed(1)}" y="${H - B + 12}" text-anchor="middle" class="tr-ax">${esc(it.label)}</text>` : '')
      + `<rect class="tr-hit" x="${x0.toFixed(1)}" y="${T}" width="${bw.toFixed(1)}" height="${H - T - B + 18}" data-tip="${trTip([it.tip || `${it.label}: ${(o.fmt || fmtInt)(it.value)}`])}"/>`;
  });
  el.innerHTML = `<svg class="tr-svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(o.title || 'chart')}">${g}</svg>`;
}
function trPaintAll() {
  for (const el of $$('#view-traffic .tr-chart[data-ch]')) { const s = TR.charts[el.dataset.ch]; if (!s) continue; if (s.kind === 'time') trPaintTime(el, s); else trPaintCols(el, s); }
}
/** Horizontal bar list: rows [{label, value, color, right, tip}] */
function trHBars(rows, o = {}) {
  const max = Math.max(...rows.map((r) => r.value), 1);
  if (!rows.length) return '<div class="tr-empty">No data for this selection</div>';
  return `<div class="tr-hb">${rows.map((r) => `<div class="tr-hb-r" data-tip="${trTip([r.tip || `${r.label}: ${(o.fmt || fmtInt)(r.value)}`])}"><span class="tr-hb-l" title="${esc(r.label)}">${esc(r.label)}</span><span class="tr-hb-t"><i style="width:${Math.max(1, (r.value / max) * 100).toFixed(1)}%;background:${r.color || 'var(--indigo)'}"></i></span><span class="tr-hb-v">${esc((o.fmt || fmtInt)(r.value))}</span>${r.right ? `<span class="tr-hb-x">${r.right}</span>` : ''}</div>`).join('')}</div>`;
}
const trCard = (title, body, o = {}) => `<section class="tr-card span-${o.span || 6}${o.cls ? ` ${o.cls}` : ''}"><header class="tr-h"><h3>${esc(title)}</h3>${o.sub ? `<span class="tr-sub">${o.sub}</span>` : ''}</header><div class="tr-body">${body}</div></section>`;
const trTable = (head, rows, o = {}) => (rows.length ? `<div class="tr-tw"><table class="grid tr-t"><thead><tr>${head.map((h, i) => `<th class="${i ? 'num' : ''}">${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>` : `<div class="tr-empty">${o.empty || 'No data for this selection'}</div>`);

// ------------------------------------------------------------------------------------------------ the page
function renderTraffic() {
  const el = $('#view-traffic'); if (!el) return;
  const snap = state.snapshot; if (!snap) { el.innerHTML = ''; return; }
  if (TR.inst !== state.current && !TR.loading) { TR.data = null; TR.none = false; TR.err = null; trResetFilters(); TR.inst = state.current; setTimeout(() => trLoad(true), 0); }
  const head = trHeadHtml();
  if (TR.loading && !TR.data) { el.innerHTML = `${head}<div class="skeleton-cards"><i></i><i></i><i></i></div>`; return; }
  if (TR.err) { el.innerHTML = `${head}<div class="panel"><div class="empty">Could not load the statistics: ${esc(TR.err)}</div></div>`; return; }
  if (!TR.data) { el.innerHTML = `${head}${trEmptyHtml()}`; return; }
  const d = TR.data; const f = TR.f;
  const sel = trSelect(d, f); const A = trAggregate(d, sel); const S = trSeries(d, sel);
  TR.charts = {};
  const body = A.n ? trBody(d, sel, A, S) : '<div class="panel"><div class="empty">No traffic matches these filters. <button class="link" type="button" data-tr-reset>Reset filters</button></div></div>';
  el.innerHTML = `${head}${trFiltersHtml(d, f, sel, A)}${body}`;
  trPaintAll();
}
function trHeadHtml() {
  const d = TR.data; const can = trCanUpload();
  const src = d && d.source ? d.source : null;
  const files = src && src.files ? src.files : [];
  const chips = can && !(src && src.demo) && files.length ? `<div class="tr-chips">${files.map((f) => `<span class="tr-chip" title="${esc(`${f.filename}: ${fmtInt(f.lines)} lines${f.range ? `, ${trTimeS(f.range.from)} to ${trTimeS(f.range.to)}` : ''}`)}">${esc(f.filename)} <span class="muted">${esc(fmtBytes(f.bytes || 0))}</span><button type="button" data-tr-rmpart="${esc(f.part)}" title="Remove this file from the statistics" aria-label="Remove ${esc(f.filename)}">×</button></span>`).join('')}</div>` : '';
  const info = src ? `<span class="tr-file"><b>${esc(src.filename || 'log')}</b>${src.demo ? ' <span class="tag">demo data</span>' : ''} · ${src.bytes ? `${esc(fmtBytes(src.bytes))}${src.gzip ? ' (gz)' : ''} · ` : ''}${fmtInt(src.lines)} lines · ${d.range ? `${esc(trTimeS(d.range.from))} → ${esc(trTimeS(d.range.to))}` : ''}${d.generated && !src.demo ? ` · processed ${esc(new Date(d.generated).toLocaleString())}` : ''}</span>${chips}` : '<span class="muted small">No log uploaded yet</span>';
  const up = TR.up;
  const prog = up ? `<div class="tr-prog" id="tr-prog"><div class="tr-bar${up.done ? ' busy' : ''}"><i style="width:${up.done ? 100 : up.pct}%"></i></div><span class="muted small">${esc(up.text)}</span></div>` : '';
  const live = !(state.snapshot && state.snapshot.instance && state.snapshot.instance.source === 'config-only');
  const sw = `<div class="tsw2" role="tablist" aria-label="Traffic source"><button type="button" role="tab" aria-selected="false" class="tab-live"${live ? ' data-goto="graphs"' : ' disabled title="This instance has no live statistics endpoint"'}><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg><span><b>Live Metrics</b><small>Right now, from the stats endpoint</small></span></button><button type="button" role="tab" aria-selected="true" class="tab-log on" data-goto="traffic"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/></svg><span><b>From a Log File</b><small>Past traffic, from an uploaded access log</small></span></button></div>`;
  return `<div class="panel tr-top"><div class="tr-title"><div>${sw}<h2 class="tr-h2">Traffic from a Log File</h2><div class="tr-meta">${info}</div></div><span class="spacer"></span>
      ${can ? `<input type="file" id="tr-file" multiple accept=".log,.txt,.gz,.out,text/plain,application/gzip,application/x-gzip" hidden><button class="btn primary" type="button" data-tr-upload>${d ? 'Add log files' : 'Upload log files'}</button>${d ? '<button class="btn" type="button" data-tr-delete>Delete all</button>' : ''}` : ''}</div>
    ${prog}${TR.upErr ? `<div class="tr-err" role="alert">${esc(TR.upErr)}${TR.mix ? ` <button class="btn" type="button" data-tr-replace>Replace the existing logs with ${TR.mix.length > 1 ? 'these files' : 'this file'}</button>` : ''}</div>` : ''}</div>`;
}
function trEmptyHtml() {
  const can = trCanUpload();
  const nxp = trProduct() === 'nginx';
  return `<div class="panel tr-empty-p"><h3>${can ? `Upload ${nxp ? 'NGINX' : 'HAProxy'} logs to see the traffic` : 'No traffic log for this instance'}</h3>
    <p class="muted">${can ? (nxp ? 'Pick a complete access log, or several parts at once (rotated <code>.gz</code> files too), to be shown combined: the default <code>combined</code> format, with or without <code>$request_time</code> / <code>$upstream_*</code> fields, or JSON lines. You get requests, status codes, errors, URLs, clients and more, with filters; response times appear when the log has them.' : 'Pick a complete log, or several parts at once, to be shown combined (<code>option httplog</code> / <code>tcplog</code> lines). You get requests, response times, errors, status codes, servers, URLs, clients and more, with filters.') : `Traffic statistics come from ${nxp ? 'an NGINX access' : 'an HAProxy'} log uploaded to a connection added in the UI (Add instance → Traffic log).`}</p>
    ${can ? '<button class="btn primary" type="button" data-tr-upload>Choose log files</button>' : ''}
    <details class="tr-help" ${can ? 'open' : ''}><summary>Log too big? Split it first, then select all the parts</summary>${logHelpHtml()}</details></div>`;
}
function trFiltersHtml(d, f, sel, A) {
  const opt = (v, t, cur) => `<option value="${esc(v)}"${cur === v ? ' selected' : ''}>${esc(t)}</option>`;
  const srvs = [...new Set(d.keys.filter((k) => (!f.be || k.be === f.be) && (!f.fe || k.fe === f.fe)).map((k) => k.srv))].sort();
  const rng = [['all', 'Entire log'], ['15m', 'Last 15 minutes'], ['30m', 'Last 30 minutes'], ['1h', 'Last hour'], ['3h', 'Last 3 hours'], ['6h', 'Last 6 hours'], ['12h', 'Last 12 hours'], ['24h', 'Last 24 hours']];
  const custom = f.range === 'custom' ? `<option value="custom" selected>${esc(trTime(f.from, true))} → ${esc(trTime(f.to, true))}</option>` : '';
  const active = f.range !== 'all' || f.fe || f.be || f.srv || f.cls || f.proto;
  return `<div class="panel tr-filters"><label>Time<select data-trf="range">${rng.map(([v, t]) => opt(v, t, f.range)).join('')}${custom}</select></label>
    <label>${esc(lbl('frontend'))}<select data-trf="fe">${opt('', 'All', f.fe)}${d._fes.map((x) => opt(x, x, f.fe)).join('')}</select></label>
    <label>${esc(lbl('backend'))}<select data-trf="be">${opt('', 'All', f.be)}${d._bes.map((x) => opt(x, x, f.be)).join('')}</select></label>
    <label>${esc(lbl('server'))}<select data-trf="srv">${opt('', 'All', f.srv)}${srvs.map((x) => opt(x, x, f.srv)).join('')}</select></label>
    <label>Status<select data-trf="cls">${opt('', 'All', f.cls)}${['2xx', '3xx', '4xx', '5xx', 'abt', 'tcp'].map((c) => opt(c, c === 'abt' ? 'Aborted' : c === 'tcp' ? 'TCP sessions' : c, f.cls)).join('')}</select></label>
    <label>Protocol<select data-trf="proto">${opt('', 'All', f.proto)}${opt('http', 'HTTP', f.proto)}${opt('tcp', 'TCP', f.proto)}</select></label>
    <span class="spacer"></span><span class="tr-count muted small">${fmtInt(A.n)} request${A.n === 1 ? '' : 's'} · ${esc(trTime(sel.from, true))} → ${esc(trTime(sel.to, true))}</span>
    <button class="btn" type="button" data-tr-reset${active ? '' : ' disabled'}>Reset filters</button></div>`;
}

function trBody(d, sel, A, S) {
  const nx = d.product === 'nginx'; const timed = !nx || (d.stats.timed || 0) > 0; const hasUp = !nx || d.keys.some((k) => k.be !== '(no upstream)');
  const spanS = Math.max(1, (sel.to - sel.from) / 1000);
  const p50 = trPercentile(A.hHttp, d.edges, 0.5); const p95 = trPercentile(A.hHttp, d.edges, 0.95); const p99 = trPercentile(A.hHttp, d.edges, 0.99);
  const errN = (A.cls['5xx'] || 0) + (A.cls.abt || 0);
  const peakMin = Math.max(...S.http.map((v, i) => (v + S.tcp[i]) / (S.step / 60000)), 0);
  const kpi = (label, value, sub, tip, tone) => `<div class="tr-kpi${tone ? ` ${tone}` : ''}" data-tip="${trTip([tip])}"><span class="tr-kl">${esc(label)}</span><b class="tr-kv">${value}</b><span class="tr-ks">${sub}</span></div>`;
  const kpis = [
    kpi('Requests', fmtInt(A.http), `${fmtInt(A.http / spanS * 60 < 10 ? Math.round(A.http / spanS * 60) : A.http / spanS * 60)}/min avg · peak ${fmtInt(peakMin)}/min`, 'HTTP requests in the selection, and TCP sessions are counted separately.'),
    ...(nx ? [] : [kpi('TCP sessions', fmtInt(A.tcp), A.tcp ? `avg ${esc(trMs(A.ttTcp / A.tcp))} long` : 'no TCP traffic', 'Connections to TCP (layer 4) frontends. The time is the whole session.')]),
    ...(!timed ? [] : [kpi('Avg response', trMs(A.http ? A.tt / A.http : null), `median ${trMs(p50)}`, 'Total time per request (HAProxy "Tt"), including slow clients. Median is estimated from the latency histogram.'),
    kpi('95th percentile', trMs(p95), `99th ${trMs(p99)}`, '95% of requests were faster than this (estimated from the latency histogram).', p95 > 1000 ? 'warn' : '')]),
    kpi('Error rate', trPct(A.http ? errN / A.http : null), `${fmtInt(errN)} × 5xx${nx ? '' : ' or aborted'}`, '5xx responses plus requests that ended without a status (client or server aborted).', errN / (A.http || 1) > 0.02 ? 'bad' : ''),
    kpi('Data sent', fmtBytes(A.bytes), `${fmtBytes(A.bytes / spanS)}/s avg`, 'Bytes returned to clients (HAProxy "bytes_read").'),
    kpi('Unique clients', fmtInt(d.stats.uniqueClients), d.stats.uniqueApprox ? 'whole log, approximate' : 'whole log', 'Distinct client IP addresses in the whole log (not narrowed by the filters).'),
    ...(nx ? [] : [kpi('Peak concurrency', fmtInt(A.act), `frontend ${fmtInt(A.fe)} · backend ${fmtInt(A.be)}`, 'Highest number of simultaneous connections the proxy reported in a log line (process / frontend / backend).')]),
  ];
  const cards = [];
  // 1. requests over time
  const reqSeries = HTTP_CLASSES.filter((c) => sumArr(S.cls[c])).map((c) => ({ label: CLS_LABEL[c], color: CLS_COLOR[c], vals: S.cls[c] }));
  if (sumArr(S.tcp)) reqSeries.push({ label: CLS_LABEL.tcp, color: CLS_COLOR.tcp, vals: S.tcp });
  cards.push(trCard('Requests over time', trTimeChart('req', S, reqSeries, { type: 'stack', brush: true, title: 'Requests over time' }), { span: 12, sub: `per ${S.step >= 3600000 ? `${S.step / 3600000} h` : `${S.step / 60000} min`} · drag to zoom into a period` }));
  // 2. response time + throughput
  const avgTt = S.tt.map((v, i) => (S.http[i] ? v / S.http[i] : 0)); const p95s = S.hist.map((h) => trPercentile(h, d.edges, 0.95) || 0); const avgTr = S.trs.map((v, i) => (S.trn[i] ? v / S.trn[i] : 0));
  if (timed) cards.push(trCard('Response time', trTimeChart('rt', S, [{ label: '95th percentile', color: '#f87171', vals: p95s }, { label: 'Average (total)', color: '#22d3ee', vals: avgTt }, { label: 'Average server time', color: '#34d399', vals: avgTr }], { type: 'line', fmt: trMs, title: 'Response time' }), { sub: 'total time per request; server time = until the first response byte' }));
  cards.push(trCard('Throughput', trTimeChart('bw', S, [{ label: 'Data sent to clients per second', color: '#818cf8', vals: S.bytes.map((v) => v / (S.step / 1000)) }], { type: 'area', fmt: (v) => `${fmtBytes(v)}/s`, title: 'Throughput' }), { sub: 'bytes per second' }));
  // 3. errors + concurrency
  cards.push(trCard('Error rate over time', trTimeChart('err', S, [{ label: '5xx + aborted (% of requests)', color: '#f87171', vals: S.err.map((v, i) => (S.http[i] ? (v / S.http[i]) * 100 : 0)) }, { label: '4xx (% of requests)', color: '#fbbf24', vals: S.cls['4xx'].map((v, i) => (S.http[i] ? (v / S.http[i]) * 100 : 0)) }], { type: 'line', fmt: (v) => `${v.toFixed(v < 10 ? 1 : 0)}%`, title: 'Error rate' }), { sub: 'share of HTTP requests' }));
  if (!nx) cards.push(trCard('Concurrent connections', trTimeChart('conc', S, [{ label: 'Process (all)', color: '#22d3ee', vals: S.act }, { label: 'Frontend', color: '#818cf8', vals: S.fe }, { label: 'Backend', color: '#34d399', vals: S.be }], { type: 'line', title: 'Concurrent connections' }), { sub: 'peak per period, as reported by HAProxy' }));
  // 4. donuts
  const stSegs = HTTP_CLASSES.map((c) => ({ label: CLS_LABEL[c], value: A.cls[c] || 0, color: CLS_COLOR[c] })).filter((s) => s.value);
  cards.push(`<div class="span-4 tr-dn">${donutCard('Status classes', stSegs, { big: fmtInt(A.http), sub: 'requests' }, 'HTTP responses by status class')}</div>`);
  const meth = trAggDim(d, 'method', sel); const PAL = ['#22d3ee', '#818cf8', '#34d399', '#fbbf24', '#f87171', '#a78bfa', '#94a3b8'];
  cards.push(`<div class="span-4 tr-dn">${donutCard('Methods', meth.slice(0, 6).map((m, i) => ({ label: m.v, value: m.n, color: PAL[i] })), { big: fmtInt(sumArr(meth.map((m) => m.n))), sub: 'requests' }, 'HTTP methods')}</div>`);
  const mix = [{ label: 'HTTP', value: A.http, color: '#22d3ee' }, { label: 'TCP', value: A.tcp, color: '#818cf8' }];
  const ver = trAggDim(d, 'version', sel).filter((v) => v.v && v.v !== '-');
  cards.push(`<div class="span-4 tr-dn">${donutCard('Traffic mix', [...mix, ...ver.map((v, i) => ({ label: v.v, value: 0, color: PAL[i + 2] }))].filter((s) => s.value || false), { big: trPct(A.n ? A.http / A.n : 0, 0), sub: 'HTTP' }, 'HTTP vs TCP sessions in the selection')}</div>`);
  // 5. backends, servers
  const bes = trGroup(d, A, 'be'); const srvs = trGroup(d, A, 'srv').filter((x) => !/^<.*>$/.test(x.name) || x.n);
  const right = (x) => `${x.ttn ? `<em>${esc(trMs(x.tt / x.ttn))}</em>` : ''}${x.err ? `<em class="bad">${esc(trPct(x.err / x.n))} err</em>` : ''}`;
  if (hasUp) cards.push(trCard(`${lbl('backend')}s`, trHBars(bes.slice(0, 12).map((x) => ({ label: x.name, value: x.n, right: right(x), tip: `${x.name}\n${fmtInt(x.n)} requests\n${fmtBytes(x.bytes)} sent\navg ${trMs(x.ttn ? x.tt / x.ttn : null)}\nerrors ${fmtInt(x.err)}` }))), { sub: 'requests · avg time · error rate' }));
  if (hasUp) cards.push(trCard(`${lbl('server')}s`, trHBars(srvs.slice(0, 12).map((x) => ({ label: x.name, value: x.n, color: x.err / x.n > 0.02 ? 'var(--red)' : 'var(--green)', right: right(x), tip: `${x.name}\n${fmtInt(x.n)} requests\n${fmtBytes(x.bytes)} sent\navg ${trMs(x.ttn ? x.tt / x.ttn : null)}\nerrors ${fmtInt(x.err)}` }))), { sub: 'load share · avg time · error rate' }));
  // 6. frontends, latency histogram, tcp sessions
  const fes = trGroup(d, A, 'fe');
  cards.push(trCard(`${lbl('frontend')}s`, trHBars(fes.slice(0, 8).map((x) => ({ label: x.name, value: x.n, color: 'var(--cyan)', right: `<em>${esc(fmtBytes(x.bytes))}</em>` }))), { span: 4, sub: 'requests · data sent' }));
  if (timed) {
  const labels = d.edges.map((e) => (e < 1000 ? `${e}ms` : `${e / 1000}s`)); labels.push(`>${labels[labels.length - 1]}`);
    const hist = (h, color) => h.map((v, i) => ({ label: i ? `<${labels[i]}`.replace('<>', '>') : '<1ms', value: v, color, tip: `${i ? `${labels[i - 1]} to ${labels[i]}` : 'under 1ms'}: ${fmtInt(v)}` }));
    const hh = hist(A.hHttp, '#22d3ee'); hh[hh.length - 1].label = labels[labels.length - 1];
    cards.push(trCard('Response time distribution', trColChart('hist', hh, { title: 'Response time distribution', h: 190 }), { span: 4, sub: 'HTTP requests by total time' }));
    if (A.tcp) { const th = hist(A.hTcp, '#818cf8'); th[th.length - 1].label = labels[labels.length - 1]; cards.push(trCard('TCP session length', trColChart('hist2', th, { title: 'TCP session length', h: 190 }), { span: 4, sub: 'sessions by duration' })); } else if (!nx) cards.push(trCard('Queue and connect time', trTimeChart('qc', S, [{ label: 'Avg time in queue', color: '#fbbf24', vals: S.tw.map((v, i) => (S.http[i] + S.tcp[i] ? v / (S.http[i] + S.tcp[i]) : 0)) }, { label: 'Avg connect time', color: '#a78bfa', vals: S.tc.map((v, i) => (S.http[i] + S.tcp[i] ? v / (S.http[i] + S.tcp[i]) : 0)) }], { type: 'line', fmt: trMs, h: 190, title: 'Queue and connect time' }), { span: 4, sub: 'waiting for a free server' }));
  } else {
  const codes = trAggDim(d, 'code', sel);
  const CODE_COL = (v) => (v[0] === '2' ? 'var(--green)' : v[0] === '3' ? 'var(--cyan)' : v[0] === '4' ? 'var(--amber)' : 'var(--red)');
    cards.push(trCard('Status codes', trHBars(codes.slice(0, 10).map((x) => ({ label: x.v, value: x.n, color: CODE_COL(x.v), right: `<em>${esc(trPct(x.n / (A.http || 1)))}</em>`, tip: `${x.v}: ${fmtInt(x.n)} requests` }))), { span: 8, sub: 'responses by exact status code' }));
  }
  // 7. heatmap + terminations
  cards.push(trCard('Requests by hour', trHeat(d, sel, A, hasUp ? 'be' : 'fe'), { sub: `${esc(lbl(hasUp ? 'backend' : 'frontend').toLowerCase())} × hour of day` }));
  const terms = trAggDim(d, 'term', sel);
  if (!nx) cards.push(trCard('How sessions ended', trHBars(terms.slice(0, 10).map((x) => ({ label: x.v, value: x.n, color: x.v[0] === '-' || x.v[0] === 'L' ? 'var(--green)' : 'var(--amber)', right: `<em>${esc(trTerm(x.v))}</em>`, tip: `${x.v}: ${trTerm(x.v)}\n${fmtInt(x.n)} sessions` }))), { sub: 'termination state: who ended it, and when' }));
  // 8. paths, slowest
  const paths = trAggPaths(d, sel); const tot = A.http || 1;
  cards.push(trCard('Top URLs', trTable(['URL', 'Requests', 'Share', 'Avg', 'Max', 'Errors', 'Data'], paths.slice(0, 12).map((p) => `<tr><td class="mono pth" title="${esc(p.path)}">${esc(p.path)}</td><td class="num">${fmtInt(p.n)}</td><td class="num">${trPct(p.n / tot)}</td><td class="num">${timed ? esc(trMs(p.tt / p.n)) : '–'}</td><td class="num">${timed ? esc(trMs(p.max)) : '–'}</td><td class="num ${p.err ? 'bad' : ''}">${p.err ? trPct(p.err / p.n) : '–'}</td><td class="num">${esc(fmtBytes(p.bytes))}</td></tr>`)), { sub: 'whole log · ids in the URL are grouped (:n, :id)' }));
  const slow = d.slow.filter((r) => sel.keyOk[r[2]] && r[0] >= sel.from && r[0] < sel.to).slice(0, 12);
  if (timed) cards.push(trCard('Slowest requests', trTable(['When', 'Time', 'Status', 'Request', 'Server'], slow.map((r) => `<tr><td class="nw">${esc(trTimeS(r[0]))}</td><td class="num">${esc(trMs(r[1]))}</td><td class="num"><span class="tr-st st-${esc(String(r[3])[0])}">${esc(r[3] < 0 ? 'abort' : r[3])}</span></td><td class="mono pth" title="${esc(`${r[4]} ${r[5]}`)}">${esc(r[4])} ${esc(r[5])}</td><td class="nw">${esc(d.keys[r[2]].srv)}</td></tr>`)), { sub: 'longest total time' }));
  // 9. clients, hosts
  const cl = trAggClients(d, sel);
  cards.push(trCard('Top clients', trTable(['Client', 'Requests', 'Share', 'Data', 'Errors'], cl.slice(0, 12).map((c) => `<tr><td class="mono">${esc(c.ip)}</td><td class="num">${fmtInt(c.n)}</td><td class="num">${trPct(c.n / (A.n || 1))}</td><td class="num">${esc(fmtBytes(c.bytes))}</td><td class="num ${c.err ? 'bad' : ''}">${c.err ? fmtInt(c.err) : '–'}</td></tr>`)), { sub: 'whole log' }));
  const hosts = trAggDim(d, 'host', sel);
  if (!nx || hosts.length) cards.push(trCard('Sites and origins', trHBars(hosts.slice(0, 10).map((x) => ({ label: x.v, value: x.n, color: 'var(--indigo)', right: x.err ? `<em class="bad">${esc(trPct(x.err / x.n))} err</em>` : '' })), {}) + (hosts.length ? '' : ''), { sub: d.product === 'nginx' ? 'from the Host header or $host in the log format' : 'from the captured request header (capture request header …)' }));
  // 10. error samples, events
  const errs = d.errors.filter((r) => sel.keyOk[r[1]] && r[0] >= sel.from && r[0] < sel.to).slice(-12).reverse();
  cards.push(trCard('Recent errors', trTable(['When', 'Status', 'Request', 'Server', 'Ended'], errs.map((r) => `<tr><td class="nw">${esc(trTimeS(r[0]))}</td><td class="num"><span class="tr-st st-5">${esc(r[2] < 0 ? 'abort' : r[2])}</span></td><td class="mono pth" title="${esc(`${r[3]} ${r[4]}`)}">${esc(r[3])} ${esc(r[4])}</td><td class="nw">${esc(d.keys[r[1]].srv)}</td><td class="nw" title="${esc(trTerm(r[6]))}">${esc(r[6])}</td></tr>`), { empty: '✓ No 5xx or aborted requests in the sample' }), { sub: '5xx responses and aborted requests' }));
  cards.push(trCard(nx ? 'Error log events' : 'Server events and connection errors', trEvents(d, sel), { sub: nx ? 'lines of the NGINX error log, when included' : 'health changes and connection-level failures' }));
  // 11. data quality
  const st = d.stats;
  cards.push(trCard('About this data', `<div class="tr-dq"><div><b>${fmtInt(st.lines)}</b><span>lines read</span></div><div><b>${fmtInt(st.http + st.tcp)}</b><span>requests understood</span></div><div><b>${fmtInt(st.conn + st.events)}</b><span>connection errors &amp; events</span></div><div class="${st.unparsed ? 'warn' : ''}"><b>${fmtInt(st.unparsed)}</b><span>lines skipped</span></div><div><b>${esc(d.bucketMs >= 3600000 ? `${d.bucketMs / 3600000} h` : `${d.bucketMs / 60000} min`)}</b><span>time resolution</span></div></div>${d.unparsed && d.unparsed.length ? `<details class="tr-help"><summary>Skipped lines (masked samples)</summary>${d.unparsed.map((u) => `<div class="mono small tr-skip">${fmtInt(u.n)} × ${esc(u.sample)}</div>`).join('')}</details>` : ''}<p class="muted small">Skipped lines are lines that are not in HAProxy's http or tcp log format, for example truncated lines. They do not affect the numbers above. Top URLs, clients and sites cover the whole log; time filters use the log's own timestamps.</p>`, { span: 12 }));
  return `<div class="tr-kpis">${kpis.join('')}</div><div class="tr-grid">${cards.join('')}</div>`;
}
function trAggPaths(d, sel) {
  const m = new Map();
  for (const r of d.paths.rows) { if (!sel.keyOk[r[1]]) continue; let x = m.get(r[0]); if (!x) { x = { path: d.paths.values[r[0]], n: 0, bytes: 0, tt: 0, max: 0, err: 0 }; m.set(r[0], x); } x.n += r[2]; x.bytes += r[3]; x.tt += r[4]; if (r[5] > x.max) x.max = r[5]; x.err += r[6]; }
  return [...m.values()].sort((a, b) => b.n - a.n);
}
function trAggClients(d, sel) {
  const m = new Map();
  for (const r of d.clients.rows) { if (!sel.keyOk[r[1]]) continue; let x = m.get(r[0]); if (!x) { x = { ip: d.clients.values[r[0]], n: 0, bytes: 0, err: 0 }; m.set(r[0], x); } x.n += r[2]; x.bytes += r[3]; x.err += r[4]; }
  return [...m.values()].sort((a, b) => b.n - a.n);
}
function trHeat(d, sel, A, by = 'be') {
  const F = d.facts; const m = new Map(); const hours = new Set();
  for (const i of sel.rows) { const be = d.keys[F.k[i]][by]; const h = Math.floor(d._ts[i] / 3600000); hours.add(h); let r = m.get(be); if (!r) { r = new Map(); m.set(be, r); } r.set(h, (r.get(h) || 0) + F.n[i]); }
  const hs = [...hours].sort((a, b) => a - b).slice(-48); if (!hs.length) return '<div class="tr-empty">No data for this selection</div>';
  const rowsB = [...m.entries()].map(([be, r]) => ({ be, r, tot: sumArr([...r.values()]) })).sort((a, b) => b.tot - a.tot).slice(0, 10);
  const max = Math.max(...rowsB.flatMap((x) => [...x.r.values()]), 1);
  const cell = (v) => (v ? `<td class="tr-hc" style="background:color-mix(in srgb, var(--cyan) ${Math.round(12 + 78 * Math.sqrt(v / max))}%, transparent)" data-tip="${trTip([`${fmtInt(v)} requests`])}">${v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 0 : 1)}k` : v}</td>` : '<td class="tr-hc z"></td>');
  return `<div class="tr-tw"><table class="tr-heat"><thead><tr><th></th>${hs.map((h) => `<th>${p2(new Date(h * 3600000).getUTCHours())}</th>`).join('')}</tr></thead><tbody>${rowsB.map((x) => `<tr><th class="tr-hl" title="${esc(x.be)}">${esc(x.be)}</th>${hs.map((h) => cell(x.r.get(h) || 0).replace('<td class="tr-hc"', `<td data-tip="${trTip([`${x.be}`, `${trTime(h * 3600000, true)}:00`, `${fmtInt(x.r.get(h) || 0)} requests`])}" class="tr-hc"`)).join('')}</tr>`).join('')}</tbody></table></div>`;
}
function trEvents(d, sel) {
  const ev = d.events.filter((e) => e[0] >= sel.from && e[0] < sel.to);
  const noise = d.noise; const msgs = noise.msgs.slice(0, 4); const clients = noise.clients.slice(0, 4);
  const noiseTotal = sumArr(noise.n);
  const list = ev.slice(0, 8).map((e) => `<div class="tr-ev ${e[1]}"><i></i><span class="nw mono small">${esc(trTimeS(e[0]))}</span><span>${esc(e[2])}</span></div>`).join('');
  const conn = noiseTotal ? `<div class="tr-conn"><b>${fmtInt(noiseTotal)}</b> connection errors${msgs.length ? `: ${msgs.map((m) => `${esc(m[0])} (${fmtInt(m[1])})`).join(', ')}` : ''}${clients.length ? `<div class="muted small">most from ${clients.map((c) => `<span class="mono">${esc(c[0])}</span> (${fmtInt(c[1])})`).join(', ')}</div>` : ''}</div>` : '';
  return `${list || `<div class="tr-empty">✓ No ${d.product === 'nginx' ? 'error-log events' : 'server up/down events'} in this period</div>`}${d.eventCount > 8 ? `<div class="muted small">${fmtInt(d.eventCount - Math.min(8, ev.length))} more in the log</div>` : ''}${conn}`;
}

// ------------------------------------------------------------------------------------------------ interaction
async function trUpload(list) {
  const files = []; const problems = [];
  for (const f of list) { const bad = logFileProblem(f); if (bad) problems.push(bad); else files.push(f); }
  TR.upErr = problems.length ? problems.join(' · ') : null;
  if (!files.length) { renderTraffic(); return; }
  TR.up = { pct: 0, text: `Uploading ${files.length > 1 ? `${files.length} files` : fmtBytes(files[0].size)}…`, done: false }; renderTraffic();
  const r = await uploadLogs(state.current, files, (tag, f, l, t, done) => {
    TR.up = { pct: Math.round((l / t) * 100), done, text: done ? `${tag}${f.name} uploaded. Processing…` : `${tag}${f.name}: uploading ${fmtBytes(l)} of ${fmtBytes(t)}` };
    const p = $('#tr-prog'); if (p) logProgressUi(p, l, t, done, `${tag}${f.name}: `);
  }, false);
  TR.up = null;
  const errs = [...problems, ...r.failed.map((x) => `${x.name}: ${x.error}`)]; TR.upErr = errs.length ? errs.join(' · ') : null;
  TR.mix = r.failed.length && r.failed.every((x) => /files already uploaded are/.test(x.error)) ? files : null; // an HAProxy log next to NGINX ones (or the reverse): offer to start over
  if (r.done.length) { trResetFilters(); logSummaryToast(r); await trLoad(true); } else renderTraffic();
}
document.addEventListener('click', async (e) => {
  if (e.target.closest('[data-tr-replace]') && TR.mix) { const files = TR.mix; TR.mix = null; TR.upErr = null; TR.up = { pct: 0, text: 'Replacing the existing logs…', done: false }; renderTraffic(); const r = await uploadLogs(state.current, files, (tag, f, l, tt, done) => { TR.up = { pct: Math.round((l / tt) * 100), done, text: done ? `${tag}${f.name} uploaded. Processing…` : `${tag}${f.name}: uploading ${fmtBytes(l)} of ${fmtBytes(tt)}` }; const p = $('#tr-prog'); if (p) logProgressUi(p, l, tt, done, `${tag}${f.name}: `); }, true); TR.up = null; TR.upErr = r.failed.length ? r.failed.map((x) => `${x.name}: ${x.error}`).join(' · ') : null; if (r.done.length) { trResetFilters(); logSummaryToast(r); await trLoad(true); } else renderTraffic(); return; }
  if (e.target.closest('[data-tr-upload]')) { const f = $('#tr-file'); if (f) f.click(); else { const i = document.createElement('input'); i.type = 'file'; i.accept = '.log,.txt,.gz,.out'; i.multiple = true; i.onchange = () => i.files.length && trUpload([...i.files]); i.click(); } return; }
  const rm = e.target.closest('[data-tr-rmpart]');
  if (rm) {
    try { await api(`/instances/${encodeURIComponent(state.current)}/logs?part=${encodeURIComponent(rm.dataset.trRmpart)}`, { method: 'DELETE' }); await trLoad(true).catch(() => {}); } catch (err) { toast(err.message, 'err', 6000); }
    if (TR.data && TR.data.source && !(TR.data.source.files || []).length) { TR.data = null; TR.none = true; }
    return;
  }
  if (e.target.closest('[data-tr-reset]')) { trResetFilters(); renderTraffic(); return; }
  if (e.target.closest('[data-tr-delete]')) {
    const ok = await confirmDialog({ title: 'Delete all the traffic statistics?', message: 'The statistics of every uploaded file of this instance are removed from the server. The instance itself stays. You can upload a log again at any time.', confirmText: 'Delete', danger: true });
    if (!ok) return;
    try { await api(`/instances/${encodeURIComponent(state.current)}/logs`, { method: 'DELETE' }); TR.data = null; TR.none = true; trResetFilters(); renderTraffic(); toast('Traffic statistics deleted', 'ok'); } catch (err) { toast(err.message, 'err', 6000); }
    return;
  }
  const cp = e.target.closest('[data-copy]');
  if (cp) { try { await navigator.clipboard.writeText(cp.dataset.copy); const t = cp.textContent; cp.textContent = '✓'; setTimeout(() => { cp.textContent = t; }, 1200); } catch { toast('Copy is not available in this browser', 'err'); } }
});
document.addEventListener('change', (e) => {
  if (e.target.id === 'tr-file') { const f = [...e.target.files]; e.target.value = ''; if (f.length) trUpload(f); return; }
  const k = e.target.dataset && e.target.dataset.trf; if (!k) return;
  const v = e.target.value; const f = TR.f;
  if (k === 'range') { f.range = v; f.from = f.to = null; } else f[k] = v;
  if (k === 'be' || k === 'fe') { f.srv = ''; }
  renderTraffic();
});
// drag on a time chart to zoom into that period; double-click to go back
(function brush() {
  let drag = null;
  document.addEventListener('mousedown', (e) => {
    const svg = e.target.closest && e.target.closest('.tr-brushable svg'); if (!svg || e.button !== 0) return;
    const r = svg.getBoundingClientRect(); drag = { svg, r, x0: e.clientX - r.left, rect: svg.querySelector('.tr-brush') };
    drag.rect.hidden = false; drag.rect.setAttribute('x', drag.x0); drag.rect.setAttribute('width', 0); e.preventDefault();
  });
  document.addEventListener('mousemove', (e) => {
    if (!drag) return; const x = Math.max(+drag.svg.dataset.l, Math.min(+drag.svg.dataset.r, e.clientX - drag.r.left));
    drag.x1 = x; drag.rect.setAttribute('x', Math.min(drag.x0, x)); drag.rect.setAttribute('width', Math.abs(x - drag.x0));
  });
  document.addEventListener('mouseup', () => {
    if (!drag) return; const d = drag; drag = null; d.rect.hidden = true;
    if (d.x1 == null || Math.abs(d.x1 - d.x0) < 8) return;
    const L = +d.svg.dataset.l; const Rr = +d.svg.dataset.r; const n = +d.svg.dataset.n; const step = +d.svg.dataset.step; const t0 = +d.svg.dataset.t0;
    const toT = (x) => t0 + ((x - L) / (Rr - L)) * n * step;
    const a = toT(Math.min(d.x0, d.x1)); const b = toT(Math.max(d.x0, d.x1));
    TR.f.range = 'custom'; TR.f.from = Math.floor(a / 60000) * 60000; TR.f.to = Math.max(TR.f.from + 60000, Math.ceil(b / 60000) * 60000); renderTraffic();
  });
  document.addEventListener('dblclick', (e) => { if (e.target.closest && e.target.closest('.tr-brushable svg') && TR.f.range === 'custom') { TR.f.range = 'all'; TR.f.from = TR.f.to = null; renderTraffic(); } });
})();
let trResizeT = null;
window.addEventListener('resize', () => { clearTimeout(trResizeT); trResizeT = setTimeout(() => { if (state.view === 'traffic' && TR.data) trPaintAll(); }, 120); });

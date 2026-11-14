'use strict';
/* GateLight UI: offline analysis, command palette, landing / live / review modes. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
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
    const L = labelsOf(res.type);
    state.analysis = true;
    state.analysisCfg = { type: res.type, files: payload.files || [{ name: DEFAULT_FILE[res.type] || 'config', content: payload.config || '' }] };
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

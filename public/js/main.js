'use strict';
/* GateLight UI: event wiring and start-up (loads after the other js/ files; start-up waits for DOMContentLoaded). Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
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
  $('#cfg-history').addEventListener('click', chOpen);
  $('#ch-close').addEventListener('click', chClose);
  $('#cfghist').addEventListener('mousedown', (e) => { if (e.target.id === 'cfghist') chClose(); });
  $('#ch-versions').addEventListener('click', (e) => { const b = e.target.closest('[data-ch-v]'); if (!b) return; CH.sel = Number(b.dataset.chV); CH.from = null; chList(); chLoad(); });
  $('#ch-from').addEventListener('change', (e) => { CH.from = e.target.value ? Number(e.target.value) : null; chLoad(); });
  $('#ch-copy').addEventListener('click', async () => { if (!CH.diff) return; try { await navigator.clipboard.writeText(chDiffText(CH.diff)); toast('Diff copied', 'ok'); } catch { toast('Copy is not available in this browser', 'err'); } });
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
  ['#cx-url', '#cx-socket', '#cx-plus', '#cx-balancer', '#cx-metrics-caddy', '#cx-metrics-traefik', '#cx-cfgtext', '#cx-cfgurls'].forEach((q) => $(q).addEventListener('input', () => { if (q === '#cx-cfgtext' && $(q).value) cx.files = []; cxFilesNote(); cxSync(); }));
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
  state.urlmapOpen = loadPref('gatelight.urlmapOpen', false);
  state.urlmapMode = loadPref('gatelight.urlmapMode', 'normal'); state.urlmapH = loadPref('gatelight.urlmapH', 0);
  const reflow = () => setTimeout(() => { if (network) { network.setSize('100%', '100%'); network.redraw(); network.fit({ animation: false }); } }, 60);
  $('#topo-urlmap').addEventListener('click', () => {
    state.urlmapOpen = !state.urlmapOpen; savePref('gatelight.urlmapOpen', state.urlmapOpen);
    if (state.urlmapOpen && state.urlmapMode === 'min') state.urlmapMode = 'normal';
    if (!state.urlmapOpen) $('#view-topology').classList.remove('um-max');
    renderUrlMap(); reflow();
  });
  $('#urlmap').addEventListener('click', (e) => {
    if (e.target.closest('[data-um-fs]')) { e.stopPropagation(); toggleUrlmapFs(); return; }
    const b = e.target.closest('[data-um]'); if (!b) return;
    e.stopPropagation();
    if (b.dataset.um === 'close') { state.urlmapOpen = false; savePref('gatelight.urlmapOpen', false); $('#view-topology').classList.remove('um-max'); }
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
  $$('[data-az-ex]').forEach((b) => b.addEventListener('click', () => loadExample(b.dataset.azEx)));
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
    if (e.key === 'Escape') { if (!$('#chartview').hidden) cvClose(); else if (!$('#cfghist').hidden) chClose(); else if (!$('#cfgup').hidden) cuClose(); else if (!$('#connect').hidden) cxClose(); else if (pal.open) paletteClose(); else if (!$('#help').hidden) $('#help').hidden = true; else if (state.view === 'detail') detailBack(); else if (document.body.classList.contains('topo-fs')) setTopoFs(false); return; }
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
  if (ALL_TYPES.includes(ex)) { setMode('review'); await loadExample(ex); return; }
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

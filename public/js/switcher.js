'use strict';
/* GateLight UI: instance switcher (header dropdown). Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
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
    <div class="isel-foot"><button type="button" class="link" data-isel-add>${state.meta && state.meta.canManage ? '＋ Add Instance' : 'Review a config'}</button><button type="button" class="link" data-isel-all>Manage instances</button></div>`;
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

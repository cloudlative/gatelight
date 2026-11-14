'use strict';
/* GateLight UI: Running Config page and Config History. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
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
  const isNginx = s.instance.type === 'nginx' || s.instance.type === 'caddy';
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

// ---- Config History: versions GateLight has seen, and the diff between any two ----
const CH = { versions: [], sel: null, from: null, diff: null };
const chSource = { url: 'fetched from URL', file: 'read from file', uploaded: 'uploaded' };
async function chOpen() {
  if (!state.current || state.mode === 'review') return;
  $('#cfghist').hidden = false;
  $('#ch-versions').innerHTML = '<div class="empty">Loading…</div>'; $('#ch-diff').innerHTML = ''; $('#ch-note').textContent = '';
  try {
    const r = await api(`/instances/${encodeURIComponent(state.current)}/config/versions`);
    CH.versions = r.versions; CH.sel = r.versions[0] ? r.versions[0].id : null; CH.from = null;
    $('#ch-note').textContent = `Keeps the last ${r.keep} versions${r.persisted ? '' : ' (in memory only: history is lost on restart because HISTORY_DB is off)'}. Passwords and keys are masked.`;
    chList(); await chLoad();
  } catch (e) { $('#ch-versions').innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  $('#ch-close').focus();
}
function chClose() { $('#cfghist').hidden = true; }
function chList() {
  const v = CH.versions;
  $('#ch-versions').innerHTML = v.map((x, i) => `<button type="button" class="ch-v${x.id === CH.sel ? ' on' : ''}" data-ch-v="${x.id}" aria-pressed="${x.id === CH.sel}">
    <b>${i === 0 ? 'Current · ' : ''}${esc(fmtDateTime(x.ts))}</b>
    <span class="muted small">${esc(chSource[x.source] || x.source || '')} · ${x.files} file${x.files === 1 ? '' : 's'}, ${fmtInt(x.lines)} lines</span>
    <span class="small">${x.change ? `<span class="add">+${x.change.linesAdded}</span> <span class="del">−${x.change.linesRemoved}</span>${x.change.entitiesAdded || x.change.entitiesRemoved ? ` · <span class="muted">${x.change.entitiesAdded ? `${x.change.entitiesAdded} new` : ''}${x.change.entitiesAdded && x.change.entitiesRemoved ? ', ' : ''}${x.change.entitiesRemoved ? `${x.change.entitiesRemoved} gone` : ''}</span>` : ''}` : '<span class="muted">first version seen</span>'}</span>
  </button>`).join('') || '<div class="empty">No versions recorded yet.</div>';
  const idx = v.findIndex((x) => x.id === CH.sel);
  const older = v.slice(idx + 1);
  $('#ch-from').innerHTML = older.map((x, i) => `<option value="${x.id}">${i === 0 ? 'Previous version · ' : ''}${esc(fmtDateTime(x.ts))}</option>`).join('') || '<option value="">(no older version)</option>';
  $('#ch-from').disabled = !older.length;
  if (CH.from && older.some((x) => x.id === CH.from)) $('#ch-from').value = String(CH.from);
}
async function chLoad() {
  const box = $('#ch-diff');
  if (CH.sel == null) { box.innerHTML = ''; return; }
  const idx = CH.versions.findIndex((x) => x.id === CH.sel);
  if (!CH.versions[idx + 1]) { CH.diff = null; box.innerHTML = '<div class="panel"><div class="empty">This is the oldest version GateLight has. Later changes are compared against it.</div></div>'; return; }
  box.innerHTML = '<div class="empty">Comparing…</div>';
  try {
    const q = CH.from ? `?from=${encodeURIComponent(CH.from)}` : '';
    const d = await api(`/instances/${encodeURIComponent(state.current)}/config/versions/${CH.sel}/diff${q}`);
    CH.diff = d;
    const ents = [...d.entitiesAdded.map((k) => `<span class="tag add">+ ${esc(k)}</span>`), ...d.entitiesRemoved.map((k) => `<span class="tag del">− ${esc(k)}</span>`)].join('');
    const head = `<p class="muted small">${esc(fmtDateTime(d.from.ts))} → ${esc(fmtDateTime(d.to.ts))}: <b class="add">+${d.linesAdded}</b> <b class="del">−${d.linesRemoved}</b> lines in ${d.files.length} file${d.files.length === 1 ? '' : 's'}${d.unchanged ? `, ${d.unchanged} unchanged` : ''}</p>${ents ? `<div class="ch-ents">${ents}</div>` : ''}`;
    const files = d.files.map((f) => `<div class="ch-file"><h4>${esc(f.name)} <span class="tag">${esc(f.status)}</span><span class="muted small">+${f.added} −${f.removed}</span></h4>
      <div class="fg-udiff">${f.hunks.map((h) => `<div class="fg-hh">@@ -${h.oldStart} +${h.newStart} @@</div>${h.lines.map((r) => `<div class="fg-dr ${r.t === '+' ? 'add' : r.t === '-' ? 'del' : ''}"><i>${r.a == null ? '' : r.a}</i><i>${r.b == null ? '' : r.b}</i><b>${r.t === ' ' ? '' : r.t === '+' ? '+' : '−'}</b><code>${esc(r.text) || ' '}</code></div>`).join('')}`).join('')}</div></div>`).join('');
    box.innerHTML = head + (files ? `<div class="ch-files">${files}</div>` : '<div class="panel"><div class="empty">No differences between these two versions.</div></div>');
  } catch (e) { box.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}
function chDiffText(d) {
  return d.files.map((f) => [`--- a/${f.name}`, `+++ b/${f.name}`, ...f.hunks.flatMap((h) => [`@@ -${h.oldStart} +${h.newStart} @@`, ...h.lines.map((r) => `${r.t}${r.text}`)])].join('\n')).join('\n');
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

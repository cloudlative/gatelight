'use strict';
/* GateLight UI: Update Config and Connect a Server. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
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
  $('#cx-url-label').textContent = { nginx: 'Status URL (stub_status)', apache: 'server-status URL (mod_status)', caddy: 'Admin API URL', traefik: 'API URL' }[t] || 'Stats URL';
  $('#cx-url').placeholder = { nginx: 'http://host/nginx_status', apache: 'http://host/server-status', caddy: 'http://127.0.0.1:2019', traefik: 'http://host:8080' }[t] || 'http://host:8404/stats';
  const hasCfg = cx.files.length > 0 || $('#cx-cfgtext').value.trim() || $('#cx-cfgurls').value.trim() || cx.hadConfig || cx.logFiles.length;
  const live = $('#cx-url').value.trim() || ($('#cx-socket').value || '').trim() || ($('#cx-plus').value || '').trim() || (t === 'apache' && ($('#cx-balancer').value || '').trim());
  const configOnly = Boolean(hasCfg && !live);
  $('#cx-test').hidden = configOnly;
  $('#cx-url-opt').hidden = !hasCfg;
  const logOnly = configOnly && cx.logFiles.length && !(cx.files.length || $('#cx-cfgtext').value.trim() || $('#cx-cfgurls').value.trim() || cx.hadConfig);
  $('#cx-save').textContent = cx.editing ? (cx.logFiles.length ? `Save & upload ${cx.logFiles.length > 1 ? 'logs' : 'log'}` : 'Save changes') : logOnly ? 'Save & analyse logs' : configOnly ? 'Save config' : cx.inline ? 'Connect' : 'Save & connect';
  { const lp = $('#cx-logprod'); if (lp) lp.textContent = t === 'haproxy' ? 'HAProxy' : `${TYPE_NAME[t]} access`; const lh = $('#cx-loghelp'); if (lh && lh.dataset.prod !== t) { lh.dataset.prod = t; lh.innerHTML = logHelpHtml(t); } }
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
  else if (t === 'apache') b.balancerUrl = $('#cx-balancer').value;
  else if (t === 'caddy' || t === 'traefik') b.metricsUrl = $(`#cx-metrics-${t}`).value;
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
      $('#cx-insecure').checked = Boolean(d.insecureTls); $('#cx-socket').value = d.socket || ''; $('#cx-plus').value = d.plusApiUrl || ''; $('#cx-balancer').value = d.balancerUrl || ''; $('#cx-metrics-caddy').value = d.type === 'caddy' ? d.metricsUrl || '' : ''; $('#cx-metrics-traefik').value = d.type === 'traefik' ? d.metricsUrl || '' : '';
      $('#cx-probe').checked = d.probe !== false; $('#cx-cfgurls').value = (d.configUrls || []).join('\n');
      cx.hadPassword = d.hasPassword; cx.hadConfig = (d.configFiles || []).length > 0; cx.hadNames = (d.configFiles || []).slice(0, 3).join(', ') + ((d.configFiles || []).length > 3 ? '…' : '');
      $('#cx-pass').placeholder = d.hasPassword ? '•••••••• (unchanged)' : '';
      if (d.socket || d.plusApiUrl || d.balancerUrl || d.metricsUrl) $('#cx-form details.adv').open = true;
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

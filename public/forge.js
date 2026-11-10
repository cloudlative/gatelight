'use strict';
/**
 * Config Forge: paste or upload a HAProxy / NGINX configuration, get a scored assessment and a rewritten best-practice
 * version with every change explained and switchable. All the analysis happens on the server (src/improve); this file
 * is the page. Nothing is ever sent to a load balancer.
 */
const FG = { src: 'paste', text: '', files: [], product: '', version: '', data: null, loading: false, err: null, tab: 'changes', cat: 'all', kind: 'all', toggles: {}, file: 0, req: null, versions: null, timer: null, srcNote: '' };
const FG_CATS = { security: 'Security', reliability: 'Reliability', performance: 'Performance', observability: 'Observability', compatibility: 'Compatibility', hygiene: 'Hygiene' };
const FG_CAT_ICON = { security: '🛡', reliability: '⛑', performance: '⚡', observability: '🔍', compatibility: '♻', hygiene: '✦' };
const FG_SEV = { high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };
const FG_NGINX_V = ['1.31', '1.30', '1.28', '1.26', '1.24', '1.22', '1.20', '1.18', '1.16', '1.14'];

function forgeReset() { Object.assign(FG, { data: null, err: null, loading: false, toggles: {}, tab: 'changes', cat: 'all', kind: 'all', file: 0 }); }
/** Leaving the page or changing instance starts clean. */
function forgeClear() { forgeReset(); FG.text = ''; FG.files = []; FG.req = null; FG.srcNote = ''; }

// ------------------------------------------------------------------------------------------------ request
function forgeBody() {
  const b = { type: FG.product || undefined, version: FG.version || undefined, toggles: FG.toggles };
  if (FG.files.length) b.files = FG.files; else b.config = FG.text;
  return b;
}
async function forgeRun(opts = {}) {
  if (FG.loading && !opts.again) return;
  if (!opts.again && FG.req !== 'instance') { forgeReset(); }
  FG.loading = true; FG.err = null; renderForgeResults();
  try {
    if (!FG.versions) { try { FG.versions = await api('/validate/versions'); } catch { FG.versions = false; } }
    const url = FG.req === 'instance' && state.current && state.mode === 'live' ? `/instances/${encodeURIComponent(state.current)}/improve` : '/improve';
    const body = FG.req === 'instance' ? { version: FG.version || undefined, toggles: FG.toggles } : forgeBody();
    if (url === '/improve' && !body.config && !(body.files && body.files.length)) throw new Error('Paste or upload a configuration first.');
    FG.data = await api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!FG.product) FG.detected = FG.data.product; else FG.detected = null;
    if (FG.file >= FG.data.files.length) FG.file = 0;
  } catch (e) { FG.err = e.message; FG.data = null; }
  FG.loading = false; renderForge();
}
const forgeAgain = () => { clearTimeout(FG.timer); FG.timer = setTimeout(() => forgeRun({ again: true }), 220); };

// ------------------------------------------------------------------------------------------------ page
function renderForge() {
  const el = $('#view-forge'); if (!el) return;
  if (FG.inst !== state.current && state.mode === 'live') { FG.inst = state.current; if (FG.req === 'instance') { forgeClear(); FG.src = 'paste'; } }
  const live = state.mode === 'live' && state.snapshot && state.current;
  const tab = (id, label) => `<button type="button" class="fg-src${FG.src === id ? ' on' : ''}" data-fg-src="${id}">${label}</button>`;
  const prodTyped = FG.product || (FG.data && FG.data.product) || '';
  const verSel = prodTyped === 'haproxy' && FG.versions && FG.versions.haproxy
    ? `<select id="fg-version" aria-label="Target HAProxy version"><option value="">Latest (${esc(FG.versions.haproxy.latest)})</option>${FG.versions.haproxy.list.map((v) => `<option value="${esc(v)}"${FG.version === v ? ' selected' : ''}>HAProxy ${esc(v)}</option>`).join('')}</select>`
    : `<input id="fg-version" list="fg-nginx-v" placeholder="${prodTyped === 'haproxy' ? 'Version, e.g. 2.8' : 'Version, e.g. 1.24.0'} (empty = latest)" value="${esc(FG.version)}" aria-label="Target version" autocomplete="off"><datalist id="fg-nginx-v">${(prodTyped === 'haproxy' ? ['3.2', '3.0', '2.9', '2.8', '2.6', '2.4', '2.2', '1.8'] : FG_NGINX_V).map((v) => `<option value="${v}">`).join('')}</datalist>`;
  el.innerHTML = `<div class="panel fg-top"><div class="fg-title"><div><h2 class="fg-h2">Config Forge</h2><div class="muted">Assess a HAProxy or NGINX configuration and rewrite it to current best practice. Every change comes with the reason, can be switched off, and nothing touches your servers.</div></div></div>
    <div class="fg-srcs" role="tablist">${tab('paste', 'Paste')}${tab('upload', 'Upload files')}${live ? tab('instance', 'This instance') : ''}${tab('example', 'Examples')}</div>
    <div class="fg-input">${forgeInputHtml()}</div>
    <div class="fg-opts"><label>Product<select id="fg-product"><option value="">Auto-detect</option><option value="haproxy"${FG.product === 'haproxy' ? ' selected' : ''}>HAProxy</option><option value="nginx"${FG.product === 'nginx' ? ' selected' : ''}>NGINX</option></select></label>
      <label>Target version${verSel}</label><span class="spacer"></span>
      <button class="btn primary" type="button" data-fg-run${FG.loading ? ' disabled' : ''}>${FG.loading ? 'Working…' : (FG.data ? 'Analyze again' : 'Analyze & improve')}</button></div></div>
    <div id="forge-res"></div>`;
  renderForgeResults();
}
function forgeInputHtml() {
  if (FG.src === 'paste') return `<textarea id="fg-text" spellcheck="false" rows="11" placeholder="Paste haproxy.cfg or nginx.conf here. For NGINX with several files, use “Upload files”.">${esc(FG.text)}</textarea>`;
  if (FG.src === 'upload') return `<div class="fg-drop" id="fg-drop"><input type="file" id="fg-files" multiple hidden><input type="file" id="fg-dir" webkitdirectory hidden>
      <div><b>Drop configuration files here</b>, or <button type="button" class="link" data-fg-pick="files">choose files</button> · <button type="button" class="link" data-fg-pick="dir">choose a folder</button></div>
      <div class="muted small">HAProxy: one file (or a conf.d folder, read in name order). NGINX: nginx.conf plus the files it includes. Up to 2 MB in total.</div>
      ${FG.files.length ? `<div class="tr-chips">${FG.files.map((f, i) => `<span class="tr-chip">${esc(f.name)} <span class="muted">${esc(fmtBytes(f.content.length))}</span><button type="button" data-fg-rm="${i}" aria-label="Remove ${esc(f.name)}">×</button></span>`).join('')}</div>` : ''}</div>`;
  if (FG.src === 'instance') return `<div class="fg-inst"><p>Use the configuration GateLight holds for <b>${esc((state.snapshot && state.snapshot.instance.name) || state.current)}</b>. It is the redacted copy: passwords and secrets show as placeholders, so check them before you deploy the result.</p><button class="btn" type="button" data-fg-inst>Improve this instance's config</button></div>`;
  return `<div class="fg-inst"><p>Try it on a sample with typical mistakes.</p><button class="btn" type="button" data-fg-ex="haproxy">HAProxy example</button> <button class="btn" type="button" data-fg-ex="nginx">NGINX example</button></div>`;
}

// ------------------------------------------------------------------------------------------------ results
const fgRing = (v, grade) => { const r = 34; const c = 2 * Math.PI * r; const col = v >= 90 ? 'var(--green)' : v >= 70 ? 'var(--cyan)' : v >= 50 ? 'var(--amber)' : 'var(--red)'; return `<svg class="fg-ring" viewBox="0 0 84 84" width="84" height="84" role="img" aria-label="Score ${v} of 100"><circle cx="42" cy="42" r="${r}" fill="none" stroke="var(--bg-3)" stroke-width="8"/><circle cx="42" cy="42" r="${r}" fill="none" stroke="${col}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${(c * v / 100).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 42 42)"/><text x="42" y="44" text-anchor="middle" class="fg-rv">${v}</text><text x="42" y="60" text-anchor="middle" class="fg-rg">${esc(grade)}</text></svg>`; };
function renderForgeResults() {
  const el = $('#forge-res'); if (!el) return;
  const d = FG.data;
  if (FG.loading && !d) { el.innerHTML = '<div class="skeleton-cards"><i></i><i></i><i></i></div>'; return; }
  if (FG.err) { el.innerHTML = `<div class="panel"><div class="empty">${esc(FG.err)}</div></div>`; return; }
  if (!d) { el.innerHTML = ''; return; }
  const s = d.summary; const f = d.files[FG.file] || d.files[0];
  const cats = Object.entries(s.byCategory).filter(([, v]) => v.total);
  const head = `<div class="panel fg-score"><div class="fg-sc">${fgRing(d.score.after, d.score.gradeAfter)}<div><div class="fg-sct">After</div><div class="muted small">was <b>${d.score.before}</b> (${esc(d.score.gradeBefore)})</div></div></div>
      <div class="fg-stats"><div><b>${s.applied}</b><span>changes applied</span></div><div><b>${s.optional}</b><span>optional, off</span></div><div><b>${s.advice}</b><span>need your input</span></div><div><b>${d.files.reduce((a, x) => a + x.diff.added, 0)}</b><span>lines added</span></div></div>
      <div class="fg-cats">${cats.map(([k, v]) => `<div class="fg-cat" title="${esc(FG_CATS[k])}: ${v.applied} of ${v.total} applied"><span>${FG_CAT_ICON[k]} ${esc(FG_CATS[k])}</span><span class="fg-cbar"><i style="width:${v.total ? (v.applied / v.total) * 100 : 0}%"></i></span><b>${v.applied}/${v.total}</b></div>`).join('')}</div></div>`;
  const notes = [...d.notes, ...(FG.srcNote ? [FG.srcNote] : []), ...(d.files.some((x) => x.formatting) ? ['Indentation and spacing were normalised (4 spaces, one blank line between blocks); the diff ignores that and shows only real changes.'] : [])];
  const tabs = [['changes', `Changes (${s.auto})`], ['config', 'Improved config'], ['diff', `Diff (+${d.files.reduce((a, x) => a + x.diff.added, 0)} −${d.files.reduce((a, x) => a + x.diff.removed, 0)})`], ['advice', `Needs your input (${s.advice})`]];
  const fileSel = d.files.length > 1 ? `<select id="fg-file" aria-label="File">${d.files.map((x, i) => `<option value="${i}"${i === FG.file ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}</select>` : '';
  let body = '';
  if (FG.tab === 'changes') body = forgeChanges(d);
  else if (FG.tab === 'config') body = forgeConfig(d, f);
  else if (FG.tab === 'diff') body = forgeDiff(d, f);
  else body = forgeAdvice(d);
  el.innerHTML = `${head}${notes.length ? `<div class="fg-notes">${notes.map((n) => `<div>ⓘ ${esc(n)}</div>`).join('')}</div>` : ''}
    <div class="fg-tabs"><div class="chips">${tabs.map(([id, t]) => `<span class="chip ${FG.tab === id ? 'on' : ''}" data-fg-tab="${id}">${esc(t)}</span>`).join('')}</div>${FG.tab === 'config' || FG.tab === 'diff' ? fileSel : ''}${FG.loading ? '<span class="muted small">updating…</span>' : ''}</div>${body}`;
}
function forgeChanges(d) {
  const auto = d.changes.filter((c) => c.auto);
  const cats = [...new Set(auto.map((c) => c.category))];
  const kinds = [['all', 'All'], ['on', 'Applied'], ['off', 'Off / optional']];
  let list = auto.filter((c) => (FG.cat === 'all' || c.category === FG.cat) && (FG.kind === 'all' || (FG.kind === 'on' ? c.applied : !c.applied)));
  const ctl = `<div class="fg-ctl"><div class="chips"><span class="chip ${FG.cat === 'all' ? 'on' : ''}" data-fg-cat="all">All categories</span>${cats.map((c) => `<span class="chip ${FG.cat === c ? 'on' : ''}" data-fg-cat="${c}">${FG_CAT_ICON[c]} ${esc(FG_CATS[c])} (${auto.filter((x) => x.category === c).length})</span>`).join('')}</div>
      <div class="chips">${kinds.map(([k, t]) => `<span class="chip ${FG.kind === k ? 'on' : ''}" data-fg-kind="${k}">${t}</span>`).join('')}<span class="spacer"></span><button class="btn" type="button" data-fg-all="rec">Recommended only</button><button class="btn" type="button" data-fg-all="all">Apply everything</button><button class="btn" type="button" data-fg-all="none">Apply nothing</button></div></div>`;
  if (!list.length) return `${ctl}<div class="panel"><div class="empty">${auto.length ? 'Nothing matches this filter.' : '✓ Nothing to change automatically. This configuration already follows the recommendations that can be applied safely.'}</div></div>`;
  return `${ctl}<div class="fg-list">${list.map((c) => forgeCard(c)).join('')}</div>`;
}
function forgeCard(c) {
  const diff = c.diff.slice(0, 8).map((x) => (x.k === 'add' ? `<div class="fg-d add"><i>+</i><code>${esc(x.after)}</code></div>` : x.k === 'del' ? `<div class="fg-d del"><i>−</i><code>${esc(x.before)}</code></div>` : `<div class="fg-d del"><i>−</i><code>${esc(x.before)}</code></div><div class="fg-d add"><i>+</i><code>${esc(x.after)}</code></div>`)).join('');
  return `<article class="fg-card${c.applied ? '' : ' off'}"><label class="fg-sw" title="${c.applied ? 'Applied: click to leave it out' : 'Not applied: click to include it'}"><input type="checkbox" data-fg-t="${esc(c.key)}"${c.applied ? ' checked' : ''}><span></span></label>
    <div class="fg-cb"><div class="fg-ct"><b>${esc(c.title)}</b> <span class="fg-sev sev-${c.severity}">${esc(FG_SEV[c.severity])}</span> <span class="tag">${FG_CAT_ICON[c.category]} ${esc(FG_CATS[c.category])}</span>${c.on ? '' : ' <span class="tag">optional</span>'}</div>
      <div class="muted small">${esc(c.section)}${c.line ? ` · line ${c.line}` : ''}</div><p class="fg-why">${esc(c.why)}</p><div class="fg-diff">${diff}${c.diff.length > 8 ? `<div class="muted small">+ ${c.diff.length - 8} more lines</div>` : ''}</div></div></article>`;
}
function forgeAdvice(d) {
  const list = d.changes.filter((c) => !c.auto);
  if (!list.length) return '<div class="panel"><div class="empty">✓ Nothing needs a decision from you.</div></div>';
  return `<p class="muted">These need information only you have (a certificate, a password, an application URL), so they are not changed automatically.</p><div class="fg-list">${list.map((c) => `<article class="fg-card adv"><div class="fg-cb"><div class="fg-ct"><b>${esc(c.title)}</b> <span class="fg-sev sev-${c.severity}">${esc(FG_SEV[c.severity])}</span> <span class="tag">${FG_CAT_ICON[c.category]} ${esc(FG_CATS[c.category])}</span></div><div class="muted small">${esc(c.section)}${c.line ? ` · line ${c.line}` : ''}</div><p class="fg-why">${esc(c.why)}</p></div></article>`).join('')}</div>`;
}
function forgeConfig(d, f) {
  const added = new Set(); f.diff.hunks.forEach((h) => h.rows.forEach((r) => { if (r.t === '+') added.add(r.b); }));
  const lines = f.improved.replace(/\n$/, '').split('\n');
  const check = d.product === 'haproxy' ? 'haproxy -c -f ' : 'nginx -t -c ';
  const reload = d.product === 'haproxy' ? 'systemctl reload haproxy' : 'nginx -s reload';
  const first = d.files[0].name.split('/').pop();
  return `<div class="fg-bar"><b>${esc(f.name)}</b> <span class="muted small">${lines.length} lines · ${added.size} added or changed</span><span class="spacer"></span>
      <button class="btn" type="button" data-fg-copy>Copy</button><button class="btn primary" type="button" data-fg-dl>Download${d.files.length > 1 ? ' this file' : ''}</button>${d.files.length > 1 ? '<button class="btn" type="button" data-fg-dlall>Download all</button>' : ''}</div>
    <pre class="fg-code" tabindex="0">${lines.map((l, i) => `<span class="fg-ln${added.has(i + 1) ? ' add' : ''}"><i>${i + 1}</i>${esc(l) || ' '}</span>`).join('')}</pre>
    <div class="fg-deploy"><b>Before you deploy</b><div>Test it, then reload without dropping connections:</div>
      <div class="tr-cmds"><div><span class="tr-cmd"><code>${esc(`${check}${first}`)}</code><button type="button" class="btn icon" data-copy="${esc(`${check}${first}`)}" title="Copy" aria-label="Copy command">⧉</button></span></div><div><span class="tr-cmd"><code>${esc(reload)}</code><button type="button" class="btn icon" data-copy="${esc(reload)}" title="Copy" aria-label="Copy command">⧉</button></span></div></div>
      <div class="muted small">Keep the original, roll out to one node first, and watch the error rate. Green lines above are what this tool added or changed.</div></div>`;
}
function forgeDiff(d, f) {
  if (!f.diff.hunks.length) return '<div class="panel"><div class="empty">No differences: this file needs no changes.</div></div>';
  return `<div class="fg-bar"><b>${esc(f.name)}</b> <span class="muted small">+${f.diff.added} −${f.diff.removed}</span><span class="spacer"></span><button class="btn" type="button" data-fg-copydiff>Copy diff</button></div>
    <div class="fg-udiff">${f.diff.hunks.map((h) => { const a0 = (h.rows.find((r) => r.a != null) || {}).a || 1; const b0 = (h.rows.find((r) => r.b != null) || {}).b || 1; return `<div class="fg-hh">@@ -${a0} +${b0} @@</div>${h.rows.map((r) => `<div class="fg-dr ${r.t === '+' ? 'add' : r.t === '-' ? 'del' : ''}"><i>${r.a == null ? '' : r.a}</i><i>${r.b == null ? '' : r.b}</i><b>${r.t === ' ' ? '' : r.t === '+' ? '+' : '−'}</b><code>${esc(r.text) || ' '}</code></div>`).join('')}`; }).join('')}</div>`;
}

// ------------------------------------------------------------------------------------------------ interaction
const fgText = () => { const f = FG.data && FG.data.files[FG.file]; return f ? f.improved : ''; };
async function fgReadFiles(list) {
  const out = []; let total = FG.files.reduce((a, f) => a + f.content.length, 0);
  for (const f of list) {
    if (/\.(png|jpe?g|gif|pdf|zip|gz|tar|exe|bin|pem|key|crt|so|db)$/i.test(f.name) || f.size > 2 * 1048576) continue;
    const name = (f.webkitRelativePath || f.name).split('/').slice(1).join('/') || f.name; const content = await f.text();
    if (content.includes('\u0000')) continue; total += content.length; if (total > 2 * 1048576) break;
    out.push({ name: f.webkitRelativePath ? (f.webkitRelativePath.includes('/') ? f.webkitRelativePath.split('/').slice(1).join('/') || name : name) : name, content });
  }
  FG.files = [...FG.files, ...out.filter((x) => !FG.files.some((y) => y.name === x.name))].slice(0, 300); FG.req = 'files'; renderForge();
}
document.addEventListener('click', async (e) => {
  const t = e.target; if (!t.closest || !t.closest('#view-forge')) return;
  const src = t.closest('[data-fg-src]'); if (src) { FG.src = src.dataset.fgSrc; renderForge(); return; }
  if (t.closest('[data-fg-run]')) { const p = $('#fg-product'); FG.product = p ? p.value : ''; const v = $('#fg-version'); FG.version = v ? v.value.trim() : ''; const tx = $('#fg-text'); if (tx) FG.text = tx.value; FG.req = FG.src === 'instance' ? 'instance' : FG.files.length && FG.src === 'upload' ? 'files' : 'paste'; if (FG.src === 'paste') FG.files = []; forgeRun(); return; }
  const pick = t.closest('[data-fg-pick]'); if (pick) { const i = $(pick.dataset.fgPick === 'dir' ? '#fg-dir' : '#fg-files'); if (i) i.click(); return; }
  const rm = t.closest('[data-fg-rm]'); if (rm) { FG.files.splice(+rm.dataset.fgRm, 1); renderForge(); return; }
  if (t.closest('[data-fg-inst]')) { FG.req = 'instance'; FG.src = 'instance'; FG.srcNote = 'This is the redacted copy of the configuration that GateLight holds. Secrets appear as placeholders: restore them before you deploy.'; forgeReset(); forgeRun(); return; }
  const ex = t.closest('[data-fg-ex]');
  if (ex) { try { const r = await api(`/examples/${ex.dataset.fgEx}`); FG.src = 'upload'; FG.files = r.files.map((f) => ({ name: f.name, content: f.content })); FG.text = ''; FG.product = ex.dataset.fgEx; FG.req = 'files'; FG.srcNote = ''; forgeReset(); forgeRun(); } catch (err) { toast(err.message, 'err'); } return; }
  const tb = t.closest('[data-fg-tab]'); if (tb) { FG.tab = tb.dataset.fgTab; renderForgeResults(); return; }
  const ct = t.closest('[data-fg-cat]'); if (ct) { FG.cat = ct.dataset.fgCat; renderForgeResults(); return; }
  const kd = t.closest('[data-fg-kind]'); if (kd) { FG.kind = kd.dataset.fgKind; renderForgeResults(); return; }
  const all = t.closest('[data-fg-all]');
  if (all && FG.data) { const m = all.dataset.fgAll; FG.toggles = {}; FG.data.changes.filter((c) => c.auto).forEach((c) => { FG.toggles[c.key] = m === 'all' ? true : m === 'none' ? false : c.on; }); forgeAgain(); return; }
  if (t.closest('[data-fg-copy]')) { try { await navigator.clipboard.writeText(fgText()); toast('Copied the improved configuration', 'ok'); } catch { toast('Copy is not available in this browser', 'err'); } return; }
  if (t.closest('[data-fg-dl]') && FG.data) { const f = FG.data.files[FG.file]; download(f.name.split('/').pop(), f.improved); return; }
  if (t.closest('[data-fg-dlall]') && FG.data) { FG.data.files.forEach((f, i) => setTimeout(() => download(f.name.split('/').pop(), f.improved), i * 250)); return; }
  if (t.closest('[data-fg-copydiff]') && FG.data) { const f = FG.data.files[FG.file]; const txt = f.diff.hunks.map((h) => h.rows.map((r) => `${r.t === ' ' ? ' ' : r.t}${r.text}`).join('\n')).join('\n@@\n'); try { await navigator.clipboard.writeText(txt); toast('Diff copied', 'ok'); } catch { toast('Copy is not available in this browser', 'err'); } }
});
document.addEventListener('change', (e) => {
  const t = e.target; if (!t.closest || !t.closest('#view-forge')) return;
  if (t.matches('[data-fg-t]') && FG.data) { FG.toggles = { ...FG.toggles, [t.dataset.fgT]: t.checked }; const c = FG.data.changes.find((x) => x.key === t.dataset.fgT); if (c) c.applied = t.checked; forgeAgain(); return; }
  if (t.id === 'fg-file') { FG.file = +t.value; renderForgeResults(); return; }
  if (t.id === 'fg-files' || t.id === 'fg-dir') { fgReadFiles([...t.files]); t.value = ''; return; }
  if (t.id === 'fg-product') { FG.product = t.value; FG.version = ''; renderForge(); return; }
  if (t.id === 'fg-version') FG.version = t.value.trim();
});
document.addEventListener('input', (e) => { if (e.target.id === 'fg-text') { FG.text = e.target.value; FG.req = 'paste'; FG.files = []; } });
document.addEventListener('dragover', (e) => { if (e.target.closest && e.target.closest('#fg-drop')) { e.preventDefault(); e.target.closest('#fg-drop').classList.add('over'); } });
document.addEventListener('dragleave', (e) => { const d = e.target.closest && e.target.closest('#fg-drop'); if (d) d.classList.remove('over'); });
document.addEventListener('drop', (e) => { const d = e.target.closest && e.target.closest('#fg-drop'); if (!d) return; e.preventDefault(); d.classList.remove('over'); fgReadFiles([...e.dataTransfer.files]); });

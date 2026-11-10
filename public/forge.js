'use strict';
/**
 * Config Forge: paste or upload a HAProxy / NGINX configuration, get a scored assessment and a rewritten best-practice
 * version with every change explained and switchable. All the analysis happens on the server (src/improve); this file
 * is the page. Nothing is ever sent to a load balancer.
 */
const FG = { src: 'paste', text: '', files: [], product: '', version: '', build: '', buildOpen: false, data: null, loading: false, err: null, tab: 'findings', cat: 'all', sev: 'all', kind: 'all', toggles: {}, auto: false, file: 0, req: null, versions: null, timer: null, srcNote: '' };
const FG_CATS = { security: 'Security', reliability: 'Reliability', correctness: 'Correctness', performance: 'Performance', observability: 'Observability', compatibility: 'Compatibility', hygiene: 'Hygiene', drift: 'Drift' };
const FG_CAT_ICON = { security: '🛡', reliability: '⛑', correctness: '✔', performance: '⚡', observability: '🔍', compatibility: '♻', hygiene: '✦', drift: '⇄' };
const FG_SRC = { audit: 'Audit', validate: 'Validate' };
const FG_SEV = { high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };
const FG_NGINX_V = ['1.31', '1.30', '1.28', '1.26', '1.24', '1.22', '1.20', '1.18', '1.16', '1.14'];

function forgeReset() { Object.assign(FG, { data: null, err: null, loading: false, toggles: {}, tab: 'findings', cat: 'all', sev: 'all', kind: 'all', file: 0 }); }
/** Leaving the page or changing instance starts clean. */
function forgeClear() { forgeReset(); FG.text = ''; FG.files = []; FG.req = null; FG.srcNote = ''; }

// ------------------------------------------------------------------------------------------------ request
function forgeBody() {
  const b = { type: FG.product || undefined, version: FG.version || undefined, build: FG.build || undefined, toggles: FG.toggles };
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
    const body = FG.req === 'instance' ? { version: FG.version || undefined, build: FG.build || undefined, toggles: FG.toggles } : forgeBody();
    if (url === '/improve' && !body.config && !(body.files && body.files.length)) throw new Error('Paste or upload a configuration first.');
    FG.data = await api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (FG.data.versionDetected && !FG.version) FG.version = FG.data.target; // show what was detected; the user can change it
    if (!FG.product) FG.detected = FG.data.product; else FG.detected = null;
    if (FG.file >= FG.data.files.length) FG.file = 0;
  } catch (e) { FG.err = e.message; FG.data = null; }
  FG.loading = false; renderForge();
}
const forgeAgain = () => { clearTimeout(FG.timer); FG.timer = setTimeout(() => forgeRun({ again: true }), 220); };

// ------------------------------------------------------------------------------------------------ page
function renderForge() {
  const el = $('#view-forge'); if (!el) return;
  if (FG.inst !== state.current) { FG.inst = state.current; forgeClear(); FG.src = 'paste'; FG.auto = false; }
  if (!FG.auto && !FG.data && !FG.loading && !FG.err) { // an instance or a reviewed config is already loaded: assess it straight away
    if (state.mode === 'review' && state.analysisCfg && state.analysisCfg.files && state.analysisCfg.files.length) { FG.auto = true; FG.src = 'upload'; FG.files = state.analysisCfg.files.map((f) => ({ name: f.name, content: f.content != null ? f.content : f.raw })).filter((f) => typeof f.content === 'string'); FG.product = state.analysisCfg.type || ''; FG.req = 'files'; if (FG.files.length) setTimeout(() => forgeRun(), 0); }
    else if (state.mode === 'live' && state.snapshot && state.current) { FG.auto = true; FG.src = 'instance'; FG.req = 'instance'; FG.srcNote = 'This is the redacted copy of the configuration that GateLight holds. Secrets appear as placeholders: restore them before you deploy.'; setTimeout(() => forgeRun(), 0); }
  }
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
      ${prodTyped === 'nginx' ? `<button class="link" type="button" data-fg-build>${FG.buildOpen ? 'Hide' : 'Add'} build info</button>` : ''}
      <button class="btn primary" type="button" data-fg-run${FG.loading ? ' disabled' : ''}>${FG.loading ? 'Working…' : (FG.data ? 'Analyze again' : 'Analyze & improve')}</button></div></div>
    ${prodTyped === 'nginx' && FG.buildOpen ? `<textarea id="fg-build" rows="3" spellcheck="false" placeholder="Paste the output of  nginx -V  to also check which modules your build contains">${esc(FG.build)}</textarea>` : ''}
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
  const open = d.findings.filter((x) => x.kind !== 'optional');
  const cats = Object.entries(open.reduce((m, x) => { const c = m[x.category] || (m[x.category] = { total: 0, fixed: 0 }); c.total++; if (x.applied) c.fixed++; return m; }, {}));
  const added = d.files.reduce((a, x) => a + x.diff.added, 0); const removed = d.files.reduce((a, x) => a + x.diff.removed, 0);
  const head = `<div class="panel fg-score"><div class="fg-sc">${fgRing(d.score.after, d.score.gradeAfter)}<div><div class="fg-sct">After the rewrite</div><div class="muted small">now <b>${d.score.before}</b> (${esc(d.score.gradeBefore)})</div></div></div>
      <div class="fg-stats"><div><b>${open.length}</b><span>findings</span></div><div><b>${s.applied}</b><span>fixed by the rewrite</span></div><div><b>${s.advice + s.problems}</b><span>need your decision</span></div><div><b>${s.optional}</b><span>optional extras</span></div></div>
      <div class="fg-cats">${cats.map(([k, v]) => `<div class="fg-cat" title="${esc(FG_CATS[k] || k)}: ${v.fixed} of ${v.total} fixed by the rewrite"><span>${FG_CAT_ICON[k] || '•'} ${esc(FG_CATS[k] || k)}</span><span class="fg-cbar"><i style="width:${v.total ? (v.fixed / v.total) * 100 : 0}%"></i></span><b>${v.fixed}/${v.total}</b></div>`).join('')}</div></div>`;
  const notes = [...d.notes, ...(FG.srcNote ? [FG.srcNote] : []), ...(d.files.some((x) => x.formatting) ? ['Indentation and spacing were normalised (4 spaces, one blank line between blocks); the diff ignores that and shows only real changes.'] : [])];
  const tabs = [['findings', `Findings (${open.length + s.optional})`], ['config', 'Improved config'], ['diff', `Diff (+${added} −${removed})`]];
  const fileSel = d.files.length > 1 ? `<select id="fg-file" aria-label="File">${d.files.map((x, i) => `<option value="${i}"${i === FG.file ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}</select>` : '';
  const body = FG.tab === 'findings' ? forgeFindings(d) : FG.tab === 'config' ? forgeConfig(d, f) : forgeDiff(d, f);
  el.innerHTML = `${head}${notes.length ? `<div class="fg-notes">${notes.map((n) => `<div>ⓘ ${esc(n)}</div>`).join('')}</div>` : ''}
    <div class="fg-tabs"><div class="chips">${tabs.map(([id, t]) => `<span class="chip ${FG.tab === id ? 'on' : ''}" data-fg-tab="${id}">${esc(t)}</span>`).join('')}</div>${FG.tab !== 'findings' ? fileSel : ''}${FG.loading ? '<span class="muted small">updating…</span>' : ''}</div>${body}`;
}
const FG_KINDS = [['all', 'All'], ['auto', 'Fixed by rewrite'], ['input', 'Need your decision'], ['optional', 'Optional extras']];
const fgKind = (x) => (x.kind === 'problem' ? 'input' : x.kind);
function forgeFindings(d) {
  const all = d.findings;
  const cats = [...new Set(all.map((c) => c.category))]; const sevs = ['high', 'medium', 'low', 'info'];
  const list = all.filter((c) => (FG.cat === 'all' || c.category === FG.cat) && (FG.sev === 'all' || c.severity === FG.sev) && (FG.kind === 'all' || fgKind(c) === FG.kind));
  const cnt = (fn) => all.filter(fn).length;
  const ctl = `<div class="fg-ctl"><div class="chips">${FG_KINDS.map(([k, t]) => `<span class="chip ${FG.kind === k ? 'on' : ''}" data-fg-kind="${k}">${t} (${k === 'all' ? all.length : cnt((c) => fgKind(c) === k)})</span>`).join('')}<span class="spacer"></span><button class="btn" type="button" data-fg-all="rec">Recommended only</button><button class="btn" type="button" data-fg-all="all">Apply everything</button><button class="btn" type="button" data-fg-all="none">Apply nothing</button><button class="btn" type="button" data-fg-export>Export JSON</button></div>
      <div class="chips"><span class="chip ${FG.sev === 'all' ? 'on' : ''}" data-fg-sev="all">Any severity</span>${sevs.map((v) => `<span class="chip ${FG.sev === v ? 'on' : ''}" data-fg-sev="${v}">${FG_SEV[v]} (${cnt((c) => c.severity === v)})</span>`).join('')}<span class="muted">|</span><span class="chip ${FG.cat === 'all' ? 'on' : ''}" data-fg-cat="all">All categories</span>${cats.map((c) => `<span class="chip ${FG.cat === c ? 'on' : ''}" data-fg-cat="${c}">${FG_CAT_ICON[c] || ''} ${esc(FG_CATS[c] || c)} (${cnt((x) => x.category === c)})</span>`).join('')}</div></div>`;
  const SEV_COL = { high: '#f87171', medium: '#fbbf24', low: '#22d3ee', info: '#94a3b8' };
  const count = (key) => { const m = new Map(); for (const f of list) m.set(f[key], (m.get(f[key]) || 0) + 1); return [...m].sort((a, b) => b[1] - a[1]); };
  const prodName = d.product === 'haproxy' ? 'HAProxy' : 'NGINX';
  const bad = all.filter((c) => c.kind !== 'optional' && c.severity === 'high').length;
  const verdict = `<div class="panel val-sum"><div class="val-verdict">${bad ? `<span class="val-no">✗ ${bad} high-severity problem${bad === 1 ? '' : 's'} for ${esc(prodName)} ${esc(d.target)}</span>` : `<span class="val-ok">✓ Nothing high-severity for ${esc(prodName)} ${esc(d.target)}</span>`}</div>
      <p class="muted small">Checked against the official ${d.product === 'haproxy' ? 'manual at docs.haproxy.org' : 'documentation at nginx.org'} for the target version, plus the structural audit and the rewrite rules. Each problem is listed once; the other checks that also reported it are shown on it.</p></div>`;
  const chartRow = list.length ? `<div class="svc-charts-grid">${donutCard('Findings by severity', sevs.map((v) => ({ label: FG_SEV[v], color: SEV_COL[v], value: list.filter((c) => c.severity === v).length })), { big: String(list.length), sub: 'findings' }, 'How serious the findings are.')}${barChart('By category', count('category').slice(0, 8).map(([k, v]) => ({ label: FG_CATS[k] || k, value: v, color: '#818cf8' })), { sub: 'findings' })}${barChart('Most affected sections', count('section').slice(0, 8).map(([k, v]) => ({ label: k || '(global)', value: v, color: '#22d3ee' })), { sub: 'frontends, backends, upstreams' })}${barChart('Most frequent rules', count('rule').slice(0, 8).map(([k, v]) => ({ label: (list.find((x) => x.rule === k) || {}).title || k, value: v, color: '#fbbf24' })), { sub: 'rule · occurrences' })}</div>` : '';
  if (!list.length) return `${verdict}${ctl}<div class="panel"><div class="empty">${all.length ? 'Nothing matches this filter.' : '✓ No findings. This configuration already follows the recommendations.'}</div></div>`;
  // many occurrences of one rule fold into a group so a single noisy rule does not bury the rest
  const groups = new Map(); list.forEach((c) => { const g = groups.get(c.rule) || groups.set(c.rule, []).get(c.rule); g.push(c); });
  const out = [];
  for (const [rule, items] of groups) {
    if (items.length >= 4 && items.every((x) => x.kind === items[0].kind)) {
      const x = items[0]; const on = items.every((i) => i.applied);
      out.push(`<details class="fg-grp"><summary><b>${esc(x.title)}</b> <span class="fg-sev sev-${x.severity}">${esc(FG_SEV[x.severity])}</span> <span class="tag">${FG_CAT_ICON[x.category] || ''} ${esc(FG_CATS[x.category] || x.category)}</span> <span class="tag">${items.length} places</span>${items[0].auto ? `<label class="fg-all-sw" title="Apply to all"><input type="checkbox" data-fg-grp="${esc(rule)}"${on ? ' checked' : ''}> all</label>` : ''}</summary><p class="fg-why">${esc(x.why)}</p><div class="fg-list">${items.map(forgeCard).join('')}</div></details>`);
    } else items.forEach((c) => out.push(forgeCard(c)));
  }
  return `${verdict}${chartRow}${ctl}<div class="fg-list">${out.join('')}</div>`;
}
function forgeCard(c) {
  const fixable = c.kind === 'auto' || c.kind === 'optional';
  const diff = (c.diff || []).slice(0, 8).map((x) => (x.k === 'add' ? `<div class="fg-d add"><i>+</i><code>${esc(x.after)}</code></div>` : x.k === 'del' ? `<div class="fg-d del"><i>−</i><code>${esc(x.before)}</code></div>` : `<div class="fg-d del"><i>−</i><code>${esc(x.before)}</code></div><div class="fg-d add"><i>+</i><code>${esc(x.after)}</code></div>`)).join('');
  const where = `${esc(c.section)}${c.line ? ` · ${FG.req === 'instance' || state.mode === 'review' ? `<a ${loc(c)}>line ${c.line}</a>` : `line ${c.line}`}` : ''}`;
  const vtags = `${c.since ? `<span class="tag since">needs ≥ ${esc(c.since)}</span>` : ''}${c.until ? `<span class="tag until">gone after ${esc(c.until)}</span>` : ''}`;
  const srcs = (c.sources || []).filter((x) => x !== 'forge').map((x) => `<span class="tag" title="${esc((c.alsoFlagged || []).join(', ') || 'Also reported by this check')}">also ${esc(FG_SRC[x] || x)}</span>`).join(' ')
    + ((c.sources || []).length === 1 && c.sources[0] !== 'forge' ? `<span class="tag">${esc(FG_SRC[c.sources[0]] || c.sources[0])}</span>` : '');
  const lead = fixable ? `<label class="fg-sw" title="${c.applied ? 'Applied: click to leave it out' : 'Not applied: click to include it'}"><input type="checkbox" data-fg-t="${esc(c.key)}"${c.applied ? ' checked' : ''}><span></span></label>` : '<span class="fg-dot" title="Needs your decision"></span>';
  return `<article class="fg-card${c.applied || !fixable ? '' : ' off'}${fixable ? '' : ' adv'}">${lead}
    <div class="fg-cb"><div class="fg-ct"><b>${esc(c.title)}</b> <span class="fg-sev sev-${c.severity}">${esc(FG_SEV[c.severity])}</span> <span class="tag">${FG_CAT_ICON[c.category] || ''} ${esc(FG_CATS[c.category] || c.category)}</span>${c.kind === 'optional' ? ' <span class="tag">optional</span>' : ''}${vtags}${srcs}</div>
      <div class="muted small">${where}</div><p class="fg-why">${esc(c.why || c.detail)}</p>${!fixable && c.fix ? `<div class="fg-fix"><b>Fix</b> ${c.fix.includes('\n') ? `<pre class="val-code">${esc(c.fix)}</pre>` : esc(c.fix)}</div>` : ''}${c.docs ? `<div class="muted small"><a href="${esc(c.docs)}" target="_blank" rel="noopener noreferrer">Official documentation ↗</a></div>` : ''}${diff ? `<div class="fg-diff">${diff}${c.diff.length > 8 ? `<div class="muted small">+ ${c.diff.length - 8} more lines</div>` : ''}</div>` : ''}</div></article>`;
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
  if (t.closest('[data-fg-run]')) { const bi = $('#fg-build'); if (bi) FG.build = bi.value.trim(); const p = $('#fg-product'); FG.product = p ? p.value : ''; const v = $('#fg-version'); FG.version = v ? v.value.trim() : ''; const tx = $('#fg-text'); if (tx) FG.text = tx.value; FG.req = FG.src === 'instance' ? 'instance' : FG.files.length && FG.src === 'upload' ? 'files' : 'paste'; if (FG.src === 'paste') FG.files = []; forgeRun(); return; }
  if (t.closest('[data-fg-build]')) { const b = $('#fg-build'); if (b) FG.build = b.value; FG.buildOpen = !FG.buildOpen; renderForge(); return; }
  const pick = t.closest('[data-fg-pick]'); if (pick) { const i = $(pick.dataset.fgPick === 'dir' ? '#fg-dir' : '#fg-files'); if (i) i.click(); return; }
  const rm = t.closest('[data-fg-rm]'); if (rm) { FG.files.splice(+rm.dataset.fgRm, 1); renderForge(); return; }
  if (t.closest('[data-fg-inst]')) { FG.req = 'instance'; FG.src = 'instance'; FG.srcNote = 'This is the redacted copy of the configuration that GateLight holds. Secrets appear as placeholders: restore them before you deploy.'; forgeReset(); forgeRun(); return; }
  const ex = t.closest('[data-fg-ex]');
  if (ex) { try { const r = await api(`/examples/${ex.dataset.fgEx}`); FG.src = 'upload'; FG.files = r.files.map((f) => ({ name: f.name, content: f.content })); FG.text = ''; FG.product = ex.dataset.fgEx; FG.req = 'files'; FG.srcNote = ''; forgeReset(); forgeRun(); } catch (err) { toast(err.message, 'err'); } return; }
  const tb = t.closest('[data-fg-tab]'); if (tb) { FG.tab = tb.dataset.fgTab; renderForgeResults(); return; }
  const ct = t.closest('[data-fg-cat]'); if (ct) { FG.cat = ct.dataset.fgCat; renderForgeResults(); return; }
  const kd = t.closest('[data-fg-kind]'); if (kd) { FG.kind = kd.dataset.fgKind; renderForgeResults(); return; }
  const sv = t.closest('[data-fg-sev]'); if (sv) { FG.sev = sv.dataset.fgSev; renderForgeResults(); return; }
  if (t.closest('[data-fg-export]') && FG.data) { download('config-forge-findings.json', JSON.stringify({ product: FG.data.product, target: FG.data.target, score: FG.data.score, findings: FG.data.findings.map(({ key, rule, kind, severity, category, title, why, fix, section, line, sources }) => ({ rule, kind, severity, category, title, why, fix, section, line, sources })) }, null, 2), 'application/json'); return; }
  const all = t.closest('[data-fg-all]');
  if (all && FG.data) { const m = all.dataset.fgAll; FG.toggles = {}; FG.data.findings.filter((c) => c.auto).forEach((c) => { FG.toggles[c.key] = m === 'all' ? true : m === 'none' ? false : c.on; }); forgeAgain(); return; }
  if (t.closest('[data-fg-copy]')) { try { await navigator.clipboard.writeText(fgText()); toast('Copied the improved configuration', 'ok'); } catch { toast('Copy is not available in this browser', 'err'); } return; }
  if (t.closest('[data-fg-dl]') && FG.data) { const f = FG.data.files[FG.file]; download(f.name.split('/').pop(), f.improved); return; }
  if (t.closest('[data-fg-dlall]') && FG.data) { FG.data.files.forEach((f, i) => setTimeout(() => download(f.name.split('/').pop(), f.improved), i * 250)); return; }
  if (t.closest('[data-fg-copydiff]') && FG.data) { const f = FG.data.files[FG.file]; const txt = f.diff.hunks.map((h) => h.rows.map((r) => `${r.t === ' ' ? ' ' : r.t}${r.text}`).join('\n')).join('\n@@\n'); try { await navigator.clipboard.writeText(txt); toast('Diff copied', 'ok'); } catch { toast('Copy is not available in this browser', 'err'); } }
});
document.addEventListener('change', (e) => {
  const t = e.target; if (!t.closest || !t.closest('#view-forge')) return;
  if (t.matches('[data-fg-t]') && FG.data) { FG.toggles = { ...FG.toggles, [t.dataset.fgT]: t.checked }; const c = FG.data.findings.find((x) => x.key === t.dataset.fgT); if (c) c.applied = t.checked; forgeAgain(); return; }
  if (t.matches('[data-fg-grp]') && FG.data) { FG.data.findings.filter((x) => x.rule === t.dataset.fgGrp && x.auto).forEach((x) => { FG.toggles[x.key] = t.checked; x.applied = t.checked; }); forgeAgain(); return; }
  if (t.id === 'fg-file') { FG.file = +t.value; renderForgeResults(); return; }
  if (t.id === 'fg-files' || t.id === 'fg-dir') { fgReadFiles([...t.files]); t.value = ''; return; }
  if (t.id === 'fg-product') { FG.product = t.value; FG.version = ''; renderForge(); return; }
  if (t.id === 'fg-version') FG.version = t.value.trim();
});
document.addEventListener('input', (e) => { if (e.target.id === 'fg-text') { FG.text = e.target.value; FG.req = 'paste'; FG.files = []; } });
document.addEventListener('dragover', (e) => { if (e.target.closest && e.target.closest('#fg-drop')) { e.preventDefault(); e.target.closest('#fg-drop').classList.add('over'); } });
document.addEventListener('dragleave', (e) => { const d = e.target.closest && e.target.closest('#fg-drop'); if (d) d.classList.remove('over'); });
document.addEventListener('drop', (e) => { const d = e.target.closest && e.target.closest('#fg-drop'); if (!d) return; e.preventDefault(); d.classList.remove('over'); fgReadFiles([...e.dataTransfer.files]); });

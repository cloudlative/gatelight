'use strict';
/* GateLight UI: details pages (inspector). Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- INSPECTOR ----------
/** Details open as a page of their own (with Back), not as a panel over the current page. */
function openDetail() { if (state.view !== 'detail') state.detailFrom = state.view; switchView('detail'); window.scrollTo(0, 0); const v = $('#view-detail'); if (v) v.scrollTop = 0; }
function inspect(key, kind) {
  state.inspected = { key, kind };
  openDetail();
  refreshInspector();
  loadInspectorHistory(key);
}
function closeInspector() { state.inspected = null; }
function detailBack() {
  if (state.detailPushed) { history.back(); return; }
  const to = state.detailFrom && state.detailFrom !== 'detail' ? state.detailFrom : 'overview'; state.inspected = null; switchView(to);
}
/** Split a flat run of "<h4>Title</h4>…" sections into cards. */
function detailCards(html) {
  const parts = html.split(/(?=<h4)/).filter((x) => x.trim());
  return parts.map((p, i) => `<section class="dcard${i === 0 && !p.startsWith('<h4') ? ' first' : ''}">${p}</section>`).join('');
}

function kv(pairs) { return `<div class="kv">${pairs.filter(Boolean).map(([k, v]) => `<span>${esc(k)}</span><span>${v}</span>`).join('')}</div>`; }

function refreshInspector() {
  const ins = state.inspected; if (!ins || !state.snapshot) return;
  if (ins.kind === 'route' || ins.kind === 'missing') return;
  const r = indexRows(state.snapshot.rows).get(ins.key);
  const [proxy, name] = ins.key.split('/');
  const sec = cfgSections().find((x) => x.name === proxy && (x.type !== 'userlist'));
  const srv = sec && sec.servers.find((x) => x.name === name);
  $('#insp-kind').textContent = (r ? r.kind : ins.kind || '').toUpperCase();
  $('#insp-title').textContent = r ? (r.kind === 'server' ? `${proxy} / ${name}` : proxy) : ins.key;
  const related = state.snapshot.findings.filter((f) => f.section === proxy).slice(0, 6);
  const events = state.events.filter((e) => e.proxy === proxy && (!r || r.kind !== 'server' || e.name === name)).slice(0, 5);
  let html = '';
  if (r) {
    html += `<div>${stBadge(r.state, r.status)} ${r.check_status ? `<span class="mono small ${r.state === 'down' ? 'sev-error' : 'muted'}">${esc(r.check_status)}${r.check_code ? ` ${r.check_code}` : ''}${r.last_chk ? ` — ${esc(r.last_chk)}` : ''}</span>` : ''}</div>`;
    html += kv([
      ['Current sessions', `${fmtInt(r.scur)} <span class="muted">/ max ${fmtInt(r.smax)}${r.slim ? ` / limit ${fmtInt(r.slim)}` : ''}</span>`],
      ['Requests / s', fmtRate(r.ratePerSec)], ['5xx / s', fmtRate(r.err5xxPerSec)], ['Total sessions', fmtInt(r.stot)],
      ['Bytes in / out', `${fmtBytes(r.bin)} / ${fmtBytes(r.bout)}`],
      ['Responses', `2xx ${fmtInt(r.hrsp_2xx)} · 4xx ${fmtInt(r.hrsp_4xx)} · 5xx ${fmtInt(r.hrsp_5xx)}`],
      r.rtime != null ? ['Avg resp / connect', `${r.rtime} ms / ${r.ctime ?? '–'} ms`] : null,
      r.qcur != null && r.kind !== 'frontend' ? ['Queue', `${fmtInt(r.qcur)} (max ${fmtInt(r.qmax)})`] : null,
      r.kind === 'server' ? ['Weight', fmtInt(r.weight)] : null,
      r.lastchg != null ? ['Status for', fmtDur(r.lastchg)] : null,
      r.downtime ? ['Total downtime', fmtDur(r.downtime)] : null,
      (r.econ || r.eresp) ? ['Conn / resp errors', `${fmtInt(r.econ)} / ${fmtInt(r.eresp)}`] : null,
    ]);
    html += relationsHtml(r, proxy, sec, srv);
    html += '<h4>Trend (last samples) <button class="btn icon chart-expand" type="button" data-cv-expand="inspector" title="Pop out: bigger chart, time range, series and stats" aria-label="Pop out chart">⤢</button></h4><canvas id="insp-chart" class="chart" title="Click to pop out"></canvas>';
  } else html += '<div class="muted">No runtime data for this entry.</div>';
  if (sec) {
    html += '<h4>Configuration</h4>';
    if (srv) {
      html += kv([['Address', `<code>${esc(srv.address)}</code>`], ['Health check', srv.check ? 'enabled' : '<span class="sev-warning">none</span>'], ['Backup', srv.backup ? 'yes' : 'no'],
        ['Options', `<code>${esc(srv.options)}</code>`], ['Defined at', `<a style="color:var(--cyan);cursor:pointer" ${loc(srv)}>line ${srv.line}</a>`]]);
    } else {
      html += kv([['Section', `${esc(sec.type)} (line <a style="color:var(--cyan);cursor:pointer" ${loc(sec)}>${sec.line}</a>)`], ['Mode', esc(sec.mode)], ['Layer', `${layerTag(sec)} <span class="muted small">${esc(layerTip(sec))}</span>`],
        sec.balance ? ['Balance', esc(sec.balance)] : null,
        sec.serverNames && sec.serverNames.length ? ['Server names', sec.serverNames.map((n) => `<code>${esc(n)}</code>`).join('<br>')] : null,
        sec.binds.length ? ['Binds', sec.binds.filter((b) => !b.commented).map((b) => `<code>${esc(b.addresses.join(', '))}${b.ssl ? ' 🔒' : ''}</code>`).join('<br>')] : null,
        sec.zone ? ['Status zone', `<code>${esc(sec.zone)}</code>`] : null,
        sec.servers.length ? ['Servers', `${sec.servers.filter((x) => !x.commented).length} active`] : null,
        sec.routes.length ? ['Routes', `${sec.routes.filter((x) => !x.commented).length} active`] : null,
        Object.keys(sec.timeouts).length ? ['Timeouts', Object.entries(sec.timeouts).map(([k, v]) => `${esc(k)} ${esc(v)}`).join('<br>')] : null]);
    }
  }
  html += endpointsHtml(r, sec, srv);
  if (sec && !srv) html += urlMappingsHtml(sec);
  else if (srv) html += urlMappingsHtml(sec, true);
  if (sec && sec.locations && sec.locations.length) {
    html += `<h4>Locations</h4><div class="list">${sec.locations.map((l) => `<div class="item" ${loc(l)}><span class="tag">${esc(l.kind)}</span><div class="t mono small">${esc(`${l.modifier ? `${l.modifier} ` : ''}${l.path || ''}`)}${l.target ? ` → ${esc(l.target)}` : l.detail ? ` <span class="muted">${esc(l.detail)}</span>` : ''}</div></div>`).join('')}</div>`;
  }
  if (events.length) html += `<h4>Recent events</h4><div class="list">${events.map((e) => `<div class="item"><span class="lv-${esc(e.level)}">●</span><div class="t">${esc(e.message)}<div class="muted small">${fmtDateTime(e.ts)}</div></div></div>`).join('')}</div>`;
  if (related.length) html += `<h4>Audit findings</h4><div class="list">${related.map((f) => `<div class="item" ${loc(f)}><span class="sev-${esc(f.severity)}">●</span><div class="t">${esc(f.title)}<div class="muted small">line ${f.line}</div></div></div>`).join('')}</div>`;
  $('#insp-body').innerHTML = detailCards(html);
  $('#detail-crumb').textContent = $('#insp-title').textContent;
  drawInspectorChart();
}
let inspHistory = [];
async function loadInspectorHistory(key) {
  inspHistory = [];
  try { const h = await api(`/instances/${encodeURIComponent(state.current)}/history?key=${encodeURIComponent(key)}&points=180`); if (state.inspected && state.inspected.key === key) { inspHistory = h.points; drawInspectorChart(); cvRender(); } } catch { /* ignore */ }
}
function drawInspectorChart() {
  const c = $('#insp-chart'); if (!c) return;
  drawChart(c, inspHistory.map((p) => p.t), [
    { label: 'req/s', color: '#22d3ee', values: inspHistory.map((p) => p.rate) },
    { label: '5xx/s', color: '#f87171', values: inspHistory.map((p) => p.e5xx), minMax: 1 },
    { label: 'sessions', color: '#818cf8', values: inspHistory.map((p) => p.scur) },
  ]);
}
// Port mapping and URI transformation of a rule, as rows for the route inspector.
function flowRows(f) {
  if (!f) return [];
  const rows = [['Ports', f.portMap.map((p) => `${portTxt(p.in, p.listenerTls)} → ${p.out.length ? p.out.map((o) => `<span class="pt">:${o}</span>`).join(' ') : '?'} <span class="muted small">${esc(TLS_LABEL[p.tls] || p.tls)}</span>`).join('<br>')]];
  const steps = f.chain.filter((x) => x.applies !== false && (x.kind === 'path' || (x.kind === 'header' && /^Host$/i.test(x.args[0] || ''))));
  if (steps.length) rows.push(['URI changes', steps.map((x) => `<code>${esc(x.text)}</code>${x.cond ? ` <span class="muted small">${esc(x.cond)}</span>` : ''}`).join('<br>')]);
  if (f.example) rows.push(['Backend receives', f.example.changed ? `<code>${esc(f.example.in)}</code> → <code>${esc(f.example.out)}</code>${f.example.exact ? '' : ' <span class="muted small">(approximate)</span>'}` : `<span class="muted">the same path (${esc(f.example.in)})</span>`]);
  return rows;
}
function inspectRoute(r) {
  state.inspected = { kind: 'route' };
  $('#insp-kind').textContent = r.commented ? 'ROUTING RULE (DISABLED)' : 'ROUTING RULE';
  $('#insp-title').textContent = `${r.fe} → ${r.target}`;
  $('#insp-body').innerHTML = kv([['Type', esc(r.type)], ['Match', esc(routeSummary(r))], r.hosts && r.hosts.length ? ['Host', r.hosts.map((h) => `<code>${esc(h)}</code>`).join('<br>')] : null,
    ['Condition', `<code>${esc(r.condition)}</code>`], (r.aclRefs || []).length ? ['ACLs used', esc(r.aclRefs.join(', '))] : null,
    r.passUrl ? [r.passDirective || 'pass', `<code>${esc(r.passUrl)}</code>`] : null, r.rewriteNote ? ['URI rewrite', esc(r.rewriteNote)] : null,
    (r.rewrites || []).length ? ['rewrite rules', r.rewrites.map((x) => `<code>${esc(x)}</code>`).join('<br>')] : null,
    ...flowRows(flowOf(r.fe, r)),
    ['Defined at', `<a style="color:var(--cyan);cursor:pointer" ${loc(r)}>line ${r.line}</a>`]]);
  $('#insp-body').innerHTML = detailCards($('#insp-body').innerHTML); $('#detail-crumb').textContent = $('#insp-title').textContent;
  openDetail();
}
function inspectMissing(name) {
  state.inspected = { kind: 'missing' };
  $('#insp-kind').textContent = 'BROKEN ROUTE'; $('#insp-title').textContent = name;
  $('#insp-body').innerHTML = `<div class="finding error"><div class="ft">Backend “${esc(name)}” is not defined</div><div class="fm">A frontend routes here but no backend/listen section has this name. HAProxy will refuse to start with this configuration.</div></div>`;
  $('#insp-body').innerHTML = detailCards($('#insp-body').innerHTML); $('#detail-crumb').textContent = name;
  openDetail();
}

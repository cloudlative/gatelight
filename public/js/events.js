'use strict';
/* GateLight UI: Health Events page. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- EVENTS ----------
/** "Right now": what is already down or out of rotation. The timeline below only knows about changes seen while GateLight was running, so a server that was down before that would otherwise never appear. */
function eventsNowHtml() {
  const snap = state.snapshot; const rows = snap && snap.rows ? snap.rows : [];
  const bad = rows.filter((r) => (r.kind === 'server' || r.kind === 'backend') && ['down', 'maint', 'drain'].includes(r.state));
  const lab = { down: 'DOWN', maint: 'Maintenance', drain: 'Draining' };
  const sorted = bad.sort((a, b) => (a.state === 'down' ? 0 : 1) - (b.state === 'down' ? 0 : 1) || (b.lastchg || 0) - (a.lastchg || 0));
  const line = (r) => {
    const how = r.lastchg != null && r.lastchg >= 0 ? `for ${fmtDur(r.lastchg)}` : '';
    const why = r.check_status ? `${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}${r.last_chk ? ` · ${r.last_chk}` : ''}` : '';
    const name = r.kind === 'backend' ? `${r.proxy} <span class="tag">pool</span>` : `${esc(r.proxy)} / ${esc(r.name)}`;
    return `<tr data-inspect="${esc(r.proxy)}/${esc(r.name)}"><td><i class="dot ${r.state === 'down' ? 'c-down' : 'c-warn'}"></i></td><td><b>${name}</b></td><td class="lv-${r.state === 'down' ? 'critical' : 'warning'}">${lab[r.state]}${how ? ` <span class="muted">${esc(how)}</span>` : ''}</td><td class="muted small">${esc(why)}</td></tr>`;
  };
  const total = rows.filter((r) => r.kind === 'server').length;
  return `<div class="panel ev-now"><h3 class="flow-h">Right Now</h3>${sorted.length
    ? `<p class="muted small">${sorted.length} item${sorted.length === 1 ? '' : 's'} down or out of rotation (of ${total} servers). The duration is how long HAProxy has reported this state. Click a row for details.</p><table class="grid"><tbody>${sorted.map(line).join('')}</tbody></table>`
    : `<p class="ev-ok">✓ Nothing is down or out of rotation${total ? ` (${total} servers checked)` : ''}.</p>`}</div>`;
}
// ---- graphs on the Events page: server health over time, and who is down or flapping ----
const EV = { inst: null, hist: null, loading: false };
async function evLoadHistory() {
  if (EV.loading || !state.current || state.current === '__analysis') return;
  EV.loading = true; const id = state.current;
  try { const d = await api(`/instances/${encodeURIComponent(id)}/history-all?range=1440&max=240`); if (id === state.current) { EV.hist = (d && d.summary) || []; EV.inst = id; } } catch { EV.inst = id; EV.hist = []; }
  EV.loading = false;
  if (state.view === 'events') renderEvents();
}
function eventsChartsHtml(real) {
  const rows = (state.snapshot && state.snapshot.rows) || [];
  const servers = rows.filter((r) => r.kind === 'server');
  const top = (field, color, fmt) => servers.filter((r) => (r[field] || 0) > 0).sort((a, b) => b[field] - a[field]).slice(0, 8)
    .map((r) => ({ label: `${r.proxy} / ${r.name}`, value: r[field], text: fmt(r[field]), color, attrs: `data-inspect="${esc(r.proxy)}/${esc(r.name)}"` }));
  const lv = ['critical', 'warning', 'recovery', 'info'].map((k) => ({ label: k, value: real.filter((e) => e.level === k).length, color: { critical: '#f87171', warning: '#fbbf24', recovery: '#34d399', info: '#22d3ee' }[k] })).filter((x) => x.value);
  const hist = EV.inst === state.current && EV.hist && EV.hist.length > 1;
  const chart = `<div class="bc-card ev-wide"><div class="bc-head"><b>Servers up / down</b><span class="muted small">last 24 hours</span></div>${hist ? '<canvas id="ev-health" class="chart" title="Servers passing or failing their health check over time"></canvas>' : `<p class="muted small bc-empty">${EV.loading || EV.inst !== state.current ? 'Loading history…' : 'Collecting data… the history fills in while GateLight watches this instance.'}</p>`}</div>`;
  return `<div class="svc-charts-grid ev-charts">${chart}
    ${real.length ? donutCard('Changes by level', lv, { big: String(real.length), sub: 'changes' }, 'Recorded state changes, by how serious they were.') : barChart('Changes by level', [], { sub: 'since GateLight started watching', empty: '✓ No state changes recorded yet' })}
    ${barChart('Downtime by server', top('downtime', '#f87171', (v) => fmtDur(v)), { sub: 'time spent DOWN since the proxy started', empty: '✓ No server has been down' })}
    ${barChart('Flapping', top('chkdown', '#fbbf24', (v) => `${fmtInt(v)}×`), { sub: 'times a server went from UP to DOWN', empty: '✓ No server went down' })}
    ${barChart('Failed health checks', top('chkfail', '#818cf8', (v) => fmtInt(v)), { sub: 'failed checks since the proxy started', empty: '✓ No failed checks' })}</div>`;
}
function renderEvents() {
  const f = state.eventFilter;
  const real = state.events.filter((e) => e.type !== 'monitoring_started'); // "GateLight started monitoring" is a restart marker, not a change in your system
  const starts = state.events.filter((e) => e.type === 'monitoring_started');
  const list = real.filter((e) => f === 'all' || e.level === f);
  const startNote = starts.length ? `<p class="muted small ev-starts">GateLight (re)started monitoring ${starts.length} time${starts.length === 1 ? '' : 's'}; last ${esc(fmtDateTime(Math.max(...starts.map((e) => e.ts))))}. Changes before that are not known.</p>` : '';
  if (EV.inst !== state.current && !EV.loading) setTimeout(evLoadHistory, 0);
  $('#view-events').innerHTML = `<div class="page-help" role="note"><b>Health Events</b> is the record of what changed: a server, pool or the stats endpoint going down, degrading or coming back, and warnings found in uploaded logs. It tells you <i>when</i> something broke and recovered. For how much traffic you handle, see <button type="button" class="link" data-goto="graphs">Traffic Stats</button>; for how a request is routed, see <button type="button" class="link" data-goto="flow">Request Routing</button>.</div>
    ${eventsNowHtml()}
    ${eventsChartsHtml(real)}
    <div class="chips"><b class="ev-h">History</b>${['all', 'critical', 'warning', 'recovery', 'info'].map((x) => `<span class="chip ${f === x ? 'on' : ''}" data-ev="${x}">${x}</span>`).join('')}
      <span class="muted small">${real.length} change${real.length === 1 ? '' : 's'} recorded</span></div>
    <div class="table-wrap"><table class="grid"><thead><tr><th>Time</th><th>Level</th><th>Event</th></tr></thead><tbody>
    ${list.map((e) => `<tr ${e.proxy ? `data-inspect="${esc(e.proxy)}/${esc(e.name)}"` : ''}><td>${fmtDateTime(e.ts)}</td><td class="lv-${esc(e.level)}">${esc(e.level)}</td><td class="msg">${esc(e.message)}</td></tr>`).join('')
      || `<tr><td colspan="3" class="empty">${real.length ? 'No events at this level' : 'No changes seen yet. A server, pool or the stats endpoint going down or coming back up is recorded here from the moment GateLight started watching. Critical and warning changes also trigger your alert webhook.'}</td></tr>`}</tbody></table></div>${startNote}`;
  const ec = $('#ev-health'); if (ec && EV.hist && EV.hist.length > 1) drawChart(ec, EV.hist.map((p) => p.t), [{ label: 'up', color: '#34d399', values: EV.hist.map((p) => (p.up || 0) + (p.degraded || 0)) }, { label: 'down', color: '#f87171', values: EV.hist.map((p) => p.down || 0), minMax: 1 }]);
}

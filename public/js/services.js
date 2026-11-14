'use strict';
/* GateLight UI: Service Status table. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- SERVICES ----------
const SVC_COLS = [
  { k: 'name', t: 'Name', cmp: (a, b) => a.proxy.localeCompare(b.proxy) || a.name.localeCompare(b.name) },
  { k: 'state', t: 'Status', cmp: (a, b) => String(a.state).localeCompare(b.state) },
  { k: 'addr', t: 'IP / address', nosort: 1 },
  { k: 'ports', t: 'Port', nosort: 1 },
  { k: 'frontends', t: 'Frontend(s)', nosort: 1 }, { k: 'targets', t: 'Backend / targets', nosort: 1 },
  { k: 'scur', t: 'Sessions', num: 1 }, { k: 'ratePerSec', t: 'Req/s', num: 1 }, { k: 'spark', t: 'Trend (rate)', nosort: 1 },
  { k: 'err5xxPerSec', t: '5xx/s', num: 1 }, { k: 'stot', t: 'Total', num: 1 }, { k: 'bout', t: 'In / Out', num: 1 },
  { k: 'rtime', t: 'Resp ms', num: 1 },
];
// Ports/endpoints come from the parsed config; runtime stats alone never carry them.
const portOf = (a) => { const m = /:(\d+)(?:\D*)$/.exec(String(a || '').replace(/^[a-z0-9]+@/i, '')); return m ? m[1] : ''; };
const uniq = (a) => [...new Set(a)];
function rowEndpoints(r) { // -> { ports: ['80','443'], addrs: ['10.0.0.1:8080'] }; config first, then what the stats report
  const sec = cfgSections().find((x) => x.name === r.proxy && x.type !== 'userlist');
  let addrs = [];
  if (sec) {
    if (r.kind === 'server') { const sv = sec.servers.find((x) => x.name === r.name); addrs = sv && sv.address ? [sv.address] : []; }
    else if (r.kind === 'frontend') addrs = sec.binds.filter((b) => !b.commented).flatMap((b) => b.addresses);
    else addrs = sec.servers.filter((x) => !x.commented && x.address).map((x) => x.address);
  }
  if (!addrs.length && state.snapshot) { // no config attached: use the address HAProxy reports for each server
    if (r.kind === 'server' && r.addr) addrs = [r.addr];
    else if (r.kind === 'backend') addrs = state.snapshot.rows.filter((x) => x.proxy === r.proxy && x.kind === 'server' && x.addr).map((x) => x.addr);
  }
  return { ports: uniq(addrs.map(portOf).filter(Boolean)), addrs: uniq(addrs) };
}
// Related components for the table: who routes to this row (frontends) and where it leads (targets).
function rowRelations(r) {
  const secs = cfgSections(); const hasCfg = secs.length > 0;
  const frontends = []; const targets = [];
  const via = (name) => secs.filter(feLike).filter((fe) => fe.name !== name && fe.routes.some((rt) => !rt.commented && rt.target === name)).map((fe) => fe.name);
  if (r.kind === 'frontend') {
    const sec = secs.find((x) => x.name === r.proxy && feLike(x));
    if (sec) sec.routes.filter((rt) => !rt.commented).forEach((rt) => targets.push({ key: `${rt.target}/BACKEND`, label: rt.target }));
  } else {
    via(r.proxy).forEach((n) => frontends.push({ key: `${n}/FRONTEND`, label: n }));
    if (r.kind === 'server') targets.push({ key: `${r.proxy}/BACKEND`, label: r.proxy });
  }
  const uq = (a) => a.filter((x, i) => a.findIndex((y) => y.key === x.key) === i);
  return { hasCfg, frontends: uq(frontends), targets: uq(targets) };
}
function relCell(list, hasCfg, extra) {
  if (!list.length) return extra || `<span class="muted" ${hasCfg ? '' : 'title="Attach the config to see routing"'}>–</span>`;
  const chip = (x) => `<span class="chip" data-inspect="${esc(x.key)}">${esc(x.label)}</span>`;
  return list.slice(0, 3).map(chip).join(' ') + (list.length > 3 ? ` <span class="muted" title="${esc(list.slice(3).map((x) => x.label).join(', '))}">+${list.length - 3}</span>` : '');
}
const ipOf = (a) => String(a || '').replace(/^[a-z0-9]+@/i, '').replace(/:\d+(?:\D*)$/, '');
function addrCell(r) {
  const { addrs } = rowEndpoints(r);
  if (!addrs.length) return '<span class="muted">–</span>';
  const ips = uniq(addrs.map(ipOf).filter(Boolean));
  const shown = (r.kind === 'server' ? addrs : ips).slice(0, 2).join(', ') + ((r.kind === 'server' ? addrs : ips).length > 2 ? ` +${(r.kind === 'server' ? addrs : ips).length - 2}` : '');
  return `<span class="mono small" title="${esc(addrs.join('\n'))}">${esc(shown)}</span>`;
}
function portsCell(r) {
  const { ports, addrs } = rowEndpoints(r);
  if (!ports.length) return '<span class="muted">–</span>';
  const shown = ports.slice(0, 4).join(', ') + (ports.length > 4 ? ` +${ports.length - 4}` : '');
  return `<span class="mono" title="${esc(addrs.join('\n'))}">${esc(shown)}</span>`;
}
function filteredRows() {
  const q = $('#svc-search').value.trim().toLowerCase(); const kind = $('#svc-kind').value; const st = $('#svc-state').value;
  return state.snapshot.rows.filter((r) => ['frontend', 'backend', 'server'].includes(r.kind)
    && (!q || `${r.proxy} ${r.name} ${rowEndpoints(r).addrs.join(' ')}`.toLowerCase().includes(q))
    && (!kind || r.kind === kind)
    && (!st || (st === 'problem' ? isProblem(r) : r.state === st)));
}
function renderServices() {
  const rows = filteredRows(); const { key, desc } = state.sort;
  let out = rows;
  if (key !== 'default') {
    const col = SVC_COLS.find((c) => c.k === key);
    const get = (r) => (r[key] == null ? -Infinity : r[key]);
    out = [...rows].sort((a, b) => (col && col.cmp ? col.cmp(a, b) : (get(a) > get(b) ? 1 : get(a) < get(b) ? -1 : 0)) * (desc ? -1 : 1));
  } else {
    const order = { frontend: 0, server: 1, backend: 2 };
    out = [...rows].sort((a, b) => a.proxy.localeCompare(b.proxy) || order[a.kind] - order[b.kind] || a.name.localeCompare(b.name));
    // HAProxy lists servers before the BACKEND aggregate; show aggregate first
    out.sort((a, b) => a.proxy.localeCompare(b.proxy) || ((a.kind === 'server') - (b.kind === 'server')) || a.name.localeCompare(b.name));
  }
  const head = `<thead><tr>${SVC_COLS.map((c) => `<th data-sort="${c.k}" class="${c.num ? 'num' : ''}${state.sort.key === c.k ? ` sorted${desc ? ' desc' : ''}` : ''}">${c.t}</th>`).join('')}</tr></thead>`;
  { const sc = $('#svc-charts'); if (sc) sc.innerHTML = svcCharts(rows); }
  const body = out.map((r) => `<tr class="k-${r.kind}" data-inspect="${esc(r.proxy)}/${esc(r.name)}">
    <td class="${r.kind === 'server' ? 'indent' : ''}"><span class="mono">${esc(r.proxy)}${r.kind === 'server' ? ` / ${esc(r.name)}` : ` <span class="tag">${esc(lbl(r.kind))}</span>`}</span></td>
    <td>${stBadge(r.state, r.status)}${(() => { const d = [r.check_status ? `${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}` : '', r.lastchg != null ? `for ${fmtDur(r.lastchg)}` : '', r.kind === 'server' && r.weight != null ? `weight ${fmtInt(r.weight)}` : ''].filter(Boolean).join(' · '); return d ? `<div class="small ${r.state === 'down' ? 'sev-error' : 'muted'}">${esc(d)}</div>` : ''; })()}</td><td>${addrCell(r)}</td><td>${portsCell(r)}</td>${(() => { const rel = rowRelations(r); const n = r.kind === 'backend' ? state.snapshot.rows.filter((x) => x.proxy === r.proxy && x.kind === 'server').length : 0;
      return `<td>${r.kind === 'frontend' ? '<span class="muted">–</span>' : relCell(rel.frontends, rel.hasCfg)}</td><td>${relCell(rel.targets, rel.hasCfg, n ? `<span class="muted">${n} server${n === 1 ? '' : 's'}</span>` : '')}</td>`; })()}<td class="num">${fmtInt(r.scur)}</td><td class="num">${fmtRate(r.ratePerSec)}</td>
    <td><button type="button" class="spark-btn" data-cv-row="${esc(r.proxy)}/${esc(r.name)}" title="Click for the full chart: zoom, pan, history" aria-label="Open the full traffic chart for ${esc(r.proxy)}${r.kind === 'server' ? ` / ${esc(r.name)}` : ''}">${sparkSvg(r.spark, { color: r.state === 'down' ? '#f87171' : '#22d3ee', w: 52 })}</button></td>
    <td class="num ${(r.err5xxPerSec || 0) > 0.05 ? 'sev-warning' : ''}">${fmtRate(r.err5xxPerSec)}</td><td class="num">${fmtInt(r.stot)}</td>
    <td class="num">${fmtBytes(r.bin)}<div class="muted small">${fmtBytes(r.bout)}</div></td><td class="num">${r.rtime != null ? r.rtime : '–'}</td></tr>`).join('');
  $('#svc-table').innerHTML = head + `<tbody>${body || `<tr><td colspan="13" class="empty">${state.snapshot.rows.length ? 'No rows match the filter' : 'No runtime statistics for this instance'}</td></tr>`}</tbody>`;
}
function exportCsv() {
  const rows = filteredRows().map((r) => { const e = rowEndpoints(r); const rel = rowRelations(r); return { ...r, ports: e.ports.join(' '), endpoints: e.addrs.join(' '), frontends: rel.frontends.map((x) => x.label).join(' '), targets: rel.targets.map((x) => x.label).join(' ') }; });
  const cols = ['proxy', 'name', 'kind', 'status', 'ports', 'endpoints', 'frontends', 'targets', 'scur', 'ratePerSec', 'err5xxPerSec', 'stot', 'bin', 'bout', 'rtime', 'weight', 'lastchg', 'check_status'];
  const q = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  download(`${state.current}-services.csv`, [cols.join(','), ...rows.map((r) => cols.map((c) => q(r[c])).join(','))].join('\n'), 'text/csv');
}
function downloadBlob(name, blob) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function download(name, text, type = 'text/plain') { downloadBlob(name, new Blob([text], { type })); }

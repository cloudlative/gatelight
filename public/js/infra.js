'use strict';
/* GateLight UI: Topology network layout (what sits behind the load balancer). Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- LB INFRA: what sits behind the load balancer, and is it alive ----------
const lbi = { by: 'tree', problems: false, alive: false, open: new Set(), init: false };
const LBI_WORD = { up: 'alive', down: 'down', degraded: 'degraded', drain: 'draining', maint: 'maintenance', nocheck: 'unchecked', unknown: 'unknown' };
function lbiRows() { // live server rows, or the servers from the config when nothing is monitored yet
  const s = state.snapshot; const live = s.rows.filter((r) => r.kind === 'server');
  if (live.length) return { rows: live, monitored: true };
  const rows = [];
  for (const sec of cfgSections()) {
    if (sec.type === 'userlist' || !sec.servers) continue;
    for (const sv of sec.servers) if (!sv.commented) rows.push({ kind: 'server', proxy: sec.name, name: sv.name, state: 'unknown', status: 'not monitored', addr: sv.address });
  }
  return { rows, monitored: false };
}
function lbiServer(r) {
  const addr = (rowEndpoints(r).addrs[0]) || r.addr || '';
  const detail = [r.check_status ? `check ${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}` : '', r.lastchg != null ? `${r.state === 'up' ? 'up' : 'since'} ${fmtDur(r.lastchg)}` : '', r.weight != null && r.weight !== 1 ? `weight ${r.weight}` : ''].filter(Boolean).join(' · ');
  return `<button type="button" class="lbi-srv s-${esc(r.state)}" data-inspect="${esc(r.proxy)}/${esc(r.name)}" title="${esc(`${r.proxy} / ${r.name}\n${addr}\n${r.status || ''}`)}">
    <span class="lbi-dot s-${esc(r.state)}" aria-hidden="true"></span><span class="lbi-n"><b>${esc(r.name)}</b><span class="mono small">${esc(addr || 'address unknown')}</span></span>
    <span class="lbi-st"><span class="st st-${esc(r.state)}">${esc(LBI_WORD[r.state] || r.state)}</span>${detail ? `<span class="muted small">${esc(detail)}</span>` : ''}</span></button>`;
}
const lbiAliveText = (list) => { const up = list.filter((r) => r.state === 'up').length; return `${up}/${list.length} alive`; };
function lbiMeter(list) {
  const t = list.length || 1; const part = (st, cls) => { const n = list.filter((r) => (Array.isArray(st) ? st.includes(r.state) : r.state === st)).length; return n ? `<i class="${cls}" style="width:${(n / t) * 100}%"></i>` : ''; };
  return `<span class="lbi-meter" aria-hidden="true">${part('up', 's-up')}${part(['degraded', 'drain'], 's-degraded')}${part('down', 's-down')}${part('maint', 's-maint')}${part(['nocheck', 'unknown'], 's-unknown')}</span>`;
}
function lbiPoolState(list) { return list.some((r) => r.state === 'down') ? (list.every((r) => r.state === 'down') ? 'down' : 'degraded') : list.some((r) => r.state === 'degraded' || r.state === 'drain') ? 'degraded' : list.length && list.every((r) => r.state === 'up') ? 'up' : 'unknown'; }

// ---- hierarchy: load balancer → frontends → networks → hosts → services (with +/- folding) ----
const lbiIpv4 = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
function lbiTree(s, vis, rows, lbState, type, info, fes, binds) {
  const addrOf = (r) => (rowEndpoints(r).addrs[0]) || r.addr || '';
  const hostOf = (r) => ipOf(addrOf(r)) || 'unknown host';
  const nets = new Map();
  for (const r of vis) {
    const h = hostOf(r); const net = lbiIpv4(h) ? `${h.split('.').slice(0, 3).join('.')}.0/24` : (h === 'unknown host' ? 'Unknown' : 'Named hosts');
    if (!nets.has(net)) nets.set(net, new Map()); const hm = nets.get(net); if (!hm.has(h)) hm.set(h, []); hm.get(h).push(r);
  }
  const natural = (a, b) => a.localeCompare(b, undefined, { numeric: true });
  const netKeys = [...nets.keys()].sort(natural);
  if (!lbi.init) { lbi.init = true; lbi.open.add('lb'); netKeys.forEach((n) => { lbi.open.add(`n:${n}`); nets.get(n).forEach((_l, h) => lbi.open.add(`h:${h}`)); }); }
  const allRows = (hm) => [...hm.values()].flat();
  const word = (st) => `<span class="st st-${esc(st)}">${esc(LBI_WORD[st] || st)}</span>`;
  const tog = (id, open) => `<button type="button" class="tt" data-lbt-toggle="${esc(id)}" aria-label="${open ? 'Collapse' : 'Expand'}"></button>`;
  const node = (id, cls, head, kids) => { const open = lbi.open.has(id); return `<li class="lbt-n ${cls}" aria-expanded="${open}"><div class="lbt-row">${tog(id, open)}${head}</div><ul${open ? '' : ' hidden'}>${kids}</ul></li>`; };
  const svc = (r) => { const port = portOf(addrOf(r)); const d = [r.check_status ? `check ${r.check_status}${r.check_code ? ` ${r.check_code}` : ''}` : '', r.lastchg != null ? `${r.state === 'up' ? 'up' : 'since'} ${fmtDur(r.lastchg)}` : ''].filter(Boolean).join(' · ');
    return `<li class="lbt-n svc s-${esc(r.state)}"><button type="button" class="lbt-row lbt-leaf" data-inspect="${esc(r.proxy)}/${esc(r.name)}"><span class="lbi-dot s-${esc(r.state)}" aria-hidden="true"></span><span class="lbt-port mono">${port ? `:${esc(port)}` : '–'}</span><b>${esc(r.name)}</b><span class="chip">${esc(r.proxy)}</span>${word(r.state)}${d ? `<span class="muted small">${esc(d)}</span>` : ''}</button></li>`; };
  const host = (net, h, list) => { const st = lbiPoolState(list); const names = uniq(list.map((r) => r.name)); const pools = uniq(list.map((r) => r.proxy));
    return node(`h:${h}`, `host s-${st}`, `<span class="lbi-dot s-${st}" aria-hidden="true"></span><b class="mono">${esc(h)}</b>${word(st)}<span class="muted small">${esc(lbiAliveText(list))} · ${list.length} service${list.length === 1 ? '' : 's'}</span><span class="lbt-ids muted small" title="${esc(names.join(', '))}">${esc(names.slice(0, 3).join(', '))}${names.length > 3 ? ` +${names.length - 3}` : ''}</span>${lbiMeter(list)}`,
      list.sort((a, b) => natural(portOf(addrOf(a)), portOf(addrOf(b)))).map(svc).join('')); };
  const net = (n) => { const hm = nets.get(n); const list = allRows(hm); const st = lbiPoolState(list);
    return node(`n:${n}`, `net s-${st}`, `<span class="lbt-ico" aria-hidden="true">⌗</span><b class="mono">${esc(n)}</b><span class="muted small">${hm.size} host${hm.size === 1 ? '' : 's'} · ${esc(lbiAliveText(list))}</span>${lbiMeter(list)}`,
      [...hm.keys()].sort(natural).map((h) => host(n, h, hm.get(h))).join('')); };
  const allList = vis; const lbSt = lbState === 'up' ? lbiPoolState(rows) : 'unknown';
  const ports = binds.slice(0, 6).map((b) => `<span class="chip mono">${esc(b)}</span>`).join(' ');
  const root = node('lb', `lb s-${lbSt}`, `<span class="lbi-dot s-${lbState}" aria-hidden="true"></span><b>${esc(s.instance.name || state.current)}</b><span class="muted small">${esc(type)}${info.version ? ` ${esc(info.version)}` : ''}${info.uptimeSec != null ? ` · up ${esc(fmtDur(info.uptimeSec))}` : ''}</span>${word(lbState === 'up' ? lbSt : lbState === 'down' ? 'down' : 'unknown')}<span class="muted small">${nets.size} network${nets.size === 1 ? '' : 's'} · ${new Set(allList.map(hostOf)).size} hosts · ${esc(lbiAliveText(rows))}</span>`,
    `${fes.length || ports ? `<li class="lbt-n front"><div class="lbt-row"><span class="lbt-ico" aria-hidden="true">⇥</span><span class="muted small">Entry points</span>${fes.map((f) => `<button type="button" class="chip" data-inspect="${esc(f.proxy)}/${esc(f.name)}">${esc(f.proxy)}${rowEndpoints(f).ports.length ? ` :${esc(rowEndpoints(f).ports.slice(0, 3).join(', :'))}` : ''}</button>`).join(' ') || ports}</div></li>` : ''}${netKeys.map(net).join('') || '<li class="empty">Nothing to show for this filter</li>'}`);
  return `<div class="lbt"><div class="lbt-ctl"><button type="button" class="btn" data-lbt-all="open">＋ Expand all</button><button type="button" class="btn" data-lbt-all="close">－ Collapse all</button></div><ul class="lbt-root">${root}</ul></div>`;
}
function renderLbInfra() {
  const s = state.snapshot; const el = $('#infra'); if (!s || !el) return;
  const { rows, monitored } = lbiRows();
  const vis = lbi.problems ? rows.filter((r) => r.state !== 'up') : lbi.alive ? rows.filter((r) => r.state === 'up') : rows;
  const count = (st) => rows.filter((r) => r.state === st).length;
  const fes = s.rows.filter((r) => r.kind === 'frontend'); const info = s.info || {};
  const binds = []; for (const sec of cfgSections()) if (feLike(sec)) for (const b of sec.binds || []) if (!b.commented) binds.push(...b.addresses.map((a) => `${sec.name} ${a}`));
  const type = TYPE_NAME[snapshotType()] || 'Load balancer';
  const lbState = s.ok ? 'up' : (s.instance.source === 'config-only' ? 'unknown' : 'down');
  const hosts = new Set(rows.map((r) => ipOf((rowEndpoints(r).addrs[0]) || r.addr || '')).filter(Boolean));
  const pools = [...new Set(rows.map((r) => r.proxy))].sort();
  const bePools = new Map(s.rows.filter((r) => r.kind === 'backend').map((r) => [r.proxy, r]));
  const lb = `<div class="lbi-lb"><div class="lbi-lb-h"><span class="lbi-dot s-${lbState}" aria-hidden="true"></span><b>${esc(s.instance.name || state.current)}</b><span class="st st-${lbState}">${lbState === 'up' ? 'alive' : lbState === 'down' ? 'unreachable' : 'config only'}</span></div>
    <div class="muted small">${esc(type)}${info.version ? ` ${esc(info.version)}` : ''}${info.uptimeSec != null ? ` · up ${esc(fmtDur(info.uptimeSec))}` : ''}</div>
    ${fes.length ? `<h4>${esc(lbl('frontend'))}s</h4><ul class="lbi-fe">${fes.map((f) => `<li data-inspect="${esc(f.proxy)}/${esc(f.name)}" class="clickable"><span class="lbi-dot s-${esc(f.state)}" aria-hidden="true"></span><b>${esc(f.proxy)}</b>${(rowEndpoints(f).ports.length ? `<span class="mono small muted">:${esc(rowEndpoints(f).ports.join(', :'))}</span>` : '')}</li>`).join('')}</ul>` : (binds.length ? `<h4>Listening</h4><ul class="lbi-fe">${binds.slice(0, 8).map((b) => `<li><span class="mono small">${esc(b)}</span></li>`).join('')}</ul>` : '')}
    <div class="lbi-sum"><div><b>${count('up')}</b><span>alive</span></div><div class="${count('down') ? 'bad' : ''}"><b>${count('down')}</b><span>down</span></div><div><b>${count('degraded') + count('drain')}</b><span>degraded</span></div><div><b>${hosts.size}</b><span>hosts</span></div></div></div>`;

  let body = '';
  if (lbi.by === 'host') {
    const groups = new Map();
    for (const r of vis) { const h = ipOf((rowEndpoints(r).addrs[0]) || r.addr || '') || 'unknown host'; if (!groups.has(h)) groups.set(h, []); groups.get(h).push(r); }
    body = [...groups].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true })).map(([h, list]) => {
      const st = lbiPoolState(list);
      return `<section class="lbi-pool s-${st}"><header><span class="lbi-dot s-${st}" aria-hidden="true"></span><b class="mono">${esc(h)}</b><span class="st st-${st}">${esc(LBI_WORD[st] || st)}</span><span class="muted small">${esc(lbiAliveText(list))} · ${list.length} service${list.length === 1 ? '' : 's'}</span>${lbiMeter(list)}</header>
        <div class="lbi-srvs">${list.map((r) => lbiServer(r)).join('')}</div><div class="muted small lbi-from">serves: ${esc(uniq(list.map((r) => r.proxy)).join(', '))}</div></section>`;
    }).join('');
  } else {
    body = pools.map((p) => {
      const all = rows.filter((r) => r.proxy === p); const list = vis.filter((r) => r.proxy === p); if (!list.length) return '';
      const st = bePools.get(p) && bePools.get(p).state === 'down' ? 'down' : lbiPoolState(all);
      const from = rowRelations({ kind: 'backend', proxy: p, name: 'BACKEND' }).frontends;
      return `<section class="lbi-pool s-${st}"><header><span class="lbi-dot s-${st}" aria-hidden="true"></span><b class="clickable" data-inspect="${esc(p)}/BACKEND">${esc(p)}</b><span class="st st-${st}">${esc(LBI_WORD[st] || st)}</span><span class="muted small">${esc(lbiAliveText(all))}</span>${lbiMeter(all)}</header>
        ${from.length ? `<div class="muted small lbi-from">reached from: ${from.map((f) => `<span class="chip" data-inspect="${esc(f.key)}">${esc(f.label)}</span>`).join(' ')}</div>` : ''}
        <div class="lbi-srvs">${list.map((r) => lbiServer(r)).join('')}</div></section>`;
    }).join('');
  }
  el.innerHTML = `<div class="lbi-bar"><div class="seg" role="group" aria-label="Group by"><button type="button" class="${lbi.by === 'tree' ? 'on' : ''}" data-lbi-by="tree">Hierarchy</button><button type="button" class="${lbi.by === 'pool' ? 'on' : ''}" data-lbi-by="pool">By pool</button><button type="button" class="${lbi.by === 'host' ? 'on' : ''}" data-lbi-by="host">By host</button></div>
    <label class="gr-ctl"><input type="checkbox" id="lbi-alive"${lbi.alive ? ' checked' : ''}> Only show what is alive</label>
    <label class="gr-ctl"><input type="checkbox" id="lbi-problems"${lbi.problems ? ' checked' : ''}> Only show what is not alive</label><span class="spacer"></span>
    <span class="muted small lbi-key"><i class="lbi-dot s-up"></i>alive <i class="lbi-dot s-degraded"></i>degraded <i class="lbi-dot s-down"></i>down <i class="lbi-dot s-maint"></i>maintenance <i class="lbi-dot s-unknown"></i>unchecked</span></div>
    ${monitored ? '' : '<div class="banner info lbi-note">No live statistics for this instance, so aliveness is unknown. Connect the stats endpoint to see live status; the layout below comes from the config.</div>'}
    ${rows.length && lbi.by === 'tree' ? lbiTree(s, vis, rows, lbState, type, info, fes, binds) : rows.length ? `<div class="lbi-layout">${lb}<div class="lbi-pools">${body || (lbi.alive ? '<div class="empty">Nothing is alive right now</div>' : '<div class="empty">✓ Everything is alive</div>')}</div></div>` : '<div class="empty">Nothing behind this load balancer yet. Attach a config or connect the stats endpoint.</div>'}`;
}

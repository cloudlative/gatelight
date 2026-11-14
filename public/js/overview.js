'use strict';
/* GateLight UI: Overview page. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- OVERVIEW ----------
/** KPI card: value + live detail + a plain-language "what is this" line; a button that jumps to the matching, pre-filtered view. */
function card(label, value, sub, tone, o = {}) {
  const act = o.go ? ` data-card="${esc(o.go)}"` : '';
  const tag = o.go ? 'button type="button"' : 'div';
  return `<${tag} class="card ${tone || ''}${o.go ? ' clickable' : ''}"${act} title="${esc(o.help || '')}"${o.go ? ` aria-label="${esc(`${label}: ${value}. ${o.help || ''} Click to ${o.cta || 'open'}.`)}"` : ''}>
    <div class="label">${esc(label)}</div><div class="value">${esc(value)}</div><div class="sub">${esc(sub || '')}</div>
    ${o.help && !o.compact ? `<div class="why">${esc(o.help)}</div>` : ''}${o.cta && !o.compact ? `<div class="go">${esc(o.cta)} →</div>` : ''}</${o.go ? 'button' : 'div'}>`;
}
// card id -> { view, filters on the Services table, sort }
const CARD_GO = {
  'servers-up': { view: 'services', kind: 'server', st: 'up', sort: 'default' },
  down: { view: 'services', kind: '', st: 'down', sort: 'default' },
  rate: { view: 'services', kind: 'backend', st: '', sort: 'ratePerSec', desc: true },
  err5xx: { view: 'services', kind: 'backend', st: '', sort: 'err5xxPerSec', desc: true },
  bytes: { view: 'services', kind: 'backend', st: '', sort: 'bout', desc: true },
  findings: { view: 'forge' },
};
function openCard(id) {
  const g = CARD_GO[id]; if (!g) return;
  if (g.view === 'services') {
    $('#svc-search').value = ''; $('#svc-kind').value = g.kind; $('#svc-state').value = g.st;
    state.sort = { key: g.sort, desc: Boolean(g.desc) };
  }
  switchView(g.view);
}

function renderOverview() {
  const s = state.snapshot; const sum = s.summary; const f = s.findingsSummary;
  const hasStats = s.rows.some((r) => r.scur != null || r.stot != null || r.ratePerSec != null);
  const problems = s.rows.filter((r) => r.kind !== 'frontend' && isProblem(r)).sort((a, b) => (a.state === 'down' ? -1 : 1) - (b.state === 'down' ? -1 : 1));
  const hot = s.rows.filter((r) => r.kind === 'backend' && (r.err5xxPerSec || 0) > 0.05 && r.ratePerSec > 0)
    .map((r) => ({ r, pct: (r.err5xxPerSec / Math.max(r.ratePerSec, 0.001)) * 100 })).filter((x) => x.pct >= 1).sort((a, b) => b.pct - a.pct).slice(0, 5);
  const errs = s.findings.filter((x) => x.severity === 'error').slice(0, 5);
  const info = s.info || {};
  const alerts = (s.alerts || []).filter((a) => a.status === 'firing'); const pending = (s.alerts || []).filter((a) => a.status === 'pending');

  const showCta = state.meta.canManage && ['config-only', 'demo'].includes(s.instance.source);
  const cta = showCta ? `<div class="cta"><div><b>${s.instance.source === 'demo' ? 'You are looking at synthetic demo traffic' : 'You are looking at the configuration only'}</b><span class="muted">Connect your ${s.instance.source === 'demo' ? '' : 'live '}${esc(TYPE_NAME[s.instance.type] || 'proxy')} (URL, username, password) to see real health and traffic.</span></div><button class="btn primary" type="button" data-connect>Connect a server</button></div>` : '';
  // ---- level 1: one verdict for the whole instance ----
  const sv = sum.servers; const upN = sv.up + sv.degraded; const downN = hasStats ? sv.down + sum.backends.down : 0;
  const downRows = problems.filter((r) => r.state === 'down');
  const tone = !hasStats ? 'neutral' : downN ? 'bad' : (f.error || hot.length || alerts.length || sv.degraded || sum.err5xxPerSec > 0.5) ? 'warn' : 'ok';
  const since = downRows.length === 1 && downRows[0].lastchg > 0 ? ` for ${fmtDur(downRows[0].lastchg)}` : '';
  const headline = !hasStats ? 'Configuration loaded' : downN ? (downRows.length === 1 && downRows[0].kind === 'server' ? `${downRows[0].proxy} / ${downRows[0].name} is down${since}` : `${downN} item${downN === 1 ? '' : 's'} down`) : tone === 'warn' ? 'Running, with things to look at' : 'Everything is healthy';
  const facts = [
    hasStats ? `${upN} of ${sv.total} servers up${sv.nocheck ? `, ${sv.nocheck} without a health check` : ''}` : null,
    f.error ? `${f.error} critical config issue${f.error === 1 ? '' : 's'}` : (hasStats ? 'no critical config issues' : `${f.warning} config warning${f.warning === 1 ? '' : 's'}`),
    hasStats ? `${fmtRate(sum.ratePerSec)} requests/s${sum.err5xxPerSec > 0 ? `, ${fmtRate(sum.err5xxPerSec)} × 5xx/s` : ', no 5xx'}` : null,
  ].filter(Boolean);
  const segs = [['up', 'Up', 'var(--green)'], ['degraded', 'Degraded', 'var(--amber)'], ['down', 'Down', 'var(--red)'], ['maint', 'Maintenance', 'var(--indigo)'], ['nocheck', 'No health check', 'var(--slate)']].map(([k, t, c]) => ({ t, c, n: sv[k] || 0 })).filter((x) => x.n);
  const ico = { ok: '✓', warn: '!', bad: '✕', neutral: 'i' }[tone];
  const hero = `<section class="ov-hero ${tone}" aria-label="Overall status">
    <div class="ov-verdict"><span class="ov-ico" aria-hidden="true">${ico}</span>
      <div><h2>${esc(headline)}</h2><p class="ov-facts">${facts.map(esc).join('<i></i>')}</p>
        <div class="ov-actions">${downN ? '<button class="btn primary" type="button" data-card="down">Show what is down</button>' : ''}<button class="btn" type="button" data-goto="forge">Config Doctor</button><button class="btn" type="button" data-goto="topology">Topology</button></div></div></div>
    ${hasStats && sv.total ? `<div class="ov-servers"><div class="ov-sv-top"><b>${upN}</b><span>/ ${sv.total} servers up</span></div>
      <div class="ov-bar" role="img" aria-label="${esc(segs.map((x) => `${x.n} ${x.t}`).join(', '))}">${segs.map((x) => `<i style="flex:${x.n};background:${x.c}" title="${esc(`${x.n} ${x.t}`)}"></i>`).join('')}</div>
      <div class="ov-legend">${segs.map((x) => `<span><i style="background:${x.c}"></i>${x.n} ${esc(x.t.toLowerCase())}</span>`).join('')}</div></div>` : ''}
  </section>`;
  const proc = processPanel(info);
  const perf = hasStats || info.activeConns != null;
  $('#view-overview').innerHTML = cta + `${hero}
    <div class="ov-lvl"><span>Needs attention</span></div>
    <div class="cols">
      <div class="panel"><h2>Needs Attention <span class="tag">${problems.length + hot.length + alerts.length}</span></h2><div class="list">
        ${[...alerts, ...pending].slice(0, 5).map((a) => `<div class="item"${a.proxy ? ` data-inspect="${esc(a.proxy)}/${esc(a.name || a.proxy)}"` : ''} title="${esc(a.status === 'firing' ? `Alert rule "${a.label}" is firing` : `Alert rule "${a.label}": the condition holds and fires if it lasts`)}"><span class="st st-${a.status === 'firing' ? 'alert' : 'pending'}">${a.status === 'firing' ? 'Alert' : 'Pending'}</span><div class="t"><b>${esc(a.label)}</b><div class="muted small">${esc(a.message)} · since ${fmtDur((Date.now() - a.since) / 1000)}</div></div></div>`).join('')}
        ${problems.slice(0, 8).map((r) => `<div class="item" data-inspect="${esc(r.proxy)}/${esc(r.name)}">${stBadge(r.state, r.status)}<div class="t"><b>${esc(r.proxy)}${r.kind === 'server' ? ` / ${esc(r.name)}` : ''}</b>${rowEndpoints(r).addrs.length ? ` <span class="mono small muted">${esc(rowEndpoints(r).addrs.slice(0, 2).join(', '))}</span>` : ''}${r.check_status ? `<div class="muted small">${esc(r.check_status)}${r.last_chk ? ` — ${esc(r.last_chk)}` : ''}${r.lastchg != null ? ` · for ${fmtDur(r.lastchg)}` : ''}</div>` : ''}</div></div>`).join('')
          || (hot.length || alerts.length || pending.length ? '' : `<div class="empty">${hasStats ? '✓ Everything is healthy' : 'No runtime stats available'}</div>`)}
        ${hot.map(({ r, pct }) => `<div class="item" data-inspect="${esc(r.proxy)}/${esc(r.name)}"><span class="st st-degraded">5xx</span><div class="t"><b>${esc(r.proxy)}</b><div class="muted small">${pct.toFixed(1)}% of responses are 5xx (${fmtRate(r.err5xxPerSec)}/s)</div></div></div>`).join('')}
      </div></div>
      <div class="panel"><h2>Critical Config Issues <a class="muted small" data-goto="audit" style="cursor:pointer">view all →</a></h2><div class="list">
        ${errs.map((x) => `<div class="item" ${loc(x)}><span class="sev-error">●</span><div class="t"><b>${esc(x.title)}</b><div class="muted small">${esc(x.section)} · line ${x.line}</div></div></div>`).join('') || '<div class="empty">✓ No errors</div>'}
      </div></div>
      <div class="panel"><h2>Recent Events <a class="muted small" data-goto="events" style="cursor:pointer">view all →</a></h2><div class="list">
        ${state.events.filter((e) => e.level !== 'info').slice(0, 6).map((e) => `<div class="item"><span class="lv-${esc(e.level)}">●</span><div class="t">${esc(e.message)}<div class="muted small">${fmtDateTime(e.ts)}</div></div></div>`).join('') || '<div class="empty">No state changes recorded</div>'}
      </div></div>
    </div>
    ${perf ? `<div class="ov-lvl"><span>Performance</span></div>
    <div class="cards ov-kpis">
      ${hasStats || info.activeConns != null ? card('Requests / s', fmtRate(sum.ratePerSec), `${fmtInt(sum.sessions)} current ${info.activeConns != null ? 'connections' : 'sessions'}`, '', { go: 'rate', help: 'New HTTP requests per second across all backends, measured over the latest poll. Sessions are connections open right now.', compact: true, cta: 'Busiest backends' }) : ''}
      ${hasStats ? card('5xx / s', fmtRate(sum.err5xxPerSec), sum.ratePerSec > 0 ? `${((sum.err5xxPerSec / sum.ratePerSec) * 100).toFixed(2)}% of traffic` : '', sum.err5xxPerSec > 0.5 ? 'warn' : '', { go: 'err5xx', help: 'Server-side errors (HTTP 500–599) returned per second. A rising value usually means a failing application, not the proxy.', compact: true, cta: 'Backends by errors' }) : ''}
      ${hasStats ? card('Throughput', `${fmtBytes(sum.bytesIn + sum.bytesOut)}`, 'total in+out since start', '', { go: 'bytes', help: 'Bytes received plus sent since the proxy last restarted (a counter, not a rate).', compact: true, cta: 'Backends by traffic' }) : ''}
      ${card('Audit findings', f.error + f.warning, `${f.error} errors · ${f.warning} warnings · ${f.info} info · Config Doctor lists more`, f.error ? 'bad' : f.warning ? 'warn' : 'ok', { go: 'findings', help: 'Problems the static audit found in the configuration: errors will break or endanger the proxy, warnings are risky settings, info is advice.', compact: true, cta: 'Review findings' })}
    </div>`  : ''}
    ${hasStats || info.activeConns != null ? `<div class="panel ov-traffic"><h2>Traffic <span class="muted small">${esc(info.version ? `${TYPE_NAME[snapshotType()] || ''} ${info.version}` : '')}${info.uptimeSec != null ? ` · up ${fmtDur(info.uptimeSec)}` : ''}${info.idlePct != null ? ` · idle ${info.idlePct}%` : ''}${info.reading != null ? ` · reading/writing/waiting ${info.reading}/${info.writing}/${info.waiting}` : ''}</span><button class="btn icon chart-expand" type="button" data-cv-expand="overview" title="Pop out: bigger chart, time range, series and stats" aria-label="Pop out traffic chart">⤢</button></h2><canvas id="ov-chart" class="chart" title="Click to pop out"></canvas></div>` : ''}
    ${proc ? `<div class="ov-lvl"><span>System</span></div>${proc}` : ''}`;
  const c = $('#ov-chart');
  if (c) {
    const ser = state.series;
    drawChart(c, ser.map((p) => p.t), [
      { label: 'req/s', color: '#22d3ee', values: ser.map((p) => p.rate) },
      { label: '5xx/s', color: '#f87171', values: ser.map((p) => p.e5), minMax: 1 },
    ]);
  }
}

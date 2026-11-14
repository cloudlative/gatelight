'use strict';
/* GateLight UI: Fleet and Settings pages. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- FLEET ----------
function renderFleet() {
  const list = state.instances.filter((i) => !state.hiddenTypes.includes(i.type));
  const tone = (i) => (i.ok === false ? 'bad' : i.serversDown ? 'warn' : i.ok ? 'ok' : '');
  $('#view-fleet').innerHTML = `<h2>All Instances</h2><div class="cards fleet">${list.map((i) => `
    <div class="card clickable" data-open-instance="${esc(i.id)}">
      <div class="label"><span class="tag">${esc(TYPE_NAME[i.type] || i.type)}</span> ${esc(i.source)}</div>
      <div class="value" style="font-size:17px;margin:6px 0;color:var(--text)"><i class="dot ${tone(i) === 'bad' ? 'c-down' : tone(i) === 'warn' ? 'c-warn' : tone(i) === 'ok' ? 'c-up' : 'c-idle'}" style="margin-right:8px"></i>${esc(i.name)}</div>
      <div class="sub">${i.ok === false ? `<span class="sev-error">unreachable</span> — ${esc(i.error || '')}` : i.serversTotal ? `${i.serversTotal - i.serversDown}/${i.serversTotal} up${i.serversDown ? ` · <span class="sev-error">${i.serversDown} down</span>` : ''}` : 'no runtime data'}</div>
      <div class="sub">${i.findings ? `${i.findings.error} errors · ${i.findings.warning} warnings` : ''}</div>
    </div>`).join('') || '<div class="empty">No instances</div>'}</div>`;
}

// ---------- SETTINGS ----------
function renderSettings() {
  const f = state.meta.features || {};
  const types = ALL_TYPES.filter((t) => t === 'haproxy' || t === 'nginx' || productInfo(t));
  $('#view-settings').innerHTML = `<div class="set-wrap">
    <header class="set-head"><h2>Settings</h2><p class="muted">Which technologies GateLight loads, what this browser shows, and the instances you manage.</p></header>
    <div class="panel"><div class="panel-h"><h2>Technologies</h2></div>
      <p class="muted">What GateLight loads and polls. Turn a technology off on the server to stop it from being loaded at all.</p>
      <div class="tech-grid">${types.map((t) => {
        const on = f[t] !== false; const mine = state.instances.filter((i) => i.type === t);
        const live = mine.filter((i) => i.ok === true).length; const cfg = mine.filter((i) => i.source === 'config-only').length;
        const bad = mine.filter((i) => i.ok === false && i.source !== 'config-only').length; const down = mine.reduce((n, i) => n + (i.serversDown || 0), 0);
        const reads = { haproxy: ['Stats page (CSV)', 'Runtime API', 'haproxy.cfg'], nginx: ['stub_status', 'NGINX Plus API', 'TCP probe of upstreams', 'nginx.conf'], apache: ['mod_status (server-status?auto)', 'balancer-manager', 'apache2.conf (Debian/Ubuntu) or httpd.conf (RHEL/upstream) + includes'], caddy: ['Admin API (/reverse_proxy/upstreams)', 'Prometheus metrics', 'Caddyfile or JSON'], traefik: ['API (/api/http/…)', 'Prometheus metrics', 'static + dynamic config, Docker labels'] }[t] || [];
        const stat = (n, label, cls) => `<div class="tech-stat ${cls || ''}"><b>${n}</b><span>${label}</span></div>`;
        return `<section class="tech ${on ? 'on' : 'off'}" aria-label="${esc(TYPE_NAME[t])}">
          <header><span class="tech-ico t-${t}" aria-hidden="true">${TYPE_ABBR[t]}</span><b>${esc(TYPE_NAME[t])}</b><span class="st ${on ? 'st-up' : 'st-down'}">${on ? 'enabled' : 'disabled'}</span></header>
          <div class="tech-reads">${reads.map((r) => `<span class="chip">${esc(r)}</span>`).join('')}</div>
          ${on ? `<div class="tech-stats">${stat(mine.length, mine.length === 1 ? 'instance' : 'instances')}${stat(live, 'live')}${stat(cfg, 'config only')}${stat(bad, 'unreachable', bad ? 'bad' : '')}${stat(down, 'servers down', down ? 'bad' : '')}</div>${mine.length ? '' : `<p class="muted small tech-empty">None yet. <button class="link" type="button" data-connect>Add a ${esc(TYPE_NAME[t])} instance</button></p>`}`
            : `<p class="muted small tech-empty">Off on this server, so ${esc(TYPE_NAME[t])} instances are not loaded or polled. Set <code>ENABLE_${t.toUpperCase()}=true</code> and restart to turn it on.</p>`}
          <footer class="muted small"><code>ENABLE_${t.toUpperCase()}=${on ? 'true' : 'false'}</code></footer></section>`;
      }).join('')}</div>
      <details class="tech-how"><summary>How to turn a technology on or off</summary>
        <ul class="small muted"><li>Environment: <code>ENABLE_HAPROXY</code>, <code>ENABLE_NGINX</code>, <code>ENABLE_APACHE</code>, <code>ENABLE_CADDY</code>, <code>ENABLE_TRAEFIK</code> set to <code>true</code> or <code>false</code>.</li><li>Or <code>"features"</code> in <code>instances.json</code>. Use <code>"enabled": false</code> on a single instance to pause just that one.</li><li>A restart applies changes. To only hide a technology for yourself, use <b>Display</b> below.</li></ul></details>
    </div>
    <div class="panel"><div class="panel-h"><h2>Display</h2></div>
      <p class="muted">Per-browser preference: hide a technology from the selector and Fleet view without changing the server.</p>
      <div class="set-checks">${types.filter((t) => f[t] !== false).map((t) => `<label class="check"><input type="checkbox" data-show-type="${t}" ${state.hiddenTypes.includes(t) ? '' : 'checked'}> Show ${TYPE_NAME[t]}</label>`).join('')}</div>
    </div>
    <div class="panel"><div class="panel-h"><h2>Instances</h2>${state.meta.canManage ? '<button class="btn primary" type="button" data-connect>+ Connect a server</button>' : ''}</div>
      ${state.meta.canManage ? '' : '<p class="muted small">Servers are defined in <code>config/instances.json</code> or env vars. To add them from this page, start GateLight with <code>ALLOW_UI_INSTANCES=true</code>.</p>'}
      <div class="table-wrap"><table class="grid"><thead><tr><th>Name</th><th>Type</th><th>Source</th><th>Status</th><th>Findings</th><th></th></tr></thead><tbody>
      ${state.instances.map((i) => `<tr data-open-instance="${esc(i.id)}"><td>${esc(i.name)}</td><td>${esc(TYPE_NAME[i.type] || i.type)}</td><td class="mono small">${esc(i.source)}</td><td>${i.ok === false ? `<span class="st st-down" title="${esc(i.error || '')}">error</span>${i.error ? `<div class="muted small" style="max-width:260px">${esc(String(i.error).slice(0, 120))}</div>` : ''}` : i.ok ? '<span class="st st-up">ok</span>' : '…'}</td><td>${i.findings ? `${i.findings.error}e / ${i.findings.warning}w` : ''}</td><td>${i.managed ? `<div class="row-actions"><button class="btn" type="button" data-cx-up="${esc(i.id)}">Update Config</button><button class="btn" type="button" data-cx-edit="${esc(i.id)}">Edit</button><button class="btn" type="button" data-cx-del="${esc(i.id)}">Remove</button></div>` : ''}</td></tr>`).join('')}
      </tbody></table></div>
    </div></div>`;
}

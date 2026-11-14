'use strict';
/* GateLight UI: Profile page. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- PROFILE ----------
function renderProfile() {
  const m = state.meta || {}; const u = m.authUser ? String(m.authUser) : '';
  const left = m.authExp ? Math.max(0, m.authExp - Date.now()) : 0; const hrs = Math.floor(left / 3600e3); const mins = Math.floor((left % 3600e3) / 60000);
  const total = (m.sessionHours || 0) * 3600e3; const pct = total ? Math.max(0, Math.min(100, (left / total) * 100)) : 0;
  const mine = state.instances.filter((i) => i.managed).length;
  const light = isLight();
  const ico = (d) => `<svg class="pf-ico" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
  const I = {
    user: ico('<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>'), clock: ico('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
    monitor: ico('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'), key: ico('<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>'),
  };
  const refresh = { auto: 'Auto (follows the server)', off: 'Paused' }[refreshSetting()] || `Every ${Number(refreshSetting()) / 1000} s`;
  const row = (k, v) => `<div class="pf-row"><span>${k}</span><b>${v}</b></div>`;
  $('#view-profile').innerHTML = `<div class="pf-wrap">
    <section class="pf-hero">
      <span class="avatar big pf-av" aria-hidden="true">${esc((u[0] || '?').toUpperCase())}</span>
      <div class="pf-id"><h2>${esc(u || 'Not signed in')}</h2>
        <div class="pf-chips">${u ? '<span class="pf-chip ok"><i></i>Signed in</span>' : '<span class="pf-chip warn"><i></i>Sign-in is off on this server</span>'}<span class="pf-chip">${m.authEnabled ? 'Password sign-in' : 'Open access'}</span><span class="pf-chip mono">GateLight ${esc(m.version || '–')}</span></div></div>
      ${u ? '<button type="button" class="btn pf-out" data-logout>Sign out</button>' : ''}
    </section>
    <div class="pf-grid">
      <section class="panel pf-card"><h3>${I.clock}Session</h3>
        <div class="pf-left">${m.authExp ? `<b>${hrs}</b><span>h</span> <b>${String(mins).padStart(2, '0')}</b><span>min left</span>` : '<b>–</b>'}</div>
        <div class="pf-bar" role="img" aria-label="${Math.round(pct)}% of the session left"><i style="width:${pct.toFixed(1)}%"></i></div>
        ${row('Signed in until', m.authExp ? esc(fmtDateTime(m.authExp)) : '–')}${row('Session length', m.sessionHours ? `${m.sessionHours} h` : '–')}
        <p class="muted small">The session lasts for the configured length, then you sign in again. <code>AUTH_SESSION_HOURS</code> sets it on the server. Signing out ends it at once on this browser.</p></section>
      <section class="panel pf-card"><h3>${I.monitor}This browser</h3>
        <div class="pf-row"><span>Theme</span><b>${light ? 'Light' : 'Dark'} <button type="button" class="btn small-btn" data-prof-theme>Switch to ${light ? 'dark' : 'light'}</button></b></div>
        ${row('Auto-refresh', esc(refresh))}
        <div class="pf-row"><span>Your private connections</span><b>${mine} <button type="button" class="btn small-btn" data-goto="settings">Manage</button></b></div></section>
      <section class="panel pf-card"><h3>${I.user}Account</h3>
        ${row('Username', `<span class="mono">${esc(u || '–')}</span>`)}${row('Sign-in method', m.authEnabled ? 'Password' : 'None (open access)')}${row('GateLight version', `<span class="mono">${esc(m.version || '–')}</span>`)}</section>
      <section class="panel pf-card"><h3>${I.key}Password</h3>
        <p class="muted">The password is set on the server, not in the browser.</p>
        <div class="pf-note">To change it, set <code>AUTH_PASS</code> (or a hash in <code>AUTH_PASS_HASH</code>) in <code>.env</code> and restart GateLight. Everyone is signed out when you do.</div></section>
    </div></div>`;
}

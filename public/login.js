'use strict';
/* Sign-in page. No inline handlers (strict CSP). */
(function () {
  const $ = (s) => document.querySelector(s);
  const params = new URLSearchParams(location.search);
  const t = params.get('theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  else { // dark by default; follow a theme chosen inside the app
    let pref = 'dark'; try { const v = JSON.parse(localStorage.getItem('gatelight.theme')); if (v) pref = v; } catch { /* storage unavailable */ }
    if (pref === 'light' || pref === 'dark') document.documentElement.dataset.theme = pref; else delete document.documentElement.dataset.theme;
  }

  // Only ever send people back to a path on this site (no open redirect). The URL fragment (#demo/services) survives the trip.
  const safeNext = () => {
    const n = params.get('next') || '/';
    return n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') ? n + (n.includes('#') ? '' : location.hash) : '/';
  };

  // Already signed in (or sign-in is off): go straight on.
  fetch('/auth/session', { credentials: 'same-origin' }).then((r) => r.json()).then((s) => {
    if (!s.enabled || s.authenticated) location.replace(safeNext());
  }).catch(() => { /* show the form */ });

  const err = $('#lg-err');
  const show = (m) => { err.textContent = m; err.hidden = !m; };

  $('#lg-show').addEventListener('click', (e) => {
    const p = $('#lg-pass'); const on = p.type === 'password';
    p.type = on ? 'text' : 'password'; e.currentTarget.textContent = on ? 'Hide' : 'Show'; e.currentTarget.setAttribute('aria-pressed', String(on));
  });

  $('#lg-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    show('');
    const username = $('#lg-user').value.trim(); const password = $('#lg-pass').value;
    if (!username || !password) { show('Enter your username and password.'); return; }
    const btn = $('#lg-go'); btn.disabled = true; btn.textContent = 'Signing in…';
    try {
      const res = await fetch('/auth/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
      const body = await res.json().catch(() => ({}));
      if (res.ok) { location.replace(safeNext()); return; }
      show(body.error || `Sign-in failed (HTTP ${res.status}).`);
      $('#lg-pass').value = ''; $('#lg-pass').focus();
    } catch {
      show('Cannot reach the server. Check your connection and try again.');
    }
    btn.disabled = false; btn.textContent = 'Sign in';
  });
})();

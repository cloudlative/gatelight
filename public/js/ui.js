'use strict';
/* GateLight UI: toasts and theme. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- toasts / theme ----------
function toast(msg, kind = 'info', ms = 3600) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`; el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
}
function applyTheme(pref) {
  if (pref === 'light' || pref === 'dark') document.documentElement.dataset.theme = pref; else delete document.documentElement.dataset.theme;
  if (network) { network.destroy(); network = null; }
  if (state.snapshot) renderView(state.view);
}
function cycleTheme() {
  const order = ['dark', 'light', 'auto']; const cur = loadPref('gatelight.theme', 'dark');
  const next = order[(order.indexOf(cur) + 1) % 3];
  savePref('gatelight.theme', next); applyTheme(next); toast(`Theme: ${next}`);
}

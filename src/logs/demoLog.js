'use strict';
/** Synthetic HAProxy log for demo mode and screenshots: made-up clients, names and traffic, deterministic. */
const { createAggregator } = require('./haproxy');

function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const pick = (r, list) => { let x = r() * list.reduce((a, b) => a + b[1], 0); for (const [v, w] of list) { x -= w; if (x <= 0) return v; } return list[0][0]; };
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = (n) => String(n).padStart(2, '0');
function stamp(ms) { const d = new Date(ms); return `${p2(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}.${String(d.getUTCMilliseconds()).padStart(3, '0')}`; }
function sys(ms) { const d = new Date(ms); return `${MON[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2)} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} lb01 haproxy[1147]: `; }

const ROUTES = [ // path template, backend, base ms, weight, methods
  ['/api/orders', 'api_pool', 45, 22, [['GET', 6], ['POST', 3]]], ['/api/users/:id', 'api_pool', 30, 18, [['GET', 8], ['PUT', 1]]], ['/api/search', 'api_pool', 120, 8, [['GET', 1]]],
  ['/static/app.js', 'static_pool', 6, 16, [['GET', 1]]], ['/static/app.css', 'static_pool', 5, 12, [['GET', 1]]], ['/static/logo.svg', 'static_pool', 4, 6, [['GET', 1]]],
  ['/checkout/pay', 'checkout_pool', 380, 5, [['POST', 1]]], ['/checkout/cart', 'checkout_pool', 90, 6, [['GET', 3], ['POST', 2]]],
  ['/admin/login', 'admin_pool', 70, 2, [['GET', 2], ['POST', 1]]], ['/', 'web_pool', 55, 14, [['GET', 1]]], ['/products', 'web_pool', 75, 10, [['GET', 1]]], ['/healthz', 'web_pool', 2, 4, [['GET', 1]]],
];
const SERVERS = { api_pool: ['api-01', 'api-02'], static_pool: ['cdn-01', 'cdn-02'], checkout_pool: ['pay-01', 'pay-02'], admin_pool: ['admin-01'], web_pool: ['web-01', 'web-02', 'web-03'] };
const ORIGINS = [['https://shop.example.com', 10], ['https://www.example.com', 3], ['https://m.example.com', 2]];

function demoLines(n = 60000, seed = 7) {
  const r = rng(seed); const day = Date.UTC(2026, 10, 10); const lines = [];
  const clients = Array.from({ length: 900 }, (_, i) => (i % 9 === 0 ? `2001:db8:${(i * 7).toString(16)}:${(i * 13).toString(16)}::${(i % 250) + 1}` : `203.0.${113 + (i % 5)}.${(i * 7) % 250 + 1}`));
  const hot = clients.slice(0, 25);
  const curve = (h) => 0.25 + 0.75 * Math.max(0, Math.sin(((h - 5) / 17) * Math.PI)); // quiet at night, busy in the afternoon
  const weights = Array.from({ length: 24 }, (_, h) => curve(h)); const wsum = weights.reduce((a, b) => a + b, 0);
  const cum = []; weights.reduce((a, w, i) => { cum[i] = a + w / wsum; return cum[i]; }, 0);
  const total = ROUTES.reduce((a, x) => a + x[3], 0);
  for (let i = 0; i < n; i++) {
    const u = r(); let h = cum.findIndex((c) => u <= c); if (h < 0) h = 23;
    const t = day + h * 3600000 + Math.floor(r() * 3600000);
    const client = r() < 0.3 ? hot[Math.floor(r() * hot.length)] : clients[Math.floor(r() * clients.length)];
    const cport = 1024 + Math.floor(r() * 60000);
    if (r() < 0.12) { // plain TCP traffic (MQTT devices): long sessions, many end by timeout
      const dur = Math.floor(5000 + r() * 55000); const term = r() < 0.7 ? 'sD' : '----';
      lines.push(`${sys(t)}${client}:${cport} [${stamp(t)}] mqtt mqtt_pool/${r() < 0.5 ? 'mq-01' : 'mq-02'} ${Math.floor(r() * 3)}/0/${dur} ${Math.floor(r() * 900) + 5} ${term} ${900 + Math.floor(r() * 80)}/${800 + Math.floor(r() * 60)}/${790 + Math.floor(r() * 60)}/${790 + Math.floor(r() * 40)}/0 0/0`);
      continue;
    }
    let x = r() * total; let route = ROUTES[0]; for (const rt of ROUTES) { x -= rt[3]; if (x <= 0) { route = rt; break; } }
    const [tpl, be, base, , methods] = route;
    const srvList = SERVERS[be]; const srv = srvList[Math.floor(r() * srvList.length)];
    const incident = be === 'api_pool' && srv === 'api-02' && h >= 14 && h < 15; // an api-02 problem during the 14:00 hour
    const slowBoost = incident ? 8 : (be === 'checkout_pool' && h >= 19 && h < 21 ? 2.5 : 1);
    const tr = Math.max(1, Math.round(base * slowBoost * (0.4 + r() * 1.4) * (r() < 0.02 ? 12 : 1)));
    const errP = incident ? 0.35 : 0.004; let status = 200; const q = r();
    if (q < errP) status = incident ? pick(r, [[503, 5], [504, 3], [500, 2]]) : pick(r, [[500, 2], [502, 1], [503, 1]]);
    else if (tpl.startsWith('/static') && q < 0.1) status = 304;
    else if (tpl === '/admin/login' && q < 0.3) status = 302;
    else if (q > 0.985) status = pick(r, [[404, 6], [403, 1], [400, 1]]);
    const aborted = r() < 0.004; if (aborted) status = -1;
    const path = tpl.replace(':id', String(1000 + Math.floor(r() * 9000))) + (r() < 0.3 ? `?page=${Math.floor(r() * 9)}` : '');
    const method = pick(r, methods); const bytes = aborted ? 0 : Math.round((tpl.startsWith('/static') ? 40000 : tpl.startsWith('/api') ? 3000 : 12000) * (0.2 + r() * 1.6));
    const term = aborted ? 'CDVN' : status >= 500 ? 'sH--' : status === 304 || status === 302 ? '----' : '--VN';
    const timers = `${Math.floor(r() * 2)}/${be === 'checkout_pool' ? Math.floor(r() * 6) : 0}/${Math.floor(r() * 3)}/${aborted ? -1 : tr}/${aborted ? tr + 400 : tr + Math.floor(r() * 4)}`;
    lines.push(`${sys(t)}${client}:${cport} [${stamp(t)}] shop~ ${be}/${srv} ${timers} ${status} ${bytes} - - ${term} ${600 + Math.floor(r() * 200)}/${150 + Math.floor(r() * 100)}/${10 + Math.floor(r() * 30)}/${3 + Math.floor(r() * 8)}/0 ${incident ? Math.floor(r() * 12) : 0}/0 {${pick(r, ORIGINS)}} "${method} ${path} HTTP/1.1"`);
  }
  for (let i = 0; i < 90; i++) { const t = day + 6 * 3600000 + Math.floor(r() * 12 * 3600000); lines.push(`${sys(t)}${clients[Math.floor(r() * 60)]}:${1024 + Math.floor(r() * 60000)} [${stamp(t)}] shop/3: SSL handshake failure`); }
  const ev = (h, m, s, text) => lines.push(`${sys(day + h * 3600000 + m * 60000 + s * 1000)}${text}`);
  ev(14, 2, 10, 'Server api_pool/api-02 is DOWN, reason: Layer7 timeout, check duration: 2001ms. 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.');
  ev(14, 41, 55, 'Server api_pool/api-02 is UP, reason: Layer7 check passed, check duration: 6ms. 2 active and 0 backup servers online. 0 sessions requeued, 0 total in queue.');
  ev(9, 12, 3, 'Server web_pool/web-03 is DOWN, reason: Layer4 connection problem, info: "Connection refused", check duration: 0ms. 2 active and 0 backup servers left.');
  lines.sort(); // syslog time prefix first: roughly chronological, like a real file
  return lines;
}

let cached = null;
/** The aggregated JSON text of the demo log (computed once). */
function demoResultText() {
  if (cached) return cached;
  const a = createAggregator();
  for (const l of demoLines()) a.push(l);
  cached = JSON.stringify(a.finish({ source: { filename: 'demo-haproxy.log', bytes: 0, lines: a.stats.lines, demo: true } }));
  return cached;
}

module.exports = { demoLines, demoResultText };

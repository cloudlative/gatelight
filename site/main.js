'use strict';
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const root = document.documentElement;

  // theme: dark by default, remembered
  try { const t = localStorage.getItem('gl-site-theme'); if (t === 'light' || t === 'dark') root.dataset.theme = t; } catch { /* storage unavailable */ }
  $('#theme').addEventListener('click', () => {
    const next = root.dataset.theme === 'light' ? 'dark' : 'light';
    root.dataset.theme = next; try { localStorage.setItem('gl-site-theme', next); } catch { /* ignore */ }
  });

  // copy buttons
  $$('.cmd').forEach((box) => {
    const btn = $('.copy', box); if (!btn) return;
    btn.addEventListener('click', async () => {
      const text = (box.dataset.copy || $('code', box).innerText).replace(/&#10;/g, '\n');
      try { await navigator.clipboard.writeText(text); } catch {
        const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch { /* ignore */ } ta.remove();
      }
      btn.textContent = 'Copied'; btn.classList.add('done');
      setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1600);
    });
  });

  // screenshot tour
  const TOUR = [
    ['Overview', 'A status banner first, then what needs attention, performance and process facts. Everything links to the detail behind it.'],
    ['Graphs', 'Zoom by dragging, pan with the hand tool, one shared crosshair, clickable legends and donut charts for HTTP errors. Up to 7 days of history.'],
    ['Infrastructure', 'Load balancer, networks, hosts and services in a foldable hierarchy, each with its aliveness.'],
    ['Topology', 'Frontends, routing rules, pools and servers with live traffic. Click a node to focus its path.'],
    ['Traffic flow', 'Every domain with its listener ports, redirects, rules and servers (address and port), where TLS ends, the path your backend receives, and which relationships are live.'],
    ['Domains', 'One card per domain: the ports it is served on, redirects, rules, and every server with the address and port each listener port ends up at. Filter by alive, not alive or unused.'],
    ['Mind map', 'The same map as a radial mind map, with the URIs each node handles written on it.'],
    ['Tree', 'The whole estate as an outline, like the tree command. Fold it, copy it as text.'],
    ['NGINX', 'NGINX too: server blocks, locations and upstreams, plus a resizable URL map.'],
    ['Audit', 'Every finding has a line number and a fix, with charts showing where problems cluster. Click a category to filter.'],
    ['Details', 'Click anything for its own page: health, metrics, relationships, trend, configuration, events and findings.'],
    ['Events', 'What is down right now and for how long, graphs of server health, downtime and flapping, and the history of changes.'],
    ['NGINX traffic', 'Upload an NGINX access log and get status codes, URLs, clients and errors; response times appear when the log has them.'],
  ];
  const tabs = $$('.tabs button'); const shots = $$('.shot');
  let timer = null;
  const pick = (i, user) => {
    tabs.forEach((b, n) => b.setAttribute('aria-selected', String(n === i)));
    shots.forEach((s, n) => s.classList.toggle('on', n === i));
    $('#tour-title').textContent = `GateLight · ${TOUR[i][0]}`; $('#tour-caption').textContent = TOUR[i][1];
    if (user) { clearInterval(timer); timer = null; }
  };
  tabs.forEach((b, i) => b.addEventListener('click', () => pick(i, true)));
  let cur = 0;
  const auto = () => { cur = (cur + 1) % TOUR.length; pick(cur, false); };
  const tourEl = $('.tour');
  if ('IntersectionObserver' in window && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    new IntersectionObserver((e) => { e.forEach((x) => { if (x.isIntersecting && !timer && tabs.some((t) => t.getAttribute('aria-selected') === 'true')) timer = timer || setInterval(auto, 5200); else if (!x.isIntersecting) { clearInterval(timer); timer = null; } }); }, { threshold: 0.35 }).observe(tourEl);
  }
  tabs.forEach((b, i) => b.addEventListener('focus', () => { cur = i; }));
  tabs.forEach((b, i) => b.addEventListener('click', () => { cur = i; }));

  // reveal on scroll
  const items = $$('.reveal');
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    items.forEach((el) => io.observe(el));
  } else items.forEach((el) => el.classList.add('in'));

  // feature cards: light follows the pointer
  $$('.feat').forEach((c) => c.addEventListener('pointermove', (e) => { const r = c.getBoundingClientRect(); c.style.setProperty('--mx', `${((e.clientX - r.left) / r.width) * 100}%`); }));


  // hero visual: pointer parallax + live-ticking numbers
  const hv = $('.hero-visual');
  const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (hv && !calm) {
    hv.addEventListener('pointermove', (e) => { const r = hv.getBoundingClientRect(); hv.style.setProperty('--px', ((e.clientX - r.left) / r.width - 0.5).toFixed(3)); hv.style.setProperty('--py', ((e.clientY - r.top) / r.height - 0.5).toFixed(3)); });
    hv.addEventListener('pointerleave', () => { hv.style.setProperty('--px', 0); hv.style.setProperty('--py', 0); });
    const e5 = $('#live5xx'), line = $('#sparkline'), al = $('#liveAlive');
    const pts = [12, 9, 13, 6, 10, 4, 8]; let v = 2.5, n = 0;
    setInterval(() => {
      v = Math.max(0.4, Math.min(6, v + (Math.random() - 0.5) * 1.1));
      e5.textContent = v.toFixed(2);
      pts.shift(); pts.push(Math.round(16 - Math.min(14, v * 2.4)));
      line.setAttribute('points', pts.map((y, i) => `${i * 10},${y}`).join(' '));
      if (++n % 6 === 0) { al.textContent = al.textContent.startsWith('2') ? '3 / 3 alive' : '2 / 3 alive'; }
    }, 1400);
  }

  $('#year').textContent = new Date().getFullYear();
})();

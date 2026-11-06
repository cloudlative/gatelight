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
    ['Overview', 'Clickable, explained health cards, process facts, a traffic chart and what needs attention. Everything links to the detail behind it.'],
    ['Graphs', 'Zoom by dragging, pan with the hand tool, one shared crosshair, clickable legends and donut charts for HTTP errors. Up to 7 days of history.'],
    ['Infrastructure', 'Load balancer, networks, hosts and services in a foldable hierarchy, each with its aliveness.'],
    ['Topology', 'Frontends, routing rules, pools and servers with live traffic. Click a node to focus its path.'],
    ['Mind map', 'The same map as a radial mind map, with the URIs each node handles written on it.'],
    ['Tree', 'The whole estate as an outline, like the tree command. Fold it, copy it as text.'],
    ['NGINX', 'NGINX too: server blocks, locations and upstreams, plus a resizable URL map.'],
    ['Audit', 'Every finding has a line number and a fix, with charts showing where problems cluster. Click a category to filter.'],
    ['Details', 'Click anything for its own page: health, metrics, relationships, trend, configuration, events and findings.'],
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

  $('#year').textContent = new Date().getFullYear();
})();

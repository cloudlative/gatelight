'use strict';
/* GateLight UI: Topology: map, layouts, node icons, URL map, tree. Part of the UI split from app.js; the files share one global scope and load in order (see index.html). */
// ---------- TOPOLOGY ----------
let network = null; let visNodes = null; let visEdges = null;
const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
function isLight() {
  const t = document.documentElement.dataset.theme;
  return t === 'light' || (t !== 'dark' && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
}
// ---------- Layer 7 (HTTP) vs layer 4 (TCP) ----------
// L7 = understands HTTP: routes by host / path / method / header, can rewrite the URI and add headers.
// L4 = forwards TCP connections by address and port (and TLS SNI); it never sees paths or headers.
const layerOf = (sec) => (sec && sec.mode === 'tcp' ? 'L4' : 'L7');
function layerTip(sec) {
  if (!sec) return '';
  const l4 = layerOf(sec) === 'L4';
  const sni = (sec.routes || []).some((r) => !r.commented && (r.matchers || []).some((m) => m.field === 'TLS SNI'));
  const tls = (sec.binds || []).some((b) => b.ssl && !b.commented);
  if (!l4) return `L7 · HTTP: routes by host, path, method and headers; can rewrite the URI, add headers${tls ? ', ends TLS here' : ''} and see status codes.`;
  return `L4 · TCP: forwards connections by address and port${sni ? ' and TLS SNI' : ''}; cannot see paths or headers, so no URI routing or rewriting. ${tls ? 'TLS is ended at this proxy.' : 'TLS (if any) stays encrypted end to end.'}`;
}
const layerTag = (sec) => `<span class="tag layer-${layerOf(sec).toLowerCase()}" title="${esc(layerTip(sec))}">${layerOf(sec)}</span>`;

const DARK_NODES = {
  fe: { background: '#0e7490', border: '#22d3ee' }, be: { background: '#3730a3', border: '#818cf8' },
  up: { background: '#065f46', border: '#34d399' }, degraded: { background: '#78350f', border: '#fbbf24' },
  down: { background: '#7f1d1d', border: '#f87171' }, maint: { background: '#312e81', border: '#818cf8' },
  idle: { background: '#1e293b', border: '#64748b' }, missing: { background: '#450a0a', border: '#f87171' },
};
const LIGHT_NODES = { // solid fills with a darker rim: the label sits outside the shape, so the shape can be bold
  fe: { background: '#0891b2', border: '#0e7490' }, be: { background: '#6366f1', border: '#4338ca' },
  up: { background: '#10b981', border: '#047857' }, degraded: { background: '#f59e0b', border: '#b45309' },
  down: { background: '#ef4444', border: '#b91c1c' }, maint: { background: '#a5b4fc', border: '#4f46e5' },
  idle: { background: '#cbd5e1', border: '#64748b' }, missing: { background: '#fca5a5', border: '#dc2626' },
};
let NODE_COLORS = DARK_NODES;

/** Break long identifiers at a separator so neighbouring labels do not collide. */
function wrapName(name, max = 14) {
  const s = String(name);
  if (s.length <= max) return s;
  const cut = Math.max(s.lastIndexOf('-', max), s.lastIndexOf('_', max), s.lastIndexOf('.', max), s.lastIndexOf(':', max));
  return cut > 3 ? `${s.slice(0, cut + 1)}\n${s.slice(cut + 1)}` : s;
}

/** Selecting a node or link in the map shows a small bar with its summary; "Open details" goes to the full page. */
let topoSel = null;
function topoSelect(node, route) {
  const el = $('#topo-sel'); if (!el) return;
  topoSel = node ? { node } : route ? { route } : null;
  if (!topoSel) { el.hidden = true; el.innerHTML = ''; return; }
  let title; let sub; let st = '';
  if (route) { title = `${route.fe} → ${route.target}`; sub = `Routing rule · ${routeSummary(route)}`; }
  else if (node._key) { const r = indexRows(state.snapshot.rows).get(node._key); title = r && r.kind === 'server' ? node._key.replace('/', ' / ') : node._key.split('/')[0]; sub = `${r ? lbl(r.kind) : node._kind}${r && r.ratePerSec != null ? ` · ${fmtRate(r.ratePerSec)} req/s` : ''}`; st = r ? stBadge(r.state, r.status) : ''; }
  else { title = node.id.slice(8); sub = 'Broken route: not defined'; }
  el.innerHTML = `<div class="ts-t"><b>${esc(title)}</b> ${st}<div class="muted small">${esc(sub)}</div></div>${node && /^(fe|be):/.test(node.id) ? `<button type="button" class="btn" data-topo-toggle="${esc(node.id)}" title="Same as shift-click on the node">${collapsedSet().has(node.id) ? '▸ Expand' : '▾ Collapse'}</button>` : ''}<button type="button" class="btn primary" data-topo-open>Open details →</button><button type="button" class="btn icon" data-topo-sel-x aria-label="Clear selection">✕</button>`;
  el.hidden = false;
}
/** Fold the parts of the map the user collapsed (shift-click a node, or Collapse all): a collapsed entry point hides the pools only it reaches, a collapsed pool hides its members. */
function collapseGraph(nodes, edges) {
  const col = collapsedSet();
  const hidden = new Set(); const srcs = new Map(); const kids = new Map();
  edges.forEach((e) => { if (e.from !== e.to) kids.set(e.from, (kids.get(e.from) || 0) + 1); });
  if (col.size) {
    edges.filter((e) => String(e.id).startsWith('r:')).forEach((e) => (srcs.get(e.to) || srcs.set(e.to, []).get(e.to)).push(e.from));
    for (let changed = true; changed;) {
      changed = false;
      for (const [pool, from] of srcs) if (!hidden.has(pool) && from.every((f) => col.has(f) || hidden.has(f))) { hidden.add(pool); changed = true; }
    }
    const parent = new Map(edges.filter((e) => String(e.id).startsWith('e:sv:')).map((e) => [e.to, e.from]));
    nodes.forEach((n) => { if (n._kind === 'server') { const pa = parent.get(n.id); if (pa && (col.has(pa) || hidden.has(pa))) hidden.add(n.id); } });
  }
  const direct = new Map();
  edges.forEach((e) => { if (col.has(e.from) && hidden.has(e.to)) direct.set(e.from, (direct.get(e.from) || 0) + 1); });
  const out = nodes.filter((n) => !hidden.has(n.id));
  // the arrow under a node says whether it is open (▾, pointing down at what it holds) or folded (▸, pointing right)
  out.forEach((n) => {
    if (!/^(fe|be):/.test(n.id)) return;
    if (col.has(n.id)) { n._collapsed = true; const k = direct.get(n.id) || 0; n.label += `\n▸ ${k ? `${k} hidden` : 'folded'}`; n.borderWidth = 3; }
    else if (kids.get(n.id)) n.label += '\n▾';
  });
  return { nodes: out, edges: edges.filter((e) => !hidden.has(e.from) && !hidden.has(e.to)) };
}
const collapsedSet = () => (state.collapsed || (state.collapsed = new Set()));
function toggleCollapse(id) {
  if (!/^(fe|be):/.test(id)) return;
  const c = collapsedSet(); if (c.has(id)) c.delete(id); else c.add(id);
  renderTopology();
}
function topoCollapseAll(collapse) {
  const c = collapsedSet(); c.clear();
  if (collapse) { cfgSections().forEach((x) => { if (feLike(x) && x.routes.length) c.add(`fe:${x.name}`); else if (beLike(x) && x.type !== 'listen' && x.servers.some((v) => !v.commented)) c.add(`be:${x.name}`); }); }
  else { $('#topo-servers').checked = true; }
  state.focus = null; topoSelect(null); renderTopology();
}
function buildGraph() {
  NODE_COLORS = isLight() ? LIGHT_NODES : DARK_NODES;
  const FG = cssVar('--text') || '#e5eaf3'; const FG2 = cssVar('--muted') || '#cbd5e1'; const BG = cssVar('--bg') || '#0a0f1a';
  const s = state.snapshot; const rows = indexRows(s.rows); const sections = cfgSections();
  const showServers = $('#topo-servers').checked; const q = $('#topo-search').value.trim().toLowerCase();
  const onlyProblems = $('#topo-problems').checked; const urlLabels = $('#topo-urls').checked;
  const mindmap = $('#topo-layout').value === 'mindmap'; // radial: URIs live on the nodes, lines stay clean
  const nodes = []; const edges = []; const ids = new Set();
  const referenced = new Set();
  sections.filter(feLike).forEach((fe) => fe.routes.forEach((r) => { if (!r.commented && !r.dynamic) referenced.add(r.target); }));
  const beNames = new Set(sections.filter(beLike).map((b) => b.name));
  const suspect = new Set();
  sections.filter(feLike).forEach((fe) => fe.routes.forEach((r) => { if (r.maybeUpstream) suspect.add(r.target); }));
  const routeCount = sections.filter(feLike).reduce((n, fe) => n + fe.routes.length, 0);
  const worstOf = (names, prefix) => {
    const st = names.map((n) => (rows.get(`${prefix}/${n}`) || {}).state).filter(Boolean);
    if (!st.length) return null;
    const up = st.filter((x) => x === 'up' || x === 'nocheck').length;
    if (st.every((x) => x === 'down')) return 'down';
    if (st.some((x) => x === 'down' || x === 'degraded')) return 'degraded';
    return up ? 'up' : 'maint';
  };

  sections.filter(feLike).forEach((fe) => {
    const r = rows.get(`${fe.name}/FRONTEND`);
    const id = `fe:${fe.name}`;
    ids.add(id);
    nodes.push({
      id, label: `${wrapName(fe.name)}\n${r && r.ratePerSec != null ? `${fmtRate(r.ratePerSec)}/s` : `${fe.routes.filter((x) => !x.commented).length} route${fe.routes.filter((x) => !x.commented).length === 1 ? '' : 's'}${fe.binds.some((b) => b.ssl && !b.commented) ? ' 🔒' : ''}`} · ${layerOf(fe)}`, shape: 'diamond', size: 24,
      color: NODE_COLORS.fe, borderWidth: 2, shapeProperties: { borderDashes: layerOf(fe) === 'L4' ? [3, 3] : false }, title: layerTip(fe), _layer: layerOf(fe), font: { color: FG, size: 14, face: 'system-ui', vadjust: -2, strokeWidth: 4, strokeColor: BG }, level: 0, _kind: 'frontend', _key: `${fe.name}/FRONTEND`, _section: fe.name, _pool: fe.type === 'listen' && fe.servers.some((x) => !x.commented),
      _problem: Boolean(r && isProblem(r)),
    });
  });

  sections.filter(beLike).forEach((be) => {
    const r = rows.get(`${be.name}/BACKEND`);
    const servers = be.servers.filter((x) => !x.commented);
    const worst = worstOf(servers.map((x) => x.name), be.name) || (r && r.state !== 'up' ? r.state : null);
    const idle = r && (r.stot || 0) === 0;
    const orphan = be.type === 'backend' && !referenced.has(be.name);
    let col = NODE_COLORS.be;
    if (be.implicit && suspect.has(be.name)) col = NODE_COLORS.missing;
    else if (worst === 'down') col = NODE_COLORS.down; else if (worst === 'degraded') col = NODE_COLORS.degraded; else if (idle && s.rows.length) col = NODE_COLORS.idle;
    if (be.type === 'listen') return;
    const id = `be:${be.name}`;
    ids.add(id);
    nodes.push({
      id, label: `${wrapName(be.name)}\n${r ? `${fmtRate(r.ratePerSec)}/s` : `${servers.length} srv`} · ${layerOf(be)}${orphan ? '\n(orphan)' : ''}`, shape: 'hexagon', size: 22,
      color: { ...col, border: orphan ? '#fbbf24' : col.border }, borderWidth: orphan ? 3 : 2, shapeProperties: { borderDashes: orphan ? [5, 4] : layerOf(be) === 'L4' ? [3, 3] : false }, title: layerTip(be), _layer: layerOf(be),
      font: { color: FG, size: 14, face: 'system-ui', strokeWidth: 4, strokeColor: BG }, level: 1, _kind: 'backend', _key: `${be.name}/BACKEND`, _section: be.name,
      _problem: worst === 'down' || worst === 'degraded',
    });
  });

  const serverParent = (be) => (be.type === 'listen' ? `fe:${be.name}` : `be:${be.name}`);
  {
    sections.filter(beLike).forEach((be) => {
      // Members are shown when enabled globally, or for the pool/entry point currently focused.
      // (a focused member counts too: clicking a server must not remove it and its siblings from the graph)
      if (!showServers && state.focus !== `be:${be.name}` && state.focus !== serverParent(be) && !String(state.focus || '').startsWith(`sv:${be.name}/`)) return;
      be.servers.filter((x) => !x.commented && !x.template).forEach((sv) => {
        const r = rows.get(`${be.name}/${sv.name}`);
        const st = r ? r.state : 'idle';
        const col = NODE_COLORS[st] || NODE_COLORS.idle;
        const id = `sv:${be.name}/${sv.name}`;
        ids.add(id);
        nodes.push({
          id, label: `${sv.name}${r && r.ratePerSec != null ? `\n${fmtRate(r.ratePerSec)}/s` : ''}`, shape: 'dot', size: 11 + Math.min(10, Math.log10((r && r.ratePerSec || 0) + 1) * 5),
          color: col, font: { color: FG, size: 12, face: 'system-ui', strokeWidth: 4, strokeColor: BG }, level: 2, _kind: 'server', _key: `${be.name}/${sv.name}`, _section: be.name, _layer: layerOf(be),
          _problem: st === 'down' || st === 'degraded',
        });
        edges.push({ id: `e:${id}`, from: serverParent(be), to: id, color: { color: st === 'down' ? '#f87171' : '#475569' }, width: 1, arrows: { to: { enabled: true, scaleFactor: 0.45 } } });
      });
    });
  }

  const uriBy = new Map(); // node id -> URIs / hosts it handles
  sections.filter(feLike).forEach((fe) => {
    fe.routes.forEach((rt, i) => {
      if (rt.dynamic || selfAnswered(rt)) return;
      let target = `be:${rt.target}`;
      if (!beNames.has(rt.target)) {
        target = `missing:${rt.target}`;
        if (!ids.has(target) && !rt.commented) {
          ids.add(target);
          nodes.push({ id: target, label: `${rt.target}\n(undefined)`, shape: 'box', color: NODE_COLORS.missing, font: { color: FG, size: 12, strokeWidth: 4, strokeColor: BG }, level: 1, _kind: 'missing', _problem: true });
        }
        if (rt.commented) return;
      } else {
        const be = sections.find((x) => x.name === rt.target && beLike(x));
        if (be && be.type === 'listen') target = `fe:${rt.target}`;
      }
      if (!rt.commented) {
        const u = routeUri(rt);
        (uriBy.get(target) || uriBy.set(target, []).get(target)).push(u);
        (uriBy.get(`fe:${fe.name}`) || uriBy.set(`fe:${fe.name}`, []).get(`fe:${fe.name}`)).push(u);
      }
      const br = rows.get(`${rt.target}/BACKEND`);
      const w = br && br.ratePerSec ? 1.5 + Math.min(6, Math.log10(br.ratePerSec + 1) * 2) : 1.5;
      edges.push({
        id: `r:${fe.name}:${i}`, from: `fe:${fe.name}`, to: target, arrows: { to: { enabled: true, scaleFactor: 0.8 } }, width: rt.commented ? 1 : w,
        dashes: rt.commented || rt.type === 'default', color: { color: rt.commented ? '#94a3b8' : (isLight() ? '#0891b2' : '#22d3ee'), opacity: rt.commented ? 0.5 : 0.75 },
        title: routeTitle(fe, rt),
        label: urlLabels && routeCount <= 60 && !mindmap ? (rt.type === 'default' ? 'default' : (rt.short || rt.condition.replace(/^location /, '')).slice(0, 38)) : undefined, font: { size: 11, color: isLight() ? '#0e7490' : '#67e8f9', strokeWidth: 4, strokeColor: BG, align: 'middle' }, _route: { fe: fe.name, ...rt }, smooth: { type: 'cubicBezier', roundness: 0.4 },
      });
    });
  });

  // What each component handles: shown under the node name in the mind map, and in every node's hover tooltip.
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const clip = (t, n = 30) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);
  for (const [id, list] of uriBy) {
    const n = byId.get(id); const all = [...new Set(list)]; if (!n || !all.length) continue;
    n.title = `${n.title ? `${n.title}\n\n` : ''}${n.id.startsWith('fe:') ? 'Handles' : 'Serves'} ${all.length} URL rule${all.length === 1 ? '' : 's'}:\n${all.slice(0, 20).join('\n')}${all.length > 20 ? `\n+${all.length - 20} more` : ''}`;
    if (mindmap && urlLabels) n.font = { ...n.font, background: BG, size: 12 };
    if (mindmap && urlLabels) n.label += `\n${all.slice(0, 3).map((u) => clip(u)).join('\n')}${all.length > 3 ? `\n+${all.length - 3} more` : ''}`;
  }
  if (mindmap && urlLabels) { // members inherit their pool's URIs
    for (const n of nodes) if (n._kind === 'server') {
      const list = [...new Set(uriBy.get(`be:${n._section}`) || uriBy.get(`fe:${n._section}`) || [])];
      if (list.length) { n.title = `${n._key}\nServes: ${list.slice(0, 10).join(', ')}${list.length > 10 ? ` +${list.length - 10}` : ''}`; if (list.length) n.label += `\n${clip(list[0], 22)}${list.length > 1 ? ` +${list.length - 1}` : ''}`; }
    }
  }

  // Filtering (dim non-matching rather than removing, so layout stays stable)
  const layerSel = ($('#topo-layer') || {}).value || '';
  const match = (n) => (!q || n.label.toLowerCase().includes(q) || (n._section || '').toLowerCase().includes(q)) && (!onlyProblems || n._problem) && (!layerSel || !n._layer || n._layer === layerSel);
  for (const n of nodes) {
    n.opacity = match(n) ? 1 : 0.12;
    if (!match(n)) n.font = { ...n.font, color: 'rgba(148,163,184,.25)' };
  }
  if (q || onlyProblems || layerSel) { // links follow their nodes: a link stays lit when at least one end matches
    const lit = new Set(nodes.filter(match).map((n) => n.id));
    for (const e of edges) if (!(lit.has(e.from) || lit.has(e.to))) { dimEdge(e); }
  }
  if (state.focus && ids.has(state.focus)) {
    const out = new Map(); const inn = new Map();
    edges.forEach((e) => { (out.get(e.from) || out.set(e.from, []).get(e.from)).push(e.to); (inn.get(e.to) || inn.set(e.to, []).get(e.to)).push(e.from); });
    const keep = new Set([state.focus]);
    const walk = (adj) => { const q = [state.focus]; while (q.length) { const x = q.pop(); for (const y of adj.get(x) || []) if (!keep.has(y)) { keep.add(y); q.push(y); } } };
    walk(out); walk(inn);
    // Focusing a member keeps its pool-mates visible: the point is to see where it sits, not to hide the rest of the pool.
    if (state.focus.startsWith('sv:')) for (const parent of inn.get(state.focus) || []) for (const sib of out.get(parent) || []) keep.add(sib);
    for (const n of nodes) if (!keep.has(n.id)) { n.opacity = 0.1; n.font = { ...n.font, color: 'rgba(148,163,184,.2)' }; }
    for (const e of edges) if (!(keep.has(e.from) && keep.has(e.to))) { dimEdge(e); }
  }
  const g = collapseGraph(nodes, edges);
  g.nodes.forEach((n) => applyNodeIcon(n, FG, BG));
  return g;
}

// ---------- topology node icons: a rounded badge with a state-coloured ring and a glyph (drawn on the canvas, so dimming and selection still work) ----------
const ICON_PATHS = {
  frontend: ['M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4', 'M10 17l5-5-5-5', 'M15 12H3'], // an arrow entering a bracket: where traffic comes in
  backend: ['M12 2l10 5-10 5L2 7l10-5z', 'M2 17l10 5 10-5', 'M2 12l10 5 10-5'],       // stacked layers: a pool
  server: ['M5 3h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z', 'M5 13h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z', 'M7 7h.01', 'M7 17h.01'],
  missing: ['M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z', 'M12 9v4', 'M12 17h.01'],
};
const ICON_P2D = {}; const NODE_DRAW = new Map();
const DIM_LINE = 'rgba(148,163,184,.14)';
function dimEdge(e) { // explicit faint colours: vis-network does not repaint on an opacity-only change
  e.color = { color: DIM_LINE, highlight: DIM_LINE, hover: DIM_LINE, inherit: false, opacity: 1 };
  e.font = { ...(e.font || {}), color: 'rgba(0,0,0,0)', strokeColor: 'rgba(0,0,0,0)', strokeWidth: 0 };
  e.width = 1; e.dashes = true;
}
function applyNodeIcon(n, FG, BG) {
  const kind = ICON_PATHS[n._kind] ? n._kind : null; if (!kind || typeof Path2D === 'undefined') return;
  const col = n.color || {}; const light = isLight();
  const fill = col.background || '#0e1626'; const ring = col.border || '#22d3ee';
  const dashes = (n.shapeProperties && n.shapeProperties.borderDashes) || null;
  const orphan = /\(orphan\)/.test(n.label || ''); const problem = Boolean(n._problem);
  const r = kind === 'frontend' ? 26 : kind === 'backend' ? 24 : kind === 'missing' ? 21 : Math.round(14 + Math.max(0, (n.size || 11) - 11) * 0.5);
  const label = String(n.label || ''); const alpha = n.opacity == null ? 1 : n.opacity;
  NODE_DRAW.set(n.id, { alpha, fill, ring, dashes, orphan, problem, r, label, light, kind, FG, BG });
  n.shape = 'custom'; n.size = r; n.borderWidth = 0;
  n.ctxRenderer = ({ ctx, x, y, state }) => ({
    drawNode() {
      // read the latest values at draw time: vis-network keeps the first renderer closure, so filters/state changes must not be captured
      const { alpha, fill, ring, dashes, orphan, problem, r, light, kind } = NODE_DRAW.get(n.id) || {};
      ctx.save(); ctx.globalAlpha = alpha;
      if (problem) { ctx.shadowColor = ring; ctx.shadowBlur = 16; }
      ctx.beginPath(); ctx.roundRect(x - r, y - r, 2 * r, 2 * r, r * 0.38); ctx.fillStyle = fill; ctx.fill();
      const hg = ctx.createLinearGradient(x, y - r, x, y + r); hg.addColorStop(0, 'rgba(255,255,255,.16)'); hg.addColorStop(0.6, 'rgba(255,255,255,0)'); ctx.fillStyle = hg; ctx.fill();
      ctx.shadowBlur = 0; ctx.lineWidth = orphan ? 3 : 2.5; ctx.strokeStyle = ring; ctx.setLineDash(orphan ? [5, 4] : dashes || []); ctx.stroke(); ctx.setLineDash([]);
      if (state.selected || state.hover) { ctx.beginPath(); ctx.roundRect(x - r - 5, y - r - 5, 2 * r + 10, 2 * r + 10, r * 0.38 + 5); ctx.lineWidth = 2; ctx.strokeStyle = ring; ctx.globalAlpha = alpha * (state.selected ? 0.9 : 0.45); ctx.stroke(); ctx.globalAlpha = alpha; }
      const sc = (r * 1.05) / 24; ctx.translate(x - 12 * sc, y - 12 * sc); ctx.scale(sc, sc);
      ctx.lineWidth = 1.9; ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.strokeStyle = light ? '#fff' : ring;
      for (const d of ICON_PATHS[kind]) { const p = ICON_P2D[d] || (ICON_P2D[d] = new Path2D(d)); ctx.stroke(p); }
      ctx.restore();
    },
    drawExternalLabel() {
      const { alpha, r, label, light, FG, BG } = NODE_DRAW.get(n.id) || {};
      const lines = label.split('\n'); ctx.save(); ctx.globalAlpha = alpha; ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.lineJoin = 'round';
      let yy = y + r + 7;
      lines.forEach((t, i) => { ctx.font = i === 0 ? '600 13px system-ui, sans-serif' : '11px system-ui, sans-serif'; ctx.lineWidth = 4; ctx.strokeStyle = BG; ctx.strokeText(t, x, yy); ctx.fillStyle = i === 0 ? FG : (light ? '#475569' : '#9fb0c8'); ctx.fillText(t, x, yy); yy += i === 0 ? 16 : 14; });
      ctx.restore();
    },
    nodeDimensions: (() => { const d = (NODE_DRAW.get(n.id) || {}).r || r; return { width: 2 * d, height: 2 * d }; })(),
  });
}

function updateLegend() {
  const l = labels();
  $('#topo-legend-fe').textContent = l.frontend; $('#topo-legend-be').textContent = l.backend;
}
function renderUrlMap() {
  const box = $('#urlmap'); const open = Boolean(state.urlmapOpen);
  const net = $('#topo-layout').value === 'network'; box.hidden = !open || net; $('#topo-urlmap').classList.toggle('on', open);
  if (net) { $('#view-topology').classList.remove('um-max'); return; }
  if (!open || !state.snapshot) return;
  const q = $('#topo-search').value.trim().toLowerCase();
  const rows = [];
  cfgSections().filter(feLike).forEach((fe) => fe.routes.forEach((rt, i) => rows.push({ fe, rt, i })));
  const shown = rows.filter(({ fe, rt }) => !q || `${fe.name} ${rt.target} ${routeSummary(rt)} ${(rt.hosts || []).join(' ')} ${rt.passUrl || ''}`.toLowerCase().includes(q));
  const binds = (fe) => { // compact: one entry per port ("80, 443 🔒")
    const seen = new Map();
    fe.binds.filter((b) => !b.commented).forEach((b) => b.addresses.forEach((a) => { const port = String(a).replace(/^.*:/, ''); seen.set(port, seen.get(port) || b.ssl); }));
    return [...seen].map(([port, ssl]) => `${port}${ssl ? ' 🔒' : ''}`).join(', ');
  };
  const mode = state.urlmapMode || 'normal';
  box.className = `urlmap um-${mode}`; $('#view-topology').classList.toggle('um-max', mode === 'max');
  if (mode === 'normal' && state.urlmapH) box.style.height = `${state.urlmapH}px`; else box.style.height = '';
  box.innerHTML = `<div class="urlmap-grip" data-um-grip title="Drag to resize"></div>
    <div class="urlmap-head"><b>URL map</b> <button class="link" type="button" data-flow-uri title="Ports, rewrites and a request tracer">Routing details →</button> <span class="muted small">${shown.length} of ${rows.length} routing rules${mode === 'min' ? '' : ' · click a row to focus it in the graph'}</span><span class="spacer"></span>
      <button class="btn icon" type="button" data-um="min" title="${mode === 'min' ? 'Restore' : 'Minimize'}" aria-label="${mode === 'min' ? 'Restore URL map' : 'Minimize URL map'}">${mode === 'min' ? '▴' : '▁'}</button>
      <button class="btn icon" type="button" data-um="max" title="${mode === 'max' ? 'Restore size' : 'Expand to full height'}" aria-label="${mode === 'max' ? 'Restore URL map size' : 'Expand URL map'}">${mode === 'max' ? '⤡' : '⤢'}</button>
      <button class="btn icon${document.body.classList.contains('fs-urlmap') ? ' on' : ''}" type="button" data-um-fs title="${document.body.classList.contains('fs-urlmap') ? 'Exit full screen (Esc)' : 'Full screen: only the URL map'}" aria-label="Full screen URL map">${document.body.classList.contains('fs-urlmap') ? '✕' : '⛶'}</button>
      <button class="btn icon" type="button" data-um="close" title="Close" aria-label="Close URL map">✕</button></div>
    <div class="urlmap-scroll"><table class="grid urlmap-table"><thead><tr><th>${esc(lbl('frontend'))}</th><th>Host</th><th>URL / path match</th><th>Target</th><th>${snapshotType() === 'nginx' ? 'Upstream URL' : 'Servers'}</th></tr></thead><tbody>
    ${shown.map(({ fe, rt, i }) => {
    const up = rt.passUrl ? `<code>${esc(rt.passUrl)}</code>${rt.rewriteNote ? `<div class="muted small">${esc(rt.rewriteNote)}</div>` : ''}${(rt.rewrites || []).map((r) => `<div class="muted small mono">rewrite ${esc(r)}</div>`).join('')}` : `<span class="mono small">${esc(poolAddresses(rt.target))}</span>`;
    const missing = !selfAnswered(rt) && routeTargetId(rt).startsWith('missing:');
    return `<tr class="${rt.commented ? 'dim' : ''}" data-urlrow="${esc(fe.name)}|${i}">
        <td><b>${esc(fe.name)}</b> ${layerTag(fe)}<div class="muted small mono">${esc(binds(fe))}</div></td>
        <td class="mono small">${esc((rt.hosts || []).join(', ')) || '<span class="muted">any</span>'}</td>
        <td>${rt.type === 'default' ? '<span class="tag">default</span> <span class="muted">everything else</span>' : `<span class="mono">${esc(rt.match || rt.condition)}</span>`}${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}${snapshotType() === 'haproxy' && rt.rawCondition ? `<div class="muted small mono">${esc(rt.rawCondition)}</div>` : ''}</td>
        <td>${selfAnswered(rt) ? `<span class="muted">${esc(selfLabel(rt))}</span>` : missing ? `<span class="sev-error">${esc(rt.target)} (undefined)</span>` : `<b>${esc(rt.target)}</b>`}</td>
        <td>${up}</td></tr>`;
  }).join('') || '<tr><td colspan="5" class="empty">No routing rules</td></tr>'}</tbody></table></div>`;
}
function renderTopology() {
  updateLegend();
  { // layer filter with counts
    const sel = $('#topo-layer');
    if (sel && state.snapshot) {
      const secs = cfgSections().filter((x) => x.type !== 'defaults' && (feLike(x) || beLike(x)));
      const n7 = secs.filter((x) => layerOf(x) === 'L7').length; const n4 = secs.length - n7; const keep = sel.value;
      const html = `<option value="">All layers</option><option value="L7">L7 · HTTP (${n7})</option><option value="L4">L4 · TCP (${n4})</option>`;
      if (sel.dataset.sig !== html) { sel.innerHTML = html; sel.dataset.sig = html; sel.value = keep; }
      sel.hidden = !n7 || !n4; if (sel.hidden) sel.value = '';
    }
  }
  if (state.topoFor !== state.current && state.snapshot) {
    // Many members make the map unreadable once fitted to the screen: start collapsed, expand on focus.
    state.topoFor = state.current; collapsedSet().clear();
    const total = cfgSections().reduce((n, x) => n + x.servers.filter((v) => !v.commented).length, 0);
    $('#topo-servers').checked = total <= 18;
    $('#graph-hint').textContent = total <= 18 ? 'Click a node to focus its path · shift-click to collapse or expand it · double-click or “Open details” for the full page · click empty space to reset · scroll to zoom'
      : `${total} members are collapsed — click a ${lbl('backend').toLowerCase()} to expand it, or tick “Members” to show all · scroll to zoom`;
    $('#graph-hint').style.opacity = 1;
  }
  if (typeof vis === 'undefined') { $('#graph').innerHTML = '<div class="empty">vis-network failed to load</div>'; return; }
  renderUrlMap();
  const mode = $('#topo-layout').value;
  const treeOn = mode === 'tree'; const netOn = mode === 'network'; const alt = treeOn || netOn;
  $('#tree').hidden = !treeOn; $('#infra').hidden = !netOn; $('#graph-wrap').hidden = alt;
  $$('#view-topology [data-graph-only]').forEach((el) => { el.hidden = alt; });
  ['topo-search', 'topo-problems'].forEach((id) => { const e = $(`#${id}`); if (e) (e.closest('label') || e).hidden = netOn; });
  if (netOn && $('#topo-layer')) $('#topo-layer').hidden = true;
  if (netOn) { renderLbInfra(); return; }
  if (treeOn) { renderTree(); return; }
  const { nodes, edges } = buildGraph();
  let layersSig = null;
  if (mode === 'layers') {
    layoutLayers(nodes, edges);
    // Keep positions the user dragged to while nothing structural changed (the poll re-renders every few seconds).
    layersSig = nodes.map((n) => n.id).sort().join('|');
    if (layersSig === state.layersSig && network) nodes.forEach((n) => { delete n.x; delete n.y; });
  } else layerGuides = null;
  state.layersSig = layersSig;
  if (!network) {
    // Tall tiers (many pools/members) read better top-down on a landscape screen than left-to-right.
    const perTier = {};
    nodes.forEach((n) => { perTier[n.level] = (perTier[n.level] || 0) + 1; });
    const dir = Math.max(...Object.values(perTier), 0) > 6 ? 'UD' : 'LR';
    visNodes = new vis.DataSet(nodes); visEdges = new vis.DataSet(edges);
    network = new vis.Network($('#graph'), { nodes: visNodes, edges: visEdges }, graphOptions(mode, dir));
    network.on('beforeDrawing', drawLayerGuides);
    network.on('click', (p) => {
      if (p.nodes.length) {
        const n = visNodes.get(p.nodes[0]); const ev = p.event && p.event.srcEvent;
        if (ev && (ev.shiftKey || ev.ctrlKey || ev.altKey || ev.metaKey) && /^(fe|be):/.test(n.id)) { toggleCollapse(n.id); return; }
        state.focus = n.id; topoSelect(n);
        renderTopology();
      } else if (p.edges.length) { const e = visEdges.get(p.edges[0]); if (e && e._route) topoSelect(null, e._route); }
      else { const had = state.focus; state.focus = null; topoSelect(null); if (had) renderTopology(); }
    });
    network.on('doubleClick', (p) => {
      if (p.nodes.length) { const n = visNodes.get(p.nodes[0]); if (n && n._key) inspect(n._key, n._kind); else if (n && n._kind === 'missing') inspectMissing(n.id.slice(8)); }
      else if (p.edges.length) { const e = visEdges.get(p.edges[0]); if (e && e._route) inspectRoute(e._route); }
    });
    network.once('stabilized', () => { const h = $('#graph-hint'); if (h) setTimeout(() => { h.style.opacity = 0; }, 6000); });
    // The container may not have its final size yet (view just activated): refit once layout settles.
    [80, 400, 1200].forEach((ms) => setTimeout(() => network && network.fit({ animation: false }), ms));
    return;
  }
  const have = new Set(visNodes.getIds());
  const nextIds = new Set(nodes.map((n) => n.id));
  const firstTime = have.size === 0;
  visNodes.update(nodes);
  have.forEach((id) => { if (!nextIds.has(id)) visNodes.remove(id); });
  const haveE = new Set(visEdges.getIds()); const nextE = new Set(edges.map((e) => e.id));
  visEdges.update(edges); haveE.forEach((id) => { if (!nextE.has(id)) visEdges.remove(id); });
  if (firstTime) network.fit({ animation: false });
}

function exportPng() {
  if (!network) return;
  const src = network.canvas.frame.canvas; const c = document.createElement('canvas');
  c.width = src.width; c.height = src.height;
  const x = c.getContext('2d'); x.fillStyle = cssVar('--bg') || '#0a0f1a'; x.fillRect(0, 0, c.width, c.height); x.drawImage(src, 0, 0);
  c.toBlob((b) => { downloadBlob(`${(state.snapshot.instance.name || 'topology').replace(/[^\w.-]+/g, '_')}-topology.png`, b); toast('Diagram saved as PNG', 'ok'); });
}


// ---------- URL / URI mapping details ----------
// Short "what does this rule match" text for node labels: host + path, e.g. "api.example.com /v1/*".
function routeUri(rt) {
  if (rt.type === 'default') return 'default: everything else';
  const hosts = (rt.hosts || []).join(',');
  const path = (rt.short || rt.match || rt.condition || '').replace(/^location /, '');
  return hosts && !path.includes(hosts) ? `${hosts} ${path}`.trim() : path;
}
const routeSummary = (rt) => (rt.type === 'default' ? 'Any request not matched above (default)' : rt.match || rt.condition);
// The traffic-flow analysis (ports, TLS, URI change) for one routing rule, when it has been loaded.
function flowOf(fe, rt) {
  if (!FLOW.data || FLOW.key !== state.current || rt.commented) return null;
  const name = typeof fe === 'string' ? fe : fe.name;
  return FLOW.data.flows.find((f) => f.frontend === name && f.line === rt.line && f.pool.name === rt.target) || null;
}
function flowLines(f) {
  if (!f) return [];
  const l = f.portMap.map((p) => `${p.listenerTls ? '🔒' : ''}:${p.in} → ${p.out.length ? p.out.map((o) => `:${o}`).join(' ') : '?'} (${TLS_LABEL[p.tls] || p.tls})`);
  if (f.example && f.example.changed) l.push(`Backend receives: ${f.example.in} → ${f.example.out}${f.example.exact ? '' : ' (approx.)'}`);
  return l;
}
function routeTitle(fe, rt) {
  const lines = [`${fe.name} → ${rt.target}${rt.commented ? ' (disabled)' : ''}`, `Match: ${routeSummary(rt)}`, ...flowLines(flowOf(fe, rt))];
  if (rt.hosts && rt.hosts.length) lines.push(`Host: ${rt.hosts.join(', ')}`);
  if (rt.passUrl) lines.push(`${rt.passDirective || 'pass'}: ${rt.passUrl}`);
  if (rt.rewriteNote) lines.push(rt.rewriteNote);
  (rt.rewrites || []).forEach((r) => lines.push(`rewrite ${r}`));
  return lines.join('\n');
}
function poolAddresses(name) {
  const sec = cfgSections().find((x) => x.name === name && (x.type === 'backend' || x.type === 'listen' || x.type === 'upstream'));
  const list = sec ? sec.servers.filter((x) => !x.commented).map((x) => x.address || x.name) : [];
  return list.length ? `${list.slice(0, 3).join(', ')}${list.length > 3 ? ` +${list.length - 3}` : ''}` : '';
}
function routeTargetId(rt) {
  const sec = cfgSections().find((x) => x.name === rt.target && (x.type === 'backend' || x.type === 'listen' || x.type === 'upstream'));
  return sec ? (sec.type === 'listen' ? `fe:${sec.name}` : `be:${sec.name}`) : `missing:${rt.target}`;
}
// Full screen: the topology fills the window (sidebar/header hidden). Uses the browser Fullscreen API when allowed, else just fills the tab.
function setTopoFs(on, mode) {
  // mode: 'map' = only the mind map / tree, 'urlmap' = only the URL map table (independent of each other); anything else = the whole page area
  document.body.classList.toggle('topo-fs', on);
  document.body.classList.toggle('fs-map', Boolean(on && mode === 'map'));
  document.body.classList.toggle('fs-urlmap', Boolean(on && mode === 'urlmap'));
  const b = $('#topo-fs'); if (b) { const m = Boolean(on && mode === 'map'); b.textContent = m ? '✕ Exit full screen' : '⛶ Full screen'; b.classList.toggle('on', m); }
  const u = $('[data-um-fs]'); if (u) { const m = Boolean(on && mode === 'urlmap'); u.textContent = m ? '✕' : '⛶'; u.classList.toggle('on', m); u.title = m ? 'Exit full screen (Esc)' : 'Full screen: only the URL map'; }
  $$('[data-fs]').forEach((x) => { x.textContent = on ? '✕ Exit full screen' : '⛶ Full screen'; x.classList.toggle('on', on); x.setAttribute('aria-pressed', String(on)); });
  const g = $('#gr-fs'); if (g) { g.textContent = on ? '✕ Exit full screen' : '⛶ Full screen'; g.classList.toggle('on', on); g.setAttribute('aria-pressed', String(on)); }
  if (state.view === 'graphs') setTimeout(() => { if (typeof grPaintCards === 'function') grPaintCards(); }, 160);
  if (on && document.documentElement.requestFullscreen && !document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => { /* still fills the tab */ });
  if (!on && document.fullscreenElement) document.exitFullscreen().catch(() => {});
  setTimeout(() => { if (network) { network.setSize('100%', '100%'); network.redraw(); network.fit({ animation: false }); } }, 120);
}
function toggleTopoFs() { setTopoFs(!document.body.classList.contains('topo-fs')); }
function toggleMapFs() { setTopoFs(!document.body.classList.contains('fs-map'), 'map'); }
function toggleUrlmapFs() { setTopoFs(!document.body.classList.contains('fs-urlmap'), 'urlmap'); setTimeout(renderUrlMap, 0); }
/** "Relationships" card: who sends traffic here, where this sends it, and its siblings. Uses the config when present,
 *  otherwise falls back to what runtime stats imply (server -> its backend, backend -> its servers). */
function relationsHtml(r, proxy, sec, srv) {
  const rows = state.snapshot.rows; const idx = indexRows(rows);
  const node = (key, label, sub, kindTag) => {
    const row = idx.get(key);
    return `<div class="item" data-inspect="${esc(key)}">${row ? stBadge(row.state, row.status) : '<span class="tag">cfg</span>'}<div class="t"><b>${esc(label)}</b> ${kindTag ? `<span class="tag">${esc(kindTag)}</span>` : ''}${sub ? `<div class="muted small mono">${esc(sub)}</div>` : ''}</div></div>`;
  };
  const group = (title, items, empty) => `<div class="rel-g"><div class="rel-t">${title}</div>${items.length ? `<div class="list">${items.join('')}</div>` : `<div class="muted small">${empty}</div>`}</div>`;
  const feKey = (n) => `${n}/FRONTEND`; const beKey = (n) => `${n}/BACKEND`;
  const poolKey = (n) => { const t = cfgSections().find((x) => x.name === n); return t && t.type === 'listen' ? feKey(n) : beKey(n); };
  const viaRoutes = (target) => cfgSections().filter(feLike).flatMap((fe) => fe.routes.filter((rt) => rt.target === target && fe.name !== target).map((rt) => ({ fe, rt })));
  const ruleText = (rt) => (rt.type === 'default' ? 'default: any other request' : (rt.match || rt.condition || ''));
  const groups = [];
  if (r.kind === 'server' || r.kind === 'backend') {
    const from = sec ? viaRoutes(proxy) : [];
    groups.push(group('Receives traffic from', from.map(({ fe, rt }) => node(feKey(fe.name), fe.name, ruleText(rt), 'frontend')), sec ? 'No frontend routes here (unused, or only reached via default_backend of a defaults block)' : 'Unknown without the config'));
  }
  if (r.kind === 'server') {
    groups.push(group('Member of', [node(beKey(proxy), proxy, sec ? `${sec.servers.filter((x) => !x.commented).length} servers${sec.balance ? ` · ${sec.balance}` : ''}` : '', sec ? sec.type : 'backend')], ''));
    const sib = rows.filter((x) => x.proxy === proxy && x.kind === 'server' && x.name !== r.name);
    if (sib.length) groups.push(group(`Sibling servers (${sib.length})`, sib.map((x) => node(`${proxy}/${x.name}`, x.name, rowEndpoints(x).addrs[0] || '')), ''));
  } else if (r.kind === 'backend') {
    const sv = rows.filter((x) => x.proxy === proxy && x.kind === 'server');
    groups.push(group(`Sends traffic to (${sv.length} servers)`, sv.map((x) => node(`${proxy}/${x.name}`, x.name, rowEndpoints(x).addrs[0] || '', 'server')), 'No servers reported'));
  } else if (r.kind === 'frontend') {
    const routes = sec ? sec.routes.filter((rt) => !rt.commented) : [];
    groups.push(group(`Routes to (${routes.length})`, routes.map((rt) => {
      if (selfAnswered(rt)) return `<div class="item" ${loc(rt)}><span class="st st-nocheck">proxy</span><div class="t"><b>${esc(selfLabel(rt))}</b><div class="muted small mono">${esc(ruleText(rt))}</div></div></div>`;
      const missing = !cfgSections().some((x) => x.name === rt.target && x.type !== 'frontend');
      return missing ? `<div class="item" ${loc(rt)}><span class="st st-down">missing</span><div class="t"><b>${esc(rt.target)}</b><div class="muted small mono">${esc(ruleText(rt))}</div></div></div>`
        : node(poolKey(rt.target), rt.target, ruleText(rt), 'backend');
    }), sec ? 'No routing rules' : 'Unknown without the config'));
  }
  const hint = sec ? '' : `<div class="rel-hint">Runtime stats do not say which frontend routes to which backend. Attach the config (Settings → edit connection → config path or paste) to see the full chain.</div>`;
  return `<h4>Relationships</h4>${groups.join('')}${hint}`;
}
// Where a row lives: listening ports (frontend), member endpoints (backend) or its parent pool (server).
function endpointsHtml(r, sec, srv) {
  if (!sec) return '';
  const st = new Map(state.snapshot.rows.filter((x) => x.proxy === sec.name && x.kind === 'server').map((x) => [x.name, x]));
  if (srv) return `<h4>Endpoint</h4>${kv([['Address', `<code>${esc(srv.address || '–')}</code>`], ['Port', esc(portOf(srv.address) || '–')], ['Member of', `<b>${esc(sec.name)}</b> <span class="muted">(${esc(sec.type)})</span>`]])}`;
  let html = '';
  const binds = sec.binds.filter((b) => !b.commented);
  if (binds.length) html += `<h4>Listening on</h4><div class="list">${binds.map((b) => `<div class="item" ${loc(b)}><span class="tag">${esc(portOf(b.addresses[0]) || 'port')}</span><div class="t mono small">${esc(b.addresses.join(', '))}${b.ssl ? ' 🔒 TLS' : ''}</div></div>`).join('')}</div>`;
  const svs = sec.servers.filter((x) => !x.commented);
  if (svs.length) html += `<h4>Servers (${svs.length})</h4><div class="list">${svs.map((x) => { const row = st.get(x.name); return `<div class="item" data-inspect="${esc(sec.name)}/${esc(x.name)}">${row ? stBadge(row.state, row.status) : '<span class="tag">cfg</span>'}<div class="t"><b>${esc(x.name)}</b><div class="mono small muted">${esc(x.address)}</div></div></div>`; }).join('')}</div>`;
  return html;
}
function urlMappingsHtml(sec, reachedOnly) {
  let html = '';
  const item = (rt, text, extra) => `<div class="item" ${loc(rt)}><span class="tag">${rt.type === 'default' ? 'default' : 'match'}</span><div class="t mono small">${text}${extra || ''}</div></div>`;
  if (!reachedOnly && sec.routes && sec.routes.length) {
    html += `<h4>URL mappings</h4><div class="list">${sec.routes.map((rt) => item(rt, `${esc(rt.type === 'default' ? 'any other request' : (rt.match || rt.condition))} → <b>${esc(rt.target)}</b>${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}`,
      `${rt.passUrl ? `<div class="muted">${esc(rt.passUrl)}</div>` : ''}${rt.rewriteNote ? `<div class="muted">${esc(rt.rewriteNote)}</div>` : ''}`)).join('')}</div>`;
  }
  const from = cfgSections().filter(feLike).flatMap((fe) => fe.routes.filter((rt) => rt.target === sec.name && fe.name !== sec.name).map((rt) => ({ fe, rt })));
  if (from.length) html += `<h4>Reached via</h4><div class="list">${from.map(({ fe, rt }) => item(rt, `<b>${esc(fe.name)}</b>: ${esc(rt.type === 'default' ? 'default' : (rt.match || rt.condition))}${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}`)).join('')}</div>`;
  return html;
}

// ---------- "Tree" layout: the whole estate as an outline, like the `tree` command ----------
let treeText = '';
function buildTree() {
  const s = state.snapshot; const rows = indexRows(s.rows); const secs = cfgSections();
  const q = $('#topo-search').value.trim().toLowerCase(); const onlyProblems = $('#topo-problems').checked;
  const mk = (html, text, o = {}) => ({ html, text, children: [], ...o });
  const ports = (r) => { const e = rowEndpoints(r); return e.ports.length ? ` :${e.ports.slice(0, 4).join(',')}${e.ports.length > 4 ? '…' : ''}` : ''; };
  const rate = (r) => (r && r.ratePerSec != null ? ` ${fmtRate(r.ratePerSec)}/s` : '');
  const badge = (r) => (r ? stBadge(r.state, r.status) : '');
  const serverNodes = (sec) => sec.servers.filter((x) => !x.commented).map((sv) => {
    const r = rows.get(`${sec.name}/${sv.name}`);
    return mk(`${badge(r)} <b>${esc(sv.name)}</b> <span class="mono muted">${esc(sv.address || '')}</span>`, `${sv.name}  ${sv.address || ''}${r ? `  [${r.state}]` : ''}`, { key: `${sec.name}/${sv.name}`, kind: 'server', problem: Boolean(r && isProblem(r)) });
  });
  const poolNode = (sec, via) => {
    const r = rows.get(`${sec.name}/BACKEND`) || rows.get(`${sec.name}/FRONTEND`);
    const kids = serverNodes(sec);
    return mk(`${badge(r)} <b>${esc(sec.name)}</b> <span class="tag">${esc(lbl('backend').toLowerCase())}</span> ${layerTag(sec)}${sec.balance ? ` <span class="muted small">${esc(sec.balance)}</span>` : ''}<span class="muted small">${esc(rate(r))}</span>`,
      `${sec.name}  (${lbl('backend').toLowerCase()}, ${layerOf(sec)}${sec.balance ? `, ${sec.balance}` : ''})${r ? `  [${r.state}]` : ''}`, { key: `${sec.name}/BACKEND`, kind: 'backend', children: kids, problem: Boolean(r && isProblem(r)) || kids.some((k) => k.problem), via });
  };
  const fronts = secs.filter(feLike).map((fe) => {
    const r = rows.get(`${fe.name}/FRONTEND`);
    const kids = [];
    fe.routes.forEach((rt) => {
      if (rt.dynamic) return;
      const tgt = secs.find((x) => x.name === rt.target && beLike(x) && x.name !== fe.name);
      const uri = routeUri(rt);
      const rule = mk(`<span class="uri">${esc(uri)}</span>${rt.commented ? ' <span class="muted">(disabled)</span>' : ''}${rt.passUrl ? ` <span class="muted small mono">→ ${esc(rt.passUrl)}</span>` : ''}`, `${uri}${rt.commented ? ' (disabled)' : ''}`, { kind: 'rule', dim: rt.commented });
      rule.children = tgt ? [poolNode(tgt)] : selfAnswered(rt) ? [mk(`<span class="st st-nocheck">proxy</span> ${esc(selfLabel(rt))}`, `${selfLabel(rt)}  [answered by the proxy]`, { kind: 'rule' })] : [mk(`<span class="st st-down">undefined</span> <b>${esc(rt.target)}</b>`, `${rt.target}  [undefined]`, { kind: 'missing', problem: true })];
      kids.push(rule);
    });
    if (fe.type === 'listen') kids.push(...serverNodes(fe));
    return mk(`${badge(r)} <b>${esc(fe.name)}</b> <span class="tag">${esc(lbl('frontend').toLowerCase())}</span> ${layerTag(fe)} <span class="mono muted">${esc(ports({ kind: 'frontend', proxy: fe.name }).trim())}</span>${fe.binds.some((b) => b.ssl && !b.commented) ? ' 🔒' : ''}<span class="muted small">${esc(rate(r))}</span>`,
      `${fe.name}  (${lbl('frontend').toLowerCase()}, ${layerOf(fe)}${ports({ kind: 'frontend', proxy: fe.name }) ? `,${ports({ kind: 'frontend', proxy: fe.name })}` : ''})${r ? `  [${r.state}]` : ''}`, { key: `${fe.name}/FRONTEND`, kind: 'frontend', children: kids, problem: Boolean(r && isProblem(r)) });
  });
  const used = new Set(secs.filter(feLike).flatMap((fe) => fe.routes.filter((rt) => !rt.commented).map((rt) => rt.target)));
  const stray = secs.filter((x) => x.type === 'backend' && !used.has(x.name)).map((x) => poolNode(x));
  const root = mk(`<b>${esc(s.instance.name || 'Instance')}</b> <span class="muted small">${esc(TYPE_NAME[snapshotType()] || '')}</span>`, s.instance.name || 'Instance', { kind: 'root' });
  root.children = [...fronts];
  if (stray.length) root.children.push(mk(`<b>Not routed</b> <span class="muted small">no frontend sends traffic here</span>`, 'Not routed (no frontend sends traffic here)', { kind: 'group', children: stray }));
  // filter: keep a node when it or any descendant matches; problems-only keeps branches with a problem
  const keep = (n) => { n.children = n.children.filter(keep); const self = !q || n.text.toLowerCase().includes(q); return (n.kind === 'root') || ((self || n.children.length) && (!onlyProblems || n.problem || n.children.length)); };
  keep(root);
  return root;
}
function treeAscii(n, prefix = '', last = true, top = true) {
  let out = top ? `${n.text}\n` : `${prefix}${last ? '└── ' : '├── '}${n.text}\n`;
  const next = top ? '' : prefix + (last ? '    ' : '│   ');
  n.children.forEach((c, i) => { out += treeAscii(c, next, i === n.children.length - 1, false); });
  return out;
}
function renderTree() {
  const root = buildTree(); treeText = treeAscii(root);
  const li = (n) => `<li class="${n.children.length ? 'has' : ''}${n.dim ? ' dim' : ''}${closedTree.has(n.text) ? ' closed' : ''}"><div class="tn k-${n.kind}"${n.key ? ` data-inspect="${esc(n.key)}"` : ''} data-tk="${esc(n.text)}">${n.children.length ? `<span class="tg" data-tg>${closedTree.has(n.text) ? '▸' : '▾'}</span>` : '<span class="tg lf">•</span>'}${n.html}</div>${n.children.length ? `<ul>${n.children.map(li).join('')}</ul>` : ''}</li>`;
  $('#tree').innerHTML = `<div class="tree-bar"><b>Tree</b> <span class="muted small">${root.children.length ? 'click ▾ to fold · click a name for details' : ''}</span><span class="spacer"></span><button class="btn" type="button" data-tree="open">Expand all</button><button class="btn" type="button" data-tree="close">Collapse all</button><button class="btn" type="button" data-tree="copy">Copy as text</button></div>
    <ul class="tree root">${li(root)}</ul>${root.children.length ? '' : '<div class="empty">Nothing to show. Attach a config to see the structure.</div>'}`;
}
const closedTree = new Set();

// ---------- "Layers" layout: entry points on top, pools below, members under them; unconnected items collected on the left ----------
let layerGuides = null;
const LY = { slot: 170, mem: 66, rowY: 230, strayMemPerRow: 3, strayGap: 150 };

function layoutLayers(nodes, edges) {
  layerGuides = null;
  if (!nodes.length) return;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const routeEdges = edges.filter((e) => String(e.id).startsWith('r:') && !(e._route && e._route.commented) && byId.has(e.from) && byId.has(e.to));
  const members = new Map(); // parent id -> member nodes (sv:)
  edges.filter((e) => String(e.id).startsWith('e:sv:')).forEach((e) => { if (byId.has(e.from) && byId.has(e.to)) (members.get(e.from) || members.set(e.from, []).get(e.from)).push(byId.get(e.to)); });
  const wired = new Set();
  routeEdges.forEach((e) => { wired.add(e.from); wired.add(e.to); });
  nodes.filter((n) => n._pool || n._collapsed).forEach((n) => wired.add(n.id)); // a `listen` with servers is its own pool; a collapsed entry point keeps its place
  const isMember = (n) => n.id.startsWith('sv:');

  const stray = nodes.filter((n) => !isMember(n) && !wired.has(n.id));
  const fes = nodes.filter((n) => n._kind === 'frontend' && !n._pool && wired.has(n.id));
  const pools = nodes.filter((n) => !isMember(n) && wired.has(n.id) && !fes.includes(n));

  // order pools by the position of the entry points that reach them, entry points by name first
  fes.sort((a, b) => a.id.localeCompare(b.id));
  const feIdx = new Map(fes.map((n, i) => [n.id, i]));
  const bary = (n) => { const xs = routeEdges.filter((e) => e.to === n.id && feIdx.has(e.from)).map((e) => feIdx.get(e.from)); return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 1e6; };
  pools.sort((a, b) => bary(a) - bary(b) || a.id.localeCompare(b.id));

  const y0 = 0; const y1 = LY.rowY; const y2 = LY.rowY * 2 - 30;
  const center = new Map(); let cursor = 0;
  for (const n of pools) {
    const mem = members.get(n.id) || [];
    const w = Math.max(LY.slot, mem.length * LY.mem + 20);
    n.x = cursor + w / 2; n.y = y1; center.set(n.id, n.x);
    mem.forEach((m, j) => { m.x = cursor + (w - mem.length * LY.mem) / 2 + (j + 0.5) * LY.mem; m.y = y2 + (j % 2) * 34; });
    cursor += w + 24;
  }
  // entry points sit above the middle of the pools they route to
  const desired = fes.map((n) => {
    const xs = routeEdges.filter((e) => e.from === n.id && center.has(e.to)).map((e) => center.get(e.to));
    return { n, x: xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0 };
  }).sort((a, b) => a.x - b.x);
  let last = -Infinity;
  for (const d of desired) { d.x = Math.max(d.x, last + LY.slot + 20); d.n.x = d.x; d.n.y = y0; last = d.x; }

  const placed = nodes.filter((n) => n.x != null);
  const minX = placed.length ? Math.min(...placed.map((n) => n.x)) : 0;
  placed.forEach((n) => { n.x -= minX - 30; });

  // unconnected items: a column on the left, each with its own members beside it
  let strayW = 0; let sy = y0;
  const strayOrder = [...stray.filter((n) => n._kind === 'frontend'), ...stray.filter((n) => n._kind !== 'frontend')];
  for (const n of strayOrder) {
    const mem = members.get(n.id) || [];
    n.x = 0; n.y = sy;
    mem.forEach((m, j) => { m.x = 120 + (j % LY.strayMemPerRow) * 100; m.y = sy + Math.floor(j / LY.strayMemPerRow) * 56; });
    strayW = Math.max(strayW, mem.length ? 120 + Math.min(mem.length, LY.strayMemPerRow) * 100 : 60);
    sy += Math.max(1, Math.ceil(mem.length / LY.strayMemPerRow)) * 56 + 78;
  }
  const strayShift = -(strayW + LY.strayGap);
  strayOrder.forEach((n) => { n.x += strayShift; (members.get(n.id) || []).forEach((m) => { m.x += strayShift; }); });
  edges.forEach((e) => { e.smooth = { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 }; if (e.label) e.font = { ...(e.font || {}), align: 'horizontal' }; });

  layerGuides = {
    labelX: -44,
    tiers: [fes.length && { y: y0, label: 'ENTRY POINTS' }, pools.length && { y: y1, label: 'POOLS' }, pools.some((n) => (members.get(n.id) || []).length) && { y: y2, label: 'MEMBERS' }].filter(Boolean),
    stray: strayOrder.length ? { x0: strayShift - 70, x1: strayShift + strayW + 40, y0: y0 - 62, y1: Math.max(sy, y0 + 80) - 16, count: strayOrder.length } : null,
    hasMain: fes.length + pools.length > 0,
  };
}

function drawLayerGuides(ctx) {
  const g = layerGuides; if (!g || $('#topo-layout').value !== 'layers') return;
  const muted = cssVar('--muted') || '#8b97ad'; const line = cssVar('--line') || '#243049';
  ctx.save();
  ctx.font = '600 11px system-ui'; ctx.textBaseline = 'middle'; ctx.textAlign = 'right'; ctx.fillStyle = muted; ctx.globalAlpha = 0.7;
  if (g.hasMain) for (const t of g.tiers) ctx.fillText(t.label, g.labelX, t.y);
  if (g.stray) {
    const s = g.stray; ctx.globalAlpha = 1;
    ctx.fillStyle = isLight() ? 'rgba(100,116,139,.07)' : 'rgba(148,163,184,.05)'; ctx.strokeStyle = line; ctx.setLineDash([6, 5]); ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.roundRect(s.x0, s.y0, s.x1 - s.x0, s.y1 - s.y0, 14); ctx.fill(); ctx.stroke(); ctx.setLineDash([]);
    ctx.textAlign = 'left'; ctx.fillStyle = muted; ctx.font = '600 11px system-ui';
    ctx.fillText(`NOT CONNECTED (${s.count})`, s.x0 + 14, s.y0 + 16);
  }
  ctx.restore();
}

function graphOptions(mode, dir = 'LR') {
  const flow = mode === 'flow';
  if (mode === 'layers') return { layout: { hierarchical: false }, physics: { enabled: false }, interaction: { hover: true, tooltipDelay: 150, navigationButtons: false }, nodes: { borderWidth: 2, scaling: { label: { enabled: false } } }, edges: { smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 }, font: { size: 9 } } };
  return {
    layout: flow ? { hierarchical: { enabled: true, direction: dir, sortMethod: 'directed', levelSeparation: dir === 'LR' ? 270 : 150, nodeSpacing: dir === 'LR' ? 104 : 130, treeSpacing: 90, shakeTowards: 'roots' } } : { hierarchical: false },
    physics: flow ? { enabled: false } : { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -150, springLength: 190, avoidOverlap: 0.8 }, stabilization: { iterations: 250 } },
    interaction: { hover: true, tooltipDelay: 150, navigationButtons: false },
    nodes: { borderWidth: 2, scaling: { label: { enabled: false, drawThreshold: 2 } } }, edges: { smooth: { type: 'cubicBezier', roundness: 0.4 }, font: { size: 9 } },
  };
}

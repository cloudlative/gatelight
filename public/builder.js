'use strict';
/* global state, $, $$, esc, api, toast, TYPE_NAME, availableTypes, productInfo */
/**
 * Config Builder: describe sites, routes and server pools once, get a configuration for HAProxy, NGINX, Apache,
 * Caddy or Traefik. Every result is parsed back, validated against the documentation of the chosen version and
 * audited on the server (POST /api/build) before it is shown. Nothing is deployed.
 */
const BD = { product: 'nginx', version: '', spec: null, out: null, compare: null, file: 0, loading: false, err: null, errors: null, timer: null, seq: 0, products: null };
const BD_KEY = 'gatelight.builder.v1';

function bdSave() { try { localStorage.setItem(BD_KEY, JSON.stringify({ product: BD.product, version: BD.version, spec: BD.spec })); } catch { /* storage unavailable */ } }
function bdLoad() { try { return JSON.parse(localStorage.getItem(BD_KEY) || 'null'); } catch { return null; } }
const bdClone = (o) => JSON.parse(JSON.stringify(o));
const newSite = (n) => ({ name: `site${n}`, hosts: [], tls: { mode: 'acme', email: '' }, routes: [], defaultPool: (BD.spec && BD.spec.pools[0] && BD.spec.pools[0].name) || null, securityHeaders: true, compression: true });
const newPool = (n) => ({ name: `pool${n}`, balance: 'roundrobin', servers: [{ address: '10.0.0.10:8080' }], healthCheck: { path: '/health', interval: 5 }, scheme: 'http', timeouts: { connect: 5, server: 60 } });

async function renderBuilder() {
  const el = $('#view-builder');
  if (!BD.products) {
    try {
      const r = await api('/build/example');
      BD.products = r.products; BD.example = r.spec;
      const saved = bdLoad();
      if (saved && saved.spec) { BD.spec = saved.spec; BD.product = saved.product || BD.product; BD.version = saved.version || ''; } else BD.spec = bdClone(r.spec);
    } catch (e) { el.innerHTML = `<div class="panel"><div class="empty">${esc(e.message)}</div></div>`; return; }
  }
  if (!BD.products.some((p) => p.type === BD.product) && BD.products[0]) BD.product = BD.products[0].type;
  bdRenderAll();
  bdRun();
}

function bdRenderAll() {
  const el = $('#view-builder');
  const prod = BD.products.find((p) => p.type === BD.product);
  const vers = prod && prod.versions && prod.versions.list ? prod.versions.list : [];
  el.innerHTML = `<div class="page-help" role="note"><b>Config Builder</b> writes a new configuration from a few answers: your sites, how paths are routed and which servers answer. Pick a product to get its configuration, checked against the official documentation for the version you choose. To check or fix an existing configuration instead, open <button type="button" class="link" data-goto="forge">Config Doctor</button>.</div>
    <div class="panel bd-top">
      <div class="bd-prods" role="radiogroup" aria-label="Product">${BD.products.map((p) => `<button type="button" class="chip${p.type === BD.product && !BD.compare ? ' on' : ''}" role="radio" aria-checked="${p.type === BD.product && !BD.compare}" data-bd-prod="${p.type}">${esc(p.name)}</button>`).join('')}<button type="button" class="chip${BD.compare ? ' on' : ''}" data-bd-compare title="Build for every product and compare the checks">Compare all</button></div>
      <div class="bd-ctl">
        <label class="small muted">Version <select id="bd-version" aria-label="Target version"${BD.compare ? ' disabled' : ''}><option value="">Latest${prod && prod.versions ? ` (${esc(prod.versions.latest)})` : ''}</option>${vers.map((v) => `<option value="${esc(v)}"${BD.version === v ? ' selected' : ''}>${esc(TYPE_NAME[BD.product])} ${esc(v)}</option>`).join('')}</select></label>
        ${BD.product === 'apache' && !BD.compare ? `<label class="small muted">Layout <select id="bd-layout" aria-label="Apache layout">${[['debian', 'apache2 (Debian / Ubuntu)'], ['rhel', 'httpd (RHEL / Fedora)'], ['standalone', 'httpd, one httpd.conf (source build)']].map(([v, l]) => `<option value="${v}"${((BD.spec.options || {}).layout || 'debian') === v ? ' selected' : ''}>${l}</option>`).join('')}</select></label>` : ''}
        <span class="spacer"></span>
        <button class="btn" type="button" data-bd-example>Load example</button>
        <button class="btn" type="button" data-bd-clear>Start empty</button>
        <button class="btn" type="button" data-bd-export title="Download this description as JSON, to keep or to load again">Export spec</button>
        <label class="btn" title="Load a spec exported earlier">Import spec<input type="file" accept=".json,application/json" id="bd-import" hidden></label>
      </div>
    </div>
    <div class="bd-grid">
      <form class="bd-form" id="bd-form" autocomplete="off" novalidate>${bdFormHtml()}</form>
      <section class="bd-out" id="bd-out" aria-live="polite">${bdOutHtml()}</section>
    </div>`;
}

// ---------------------------------------------------------------- form
const chk = (path, on, label, title = '') => `<label class="check"${title ? ` title="${esc(title)}"` : ''}><input type="checkbox" data-bd="${path}"${on ? ' checked' : ''}> ${label}</label>`;
const inp = (path, val, label, attrs = '') => `<label class="fld"><span>${label}</span><input data-bd="${path}" value="${esc(val == null ? '' : val)}" ${attrs}></label>`;
const sel = (path, val, opts, label) => `<label class="fld"><span>${label}</span><select data-bd="${path}">${opts.map(([v, t]) => `<option value="${esc(v)}"${String(val) === String(v) ? ' selected' : ''}>${esc(t)}</option>`).join('')}</select></label>`;

function bdFormHtml() {
  const s = BD.spec;
  const pools = s.pools.map((p) => [p.name, p.name]);
  const sites = s.sites.map((x, i) => {
    const t = x.tls || {}; const mode = t.mode || 'none';
    const routes = (x.routes || []).map((r, j) => `<tr>
      <td><input data-bd="sites.${i}.routes.${j}.path" value="${esc(r.path || '')}" aria-label="Path" placeholder="/api/"></td>
      <td><select data-bd="sites.${i}.routes.${j}.match" aria-label="Match">${[['prefix', 'starts with'], ['exact', 'is exactly']].map(([v, l]) => `<option value="${v}"${(r.match || 'prefix') === v ? ' selected' : ''}>${l}</option>`).join('')}</select></td>
      <td><select data-bd="sites.${i}.routes.${j}.pool" aria-label="Pool">${pools.map(([v]) => `<option${r.pool === v ? ' selected' : ''}>${esc(v)}</option>`).join('')}</select></td>
      <td class="c"><input type="checkbox" data-bd="sites.${i}.routes.${j}.stripPrefix"${r.stripPrefix ? ' checked' : ''} aria-label="Strip the prefix" title="Remove the matched prefix before passing the request on"></td>
      <td><input data-bd="sites.${i}.routes.${j}.rewriteTo" value="${esc(r.rewriteTo || '')}" aria-label="Rewrite to" placeholder="(unchanged)"></td>
      <td><button class="btn icon" type="button" data-bd-del="sites.${i}.routes.${j}" aria-label="Remove route">✕</button></td></tr>`).join('');
    const users = x.basicAuth && x.basicAuth.users ? x.basicAuth.users.map((u) => `${u.user}:${u.hash}`).join('\n') : '';
    return `<fieldset class="bd-card"><legend>Site <b>${esc(x.name)}</b></legend><button class="btn icon bd-x" type="button" data-bd-del="sites.${i}" aria-label="Remove site" title="Remove site">✕</button>
      <div class="bd-row">${inp(`sites.${i}.name`, x.name, 'Name')}${inp(`sites.${i}.hosts`, (x.hosts || []).join(', '), 'Host names <span class="muted">(comma separated; empty = any)</span>', 'placeholder="shop.example.com, www.shop.example.com"')}</div>
      <div class="bd-row">${sel(`sites.${i}.tls.mode`, mode, [['acme', 'HTTPS, automatic certificate (ACME)'], ['files', 'HTTPS, certificate files'], ['none', 'Plain HTTP only']], 'Encryption')}
        ${mode === 'files' ? `${inp(`sites.${i}.tls.cert`, t.cert, 'Certificate file', 'placeholder="/etc/ssl/site/fullchain.pem"')}${inp(`sites.${i}.tls.key`, t.key, 'Key file', 'placeholder="/etc/ssl/site/privkey.pem"')}` : mode === 'acme' ? inp(`sites.${i}.tls.email`, t.email, 'ACME contact e-mail <span class="muted">(optional)</span>', 'type="email" placeholder="ops@example.com"') : ''}</div>
      ${mode !== 'none' ? `<div class="bd-checks">${chk(`sites.${i}.tls.redirectHttp`, t.redirectHttp !== false, 'Redirect HTTP to HTTPS')}${chk(`sites.${i}.tls.hsts`, t.hsts !== false, 'HSTS', 'Strict-Transport-Security: browsers only use HTTPS for this site from now on')}${sel(`sites.${i}.tls.minVersion`, t.minVersion || '1.2', [['1.2', 'TLS 1.2 and newer'], ['1.3', 'TLS 1.3 only']], 'Minimum TLS')}</div>` : ''}
      <div class="bd-sub">Routes <span class="muted small">longest path wins; everything else goes to the default pool</span></div>
      <table class="grid bd-routes"><thead><tr><th>Path</th><th>Match</th><th>Pool</th><th title="Strip the prefix">Strip</th><th>Rewrite to</th><th></th></tr></thead><tbody>${routes || '<tr><td colspan="6" class="muted small">No path routes: all requests go to the default pool.</td></tr>'}</tbody></table>
      <button class="btn" type="button" data-bd-add-route="${i}">+ Route</button>
      <div class="bd-row">${sel(`sites.${i}.defaultPool`, x.defaultPool || '', [['', '(none: answer 404)'], ...pools], 'Default pool')}${inp(`sites.${i}.redirectTo`, x.redirectTo || '', 'Or redirect everything to', 'placeholder="https://www.example.com/"')}</div>
      <details class="bd-more"><summary>Security and limits</summary>
        <div class="bd-checks">${chk(`sites.${i}.securityHeaders`, x.securityHeaders !== false, 'Security headers')}${chk(`sites.${i}.compression`, x.compression !== false, 'Compression')}${chk(`sites.${i}.websocket`, x.websocket, 'WebSocket')}</div>
        <div class="bd-row">${inp(`sites.${i}.rateLimit.rps`, x.rateLimit ? x.rateLimit.rps : '', 'Rate limit <span class="muted">(requests/s per client)</span>', 'type="number" min="0" placeholder="off"')}${inp(`sites.${i}.rateLimit.burst`, x.rateLimit ? x.rateLimit.burst : '', 'Burst', 'type="number" min="0"')}${inp(`sites.${i}.maxBodyMb`, x.maxBodyMb == null ? '' : x.maxBodyMb, 'Max upload (MB)', 'type="number" min="0" placeholder="default"')}</div>
        <label class="fld"><span>Basic auth users <span class="muted">(one <code>user:bcrypt-hash</code> per line, e.g. from <code>htpasswd -nbB user pw</code>; never a plain password)</span></span><textarea data-bd="sites.${i}.basicAuth.users" rows="2" spellcheck="false" placeholder="admin:$2y$10$...">${esc(users)}</textarea></label>
      </details>
    </fieldset>`;
  }).join('');
  const poolHtml = s.pools.map((p, i) => {
    const hc = p.healthCheck;
    const servers = (p.servers || []).map((v) => [v.address, v.weight != null && v.weight !== '' ? `weight=${v.weight}` : '', v.backup ? 'backup' : ''].filter(Boolean).join(' ')).join('\n');
    return `<fieldset class="bd-card"><legend>Pool <b>${esc(p.name)}</b></legend><button class="btn icon bd-x" type="button" data-bd-del="pools.${i}" aria-label="Remove pool" title="Remove pool">✕</button>
      <div class="bd-row">${inp(`pools.${i}.name`, p.name, 'Name')}${sel(`pools.${i}.balance`, p.balance || 'roundrobin', [['roundrobin', 'Round robin'], ['leastconn', 'Least connections'], ['iphash', 'Client IP hash'], ['random', 'Random']], 'Balancing')}${sel(`pools.${i}.scheme`, p.scheme || 'http', [['http', 'HTTP to servers'], ['https', 'HTTPS to servers']], 'Protocol')}</div>
      <label class="fld"><span>Servers <span class="muted">(one <code>host:port</code> per line; add <code>weight=N</code> or <code>backup</code>)</span></span><textarea data-bd="pools.${i}.servers" rows="${Math.max(2, (p.servers || []).length)}" spellcheck="false">${esc(servers)}</textarea></label>
      <div class="bd-checks">${chk(`pools.${i}.hc`, Boolean(hc), 'Health check')}${hc ? `${inp(`pools.${i}.healthCheck.path`, hc.path, 'Path')}${inp(`pools.${i}.healthCheck.interval`, hc.interval || 5, 'Every (s)', 'type="number" min="1"')}` : ''}${chk(`pools.${i}.sticky`, p.sticky, 'Sticky sessions', 'Keep a client on the same server (cookie)')}${p.scheme === 'https' ? chk(`pools.${i}.verifyTls`, p.verifyTls !== false, 'Verify server certificates') : ''}</div>
      <div class="bd-row">${inp(`pools.${i}.timeouts.connect`, p.timeouts ? p.timeouts.connect : 5, 'Connect timeout (s)', 'type="number" min="1"')}${inp(`pools.${i}.timeouts.server`, p.timeouts ? p.timeouts.server : 60, 'Response timeout (s)', 'type="number" min="1"')}</div>
    </fieldset>`;
  }).join('');
  const o = s.options || {}; const sp = o.statusPage || {};
  return `<div class="bd-h"><h3>Sites</h3><button class="btn" type="button" data-bd-add-site>+ Site</button></div>${sites || '<p class="muted">No sites yet.</p>'}
    <div class="bd-h"><h3>Server pools</h3><button class="btn" type="button" data-bd-add-pool>+ Pool</button></div>${poolHtml || '<p class="muted">No pools yet.</p>'}
    <fieldset class="bd-card"><legend>Options</legend>
      <div class="bd-checks">${chk('options.accessLog', o.accessLog !== false, 'Access log')}${sel('options.logFormat', o.logFormat || 'combined', [['combined', 'Combined (text)'], ['json', 'JSON']], 'Log format')}${chk('options.statusPage.enabled', sp.enabled, 'Status page / metrics')}</div>
      ${sp.enabled ? `<div class="bd-row">${inp('options.statusPage.port', sp.port || 8404, 'Status port', 'type="number" min="1" max="65535"')}${inp('options.statusPage.allow', (sp.allow || ['127.0.0.1']).join(', '), 'Allowed from', 'placeholder="127.0.0.1, 10.0.0.0/8"')}</div>` : ''}
      <div class="bd-row">${inp('options.clientTimeout', o.clientTimeout || 60, 'Client timeout (s)', 'type="number" min="1"')}${inp('options.maxConnections', o.maxConnections || 10000, 'Max connections', 'type="number" min="1"')}</div>
    </fieldset>`;
}

/** Write one form control back into the spec. */
function bdSet(path, el) {
  const parts = path.split('.');
  const last = parts.pop();
  let o = BD.spec;
  for (const k of parts) { if (o[k] == null) o[k] = /^\d+$/.test(k) ? [] : {}; o = o[k]; }
  const v = el.type === 'checkbox' ? el.checked : el.value;
  if (last === 'hosts') o.hosts = String(v).split(/[\s,]+/).filter(Boolean);
  else if (last === 'allow') o.allow = String(v).split(/[\s,]+/).filter(Boolean);
  else if (last === 'servers') o.servers = String(v).split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { const w = l.split(/\s+/); const s = { address: w[0] }; for (const x of w.slice(1)) { if (x === 'backup') s.backup = true; else if (/^weight=\d+$/.test(x)) s.weight = Number(x.slice(7)); } return s; });
  else if (last === 'hc') o.healthCheck = v ? { path: '/health', interval: 5 } : null;
  else if (last === 'users') { const site = o; const users = String(v).split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { const i = l.indexOf(':'); return { user: l.slice(0, i), hash: l.slice(i + 1) }; }); BD.spec.sites[parts[1]].basicAuth = users.length ? { realm: 'Restricted', users } : null; void site; }
  else if (parts[parts.length - 1] === 'rateLimit') { o[last] = v === '' ? null : Number(v); const site = BD.spec.sites[parts[1]]; if (!(Number(site.rateLimit.rps) > 0)) site.rateLimit = null; }
  else if (el.type === 'number') o[last] = v === '' ? null : Number(v);
  else if (last === 'defaultPool') o[last] = v || null;
  else if (last === 'redirectTo' || last === 'rewriteTo') o[last] = v.trim() || null;
  else o[last] = v;
  // a renamed pool keeps its routes
  if (parts[0] === 'pools' && last === 'name') { const old = el.dataset.prev; if (old) BD.spec.sites.forEach((x) => { if (x.defaultPool === old) x.defaultPool = v; (x.routes || []).forEach((r) => { if (r.pool === old) r.pool = v; }); }); el.dataset.prev = v; }
}
function bdDel(path) {
  const parts = path.split('.'); const idx = Number(parts.pop());
  let o = BD.spec; for (const k of parts) o = o[k];
  const [gone] = o.splice(idx, 1);
  if (parts[0] === 'pools' && gone) BD.spec.sites.forEach((x) => { if (x.defaultPool === gone.name) x.defaultPool = null; x.routes = (x.routes || []).filter((r) => r.pool !== gone.name); });
}

// ---------------------------------------------------------------- output
function bdChecks(r) {
  const v = r.validation || {}; const a = r.audit || {};
  const vs = v.summary || {}; const as = a.summary || {};
  const chipC = (n, kind, label) => `<span class="bd-chk ${n ? kind : 'ok'}">${n ? `${n} ${label}${n === 1 ? '' : 's'}` : `no ${label}s`}</span>`;
  return `${v.error ? `<span class="bd-chk bad" title="${esc(v.error)}">validator failed</span>` : `${chipC(vs.error || 0, 'bad', 'error')}${chipC(vs.warning || 0, 'warn', 'warning')}`}${a.error ? '' : `<span class="bd-chk ${as.error ? 'bad' : as.warning ? 'warn' : 'ok'}" title="Structural audit of the generated config">audit: ${as.error || 0}e / ${as.warning || 0}w</span>`}`;
}
function bdOutHtml() {
  if (BD.errors) return `<div class="panel bd-err"><h3>Fix these first</h3><ul>${BD.errors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul></div>`;
  if (BD.err) return `<div class="panel bd-err"><div>${esc(BD.err)}</div></div>`;
  if (BD.compare) {
    return `<div class="panel"><h2>All products <span class="muted small">same description, each checked against its latest documented version</span></h2>
      <table class="grid"><thead><tr><th>Product</th><th>Version</th><th>Checks</th><th>Not supported</th><th></th></tr></thead><tbody>
      ${BD.compare.map((r) => `<tr><td><b>${esc(r.name)}</b></td><td class="mono small">${esc(r.target || '')}</td><td>${r.error ? `<span class="bd-chk bad">${esc(r.error)}</span>` : bdChecks(r)}</td><td class="small">${(r.unsupported || []).length ? `<span class="muted">${(r.unsupported || []).map(esc).join('<br>')}</span>` : '<span class="muted">everything</span>'}</td><td>${r.error ? '' : `<button class="btn" type="button" data-bd-prod="${r.product}">Open</button>`}</td></tr>`).join('')}</tbody></table></div>`;
  }
  const r = BD.out;
  if (!r) return `<div class="panel"><div class="empty">${BD.loading ? 'Building…' : 'Describe a site and a pool to get a configuration.'}</div></div>`;
  const f = r.files[Math.min(BD.file, r.files.length - 1)];
  const vf = (r.validation && r.validation.findings || []).filter((x) => x.severity !== 'info');
  const af = (r.audit && r.audit.findings || []).filter((x) => x.severity !== 'info');
  const lines = f.content.split('\n');
  return `<div class="panel bd-res">
    <div class="bd-res-h"><h2>${esc(r.name)} <span class="muted small">${esc(r.target ? `for ${r.target}` : '')}</span></h2><span class="spacer"></span>${bdChecks(r)}</div>
    ${r.model ? `<p class="muted small">${r.model.frontends.length} listener${r.model.frontends.length === 1 ? '' : 's'} (${esc([...new Set(r.model.frontends.flatMap((x) => x.ports))].filter(Boolean).join(', '))}), ${r.model.backends.length} pool${r.model.backends.length === 1 ? '' : 's'} with ${r.model.backends.reduce((n, b) => n + b.servers, 0)} servers, ${r.model.frontends.reduce((n, x) => n + x.routes, 0)} routing rules, read back from the generated file.</p>` : ''}
    ${(r.unsupported || []).length ? `<div class="bd-note warn"><b>Not available in ${esc(r.name)}${r.target ? ` ${esc(r.target)}` : ''}</b><ul>${r.unsupported.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}
    ${(r.notes || []).length ? `<details class="bd-note"><summary>Notes (${r.notes.length})</summary><ul>${r.notes.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></details>` : ''}
    ${vf.length || af.length ? `<details class="bd-note warn" open><summary>Checks to look at (${vf.length + af.length})</summary><ul>${[...vf.map((x) => ({ ...x, src: 'validator' })), ...af.map((x) => ({ ...x, src: 'audit' }))].map((x) => `<li><span class="sev-${esc(x.severity)}">●</span> ${esc(x.title)} <span class="muted small">${esc(x.src)}${x.file ? ` · ${esc(x.file)}` : ''}${x.line ? `:${x.line}` : ''}</span></li>`).join('')}</ul></details>` : ''}
    <div class="fg-bar">${r.files.length > 1 ? `<div class="chips" role="tablist">${r.files.map((x, i) => `<button type="button" class="chip${i === BD.file ? ' on' : ''}" data-bd-file="${i}" role="tab" aria-selected="${i === BD.file}">${esc(x.name)}</button>`).join('')}</div>` : `<b>${esc(f.name)}</b>`}<span class="spacer"></span><button class="btn" type="button" data-bd-copy>Copy</button><button class="btn" type="button" data-bd-dl>Download</button></div>
    <pre class="fg-code bd-code">${lines.map((l, i) => `<span class="fg-ln"><i>${i + 1}</i>${esc(l) || ' '}</span>`).join('')}</pre>
  </div>`;
}
function bdPaintOut() { const o = $('#bd-out'); if (o) o.innerHTML = bdOutHtml(); }

async function bdRun() {
  clearTimeout(BD.timer);
  const seq = ++BD.seq; BD.loading = true;
  try {
    const body = BD.compare ? { product: 'all', spec: BD.spec } : { product: BD.product, version: BD.version || null, spec: BD.spec };
    const r = await fetch('/api/build', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (seq !== BD.seq) return; // a newer edit is on its way
    BD.errors = null; BD.err = null;
    if (!r.ok) { if (j.errors) BD.errors = j.errors; else BD.err = j.error || `HTTP ${r.status}`; } else if (BD.compare) BD.compare = j.results; else { BD.out = j; if (BD.file >= j.files.length) BD.file = 0; }
  } catch (e) { if (seq === BD.seq) BD.err = e.message; }
  if (seq === BD.seq) { BD.loading = false; bdPaintOut(); }
}
const bdSoon = () => { clearTimeout(BD.timer); BD.timer = setTimeout(bdRun, 350); bdSave(); };

// ---------------------------------------------------------------- events
document.addEventListener('input', (e) => {
  const el = e.target.closest('#bd-form [data-bd]'); if (!el) return;
  if (el.tagName === 'SELECT' || el.type === 'checkbox') return; // handled on change
  bdSet(el.dataset.bd, el); bdSoon();
});
document.addEventListener('focusin', (e) => { const el = e.target.closest('#bd-form [data-bd$=".name"]'); if (el && !el.dataset.prev) el.dataset.prev = el.value; });
document.addEventListener('change', (e) => {
  const el = e.target.closest('#bd-form [data-bd]');
  if (el) {
    bdSet(el.dataset.bd, el); bdSave();
    // structural changes (TLS mode, health check, status page, pool names) change which fields exist
    if (el.tagName === 'SELECT' || el.type === 'checkbox' || /\.name$/.test(el.dataset.bd)) { const f = $('#bd-form'); const y = window.scrollY; f.innerHTML = bdFormHtml(); window.scrollTo(0, y); }
    bdSoon(); return;
  }
  if (e.target.id === 'bd-version') { BD.version = e.target.value; bdSave(); bdRun(); }
  if (e.target.id === 'bd-layout') { BD.spec.options = { ...(BD.spec.options || {}), layout: e.target.value }; BD.file = 0; bdSave(); bdRun(); }
  if (e.target.id === 'bd-import') {
    const file = e.target.files[0]; e.target.value = ''; if (!file) return;
    file.text().then((t) => { const j = JSON.parse(t); BD.spec = j.spec || j; BD.compare = null; bdSave(); bdRenderAll(); bdRun(); toast('Spec loaded', 'ok'); }).catch((err) => toast(`Could not read the file: ${err.message}`, 'err'));
  }
});
document.addEventListener('click', async (e) => {
  if (!e.target.closest('#view-builder')) return;
  const t = e.target;
  const prod = t.closest('[data-bd-prod]');
  if (prod) { BD.product = prod.dataset.bdProd; BD.version = ''; BD.compare = null; BD.file = 0; bdSave(); bdRenderAll(); bdRun(); return; }
  if (t.closest('[data-bd-compare]')) { BD.compare = []; bdRenderAll(); bdRun(); return; }
  const fileTab = t.closest('[data-bd-file]'); if (fileTab) { BD.file = Number(fileTab.dataset.bdFile); bdPaintOut(); return; }
  const del = t.closest('[data-bd-del]'); if (del) { bdDel(del.dataset.bdDel); $('#bd-form').innerHTML = bdFormHtml(); bdSoon(); return; }
  const addR = t.closest('[data-bd-add-route]');
  if (addR) { const s = BD.spec.sites[addR.dataset.bdAddRoute]; (s.routes = s.routes || []).push({ path: '/api/', match: 'prefix', pool: BD.spec.pools[0] ? BD.spec.pools[0].name : '', stripPrefix: false }); $('#bd-form').innerHTML = bdFormHtml(); bdSoon(); return; }
  if (t.closest('[data-bd-add-site]')) { BD.spec.sites.push(newSite(BD.spec.sites.length + 1)); $('#bd-form').innerHTML = bdFormHtml(); bdSoon(); return; }
  if (t.closest('[data-bd-add-pool]')) { BD.spec.pools.push(newPool(BD.spec.pools.length + 1)); $('#bd-form').innerHTML = bdFormHtml(); bdSoon(); return; }
  if (t.closest('[data-bd-example]')) { BD.spec = bdClone(BD.example); bdSave(); bdRenderAll(); bdRun(); return; }
  if (t.closest('[data-bd-clear]')) { BD.spec = { sites: [], pools: [newPool(1)], options: {} }; BD.spec.sites.push(newSite(1)); BD.spec.sites[0].defaultPool = 'pool1'; bdSave(); bdRenderAll(); bdRun(); return; }
  if (t.closest('[data-bd-export]')) { bdDownload('gatelight-spec.json', JSON.stringify({ spec: BD.spec }, null, 2), 'application/json'); return; }
  if (t.closest('[data-bd-copy]') && BD.out) { const f = BD.out.files[BD.file]; try { await navigator.clipboard.writeText(f.content); toast(`${f.name} copied`, 'ok'); } catch { toast('Copy is not available in this browser', 'err'); } return; }
  if (t.closest('[data-bd-dl]') && BD.out) { const f = BD.out.files[BD.file]; bdDownload(f.name.split('/').pop(), f.content, 'text/plain'); }
});
function bdDownload(name, text, type) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name;
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

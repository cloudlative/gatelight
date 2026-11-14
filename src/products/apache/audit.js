'use strict';
/**
 * Structural audit of an Apache httpd configuration (shared model from parse.js). Rule ids start with `apache-`;
 * every finding links the official httpd 2.4 documentation page it is based on.
 */
const { LAYOUT } = require('./parse');

const D = 'https://httpd.apache.org/docs/2.4/';
const DOC = {
  proxypass: `${D}mod/mod_proxy.html#proxypass`, proxypassreverse: `${D}mod/mod_proxy.html#proxypassreverse`, proxyrequests: `${D}mod/mod_proxy.html#proxyrequests`,
  balancer: `${D}mod/mod_proxy_balancer.html`, sticky: `${D}mod/mod_proxy_balancer.html#stickyness_implementation`, manager: `${D}mod/mod_proxy_balancer.html#balancer_manager`,
  hcheck: `${D}mod/mod_proxy_hcheck.html`, status: `${D}mod/mod_status.html`, options: `${D}mod/core.html#options`, tokens: `${D}mod/core.html#servertokens`,
  signature: `${D}mod/core.html#serversignature`, trace: `${D}mod/core.html#traceenable`, sslprotocol: `${D}mod/mod_ssl.html#sslprotocol`, sslcert: `${D}mod/mod_ssl.html#sslcertificatefile`,
  vhosts: `${D}vhosts/name-based.html`, include: `${D}mod/core.html#include`, secret: `${D}mod/mod_headers.html#requestheader`, require: `${D}mod/mod_authz_core.html#require`,
  compat: `${D}mod/mod_access_compat.html`, upgrading: `${D}upgrading.html#access`, lbmethod: `${D}mod/mod_proxy_balancer.html#scheduler`, ordering: `${D}mod/mod_proxy.html#proxypass`,
  loadmodule: `${D}mod/mod_so.html#loadmodule`, md: `${D}mod/mod_md.html#mdomain`, redirect: `${D}rewrite/avoid.html#redirect`, server: `${D}mod/core.html#servername`,
};
const RULE_TITLES = {
  'apache-undefined-balancer': 'ProxyPass to an undefined balancer', 'apache-orphan-balancer': 'Balancers that nothing routes to', 'apache-empty-balancer': 'Balancers without members',
  'apache-single-member': 'Single-member balancers (no redundancy)', 'apache-all-backup': 'Balancers with only hot-standby / disabled members', 'apache-no-healthcheck': 'Members without active health checks',
  'apache-no-proxypassreverse': 'ProxyPass without ProxyPassReverse', 'apache-open-proxy': 'Open forward proxy (ProxyRequests On)', 'apache-status-open': 'server-status / balancer-manager without access restriction',
  'apache-indexes': 'Directory listing enabled (Options Indexes)', 'apache-server-tokens': 'Server version exposed (ServerTokens)', 'apache-server-signature': 'Server signature on error pages',
  'apache-trace-enable': 'TRACE method enabled', 'apache-weak-tls': 'Legacy TLS protocols enabled', 'apache-no-tls-protocols': 'No explicit SSLProtocol', 'apache-ssl-no-cert': 'SSLEngine on without a certificate',
  'apache-no-http-redirect': 'HTTP virtual host serves content without HTTPS redirect', 'apache-duplicate-servername': 'Duplicate ServerName on the same address:port', 'apache-include-note': 'Include problems',
  'apache-inline-secret': 'Secrets stored in config', 'apache-proxypass-slash': 'ProxyPass trailing-slash mismatch', 'apache-proxypass-shadowed': 'ProxyPass rule hidden by an earlier one',
  'apache-sticky-config': 'Incomplete sticky-session setup', 'apache-module-missing': 'Proxy feature without its module', 'apache-access-compat-mix': 'Old Order/Allow/Deny mixed with Require',
  'apache-live-drift': 'Live members not in the configuration', 'apache-selinux-proxy': 'SELinux may block outgoing proxy connections',
};
const SEVERITY_ORDER = { error: 0, warning: 1, info: 2 };
const LB_MODULE = { byrequests: 'lbmethod_byrequests_module', bybusyness: 'lbmethod_bybusyness_module', bytraffic: 'lbmethod_bytraffic_module', heartbeat: 'lbmethod_heartbeat_module' };
const SCHEME_MODULE = { http: 'proxy_http_module', https: 'proxy_http_module', fcgi: 'proxy_fcgi_module', ajp: 'proxy_ajp_module', scgi: 'proxy_scgi_module', uwsgi: 'proxy_uwsgi_module', h2: 'proxy_http2_module', h2c: 'proxy_http2_module', ftp: 'proxy_ftp_module', ws: 'proxy_wstunnel_module', wss: 'proxy_wstunnel_module' };
const LOOPBACK = /^(127\.|\[?::1\]?$|localhost$)/;

/** Protocols enabled by an SSLProtocol argument list ("all -SSLv3 +TLSv1.2" ...). */
function sslProtocols(args) {
  const ALL = ['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
  const set = new Set();
  for (const raw of args) {
    const sign = raw[0] === '-' ? '-' : '+'; const p = raw.replace(/^[+-]/, '');
    const items = /^all$/i.test(p) ? ALL : ALL.filter((x) => x.toLowerCase() === p.toLowerCase());
    if (sign === '-') items.forEach((x) => set.delete(x)); else if (raw[0] === '+' || /^all$/i.test(p)) items.forEach((x) => set.add(x)); else { if (!/^[+-]/.test(raw) && set.size && args.indexOf(raw) > 0) { /* bare names after others still add */ } items.forEach((x) => set.add(x)); }
  }
  return [...set];
}

function audit(sections, { notes = [], rows = [] } = {}) {
  const findings = [];
  const add = (f) => findings.push({ category: 'hygiene', detail: '', fix: '', ...f });
  const global = sections.find((s) => s.type === 'global') || { directives: [], loadedModules: [] };
  const frontends = sections.filter((s) => s.type === 'frontend');
  const balancers = sections.filter((s) => s.type === 'backend' && !s.implicit);
  const loaded = new Set([...(global.loadedModules || []), ...(global.staticModules || [])]);
  const layout = global.layout || 'unknown'; const L = LAYOUT[layout] || LAYOUT.unknown;
  const enableFix = (id) => { const m = id.replace(/_module$/, ''); return layout === 'debian' ? `Run \`a2enmod ${m}\` and \`${L.reload}\`.` : layout === 'rhel' ? `Add \`LoadModule ${id} modules/mod_${m}.so\` to /etc/httpd/conf.modules.d/ (00-proxy.conf / 00-base.conf), then \`${L.reload}\`.` : `Add \`LoadModule ${id} modules/mod_${m}.so\`.`; };
  const hasLoad = (global.loadedModules || []).length > 0; // only when the configuration loads modules itself
  const gd = (name) => global.directives.filter((d) => d.lkeyword === name && !d.within.some((w) => /^<(Location|Directory|Files|Proxy)/i.test(w)));
  const lastG = (name) => gd(name).pop();
  const all = [global, ...frontends];
  const dirsOf = (s) => s.directives || [];
  const sectionName = (s) => (s.type === 'global' ? 'global' : s.name);

  for (const n of notes) {
    if (/analysed as active/.test(n.msg) || n.kind === 'layout') continue;
    add({ id: 'apache-include-note', severity: 'info', section: 'global', file: n.file, line: 1, title: n.msg, detail: 'Part of the configuration could not be analysed.', fix: 'Upload or mount the whole configuration tree (conf.d, conf.modules.d, sites-enabled ...).', docs: DOC.include });
  }

  // ---------------- server-wide
  const pr = all.flatMap((s) => dirsOf(s).filter((d) => d.lkeyword === 'proxyrequests' && /^on$/i.test(d.args[0] || '')).map((d) => ({ s, d })));
  for (const { s, d } of pr) {
    const restricted = all.some((x) => dirsOf(x).some((y) => y.lkeyword === 'require' && !/^all$/i.test(y.args[0] || '') && y.within.some((w) => /^<Proxy\s+"?\*"?>/i.test(w))));
    add({ id: 'apache-open-proxy', severity: restricted ? 'warning' : 'error', category: 'security', section: sectionName(s), file: d.file, line: d.line, title: 'ProxyRequests On turns httpd into a forward proxy', detail: restricted ? 'A <Proxy "*"> block restricts who may use it; make sure only trusted clients match.' : 'Without a <Proxy "*"> block that restricts clients, anyone can relay traffic through this server (spam, attacks, access to internal hosts). A reverse proxy never needs it.', fix: 'Set `ProxyRequests Off` (reverse proxying with ProxyPass works without it).', docs: DOC.proxyrequests });
  }
  const tok = lastG('servertokens');
  if (!tok) add({ id: 'apache-server-tokens', severity: 'info', category: 'security', section: 'global', file: global.file, line: 1, title: 'ServerTokens is not set (default Full)', detail: 'The Server header then reveals the httpd version, OS and compiled-in modules.', fix: 'Add `ServerTokens Prod`.', docs: DOC.tokens });
  else if (!/^prod(uctonly)?$/i.test(tok.args[0] || '')) add({ id: 'apache-server-tokens', severity: /^(full|os)$/i.test(tok.args[0] || '') ? 'warning' : 'info', category: 'security', section: 'global', file: tok.file, line: tok.line, title: `ServerTokens ${tok.args[0]} exposes the httpd version`, detail: 'Version banners make it easy to match the server against known vulnerabilities.', fix: 'Use `ServerTokens Prod`.', docs: DOC.tokens });
  for (const s of all) for (const d of dirsOf(s).filter((x) => x.lkeyword === 'serversignature' && !/^off$/i.test(x.args[0] || ''))) add({ id: 'apache-server-signature', severity: 'info', category: 'security', section: sectionName(s), file: d.file, line: d.line, title: `ServerSignature ${d.args[0]} adds the server version to error pages`, detail: '', fix: 'Set `ServerSignature Off`.', docs: DOC.signature });
  const trace = lastG('traceenable');
  if (!trace || !/^off$/i.test(trace.args[0] || '')) add({ id: 'apache-trace-enable', severity: 'info', category: 'security', section: 'global', file: trace ? trace.file : global.file, line: trace ? trace.line : 1, title: trace ? `TraceEnable ${trace.args[0]}` : 'TRACE is enabled (TraceEnable defaults to On)', detail: 'TRACE echoes the request back, which helps cross-site tracing and leaks headers added by intermediaries.', fix: 'Add `TraceEnable Off`.', docs: DOC.trace });

  // ---------------- Options Indexes, status handlers, compat mix, secrets (every scope)
  for (const s of all) {
    const ds = dirsOf(s);
    for (const d of ds.filter((x) => x.lkeyword === 'options')) {
      const a = d.args.map((x) => x.toLowerCase());
      if (a.includes('indexes') || a.includes('+indexes') || a.includes('all')) add({ id: 'apache-indexes', severity: 'warning', category: 'security', section: sectionName(s), file: d.file, line: d.line, title: `Directory listing enabled: Options ${d.args.join(' ')}${d.within.length ? ` in ${d.within[d.within.length - 1]}` : ''}`, detail: 'When a folder has no index file, httpd lists its contents (backups, dumps, source files).', fix: 'Remove `Indexes` (or write `Options -Indexes`).', docs: DOC.options });
    }
    const handlers = ds.filter((x) => x.lkeyword === 'sethandler' && /^(server-status|balancer-manager|server-info)$/i.test(x.args[0] || ''));
    for (const h of handlers) {
      const where = h.within[h.within.length - 1] || '';
      const same = ds.filter((x) => x.within[x.within.length - 1] === where && x.within.length === h.within.length);
      const req = same.filter((x) => x.lkeyword === 'require');
      const restricted = req.some((x) => !/^all$/i.test(x.args[0] || '') || /^denied$/i.test(x.args[1] || '')) || same.some((x) => x.lkeyword === 'allow' && !/\ball\b/i.test(x.args.join(' ')))
        || same.some((x) => x.lkeyword === 'authtype');
      const open = req.some((x) => /^all$/i.test(x.args[0] || '') && /^granted$/i.test(x.args[1] || ''));
      if (!restricted || open) {
        const loop = s.binds && s.binds.length && s.binds.every((b) => LOOPBACK.test(b.host || ''));
        const mgr = /balancer-manager/i.test(h.args[0]);
        add({ id: 'apache-status-open', severity: loop ? 'warning' : 'error', category: 'security', section: sectionName(s), file: h.file, line: h.line, title: `${h.args[0]}${where ? ` at ${where}` : ''} has no access restriction`, detail: `${mgr ? 'balancer-manager can change balancer members (disable, drain, re-weight) through simple HTTP requests.' : 'Anyone who reaches this URL sees request counters, client addresses and URLs being served.'}${loop ? ' The virtual host only listens on loopback, which limits the exposure.' : ''}`, fix: `Add \`Require ip 127.0.0.1\` (or your monitoring network) to the section.`, docs: mgr ? DOC.manager : DOC.status });
      }
    }
    const old = ds.filter((x) => ['order', 'allow', 'deny', 'satisfy'].includes(x.lkeyword));
    if (old.length) {
      const scopes = new Set(old.map((x) => x.within.join('>')));
      for (const sc of scopes) {
        const mixed = ds.some((x) => x.lkeyword === 'require' && x.within.join('>') === sc);
        if (mixed) { const o = old.find((x) => x.within.join('>') === sc); add({ id: 'apache-access-compat-mix', severity: 'warning', category: 'security', section: sectionName(s), file: o.file, line: o.line, title: `Order/Allow/Deny mixed with Require${o.within.length ? ` in ${o.within[o.within.length - 1]}` : ''}`, detail: 'httpd 2.4 discourages mixing the old mod_access_compat directives with Require: the old ones take precedence when sections merge, with surprising results.', fix: 'Replace Order/Allow/Deny with `Require` (e.g. `Require all granted`, `Require ip 10.0.0.0/8`).', docs: DOC.upgrading }); }
      }
    }
    for (const d of ds) {
      const val = d.args.join(' ');
      let what = null;
      if (/^(proxypass|proxypassmatch|balancermember|proxypassreverse|rewriterule)$/.test(d.lkeyword) && /:\/\/[^/@\s]*:\*\*\*@/.test(val)) what = `Credentials embedded in the ${d.keyword} URL`;
      else if (/^(requestheader|header)$/.test(d.lkeyword) && d.args.some((a) => a === '***')) what = `Credential hard-coded in ${d.keyword} ${d.args.slice(0, 2).join(' ')}`;
      else if (/^(setenv|define)$/.test(d.lkeyword) && d.args[1] === '***') what = `Secret stored in ${d.keyword} ${d.args[0]}`;
      else if (d.lkeyword === 'authldapbindpassword' && !/^exec:/i.test(d.args[0] || '')) what = 'LDAP bind password stored in the configuration';
      if (what) add({ id: 'apache-inline-secret', severity: 'warning', category: 'security', section: sectionName(s), file: d.file, line: d.line, title: what, detail: 'Secrets in config files tend to leak through repositories, backups and support bundles.', fix: d.lkeyword === 'authldapbindpassword' ? 'Use `AuthLDAPBindPassword exec:/path/to/program` (2.4.5+) or a file readable only by root.' : 'Move the secret into a file only root can read (Include it, or use Define/${VAR} from the service environment).', docs: d.lkeyword === 'authldapbindpassword' ? `${D}mod/mod_authnz_ldap.html#authldapbindpassword` : DOC.secret });
    }
  }

  // ---------------- TLS, redirect, duplicates per virtual host
  const gSslProto = lastG('sslprotocol'); const gCert = lastG('sslcertificatefile');
  const mdNames = new Set(global.directives.filter((d) => d.lkeyword === 'mdomain' || d.lkeyword === 'mdomainset' || d.lkeyword === 'mdmember' || d.lkeyword === 'mdmembers').flatMap((d) => d.args.map((a) => a.toLowerCase())));
  const sslFe = frontends.filter((f) => f.ssl);
  const sslNames = new Set(sslFe.flatMap((f) => f.serverNames || []));
  for (const fe of frontends) {
    const ds = dirsOf(fe).filter((d) => !d.within.length);
    const last = (n) => ds.filter((d) => d.lkeyword === n).pop();
    if (fe.ssl) {
      const cert = last('sslcertificatefile') || gCert;
      const md = (fe.serverNames || []).some((n) => mdNames.has(n));
      if (!cert && !md) add({ id: 'apache-ssl-no-cert', severity: 'error', category: 'reliability', section: fe.name, file: fe.file, line: fe.line, title: `SSLEngine on in ${fe.name} but no SSLCertificateFile`, detail: 'httpd refuses to start ("Server should be SSL-aware but has no certificate configured") unless mod_md manages a certificate for this name.', fix: 'Add `SSLCertificateFile` and `SSLCertificateKeyFile`, or an `MDomain` for the name.', docs: DOC.sslcert });
      const proto = last('sslprotocol') || gSslProto;
      if (proto) {
        const on = sslProtocols(proto.args).filter((p) => /^(SSLv3|TLSv1|TLSv1\.1)$/.test(p));
        if (on.length) add({ id: 'apache-weak-tls', severity: on.includes('SSLv3') ? 'error' : 'warning', category: 'security', section: fe.name, file: proto.file, line: proto.line, title: `Legacy TLS protocols enabled: ${on.join(', ')} (SSLProtocol ${proto.args.join(' ')})`, detail: 'TLS 1.0/1.1 are deprecated (RFC 8996) and SSLv3 is broken (POODLE). "all" includes them unless removed explicitly.', fix: 'Use `SSLProtocol -all +TLSv1.2 +TLSv1.3`.', docs: DOC.sslprotocol });
      } else add({ id: 'apache-no-tls-protocols', severity: 'info', category: 'security', section: fe.name, file: fe.file, line: fe.line, title: 'No explicit SSLProtocol', detail: 'The default is "all -SSLv3", which still enables TLS 1.0 and 1.1 where the OpenSSL build allows them.', fix: 'Set `SSLProtocol -all +TLSv1.2 +TLSv1.3` at server level.', docs: DOC.sslprotocol });
    } else if ((fe.serverNames || []).some((n) => sslNames.has(n))) {
      const redirects = fe.routes.some((r) => r.terminal && r.transforms.some((t) => t.action === 'redirect' && /^https:\/\//i.test(t.args[1] || '')) && r.matchers.some((m) => m.field === 'Path' && (m.values[0] === '/' || /^\^?\/\(?\.\*\)?\$?$/.test(m.values[0]))));
      const serves = fe.routes.some((r) => r.target && !r.terminal) || fe.documentRoot;
      if (!redirects && serves) add({ id: 'apache-no-http-redirect', severity: 'warning', category: 'security', section: fe.name, file: fe.file, line: fe.line, title: 'Plain-HTTP virtual host serves content though an HTTPS virtual host exists for the same name', detail: 'Clients and links that use http:// bypass TLS (and HSTS cannot help on the first visit).', fix: 'Replace the content with `Redirect permanent "/" "https://<name>/"`.', docs: DOC.redirect });
    }
  }
  const seen = new Map();
  for (const fe of frontends.filter((f) => !f.main)) {
    for (const b of fe.binds) for (const n of fe.serverNames || []) {
      const k = `${String(b.address).replace(/^_default_/, '*')}|${n}`;
      if (seen.has(k)) add({ id: 'apache-duplicate-servername', severity: 'warning', category: 'reliability', section: fe.name, file: fe.file, line: fe.line, title: `Duplicate ServerName/ServerAlias "${n}" on ${b.address}`, detail: `Also used by the virtual host at ${seen.get(k)}. httpd picks the first matching virtual host; this one never answers for "${n}".`, fix: 'Remove or merge one of the virtual hosts.', docs: DOC.vhosts });
      else seen.set(k, `${fe.file}:${fe.line}`);
    }
  }

  // ---------------- routes: undefined balancer, ProxyPassReverse, slashes, shadowing, modules
  const referenced = new Set();
  const reportedRoute = new Set();
  for (const fe of frontends) {
    const ds = dirsOf(fe);
    const reverse = (route) => {
      const inLoc = route.inLocation;
      const p = route.paths[0];
      const pool = [...ds, ...global.directives.filter((d) => !d.within.length)];
      return pool.some((d) => d.lkeyword === 'proxypassreverse' && (inLoc ? (d.args.length === 1 && d.within.some((w) => w.includes(p))) || d.args[0] === p : d.args[0] === p && !d.within.length));
    };
    const earlier = [];
    for (const r of fe.routes) {
      if (r.target) referenced.add(r.target);
      const key = `${r.file}:${r.line}`;
      const first = !reportedRoute.has(key); reportedRoute.add(key);
      if (r.undefinedBalancer && first) add({ id: 'apache-undefined-balancer', severity: 'error', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `${r.directive} targets balancer://${r.target}, which is not defined`, detail: 'httpd fails requests with 500/503 ("no balancer") when no <Proxy "balancer://..."> with BalancerMember lines exists for it in this server or the main config.', fix: `Define <Proxy "balancer://${r.target}"> with BalancerMember lines.`, docs: DOC.balancer });
      const scheme = r.passUrl ? (r.passUrl.match(/^([a-z0-9+]+):/i) || [])[1] : null;
      if (first && (r.directive === 'ProxyPass' || /^proxypass$/i.test(r.directive || '')) && r.passUrl && /^(https?|balancer)$/i.test(scheme || '') && !reverse(r)) {
        add({ id: 'apache-no-proxypassreverse', severity: 'warning', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `No ProxyPassReverse for ${r.paths[0]}`, detail: 'Location / Content-Location / URI headers in backend redirects keep the internal address, so clients get redirected to a host they cannot reach.', fix: r.inLocation ? `Add \`ProxyPassReverse "${r.passUrl}"\` inside the same <Location>.` : `Add \`ProxyPassReverse "${r.paths[0]}" "${r.passUrl}"\`.`, docs: DOC.proxypassreverse });
      }
      if (first && /^proxypass$/i.test(r.directive || '') && r.passUrl && !r.dynamic) {
        const m = /^[a-z0-9+]+:\/\/[^/]+(\/.*)?$/i.exec(r.passUrl);
        const up = m ? m[1] || '' : null; const p = r.paths[0] || '';
        if (up !== null && p && ((p.endsWith('/') && up !== '' && !up.endsWith('/')) || (p.endsWith('/') && up === '' && p !== '/') || (!p.endsWith('/') && up.endsWith('/') && up !== '/'))) {
          add({ id: 'apache-proxypass-slash', severity: 'warning', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `Trailing slash mismatch: ${p} → ${r.passUrl}`, detail: '"If the first argument ends with a trailing /, the second argument should also end with a trailing /, and vice versa. Otherwise, the resulting requests to the backend may miss some needed slashes." (mod_proxy documentation)', fix: 'Make both end with "/" (or both without).', docs: DOC.proxypass });
        }
      }
      if (first && /^proxypass$/i.test(r.directive || '') && !r.inLocation && !r.inherited) {
        const p = r.paths[0];
        const hider = earlier.find((e) => p.startsWith(e.p) && e.p !== p && (e.p.endsWith('/') || p[e.p.length] === '/'));
        if (hider) add({ id: 'apache-proxypass-shadowed', severity: 'warning', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `ProxyPass ${p} is never used: ${hider.p} (line ${hider.line}) matches first`, detail: 'ProxyPass rules are checked in configuration order and the first match wins, so longer paths must come first.', fix: `Move this line above line ${hider.line}.`, docs: DOC.ordering });
        earlier.push({ p, line: r.line });
      }
      if (hasLoad && first && scheme) {
        const s = scheme.toLowerCase();
        const need = s === 'balancer' ? 'proxy_balancer_module' : SCHEME_MODULE[s];
        const wsOk = (s === 'ws' || s === 'wss') && loaded.has('proxy_http_module');
        if (!loaded.has('proxy_module')) add({ id: 'apache-module-missing', severity: 'error', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `${r.directive} needs mod_proxy, which is not loaded`, detail: 'The configuration has LoadModule lines but none for proxy_module.', fix: enableFix('proxy_module'), docs: DOC.loadmodule });
        else if (need && !loaded.has(need) && !wsOk) add({ id: 'apache-module-missing', severity: 'error', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `${s}:// targets need ${need.replace(/_module$/, '').replace(/^/, 'mod_')}, which is not loaded`, detail: 'Without the scheme handler httpd answers with 500 "No protocol handler was valid for the URL".', fix: enableFix(need), docs: DOC.loadmodule });
      }
    }
  }

  // ---------------- balancers
  const hcLoaded = loaded.has('proxy_hcheck_module');
  const stickyCookie = all.some((s) => dirsOf(s).some((d) => /^header$/i.test(d.keyword) && /set-cookie/i.test(d.args.join(' ')) && /BALANCER_WORKER_ROUTE/.test(d.args.join(' '))));
  for (const be of balancers) {
    const live = be.servers.filter((s) => !s.backup && !s.disabled);
    if (!be.servers.length) add({ id: 'apache-empty-balancer', severity: 'error', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `Balancer "${be.name}" has no members`, detail: 'Requests routed to it fail with 503.', fix: 'Add `BalancerMember` lines.', docs: DOC.balancer });
    else if (be.servers.length === 1) add({ id: 'apache-single-member', severity: 'info', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `Balancer "${be.name}" has a single member`, detail: 'No redundancy.', fix: 'Add another member or a hot standby (`status=+H`).', docs: DOC.balancer });
    else if (!live.length) add({ id: 'apache-all-backup', severity: 'warning', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `All members of "${be.name}" are hot-standby or disabled`, detail: '', fix: 'Enable at least one active member.', docs: DOC.balancer });
    if (be.servers.length && be.declared !== false) {
      const unchecked = be.servers.filter((s) => !s.check && !s.backup);
      if (unchecked.length) add({ id: 'apache-no-healthcheck', severity: hcLoaded ? 'warning' : 'info', category: 'reliability', section: be.name, file: be.file, line: be.line, title: hcLoaded ? `mod_proxy_hcheck is loaded but ${unchecked.length} member${unchecked.length > 1 ? 's' : ''} of "${be.name}" have no health check` : `Members of "${be.name}" are only checked passively`, detail: 'Without active checks httpd notices a dead member only when real requests fail, and retries it after `retry` seconds.', fix: `${hcLoaded ? '' : `Load mod_proxy_hcheck (2.4.21+; ${layout === 'debian' ? '`a2enmod proxy_hcheck`' : 'LoadModule proxy_hcheck_module'}) and `}add \`hcmethod=GET hcuri=/health hcinterval=10\` to each BalancerMember.`, docs: DOC.hcheck });
    }
    if (be.sticky && be.servers.length && !be.servers.every((s) => s.route)) add({ id: 'apache-sticky-config', severity: 'warning', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `stickysession on "${be.name}" but not every member has a route=`, detail: 'The balancer looks for a member whose route equals the cookie value; members without a route never receive sticky traffic.', fix: 'Give each BalancerMember a unique `route=` value.', docs: DOC.sticky });
    else if (be.sticky && /^ROUTEID$/i.test(be.stickysession || '') && !stickyCookie) add({ id: 'apache-sticky-config', severity: 'warning', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `stickysession=${be.stickysession} but nothing sets the cookie`, detail: 'httpd does not create the ROUTEID cookie itself; the documented pattern sets it with mod_headers.', fix: 'Add `Header add Set-Cookie "ROUTEID=.%{BALANCER_WORKER_ROUTE}e; path=/" env=BALANCER_ROUTE_CHANGED`.', docs: DOC.sticky });
    if (hasLoad && LB_MODULE[be.balance] && !loaded.has(LB_MODULE[be.balance])) add({ id: 'apache-module-missing', severity: 'error', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `lbmethod=${be.balance} needs mod_lbmethod_${be.balance}, which is not loaded`, detail: 'httpd refuses the configuration: "unknown lbmethod".', fix: enableFix(LB_MODULE[be.balance]), docs: DOC.lbmethod });
    if (!referenced.has(be.name)) add({ id: 'apache-orphan-balancer', severity: 'warning', category: 'hygiene', section: be.name, file: be.file, line: be.line, title: `Balancer "${be.name}" is never used`, detail: 'No ProxyPass / ProxyPassMatch / RewriteRule [P] points to it (it may still be reached through a variable or balancer-manager).', fix: 'Remove it if unused.', docs: DOC.balancer });
  }

  // ---------------- RHEL: SELinux denies httpd outgoing connections unless the boolean is set
  if (layout === 'rhel') {
    const fe = frontends.find((f) => f.routes.some((r) => r.target && !r.terminal));
    if (fe) { const r = fe.routes.find((x) => x.target && !x.terminal); add({ id: 'apache-selinux-proxy', severity: 'info', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: 'On SELinux systems httpd may not open connections to backends', detail: 'RHEL / Fedora run httpd confined (httpd_t). Reverse proxying to other hosts or ports fails with 503 and "permission denied: AH00957" in the error log until the httpd_can_network_connect boolean is on.', fix: 'Run `setsebool -P httpd_can_network_connect 1` (check with `getsebool httpd_can_network_connect`).', docs: `${D}mod/mod_proxy.html` }); }
  }

  // ---------------- drift against live rows (balancer-manager)
  if (rows && rows.length) {
    const byName = new Map(balancers.map((b) => [b.name, new Set(b.servers.map((s) => s.name))]));
    for (const r of rows.filter((x) => x.kind === 'server' && byName.has(x.proxy))) {
      if (!byName.get(r.proxy).has(r.name)) { const be = balancers.find((b) => b.name === r.proxy); add({ id: 'apache-live-drift', severity: 'info', category: 'drift', section: r.proxy, file: be.file, line: be.line, title: `Live member ${r.name} of "${r.proxy}" is not in the configuration`, detail: 'It was probably added through balancer-manager (BalancerPersist) or the config on disk differs from the running one.', fix: 'Add it to the configuration or remove it from the running server.', docs: DOC.manager }); }
    }
  }

  for (const f of findings) f.rule = RULE_TITLES[f.id] || f.id;
  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || String(a.file).localeCompare(String(b.file)) || ((a.line || 0) - (b.line || 0)));
  return findings;
}

module.exports = { audit, sslProtocols, RULE_TITLES, DOC };

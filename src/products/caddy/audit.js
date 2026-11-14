'use strict';
/** Structural audit of a Caddy configuration (ids `caddy-*`; finding shape of src/products/CONTRACT.md). */
const { isPublicName } = require('./model');
const { DOCS } = require('./kb');

const SEV = { error: 0, warning: 1, info: 2 };
const RULE_TITLES = {
  'caddy-include-note': 'Configuration problems', 'caddy-import-missing': 'Imports that resolve to nothing', 'caddy-unused-snippet': 'Snippets that are never imported',
  'caddy-undefined-matcher': 'Undefined named matchers', 'caddy-unused-matcher': 'Named matchers that are never used', 'caddy-duplicate-site': 'Duplicate site addresses',
  'caddy-no-health-check': 'Several upstreams without health checks', 'caddy-single-upstream': 'Single-upstream proxies (no redundancy)', 'caddy-empty-upstreams': 'reverse_proxy without upstreams',
  'caddy-upstream-tls-insecure': 'Upstream TLS certificates not verified', 'caddy-admin-exposed': 'Admin API reachable from the network', 'caddy-tls-internal-public': 'Internal CA on a public host name',
  'caddy-no-access-log': 'Sites without access logging', 'caddy-redundant-header-up': 'header_up repeats what Caddy already sets', 'caddy-client-ip-untrusted': 'client_ip without trusted_proxies',
  'caddy-basicauth-deprecated': 'Deprecated basicauth spelling', 'caddy-file-browse': 'Directory listing enabled', 'caddy-unreachable-route': 'Routes that can never match',
  'caddy-inline-secret': 'Secrets written into the Caddyfile', 'caddy-auto-https-off': 'Automatic HTTPS disabled', 'caddy-http-public': 'Public site served over plain HTTP only',
};
const LOOPBACK = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|::1|unix\/.*)(:\d+)?$/i;
const placeholder = (v) => /^\{(env\.|\$|file\.|vars\.|http\.)/.test(String(v || ''));

function audit(sections, { notes = [] } = {}) {
  const findings = [];
  const add = (f) => findings.push({ category: 'hygiene', detail: '', fix: '', ...f });
  const g = sections.find((s) => s.type === 'global') || { options: {}, directives: [] };
  const opts = g.options || {};
  const fes = sections.filter((s) => s.type === 'frontend' && !s.implicit);
  const bes = sections.filter((s) => s.type === 'backend');

  for (const n of notes.filter((x) => !/is neither a snippet nor a file/.test(x.msg))) add({ id: 'caddy-include-note', severity: /neither a snippet nor a file|outside the config root|Unclosed|Unexpected|Unterminated|Incomplete/i.test(n.msg) ? 'warning' : 'info', section: 'global', file: n.file, line: Number((/line (\d+)/.exec(n.msg) || [])[1]) || 1, title: n.msg, detail: 'Part of the configuration could not be analysed.', fix: 'Upload or mount every file the Caddyfile imports.', docs: `${DOCS}/caddyfile/directives/import` });
  for (const m of g.importsMissing || []) {
    if (!m.glob) add({ id: 'caddy-import-missing', severity: 'error', category: 'correctness', section: 'global', file: m.file, line: m.line, title: `import ${m.pattern}: no such snippet or file`, detail: 'Caddy stops with "File to import not found". Snippets must be defined before the import, in the same Caddyfile or an imported file.', fix: `Define (${m.pattern}) { ... } above, or upload the imported file.`, docs: `${DOCS}/caddyfile/directives/import` });
    else add({ id: 'caddy-import-missing', severity: 'info', section: 'global', file: m.file, line: m.line, title: `import ${m.pattern} matched no files`, detail: 'A glob that matches nothing is allowed by Caddy, but nothing from it was analysed.', fix: 'Upload the imported folder too, or remove the import.', docs: `${DOCS}/caddyfile/directives/import` });
  }
  for (const s of g.snippets || []) if (!s.uses) add({ id: 'caddy-unused-snippet', severity: 'info', section: 'global', file: s.file, line: s.line, title: `Snippet (${s.name}) is never imported`, detail: 'Dead configuration makes the Caddyfile harder to read.', fix: `Import it where needed (import ${s.name}) or delete it.`, docs: `${DOCS}/caddyfile/concepts#snippets` });

  // ---- global options
  const admin = opts.admin || {};
  if (admin.listen && !admin.off && !LOOPBACK.test(admin.listen.replace(/^tcp\//, ''))) {
    const guarded = admin.enforceOrigin && (admin.origins || []).length;
    add({ id: 'caddy-admin-exposed', severity: guarded ? 'warning' : 'error', category: 'security', section: 'global', file: admin.file || g.file, line: admin.line || g.line, title: `Admin API listens on ${admin.listen}`,
      detail: `Caddy's admin API can load a new configuration with a single unauthenticated request. Bound to a non-loopback address${guarded ? ' only an Origin check protects it, which is not authentication' : ', anyone who can reach the port can take over the server'}.`,
      fix: 'Keep the default (localhost:2019) or a unix socket, and reach it through an SSH tunnel or a protected reverse_proxy; for remote management use the remote admin with mutual TLS (JSON config).', docs: `${DOCS}/caddyfile/options#admin` });
  }
  if (opts.autoHttps === 'off') add({ id: 'caddy-auto-https-off', severity: 'info', category: 'security', section: 'global', file: g.file, line: (g.directives.find((d) => d.keyword === 'auto_https') || g).line, title: 'Automatic HTTPS is turned off', detail: 'Caddy neither obtains certificates nor redirects HTTP to HTTPS; sites without an explicit tls directive are served over plain HTTP.', fix: 'Remove `auto_https off` unless TLS is terminated in front of Caddy.', docs: `${DOCS}/automatic-https` });
  const trusted = (opts.servers || []).some((s) => s.trustedProxies);

  // ---- sites
  const seen = new Map();
  const logged = fes.filter((f) => f.directives.some((d) => d.keyword === 'log' && !d.within.length));
  for (const fe of fes) {
    for (const a of fe.addresses || []) {
      const key = `${a.scheme === 'http' ? 'http' : 'https'}://${a.hostname || '*'}:${a.port}${a.path || ''}`;
      if (seen.has(key)) add({ id: 'caddy-duplicate-site', severity: 'error', category: 'correctness', section: fe.name, file: fe.file, line: fe.line, title: `Site address ${a.raw} is defined twice`, detail: `Also defined at ${seen.get(key)}. Caddy refuses to start: "ambiguous site definition".`, fix: 'Merge the two site blocks.', docs: `${DOCS}/caddyfile/concepts#addresses` });
      else seen.set(key, `${fe.file}:${fe.line}`);
    }
    for (const m of fe.undefinedMatchers || []) add({ id: 'caddy-undefined-matcher', severity: 'error', category: 'correctness', section: fe.name, file: m.file, line: m.line, title: `Named matcher ${m.name} is not defined in this site`, detail: 'Named matchers are scoped to the site block that defines them. Caddy fails to adapt the config: "unrecognized matcher name".', fix: `Define it in this site: ${m.name} { path /... }`, docs: `${DOCS}/caddyfile/matchers#named-matchers` });
    for (const m of fe.unusedMatchers || []) add({ id: 'caddy-unused-matcher', severity: 'info', section: fe.name, file: m.file, line: m.line, title: `Named matcher ${m.name} is never used`, detail: '', fix: 'Remove it, or use it in a directive.', docs: `${DOCS}/caddyfile/matchers#named-matchers` });
    const d = (k) => fe.directives.filter((x) => x.keyword === k);
    for (const x of d('basicauth')) add({ id: 'caddy-basicauth-deprecated', severity: 'warning', category: 'compatibility', section: fe.name, file: x.file, line: x.line, title: '`basicauth` was renamed to `basic_auth` in Caddy 2.8', detail: 'The old spelling still works but logs a deprecation warning and will be removed.', fix: 'Write basic_auth.', docs: `${DOCS}/caddyfile/directives/basic_auth`, since: '2.8.0' });
    if (fe.tls && fe.tls.args[0] === 'internal') {
      const pub = (fe.serverNames || []).filter(isPublicName);
      if (pub.length) add({ id: 'caddy-tls-internal-public', severity: 'warning', category: 'security', section: fe.name, file: fe.tls.file, line: fe.tls.line, title: `tls internal on public name ${pub[0]}`, detail: 'Certificates from Caddy\'s internal CA are only trusted by machines that installed its root; public visitors get certificate errors (and learn to click through them).', fix: 'Remove `tls internal` so Caddy obtains a publicly trusted certificate, or use an internal host name.', docs: `${DOCS}/caddyfile/directives/tls` });
    }
    for (const r of fe.routes) if (r.browse) add({ id: 'caddy-file-browse', severity: 'warning', category: 'security', section: fe.name, file: r.file, line: r.line, title: 'file_server browse lists directory contents', detail: 'Anyone can enumerate the files under the site root (backups, dumps, keys left there by mistake).', fix: 'Remove `browse` unless a listing is the purpose of the site, and protect it with basic_auth if so.', docs: `${DOCS}/caddyfile/directives/file_server` });
    // routes after a catch-all terminal route never run (directive order!)
    const catchAll = fe.routes.find((r) => r.type === 'default' && (r.terminal || r.target));
    if (catchAll) for (const r of fe.routes.slice(fe.routes.indexOf(catchAll) + 1)) {
      add({ id: 'caddy-unreachable-route', severity: 'warning', category: 'correctness', section: fe.name, file: r.file, line: r.line, title: `${r.directive} at line ${r.line} can never run`, detail: `Caddy sorts directives by its directive order, so "${catchAll.directive}" without a matcher (line ${catchAll.line}) handles every request before "${r.directive}" is reached, wherever they are written.`, fix: 'Wrap both in mutually exclusive handle blocks (most specific first is automatic), give the catch-all a matcher, or use a route block to keep the written order.', docs: `${DOCS}/caddyfile/directives#directive-order` });
    }
    // proxy headers
    for (const x of d('header_up')) {
      const [name, ...val] = x.args; const n = String(name || '').replace(/^\+/, '').toLowerCase();
      if (['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host'].includes(n) && !String(name).startsWith('-')) add({ id: 'caddy-redundant-header-up', severity: 'info', category: 'hygiene', section: fe.name, file: x.file, line: x.line, title: `header_up ${name} is set by Caddy already`, detail: `reverse_proxy sets X-Forwarded-For and X-Forwarded-Proto (and X-Forwarded-Host since 2.5) itself, and ignores incoming values unless the client is a trusted proxy. Overriding ${name} with ${val.join(' ') || 'a value'} can drop the chain from trusted proxies or let clients spoof it.`, fix: `Remove the line; configure servers { trusted_proxies ... } to keep values from your load balancer.`, docs: `${DOCS}/caddyfile/directives/reverse_proxy#defaults` });
      if (n === 'host' && /^\{(host|http\.request\.host)\}$/.test(val[0] || '')) add({ id: 'caddy-redundant-header-up', severity: 'info', category: 'hygiene', section: fe.name, file: x.file, line: x.line, title: 'header_up Host {host} is the default for HTTP upstreams', detail: 'Caddy passes the incoming Host header through unchanged unless the upstream is HTTPS (since 2.11, Caddy then sends the upstream\'s host).', fix: 'Remove the line unless the upstream is HTTPS and needs the original host.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#https` });
      if (/authorization|token|secret|api[-_]?key|password/i.test(n) && val.length && !placeholder(val[0])) add({ id: 'caddy-inline-secret', severity: 'warning', category: 'security', section: fe.name, file: x.file, line: x.line, title: `Credential written into header_up ${name}`, detail: 'Secrets in the Caddyfile leak through repositories, backups and the admin API (/config/).', fix: `Use an environment placeholder: header_up ${name} "Bearer {env.UPSTREAM_TOKEN}"`, docs: `${DOCS}/caddyfile/concepts#environment-variables` });
    }
    for (const x of fe.directives.filter((y) => (y.keyword === 'dns' || y.keyword === 'acme_dns') && y.args[1] && !placeholder(y.args[1]) && y.args[1] !== '{')) add({ id: 'caddy-inline-secret', severity: 'warning', category: 'security', section: fe.name, file: x.file, line: x.line, title: `DNS provider credential written into the Caddyfile (${x.args[0]})`, detail: 'API tokens of the DNS provider can change your DNS zone.', fix: `dns ${x.args[0]} {env.${String(x.args[0]).toUpperCase()}_API_TOKEN}`, docs: `${DOCS}/caddyfile/directives/tls` });
    const usesClientIp = fe.directives.some((x) => x.keyword === 'client_ip' || (x.keyword === 'lb_policy' && x.args[0] === 'client_ip_hash') || (x.keyword.startsWith('@') && x.args[0] === 'client_ip')) || (fe.matchers || []).some((m) => m.parts.some((p) => p.type === 'client_ip' || (p.type === 'not' && /client_ip/.test(JSON.stringify(p.args)))));
    const nested = fe.directives.some((x) => x.keyword === 'not' && x.args[0] === 'client_ip');
    if ((usesClientIp || nested) && !trusted) add({ id: 'caddy-client-ip-untrusted', severity: 'warning', category: 'security', section: fe.name, file: fe.file, line: fe.line, title: 'client_ip is used, but no trusted_proxies are configured', detail: 'Without servers { trusted_proxies ... }, the client IP is the address of the immediate peer. Behind a load balancer or CDN every request then has the balancer\'s IP, so IP rules match everyone or no one.', fix: 'Add `servers { trusted_proxies static <your LB ranges> }` to the global options.', docs: `${DOCS}/caddyfile/options#trusted-proxies` });
    if (logged.length && !logged.includes(fe)) add({ id: 'caddy-no-access-log', severity: 'info', category: 'observability', section: fe.name, file: fe.file, line: fe.line, title: `Site ${fe.name} has no access log`, detail: `${logged.length} other site${logged.length > 1 ? 's' : ''} log requests; this one does not, so its traffic is invisible in the access logs.`, fix: 'Add a `log` directive (or import the logging snippet).', docs: `${DOCS}/caddyfile/directives/log` });
    const plainPublic = (fe.addresses || []).filter((a) => !a.tls && a.hostname && isPublicName(a.hostname));
    if (plainPublic.length && fe.routes.some((r) => r.target) && !fes.some((o) => o !== fe && (o.addresses || []).some((a) => a.tls && a.hostname === plainPublic[0].hostname))) add({ id: 'caddy-http-public', severity: 'info', category: 'security', section: fe.name, file: fe.file, line: fe.line, title: `${plainPublic[0].raw} proxies content over plain HTTP only`, detail: 'Writing http:// opts the site out of Automatic HTTPS.', fix: `Drop the http:// prefix to get a certificate and an automatic redirect.`, docs: `${DOCS}/automatic-https` });
  }

  // ---- upstreams
  for (const be of bes) {
    const live = be.servers.filter((s) => !s.disabled);
    if (!be.servers.length && !be.dynamic) add({ id: 'caddy-empty-upstreams', severity: 'error', category: 'reliability', section: be.name, file: be.file, line: be.line, title: 'reverse_proxy has no upstreams', detail: 'Every request fails with 502.', fix: 'List at least one upstream (reverse_proxy host:port) or configure dynamic upstreams.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#upstreams` });
    if (live.length > 1 && !be.healthCheck && !be.passiveHealth) add({ id: 'caddy-no-health-check', severity: 'warning', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `${live.length} upstreams without health checks`, detail: `Caddy keeps sending a share of the requests to an upstream that is down (${be.balance} selection). Retries (lb_try_duration) only help if they are configured.`, fix: 'Add active health checks (health_uri /health, health_interval 10s) and/or passive ones (fail_duration 30s), plus lb_try_duration 5s.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#active-health-checks` });
    if (be.servers.length === 1 && !be.dynamic) add({ id: 'caddy-single-upstream', severity: 'info', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `Upstream set "${be.name}" has a single upstream`, detail: 'No redundancy: when it is down, requests fail with 502.', fix: 'Add another upstream if the application can run twice.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#upstreams` });
    if (be.transport && be.transport.insecureSkipVerify) {
      add({ id: 'caddy-upstream-tls-insecure', severity: 'warning', category: 'security', section: be.name, file: be.transport.insecureFile || be.file, line: be.transport.insecureLine || be.line, title: 'tls_insecure_skip_verify disables certificate checks to the upstream', detail: 'The connection is encrypted but not authenticated: anyone in the path can impersonate the upstream.', fix: 'Remove it and trust the upstream\'s CA with tls_trust_pool file <ca.pem> (2.8+) or tls_trusted_ca_certs.', docs: `${DOCS}/caddyfile/directives/reverse_proxy#tls_insecure_skip_verify` });
    }
  }

  for (const f of findings) f.rule = RULE_TITLES[f.id] || f.id;
  findings.sort((a, b) => (SEV[a.severity] - SEV[b.severity]) || String(a.file).localeCompare(String(b.file)) || ((a.line || 0) - (b.line || 0)));
  return findings;
}

module.exports = { audit, RULE_TITLES };

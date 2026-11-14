'use strict';
/** Structural audit of a parsed Traefik configuration (rules `traefik-*`, finding shape of src/audit.js). */
const K = require('./kb');

const SEV = { error: 0, warning: 1, info: 2 };
const TITLES = {
  'traefik-syntax': 'Configuration files that do not parse', 'traefik-note': 'Load notes', 'traefik-unknown-service': 'Routers pointing at undefined services',
  'traefik-unknown-middleware': 'Routers using undefined middlewares', 'traefik-unused-service': 'Services no router uses', 'traefik-unused-middleware': 'Middlewares nothing uses',
  'traefik-single-server': 'Single-server services (no redundancy)', 'traefik-no-healthcheck': 'Load-balanced services without health checks', 'traefik-api-insecure': 'API / dashboard exposed without protection',
  'traefik-dashboard-no-auth': 'Dashboard router without authentication', 'traefik-insecure-skip-verify': 'Upstream TLS certificates not verified', 'traefik-websecure-no-tls': 'HTTPS entryPoint routers without TLS',
  'traefik-no-https-redirect': 'HTTP entryPoint without redirection to HTTPS', 'traefik-docker-exposed': 'Docker containers exposed by default', 'traefik-no-access-log': 'No access log',
  'traefik-debug-log': 'Debug logging enabled', 'traefik-weak-tls': 'TLS options allowing TLS 1.0 / 1.1', 'traefik-duplicate-rule': 'Routers with the same rule and priority',
  'traefik-no-cert': 'TLS routers without a certificate source', 'traefik-ipwhitelist': 'Deprecated ipWhiteList middleware', 'traefik-rule-error': 'Router rules that do not parse',
  'traefik-no-service': 'Routers without a service', 'traefik-unknown-transport': 'Services using an undefined serversTransport', 'traefik-empty-service': 'Services without servers',
};

function audit(sections, { notes = [] } = {}) {
  const findings = [];
  const g = (sections.find((s) => s.type === 'global') || {}).traefik || {};
  const major = '3'; // docs links follow the current major unless the rule is v2-specific
  const docs = (topic, anchor) => K.docsUrl(topic, major, anchor);
  const add = (f) => findings.push({ category: 'hygiene', detail: '', fix: '', ...f });
  const fes = sections.filter((s) => s.type === 'frontend');
  const bes = sections.filter((s) => s.type === 'backend');
  const beNames = new Set(bes.map((b) => b.name));
  const routes = fes.flatMap((fe) => fe.routes.map((r) => ({ fe, r })));
  const seenRouter = new Set();
  const once = (key) => { if (seenRouter.has(key)) return false; seenRouter.add(key); return true; };

  for (const n of notes) {
    const syntax = /syntax error/i.test(n.msg);
    add({ id: syntax ? 'traefik-syntax' : 'traefik-note', severity: syntax ? 'error' : 'info', category: syntax ? 'syntax' : 'hygiene', section: 'global', file: n.file, line: n.line || 1, title: n.msg, detail: syntax ? 'Traefik refuses a static file it cannot parse and the file provider skips a dynamic file with errors.' : 'Part of the configuration could not be analysed or needs attention.', fix: syntax ? 'Fix the syntax at the given line.' : '' });
  }

  // ---- routers
  const used = new Set();
  for (const { fe, r } of routes) {
    if (r.provider === 'internal') continue; // routers Traefik generates itself
    if (r.target) used.add(r.target);
    const key = `${r.router}@${r.provider}`;
    if (!once(`${key}|refs`)) continue;
    if (r.ruleError) add({ id: 'traefik-rule-error', severity: 'error', category: 'syntax', section: fe.name, file: r.file, line: r.line, title: `Router "${r.router}": ${r.ruleError === 'missing rule' ? 'no rule' : `rule does not parse (${r.ruleError})`}`, detail: 'Traefik disables a router whose rule is missing or invalid; its requests fall through to other routers or get a 404.', fix: 'Write the rule with matchers such as Host(`example.com`) && PathPrefix(`/api`).', docs: docs('routers') });
    if (r.missingService === '(none)') add({ id: 'traefik-no-service', severity: 'error', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `Router "${r.router}" has no service`, detail: 'A router without a service is reported as an error by Traefik and does not route.', fix: 'Add `service: <name>` to the router.', docs: docs('routerOptions') });
    else if (r.missingService) add({ id: 'traefik-unknown-service', severity: 'error', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `Router "${r.router}" uses service "${r.missingService}", which is not defined`, detail: `No ${r.proto.toUpperCase()} service of that name exists in the analysed files (a name without "@provider" is looked up in the router's own provider, "${r.provider}"). Traefik marks the router as failing and answers 404.`, fix: `Define the service, or reference another provider's service as "name@provider" (e.g. ${r.missingService.replace(/@.*/, '')}@file).`, docs: docs('routerOptions') });
    for (const m of r.missingMiddlewares || []) add({ id: 'traefik-unknown-middleware', severity: 'error', category: 'reliability', section: fe.name, file: r.file, line: r.line, title: `Router "${r.router}" uses middleware "${m}", which is not defined`, detail: 'Traefik disables a router whose middleware cannot be found.', fix: 'Define the middleware, or add the provider suffix (e.g. auth@file when the router comes from docker labels).', docs: docs('middlewares') });
    // dashboard / API without authentication
    if (/^(api|dashboard)@internal$/.test(r.target || '')) {
      const types = (r.middlewares || []).map((m) => String(m.type || '').toLowerCase());
      const auth = types.some((t) => /^(basicauth|digestauth|forwardauth|plugin)$/.test(t));
      const ip = types.some((t) => /^ip(allow|white)list$/.test(t));
      if (!auth) add({ id: 'traefik-dashboard-no-auth', severity: ip ? 'warning' : 'error', category: 'security', section: fe.name, file: r.file, line: r.line, title: `The API / dashboard router "${r.router}" has no authentication middleware${ip ? ' (only an IP allow list)' : ''}`, detail: 'The API shows the whole routing configuration (hosts, backends, middlewares); anyone who can reach this router can read it.', fix: 'Add a basicAuth, digestAuth or forwardAuth middleware to the router.', docs: docs('api') });
    }
    // HTTPS entryPoint routers without TLS
    const port = (fe.binds[0] || {}).port;
    if (r.proto === 'http' && !r.tls && !fe.entryPoint.tls && (port === '443' || /^(websecure|https)$/i.test(fe.name)) && once(`${key}|tls|${fe.name}`)) {
      add({ id: 'traefik-websecure-no-tls', severity: 'warning', category: 'security', section: fe.name, file: r.file, line: r.line, title: `Router "${r.router}" on entryPoint "${fe.name}" (${port ? `:${port}` : 'HTTPS'}) has no tls section`, detail: 'Without `tls` the router only matches plain-HTTP requests, so on an HTTPS port it never matches TLS traffic (clients get 404) - or it serves cleartext on port 443.', fix: 'Add `tls: {}` (or tls.certResolver) to the router, or set `http.tls` on the entryPoint.', docs: docs('routerOptions', 'tls') });
    }
  }

  // ---- routers that cannot be told apart: same rule, same priority, same entryPoint
  for (const fe of fes) {
    const byKey = new Map();
    for (const r of fe.routes) {
      if (r.internal || r.branch > 1) continue;
      const k = `${r.proto}|${r.priority}|${String(r.rawCondition).replace(/\s+/g, '')}|${r.tls ? 'tls' : ''}`;
      if (!byKey.has(k)) byKey.set(k, []);
      byKey.get(k).push(r);
    }
    for (const list of byKey.values()) {
      const names = [...new Set(list.map((r) => r.router))];
      if (names.length > 1) add({ id: 'traefik-duplicate-rule', severity: 'warning', category: 'reliability', section: fe.name, file: list[1].file, line: list[1].line, title: `Routers ${names.map((n) => `"${n}"`).join(', ')} have the same rule and priority (${list[0].priority}) on "${fe.name}"`, detail: 'Traefik sorts routers by priority only (later v3 releases break ties by provider precedence); with equal priority it is not defined which one serves the request.', fix: 'Remove the duplicate or give one router an explicit higher `priority`.', docs: docs('routers', 'priority') });
    }
  }

  // ---- services
  const children = new Set((g.serviceRefs || []).filter((x) => x.to).map((x) => x.to));
  for (const ref of g.serviceRefs || []) {
    if (ref.missing && ref.transport) add({ id: 'traefik-unknown-transport', severity: 'error', category: 'reliability', section: ref.from, file: ref.file, line: ref.line, title: `Service "${ref.from}" uses serversTransport "${ref.transport}", which is not defined`, detail: 'Traefik cannot build the service and routers using it fail.', fix: 'Define it under http.serversTransports or fix the name.', docs: docs('serversTransport') });
    else if (ref.missing) add({ id: 'traefik-unknown-service', severity: 'error', category: 'reliability', section: ref.from, file: ref.file, line: ref.line, title: `Service "${ref.from}" refers to service "${ref.to}", which is not defined`, detail: 'Weighted, mirroring and failover services need every child service to exist.', fix: 'Define the child service or fix the name.', docs: docs('services') });
  }
  for (const be of bes) {
    if (!used.has(be.name) && !children.has(be.name)) add({ id: 'traefik-unused-service', severity: 'warning', category: 'hygiene', section: be.name, file: be.file, line: be.line, title: `Service "${be.name}" is not used by any router`, detail: 'It may be referenced by a provider that was not uploaded (as name@provider).', fix: 'Remove it if unused.', docs: docs('services') });
    if (be.composite) continue;
    if (!be.servers.length) add({ id: 'traefik-empty-service', severity: 'error', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `Service "${be.name}" has no servers`, detail: 'Requests routed to it get 503 Service Unavailable.', fix: 'Add servers to loadBalancer.servers.', docs: docs('services') });
    else if (be.servers.length === 1) add({ id: 'traefik-single-server', severity: 'info', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `Service "${be.name}" has a single server`, detail: 'No redundancy: when it fails, requests fail.', fix: 'Add another server (and a healthCheck).', docs: docs('services') });
    else if (!be.healthCheck && be.mode === 'http') add({ id: 'traefik-no-healthcheck', severity: 'warning', category: 'reliability', section: be.name, file: be.file, line: be.line, title: `Service "${be.name}" balances ${be.servers.length} servers without a healthCheck`, detail: 'Without active health checks Traefik keeps sending a share of the requests to a server that is down.', fix: 'Add loadBalancer.healthCheck with a path and an interval.', docs: docs('services', 'health-check') });
  }

  // ---- middlewares
  for (const m of g.middlewares || []) {
    if (!m.usedBy.length) add({ id: 'traefik-unused-middleware', severity: 'info', category: 'hygiene', section: 'global', file: m.file, line: m.line, title: `Middleware "${m.name}" (${m.type}) is not used`, detail: 'No router, chain or entryPoint in the analysed files refers to it (another provider may, as name@file).', fix: 'Remove it if unused.', docs: docs('middlewares') });
  }
  for (const w of g.ipWhiteList || []) add({ id: 'traefik-ipwhitelist', severity: 'info', category: 'compatibility', section: 'global', file: w.file, line: w.line, title: `Middleware "${w.name}" uses the deprecated ipWhiteList`, detail: 'ipWhiteList is deprecated since v2.11 and renamed ipAllowList in v3 (same options). Keep it only for Traefik older than v2.11.', fix: 'On v2.11+ rename `ipWhiteList` to `ipAllowList`.', docs: K.docsUrl('migrationV3', '3') });

  // ---- static configuration
  if (g.api && g.api.insecure) add({ id: 'traefik-api-insecure', severity: 'error', category: 'security', section: 'global', file: g.file, line: g.apiLine || 1, title: 'api.insecure is true: the API and dashboard are served without authentication on the "traefik" entryPoint (:8080)', detail: 'Anyone who can reach port 8080 can read the whole configuration.', fix: 'Remove `api.insecure` and publish `api@internal` through a router with an authentication middleware.', docs: docs('api') });
  for (const t of g.serversTransports || []) if (t.insecureSkipVerify) add({ id: 'traefik-insecure-skip-verify', severity: 'warning', category: 'security', section: 'global', file: t.file, line: t.line, title: `${t.static ? 'serversTransport' : `serversTransport "${t.name}"`} has insecureSkipVerify: true`, detail: 'Backend certificates are not verified, so a man in the middle between Traefik and the backend goes unnoticed.', fix: 'Remove insecureSkipVerify and trust the backend CA with `rootCAs`.', docs: docs('serversTransport') });
  if (g.docker && !g.docker.inferred && g.docker.exposedByDefault && !g.docker.constraints) add({ id: 'traefik-docker-exposed', severity: 'warning', category: 'security', section: 'global', file: g.docker.file, line: g.docker.line, title: 'providers.docker.exposedByDefault is true (the default): every container gets a router', detail: 'Any container started on the host - a database, an admin tool - is published with a default Host rule unless it opts out.', fix: 'Set `exposedByDefault: false` and add `traefik.enable=true` to the containers you publish (or use `constraints`).', docs: docs('docker') });
  if (g.hasStatic && !g.accessLog) add({ id: 'traefik-no-access-log', severity: 'info', category: 'observability', section: 'global', file: g.file, line: 1, title: 'No access log', detail: 'Without accessLog there is no record of requests, status codes or backend timings (and nothing for Traffic Stats).', fix: 'Add `accessLog: { format: json }` (with a filePath).', docs: docs('accessLogs') });
  if (g.logLevel && /^(debug|trace)$/i.test(String(g.logLevel))) add({ id: 'traefik-debug-log', severity: 'info', category: 'observability', section: 'global', file: g.file, line: g.logLine || 1, title: `log.level is ${g.logLevel}`, detail: 'Debug logs are very verbose, slow Traefik down and can include request details. Fine while troubleshooting, not in production.', fix: 'Use `log.level: INFO` (or WARN) in production.', docs: docs('logs') });
  for (const o of g.tlsOptions || []) {
    if (/^VersionTLS1[01]$/.test(String(o.minVersion || ''))) add({ id: 'traefik-weak-tls', severity: 'warning', category: 'security', section: `tls.options.${o.name}`, file: o.file, line: o.minLine || o.line, title: `TLS options "${o.name}" allow ${o.minVersion === 'VersionTLS10' ? 'TLS 1.0' : 'TLS 1.1'}`, detail: 'TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail compliance scans.', fix: 'Set `minVersion: VersionTLS12`.', docs: docs('tls') });
  }

  // ---- entryPoints: HTTP without redirection while an HTTPS one exists
  const tlsEps = fes.filter((fe) => fe.mode === 'http' && fe.binds.some((b) => b.ssl || b.port === '443' || /^(websecure|https)$/i.test(fe.name)));
  for (const fe of fes) {
    const port = (fe.binds[0] || {}).port;
    if (fe.mode !== 'http' || fe.binds.some((b) => b.ssl) || fe.entryPoint.redirect || !(port === '80' || /^(web|http)$/i.test(fe.name)) || !tlsEps.length) continue;
    const content = fe.routes.filter((r) => r.proto === 'http' && !r.internal && !r.terminal && !(r.transforms || []).some((t) => t.action === 'redirect'));
    if (!fe.routes.length || !fe.routes.every((r) => (r.transforms || []).some((t) => t.action === 'redirect'))) add({ id: 'traefik-no-https-redirect', severity: 'warning', category: 'security', section: fe.name, file: fe.file, line: fe.line, title: `entryPoint "${fe.name}" (:${port || '80'}) does not redirect to HTTPS${content.length ? ` and serves ${content.length} route${content.length > 1 ? 's' : ''} in cleartext` : ''}`, detail: `An HTTPS entryPoint (${tlsEps.map((x) => x.name).join(', ')}) exists, but plain-HTTP requests are not sent there, so clients (and cookies) can stay on HTTP.`, fix: `Add http.redirections.entryPoint (to: ${tlsEps[0].name}, scheme: https) to the entryPoint.`, docs: docs('entrypoints', 'redirection') });
  }

  // ---- TLS routers without a certificate source
  const acme = (g.certResolvers || []).filter((c) => c.acme);
  if (acme.length && !g.tlsCertificates) {
    for (const { fe, r } of routes) {
      if (!r.tls || r.internal || r.proto !== 'http' || r.certResolver || !r.hosts.length) continue;
      const epResolver = fe.entryPoint.tls && (sections.find((s) => s.type === 'global').directives || []).some((d) => d.keyword === `entryPoints.${fe.name}.http.tls.certResolver`);
      if (epResolver || !once(`${r.router}|cert`)) continue;
      add({ id: 'traefik-no-cert', severity: 'info', category: 'security', section: fe.name, file: r.file, line: r.line, title: `Router "${r.router}" has tls but no certResolver (ACME resolver "${acme[0].name}" exists)`, detail: 'Without tls.certResolver (on the router or the entryPoint) and without a matching tls.certificates entry, Traefik serves its self-signed default certificate for these hosts.', fix: `Add tls.certResolver: ${acme[0].name} to the router (or http.tls.certResolver on the entryPoint).`, docs: docs('acme') });
    }
  }

  for (const f of findings) f.rule = TITLES[f.id] || f.id;
  findings.sort((a, b) => (SEV[a.severity] - SEV[b.severity]) || String(a.file).localeCompare(String(b.file)) || ((a.line || 0) - (b.line || 0)));
  return findings;
}

module.exports = { audit, TITLES };

'use strict';
/**
 * Config Builder for Traefik: the normalised spec (src/build/spec.js) -> static traefik.yml + dynamic.yml
 * (file provider). Version-aware: v2 / v3 option names (ipWhiteList / ipAllowList), per-server weights (v3.0+),
 * load-balancing strategies (p2c 3.5+, hrw 3.6+), failover services for backup servers (2.7+).
 */
const { normalizeSpec } = require('../../build/spec');
const K = require('./kb');
const YAML = require('./yaml');

const q = (s) => `\`${s}\``;
const slug = (s) => String(s).replace(/[^A-Za-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'root';
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function build(input) {
  const spec = normalizeSpec(input);
  const tv = K.resolveVersion(spec.version);
  const major = tv.major; const minor = tv.minor;
  const gte = (m) => K.MINORS.indexOf(minor) >= K.MINORS.indexOf(m);
  const notes = []; const unsupported = [];
  if (tv.note) notes.push(tv.note);
  notes.push(`Generated for Traefik ${tv.version} (${major === '3' ? 'v3' : 'v2'} rule syntax). Start Traefik with --configFile=/etc/traefik/traefik.yml and put dynamic.yml at /etc/traefik/dynamic.yml.`);
  const allowMw = gte('2.11') ? 'ipAllowList' : 'ipWhiteList';

  // ---------------------------------------------------------------- entryPoints
  const eps = {}; // name -> { address, ...}
  const httpEp = new Map(); const httpsEp = new Map(); // port -> name
  const epFor = (map, port, def, prefix) => { if (!map.has(port)) map.set(port, map.size === 0 && port === def ? prefix : `${prefix}-${port}`); return map.get(port); };
  for (const s of spec.sites) { epFor(httpEp, s.http.port, 80, 'web'); if (s.https) epFor(httpsEp, s.https.port, 443, 'websecure'); }
  // name the default ports first so "web" / "websecure" are :80 / :443 when used
  for (const [port, name] of [...httpEp, ...httpsEp]) eps[name] = { address: `:${port}` };
  const tlsSitesOn = (port) => spec.sites.filter((s) => s.http.port === port);
  for (const [port, name] of httpEp) {
    const sites = tlsSitesOn(port);
    if (sites.length && sites.every((s) => s.https && s.tls.redirectHttp)) {
      const to = httpsEp.get(sites[0].https.port);
      if (sites.every((s) => httpsEp.get(s.https.port) === to)) eps[name].http = { redirections: { entryPoint: { to, scheme: 'https', permanent: true } } };
    }
  }
  const timeouts = { readTimeout: `${spec.options.clientTimeout}s`, idleTimeout: `${Math.max(spec.options.clientTimeout, 180)}s` };
  for (const name of Object.keys(eps)) eps[name].transport = { respondingTimeouts: timeouts };

  // ---------------------------------------------------------------- dynamic: middlewares
  const mws = {}; const routers = {}; const services = {}; const transports = {};
  const addMw = (name, def) => { mws[name] = def; return name; };
  const acme = spec.sites.filter((s) => s.tls.mode === 'acme');
  const certs = []; const seenCert = new Set();
  for (const s of spec.sites.filter((x) => x.tls.mode === 'files')) { const k = `${s.tls.cert}|${s.tls.key}`; if (!seenCert.has(k)) { seenCert.add(k); certs.push({ certFile: s.tls.cert, keyFile: s.tls.key }); } }
  const minTls = spec.sites.some((s) => s.https && s.tls.minVersion === '1.2') || !spec.sites.some((s) => s.https) ? 'VersionTLS12' : 'VersionTLS13';
  const tlsOptions = { default: { minVersion: minTls } };
  if (minTls === 'VersionTLS12' && spec.sites.some((s) => s.https && s.tls.minVersion === '1.3')) tlsOptions.modern = { minVersion: 'VersionTLS13' };

  for (const s of spec.sites) {
    const n = slug(s.name);
    const hostRule = s.hosts.length ? s.hosts.map((h) => (h.startsWith('*.') ? (major === '3' ? `HostRegexp(${q(`^[^.]+\\.${reEsc(h.slice(2))}$`)})` : `HostRegexp(${q(`{sub:[^.]+}.${h.slice(2)}`)})`) : `Host(${q(h)})`)).join(' || ') : null;
    const withHosts = (pathRule) => (hostRule ? (pathRule ? `${s.hosts.length > 1 ? `(${hostRule})` : hostRule} && ${pathRule}` : hostRule) : (pathRule || 'PathPrefix(`/`)'));
    const tlsCfg = s.https ? (s.tls.mode === 'acme' ? { certResolver: 'letsencrypt' } : {}) : null;
    if (tlsCfg && s.tls.minVersion === '1.3' && tlsOptions.modern) tlsCfg.options = 'modern';
    const common = [];
    if (s.redirectTo) { /* a redirect-only site needs no auth, headers or compression */ } else {
    if (s.basicAuth) common.push(addMw(`${n}-auth`, { basicAuth: { realm: s.basicAuth.realm, users: s.basicAuth.users.map((u) => `${u.user}:${u.hash}`) } }));
    if (s.rateLimit) common.push(addMw(`${n}-ratelimit`, { rateLimit: { average: s.rateLimit.rps, burst: Math.max(1, s.rateLimit.burst) } }));
    if (s.maxBodyMb) common.push(addMw(`${n}-body-limit`, { buffering: { maxRequestBodyBytes: s.maxBodyMb * 1024 * 1024 } }));
    if (s.securityHeaders || (s.https && s.tls.hsts)) {
      const h = {};
      if (s.https && s.tls.hsts) h.stsSeconds = 31536000;
      if (s.securityHeaders) Object.assign(h, { contentTypeNosniff: true, customFrameOptionsValue: 'SAMEORIGIN', referrerPolicy: 'strict-origin-when-cross-origin' });
      common.push(addMw(`${n}-headers`, { headers: h }));
    }
    if (s.compression) common.push(addMw(`${n}-compress`, { compress: {} }));
    }
    const epsFor = (secure) => [secure ? httpsEp.get(s.https.port) : httpEp.get(s.http.port)];
    // routers on HTTPS (and on HTTP when there is no TLS, or TLS without redirect)
    const variants = [];
    if (s.https) variants.push({ secure: true });
    if (!s.https || !s.tls.redirectHttp) variants.push({ secure: false });
    const httpRedirectNeeded = s.https && s.tls.redirectHttp && !(eps[httpEp.get(s.http.port)].http);
    if (httpRedirectNeeded) {
      const mw = addMw(`${n}-to-https`, { redirectScheme: { scheme: 'https', permanent: true, ...(s.https.port !== 443 ? { port: String(s.https.port) } : {}) } });
      routers[`${n}-http-redirect`] = { rule: withHosts(null), entryPoints: epsFor(false), middlewares: [mw], service: 'noop@internal', priority: 1 };
    }
    for (const v of variants) {
      const suffix = v.secure || !s.https ? '' : '-http';
      const extra = (r) => { if (v.secure) r.tls = { ...tlsCfg }; return r; };
      if (s.redirectTo) {
        const target = s.redirectTo.replace(/\/+$/, '');
        const mw = addMw(`${n}-redirect`, { redirectRegex: { regex: '^https?://[^/]+/?(.*)$', replacement: `${target}/\${1}`, permanent: true } });
        routers[`${n}${suffix}`] = extra({ rule: withHosts(null), entryPoints: epsFor(v.secure), middlewares: [mw], service: 'noop@internal', priority: 1 });
        continue;
      }
      s.routes.forEach((r, i) => {
        const pathRule = r.match === 'exact' ? `Path(${q(r.path)})` : r.path === '/' ? null : `PathPrefix(${q(r.path)})`;
        const mwList = [...common];
        if (r.rewriteTo) mwList.push(addMw(`${n}-rewrite-${i + 1}`, r.match === 'exact' ? { replacePath: { path: r.rewriteTo } } : { replacePathRegex: { regex: `^${reEsc(r.path.replace(/\/$/, ''))}(.*)`, replacement: `${r.rewriteTo.replace(/\/$/, '')}\${1}` } }));
        else if (r.stripPrefix) mwList.push(addMw(`${n}-strip-${i + 1}`, { stripPrefix: { prefixes: [r.path.replace(/\/$/, '')] } }));
        // explicit priorities: exact paths first, then longer prefixes (routing/routers "Priority")
        routers[`${n}${suffix}-${slug(r.path)}${r.match === 'exact' ? '-exact' : ''}`] = extra({ rule: withHosts(pathRule), entryPoints: epsFor(v.secure), ...(mwList.length ? { middlewares: [...new Set(mwList)] } : {}), service: r.pool, priority: (r.match === 'exact' ? 2000 : 1000) + r.path.length });
      });
      if (s.defaultPool) routers[`${n}${suffix}`] = extra({ rule: withHosts(null), entryPoints: epsFor(v.secure), ...(common.length ? { middlewares: common } : {}), service: s.defaultPool, priority: 10 });
    }
    if (s.websocket) notes.push(`Site ${s.name}: WebSocket upgrades are proxied by default; nothing to configure.`);
    if (!s.defaultPool && !s.redirectTo) notes.push(`Site ${s.name}: requests that match none of its routes get Traefik's 404.`);
  }

  // ---------------------------------------------------------------- services
  const strategyFor = (p) => {
    if (p.balance === 'roundrobin') return null;
    if (p.balance === 'leastconn') { if (gte('3.5')) return 'p2c'; unsupported.push(`Pool ${p.name}: "leastconn" needs Traefik 3.5+ (strategy p2c, the closest documented algorithm); weighted round robin is used.`); return null; }
    if (p.balance === 'iphash') { if (gte('3.6')) return 'hrw'; unsupported.push(`Pool ${p.name}: "iphash" needs Traefik 3.6+ (strategy hrw); use sticky cookies for affinity. Weighted round robin is used.`); return null; }
    unsupported.push(`Pool ${p.name}: "random" has no Traefik equivalent${gte('3.5') ? ' (p2c picks the less loaded of two random servers)' : ''}; weighted round robin is used.`);
    return null;
  };
  const tlsPools = new Set(spec.sites.filter((s) => s.https).flatMap((s) => [...s.routes.map((r) => r.pool), s.defaultPool].filter(Boolean)));
  for (const p of spec.pools) {
    const lb = (servers) => {
      const o = { servers: servers.map((sv) => ({ url: `${p.scheme}://${sv.address}`, ...(major === '3' && sv.weight != null && sv.weight !== 1 ? { weight: sv.weight } : {}) })) };
      const st = strategyFor(p); if (st && servers.length > 1) o.strategy = st;
      if (p.healthCheck) o.healthCheck = { path: p.healthCheck.path, interval: `${p.healthCheck.interval}s`, timeout: `${p.healthCheck.timeout}s` };
      if (p.sticky) o.sticky = { cookie: { name: `${slug(p.name).replace(/-/g, '_')}_lb`, secure: tlsPools.has(p.name), httpOnly: true, sameSite: 'lax' } };
      o.passHostHeader = true;
      o.serversTransport = `${slug(p.name)}-transport`;
      return o;
    };
    transports[`${slug(p.name)}-transport`] = { forwardingTimeouts: { dialTimeout: `${p.timeouts.connect}s`, responseHeaderTimeout: `${p.timeouts.server}s` }, ...(p.scheme === 'https' && !p.verifyTls ? { insecureSkipVerify: true } : {}) };
    if (p.scheme === 'https' && p.verifyTls) notes.push(`Pool ${p.name}: backend certificates are verified against the system CAs; add rootCAs to ${slug(p.name)}-transport for a private CA.`);
    if (p.scheme === 'https' && !p.verifyTls) notes.push(`Pool ${p.name}: backend certificates are NOT verified (insecureSkipVerify) as requested.`);
    if (p.healthCheck && (p.healthCheck.rise !== 2 || p.healthCheck.fall !== 3)) notes.push(`Pool ${p.name}: Traefik health checks have no rise/fall counts; one failed check marks a server down.`);
    const active = p.servers.filter((s) => !s.backup); const backup = p.servers.filter((s) => s.backup);
    const weights = new Set(active.map((s) => (s.weight == null ? 1 : s.weight)));
    let main = p.name;
    if (backup.length) {
      if (gte('2.7') && p.healthCheck && active.length) {
        services[p.name] = { failover: { service: `${p.name}-primary`, fallback: `${p.name}-backup` } };
        main = `${p.name}-primary`;
        services[`${p.name}-backup`] = { loadBalancer: lb(backup) };
        notes.push(`Pool ${p.name}: backup servers are a failover service (${p.name}-backup takes over when every server of ${p.name}-primary fails its health check).`);
      } else {
        unsupported.push(`Pool ${p.name}: backup servers ${backup.map((s) => s.address).join(', ')} were left out: ${gte('2.7') ? 'a failover service needs a health check on the pool' : 'failover services need Traefik 2.7+'}.`);
      }
    }
    if (major === '2' && weights.size > 1) {
      // v2: per-server weights only through a weighted service of one-server services
      services[main] = { weighted: { services: active.map((s, i) => ({ name: `${main}-s${i + 1}`, weight: s.weight == null ? 1 : s.weight })), ...(p.sticky ? { sticky: { cookie: { name: `${slug(p.name).replace(/-/g, '_')}_w`, httpOnly: true, secure: tlsPools.has(p.name) } } } : {}) } };
      active.forEach((s, i) => { services[`${main}-s${i + 1}`] = { loadBalancer: lb([s]) }; });
      notes.push(`Pool ${p.name}: Traefik v2 has no per-server weight, so each server is its own service inside a weighted service.`);
    } else services[main] = { loadBalancer: lb(active.length ? active : p.servers) };
  }

  // ---------------------------------------------------------------- status page: API + dashboard + metrics, IP-restricted
  const sp = spec.options.statusPage;
  const statik = {
    global: { checkNewVersion: false, sendAnonymousUsage: false },
    log: { level: 'INFO' },
    ...(spec.options.accessLog ? { accessLog: { filePath: '/var/log/traefik/access.log', format: spec.options.logFormat === 'json' ? 'json' : 'common', bufferingSize: 100 } } : {}),
    entryPoints: eps,
    providers: { file: { filename: '/etc/traefik/dynamic.yml', watch: true } },
  };
  if (sp.enabled) {
    eps.traefik = { address: `:${sp.port}` };
    statik.api = { dashboard: true };
    statik.metrics = { prometheus: { entryPoint: 'traefik', manualRouting: true, addRoutersLabels: true, addServicesLabels: true } };
    const allow = addMw('status-allow', { [allowMw]: { sourceRange: sp.allow.length ? sp.allow : ['127.0.0.1/32'] } });
    routers.dashboard = { rule: 'PathPrefix(`/api`) || PathPrefix(`/dashboard`)', entryPoints: ['traefik'], middlewares: [allow], service: 'api@internal' };
    routers.metrics = { rule: 'PathPrefix(`/metrics`)', entryPoints: ['traefik'], middlewares: [allow], service: 'prometheus@internal' };
    notes.push(`Status: dashboard at http://<host>:${sp.port}/dashboard/, API at /api, Prometheus metrics at /metrics, allowed from ${(sp.allow.length ? sp.allow : ['127.0.0.1/32']).join(', ')} only. Add a basicAuth middleware for a second factor.`);
  }
  if (acme.length) {
    statik.certificatesResolvers = { letsencrypt: { acme: { email: acme.find((s) => s.tls.email) ? acme.find((s) => s.tls.email).tls.email : 'admin@example.com', storage: '/etc/traefik/acme.json', httpChallenge: { entryPoint: httpEp.get(acme[0].http.port) } } } };
    if (!acme.some((s) => s.tls.email)) notes.push('ACME: set certificatesResolvers.letsencrypt.acme.email to a real address.');
    notes.push('ACME: the HTTP challenge needs port 80 reachable from the internet; /etc/traefik/acme.json must be writable (chmod 600).');
  }
  if (spec.options.maxConnections !== 10000) unsupported.push(`options.maxConnections (${spec.options.maxConnections}): Traefik has no global connection limit (the inFlightReq middleware limits concurrent requests per client).`);
  if (spec.options.workers !== 'auto') unsupported.push('options.workers: Traefik is one Go process that uses every CPU (GOMAXPROCS); there is no worker count.');
  if (spec.options.logFormat === 'combined' && spec.options.accessLog) notes.push('Access log: Traefik\'s "common" format is CLF plus request count, router, server URL and duration (GateLight Traffic Stats reads it and JSON).');

  const dynamic = { http: { routers, ...(Object.keys(mws).length ? { middlewares: mws } : {}), services, ...(Object.keys(transports).length ? { serversTransports: transports } : {}) }, tls: { options: tlsOptions, ...(certs.length ? { certificates: certs } : {}) } };

  const head = (what) => `# ${what} - generated by GateLight for Traefik ${tv.version}\n# Docs: ${K.docsUrl(what.startsWith('Static') ? 'staticReference' : 'dynamicReference', major)}\n`;
  return {
    files: [
      { name: 'traefik.yml', content: `${head('Static configuration (traefik.yml)')}\n${YAML.stringify(statik)}\n` },
      { name: 'dynamic.yml', content: `${head('Dynamic configuration (file provider)')}\n${YAML.stringify(dynamic)}\n` },
    ],
    notes: [...new Set(notes)], unsupported: [...new Set(unsupported)],
  };
}

module.exports = { build };

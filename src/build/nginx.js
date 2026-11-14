'use strict';
/**
 * Config Builder, NGINX side: turn a product-neutral spec (./spec.js) into nginx.conf + conf.d/<site>.conf
 * (+ htpasswd/<site> for basic auth), for open-source NGINX.
 *
 * Directives and parameters are chosen for the target version (spec.version, or the newest in src/kb/nginx.json),
 * using the same knowledge base as the validator and Config Doctor:
 *   - `http2 on;` from 1.25.1, `listen ... ssl http2` from 1.9.5 before it
 *   - `ssl_reject_handshake` (1.19.4) for the TLS catch-all, a certificate + 444 before it
 *   - TLSv1.3 (1.13.0), `add_header ... always` (1.7.5), `log_format escape=json` (1.11.8), `random` (1.15.1),
 *     upstream `zone` (1.9.0), `limit_req_status` (1.3.15), `$request_id` (1.11.0)
 *   - `sticky cookie` in the open-source upstream module (KB changelog: 1.31.0); a cookie + consistent hash before it
 * What open-source NGINX cannot do (active health checks: NGINX Plus `health_check`; built-in ACME: the separate
 * ngx_http_acme_module) is listed in `unsupported` with the workaround that is generated instead.
 */
const { normalizeSpec } = require('./spec');
const V = require('../validate/version');
const kb = require('../kb/nginx.json');

const IND = '    ';
const CIPHERS = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const GZIP_TYPES = 'text/plain text/css text/xml text/javascript application/javascript application/json application/xml image/svg+xml';
const CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt';
const WEBROOT = '/var/www/letsencrypt';
const ACME_PATH = '/.well-known/acme-challenge/';
const isIp = (h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':');
const hostOf = (addr) => addr.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
const ident = (s) => String(s).replace(/[^A-Za-z0-9_]/g, '_');
const q = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const isLoopback = (a) => /^127\./.test(a) || a === '::1' || a === '::1/128';
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Resolve the target version ("1.24" -> "1.24.0"; null -> newest documented). */
function targetOf(version, notes) {
  if (!version) return kb.latest;
  const p = V.parse(V.detect(version) || version);
  if (!p) { notes.push(`Could not read "${version}" as an NGINX version; the configuration targets ${kb.latest}.`); return kb.latest; }
  const t = p.join('.');
  if (V.cmp(t, kb.latest) > 0) notes.push(`NGINX ${t} is newer than the newest documented release (${kb.latest}); the configuration uses what ${kb.latest} documents.`);
  return t;
}

/** A tiny writer that keeps the indentation of nested blocks. */
function writer() {
  const lines = []; let depth = 0;
  const w = {
    lines,
    line: (t) => { lines.push(`${IND.repeat(depth)}${t}`); return w; },
    comment: (t) => { [].concat(t).forEach((c) => lines.push(`${IND.repeat(depth)}# ${c}`)); return w; },
    open: (head) => { lines.push(`${IND.repeat(depth)}${head} {`); depth++; return w; },
    close: () => { depth--; lines.push(`${IND.repeat(depth)}}`); return w; },
    blank: () => { const last = lines[lines.length - 1]; if (lines.length && last !== '' && !/\{$/.test(last)) lines.push(''); return w; },
    text: () => `${lines.join('\n').replace(/\n{3,}/g, '\n\n')}\n`,
  };
  return w;
}

function build(input) {
  const spec = normalizeSpec(input);
  const notes = []; const unsupported = [];
  const t = targetOf(spec.version, notes);
  const ge = (v) => V.gte(t, v);
  const o = spec.options;
  const poolBy = new Map(spec.pools.map((p) => [p.name, p]));
  const always = ge('1.7.5') ? ' always' : '';
  const sites = spec.sites;

  // ------------------------------------------------------------------------------------------ what is used
  const usesPool = (s, n) => !s.redirectTo && (s.defaultPool === n || s.routes.some((r) => r.pool === n));
  const usedPools = spec.pools.map((p) => p.name).filter((n) => sites.some((s) => usesPool(s, n)));
  spec.pools.filter((p) => !usedPools.includes(p.name)).forEach((p) => notes.push(`Pool "${p.name}" is not used by any site, so no upstream was written for it.`));
  const sitesUsing = (n) => sites.filter((s) => usesPool(s, n));
  const tlsSites = sites.filter((s) => s.tls.mode !== 'none');
  const acmeSites = sites.filter((s) => s.tls.mode === 'acme');
  const certOf = (s) => (s.tls.mode === 'acme' ? { cert: `/etc/letsencrypt/live/${s.hosts[0]}/fullchain.pem`, key: `/etc/letsencrypt/live/${s.hosts[0]}/privkey.pem` } : { cert: s.tls.cert, key: s.tls.key });
  const anyWs = sites.some((s) => s.websocket && !s.redirectTo);
  const nativeSticky = ge('1.31.0') && Boolean(kb.directives.sticky);
  const stickyMode = (p) => (!p.sticky ? null : nativeSticky ? 'native' : ge('1.11.0') && ge('1.7.2') ? 'hash' : 'iphash');
  const balanceOf = (p) => {
    const st = stickyMode(p);
    if (st === 'hash') return 'hash';
    if (st === 'iphash' || p.balance === 'iphash') return 'ip_hash';
    if (p.balance === 'random') return ge('1.15.1') ? 'random' : null;
    return p.balance === 'leastconn' ? 'least_conn' : null;
  };
  const httpsOnly = (n) => sitesUsing(n).every((s) => s.tls.mode !== 'none' && s.tls.redirectHttp);
  const cookieName = (n) => `gl_${ident(n)}`;

  // ports: which ones have a catch-all site (it becomes the default server there)
  const defaultTaken = new Map(); // "port" or "port ssl" -> site name
  for (const s of sites.filter((x) => !x.hosts.length)) {
    for (const key of [`${s.http.port}`, ...(s.https ? [`${s.https.port} ssl`] : [])]) {
      if (defaultTaken.has(key)) unsupported.push(`Sites "${defaultTaken.get(key)}" and "${s.name}" are both catch-alls (no host names) on port ${key.split(' ')[0]}; NGINX has one default server per port, so "${defaultTaken.get(key)}" answers unknown hosts there.`);
      else defaultTaken.set(key, s.name);
    }
  }

  // ------------------------------------------------------------------------------------------ nginx.conf
  const m = writer();
  m.comment('NGINX configuration generated by GateLight Config Builder (spec format 1)');
  m.comment(`Target: NGINX ${t}${spec.version ? ` (requested ${spec.version})` : ' (newest documented release)'}, open source. Check it with: nginx -t`);
  m.comment(`Sites: ${sites.map((s) => `${s.name} (${s.hosts.length ? s.hosts.join(', ') : 'any host'})`).join('; ')} -> conf.d/<site>.conf`);
  m.blank();
  const workerConns = Math.min(65535, Math.max(512, o.maxConnections));
  m.line(`worker_processes ${o.workers === 'auto' ? 'auto' : o.workers};`);
  if (workerConns > 1024) m.line(`worker_rlimit_nofile ${workerConns * 2};`);
  m.line('error_log /var/log/nginx/error.log warn;');
  m.blank();
  m.open('events');
  m.comment('Per worker; every proxied request uses two connections (client and upstream)');
  m.line(`worker_connections ${workerConns};`);
  m.close();
  if (o.maxConnections > 65535) notes.push('worker_connections is capped at 65535 per worker.');
  m.blank();
  m.open('http');
  m.line('include mime.types;');
  m.line('default_type application/octet-stream;');
  m.blank();
  m.comment('Basics: hide the version, send files efficiently, drop slow clients');
  m.line('server_tokens off;');
  m.line('sendfile on;');
  m.line('tcp_nopush on;');
  m.line('tcp_nodelay on;');
  m.line(`keepalive_timeout ${Math.min(o.clientTimeout, 75)}s;`);
  m.line(`client_header_timeout ${Math.min(o.clientTimeout, 15)}s;`);
  m.line(`client_body_timeout ${o.clientTimeout}s;`);
  m.line(`send_timeout ${o.clientTimeout}s;`);
  if (sites.some((s) => !s.redirectTo && s.maxBodyMb == null)) notes.push(`Sites without maxBodyMb keep the NGINX default request body limit of 1 MB (client_max_body_size); set maxBodyMb: 0 for no limit.`);

  m.blank();
  if (o.accessLog) {
    if (o.logFormat === 'json') {
      m.comment('Access log: one JSON object per request');
      const fmt = '{"time":"$time_iso8601","client":"$remote_addr","host":"$host","method":"$request_method","uri":"$request_uri","status":$status,"bytes":$body_bytes_sent,"duration":$request_time,"upstream":"$upstream_addr","upstream_time":"$upstream_response_time","referer":"$http_referer","user_agent":"$http_user_agent"}';
      m.line(`log_format json${ge('1.11.8') ? ' escape=json' : ''} '${fmt}';`);
      if (!ge('1.11.8')) notes.push(`NGINX ${t} cannot JSON-escape log values (log_format escape=json arrived in 1.11.8); values with quotes break the JSON.`);
      m.line('access_log /var/log/nginx/access.log json;');
    } else {
      m.comment('Access log in the standard "combined" format');
      m.line('access_log /var/log/nginx/access.log combined;');
    }
  } else { m.comment('Access logs are off (errors still go to the error log)'); m.line('access_log off;'); }

  const gz = sites.filter((s) => !s.redirectTo);
  const gzAll = gz.length && gz.every((s) => s.compression); const gzAny = gz.some((s) => s.compression);
  if (gzAny) {
    m.blank(); m.comment(gzAll ? 'Compress text responses' : 'Compression settings (switched on per site)');
    if (gzAll) m.line('gzip on;');
    m.line('gzip_vary on;'); m.line('gzip_proxied any;'); m.line('gzip_comp_level 5;'); m.line('gzip_min_length 1024;');
    m.line(`gzip_types ${GZIP_TYPES};`);
  }
  if (tlsSites.length) {
    m.blank(); m.comment('TLS: TLS 1.2+ with forward-secret AEAD ciphers, shared session cache, no tickets');
    const floor13 = tlsSites.every((s) => s.tls.minVersion === '1.3') && ge('1.13.0');
    m.line(`ssl_protocols ${floor13 ? 'TLSv1.3' : `TLSv1.2${ge('1.13.0') ? ' TLSv1.3' : ''}`};`);
    m.line(`ssl_ciphers ${CIPHERS};`);
    m.line('ssl_prefer_server_ciphers off;');
    m.line('ssl_session_cache shared:SSL:10m;');
    m.line('ssl_session_timeout 1d;');
    if (ge('1.5.9')) m.line('ssl_session_tickets off;');
    if (!ge('1.13.0') && tlsSites.some((s) => s.tls.minVersion === '1.3')) notes.push(`NGINX ${t} cannot use TLS 1.3 (1.13.0+); TLS 1.2 is the floor.`);
  }
  const rlSites = sites.filter((s) => s.rateLimit && !s.redirectTo);
  if (rlSites.length) {
    m.blank(); m.comment('Rate limits: one zone per site, keyed by client address');
    for (const s of rlSites) m.line(`limit_req_zone $binary_remote_addr zone=rl_${ident(s.name)}:10m rate=${s.rateLimit.rps}r/s;`);
    if (ge('1.3.15')) m.line('limit_req_status 429;');
    else notes.push(`NGINX ${t} answers rate-limited requests with 503 (limit_req_status arrived in 1.3.15).`);
  }
  if (anyWs) {
    m.blank(); m.comment('WebSocket: pass "Connection: upgrade" through, otherwise keep upstream connections alive');
    m.open('map $http_upgrade $connection_upgrade'); m.line('default upgrade;'); m.line("'' '';"); m.close();
  }
  const hashSticky = usedPools.map((n) => poolBy.get(n)).filter((p) => stickyMode(p) === 'hash');
  for (const p of hashSticky) {
    const c = cookieName(p.name);
    m.blank(); m.comment([`Sticky sessions for pool "${p.name}" (open-source NGINX ${t} has no "sticky" directive): the cookie`, `${c} carries a random key and the upstream hashes it, so a client keeps its server.`]);
    m.open(`map $cookie_${c} $${c}_key`); m.line('"" $request_id;'); m.line(`default $cookie_${c};`); m.close();
    m.open(`map $cookie_${c} $${c}_set`); m.line(`"" ${q(`${c}=$request_id; Path=/; HttpOnly; SameSite=Lax${httpsOnly(p.name) ? '; Secure' : ''}`)};`); m.line('default "";'); m.close();
    notes.push(`Pool "${p.name}": sticky sessions use a cookie (${c}) and "hash ... consistent" because the open-source "sticky" directive is only documented from NGINX 1.31.0 on; this replaces the "${p.balance}" balancing for that pool.`);
  }
  for (const p of usedPools.map((n) => poolBy.get(n)).filter((x) => stickyMode(x) === 'iphash')) notes.push(`Pool "${p.name}": NGINX ${t} cannot set a sticky cookie; ip_hash keeps each client address on one server instead.`);

  // --- upstreams
  for (const name of usedPools) {
    const p = poolBy.get(name); const users = sitesUsing(name);
    m.blank(); m.comment(`Pool "${name}": ${p.servers.length} server${p.servers.length > 1 ? 's' : ''}, used by ${users.map((s) => s.name).join(', ')}`);
    m.open(`upstream ${name}`);
    const bal = balanceOf(p);
    if (p.balance === 'random' && !ge('1.15.1')) notes.push(`Pool "${name}": "random" needs NGINX 1.15.1+; round-robin is used.`);
    if (bal === 'hash') m.line(`hash $${cookieName(name)}_key consistent;`);
    else if (bal) m.line(`${bal};`);
    if (ge('1.9.0')) m.line(`zone ${name} 64k;`);
    const noBackup = ['ip_hash', 'hash', 'random'].includes(bal);
    const hc = p.healthCheck;
    const passive = hc ? ` max_fails=${hc.fall} fail_timeout=${Math.max(hc.interval * hc.fall, 10)}s` : '';
    if (hc) m.comment(`Passive health check: ${hc.fall} failed requests take a server out for ${Math.max(hc.interval * hc.fall, 10)}s`);
    p.servers.forEach((sv) => {
      const params = [];
      if (sv.weight === 0) params.push('down');
      else if (sv.weight != null && sv.weight !== 1) params.push(`weight=${sv.weight}`);
      if (sv.backup && noBackup) { m.line(`# server ${sv.address}${passive} backup;   # "backup" cannot be combined with ${bal}`); return; }
      if (sv.backup) params.push('backup');
      m.line(`server ${sv.address}${passive}${params.length ? ` ${params.join(' ')}` : ''};`);
    });
    if (p.servers.some((x) => x.backup) && noBackup) unsupported.push(`Pool "${name}": NGINX does not allow backup servers with ${bal} (https://nginx.org/en/docs/http/ngx_http_upstream_module.html#server); the backup server lines are commented out.`);
    if (p.servers.some((x) => x.weight === 0)) notes.push(`Pool "${name}": NGINX has no weight 0; those servers are marked "down".`);
    if (stickyMode(p) === 'native') m.line(`sticky cookie ${cookieName(name)} path=/ httponly samesite=lax${httpsOnly(name) ? ' secure' : ''};`);
    if (ge('1.1.4')) m.line('keepalive 32;');
    m.close();
    if (hc) unsupported.push(`Pool "${name}": active health checks (GET ${hc.path} every ${hc.interval}s) need NGINX Plus ("health_check", https://nginx.org/en/docs/http/ngx_http_upstream_hc_module.html). Open-source NGINX only checks passively: max_fails=${hc.fall} fail_timeout=${Math.max(hc.interval * hc.fall, 10)}s.`);
    if (p.scheme === 'https') {
      const names = [...new Set(p.servers.map((x) => hostOf(x.address)).filter((h) => !isIp(h)))];
      if (p.verifyTls) notes.push(`Pool "${name}": upstream certificates are verified against ${CA_BUNDLE} (Debian/Ubuntu/Alpine; RHEL: /etc/pki/tls/certs/ca-bundle.crt, or your internal CA)${names.length > 1 ? `; NGINX checks every server against one name (${names[0]})` : ''}${!names.length ? '; the servers are IP addresses, so set proxy_ssl_name to the name in their certificate' : ''}.`);
      else notes.push(`Pool "${name}": TLS to the servers is encrypted but not authenticated (proxy_ssl_verify off), as requested.`);
    }
  }

  // --- default servers for unknown host names
  const portSet = new Map(); // key -> [sites]
  for (const s of sites) {
    const keyP = `${s.http.port}`; (portSet.get(keyP) || portSet.set(keyP, []).get(keyP)).push(s);
    if (s.https) { const k = `${s.https.port} ssl`; (portSet.get(k) || portSet.set(k, []).get(k)).push(s); }
  }
  const http2Listen = ge('1.9.5') && !ge('1.25.1');
  for (const [key, list] of portSet) {
    if (defaultTaken.has(key)) continue;
    const [port, ssl] = key.split(' ');
    m.blank();
    if (!ssl) {
      m.comment(`Port ${port}: requests for unknown host names are closed without an answer`);
      m.open('server'); m.line(`listen ${port} default_server;`); m.line('server_name _;'); m.line('return 444;'); m.close();
    } else {
      const c = certOf(list[0]);
      if (ge('1.19.4')) {
        m.comment([`Port ${port}: TLS handshakes for unknown host names are refused (ssl_reject_handshake).`, 'The certificate is never sent; it is listed for tools that expect one in every TLS server.']);
        m.open('server'); m.line(`listen ${port} ssl${http2Listen ? ' http2' : ''} default_server;`); m.line('server_name _;'); m.line('ssl_reject_handshake on;');
      } else {
        m.comment([`Port ${port}: unknown host names are closed without an answer (NGINX ${t} needs a certificate here;`, 'ssl_reject_handshake arrived in 1.19.4)']);
        m.open('server'); m.line(`listen ${port} ssl${http2Listen ? ' http2' : ''} default_server;`); m.line('server_name _;');
      }
      m.line(`ssl_certificate ${c.cert};`); m.line(`ssl_certificate_key ${c.key};`);
      if (!ge('1.19.4')) m.line('return 444;');
      m.close();
    }
  }

  // --- status page
  if (o.statusPage.enabled) {
    const sp = o.statusPage; const allow = sp.allow.length ? sp.allow : ['127.0.0.1'];
    if (portSet.has(`${sp.port}`) || portSet.has(`${sp.port} ssl`)) unsupported.push(`The status page port ${sp.port} is also used by a site; the status page was left out. Choose another port.`);
    else {
      m.blank(); m.comment(`Status page (stub_status, needs --with-http_stub_status_module): http://<host>:${sp.port}/nginx_status`);
      m.open('server');
      m.line(`listen ${allow.every(isLoopback) ? '127.0.0.1:' : ''}${sp.port};`);
      m.line('access_log off;');
      m.open('location = /nginx_status');
      m.line(ge('1.7.5') ? 'stub_status;' : 'stub_status on;');
      allow.forEach((a) => m.line(`allow ${a};`));
      m.line('deny all;');
      m.close();
      m.open('location /'); m.line('return 404;'); m.close();
      m.close();
    }
  }
  m.blank();
  m.comment('One file per site');
  m.line('include conf.d/*.conf;');
  m.close();

  // ------------------------------------------------------------------------------------------ conf.d/<site>.conf
  const files = [{ name: 'nginx.conf', content: m.text() }];
  for (const s of sites) {
    const w = writer();
    const names = s.hosts.length ? s.hosts.join(' ') : '_';
    const tls = s.tls.mode !== 'none';
    const c = tls ? certOf(s) : null;
    w.comment(`Site "${s.name}": ${s.hosts.length ? s.hosts.join(', ') : 'any host name (catch-all)'}`);
    w.comment(`Generated by GateLight Config Builder for NGINX ${t}; included from nginx.conf (http context).`);
    const listen = (port, ssl) => `listen ${port}${ssl ? ' ssl' : ''}${ssl && http2Listen ? ' http2' : ''}${defaultTaken.get(`${port}${ssl ? ' ssl' : ''}`) === s.name ? ' default_server' : ''};`;
    const acmeLocation = () => {
      w.comment('ACME HTTP-01 challenges for certbot (webroot mode)');
      w.open(`location ^~ ${ACME_PATH}`);
      w.line(`alias ${WEBROOT}${ACME_PATH};`);
      w.line('default_type text/plain;');
      if (s.basicAuth && !s.redirectTo) w.line('auth_basic off;');
      w.close();
      w.blank();
    };
    const tlsLines = () => {
      if (ge('1.25.1')) w.line('http2 on;');
      w.line(`server_name ${names};`);
      w.blank();
      w.line(`ssl_certificate ${c.cert};`);
      w.line(`ssl_certificate_key ${c.key};`);
      if (s.tls.minVersion === '1.3' && ge('1.13.0') && !tlsSites.every((x) => x.tls.minVersion === '1.3')) {
        w.line('ssl_protocols TLSv1.3;');
        notes.push(`Site "${s.name}": "ssl_protocols TLSv1.3" is set in its server block, but NGINX may negotiate the protocol with the settings of the port's default server before it sees the host name (depends on the NGINX and OpenSSL build). For a guaranteed TLS 1.3 floor give the site its own port, or make every site on the port TLS 1.3 only.`);
      }
    };
    const headerLines = () => {
      const h = [];
      if (tls && s.tls.hsts) h.push(`add_header Strict-Transport-Security "max-age=31536000"${always};`);
      if (s.securityHeaders) {
        h.push(`add_header X-Content-Type-Options "nosniff"${always};`);
        h.push(`add_header X-Frame-Options "SAMEORIGIN"${always};`);
        h.push(`add_header Referrer-Policy "strict-origin-when-cross-origin"${always};`);
      }
      const stickyFor = [...new Set([...s.routes.map((r) => r.pool), s.defaultPool].filter(Boolean))].filter((n) => stickyMode(poolBy.get(n)) === 'hash');
      stickyFor.forEach((n) => h.push(`add_header Set-Cookie $${cookieName(n)}_set;`));
      if (h.length) { w.blank(); w.comment(stickyFor.length ? 'Response headers (security headers; the sticky cookie is only sent when missing)' : 'Security headers, also on error pages'); h.forEach(w.line); }
    };

    if (s.redirectTo) {
      // ------------------------------------------------------------------ redirect-only site
      const u = new URL(s.redirectTo);
      const keepPath = u.pathname === '/' && !u.search;
      const target = keepPath ? `${u.protocol}//${u.host}$request_uri` : s.redirectTo;
      w.blank(); w.comment(`Only redirects to ${s.redirectTo}${keepPath ? ' (path and query are kept)' : ''}`);
      w.open('server');
      w.line(listen(s.http.port, false));
      if (tls) { w.line(listen(s.https.port, true)); tlsLines(); } else w.line(`server_name ${names};`);
      headerLines();
      w.blank();
      if (s.tls.mode === 'acme') { acmeLocation(); w.open('location /'); w.line(`return 301 ${target};`); w.close(); } else w.line(`return 301 ${target};`);
      w.close();
      files.push({ name: `conf.d/${s.name}.conf`, content: w.text() });
      if (s.basicAuth) notes.push(`Site "${s.name}" only redirects, so its basic auth is not used.`);
      continue;
    }

    // ------------------------------------------------------------------ HTTP -> HTTPS redirect server
    const split = tls && s.tls.redirectHttp;
    if (split) {
      w.blank(); w.comment('Plain HTTP: redirect to HTTPS');
      w.open('server');
      w.line(listen(s.http.port, false));
      w.line(`server_name ${names};`);
      const to = `https://$host${s.https.port === 443 ? '' : `:${s.https.port}`}$request_uri`;
      w.blank();
      if (s.tls.mode === 'acme') { acmeLocation(); w.open('location /'); w.line(`return 301 ${to};`); w.close(); } else w.line(`return 301 ${to};`);
      w.close();
    }

    // ------------------------------------------------------------------ the site itself
    w.blank(); w.comment(split ? 'HTTPS' : tls ? 'HTTP and HTTPS (no redirect to HTTPS, as requested)' : 'HTTP');
    w.open('server');
    if (!split) w.line(listen(s.http.port, false));
    if (tls) { w.line(listen(s.https.port, true)); tlsLines(); } else w.line(`server_name ${names};`);
    headerLines();
    const limits = [];
    if (s.maxBodyMb != null) limits.push(`client_max_body_size ${s.maxBodyMb ? `${s.maxBodyMb}m` : '0'};`);
    if (s.compression && !gzAll) limits.push('gzip on;');
    if (limits.length) { w.blank(); limits.forEach(w.line); }
    if (s.rateLimit) { w.blank(); w.comment(`At most ${s.rateLimit.rps} requests/s per client address, bursts of ${s.rateLimit.burst} served at once`); w.line(`limit_req zone=rl_${ident(s.name)} burst=${s.rateLimit.burst} nodelay;`); }
    if (s.basicAuth) {
      w.blank(); w.comment('Basic authentication (users in htpasswd/' + s.name + ', next to nginx.conf)');
      w.line(`auth_basic ${q(s.basicAuth.realm)};`);
      w.line(`auth_basic_user_file htpasswd/${s.name};`);
      files.push({ name: `htpasswd/${s.name}`, content: `# Users for site "${s.name}" (bcrypt), generated by GateLight Config Builder.\n# Path is relative to the directory of nginx.conf; keep it readable by the nginx workers only.\n${s.basicAuth.users.map((u) => `${u.user}:${u.hash}`).join('\n')}\n` });
    }
    // proxy defaults (all at server level: proxy_set_header in a location would replace the whole list)
    w.blank(); w.comment('Proxying: the same headers for every location below');
    w.line('proxy_http_version 1.1;');
    w.line('proxy_set_header Host $host;');
    w.line('proxy_set_header X-Real-IP $remote_addr;');
    w.line('proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;');
    w.line('proxy_set_header X-Forwarded-Proto $scheme;');
    if (s.websocket) { w.line('proxy_set_header Upgrade $http_upgrade;'); w.line('proxy_set_header Connection $connection_upgrade;'); } else {
      if (ge('1.29.7')) w.comment('HTTP/1.1 and no Connection header are the defaults from NGINX 1.29.7; kept for older versions');
      w.line('proxy_set_header Connection "";');
    }

    if (s.tls.mode === 'acme' && !split) { w.blank(); acmeLocation(); }
    const seen = new Set();
    const loc = (head, pool, body) => {
      const p = poolBy.get(pool);
      w.blank(); w.open(`location ${head}`);
      body.forEach((b) => w.line(b));
      w.line(`proxy_connect_timeout ${p.timeouts.connect}s;`);
      w.line(`proxy_send_timeout ${s.websocket ? Math.max(p.timeouts.server, 3600) : p.timeouts.server}s;`);
      w.line(`proxy_read_timeout ${s.websocket ? Math.max(p.timeouts.server, 3600) : p.timeouts.server}s;`);
      if (p.scheme === 'https') {
        if (p.verifyTls) {
          const host = p.servers.map((x) => hostOf(x.address)).find((h) => !isIp(h));
          w.line('proxy_ssl_verify on;');
          w.line(`proxy_ssl_trusted_certificate ${CA_BUNDLE};`);
          w.line('proxy_ssl_verify_depth 2;');
          w.line('proxy_ssl_server_name on;');
          if (host) w.line(`proxy_ssl_name ${host};`); else w.comment('proxy_ssl_name <name in the servers\' certificate>;   # the servers are IP addresses');
        } else w.line('proxy_ssl_verify off;');
      }
      w.close();
    };
    for (const r of s.routes) {
      const key = `${r.match} ${r.path}`;
      if (seen.has(key)) { notes.push(`Site "${s.name}": route ${r.path} is listed twice; the first one is used.`); continue; }
      seen.add(key);
      const up = `${poolBy.get(r.pool).scheme}://${r.pool}`;
      const to = r.rewriteTo || (r.stripPrefix ? '/' : null);
      if (r.stripPrefix && r.rewriteTo) notes.push(`Site "${s.name}": route ${r.path} has both stripPrefix and rewriteTo; rewriteTo wins.`);
      let body;
      if (r.match === 'exact') body = [`proxy_pass ${up}${to || ''};`];
      else if (!to) body = [`proxy_pass ${up};`];
      else if (r.path.endsWith('/')) body = [`proxy_pass ${up}${to.replace(/\/$/, '')}/;`];
      else if (to === '/') body = [`rewrite ^${reEsc(r.path)}/?(.*)$ /$1 break;`, `proxy_pass ${up};`];
      else body = [`proxy_pass ${up}${to.replace(/\/$/, '')};`];
      loc(r.match === 'exact' ? `= ${r.path}` : r.path, r.pool, body);
    }
    if (!seen.has('prefix /')) {
      if (s.defaultPool) loc('/', s.defaultPool, [`proxy_pass ${poolBy.get(s.defaultPool).scheme}://${s.defaultPool};`]);
      else { w.blank(); w.comment('No default pool: everything outside the routes above is not found'); w.open('location /'); w.line('return 404;'); w.close(); }
    }
    w.close();
    files.push({ name: `conf.d/${s.name}.conf`, content: w.text() });
  }

  // ------------------------------------------------------------------------------------------ notes
  if (acmeSites.length) {
    unsupported.push(`Automatic certificates (ACME): open-source NGINX has no built-in ACME client; the separate ngx_http_acme_module (https://nginx.org/en/docs/http/ngx_http_acme_module.html, package nginx-module-acme, loaded with load_module) is not part of a standard build. The configuration uses certbot instead: challenges are served from ${WEBROOT} and certificates are read from /etc/letsencrypt/live/<first host>/. Issue with: certbot certonly --webroot -w ${WEBROOT} ${acmeSites.map((s) => s.hosts.map((h) => `-d ${h}`).join(' ')).join(' ; ')}${acmeSites.find((s) => s.tls.email) ? ` --email ${acmeSites.find((s) => s.tls.email).tls.email}` : ''}, and reload NGINX from a deploy hook (--deploy-hook "systemctl reload nginx"). NGINX refuses to start while a certificate file is missing: start with a temporary self-signed one, or issue the first certificate before enabling the HTTPS server.`);
  }
  if (sites.some((s) => s.basicAuth && !s.redirectTo)) notes.push('Basic auth: NGINX checks the bcrypt hashes in htpasswd/<site> with the system crypt(), which knows $2y$/$2b$ with libxcrypt (Debian 11+, Ubuntu 22.04+, RHEL/Fedora) and musl (Alpine) but not with an old glibc-only crypt; there, regenerate the users with: openssl passwd -6. Deploy htpasswd/ next to nginx.conf (e.g. /etc/nginx/htpasswd/), readable by the nginx workers only.');
  if (sites.some((s) => s.websocket && !s.redirectTo)) notes.push('WebSocket sites keep idle proxied connections open for up to an hour (proxy_read_timeout / proxy_send_timeout 3600s), which also applies to slow ordinary requests on those sites.');
  if (o.statusPage.enabled && !o.statusPage.allow.every(isLoopback)) notes.push(`Status page: listens on all addresses (port ${o.statusPage.port}) and only answers ${o.statusPage.allow.join(', ')} (allow/deny).`);
  notes.push('Listeners are IPv4 only; add "listen [::]:<port> ...;" lines next to each listen for IPv6.');
  return { files, notes: [...new Set(notes)], unsupported: [...new Set(unsupported)] };
}

module.exports = { build, targetOf };

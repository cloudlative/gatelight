'use strict';
/**
 * Config Builder, HAProxy side: turn a product-neutral spec (./spec.js) into one haproxy.cfg.
 *
 * Every keyword is chosen for the target branch (spec.version, or the newest in src/kb/haproxy.json), using the same
 * knowledge base as the validator and Config Doctor, so the output validates cleanly for that version:
 *   - `ssl-min-ver` (1.8+) or `no-tlsv10 no-tlsv11` before it; TLS 1.3 suites from 1.8
 *   - `http-request return` / `deny_status 404|413` and `http-check send` from 2.2, `option httpchk GET /x` before
 *   - `replace-path` from 2.0, `set-path %[path,regsub(...)]` before; `balance random` from 1.9
 *   - `crt-store` (separate key file) from 3.0, native ACME (`acme` section) from 3.2
 *   - the Prometheus exporter service from 2.4
 * Anything a version cannot do goes to `unsupported` with the reason; smaller compromises go to `notes`.
 *
 * Layout: global, [resolvers], [acme], [crt-store], defaults, [userlists], one frontend per group of sites that share a
 * port, [stats listen], one backend per pool that a site uses.
 */
const { normalizeSpec } = require('./spec');
const V = require('../validate/version');
const kb = require('../kb/haproxy.json');

const IND = '    ';
const CIPHERS = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const SUITES = 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';
const COMPRESS_TYPES = 'text/html text/plain text/css text/xml text/javascript application/javascript application/json application/xml image/svg+xml';
const CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt';
const CERT_DIR = '/etc/haproxy/certs';
const ACME_PATH = '/.well-known/acme-challenge/';
const DOCS = (branch) => `https://docs.haproxy.org/${branch}/configuration.html`;

const LATEST = kb.versions[kb.versions.length - 1];
const isIp = (h) => /^\[?[0-9a-fA-F:.]+\]?$/.test(h) && (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':'));
const hostOf = (addr) => addr.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const ident = (s) => String(s).replace(/[^A-Za-z0-9_.-]/g, '_');
const q = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const isLoopback = (a) => /^127\./.test(a) || a === '::1' || a === '::1/128';

/** Resolve the target branch ("2.8.5" -> "2.8"; null -> newest documented). */
function targetOf(version, notes) {
  if (!version) return LATEST;
  const b = V.haproxyBranch(V.detect(version) || version, kb.versions);
  if (!b) { notes.push(`Could not read "${version}" as a HAProxy version; the configuration targets ${LATEST}.`); return LATEST; }
  if (V.lt(version, kb.versions[0])) notes.push(`HAProxy ${version} is older than the oldest documented branch (${kb.versions[0]}); the configuration targets ${b}.`);
  return b;
}

/** Group sites into frontends: sites that share any port must live in the same frontend (a port is bound once). */
function groupSites(sites) {
  const parent = sites.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const byPort = new Map();
  sites.forEach((s, i) => [s.http.port, s.https && s.https.port].filter(Boolean).forEach((p) => {
    if (byPort.has(p)) parent[find(i)] = find(byPort.get(p)); else byPort.set(p, i);
  }));
  const groups = new Map();
  sites.forEach((s, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(s); });
  return [...groups.values()];
}

function build(input) {
  const spec = normalizeSpec(input);
  const notes = []; const unsupported = [];
  const t = targetOf(spec.version, notes);
  const ge = (v) => V.gte(t, v);
  const docs = () => DOCS(t);
  const poolBy = new Map(spec.pools.map((p) => [p.name, p]));
  const o = spec.options;

  // ------------------------------------------------------------------------------------------ what is used
  const sites = spec.sites.filter((s) => {
    const plain = s.http.port; const tls = s.https && s.https.port;
    const clash = spec.sites.find((x) => x !== s && ((tls && x.http.port === tls) || (x.https && x.https.port === plain)));
    if (clash && spec.sites.indexOf(clash) < spec.sites.indexOf(s)) {
      unsupported.push(`Site "${s.name}" uses a port as plain HTTP and as HTTPS together with site "${clash.name}"; one HAProxy listener cannot be both. The site was left out: give it its own ports.`);
      return false;
    }
    return true;
  });
  const usedPools = spec.pools.map((p) => p.name).filter((n) => sites.some((s) => !s.redirectTo && (s.defaultPool === n || s.routes.some((r) => r.pool === n))));
  spec.pools.filter((p) => !usedPools.includes(p.name)).forEach((p) => notes.push(`Pool "${p.name}" is not used by any site, so no backend was written for it.`));
  /** where a site sends what its routes do not match: its default pool, or the pool of a "/" prefix route */
  const fallbackPool = (s) => s.defaultPool || (s.routes.find((r) => r.match === 'prefix' && r.path === '/') || {}).pool || null;
  const sitesUsing = (pool) => sites.filter((s) => !s.redirectTo && (s.defaultPool === pool || s.routes.some((r) => r.pool === pool)));
  const tlsSites = sites.filter((s) => s.tls.mode !== 'none');
  const acmeSites = sites.filter((s) => s.tls.mode === 'acme');
  const nativeAcme = ge('3.2') && Boolean(kb.sections.acme);
  const statelessAcme = !nativeAcme && ge('2.2');
  const crtStore = ge('3.0') && Boolean(kb.sections['crt-store']);
  const hostnames = spec.pools.some((p) => usedPools.includes(p.name) && p.servers.some((x) => !isIp(hostOf(x.address))));
  const useResolvers = hostnames && ge('1.9');
  const backendName = (pool) => pool; // backends carry the pool names (the status page listen gives way, see below)

  // certificate path per TLS site
  const certOf = new Map();
  for (const s of tlsSites) {
    if (s.tls.mode === 'files') {
      if (crtStore) certOf.set(s.name, s.tls.cert);
      else {
        const combined = `${CERT_DIR}/${s.name}.pem`;
        certOf.set(s.name, combined);
        notes.push(`Site "${s.name}": HAProxy ${t} reads the certificate and its key from one PEM file. Create it with: cat ${s.tls.cert} ${s.tls.key} > ${combined} (chmod 600), and rebuild it after every renewal.${ge('3.0') ? '' : ' (HAProxy 3.0+ can load a separate key with a crt-store section.)'}`);
      }
    } else certOf.set(s.name, `${CERT_DIR}/${s.name}.pem`);
  }

  // ------------------------------------------------------------------------------------------ output helpers
  const out = [];
  const blank = () => { if (out.length && out[out.length - 1] !== '') out.push(''); };
  const section = (header, comment) => { blank(); if (comment) [].concat(comment).forEach((c) => out.push(`# ${c}`)); out.push(header); };
  const line = (text) => out.push(`${IND}${text}`);
  const comment = (text) => [].concat(text).forEach((c) => out.push(`${IND}# ${c}`));
  const gap = () => { if (out[out.length - 1] !== '' && !/^\S/.test(out[out.length - 1])) out.push(''); };

  // ------------------------------------------------------------------------------------------ header
  out.push('# HAProxy configuration generated by GateLight Config Builder (spec format 1)');
  out.push(`# Target: HAProxy ${t}${spec.version ? ` (requested ${spec.version})` : ' (newest documented branch)'}. Check it with: haproxy -c -f /etc/haproxy/haproxy.cfg`);
  out.push(`# Sites: ${sites.map((s) => `${s.name} (${s.hosts.length ? s.hosts.join(', ') : 'any host'})`).join('; ') || 'none'}`);
  if (usedPools.length) out.push(`# Pools: ${usedPools.join(', ')}`);

  // ------------------------------------------------------------------------------------------ global
  section('global');
  comment('Logs go to the local syslog socket. In a container use: log stdout format raw local0');
  line('log /dev/log local0');
  line(`maxconn ${o.maxConnections}`);
  line('user haproxy');
  line('group haproxy');
  if (o.workers !== 'auto') {
    if (ge('1.8')) line(`nbthread ${o.workers}`);
    else notes.push(`HAProxy ${t} has no threads (nbthread arrived in 1.8); "workers: ${o.workers}" was not applied.`);
  } else if (!ge('2.0')) notes.push(`HAProxy ${t} runs one thread unless nbthread is set; from 2.0 it starts one thread per CPU by default.`);
  comment('Runtime API (also read by GateLight). Keep it a local UNIX socket.');
  line('stats socket /run/haproxy/admin.sock mode 660 level admin');
  line('stats timeout 30s');
  if (tlsSites.length) {
    gap(); comment('TLS for every bind line: modern ciphers, no TLS 1.0/1.1, no session tickets (forward secrecy)');
    const floor = tlsSites.every((s) => s.tls.minVersion === '1.3') && ge('1.8') ? 'TLSv1.3' : 'TLSv1.2';
    line(`ssl-default-bind-ciphers ${CIPHERS}`);
    if (ge('1.8') && kb.global['ssl-default-bind-ciphersuites']) line(`ssl-default-bind-ciphersuites ${SUITES}`);
    line(`ssl-default-bind-options ${ge('1.8') ? `ssl-min-ver ${floor}` : 'no-sslv3 no-tlsv10 no-tlsv11'} no-tls-tickets`);
    if (!ge('1.8') && tlsSites.some((s) => s.tls.minVersion === '1.3')) notes.push(`HAProxy ${t} cannot require TLS 1.3 (ssl-min-ver arrived in 1.8); TLS 1.2 is the floor.`);
  }
  if (acmeSites.length && nativeAcme) {
    gap(); comment(['ACME (Let\'s Encrypt) is native from HAProxy 3.2, where it is marked experimental', `(section "acme" of ${docs()})`]);
    line('expose-experimental-directives');
  } else if (acmeSites.length && statelessAcme) {
    gap(); comment(['acme.sh "stateless" mode: HAProxy answers HTTP-01 challenges itself (see the frontend).', 'Replace the value with the output of: acme.sh --register-account (ACCOUNT_THUMBPRINT=...)']);
    line("setenv ACCOUNT_THUMBPRINT 'REPLACE_WITH_ACME_SH_ACCOUNT_THUMBPRINT'");
  }

  if (useResolvers) {
    section('resolvers dns', 'DNS for servers given by host name: re-resolved at runtime instead of only at startup');
    line('parse-resolv-conf');
    line('hold valid 10s');
  } else if (hostnames) notes.push(`Servers given by host name are resolved once at startup (HAProxy ${t} cannot read /etc/resolv.conf in a resolvers section; parse-resolv-conf arrived in 1.9).`);

  // ------------------------------------------------------------------------------------------ ACME / certificates
  if (acmeSites.length) {
    if (nativeAcme) {
      const email = (acmeSites.find((s) => s.tls.email) || { tls: {} }).tls.email;
      section('acme le', ['Let\'s Encrypt account. HAProxy renews the certificates listed in crt-store below (acme.scheduler).']);
      line('directory https://acme-v02.api.letsencrypt.org/directory');
      line('account-key /etc/haproxy/acme/letsencrypt.account.key');
      if (email) line(`contact ${email}`);
      line('challenge HTTP-01');
      line('keytype ECDSA');
      line('map virt@acme');
      notes.push(`ACME: HAProxy ${t} obtains and renews the certificates itself (section "acme" of ${docs()}). It is experimental in 3.2 and needs an existing certificate file at startup: create a temporary self-signed one at each path under ${CERT_DIR}/ (openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=<host> -keyout k -out c && cat c k > <file>), then trigger the first order with: echo "acme renew <file>" | socat stdio /run/haproxy/admin.sock`);
      if (!acmeSites.some((s) => s.tls.email)) notes.push('ACME: no contact e-mail was given; Let\'s Encrypt will not be able to warn you about expiring certificates.');
    } else {
      unsupported.push(`Automatic certificates (ACME) are native only from HAProxy 3.2 (section "acme" of https://docs.haproxy.org/3.2/configuration.html); HAProxy ${t} needs an external client. ${statelessAcme ? `The frontend answers HTTP-01 challenges for acme.sh in stateless mode (set ACCOUNT_THUMBPRINT in global), then issue with: acme.sh --issue --stateless -d <host> and install with the haproxy deploy hook (DEPLOY_HAPROXY_HOT_UPDATE=yes) into ${CERT_DIR}/<site>.pem.` : `Challenges are forwarded to certbot on 127.0.0.1:8888: certbot certonly --standalone --http-01-port 8888 -d <host>, then cat fullchain.pem privkey.pem > ${CERT_DIR}/<site>.pem.`} HAProxy needs a certificate file to start: use a temporary self-signed one until the first issue.`);
    }
  }
  if (crtStore && tlsSites.length) {
    section('crt-store', 'Certificates (crt-store, HAProxy 3.0+: the key can live in its own file)');
    for (const s of tlsSites) {
      if (s.tls.mode === 'files') line(`load crt ${q(s.tls.cert)} key ${q(s.tls.key)}`);
      else if (nativeAcme) line(`load crt ${q(certOf.get(s.name))} acme le domains ${q(s.hosts.join(','))}`);
      else line(`load crt ${q(certOf.get(s.name))}`);
    }
  }

  // ------------------------------------------------------------------------------------------ defaults
  const dConnect = 5; const dServer = 60; // the spec defaults; backends override them
  section('defaults');
  line('mode http');
  line('log global');
  if (o.logFormat === 'json') {
    comment('Access log as one JSON object per request');
    line(`log-format '{"time":"%tr","client":"%ci","frontend":"%ft","backend":"%b","server":"%s","method":"%HM","uri":"%HU","status":%ST,"bytes":%B,"duration_ms":%Ta,"termination":"%ts"}'`);
  } else line('option httplog');
  line('option dontlognull');
  if (!o.accessLog) { comment('Access logs are off: only failed or abnormal requests are logged'); line('option dontlog-normal'); }
  line('option forwardfor');
  line('option redispatch');
  line('retries 3');
  line(`maxconn ${o.maxConnections}`);
  line(`timeout connect ${dConnect}s`);
  line(`timeout client ${o.clientTimeout}s`);
  line(`timeout server ${dServer}s`);
  line('timeout http-request 10s');
  line('timeout http-keep-alive 10s');
  line('timeout queue 30s');

  // ------------------------------------------------------------------------------------------ userlists
  for (const s of sites.filter((x) => x.basicAuth && !x.redirectTo)) {
    section(`userlist ul_${ident(s.name)}`, `Basic authentication for site "${s.name}" (bcrypt hashes, checked with the system crypt())`);
    s.basicAuth.users.forEach((u) => line(`user ${u.user} password ${u.hash}`));
  }
  if (sites.some((x) => x.basicAuth && !x.redirectTo)) notes.push('Basic auth: HAProxy checks the bcrypt hashes with the system crypt(). That works where crypt() knows $2b$/$2y$ (libxcrypt on Debian 11+, Ubuntu 22.04+, RHEL/Fedora; musl on Alpine) but not with an old glibc-only crypt. bcrypt is also slow by design and HAProxy hashes on every request: keep the cost low (e.g. htpasswd -nbB -C 8) or use SHA-512 hashes (mkpasswd -m sha-512).');
  if (sites.some((x) => x.basicAuth && x.redirectTo)) notes.push('Basic auth is ignored on redirect-only sites.');

  // ------------------------------------------------------------------------------------------ frontends
  const groups = groupSites(sites);
  const routeIds = new Map(); // route -> { site, id, acl }
  const backendRules = new Map(); // pool -> [lines]
  const addBackendRule = (pool, text) => { if (!backendRules.has(pool)) backendRules.set(pool, []); if (!backendRules.get(pool).includes(text)) backendRules.get(pool).push(text); };
  const compressPools = new Set(); const tunnelPools = new Set();
  const certbotNeeded = acmeSites.length && !nativeAcme && !statelessAcme;
  let multiSeq = 0;

  groups.forEach((group) => {
    const multi = group.length > 1;
    const feName = multi ? `fe_web${++multiSeq > 1 ? multiSeq : ''}` : `fe_${ident(group[0].name)}`;
    const plainPorts = [...new Set(group.map((s) => s.http.port))].sort((a, b) => a - b);
    const tlsPorts = [...new Set(group.filter((s) => s.https).map((s) => s.https.port))].sort((a, b) => a - b);
    const allPorts = [...plainPorts, ...tlsPorts];
    const portsOf = (s) => [s.http.port, ...(s.https ? [s.https.port] : [])];
    const needPortAcl = (s) => allPorts.some((p) => !portsOf(s).includes(p));
    const hosted = group.filter((s) => s.hosts.length);
    const catchAll = group.filter((s) => !s.hosts.length);
    const ordered = [...hosted, ...catchAll];
    if (catchAll.length > 1) {
      const same = catchAll.filter((s, i) => catchAll.some((x, j) => j < i && portsOf(x).some((p) => portsOf(s).includes(p))));
      same.forEach((s) => unsupported.push(`Site "${s.name}" is a catch-all (no host names) on a port where an earlier catch-all site already answers every unknown host; it only receives requests for ports the other one does not use.`));
    }
    const mixed = (pred) => { const yes = group.filter((s) => !s.redirectTo && pred(s)); return { yes, all: yes.length === group.filter((s) => !s.redirectTo).length && yes.length > 0, none: !yes.length }; };
    /** condition matching one site (or several) in request rules */
    const siteCond = (list) => {
      if (!multi) {
        const s = list[0];
        return [s.hosts.length ? `host_${ident(s.name)}` : '', needPortAcl(s) ? `port_${ident(s.name)}` : ''].filter(Boolean).join(' ');
      }
      return `{ var(txn.site) -m str ${list.map((s) => s.name).join(' ')} }`;
    };
    /** condition for response rules: only variables survive into the response */
    const respCond = (list, all) => (all || !multi ? '' : `{ var(txn.site) -m str ${list.map((s) => s.name).join(' ')} }`);
    const join = (...parts) => parts.filter(Boolean).join(' ');

    const desc = group.map((s) => `${s.name}: ${s.hosts.length ? s.hosts.join(' ') : 'any host'}`).join('; ');
    section(`frontend ${feName}`, `${multi ? 'Sites' : 'Site'} ${desc}`);
    for (const p of plainPorts) line(`bind :${p}`);
    for (const p of tlsPorts) {
      const on = group.filter((s) => s.https && s.https.port === p);
      const crts = [...new Set(on.map((s) => certOf.get(s.name)))].map((c) => `crt ${/\s/.test(c) ? q(c) : c}`).join(' ');
      const strict = on.every((s) => s.tls.minVersion === '1.3') && tlsSites.some((s) => s.tls.minVersion !== '1.3') && ge('1.8') ? ' ssl-min-ver TLSv1.3' : '';
      if (!strict && on.some((s) => s.tls.minVersion === '1.3') && ge('1.8') && !tlsSites.every((s) => s.tls.minVersion === '1.3')) notes.push(`Port ${p} serves sites that want TLS 1.3 only and sites that accept TLS 1.2; HAProxy sets the floor per bind line, so TLS 1.2 stays allowed there (use separate ports, or a crt-list with per-certificate ssl-min-ver).`);
      line(`bind :${p} ssl ${crts}${ge('1.8') ? ' alpn h2,http/1.1' : ''}${strict}`);
    }
    if (tlsPorts.length && !ge('1.8')) notes.push(`HAProxy ${t} has no HTTP/2 frontend support (arrived in 1.8); TLS listeners use HTTP/1.1.`);

    // --- ACLs
    gap(); comment('Which site and route a request belongs to');
    for (const s of hosted) {
      const exact = s.hosts.filter((h) => !h.startsWith('*.'));
      const wild = s.hosts.filter((h) => h.startsWith('*.')).map((h) => h.slice(1));
      const withPorts = (names) => names.flatMap((h) => [h, ...portsOf(s).filter((p) => p !== 80 && p !== 443).map((p) => `${h}:${p}`)]);
      if (exact.length) line(`acl host_${ident(s.name)} hdr(host) -i ${withPorts(exact).join(' ')}`);
      if (wild.length) line(`acl host_${ident(s.name)} hdr_end(host) -i ${withPorts(wild).join(' ')}`);
    }
    for (const s of group.filter(needPortAcl)) line(`acl port_${ident(s.name)} dst_port ${portsOf(s).join(' ')}`);
    const aclNames = new Set();
    for (const s of ordered.filter((x) => !x.redirectTo)) {
      s.routes.forEach((r) => {
        let base = `${ident(s.name)}_${r.path === '/' ? 'root' : ident(r.path.replace(/^\/|\/$/g, '').replace(/\//g, '_')) || 'root'}${r.match === 'exact' ? '_exact' : ''}`;
        let n = base; let k = 2; while (aclNames.has(n)) n = `${base}${k++}`; aclNames.add(n); base = n;
        routeIds.set(r, { site: s, id: base, acl: base });
        line(`acl ${base} ${r.match === 'exact' ? 'path' : 'path_beg'} ${r.path}`);
      });
    }
    const groupAcme = group.filter((s) => s.tls.mode === 'acme');
    if (groupAcme.length && !nativeAcme && !statelessAcme) line(`acl acme_challenge path_beg ${ACME_PATH}`);

    // --- request rules
    const rules = [];
    const rule = (text, c) => rules.push({ text, comment: c });
    if (groupAcme.length) {
      if (nativeAcme) rule(`http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].%[path,field(-1,/),map(virt@acme)]" if { path_beg ${ACME_PATH} }`, 'ACME HTTP-01 challenges, answered by HAProxy (acme section)');
      else if (statelessAcme) rule(`http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].\${ACCOUNT_THUMBPRINT}" if { path_beg ${ACME_PATH} }`, 'ACME HTTP-01 challenges, answered statelessly for acme.sh');
      else rule('http-request allow if acme_challenge', 'ACME HTTP-01 challenges skip the rules below and go to certbot');
    }
    if (multi) ordered.forEach((s, i) => rule(`http-request set-var(txn.site) str(${s.name}) if ${join(s.hosts.length ? `host_${ident(s.name)}` : '', needPortAcl(s) ? `port_${ident(s.name)}` : '', '!{ var(txn.site) -m found }')}`, i === 0 ? 'Remember the site: response rules cannot see the request headers any more' : null));
    if (!catchAll.length || catchAll.every(needPortAcl)) {
      const s404 = ge('2.2') ? 404 : 403;
      const known = multi ? '{ var(txn.site) -m found }' : siteCond(group);
      rule(`http-request deny deny_status ${s404} unless ${known}`, 'Requests for host names that no site serves are refused');
    }
    const rl = mixed((s) => s.rateLimit);
    if (!rl.none) {
      rule(rl.all && !multi ? 'http-request track-sc0 src' : `http-request track-sc0 src if ${siteCond(rl.yes)}`, 'Per-client rate limit: requests per 10 s window (rate x 10 + burst)');
      for (const s of rl.yes) rule(`http-request deny deny_status 429 if ${join(siteCond([s]), `{ sc_http_req_rate(0) gt ${s.rateLimit.rps * 10 + s.rateLimit.burst} }`)}`);
      if (rl.yes.length > 1) notes.push(`Rate limits of the sites in frontend ${feName} share one per-IP counter (one stick-table per frontend): a client's requests to all of them add up.`);
    }
    for (const s of ordered.filter((x) => x.redirectTo)) {
      const u = new URL(s.redirectTo);
      const prefix = u.pathname === '/' && !u.search;
      const target = prefix ? `${u.protocol}//${u.host}` : s.redirectTo;
      rule(`http-request redirect ${prefix ? 'prefix' : 'location'} ${target} code 301${siteCond([s]) ? ` if ${siteCond([s])}` : ''}`, `Site "${s.name}" only redirects${prefix ? ' (path and query are kept)' : ''}`);
    }
    ordered.filter((x) => !x.redirectTo && x.tls.redirectHttp).forEach((s, i) => {
      const p = s.https.port;
      const to = p === 443 ? 'scheme https' : `location https://%[req.hdr(host),field(1,:)]:${p}%[capture.req.uri]`;
      rule(`http-request redirect ${to} code 301 if ${join('!{ ssl_fc }', siteCond([s]))}`, i === 0 ? 'Plain HTTP goes to HTTPS' : null);
    });
    for (const s of ordered.filter((x) => !x.redirectTo && x.maxBodyMb)) {
      rule(`http-request deny deny_status ${ge('2.2') ? 413 : 400} if ${join(siteCond([s]), `{ req.hdr_val(content-length) gt ${s.maxBodyMb * 1048576} }`)}`, rules.some((r) => /content-length/.test(r.text)) ? null : 'Request body size limit (checks Content-Length)');
    }
    if (group.some((s) => !s.redirectTo && s.maxBodyMb)) notes.push(`maxBodyMb on HAProxy checks the Content-Length header${ge('2.2') ? '' : ' and answers 400 (413 needs 2.2+)'}; chunked uploads without a length are not limited.`);
    for (const s of ordered.filter((x) => !x.redirectTo && x.basicAuth)) rule(`http-request auth realm ${q(s.basicAuth.realm)} if ${join(siteCond([s]), `!{ http_auth(ul_${ident(s.name)}) }`)}`, `Basic authentication for "${s.name}"`);
    for (const s of ordered.filter((x) => !x.redirectTo && !fallbackPool(x))) {
      const routeAcls = s.routes.map((r) => `!${routeIds.get(r).acl}`);
      rule(`http-request deny deny_status ${ge('2.2') ? 404 : 403} if ${join(siteCond([s]), ...routeAcls)}`, `"${s.name}" has no default pool: everything outside its routes is not found`);
    }
    if (!ge('2.2') && (!catchAll.length || group.some((s) => !s.redirectTo && !fallbackPool(s)))) notes.push(`HAProxy ${t} cannot generate a 404 page (errorfile 404 arrived in 2.2); unknown hosts and paths get 403 instead.`);
    if (tlsPorts.length && plainPorts.length) {
      rule('http-request set-header X-Forwarded-Proto https if { ssl_fc }', 'Tell the servers which scheme the client used');
      rule('http-request set-header X-Forwarded-Proto http unless { ssl_fc }');
    } else rule(`http-request set-header X-Forwarded-Proto ${tlsPorts.length ? 'https' : 'http'}`, 'Tell the servers which scheme the client used');
    // routes that rewrite the path: remember which route matched (the path ACLs must see the original path)
    for (const s of ordered.filter((x) => !x.redirectTo && x.routes.some((r) => r.stripPrefix || r.rewriteTo))) {
      s.routes.forEach((r, i) => {
        const id = routeIds.get(r).id;
        rule(`http-request set-var(txn.route) str(${id}) if ${join(siteCond([s]), id, '!{ var(txn.route) -m found }')}`, i === 0 ? `Remember the matched route of "${s.name}"; its backend rewrites the path` : null);
        if (!(r.stripPrefix || r.rewriteTo)) return;
        const to = r.rewriteTo || '/';
        let rw;
        if (r.match === 'exact') rw = `http-request set-path ${to}`;
        else {
          const base = r.path.replace(/\/$/, ''); const tBase = to.replace(/\/$/, '');
          const strip = tBase === '';
          const [re, rep] = r.path.endsWith('/') ? [`^${reEsc(base)}/(.*)`, `${tBase}/\\1`] : strip ? [`^${reEsc(base)}/?(.*)`, '/\\1'] : [`^${reEsc(base)}(.*)`, `${tBase}\\1`];
          rw = ge('2.0') ? `http-request replace-path ${re} ${rep}` : `http-request set-path %[path,regsub(${re.replace(/\(\.\*\)$/, '')},${rep.replace(/\\1$/, '')})]`;
        }
        addBackendRule(r.pool, `${rw} if { var(txn.route) -m str ${id} }`);
      });
      if (s.routes.some((r) => r.stripPrefix && r.rewriteTo)) notes.push(`Site "${s.name}": a route has both stripPrefix and rewriteTo; rewriteTo wins (the matched prefix is replaced by it).`);
    }
    let lastComment = null;
    rules.forEach((r) => { if (r.comment && r.comment !== lastComment) { gap(); comment(r.comment); lastComment = r.comment; } line(r.text); });

    // --- response rules
    const resp = [];
    const hsts = mixed((s) => s.tls.hsts);
    if (!hsts.none) {
      const guard = plainPorts.length ? '{ ssl_fc }' : '';
      const c = join(guard, respCond(hsts.yes, hsts.all));
      resp.push(`http-response set-header Strict-Transport-Security "max-age=31536000"${c ? ` if ${c}` : ''}`);
    }
    const sh = mixed((s) => s.securityHeaders);
    if (!sh.none) {
      const c = respCond(sh.yes, sh.all); const tail = c ? ` if ${c}` : '';
      resp.push(`http-response set-header X-Content-Type-Options nosniff${tail}`);
      resp.push(`http-response set-header X-Frame-Options SAMEORIGIN${tail}`);
      resp.push(`http-response set-header Referrer-Policy strict-origin-when-cross-origin${tail}`);
    }
    if (resp.length) { gap(); comment('Security headers on every response'); resp.forEach(line); }
    gap(); comment('Do not advertise the server software');
    line('http-response del-header Server');
    line('http-response del-header X-Powered-By');
    const comp = mixed((s) => s.compression);
    if (comp.all) { gap(); comment('Compress text responses'); line('compression algo gzip'); line(`compression type ${COMPRESS_TYPES}`); }
    else if (!comp.none) for (const s of comp.yes) [...s.routes.map((r) => r.pool), s.defaultPool].filter(Boolean).forEach((p) => compressPools.add(p));
    if (!rl.none) { gap(); comment('Request counters for the rate limit'); line('stick-table type ipv6 size 100k expire 30s store http_req_rate(10s)'); }
    for (const s of group.filter((x) => x.websocket && !x.redirectTo)) [...s.routes.map((r) => r.pool), s.defaultPool].filter(Boolean).forEach((p) => tunnelPools.add(p));

    // --- routing
    const uses = [];
    if (groupAcme.length && certbotNeeded) uses.push('use_backend acme_challenge if acme_challenge');
    const withDefault = ordered.filter((s) => !s.redirectTo && fallbackPool(s));
    const fallback = withDefault[withDefault.length - 1] || null; // reached only by that site: the others are routed or denied above
    for (const s of ordered.filter((x) => !x.redirectTo)) {
      const sc = [s.hosts.length ? `host_${ident(s.name)}` : '', needPortAcl(s) ? `port_${ident(s.name)}` : ''].filter(Boolean).join(' ');
      for (const r of s.routes) uses.push(`use_backend ${backendName(r.pool)} if ${join(sc, routeIds.get(r).acl)}`);
      if (s.defaultPool && s !== fallback) uses.push(`use_backend ${backendName(s.defaultPool)}${sc ? ` if ${sc}` : ''}`);
    }
    if (uses.length || fallback) {
      gap(); comment('Routing: first match wins (exact paths first, then the longest prefix)');
      uses.forEach(line);
      if (fallback) line(`default_backend ${backendName(fallbackPool(fallback))}`);
    }
  });

  // ------------------------------------------------------------------------------------------ status page
  if (o.statusPage.enabled) {
    const allow = o.statusPage.allow.length ? o.statusPage.allow : ['127.0.0.1'];
    const remote = allow.filter((a) => !isLoopback(a));
    const clash = sites.some((s) => s.http.port === o.statusPage.port || (s.https && s.https.port === o.statusPage.port));
    if (clash) unsupported.push(`The status page port ${o.statusPage.port} is also used by a site; the status page was left out. Choose another port.`);
    else {
      section(`listen ${sites.some((s) => s.name === 'stats') || usedPools.includes('stats') ? 'gl_stats' : 'stats'}`, `Status page: http://127.0.0.1:${o.statusPage.port}/stats${ge('2.4') ? ` and Prometheus metrics at /metrics` : ''}`);
      if (remote.length) comment(['Bound to loopback because the page has no password. To reach it from', `${remote.join(', ')}, change the address to this host's management IP (the src rule below still applies).`]);
      line(`bind 127.0.0.1:${o.statusPage.port}`);
      line(`http-request deny unless { src ${allow.join(' ')} }`);
      if (ge('2.4')) line('http-request use-service prometheus-exporter if { path /metrics }');
      else notes.push(`The Prometheus exporter service is left out for HAProxy ${t}: it needs a build with the promex add-on, which ships with the official packages from 2.4.`);
      line('stats enable');
      line('stats uri /stats');
      line('stats refresh 10s');
      if (ge('2.4')) notes.push('Status page: /metrics uses the built-in Prometheus exporter; if "haproxy -vv" does not list "prometheus-exporter", remove that line.');
      if (remote.length) notes.push(`Status page: HAProxy has no password for it, so it is bound to 127.0.0.1; to serve ${remote.join(', ')} change the bind address to the management interface (the src allow-list stays in force).`);
    }
  }

  // ------------------------------------------------------------------------------------------ backends
  if (certbotNeeded) {
    section('backend acme_challenge', 'certbot --standalone --http-01-port 8888 answers ACME challenges while it runs');
    line('server certbot 127.0.0.1:8888 check inter 2s fall 1 rise 1');
  }
  for (const name of usedPools) {
    const p = poolBy.get(name);
    const users = sitesUsing(name);
    const be = backendName(name);
    section(`backend ${be}`, `Pool "${name}": ${p.servers.length} server${p.servers.length > 1 ? 's' : ''}, used by ${users.map((s) => s.name).join(', ')}`);
    // balancing
    let balance = { roundrobin: 'roundrobin', leastconn: 'leastconn', iphash: 'source', random: 'random' }[p.balance];
    if (p.balance === 'random' && !ge('1.9')) { balance = 'roundrobin'; notes.push(`Pool "${name}": "balance random" needs HAProxy 1.9+; roundrobin is used.`); }
    line(`balance ${balance}`);
    if (p.balance === 'iphash') line('hash-type consistent');
    if (p.timeouts.connect !== dConnect) line(`timeout connect ${p.timeouts.connect}s`);
    if (p.timeouts.server !== dServer) line(`timeout server ${p.timeouts.server}s`);
    if (tunnelPools.has(name)) { comment('WebSocket connections stay open up to an hour without traffic'); line('timeout tunnel 1h'); }
    if (compressPools.has(name)) {
      line('compression algo gzip'); line(`compression type ${COMPRESS_TYPES}`);
      if (users.some((s) => !s.compression)) notes.push(`Pool "${name}" compresses responses for every site that uses it (${users.map((s) => s.name).join(', ')}), because compression is set per backend when sites in one frontend disagree.`);
    }
    const rw = backendRules.get(name) || [];
    if (rw.length) { comment('Path rewrites of the routes that lead here'); rw.forEach(line); }
    // health checks
    const hc = p.healthCheck;
    const hostFor = (users.flatMap((s) => s.hosts).find((h) => !h.startsWith('*.'))) || null;
    if (hc) {
      comment(`Active health check: GET ${hc.path} every ${hc.interval}s`);
      if (ge('2.2')) {
        line('option httpchk');
        line(`http-check send meth GET uri ${hc.path}${hostFor ? ` ver HTTP/1.1 hdr Host ${hostFor}` : ''}`);
        line('http-check expect status 200-399');
      } else {
        line(`option httpchk GET ${hc.path}`); // the structured http-check send form arrived in 2.2
        line('http-check expect rstatus ^[23]');
      }
      line(`timeout check ${hc.timeout}s`);
    }
    // sticky
    const httpsOnly = users.every((s) => s.tls.mode !== 'none' && s.tls.redirectHttp);
    if (p.sticky) { comment('Sticky sessions: a cookie remembers the server'); line(`cookie GL_${ident(name).toUpperCase()} insert indirect nocache httponly${httpsOnly ? ' secure' : ''}`); }
    // servers
    const dflt = ['check', `inter ${hc ? hc.interval : 2}s`, `fall ${hc ? hc.fall : 3}`, `rise ${hc ? hc.rise : 2}`];
    if (!hc) comment('No HTTP health check configured: servers get a TCP connect check');
    if (p.scheme === 'https') {
      if (p.verifyTls) dflt.push('ssl', 'verify', 'required', 'ca-file', CA_BUNDLE);
      else dflt.push('ssl', 'verify', 'none');
    }
    line(`default-server ${dflt.join(' ')}`);
    p.servers.forEach((sv, i) => {
      const sname = `${ident(name)}${i + 1}`;
      const host = hostOf(sv.address);
      const opts = [];
      if (sv.weight != null) opts.push(`weight ${sv.weight}`);
      if (sv.backup) opts.push('backup');
      if (p.sticky) opts.push(`cookie ${sname}`);
      if (p.scheme === 'https' && !isIp(host)) opts.push(`sni str(${host})`, ...(ge('1.8') ? ['check-sni', host] : []), ...(p.verifyTls ? [`verifyhost ${host}`] : []));
      if (useResolvers && !isIp(host)) opts.push('resolvers dns init-addr last,libc,none');
      line(`server ${sname} ${sv.address}${opts.length ? ` ${opts.join(' ')}` : ''}`);
    });
    if (p.scheme === 'https' && p.verifyTls) notes.push(`Pool "${name}": server certificates are verified against ${CA_BUNDLE} (Debian/Ubuntu/Alpine; on RHEL use /etc/pki/tls/certs/ca-bundle.crt, or point ca-file at your internal CA).${p.servers.some((x) => isIp(hostOf(x.address))) ? ' Servers given by IP address must present a certificate with that IP in its subject alternative names.' : ''}`);
    if (p.scheme === 'https' && !p.verifyTls) notes.push(`Pool "${name}": TLS to the servers is encrypted but not authenticated (verify none), as requested.`);
    if (!hc) notes.push(`Pool "${name}" has no HTTP health check, so HAProxy only checks that the TCP port accepts connections.`);
  }

  return { files: [{ name: 'haproxy.cfg', content: `${out.join('\n').replace(/\n{3,}/g, '\n\n')}\n` }], notes: [...new Set(notes)], unsupported: [...new Set(unsupported)] };
}

module.exports = { build, targetOf };

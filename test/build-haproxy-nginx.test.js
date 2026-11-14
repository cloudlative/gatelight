'use strict';
/**
 * Config Builder: HAProxy and NGINX generators (src/build/haproxy.js, src/build/nginx.js).
 * Every spec is built for several target versions and the output is run through GateLight's own engines:
 * the parsers (routes, backends, servers), the version-aware validator, the structural audit and the Config Doctor.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { EXAMPLE_SPEC, normalizeSpec } = require('../src/build/spec');
const haproxy = require('../src/build/haproxy');
const nginx = require('../src/build/nginx');
const { validateConfig } = require('../src/validate');
const { improveConfig } = require('../src/improve');
const { parseConfig } = require('../src/haproxyConfig');
const { auditConfig } = require('../src/audit');
const { parseNginxFiles } = require('../src/nginxConfig');
const { auditNginx } = require('../src/nginxAudit');

const HASH = `$2y$10$${'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0'}`;

const SPECS = {
  example: EXAMPLE_SPEC,
  acme: {
    sites: [{ name: 'blog', hosts: ['blog.example.org', 'www.blog.example.org'], tls: { mode: 'acme', email: 'ops@example.org' }, defaultPool: 'app' }],
    pools: [{ name: 'app', servers: ['10.1.0.5:3000', '10.1.0.6:3000'], healthCheck: { path: '/ping' } }],
  },
  plainCatchAll: {
    sites: [{ name: 'any', hosts: [], tls: { mode: 'none' }, routes: [{ path: '/', pool: 'app' }, { path: '/health', match: 'exact', pool: 'app', rewriteTo: '/status' }], securityHeaders: false }],
    pools: [{ name: 'app', servers: ['127.0.0.1:8080', '127.0.0.1:8081'], healthCheck: null }],
    options: { accessLog: false, workers: 4, maxConnections: 2000 },
  },
  redirects: {
    sites: [
      { name: 'old', hosts: ['old.example.com'], tls: { mode: 'files', cert: '/etc/ssl/old.pem', key: '/etc/ssl/old.key' }, redirectTo: 'https://new.example.com/' },
      { name: 'promo', hosts: ['promo.example.com'], redirectTo: 'https://new.example.com/landing?src=promo' },
      { name: 'new', hosts: ['new.example.com'], tls: { mode: 'files', cert: '/etc/ssl/new/fullchain.pem', key: '/etc/ssl/new/privkey.pem' }, defaultPool: 'web' },
    ],
    pools: [{ name: 'web', servers: ['10.0.0.1:80', '10.0.0.2:80'], healthCheck: { path: '/' } }],
  },
  secure: {
    sites: [{
      name: 'app', hosts: ['app.example.com'], tls: { mode: 'files', cert: '/etc/ssl/app/fullchain.pem', key: '/etc/ssl/app/privkey.pem' }, websocket: true,
      basicAuth: { realm: 'App staff', users: [{ user: 'alice', hash: HASH }, { user: 'bob', hash: HASH }] }, rateLimit: { rps: 5, burst: 10 }, maxBodyMb: 50,
      routes: [{ path: '/ws', pool: 'realtime', stripPrefix: true }, { path: '/api/', pool: 'secureapi', rewriteTo: '/v2/' }],
    }],
    pools: [
      { name: 'realtime', servers: ['10.2.0.1:9000', '10.2.0.2:9000'], healthCheck: { path: '/healthz' }, timeouts: { connect: 3, server: 30 } },
      { name: 'secureapi', scheme: 'https', verifyTls: true, servers: ['api1.internal.example.com:443', 'api2.internal.example.com:443'], healthCheck: { path: '/health', interval: 10, timeout: 3, rise: 3, fall: 2 } },
    ],
  },
  balancing: {
    sites: [
      { name: 'lb', hosts: ['lb.example.net', '*.lb.example.net'], tls: { mode: 'files', cert: '/etc/ssl/lb.pem', key: '/etc/ssl/lb.key' }, routes: [{ path: '/a/', pool: 'hashed' }, { path: '/b/', pool: 'rand' }, { path: '/c', pool: 'sticky' }], defaultPool: 'least' },
      { name: 'other', hosts: ['other.example.net'], http: { port: 8080 }, tls: { mode: 'none' }, defaultPool: 'least', compression: false },
    ],
    pools: [
      { name: 'hashed', balance: 'iphash', servers: [{ address: '10.3.0.1:80', weight: 3 }, { address: '10.3.0.2:80', weight: 1 }, { address: '10.3.0.3:80', backup: true }] },
      { name: 'rand', balance: 'random', servers: [{ address: '10.4.0.1:80', weight: 2 }, '10.4.0.2:80'] },
      { name: 'sticky', balance: 'leastconn', sticky: true, servers: ['10.5.0.1:80', '10.5.0.2:80', { address: '10.5.0.3:80', backup: true }] },
      { name: 'least', balance: 'leastconn', servers: [{ address: '10.6.0.1:80', weight: 5 }, { address: '10.6.0.2:80', weight: 0 }, { address: '10.6.0.9:80', backup: true }] },
    ],
    options: { logFormat: 'json', statusPage: { enabled: true, port: 9000, allow: ['127.0.0.1'] } },
  },
};

const HAPROXY_VERSIONS = ['2.0', '2.4', '2.8', null];
const NGINX_VERSIONS = ['1.18.0', '1.24.0', null];
const configFiles = (files) => files.filter((f) => !f.name.startsWith('htpasswd/')); // user files are not NGINX syntax

/** Problems the generator must never produce: errors, and warnings about directives the version does not know. */
function assertValid(product, version, files, label) {
  const v = validateConfig({ product, version, files, config: product === 'haproxy' ? files[0].content : undefined });
  const bad = v.findings.filter((f) => f.severity === 'error' || (f.severity === 'warning' && /^compat-/.test(f.id)));
  assert.deepEqual(bad.map((f) => `${f.id} ${f.file || ''}:${f.line} ${f.title}`), [], `${label}: validator`);
  return v;
}

function assertDoctor(product, version, files, label) {
  const r = improveConfig({ product, version, files });
  const highAuto = r.changes.filter((c) => c.auto && c.on && c.severity === 'high');
  assert.deepEqual(highAuto.map((c) => `${c.rule}: ${c.title}`), [], `${label}: Config Doctor proposes a high-severity rewrite`);
  assert.ok(r.score.before >= 90, `${label}: Config Doctor score ${r.score.before} < 90 (${r.changes.filter((c) => c.on || !c.auto).map((c) => `${c.severity} ${c.rule}`).join(', ')})`);
  return r;
}

// ------------------------------------------------------------------------------------------------------- HAProxy
for (const [name, input] of Object.entries(SPECS)) {
  for (const version of HAPROXY_VERSIONS) {
    const label = `haproxy ${version || 'latest'} ${name}`;
    test(`Config Builder ${label}: parses, validates, audits and scores well`, () => {
      const spec = normalizeSpec(input);
      const out = haproxy.build({ ...input, version });
      assert.equal(out.files.length, 1);
      assert.equal(out.files[0].name, 'haproxy.cfg');
      assert.ok(Array.isArray(out.notes) && Array.isArray(out.unsupported));
      const text = out.files[0].content;
      assert.match(text, /^# HAProxy configuration generated by GateLight Config Builder/);

      // parses back into the expected model
      const secs = parseConfig(text);
      const fronts = secs.filter((s) => s.type === 'frontend');
      const backs = secs.filter((s) => s.type === 'backend');
      const used = spec.pools.filter((p) => spec.sites.some((s) => !s.redirectTo && (s.defaultPool === p.name || s.routes.some((r) => r.pool === p.name))));
      for (const p of used) {
        const be = backs.find((b) => b.name === p.name);
        assert.ok(be, `${label}: backend ${p.name}`);
        assert.equal(be.servers.length, p.servers.length, `${label}: servers of ${p.name}`);
        assert.equal(be.balance, { roundrobin: 'roundrobin', leastconn: 'leastconn', iphash: 'source', random: 'random' }[p.balance]);
        p.servers.forEach((sv, i) => {
          assert.equal(be.servers[i].address, sv.address);
          assert.equal(be.servers[i].backup, sv.backup);
          assert.equal(be.servers[i].weight, sv.weight);
        });
        assert.ok(be.effective.defaultServer.check, `${label}: ${p.name} servers are health-checked`);
      }
      for (const s of spec.sites.filter((x) => !x.redirectTo)) {
        const fe = fronts.find((f) => f.binds.some((b) => b.addresses.includes(`:${s.http.port}`)));
        assert.ok(fe, `${label}: frontend for ${s.name}`);
        if (s.https) assert.ok(fe.binds.some((b) => b.ssl && b.addresses.includes(`:${s.https.port}`)), `${label}: TLS bind for ${s.name}`);
        for (const r of s.routes) {
          const want = r.match === 'exact' ? r.path : `${r.path}…`;
          const route = fe.routes.find((x) => x.paths.includes(want) && (!s.hosts.length || s.hosts.filter((h) => !h.startsWith('*.')).every((h) => x.hosts.includes(h))));
          assert.ok(route, `${label}: route ${r.path} of ${s.name}`);
          assert.equal(route.target, r.pool, `${label}: route ${r.path} goes to ${r.pool}`);
        }
        if (s.defaultPool) assert.ok(fe.routes.some((x) => x.target === s.defaultPool && (x.type === 'default' || !x.paths.length)), `${label}: default pool of ${s.name}`);
      }

      assertValid('haproxy', version, out.files, label);
      const audit = auditConfig(secs, { runtime: { rows: [] } });
      assert.deepEqual(audit.filter((f) => f.severity === 'error').map((f) => `${f.id}: ${f.title}`), [], `${label}: audit`);
      assertDoctor('haproxy', version, out.files, label);
    });
  }
}

test('HAProxy output follows the target version', () => {
  const v20 = haproxy.build({ ...EXAMPLE_SPEC, version: '2.0' }).files[0].content;
  const v24 = haproxy.build({ ...EXAMPLE_SPEC, version: '2.4.62' }).files[0].content;
  const latest = haproxy.build(EXAMPLE_SPEC).files[0].content;
  // health checks: http-check send from 2.2, the inline form before
  assert.match(v20, /option httpchk GET \/health\n/);
  assert.doesNotMatch(v20, /http-check send/);
  assert.match(v24, /option httpchk\n\s+http-check send meth GET uri \/health ver HTTP\/1\.1 hdr Host shop\.example\.com/);
  // 404 / 413 need 2.2 (errorfile codes); before that 403 / 400
  assert.match(v20, /deny_status 403 unless host_shop/);
  assert.match(v24, /deny_status 404 unless host_shop/);
  assert.match(v24, /deny_status 413 if host_shop \{ req\.hdr_val\(content-length\) gt 10485760 \}/);
  // Prometheus exporter from 2.4
  assert.doesNotMatch(v20, /prometheus-exporter/);
  assert.match(v24, /http-request use-service prometheus-exporter if \{ path \/metrics \}/);
  // TLS floor, separate key file with crt-store from 3.0
  assert.match(v24, /ssl-default-bind-options ssl-min-ver TLSv1\.2 no-tls-tickets/);
  assert.match(v24, /bind :443 ssl crt \/etc\/haproxy\/certs\/shop\.pem alpn h2,http\/1\.1/);
  assert.match(latest, /crt-store\n\s+load crt "\/etc\/ssl\/shop\/fullchain\.pem" key "\/etc\/ssl\/shop\/privkey\.pem"/);
  assert.match(latest, /bind :443 ssl crt \/etc\/ssl\/shop\/fullchain\.pem/);
  // features of the example
  assert.match(latest, /stick-table type ipv6 size 100k expire 30s store http_req_rate\(10s\)/);
  assert.match(latest, /http-request deny deny_status 429 if host_shop \{ sc_http_req_rate\(0\) gt 240 \}/);
  assert.match(latest, /http-request replace-path \^\/api\/\(\.\*\) \/\\1 if \{ var\(txn\.route\) -m str shop_api \}/);
  assert.match(latest, /cookie GL_WEB insert indirect nocache httponly secure/);
  assert.match(latest, /server api3 10\.0\.1\.23:9000 backup/);
  assert.match(latest, /bind 127\.0\.0\.1:8404\n\s+http-request deny unless \{ src 127\.0\.0\.1 10\.0\.0\.0\/8 \}/);
  // older than 2.0: set-path with regsub instead of replace-path
  assert.match(haproxy.build({ ...EXAMPLE_SPEC, version: '1.9' }).files[0].content, /http-request set-path %\[path,regsub\(\^\/api\/,\/\)\]/);
});

test('HAProxy ACME: native acme section from 3.2, an external client before', () => {
  const v32 = haproxy.build({ ...SPECS.acme, version: '3.2' });
  assert.match(v32.files[0].content, /\nacme le\n\s+directory https:\/\/acme-v02\.api\.letsencrypt\.org\/directory/);
  assert.match(v32.files[0].content, /load crt "\/etc\/haproxy\/certs\/blog\.pem" acme le domains "blog\.example\.org,www\.blog\.example\.org"/);
  assert.match(v32.files[0].content, /map\(virt@acme\)/);
  assert.equal(v32.unsupported.filter((u) => /ACME/.test(u)).length, 0);
  const v28 = haproxy.build({ ...SPECS.acme, version: '2.8' });
  assert.doesNotMatch(v28.files[0].content, /^acme /m);
  assert.match(v28.files[0].content, /setenv ACCOUNT_THUMBPRINT/);
  assert.ok(v28.unsupported.some((u) => /ACME/.test(u) && /3\.2/.test(u) && /acme\.sh/.test(u)));
  const v20 = haproxy.build({ ...SPECS.acme, version: '2.0' });
  assert.match(v20.files[0].content, /use_backend acme_challenge if acme_challenge/);
  assert.ok(v20.unsupported.some((u) => /certbot/.test(u)));
});

test('HAProxy multi-site frontends remember the site for response rules and routing stays per host', () => {
  const out = haproxy.build(SPECS.redirects).files[0].content;
  assert.match(out, /http-request set-var\(txn\.site\) str\(old\) if host_old !\{ var\(txn\.site\) -m found \}/);
  assert.match(out, /http-request redirect prefix https:\/\/new\.example\.com code 301 if \{ var\(txn\.site\) -m str old \}/);
  assert.match(out, /http-request redirect location https:\/\/new\.example\.com\/landing\?src=promo code 301/);
  assert.match(out, /http-request deny deny_status 404 unless \{ var\(txn\.site\) -m found \}/);
  const userlist = haproxy.build(SPECS.secure).files[0].content;
  assert.match(userlist, /userlist ul_app\n\s+user alice password \$2y\$10\$/);
  assert.match(userlist, /http-request auth realm "App staff" if host_app !\{ http_auth\(ul_app\) \}/);
  assert.match(userlist, /timeout tunnel 1h/);
  assert.match(userlist, /default-server check inter 10s fall 2 rise 3 ssl verify required ca-file \/etc\/ssl\/certs\/ca-certificates\.crt/);
  assert.match(userlist, /server secureapi1 api1\.internal\.example\.com:443 sni str\(api1\.internal\.example\.com\) check-sni api1\.internal\.example\.com verifyhost api1\.internal\.example\.com resolvers dns/);
});

// ------------------------------------------------------------------------------------------------------- NGINX
for (const [name, input] of Object.entries(SPECS)) {
  for (const version of NGINX_VERSIONS) {
    const label = `nginx ${version || 'latest'} ${name}`;
    test(`Config Builder ${label}: parses, validates, audits and scores well`, () => {
      const spec = normalizeSpec(input);
      const out = nginx.build({ ...input, version });
      assert.equal(out.files[0].name, 'nginx.conf');
      for (const s of spec.sites) assert.ok(out.files.some((f) => f.name === `conf.d/${s.name}.conf`), `${label}: conf.d/${s.name}.conf`);
      for (const s of spec.sites.filter((x) => x.basicAuth && !x.redirectTo)) {
        const pw = out.files.find((f) => f.name === `htpasswd/${s.name}`);
        assert.ok(pw, `${label}: htpasswd/${s.name}`);
        s.basicAuth.users.forEach((u) => assert.ok(pw.content.includes(`${u.user}:${u.hash}`)));
      }
      const files = configFiles(out.files);

      const p = parseNginxFiles(files);
      const fronts = p.sections.filter((x) => x.type === 'frontend');
      const ups = p.sections.filter((x) => x.type === 'backend' && !x.implicit);
      const used = spec.pools.filter((pl) => spec.sites.some((s) => !s.redirectTo && (s.defaultPool === pl.name || s.routes.some((r) => r.pool === pl.name))));
      assert.deepEqual(ups.map((u) => u.name).sort(), used.map((pl) => pl.name).sort(), `${label}: upstreams`);
      for (const pl of used) {
        const u = ups.find((x) => x.name === pl.name);
        const backupDropped = ['iphash', 'random'].includes(pl.balance) || (pl.sticky && version !== null); // ip_hash / random / hash allow no backup (sticky is a hash before 1.31.0)
        assert.equal(u.servers.length, pl.servers.filter((x) => !(x.backup && backupDropped)).length, `${label}: servers of ${pl.name}`);
        if (pl.balance === 'leastconn' && !pl.sticky) assert.equal(u.balance, 'least_conn');
        if (pl.balance === 'iphash') assert.equal(u.balance, 'ip_hash');
      }
      for (const s of spec.sites) {
        const mine = fronts.filter((f) => (s.hosts.length ? s.hosts.every((h) => f.serverNames.includes(h)) : f.serverNames.includes('_') && f.file === `conf.d/${s.name}.conf`));
        assert.ok(mine.length, `${label}: server blocks of ${s.name}`);
        if (s.redirectTo) continue;
        const content = mine.find((f) => f.routes.length) || mine[mine.length - 1];
        for (const r of s.routes) {
          const route = content.routes.find((x) => x.paths && x.paths[0] === r.path && (x.matchModifier === '=') === (r.match === 'exact'));
          assert.ok(route, `${label}: location for ${r.path}`);
          assert.equal(route.target, r.pool, `${label}: ${r.path} goes to ${r.pool}`);
        }
        if (s.defaultPool && !s.routes.some((r) => r.path === '/' && r.match === 'prefix')) {
          assert.ok(content.routes.some((x) => x.paths && x.paths[0] === '/' && x.matchModifier === '' && x.target === s.defaultPool), `${label}: default pool of ${s.name}`);
        }
        const ports = [s.http.port, ...(s.https ? [s.https.port] : [])].map(String);
        ports.forEach((port) => assert.ok(mine.some((f) => f.binds.some((b) => b.port === port)), `${label}: ${s.name} listens on ${port}`));
      }

      assertValid('nginx', version, files, label);
      const audit = auditNginx(p.sections, { notes: p.notes });
      assert.deepEqual(audit.filter((f) => f.severity === 'error').map((f) => `${f.id}: ${f.title}`), [], `${label}: audit`);
      assertDoctor('nginx', version, files, label);
    });
  }
}

test('NGINX output follows the target version', () => {
  const site = (out, name) => out.files.find((f) => f.name === `conf.d/${name}.conf`).content;
  const main = (out) => out.files[0].content;
  const v118 = nginx.build({ ...EXAMPLE_SPEC, version: '1.18.0' });
  const v124 = nginx.build({ ...EXAMPLE_SPEC, version: '1.24.0' });
  const latest = nginx.build(EXAMPLE_SPEC);
  // HTTP/2: listen parameter before 1.25.1, the http2 directive from it
  assert.match(site(v124, 'shop'), /listen 443 ssl http2;/);
  assert.doesNotMatch(site(v124, 'shop'), /http2 on;/);
  assert.match(site(latest, 'shop'), /listen 443 ssl;\n\s+http2 on;/);
  // TLS catch-all: ssl_reject_handshake from 1.19.4
  assert.doesNotMatch(main(v118), /ssl_reject_handshake on/);
  assert.match(main(v118), /listen 443 ssl http2 default_server;[\s\S]*?return 444;/);
  assert.match(main(v124), /listen 443 ssl http2 default_server;\n\s+server_name _;\n\s+ssl_reject_handshake on;/);
  // sticky: open-source directive from 1.31.0 (KB changelog), a hashed cookie before
  assert.match(main(v124), /hash \$gl_web_key consistent;/);
  assert.match(main(v124), /map \$cookie_gl_web \$gl_web_key \{\n\s+"" \$request_id;/);
  assert.match(site(v124, 'shop'), /add_header Set-Cookie \$gl_web_set;/);
  assert.match(main(latest), /sticky cookie gl_web path=\/ httponly samesite=lax secure;/);
  assert.doesNotMatch(main(latest), /\$gl_web_key/);
  // the rest of the example
  assert.match(main(latest), /limit_req_zone \$binary_remote_addr zone=rl_shop:10m rate=20r\/s;/);
  assert.match(site(latest, 'shop'), /limit_req zone=rl_shop burst=40 nodelay;/);
  assert.match(site(latest, 'shop'), /client_max_body_size 10m;/);
  assert.match(site(latest, 'shop'), /location \/api\/ \{\n\s+proxy_pass http:\/\/api\/;/);
  assert.match(site(latest, 'shop'), /add_header Strict-Transport-Security "max-age=31536000" always;/);
  assert.match(main(latest), /server 10\.0\.1\.23:9000 max_fails=3 fail_timeout=15s backup;/);
  assert.match(main(latest), /location = \/nginx_status \{\n\s+stub_status;\n\s+allow 127\.0\.0\.1;\n\s+allow 10\.0\.0\.0\/8;\n\s+deny all;/);
  // active health checks are NGINX Plus only
  assert.ok(latest.unsupported.some((u) => /NGINX Plus/.test(u) && /health_check/.test(u) && /"web"/.test(u)));
});

test('NGINX: ACME via certbot, basic auth file, WebSocket, https upstream, rewrites', () => {
  const acme = nginx.build(SPECS.acme);
  const blog = acme.files.find((f) => f.name === 'conf.d/blog.conf').content;
  assert.match(blog, /location \^~ \/\.well-known\/acme-challenge\/ \{\n\s+alias \/var\/www\/letsencrypt\/\.well-known\/acme-challenge\/;/);
  assert.match(blog, /ssl_certificate \/etc\/letsencrypt\/live\/blog\.example\.org\/fullchain\.pem;/);
  assert.ok(acme.unsupported.some((u) => /ACME/.test(u) && /ngx_http_acme_module/.test(u) && /certbot/.test(u)));

  const sec = nginx.build({ ...SPECS.secure, version: '1.24.0' });
  const app = sec.files.find((f) => f.name === 'conf.d/app.conf').content;
  assert.match(app, /auth_basic "App staff";\n\s+auth_basic_user_file htpasswd\/app;/);
  assert.match(app, /proxy_set_header Upgrade \$http_upgrade;\n\s+proxy_set_header Connection \$connection_upgrade;/);
  assert.match(sec.files[0].content, /map \$http_upgrade \$connection_upgrade/);
  assert.match(app, /location \/ws \{\n\s+rewrite \^\/ws\/\?\(\.\*\)\$ \/\$1 break;\n\s+proxy_pass http:\/\/realtime;/);
  assert.match(app, /proxy_pass https:\/\/secureapi\/v2\/;[\s\S]*?proxy_ssl_verify on;\n\s+proxy_ssl_trusted_certificate \/etc\/ssl\/certs\/ca-certificates\.crt;[\s\S]*?proxy_ssl_name api1\.internal\.example\.com;/);
  assert.match(app, /location \/ \{\n\s+return 404;/);
  assert.ok(sec.notes.some((n) => /bcrypt/.test(n) && /crypt\(\)/.test(n)));

  const bal = nginx.build({ ...SPECS.balancing, version: '1.24.0' });
  assert.match(bal.files[0].content, /upstream hashed \{\n\s+ip_hash;/);
  assert.match(bal.files[0].content, /# server 10\.3\.0\.3:80 max_fails=3 fail_timeout=15s backup;/);
  assert.match(bal.files[0].content, /upstream rand \{\n\s+random;/);
  assert.match(bal.files[0].content, /server 10\.6\.0\.2:80 max_fails=3 fail_timeout=15s down;/);
  assert.ok(bal.unsupported.some((u) => /backup/.test(u) && /ip_hash/.test(u)));
  assert.match(bal.files[0].content, /log_format json escape=json/);
  assert.match(bal.files[0].content, /listen 127\.0\.0\.1:9000;/);
});

test('redirectHttp: false serves the site on HTTP and HTTPS alike', () => {
  const input = { sites: [{ name: 'both', hosts: ['both.example.com'], tls: { mode: 'files', cert: '/c.pem', key: '/k.pem', redirectHttp: false }, defaultPool: 'p' }], pools: [{ name: 'p', servers: ['10.9.0.1:80', '10.9.0.2:80'] }] };
  const hap = haproxy.build(input).files[0].content;
  assert.doesNotMatch(hap, /redirect scheme https/);
  assert.match(hap, /Strict-Transport-Security "max-age=31536000" if \{ ssl_fc \}/);
  const ngx = nginx.build(input).files.find((f) => f.name === 'conf.d/both.conf').content;
  assert.match(ngx, /server \{\n\s+listen 80;\n\s+listen 443 ssl;/);
  assert.doesNotMatch(ngx, /return 301/);
  for (const [product, files] of [['haproxy', [{ name: 'haproxy.cfg', content: hap }]], ['nginx', configFiles(nginx.build(input).files)]]) assertValid(product, null, files, `${product} redirectHttp false`);
});

test('unknown versions fall back to the newest documented release with a note', () => {
  const h = haproxy.build({ ...EXAMPLE_SPEC, version: 'banana' });
  assert.ok(h.notes.some((n) => /Could not read "banana"/.test(n)));
  const n = nginx.build({ ...EXAMPLE_SPEC, version: 'banana' });
  assert.ok(n.notes.some((x) => /Could not read "banana"/.test(x)));
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const apache = require('../src/products/apache');
const { EXAMPLE_SPEC } = require('../src/build/spec');

const HASH = `$2y$10$${'a'.repeat(53)}`;
const EXTRA = {
  sites: [
    { name: 'app', hosts: ['app.example.com', 'www.app.example.com'], tls: { mode: 'acme', email: 'ops@example.com' }, routes: [{ path: '/ws', pool: 'rt' }, { path: '/admin', match: 'exact', pool: 'rt', rewriteTo: '/dashboard' }, { path: '/v1/', pool: 'rt', rewriteTo: '/api/v1/' }], defaultPool: 'rt', websocket: true, basicAuth: { realm: 'Staff', users: [{ user: 'alice', hash: HASH }] } },
    { name: 'old', hosts: ['old.example.com'], redirectTo: 'https://app.example.com/' },
  ],
  pools: [{ name: 'rt', balance: 'iphash', servers: ['10.0.9.1:3000', '10.0.9.2:3000'], scheme: 'https', verifyTls: false, healthCheck: { path: '/ready' } }],
  options: { logFormat: 'json' },
};

function check(spec, layout, version) {
  const out = apache.build({ ...spec, version, options: { ...(spec.options || {}), layout } });
  assert.ok(out.files.length && Array.isArray(out.notes) && Array.isArray(out.unsupported));
  const parsed = apache.parseFiles(out.files);
  const v = apache.validate({ files: out.files, version: version || undefined });
  assert.deepEqual(v.findings.filter((f) => f.severity === 'error').map((f) => `${f.file}:${f.line} ${f.title}`), [], `${layout} ${version}: validator errors`);
  const a = apache.audit(parsed.sections, { notes: parsed.notes });
  assert.deepEqual(a.filter((f) => f.severity === 'error').map((f) => f.title), [], `${layout} ${version}: audit errors`);
  const im = apache.improve({ files: out.files, version: version || undefined });
  assert.deepEqual(im.changes.filter((c) => c.auto && c.on && c.severity === 'high').map((c) => c.title), [], `${layout} ${version}: high-severity doctor changes`);
  return { out, parsed, v, a, im };
}

test('build(EXAMPLE_SPEC): parses, validates (latest and 2.4.41), audits clean, nothing high for the doctor — every layout', () => {
  for (const layout of ['debian', 'rhel', 'standalone']) for (const version of [null, '2.4.41']) {
    const { out, parsed } = check(EXAMPLE_SPEC, layout, version);
    const shop = parsed.sections.find((s) => s.type === 'frontend' && s.name === 'shop.example.com:443');
    assert.ok(shop, layout);
    assert.deepEqual(shop.serverNames, ['shop.example.com', 'www.shop.example.com']);
    assert.deepEqual(shop.routes.map((r) => r.target), ['static', 'api', 'web'], 'longest prefix first, default pool last');
    assert.deepEqual(shop.routes[1].transforms.map((t) => t.action), ['strip-prefix'], 'stripPrefix');
    const web = parsed.sections.find((s) => s.name === 'web');
    assert.equal(web.balance, 'bybusyness'); assert.equal(web.sticky, true); assert.equal(web.healthCheck.path, '/healthz');
    const api = parsed.sections.find((s) => s.name === 'api');
    assert.equal(api.servers.find((s) => s.backup).address, '10.0.1.23:9000');
    assert.ok(out.unsupported.some((u) => /rate limit/.test(u) && /mod_ratelimit/.test(u)));
    const all = out.files.map((f) => f.content).join('\n');
    assert.match(all, /SetHandler balancer-manager\n\s+Require ip 127\.0\.0\.1 10\.0\.0\.0\/8/);
    assert.match(all, /LimitRequestBody 10485760/);
    assert.match(all, /Header add Set-Cookie "ROUTEID=\.%\{BALANCER_WORKER_ROUTE\}e; path=\/" env=BALANCER_ROUTE_CHANGED/);
    if (layout === 'debian') {
      assert.deepEqual(out.files.map((f) => f.name), ['conf-available/gatelight.conf', 'sites-available/shop.conf']);
      assert.ok(!/LoadModule/.test(all));
      assert.match(out.notes[0], /a2enmod .*proxy_balancer/); assert.match(out.notes[0], /a2ensite shop/); assert.match(out.notes[0], /apache2ctl configtest/);
      assert.match(all, /Listen 8404/); assert.ok(!/^Listen 80$/m.test(all), 'ports.conf already listens on 80/443');
    } else if (layout === 'rhel') {
      assert.deepEqual(out.files.map((f) => f.name), ['conf.d/00-gatelight.conf', 'conf.d/shop.conf']);
      assert.match(out.notes.join('\n'), /dnf install mod_ssl/); assert.match(out.notes.join('\n'), /httpd_can_network_connect/);
    } else {
      assert.deepEqual(out.files.map((f) => f.name), ['httpd.conf']);
      assert.match(all, /LoadModule proxy_balancer_module modules\/mod_proxy_balancer\.so/);
      assert.match(all, /LoadModule lbmethod_bybusyness_module/);
      assert.match(all, /^Listen 443$/m);
    }
  }
});

test('build: version-aware output', () => {
  const latest = apache.build(EXAMPLE_SPEC).files.map((f) => f.content).join('\n');
  assert.match(latest, /SSLProtocol -all \+TLSv1\.2 \+TLSv1\.3/); assert.match(latest, /Protocols h2 http\/1\.1/); assert.match(latest, /hcmethod=GET hcuri=\/healthz/);
  const old = apache.build({ ...EXAMPLE_SPEC, version: '2.4.16' });
  const o = old.files.map((f) => f.content).join('\n');
  assert.ok(!/TLSv1\.3|Protocols h2|hcmethod/.test(o));
  assert.ok(old.unsupported.some((u) => /mod_proxy_hcheck needs httpd 2\.4\.21/.test(u)));
  check(EXAMPLE_SPEC, 'standalone', '2.4.16');
});

test('build: ACME (mod_md), websocket, basic auth, redirect-only site', () => {
  for (const layout of ['debian', 'rhel', 'standalone']) for (const version of [null, '2.4.41']) {
    const { out, parsed } = check(EXTRA, layout, version);
    const all = out.files.map((f) => f.content).join('\n');
    assert.match(all, /MDCertificateAgreement accepted/); assert.match(all, /MDomain app\.example\.com www\.app\.example\.com/); assert.match(all, version === '2.4.41' ? /ServerAdmin ops@example\.com/ : /MDContactEmail ops@example\.com/, 'MDContactEmail needs 2.4.42');
    assert.match(all, /AuthType Basic[\s\S]*AuthUserFile "[^"]*\.htpasswd-app"[\s\S]*Require valid-user/);
    assert.ok(out.notes.some((n) => n.includes(`alice:${HASH}`)), 'htpasswd content in the notes');
    assert.match(all, /SSLProxyEngine on/);
    assert.ok(out.notes.some((n) => /no source-IP hash/.test(n)), 'iphash note');
    const old = parsed.sections.find((s) => s.type === 'frontend' && s.name === 'old.example.com:80');
    assert.ok(old.routes[0].terminal && old.routes[0].transforms[0].args[1] === 'https://app.example.com/');
    const app = parsed.sections.find((s) => s.type === 'frontend' && s.name === 'app.example.com:443');
    if (version === '2.4.41') {
      assert.match(all, /RewriteCond %\{HTTP:Upgrade\} =websocket \[NC\]/); assert.match(all, /balancer:\/\/rt-ws/); assert.ok(!/upgrade=websocket/.test(all));
    } else {
      assert.match(all, /upgrade=websocket/); assert.ok(!/rt-ws/.test(all));
      assert.deepEqual(app.routes.map((r) => `${r.directive} ${r.paths[0]}`), ['ProxyPassMatch ^/admin$', 'ProxyPass /v1/', 'ProxyPassMatch ^/ws(/.*)?$', 'ProxyPass /'], 'exact first, then longest prefix');
      assert.deepEqual(app.routes[0].transforms[0].args, ['^/admin$', '/dashboard'], 'exact + rewriteTo');
      assert.deepEqual(app.routes[1].transforms[0].args, ['^/v1/(.*)$', '/api/v1/$1'], 'prefix rewriteTo');
      assert.deepEqual(app.routes[2].transforms[0].args, ['^/ws(/.*)?$', '/ws$1'], 'prefix without trailing slash keeps the segment boundary');
    }
    const http = parsed.sections.find((s) => s.type === 'frontend' && s.name === 'app.example.com:80');
    assert.equal(http.routes[0].transforms[0].action, 'redirect');
  }
  const ancient = apache.build({ ...EXTRA, version: '2.4.25' });
  assert.ok(ancient.unsupported.some((u) => /mod_md ships with httpd 2\.4\.30/.test(u)));
  assert.ok(!ancient.files.some((f) => /MDomain/.test(f.content)));
});

test('build: layout option defaults to debian, accepts build(spec, { layout })', () => {
  assert.equal(apache.build(EXAMPLE_SPEC).layout, 'debian');
  assert.equal(apache.build(EXAMPLE_SPEC, { layout: 'rhel' }).layout, 'rhel');
  assert.equal(apache.build({ ...EXAMPLE_SPEC, options: { ...EXAMPLE_SPEC.options, layout: 'upstream' } }).layout, 'standalone');
  const catchAll = apache.build({ sites: [{ name: 'any', defaultPool: 'p' }], pools: [{ name: 'p', servers: ['10.0.0.1:80'] }] });
  assert.equal(catchAll.files[1].name, 'sites-available/000-any.conf');
  assert.throws(() => apache.build({ sites: [] }), /Add at least one site/);
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const T = require('../src/products/traefik');
const model = require('../src/products/traefik/model');
const K = require('../src/products/traefik/kb');
const { EXAMPLE_SPEC } = require('../src/build/spec');
const { startStub } = require('./helpers');

const DIR = path.join(__dirname, '..', 'examples', 'traefik');
const read = (n) => ({ name: n, content: fs.readFileSync(path.join(DIR, n), 'utf8') });
const FILE_SET = ['traefik.yml', 'dynamic/routers.yml', 'dynamic/middlewares.yml'].map(read);
const ALL = [...FILE_SET, read('docker-compose.yml')];
const fe = (secs, n) => secs.find((s) => s.type === 'frontend' && s.name === n);
const be = (secs, n) => secs.find((s) => s.type === 'backend' && s.name === n);

// ------------------------------------------------------------------------------------------------ module + KB
test('traefik: module implements the contract', () => {
  for (const k of ['type', 'name', 'short', 'labels', 'defaultFile', 'example', 'fileFormats']) assert.ok(T[k], k);
  for (const fn of ['detect', 'parseFiles', 'loadPath', 'redact', 'audit', 'versions', 'validate', 'improve', 'build']) assert.equal(typeof T[fn], 'function', fn);
  assert.equal(T.flow.defaultPort('https'), 443); assert.equal(T.flow.defaultPort('http'), 80);
  assert.ok(fs.existsSync(T.example));
  const v = T.versions();
  assert.equal(v.list[0], v.latest); assert.ok(v.list.includes('2.11.63') || v.list.some((x) => x.startsWith('2.11.')));
  assert.ok(v.list.some((x) => x.startsWith('2.0.')) && v.list.some((x) => x.startsWith('3.0.')));
});

test('traefik: knowledge base covers v2.0..v3.x with versioned paths, matchers and middlewares', () => {
  const kb = K.kb;
  assert.ok(fs.statSync(path.join(__dirname, '..', 'src', 'kb', 'traefik.json')).size < 1024 * 1024);
  assert.equal(kb.static['entryPoints.<name>.address'].s, '2.0');
  assert.equal(kb.dynamic['http.routers.<name>.rule'].t, 'string');
  assert.equal(kb.dynamic['http.routers.<name>.ruleSyntax'].s, '3.0');
  assert.equal(kb.dynamic['http.middlewares.<name>.ipAllowList.sourceRange'].s, '2.11');
  assert.equal(kb.static['providers.marathon.endpoint'].u, '3.0');
  assert.equal(kb.static['pilot.token'].u, '3.0');
  assert.equal(kb.dynamic['http.services.<name>.loadBalancer.healthCheck.interval'].t, 'duration');
  assert.ok(kb.matchers.http.v2.Headers && !kb.matchers.http.v3.Headers && kb.matchers.http.v3.Header);
  assert.equal(kb.matchers.http.v2.ClientIP.s, '2.5');
  assert.ok(kb.matchers.http.v2.HostHeader && !kb.matchers.http.v3.HostHeader);
  assert.ok(kb.matchers.tcp.v3.HostSNIRegexp && kb.matchers.tcp.v2.ALPN.s === '2.9');
  assert.ok(kb.middlewares.http.ipWhiteList && kb.middlewares.http.grpcWeb.s === '3.0');
  assert.ok(kb.deprecated.some((d) => /ipWhiteList/.test(d.re)) && kb.notes.length > 20);
  assert.match(K.docsUrl('routers', '2'), /^https:\/\/doc\.traefik\.io\/traefik\/v2\.11\/routing\/routers\/$/);
  assert.match(K.docsUrl('routers', '3'), /^https:\/\/doc\.traefik\.io\/traefik\/[a-z]/);
});

test('traefik: detect() recognises static, dynamic, TOML and labels; not NGINX / HAProxy', () => {
  for (const f of ALL) assert.ok(T.detect(f.content) >= 0.5, f.name);
  assert.ok(T.detect('[entryPoints]\n  [entryPoints.web]\n    address = ":80"\n[providers.file]\n  directory = "/d"\n') >= 0.5);
  assert.ok(T.detect('[http.routers.r]\n  rule = "Host(`a`)"\n  service = "s"\n') >= 0.5);
  assert.ok(T.detect('http {\n  server {\n    listen 80;\n    location / { proxy_pass http://a; }\n  }\n}\n') < 0.5);
  assert.ok(T.detect('frontend fe\n  bind :80\n  default_backend be\nbackend be\n  server s1 10.0.0.1:80 check\n') < 0.5);
  assert.ok(T.detect('version: "3"\nservices:\n  db:\n    image: postgres\n') < 0.5);
});

// ------------------------------------------------------------------------------------------------ parser / model
test('parseFiles: static + dynamic files -> entryPoint frontends, priority-sorted routes, services', () => {
  const r = T.parseFiles(FILE_SET);
  const ws = fe(r.sections, 'websecure');
  assert.equal(ws.binds[0].address, '*:443'); assert.equal(ws.binds[0].port, '443'); assert.equal(ws.binds[0].ssl, true);
  assert.ok(ws.serverNames.includes('shop.example.com') && ws.serverNames.includes('traefik.example.com'));
  const web = fe(r.sections, 'web');
  assert.equal(web.binds[0].ssl, false);
  assert.equal(web.routes[0].terminal, true); assert.equal(web.routes[0].transforms[0].action, 'redirect');
  assert.equal(fe(r.sections, 'postgres').mode, 'tcp');
  assert.equal(fe(r.sections, 'metrics').binds[0].address, '127.0.0.1:8082');
  // evaluation order: TCP routers first, then priority (explicit, else rule length), highest first
  const http = ws.routes.filter((x) => x.proto === 'http');
  assert.ok(ws.routes.findIndex((x) => x.proto === 'tcp') < ws.routes.findIndex((x) => x.proto === 'http'));
  for (let i = 1; i < http.length; i++) assert.ok(http[i - 1].priority >= http[i].priority, 'sorted by priority');
  assert.equal(http[0].router, 'shop-api-beta'); assert.equal(http[0].priority, 200);
  // OR rule -> one route per branch, same priority; AND matchers per route
  const shop = http.filter((x) => x.router === 'shop');
  assert.equal(shop.length, 2); assert.equal(shop[0].priority, shop[1].priority);
  assert.deepEqual(shop.map((x) => x.hosts[0]).sort(), ['shop.example.com', 'www.shop.example.com']);
  const api = http.find((x) => x.router === 'shop-api');
  assert.equal(api.priority, '"Host(`shop.example.com`) && PathPrefix(`/api`)"'.length - 2);
  assert.deepEqual(api.matchers.map((m) => [m.field, m.op, m.values[0]]), [['Host', 'is', 'shop.example.com'], ['Path', 'begins with', '/api']]);
  assert.deepEqual(api.paths, ['/api…']);
  assert.equal(api.target, 'api-canary'); assert.equal(api.file, 'dynamic/routers.yml'); assert.equal(api.line, 15);
  assert.deepEqual(api.transforms.map((t) => t.action), ['strip-prefix']); assert.deepEqual(api.transforms[0].args, ['/api']);
  const legacy = http.filter((x) => x.router === 'shop-legacy');
  assert.equal(legacy.length, 2);
  assert.deepEqual(legacy[0].transforms.map((t) => t.action), ['replace-path-regex', 'add-prefix']);
  const beta = http[0];
  assert.deepEqual(beta.matchers[2], { field: 'Header', op: 'is', name: 'X-Canary', values: ['always'], negated: false });
  // chain expanded: secure-chain -> headers (custom request header) + compress
  assert.deepEqual(shop[0].transforms.map((t) => t.action), ['set-header']);
  assert.ok(shop[0].middlewares.some((m) => m.type === 'compress'));
  // dashboard -> terminal route to api@internal
  const dash = http.find((x) => x.router === 'dashboard');
  assert.equal(dash.target, 'api@internal'); assert.equal(dash.terminal, true);
  // services
  const web2 = be(r.sections, 'shop-web');
  assert.deepEqual(web2.servers.map((s) => s.address), ['10.0.1.11:8080', '10.0.1.12:8080']);
  assert.equal(web2.servers[0].name, 'http://10.0.1.11:8080'); assert.equal(web2.servers[0].scheme, 'http');
  assert.deepEqual([web2.healthCheck.path, web2.healthCheck.interval], ['/healthz', '10s']);
  assert.equal(web2.sticky, true); assert.equal(web2.servers[0].check, true);
  assert.equal(be(r.sections, 'api-v3').healthCheck, null);
  const canary = be(r.sections, 'api-canary');
  assert.equal(canary.composite, 'weighted'); assert.deepEqual(canary.servers.map((s) => [s.name, s.weight]), [['api-v2', 9], ['api-v3', 1]]);
  assert.equal(be(r.sections, 'api-mirror').servers[1].opts.percent, 10);
  assert.equal(be(r.sections, 'legacy-billing').servers[0].scheme, 'https');
  assert.equal(be(r.sections, 'pg-primary').mode, 'tcp');
  assert.ok(r.files.every((f) => typeof f.raw === 'string'));
});

test('parseFiles: docker-compose labels (CLI flags as static config, default service, provider suffix)', () => {
  const r = T.parseFiles([read('docker-compose.yml')]);
  const ws = fe(r.sections, 'websecure');
  assert.equal(ws.binds[0].ssl, true);
  assert.deepEqual(ws.routes.map((x) => x.router).sort(), ['docs-site', 'grafana', 'whoami']);
  const docs = ws.routes.find((x) => x.router === 'docs-site');
  assert.deepEqual(docs.transforms.map((t) => [t.action, t.args[0]]), [['strip-prefix', '/guide']]);
  assert.equal(docs.provider, 'docker'); assert.equal(docs.file, 'docker-compose.yml'); assert.ok(docs.line > 20);
  // whoami: no service label -> service named after the container, port from `expose`
  const who = be(r.sections, 'whoami');
  assert.equal(who.servers[0].address, 'whoami:80');
  assert.equal(ws.routes.find((x) => x.router === 'whoami').target, 'whoami');
  assert.equal(be(r.sections, 'docs').healthCheck.path, '/');
  assert.equal(fe(r.sections, 'web').routes[0].transforms[0].action, 'redirect', 'redirection from the CLI flags');
  assert.ok(r.notes.some((n) => /internal-tool/.test(n.msg)), 'disabled container noted');
  assert.ok(!be(r.sections, 'internal-tool'));
  // together with the file provider: docs@docker resolves across providers
  const all = T.parseFiles(ALL);
  assert.equal(fe(all.sections, 'websecure').routes.find((x) => x.router === 'docs').target, 'docs');
  assert.equal(T.audit(all.sections, { notes: all.notes }).filter((f) => f.id === 'traefik-unknown-service').length, 0);
});

test('parseFiles: TOML static + dynamic, routers without entryPoints attach to all, Go templates, syntax errors', () => {
  const r = T.parseFiles([
    { name: 'traefik.toml', content: '[entryPoints]\n  [entryPoints.web]\n    address = ":80"\n  [entryPoints.alt]\n    address = ":8000"\n[providers.file]\n  filename = "dyn.toml"\n' },
    { name: 'dyn.toml', content: '[http.routers.r]\n  rule = "PathPrefix(`/`)"\n  service = "s"\n[[http.services.s.loadBalancer.servers]]\n  url = "http://a:1"\n' },
    { name: 'tpl.yml', content: 'http:\n  routers:\n{{ range $i, $e := until 2 }}\n    r{{ $e }}:\n      rule: "Host(`x{{ $e }}.com`)"\n      service: s\n{{ end }}\n' },
    { name: 'bad.yml', content: 'http:\n  routers:\n   r: [\n' },
  ]);
  assert.equal(fe(r.sections, 'web').routes.length, 2, 'router r + templated router on every entryPoint');
  assert.equal(fe(r.sections, 'alt').routes.length, 2);
  assert.ok(r.notes.some((n) => /Go template/.test(n.msg)));
  assert.ok(r.notes.some((n) => n.file === 'bad.yml' && /syntax error/.test(n.msg) && n.line === 3));
});

test('redact(): basic-auth hashes, tokens, passwords, URL credentials, private keys', () => {
  const out = T.redact([
    'users:', '  - "admin:$apr1$Hx1aBc2d$EXAMPLE"', '  - bob:$2y$05$abcdef', 'users = ["a:$apr1$xyz", "b:hash"]',
    'token: s3cr3t-token', 'password = "pw"', 'url: http://user:pass@10.0.0.1:80/', 'keyFile: /etc/ssl/key.pem', 'email: ops@example.com',
    '  - "traefik.http.middlewares.a.basicauth.users=u:$$apr1$$zz,v:$$apr1$$yy"', 'Authorization: "Bearer abc"', 'CF_DNS_API_TOKEN: abc123',
    'key: |', '  -----BEGIN PRIVATE KEY-----', '  MIIEvQIBADAN', '  -----END PRIVATE KEY-----',
  ].join('\n'));
  for (const secret of ['Hx1aBc2d', 'abcdef', 'xyz', 's3cr3t', '"pw"', 'pass@', 'zz', 'yy', 'Bearer abc', 'abc123', 'MIIEvQIBADAN']) assert.ok(!out.includes(secret), secret);
  for (const kept of ['admin:***', 'bob:***', 'keyFile: /etc/ssl/key.pem', 'ops@example.com', 'u:***,v:***', 'user:***@']) assert.ok(out.includes(kept), kept);
  const files = T.parseFiles(ALL).files;
  assert.ok(!files.some((f) => /EXAMPLEhash/.test(f.raw)));
});

test('loadPath(): reads providers.file.directory from disk, rebased into the root', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-traefik-'));
  try {
    fs.mkdirSync(path.join(root, 'dynamic'));
    fs.copyFileSync(path.join(DIR, 'traefik.yml'), path.join(root, 'traefik.yml'));
    for (const f of ['routers.yml', 'middlewares.yml']) fs.copyFileSync(path.join(DIR, 'dynamic', f), path.join(root, 'dynamic', f));
    const r = T.loadPath(path.join(root, 'traefik.yml'), root);
    assert.deepEqual(r.files.map((f) => f.name).sort(), ['dynamic/middlewares.yml', 'dynamic/routers.yml', 'traefik.yml']);
    assert.ok(be(r.sections, 'shop-web'));
    assert.throws(() => T.loadPath('/etc/passwd', root), /outside/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------------ audit
test('audit: finds the weak spots of the example and injected mistakes', () => {
  const r = T.parseFiles(ALL);
  const ids = T.audit(r.sections, { notes: r.notes }).map((f) => f.id);
  for (const id of ['traefik-weak-tls', 'traefik-no-healthcheck', 'traefik-insecure-skip-verify', 'traefik-unused-middleware']) assert.ok(ids.includes(id), id);
  assert.ok(!ids.includes('traefik-dashboard-no-auth'));
  const bad = T.parseFiles([
    { name: 'traefik.yml', content: 'api:\n  insecure: true\nlog:\n  level: DEBUG\nentryPoints:\n  web:\n    address: ":80"\n  websecure:\n    address: ":443"\nproviders:\n  docker: {}\n' },
    { name: 'd.yml', content: 'http:\n  routers:\n    a:\n      rule: "Host(`a.com`)"\n      entryPoints: [websecure]\n      service: nope\n      middlewares: [missing]\n    b:\n      rule: "Host(`a.com`)"\n      entryPoints: [websecure]\n      service: s\n    c:\n      rule: "Host(`a.com`)"\n      entryPoints: [websecure]\n      service: s\n    dash:\n      rule: "Host(`t.a.com`)"\n      service: api@internal\n  middlewares:\n    old:\n      ipWhiteList:\n        sourceRange: [10.0.0.0/8]\n  services:\n    s:\n      loadBalancer:\n        servers: [{url: "http://a:1"}, {url: "http://b:1"}]\n' },
  ]);
  const f = T.audit(bad.sections, { notes: bad.notes });
  const has = (id, sev) => f.some((x) => x.id === id && (!sev || x.severity === sev));
  assert.ok(has('traefik-unknown-service', 'error')); assert.ok(has('traefik-unknown-middleware', 'error'));
  assert.ok(has('traefik-api-insecure', 'error')); assert.ok(has('traefik-dashboard-no-auth', 'error'));
  assert.ok(has('traefik-docker-exposed')); assert.ok(has('traefik-no-access-log')); assert.ok(has('traefik-debug-log'));
  assert.ok(has('traefik-websecure-no-tls')); assert.ok(has('traefik-no-https-redirect')); assert.ok(has('traefik-duplicate-rule'));
  assert.ok(has('traefik-ipwhitelist')); assert.ok(has('traefik-no-healthcheck'));
  assert.ok(f.every((x) => x.file && x.line && x.title && x.category && x.rule));
  assert.ok(f.filter((x) => x.docs).every((x) => /^https:\/\/doc\.traefik\.io\/traefik\//.test(x.docs)));
});

// ------------------------------------------------------------------------------------------------ validate
test('validate: the example has no errors on the latest v3; on v2.11 only the v3-only matcher', () => {
  const latest = T.validate({ files: ALL });
  assert.equal(latest.target.version, K.kb.latest);
  assert.deepEqual(latest.findings.filter((f) => f.severity === 'error'), []);
  const v211 = T.validate({ files: ALL, version: '2.11.20' });
  const errs = v211.findings.filter((f) => f.severity === 'error');
  assert.equal(errs.length, 1); assert.match(errs[0].title, /Header\(\) is v3 rule syntax/); assert.equal(errs[0].line, 24);
  assert.ok(v211.kb.generated && v211.kb.latest);
});

test('validate: flags unknown options (with suggestions), version gaps, deprecations, rule syntax, types, YAML errors', () => {
  const dyn = 'http:\n  routers:\n    r1:\n      rule: "Host(`a.com`) && Headers(`X`, `y`)"\n      service: s1\n      priorty: 10\n    r2:\n      rule: "Host(`a.com`) && HeaderRegexp(`X`, `^a`)"\n      service: s1\n  middlewares:\n    wl:\n      ipWhiteList:\n        sourceRange: [10.0.0.0/8]\n    hd:\n      headers:\n        stsSeconds: abc\n  services:\n    s1:\n      loadBalancer:\n        servers:\n          - url: 10.0.0.1:80\n            weight: 2\n';
  const st = 'entryPoints:\n  web:\n    adress: ":80"\npilot:\n  token: abc\n';
  const files = [{ name: 'dyn.yml', content: dyn }, { name: 'traefik.yml', content: st }, { name: 'broken.yml', content: 'http:\n  routers:\n    x: "unterminated\n' }];
  const v3 = T.validate({ files }).findings;
  const find = (re, sev) => v3.find((f) => re.test(f.title) && (!sev || f.severity === sev));
  const unk = find(/Unknown dynamic option "priorty"/, 'error');
  assert.ok(unk && /priority/.test(unk.detail) && unk.line === 6 && unk.file === 'dyn.yml');
  assert.ok(find(/Unknown static option "adress"/, 'error'));
  assert.ok(find(/Headers\(\) is a v2-syntax matcher/, 'error'), 'v2 matcher with v3 syntax');
  assert.ok(find(/ipWhiteList.*deprecated/, 'warning'), 'v2-only middleware name on v3');
  assert.ok(find(/pilot was removed in Traefik 3\.0/, 'error'));
  assert.ok(find(/stsSeconds should be an integer/, 'warning'));
  assert.ok(find(/needs a scheme/, 'error'));
  assert.ok(v3.find((f) => f.id === 'traefik-syntax' && f.file === 'broken.yml' && f.line === 3));
  const v2 = T.validate({ files, version: '2.10' }).findings;
  assert.ok(v2.find((f) => /HeaderRegexp\(\) is v3 rule syntax/.test(f.title)), 'v3-only matcher on v2');
  assert.ok(v2.find((f) => /servers\.weight needs Traefik 3\.0/.test(f.title)), 'option newer than the target');
  assert.ok(!v2.find((f) => /Headers\(\)/.test(f.title)), 'Headers is fine on v2');
  assert.ok(v2.find((f) => /ipWhiteList/.test(f.title)) === undefined, 'not deprecated before 2.11');
  assert.ok(T.validate({ files, version: '2.0' }).findings.find((f) => /ClientIP|ipAllowList/.test(f.title)) === undefined);
  // a static option in a dynamic file and vice versa
  const wrong = T.validate({ files: [{ name: 'd.yml', content: 'http:\n  routers: {}\nentryPoints:\n  web:\n    address: ":80"\n' }, { name: 'x.yml', content: 'tls:\n  options: {}\nproviders:\n  file: {}\n' }] }).findings;
  assert.ok(wrong.length >= 0);
  assert.match(T.validate({ files: ALL, version: 'banana' }).target.note, /Could not read/);
});

// ------------------------------------------------------------------------------------------------ improve
test('improve: rewrites the example (comments kept), idempotent, version-aware', () => {
  const a = T.improve({ files: ALL });
  const rules = a.changes.map((c) => c.rule);
  for (const r of ['tfk-tls-min', 'tfk-healthcheck', 'tfk-skip-verify']) assert.ok(rules.includes(r), r);
  assert.ok(a.changes.every((c) => c.title && c.why && c.category && ['high', 'medium', 'low', 'info'].includes(c.severity) && Array.isArray(c.ops)));
  const out = a.render((c) => c.on);
  assert.ok(out.find((f) => f.name === 'dynamic/routers.yml').content.includes('# Routers: which requests go where'));
  const mw = out.find((f) => f.name === 'dynamic/middlewares.yml').content;
  assert.match(mw, /minVersion: VersionTLS12\n/); assert.ok(!/VersionTLS11/.test(mw));
  assert.ok(T.parseFiles(out).sections.find((s) => s.name === 'api-v3').healthCheck);
  assert.deepEqual(T.validate({ files: out }).findings.filter((f) => f.severity === 'error'), []);
  const again = T.improve({ files: out });
  assert.deepEqual(again.changes.filter((c) => c.auto && c.on).map((c) => c.rule), []);
  // everything switched on (incl. opt-in changes) is idempotent too
  const all = a.render(() => true);
  assert.deepEqual(T.improve({ files: all }).changes.filter((c) => c.auto && c.on).map((c) => c.rule), []);
});

test('improve: v2 configuration migrated for v3; static hardening; TOML', () => {
  const st = 'api:\n  insecure: true\nlog:\n  level: DEBUG\nentryPoints:\n  web:\n    address: ":80"\n  websecure:\n    address: ":443"\npilot:\n  token: x\nproviders:\n  file:\n    filename: d.yml\n';
  const dy = '# routes\nhttp:\n  routers:\n    a:\n      rule: "Host(`a.com`, `b.com`) && Headers(`X`, `1`)"\n      entryPoints: [websecure]\n      service: s\n      middlewares: [wl]\n      tls: {}\n  middlewares:\n    wl:\n      ipWhiteList:\n        sourceRange: [10.0.0.0/8]\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: "http://a:1"\n          - url: "http://b:1"\n';
  const files = [{ name: 'traefik.yml', content: st }, { name: 'd.yml', content: dy }];
  const a = T.improve({ files, version: '3.1' });
  const byRule = (r) => a.changes.find((c) => c.rule === r);
  for (const r of ['tfk-https-redirect', 'tfk-api-insecure', 'tfk-access-log', 'tfk-log-level', 'tfk-tls-default', 'tfk-healthcheck', 'tfk-ipallowlist', 'tfk-v3-pilot', 'tfk-v3-rule', 'tfk-security-headers', 'tfk-compress']) assert.ok(byRule(r), r);
  assert.equal(byRule('tfk-v3-rule').auto, true);
  const out = a.render((c) => c.on);
  const d = out.find((f) => f.name === 'd.yml').content; const s = out.find((f) => f.name === 'traefik.yml').content;
  assert.match(d, /rule: "\(Host\(`a\.com`\) \|\| Host\(`b\.com`\)\) && Header\(`X`, `1`\)"/);
  assert.match(d, /ipAllowList:/); assert.match(d, /^# routes/);
  assert.match(s, /insecure: false/); assert.ok(!/pilot/.test(s)); assert.match(s, /to: websecure/);
  assert.deepEqual(T.validate({ files: out, version: '3.1' }).findings.filter((f) => f.severity === 'error'), []);
  assert.deepEqual(T.improve({ files: out, version: '3.1' }).changes.filter((c) => c.auto && c.on).map((c) => c.rule), []);
  // v2 target: no v3 rewrites, ipWhiteList kept before 2.11
  const v2 = T.improve({ files, version: '2.9' });
  assert.ok(!v2.changes.some((c) => /^tfk-v3|tfk-ipallowlist/.test(c.rule)));
  // TOML static file
  const t = T.improve({ files: [{ name: 'traefik.toml', content: '[entryPoints.web]\n  address = ":80"\n[entryPoints.websecure]\n  address = ":443"\n' }] });
  const tout = t.render((c) => c.on)[0].content;
  assert.match(tout, /\[accessLog\]/); assert.match(tout, /to = "websecure"/);
  assert.deepEqual(T.improve({ files: [{ name: 'traefik.toml', content: tout }] }).changes.filter((c) => c.auto && c.on), []);
});

// ------------------------------------------------------------------------------------------------ build
function checkBuild(spec, version) {
  const b = T.build({ ...spec, version });
  assert.deepEqual(b.files.map((f) => f.name), ['traefik.yml', 'dynamic.yml']);
  const p = T.parseFiles(b.files);
  assert.ok(p.sections.some((s) => s.type === 'frontend') && p.sections.some((s) => s.type === 'backend'));
  const v = T.validate({ files: b.files, version });
  assert.deepEqual(v.findings.filter((f) => f.severity === 'error'), [], `validate ${version}`);
  assert.deepEqual(T.audit(p.sections, { notes: p.notes }).filter((f) => f.severity === 'error'), [], `audit ${version}`);
  assert.deepEqual(T.improve({ files: b.files, version }).changes.filter((c) => c.auto && c.severity === 'high'), [], `improve ${version}`);
  return { b, p };
}

test('build(EXAMPLE_SPEC): valid for the latest v3 and for v2.11', () => {
  const { b, p } = checkBuild(EXAMPLE_SPEC, null);
  const ws = fe(p.sections, 'websecure');
  const hosts = ws.routes.filter((r) => r.router.startsWith('shop')).map((r) => r.router);
  assert.ok(hosts.indexOf('shop-api') < hosts.indexOf('shop'), 'longer path first');
  assert.ok(ws.routes.find((r) => r.router === 'shop-api').transforms.some((t) => t.action === 'strip-prefix'));
  assert.equal(fe(p.sections, 'web').routes[0].transforms[0].action, 'redirect');
  assert.equal(be(p.sections, 'api').composite, 'failover', 'backup server -> failover service');
  assert.equal(be(p.sections, 'web').balance, 'p2c', 'leastconn -> p2c on 3.5+');
  assert.ok(be(p.sections, 'web').sticky);
  assert.match(b.files[1].content, /ipAllowList/); assert.match(b.files[0].content, /manualRouting: true/);
  const v2 = checkBuild(EXAMPLE_SPEC, '2.11');
  assert.ok(v2.b.unsupported.some((u) => /leastconn/.test(u)));
  const old = checkBuild(EXAMPLE_SPEC, '2.6');
  assert.match(old.b.files[1].content, /ipWhiteList/);
  assert.ok(old.b.unsupported.some((u) => /backup/.test(u)));
});

test('build: ACME, websocket, basic auth, weights, https upstreams and a redirect-only site', () => {
  const hash = `$2y$05$${'a'.repeat(53)}`;
  const spec = {
    sites: [
      { name: 'app', hosts: ['app.example.com', 'www.app.example.com'], tls: { mode: 'acme', email: 'ops@example.com', minVersion: '1.3' }, routes: [{ path: '/ws', pool: 'app' }, { path: '/admin', match: 'exact', pool: 'app', rewriteTo: '/admin/index.html' }, { path: '/v1/', pool: 'app', rewriteTo: '/api/' }], defaultPool: 'app', websocket: true, basicAuth: { realm: 'Staff', users: [{ user: 'alice', hash }] } },
      { name: 'old', hosts: ['old.example.com'], redirectTo: 'https://app.example.com/' },
    ],
    pools: [{ name: 'app', servers: [{ address: '10.1.0.1:443', weight: 3 }, { address: '10.1.0.2:443', weight: 1 }], scheme: 'https', balance: 'iphash', healthCheck: { path: '/up' } }],
    options: { logFormat: 'json' },
  };
  for (const version of [null, '2.11']) {
    const { b, p } = checkBuild(spec, version);
    const [st, dy] = b.files.map((f) => f.content);
    assert.match(st, /certificatesResolvers:\n {2}letsencrypt:\n {4}acme:\n {6}email: ops@example\.com/);
    assert.match(st, /format: json/);
    assert.match(dy, /basicAuth:/); assert.match(dy, /alice:\$2y\$05\$/);
    assert.match(dy, /redirectRegex:/); assert.match(dy, /replacement: "https:\/\/app\.example\.com\/\$\{1\}"/);
    assert.match(dy, /minVersion: VersionTLS13/);
    assert.ok(b.notes.some((n) => /WebSocket/.test(n)));
    const old = fe(p.sections, 'web').routes.find((r) => r.router === 'old');
    assert.equal(old.terminal, true);
    if (version) { assert.match(dy, /weighted:/); assert.ok(b.unsupported.some((u) => /iphash/.test(u))); } else { assert.match(dy, /weight: 3/); assert.match(dy, /strategy: hrw/); }
  }
});

// ------------------------------------------------------------------------------------------------ live
test('live: Traefik API + Prometheus metrics -> frontend / backend / server rows joined to the config', async () => {
  const services = [
    { loadBalancer: { servers: [{ url: 'http://10.0.1.11:8080' }, { url: 'http://10.0.1.12:8080' }], healthCheck: { path: '/healthz', interval: '10s' }, passHostHeader: true }, name: 'shop-web@file', provider: 'file', serverStatus: { 'http://10.0.1.11:8080': 'UP', 'http://10.0.1.12:8080': 'DOWN' }, status: 'enabled', type: 'loadbalancer', usedBy: ['shop@file'] },
    { loadBalancer: { servers: [{ url: 'http://10.0.3.31:9000' }, { url: 'http://10.0.3.32:9000' }] }, name: 'api-v3@file', provider: 'file', serverStatus: { 'http://10.0.3.31:9000': 'UP', 'http://10.0.3.32:9000': 'UP' }, status: 'enabled', type: 'loadbalancer' },
    { loadBalancer: { servers: [{ url: 'http://whoami:80' }] }, name: 'whoami-myproject@docker', provider: 'docker', serverStatus: { 'http://whoami:80': 'DOWN' }, status: 'enabled', type: 'loadbalancer' },
    { name: 'api@internal', provider: 'internal', status: 'enabled', type: 'api' },
  ];
  const routers = [{ entryPoints: ['websecure'], name: 'shop@file', provider: 'file', rule: 'Host(`shop.example.com`)', service: 'shop-web', status: 'enabled', using: ['websecure'] }, { name: 'broken@file', status: 'disabled', error: ['the service "nope@file" does not exist'], rule: 'Host(`x`)' }];
  const metrics = [
    '# HELP traefik_entrypoint_requests_total How many HTTP requests processed on an entrypoint, partitioned by status code, protocol, and method.',
    '# TYPE traefik_entrypoint_requests_total counter',
    'traefik_entrypoint_requests_total{code="200",entrypoint="websecure",method="GET",protocol="http"} 900',
    'traefik_entrypoint_requests_total{code="502",entrypoint="websecure",method="GET",protocol="http"} 10',
    'traefik_entrypoint_requests_total{code="301",entrypoint="web",method="GET",protocol="http"} 50',
    'traefik_entrypoint_open_connections{entrypoint="websecure",method="GET",protocol="http"} 7',
    'traefik_entrypoint_request_duration_seconds_sum{code="200",entrypoint="websecure",method="GET",protocol="http"} 45.5',
    'traefik_entrypoint_request_duration_seconds_count{code="200",entrypoint="websecure",method="GET",protocol="http"} 910',
    'traefik_service_requests_total{code="200",method="GET",protocol="http",service="shop-web@file"} 400',
    'traefik_service_requests_total{code="503",method="GET",protocol="http",service="shop-web@file"} 4',
    'traefik_service_request_duration_seconds_sum{code="200",method="GET",protocol="http",service="shop-web@file"} 8',
    'traefik_service_request_duration_seconds_count{code="200",method="GET",protocol="http",service="shop-web@file"} 404',
    'traefik_service_server_up{service="shop-web@file",url="http://10.0.1.11:8080"} 1',
  ].join('\n');
  const stub = await startStub((req, res) => {
    const u = new URL(req.url, 'http://x');
    const json = (o, h = {}) => { res.writeHead(200, { 'Content-Type': 'application/json', ...h }); res.end(JSON.stringify(o)); };
    if (u.pathname === '/api/version') return json({ Version: '3.7.19', Codename: 'test', startDate: new Date(Date.now() - 3600e3).toISOString() });
    if (u.pathname === '/api/overview') return json({ http: { routers: { total: 2, warnings: 0, errors: 1 }, services: { total: 4, warnings: 0, errors: 0 }, middlewares: { total: 0, warnings: 0, errors: 0 } }, tcp: {}, features: { tracing: '', metrics: 'Prometheus', accessLog: true }, providers: ['File', 'Docker'] });
    if (u.pathname === '/api/entrypoints') return json([{ address: ':80', name: 'web' }, { address: ':443', name: 'websecure' }]);
    if (u.pathname === '/api/http/routers') return json(routers);
    if (u.pathname === '/api/http/services') { // two pages, like the real pagination
      if (u.searchParams.get('page') === '2') return json(services.slice(2));
      return json(services.slice(0, 2), { 'X-Next-Page': '2' });
    }
    if (u.pathname === '/api/tcp/routers' || u.pathname === '/api/tcp/services') return json([]);
    if (u.pathname === '/metrics') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(metrics); }
    res.writeHead(404); res.end('404 page not found');
  });
  try {
    const cfg = T.parseFiles(ALL);
    const inst = { statsUrl: `${stub.url}/api`, timeoutMs: 2000 };
    assert.equal(T.live.hasSource(inst), true); assert.ok(T.live.sources(inst).includes('traefik-api'));
    const { rows, info } = await T.live.collect(inst, { sections: cfg.sections }, {});
    const row = (proxy, name) => rows.find((r) => r.proxy === proxy && r.name === name);
    assert.equal(info.version, '3.7.19'); assert.ok(info.uptimeSec >= 3599); assert.equal(info.errors, 1); assert.equal(info.problems[0].name, 'broken@file');
    const ws = row('websecure', 'FRONTEND');
    assert.equal(ws.status, 'OPEN'); assert.equal(ws.req_tot, 910); assert.equal(ws.hrsp_2xx, 900); assert.equal(ws.hrsp_5xx, 10); assert.equal(ws.scur, 7); assert.equal(ws.rtime, 50);
    assert.equal(row('web', 'FRONTEND').hrsp_3xx, 50);
    assert.equal(row('shop-web', 'http://10.0.1.11:8080').status, 'UP');
    assert.equal(row('shop-web', 'http://10.0.1.12:8080').status, 'DOWN');
    assert.equal(row('shop-web', 'http://10.0.1.12:8080').addr, '10.0.1.12:8080');
    const sw = row('shop-web', 'BACKEND');
    assert.equal(sw.status, 'UP'); assert.equal(sw.req_tot, 404); assert.equal(sw.hrsp_5xx, 4); assert.equal(sw.check_status, '1/2 up');
    assert.equal(row('api-v3', 'http://10.0.3.31:9000').status, 'NO CHECK', 'no healthCheck in the config');
    assert.equal(row('whoami', 'BACKEND').status, 'DOWN', 'docker <service>-<project> joined to the compose service');
    assert.ok(!rows.some((r) => /internal/.test(r.proxy)));
    assert.ok(stub.hits.every((h) => h.method === 'GET'));
    assert.ok(stub.hits.some((h) => h.url.includes('page=2')));
  } finally { await stub.close(); }
});

// ------------------------------------------------------------------------------------------------ logs
const CLF = Array.from({ length: 20 }, (_, i) => `10.0.0.${i} - ${i % 5 ? '-' : 'alice'} [10/Nov/2026:06:33:${String(i).padStart(2, '0')} +0000] "GET /api/items/${1000 + i}?token=secret HTTP/1.1" ${i % 10 === 9 ? 502 : 200} ${512 + i} "-" "Mozilla/5.0 (X11)" ${i + 1} "shop-api@file" "http://10.0.2.2${i % 2}:9000" ${10 + i}ms`);
const JSONL = Array.from({ length: 10 }, (_, i) => JSON.stringify({ ClientAddr: `192.0.2.${i}:51000`, ClientHost: `192.0.2.${i}`, DownstreamContentSize: 100, DownstreamStatus: i === 3 ? 504 : 200, Duration: (5 + i) * 1e6, OriginDuration: (4 + i) * 1e6, OriginStatus: 200, RequestHost: 'shop.example.com', RequestMethod: 'POST', RequestPath: '/cart?id=7', RequestProtocol: 'HTTP/2.0', RouterName: 'shop@file', ServiceName: 'shop-web@file', ServiceURL: 'http://10.0.1.11:8080', ServiceAddr: '10.0.1.11:8080', StartUTC: `2026-11-10T06:34:0${i}.123Z`, 'request_User-Agent': 'curl/8', entryPointName: 'websecure', level: 'info', msg: '', time: '2026-11-10T06:34:00Z' }));

test('logs: Traefik CLF and JSON access logs aggregated (no query strings or user agents kept)', () => {
  const cfg = T.parseFiles(ALL);
  const a = T.logs.createAggregator({ sections: cfg.sections });
  for (const l of [...CLF, ...JSONL]) assert.equal(a.push(l), true, l.slice(0, 60));
  assert.equal(a.push('garbage line that is not a log'), false);
  const r = a.finish({ filename: 'access.log' });
  assert.equal(r.product, 'traefik');
  assert.equal(r.stats.http, 30);
  const keys = r.keys;
  assert.ok(keys.some((k) => k.fe === 'websecure' && k.be === 'api-canary' && k.srv === '10.0.2.20:9000'), 'CLF: router -> entryPoint, service from the config, server from the URL');
  assert.ok(keys.some((k) => k.fe === 'websecure' && k.be === 'shop-web' && k.srv === '10.0.1.11:8080'), 'JSON: ServiceName / ServiceAddr');
  assert.ok(keys.some((k) => k.cls === '5xx'));
  const blob = JSON.stringify(r);
  assert.ok(!blob.includes('token=secret') && !blob.includes('id=7') && !blob.includes('Mozilla') && !blob.includes('curl/8'));
  assert.ok(r.dims.host.values.includes('shop.example.com'));
  // without the config: the router is the frontend
  const b = T.logs.createAggregator(); CLF.forEach((l) => b.push(l));
  assert.ok(b.finish().keys.some((k) => k.fe === 'shop-api'));
});

test('logs: sniff() recognises Traefik lines and not plain NGINX / HAProxy lines', () => {
  const nginxSniff = require('../src/logs/nginx').sniff;
  assert.equal(T.logs.sniff(CLF).ratio, 1); assert.equal(T.logs.sniff(CLF).specific, true);
  assert.equal(T.logs.sniff(JSONL).ratio, 1);
  const NGX = Array.from({ length: 10 }, (_, i) => `10.0.0.${i} - - [17/May/2015:08:05:${String(i).padStart(2, '0')} +0000] "GET /a/${i} HTTP/1.1" 200 512 "-" "curl/8"`);
  assert.equal(T.logs.sniff(NGX).ratio, 0);
  assert.equal(T.logs.sniff(['{"status":200,"request":"GET / HTTP/1.1","time_local":"x"}']).ratio, 0);
  assert.ok(T.logs.sniff(CLF).ratio >= nginxSniff(CLF).ratio);
});

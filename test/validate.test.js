'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { validateConfig, versions } = require('../src/validate');
const V = require('../src/validate/version');
const { startApp, get, post } = require('./helpers');

const FX = path.join(__dirname, 'fixtures');
const read = (f) => fs.readFileSync(path.join(FX, f), 'utf8');
const hp = (config, version) => validateConfig({ product: 'haproxy', version, config });
const ng = (config, version, extra = {}) => validateConfig({ product: 'nginx', version, config, ...extra });
const ids = (r) => r.findings.map((f) => f.id);
const has = (r, id, re) => r.findings.some((f) => f.id === id && (!re || re.test(f.title)));
const hard = (r) => r.findings.filter((f) => f.severity === 'error' || (f.category === 'compat' && f.severity === 'warning'));

test('versions: parsing, comparison and detection from free text', () => {
  assert.equal(V.cmp('2.8.5', '2.10.0'), -1);
  assert.equal(V.cmp('1.25.1', '1.25.1'), 0);
  assert.equal(V.detect('HAProxy version 2.8.5-1ubuntu3, released 2024/01/01'), '2.8.5');
  assert.equal(V.detect('nginx/1.24.0 (Ubuntu)'), '1.24.0');
  assert.equal(V.haproxyBranch('2.8.5', ['1.7', '2.8', '3.0']), '2.8');
  assert.equal(V.haproxyBranch('2.9.1', ['1.7', '2.8', '3.0']), '2.8');
  const v = versions();
  assert.ok(v.haproxy.list.includes('2.8') && v.haproxy.list[0] === v.haproxy.latest);
  assert.match(v.nginx.latest, /^1\.\d+\.\d+$/);
});

// ------------------------------------------------------------------------------------------------ HAProxy
test('HAProxy: a large valid configuration produces no compatibility errors on a modern version', () => {
  const r = hp(read('valid-complex.haproxy.cfg'), '3.0');
  assert.deepEqual(hard(r).map((f) => `${f.id}:${f.title}`), []);
  assert.ok(r.summary.ok);
});

test('HAProxy: unknown keywords get "did you mean" suggestions, wherever they appear', () => {
  const r = hp(`global\n  maxconn 10\ndefaults\n  mode http\n  timeout cliet 5s\nfrontend f\n  bind :80\n  http-request set-header X %[req.hdr(host),lowerr]\n  acl a path_begg /x\n  use_backend b if { hdr_beg(host) a }\n  default_backend b\nbackend b\n  optoin httplog\n  server s1 10.0.0.1:80 chek\n`, '2.8');
  assert.ok(has(r, 'compat-unknown-keyword', /optoin/));
  assert.ok(r.findings.find((f) => /optoin/.test(f.title)).fix.includes('option'));
  assert.ok(has(r, 'compat-unknown-converter', /lowerr/));
  assert.ok(has(r, 'compat-unknown-fetch', /path_begg/));
  assert.ok(has(r, 'compat-unknown-server option', /chek/));
  assert.ok(r.findings.some((f) => f.id === 'compat-unknown-keyword' && /cliet/.test(f.title)));
});

test('HAProxy: the same file is valid or invalid depending on the target version', () => {
  const cfg = `global\n  nbproc 2\ndefaults\n  mode http\n  timeout client 1s\nfrontend f\n  bind quic4@:443 ssl crt /x.pem\n  http-after-response set-header X-A 1\n  default_backend b\nbackend b\n  server s 10.0.0.1:80\n`;
  const old = hp(cfg, '2.0');
  assert.ok(has(old, 'compat-too-new', /quic4/), 'quic needs 2.6');
  assert.ok(has(old, 'compat-too-new', /http-after-response/), 'http-after-response needs 2.2');
  assert.ok(!has(old, 'compat-removed'), 'nbproc still exists in 2.0');
  const next = hp(cfg, '3.2');
  assert.ok(has(next, 'compat-removed', /nbproc/), 'nbproc was removed in 2.5');
  assert.ok(!has(next, 'compat-too-new'));
  assert.ok(next.findings.find((f) => f.id === 'compat-removed').fix.includes('nbthread'));
});

test('HAProxy: removed and deprecated legacy rules point at the replacement', () => {
  const cfg = `defaults\n  mode http\n  timeout client 1s\n  timeout clitimeout 1s\nfrontend f\n  bind :80\n  reqadd X-A: 1\n  default_backend b\nbackend b\n  server s 10.0.0.1:80\n`;
  const old = hp(cfg, '1.9');
  assert.ok(old.findings.some((f) => f.id === 'compat-deprecated' && /clitimeout/.test(f.title)));
  const modern = hp(cfg, '2.4');
  const removed = modern.findings.filter((f) => f.id === 'compat-removed').map((f) => f.title).join(' ');
  assert.match(removed, /reqadd/); assert.match(removed, /clitimeout/);
  assert.ok(modern.findings.find((f) => /reqadd/.test(f.title)).fix.includes('http-request add-header'));
});

test('HAProxy: keywords in the wrong section type are reported', () => {
  const r = hp(`defaults\n  mode http\n  timeout client 1s\nfrontend f\n  bind :80\n  balance roundrobin\n  server s 10.0.0.1:80\n  default_backend b\nbackend b\n  bind :81\n  server s 10.0.0.1:80\n`, '2.8');
  assert.ok(has(r, 'compat-wrong-section', /balance/));
  assert.ok(has(r, 'compat-wrong-section', /bind/));
});

test('HAProxy: preprocessor conditions are evaluated for the target version', () => {
  const cfg = `global\n  maxconn 1\n.if version_atleast(2.8)\n  tune.bufsize 16384\n  thread-groups 2\n.else\n  nbproc 2\n.endif\n`;
  assert.ok(!hp(cfg, '3.0').findings.some((f) => f.id.startsWith('compat-')), 'new branch only on >= 2.8');
  assert.ok(!hp(cfg, '2.0').findings.some((f) => f.id === 'compat-too-new'), 'new branch is skipped on 2.0');
  assert.ok(has(hp('global\n.if version_atleast(2.8\n  maxconn 1\n', '3.0'), 'syntax-preprocessor') || has(hp('global\n.if foo\n  maxconn 1\n', '3.0'), 'syntax-preprocessor', /endif/));
});

test('HAProxy: line continuations, quotes and ${ENV} do not confuse the lexer', () => {
  const r = hp(`global\n  maxconn 100\ndefaults\n  mode http\n  timeout client 1s\nfrontend f\n  bind "\${BIND_ADDR}:443" ssl \\\n    crt /etc/x.pem \\\n    alpn h2,http/1.1\n  http-request set-header X-Msg "hello # not a comment"\n  default_backend b\nbackend b\n  server s \${SRV}:80 check\n`, '3.0');
  assert.deepEqual(r.findings.filter((f) => f.id.startsWith('compat-') || f.id.startsWith('syntax-')), []);
});

test('HAProxy: version-aware recommendations (HSTS style, nbproc, weak ciphers)', () => {
  const cfg = `global\n  nbthread 4\n  ssl-default-bind-ciphers RC4:3DES\ndefaults\n  mode http\n  timeout client 1s\nfrontend f\n  bind :443 ssl crt /x.pem\n  default_backend b\nbackend b\n  server s 10.0.0.1:80\n`;
  const r30 = hp(cfg, '3.0'); const r16 = hp(cfg, '1.8');
  assert.ok(ids(r30).includes('rec-weak-ciphers'));
  assert.match(r30.findings.find((f) => f.id === 'rec-hsts').fix, /http-after-response/);
  assert.match(r16.findings.find((f) => f.id === 'rec-hsts').fix, /http-response/);
  assert.ok(r30.findings.filter((f) => f.id.startsWith('rec-')).every((f) => f.category !== 'compat'));
});

// ------------------------------------------------------------------------------------------------ NGINX
test('NGINX: a large valid configuration (map/geo/stream/regex/lua/auth_request) has no errors or compat warnings', () => {
  const r = ng(read('valid-complex.nginx.conf'), '1.27.4');
  assert.deepEqual(hard(r).map((f) => `${f.id}:${f.title}`), []);
  assert.ok(r.summary.ok);
});

test('NGINX: strict syntax errors have file, line and a fix', () => {
  let r = ng('http {\n  server {\n    listen 80\n  }\n}\n', '1.24.0');
  assert.ok(has(r, 'syntax-nginx', /Missing ";"/));
  r = ng('http {\n  server {\n    listen 80;\n', '1.24.0');
  assert.ok(r.findings.filter((f) => f.id === 'syntax-nginx').length >= 1 && /Unclosed block|end of file/.test(r.findings.map((f) => f.title).join(' ')));
  r = ng('http { server { add_header X "abc; } }\n', '1.24.0');
  assert.ok(has(r, 'syntax-nginx', /Unterminated/));
  r = ng('http {}\n}\n', '1.24.0');
  assert.ok(has(r, 'syntax-nginx', /Unexpected "}"/));
});

test('NGINX: context, unknown directives, duplicates, arity and block form', () => {
  const r = ng(`events {}\nhttp {\n  proxy_pass http://x;\n  server {\n    listen 80;\n    server_nmae a;\n    root /a;\n    root /b;\n    location /y { proxy_pass; }\n    location /y { return 200; }\n    location /z;\n    if ($host = x) { proxy_pass http://z; }\n  }\n}\n`, '1.24.0');
  assert.ok(has(r, 'compat-wrong-context', /proxy_pass/));
  assert.ok(has(r, 'compat-unknown-directive', /server_nmae/));
  assert.ok(r.findings.find((f) => /server_nmae/.test(f.title)).fix.includes('server_name'));
  assert.ok(has(r, 'compat-duplicate', /root/));
  assert.ok(has(r, 'compat-bad-arguments', /too few/));
  assert.ok(has(r, 'compat-duplicate', /Duplicate location/));
  assert.ok(has(r, 'syntax-nginx', /needs a block/));
});

test('NGINX: the same file is valid or invalid depending on the target version', () => {
  const cfg = `events {}\nhttp {\n  server {\n    listen 443 ssl;\n    http2 on;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl on;\n  }\n}\n`;
  const old = ng(cfg, '1.18.0');
  assert.ok(has(old, 'compat-too-new', /http2/), 'http2 directive needs 1.25.1');
  assert.ok(!has(old, 'compat-removed'), 'ssl on still works in 1.18');
  assert.ok(old.findings.some((f) => f.id === 'compat-deprecated' && /"ssl"/.test(f.title)), 'ssl on is deprecated since 1.15.0');
  const mod = ng(cfg, '1.27.0');
  assert.ok(!has(mod, 'compat-too-new'));
  assert.ok(has(mod, 'compat-removed', /"ssl" was removed/));
  assert.ok(has(ng('events {}\nhttp { server { listen 443 quic; } }\n', '1.24.0'), 'compat-too-new', /quic/));
  assert.ok(has(ng('events {}\nhttp { server { listen 443 ssl http2; } }\n', '1.27.0'), 'compat-deprecated', /http2/));
  assert.ok(!has(ng('events {}\nhttp { server { listen 443 ssl http2; } }\n', '1.20.0'), 'compat-deprecated'));
  assert.ok(has(ng('events {}\nhttp { limit_zone one $binary_remote_addr 10m; }\n', '1.24.0'), 'compat-removed', /limit_zone/));
});

test('NGINX: cross-references (zones), proxy_pass URI rules and unknown variables', () => {
  const r = ng(`events {}\nhttp {\n  server {\n    limit_req zone=missing burst=5;\n    proxy_cache nozone;\n    location ~ ^/x/ { proxy_pass http://backend/path/; }\n    location /v { set $a $unknown_thing; return 200 $uri; }\n    location /p { proxy_pass http://$host; }\n  }\n}\n`, '1.24.0');
  assert.ok(has(r, 'compat-undefined-zone', /limit_req/));
  assert.ok(has(r, 'compat-undefined-zone', /proxy_cache/));
  assert.ok(has(r, 'compat-proxy-pass-uri'));
  assert.ok(has(r, 'compat-unknown-variable', /unknown_thing/));
  assert.ok(has(r, 'compat-no-resolver'));
  assert.ok(!has(r, 'compat-unknown-variable', /\$uri|\$host/));
});

test('NGINX: variables introduced in a later version are reported for older targets', () => {
  const cfg = 'events {}\nhttp { log_format m "$request_id $ssl_ech_status"; }\n';
  assert.ok(has(ng(cfg, '1.8.0'), 'compat-too-new', /request_id/));
  assert.ok(!has(ng(cfg, '1.20.0'), 'compat-too-new', /request_id/));
});

test('NGINX: recommendations follow the version (upstream keepalive defaults changed in 1.29.7)', () => {
  const cfg = `events {}\nhttp {\n  upstream u { server 10.0.0.1; keepalive 8; }\n  server { listen 80; location / { proxy_pass http://u; } }\n}\n`;
  assert.ok(ids(ng(cfg, '1.24.0')).includes('rec-nginx-keepalive-http11'));
  assert.ok(!ids(ng(cfg, '1.30.0')).includes('rec-nginx-keepalive-http11'));
});

test('NGINX: add_header in an inner block hides the inherited ones (silent security-header loss)', () => {
  const r = ng(`events {}\nhttp {\n  server {\n    listen 80;\n    add_header X-Frame-Options DENY always;\n    location /a { add_header X-Other 1; }\n    location /b { return 200; }\n  }\n}\n`, '1.24.0');
  assert.equal(r.findings.filter((f) => f.id === 'rec-nginx-inherit').length, 1);
});

test('NGINX: "nginx -V" build flags make missing modules an error', () => {
  const cfg = 'events {}\nhttp { server { listen 80; location / { stub_status; } } }\n';
  assert.ok(!has(ng(cfg, '1.24.0'), 'compat-module-missing'));
  const r = ng(cfg, '1.24.0', { build: 'configure arguments: --with-http_ssl_module --with-http_v2_module' });
  assert.ok(has(r, 'compat-module-missing', /--with-http_stub_status_module/));
  assert.ok(!has(ng(cfg, '1.24.0', { build: 'configure arguments: --with-http_stub_status_module' }), 'compat-module-missing'));
});

test('NGINX: multi-file configs report the file of every finding', () => {
  const files = [
    { name: 'nginx.conf', content: 'events {}\nhttp { include conf.d/*.conf; }\n' },
    { name: 'conf.d/app.conf', content: 'server {\n  listen 80;\n  bogus_directive on;\n}\n' },
  ];
  const r = validateConfig({ product: 'nginx', version: '1.24.0', files });
  const f = r.findings.find((x) => x.id === 'compat-unknown-directive');
  assert.equal(f.file, 'conf.d/app.conf'); assert.equal(f.line, 3);
});

// ------------------------------------------------------------------------------------------------ API
test('API: /validate and /validate/versions, with auto type detection', async () => {
  const t = await startApp({});
  try {
    const v = await get(t.base, '/api/validate/versions');
    assert.equal(v.status, 200); assert.ok(v.json.haproxy.list.length > 10);
    const r = await post(t.base, '/api/validate', { config: 'global\n  nbproc 2\nfrontend f\n  bind :80\n', version: '3.0' });
    assert.equal(r.status, 200);
    assert.equal(r.json.product, 'haproxy');
    assert.ok(r.json.findings.some((f) => f.id === 'compat-removed'));
    const n = await post(t.base, '/api/validate', { type: 'nginx', config: 'events {}\nhttp { server { listen 80; bogus on; } }', version: 'nginx/1.24.0' });
    assert.equal(n.json.product, 'nginx'); assert.equal(n.json.target.version, '1.24.0');
    assert.ok(n.json.findings.some((f) => f.id === 'compat-unknown-directive'));
    assert.equal((await post(t.base, '/api/validate', {})).status, 400);
    assert.equal((await post(t.base, '/api/validate', { type: 'apache', config: 'x' })).status, 400);
  } finally { await t.close(); }
});

test('API: /instances/:id/validate uses the instance config and its detected version', async () => {
  const t = await startApp({ DEMO_MODE: 'true' });
  try {
    for (const p of t.registry.pollers.values()) await p.poll();
    const r = await get(t.base, '/api/instances/demo-haproxy/validate');
    assert.equal(r.status, 200);
    assert.equal(r.json.product, 'haproxy');
    assert.ok(Array.isArray(r.json.findings) && r.json.summary);
    const forced = await get(t.base, '/api/instances/demo-haproxy/validate?version=1.8');
    assert.equal(forced.json.target.branch, '1.8');
    const nx = await get(t.base, '/api/instances/demo-nginx/validate?version=1.18.0');
    assert.equal(nx.json.target.version, '1.18.0');
    assert.equal((await get(t.base, '/api/instances/nope/validate')).status, 404);
  } finally { await t.close(); }
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { improveConfig, detectProduct } = require('../src/improve');
const hap = require('../src/improve/haproxy');
const ngx = require('../src/improve/nginx');
const { startApp, get } = require('./helpers');

const ex = (...p) => fs.readFileSync(path.join(__dirname, '..', 'examples', ...p), 'utf8');
const readDir = (d) => { const out = []; (function w(dir, pre = '') { for (const f of fs.readdirSync(dir)) { const fp = path.join(dir, f); if (fs.statSync(fp).isDirectory()) w(fp, `${pre}${f}/`); else if (/\.(conf|types)$/.test(f)) out.push({ name: pre + f, content: fs.readFileSync(fp, 'utf8') }); } })(d); return out; };
const rules = (r) => r.changes.map((c) => c.rule);
const post = (base, p, body) => fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: await r.json() }));

test('product detection', () => {
  assert.equal(detectProduct(ex('haproxy', 'haproxy.cfg')), 'haproxy');
  assert.equal(detectProduct(ex('nginx', 'nginx.conf')), 'nginx');
  assert.equal(detectProduct('hello world'), null);
});

test('HAProxy: the example improves, the result is stable and never gets worse', () => {
  const r = improveConfig({ config: ex('haproxy', 'haproxy.cfg'), version: '2.8' });
  assert.equal(r.product, 'haproxy'); assert.ok(r.score.after > r.score.before); assert.equal(r.summary.stable, true);
  for (const id of ['hap-tls-options', 'hap-tls-ciphers', 'hap-hsts', 'hap-check', 'hap-timeout-http-request']) assert.ok(rules(r).includes(id), id);
  const out = r.files[0].improved;
  assert.match(out, /ssl-default-bind-options .*no-tls-tickets/); assert.match(out, /Strict-Transport-Security/); assert.match(out, /server cdn-02 .* check inter 2s/);
  assert.equal(improveConfig({ config: out, version: '2.8' }).changes.filter((c) => c.auto && c.on).length, 0); // idempotent
  // the rewrite keeps the structure: same sections in the same order
  const names = (t) => hap.parse(t).sections.map((s) => `${s.type} ${s.name}`);
  assert.deepEqual(names(out), names(ex('haproxy', 'haproxy.cfg')));
});

test('HAProxy: no defaults, legacy keywords and version gates', () => {
  const legacy = `global\n    maxconn 100\ndefaults\n    clitimeout 30s\n    srvtimeout 30s\n    contimeout 5s\n    option forceclose\nfrontend f\n    bind *:80\n    mode http\n    reqadd X-Forwarded-Proto:\\ http\n    block if { path_beg /admin }\n    redirect scheme https if !{ ssl_fc }\n    default_backend b\nbackend b\n    mode http\n    server s1 10.0.0.1:80\n    server s2 10.0.0.2:80\n`;
  const r = improveConfig({ config: legacy, version: '2.8' }); const out = r.files[0].improved;
  assert.match(out, /http-request add-header X-Forwarded-Proto http/); assert.match(out, /http-request deny if \{ path_beg \/admin \}/);
  assert.match(out, /timeout client 30s/); assert.doesNotMatch(out, /clitimeout|reqadd|forceclose|\n\s+block /);
  assert.equal((out.match(/timeout client/g) || []).length, 1); // the legacy timeout is converted, not duplicated
  assert.match(out, /default-server check inter 2s fall 3 rise 2/);
  // no defaults section at all: one is added
  const bare = improveConfig({ config: 'frontend f\n    bind *:80\n    mode http\n    default_backend b\nbackend b\n    mode http\n    server a 1.1.1.1:80 check\n', version: '2.8' });
  assert.match(bare.files[0].improved, /^defaults\n/m); assert.match(bare.files[0].improved, /timeout connect 5s/);
  // old HAProxy: no ssl-min-ver before 1.8
  const tls = 'global\n    log /dev/log local0\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\nfrontend f\n    bind *:443 ssl crt /x.pem\n    default_backend b\nbackend b\n    server a 1.1.1.1:80 check\n';
  assert.match(improveConfig({ config: tls, version: '1.7' }).files[0].improved, /no-sslv3 no-tlsv10 no-tlsv11/);
  assert.match(improveConfig({ config: tls, version: '2.8' }).files[0].improved, /ssl-min-ver TLSv1\.2/);
  assert.doesNotMatch(improveConfig({ config: tls, version: '1.7' }).files[0].improved, /alpn/); // h2 needs 1.9+
});

test('HAProxy: toggles switch a change off and optional ones on; advice is never applied', () => {
  const base = improveConfig({ config: ex('haproxy', 'haproxy.cfg'), version: '2.8' });
  const hsts = base.changes.find((c) => c.rule === 'hap-hsts'); const rl = base.changes.find((c) => c.rule === 'hap-ratelimit'); const adv = base.changes.find((c) => !c.auto);
  assert.equal(hsts.applied, true); assert.equal(rl.applied, false); assert.ok(adv && adv.applied === false);
  const t = improveConfig({ config: ex('haproxy', 'haproxy.cfg'), version: '2.8', toggles: { [hsts.key]: false, [rl.key]: true } });
  assert.doesNotMatch(t.files[0].improved, /Strict-Transport-Security/); assert.match(t.files[0].improved, /http_req_rate/);
  assert.ok(t.score.after <= base.score.after + 20); // the user's choice is respected, the score reflects what is left
});

test('NGINX: the example improves, keeps inheritance right and is stable', () => {
  const files = readDir(path.join(__dirname, '..', 'examples', 'nginx'));
  const r = improveConfig({ product: 'nginx', files, version: '1.24.0' });
  assert.ok(r.score.after > r.score.before); assert.equal(r.summary.stable, true);
  const app = r.files.find((f) => f.name === 'conf.d/app.conf').improved; const main = r.files.find((f) => f.name === 'nginx.conf').improved;
  assert.match(main, /server_tokens off;/); assert.match(main, /ssl_protocols TLSv1\.2 TLSv1\.3;/); assert.match(main, /server \{\s+listen 80 default_server;/);
  assert.match(app, /add_header Strict-Transport-Security "max-age=31536000" always;/);
  // a location with its own proxy_set_header gets the complete set (it would not inherit the server's)
  const loc = app.slice(app.indexOf('location /api/'), app.indexOf('location /grafana/'));
  for (const h of ['Host', 'X-Real-IP', 'X-Forwarded-For', 'X-Forwarded-Proto']) assert.match(loc, new RegExp(`proxy_set_header ${h} `));
  assert.match(loc, /Authorization "Bearer s3cr3t-token-value"/); // the existing header is untouched
  // version gate: HTTP/2 syntax follows the version
  assert.match(app, /listen 443 ssl http2;/);
  assert.match(improveConfig({ product: 'nginx', files, version: '1.27.0' }).files.find((f) => f.name === 'conf.d/app.conf').improved, /http2 on;/);
  const old = improveConfig({ product: 'nginx', files: [{ name: 'a.conf', content: 'http {\n    server {\n        listen 443 ssl;\n        server_name a.example;\n        ssl_certificate a.pem;\n        ssl_certificate_key a.key;\n    }\n}\n' }], version: '1.18.0' });
  assert.match(old.files[0].improved, /listen 443 ssl http2;/); assert.doesNotMatch(old.files[0].improved, /http2 on;/);
  assert.doesNotMatch(old.files[0].improved, /ssl_reject_handshake/); // not available before 1.19.4
});

test('NGINX: legacy and risky constructs', () => {
  const cfg = `events {}\nhttp {\n    server {\n        listen 443;\n        ssl on;\n        server_name a.example;\n        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n        location /status { stub_status; }\n        location /d/ { autoindex on; root /srv; }\n        location /lua { content_by_lua_block { ngx.say("hi { }") } }\n    }\n    server {\n        listen 80;\n        server_name a.example;\n        rewrite ^ https://$host$request_uri? permanent;\n    }\n}\n`;
  const r = improveConfig({ product: 'nginx', config: cfg, version: '1.24.0' }); const out = r.files[0].improved;
  assert.doesNotMatch(out, /ssl on;/); assert.match(out, /listen 443 ssl( http2)?;/); assert.doesNotMatch(out, /TLSv1 TLSv1\.1/);
  assert.match(out, /location \/status \{\s+allow 127\.0\.0\.1;\s+deny all;\s+stub_status;/); assert.doesNotMatch(out, /autoindex on/);
  assert.match(out, /return 301 https:\/\/\$host\$request_uri;/); assert.match(out, /content_by_lua_block \{\s+ngx\.say\("hi \{ \}"\)/); // opaque code survives
  assert.equal(improveConfig({ product: 'nginx', config: out, version: '1.24.0' }).changes.filter((c) => c.auto && c.on).length, 0);
});

test('the printers round-trip and keep comments', () => {
  const h = '# top\nglobal\n    # why\n    maxconn 10 # inline\n\nfrontend f\n    bind *:80\n';
  assert.equal(hap.print(hap.parse(h)), h);
  const n = '# top\nhttp {\n    # c\n    server {\n        listen 80; # trail\n    }\n}\n';
  assert.equal(ngx.print(ngx.parse(n)), n);
});

test('errors: empty, too big, unknown product', () => {
  assert.throws(() => improveConfig({ config: '  ' }), /Paste or upload/);
  assert.throws(() => improveConfig({ config: 'just some words' }), /Could not tell/);
  assert.throws(() => improveConfig({ config: 'x'.repeat(2.5 * 1048576), product: 'nginx' }), /limit/);
});

test('API: /api/improve and the instance route', async () => {
  const os = require('os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-imp-')); fs.writeFileSync(path.join(dir, 'i.json'), '[]');
  const t = await startApp({ INSTANCES_FILE: path.join(dir, 'i.json'), DATA_DIR: dir, ALLOW_UI_INSTANCES: 'true' });
  const A = { Cookie: `gl_sid=${'f'.repeat(64)}`, 'Content-Type': 'application/json' };
  try {
    const ok = await post(t.base, '/api/improve', { type: 'haproxy', config: ex('haproxy', 'haproxy.cfg'), version: '2.8' });
    assert.equal(ok.status, 200); assert.ok(ok.json.changes.length > 5); assert.equal(typeof ok.json.score.after, 'number');
    assert.equal((await post(t.base, '/api/improve', { config: '' })).status, 400);
    assert.equal((await post(t.base, '/api/improve', { config: 'nonsense nonsense' })).status, 422);
    const made = await fetch(`${t.base}/api/instances`, { method: 'POST', headers: A, body: JSON.stringify({ type: 'haproxy', name: 'cfg-only', configFiles: [{ name: 'haproxy.cfg', content: ex('haproxy', 'haproxy.cfg') }] }) });
    const id = (await made.json()).id; assert.ok(id);
    const inst = await fetch(`${t.base}/api/instances/${id}/improve`, { method: 'POST', headers: A, body: '{}' }).then(async (r) => ({ status: r.status, json: await r.json() }));
    assert.equal(inst.status, 200, JSON.stringify(inst.json).slice(0, 200)); assert.equal(inst.json.product, 'haproxy'); assert.ok(inst.json.changes.length > 5);
  } finally { await t.close(); }
});

test('robust: garbage never crashes the engine, and big configs stay fast', () => {
  let seed = 7; const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const chars = '{}; #"\'\n\t\\$abc_/:=.0123456789frontendbackendserver location listen';
  for (let k = 0; k < 400; k++) {
    let s = ''; const L = Math.floor(rnd() * 120); for (let i = 0; i < L; i++) s += chars[Math.floor(rnd() * chars.length)];
    for (const product of ['haproxy', 'nginx']) { try { improveConfig({ config: `${s}\n`, product }); } catch (e) { assert.ok(e.status, `unexpected crash for ${product}: ${JSON.stringify(s)}: ${e.message}`); } }
  }
  let h = 'global\n    log /dev/log local0\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\n';
  for (let i = 0; i < 600; i++) h += `frontend f${i}\n    bind :${1000 + i}\n    default_backend b${i}\nbackend b${i}\n    server s1 10.0.0.1:80\n    server s2 10.0.0.2:80\n`;
  const t = Date.now(); const r = improveConfig({ config: h, version: '2.8' });
  assert.ok(Date.now() - t < 4000, 'a 3,600 line config must finish in a few seconds'); assert.equal(r.summary.stable, true);
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadNginxConfig, parseNginxFiles, parseNginxText, tokenize, redactNginx } = require('../src/nginxConfig');
const { auditNginx } = require('../src/nginxAudit');
const { parseStubStatus, probeUpstreams } = require('../src/nginxStats');

const EX = path.join(__dirname, '..', 'examples', 'nginx');
const ids = (f) => new Set(f.map((x) => x.id));

test('tokenizer: comments, quotes, braces, ${var}', () => {
  const t = tokenize('a "b c" ${x}; # c\n{ }').map((x) => x.v || x.t);
  assert.deepEqual(t, ['a', 'b c', '${x}', ';', '{', '}']);
});

test('example config: includes resolved, topology model built', () => {
  const r = loadNginxConfig(path.join(EX, 'nginx.conf'));
  assert.deepEqual(r.files.map((f) => f.name).sort(), ['conf.d/app.conf', 'mime.types', 'nginx.conf']);
  const fe = r.sections.find((s) => s.type === 'frontend' && s.name === 'app.example.com:443');
  assert.deepEqual(fe.routes.map((x) => x.target), ['web_pool', 'api_pool', '10.0.5.50:3000', 'realtime_pool:80']);
  assert.ok(fe.binds.some((b) => b.ssl));
  assert.equal(r.sections.find((s) => s.name === 'web_pool').balance, 'least_conn');
  assert.equal(r.sections.find((s) => s.name === 'web_pool').servers.find((s) => s.backup).address, '10.0.1.12:8080');
  const stream = r.sections.find((s) => s.type === 'frontend' && s.isStream);
  assert.equal(stream.routes[0].target, 'mqtt_pool');
  assert.equal(r.sections.find((s) => s.name === 'mqtt_pool').mode, 'tcp');
});

test('example config: audit finds the planted problems and no false positives', () => {
  const r = loadNginxConfig(path.join(EX, 'nginx.conf'));
  const f = auditNginx(r.sections, { notes: r.notes });
  for (const id of ['nginx-undefined-upstream', 'nginx-alias-traversal', 'nginx-weak-tls', 'nginx-inline-secret', 'nginx-orphan-upstream', 'nginx-autoindex', 'nginx-single-server']) {
    assert.ok(ids(f).has(id), `missing ${id}`);
  }
  assert.ok(!ids(f).has('nginx-stub-status-open'), 'stub_status is protected by allow/deny');
  assert.ok(!ids(f).has('nginx-no-http-redirect'), 'port 80 block redirects');
  assert.ok(f.every((x) => x.file && x.line));
});

test('include sandbox: paths outside the config root are skipped, not read', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nx-'));
  const secret = path.join(dir, 'outside-secret.conf');
  fs.mkdirSync(path.join(dir, 'root'));
  fs.writeFileSync(secret, 'server { listen 9999; server_name leaked; }');
  fs.writeFileSync(path.join(dir, 'root', 'nginx.conf'), `http { include ../outside-secret.conf; include ${secret}; include /etc/passwd; }`);
  const r = loadNginxConfig(path.join(dir, 'root', 'nginx.conf'));
  assert.equal(r.sections.filter((s) => s.type === 'frontend').length, 0);
  assert.equal(r.files.length, 1);
  assert.ok(r.notes.some((n) => /outside the config root/.test(n.msg)));
});

test('include loops do not hang', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nx-'));
  fs.writeFileSync(path.join(dir, 'nginx.conf'), 'http { include a.conf; }');
  fs.writeFileSync(path.join(dir, 'a.conf'), 'include nginx.conf;');
  const r = loadNginxConfig(path.join(dir, 'nginx.conf'));
  assert.ok(r.notes.some((n) => /loop/.test(n.msg)));
});

test('uploaded file set: folder prefix stripped, includes resolved virtually', () => {
  const rd = (p) => fs.readFileSync(path.join(EX, p), 'utf8');
  const r = parseNginxFiles([{ name: 'etc/nginx.conf', content: rd('nginx.conf') }, { name: 'etc/conf.d/app.conf', content: rd('conf.d/app.conf') }]);
  assert.equal(r.mainFile, 'nginx.conf');
  assert.ok(r.sections.some((s) => s.type === 'frontend' && s.name === 'app.example.com:443'));
  assert.ok(!r.notes.some((n) => /not found/.test(n.msg)));
});

test('uploaded set missing its includes explains what to upload; fragments are noted', () => {
  const rd = (p) => fs.readFileSync(path.join(EX, p), 'utf8');
  const missing = parseNginxFiles([{ name: 'nginx.conf', content: rd('nginx.conf') }]);
  assert.ok(missing.notes.some((n) => /matched no files/.test(n.msg)));
  const frag = parseNginxFiles([{ name: 'app.conf', content: rd('conf.d/app.conf') }]);
  assert.ok(frag.sections.some((s) => s.type === 'frontend'));
  assert.ok(frag.notes.some((n) => /fragment/.test(n.msg)));
});

test('secrets are redacted in NGINX output', () => {
  const out = redactNginx('proxy_set_header Authorization "Bearer abc123";\nset $api_key "k-999";\nproxy_pass http://u:pw@host/;\nproxy_set_header Host $host;');
  assert.ok(!out.includes('abc123')); assert.ok(!out.includes('k-999')); assert.ok(!out.includes(':pw@'));
  assert.ok(out.includes('Host $host'));
});

test('stub_status parsing and probe rows', async () => {
  const s = parseStubStatus('Active connections: 5 \nserver accepts handled requests\n 10 10 99 \nReading: 1 Writing: 2 Waiting: 2 \n');
  assert.deepEqual([s.activeConns, s.requestsTotal, s.waiting], [5, 99, 2]);
  assert.equal(parseStubStatus('nope'), null);
  const sections = parseNginxText('http { upstream u { server 127.0.0.1:1; } server { listen 80; location / { proxy_pass http://u; } } }').sections;
  const rows = await probeUpstreams({ probeTimeoutMs: 300 }, sections);
  const srv = rows.find((r) => r.kind === 'server');
  assert.equal(srv.status, 'DOWN');
  assert.equal(rows.find((r) => r.kind === 'backend').status, 'DOWN');
});

test('stub_status: `allow all` is not a restriction; allow+deny or auth_basic is', () => {
  const flagged = (loc) => auditNginx(parseNginxText(`http { server { listen 80; location /s { stub_status; ${loc} } } }`).sections)
    .some((f) => f.id === 'nginx-stub-status-open');
  assert.equal(flagged(''), true);
  assert.equal(flagged('allow all;'), true);
  assert.equal(flagged('allow 10.0.0.0/8; deny all;'), false);
  assert.equal(flagged('allow 127.0.0.1;'), false);
  assert.equal(flagged('auth_basic "x"; auth_basic_user_file /etc/h;'), false);
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseConfig, redactConfig, conditionAcls } = require('../src/haproxyConfig');
const { auditConfig } = require('../src/audit');
const { parseStatsCsv, parseInfo, statusClass, splitCsvLine } = require('../src/statsParser');

const CFG = `
global
    maxconn 1000
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    default-server check

frontend web
    bind *:80
    bind *:443 ssl crt /etc/ssl/x.pem
    acl is_api path_beg /api   # trailing comment
    acl unused_acl path_beg /zzz
    use_backend api if is_api
    use_backend ghost if !is_api is_missing
    #use_backend legacy if { path_beg /old }
    # this is just prose: server restarts nightly
    default_backend app

backend app
    balance leastconn
    server a1 10.0.0.1:80 check weight 3
    server a2 10.0.0.2:80 backup
    #server a3 10.0.0.3:80 check

backend api
    server only 10.0.1.1:8080 disabled

backend lonely
    server l1 10.0.2.1:80

userlist ops
    user admin insecure-password hunter2
    user bob password plaintextnothash

listen stats
    bind 0.0.0.0:8404
    stats enable
    stats auth admin:admin
`;

test('parses sections with line numbers and effective defaults', () => {
  const s = parseConfig(CFG);
  const web = s.find((x) => x.name === 'web');
  assert.equal(web.type, 'frontend');
  assert.ok(web.line > 1 && web.endLine > web.line);
  assert.equal(web.effective.timeouts.client, '30s');
  assert.equal(s.find((x) => x.name === 'app').balance, 'leastconn');
});

test('routes: active, commented, default and prose-comments ignored', () => {
  const web = parseConfig(CFG).find((x) => x.name === 'web');
  const targets = web.routes.map((r) => `${r.target}${r.commented ? '(c)' : ''}`);
  assert.deepEqual(targets, ['api', 'ghost', 'legacy(c)', 'app']);
  assert.equal(web.routes.find((r) => r.target === 'app').type, 'default');
  assert.deepEqual(web.routes.find((r) => r.target === 'ghost').aclRefs, ['is_api', 'is_missing']);
});

test('servers: options, backup, disabled, commented, default-server check inherited', () => {
  const app = parseConfig(CFG).find((x) => x.name === 'app');
  const a1 = app.servers.find((x) => x.name === 'a1');
  assert.equal(a1.weight, 3); assert.equal(a1.check, true);
  assert.equal(app.servers.find((x) => x.name === 'a2').backup, true);
  assert.equal(app.servers.find((x) => x.name === 'a3').commented, true);
  assert.equal(parseConfig(CFG).find((x) => x.name === 'api').servers[0].disabled, true);
});

test('inline comments are stripped; "# server restarts" prose is not a server', () => {
  const web = parseConfig(CFG).find((x) => x.name === 'web');
  assert.equal(web.acls.find((a) => a.name === 'is_api').expression, 'path_beg /api');
  const s = parseConfig('backend b\n  # server restarts nightly\n  server x 1.2.3.4:80\n');
  assert.equal(s[0].servers.length, 1);
});

test('commented-out sections do not leak their contents into the previous section', () => {
  const s = parseConfig('listen stats\n bind :8404\n\n#frontend old_fe\n#    bind :8888\n#    use_backend old_be if x\n#    acl x path_beg /x\n\n# backend notes are prose, not a section\nbackend real\n server a 1.1.1.1:80\n');
  assert.deepEqual(s.map((x) => x.name), ['stats', 'real']);
  assert.equal(s[0].routes.length, 0);
  assert.equal(s[0].acls.length, 0);
});

test('conditionAcls handles negation, anonymous acls and operators', () => {
  assert.deepEqual(conditionAcls('if !a b || c'), ['a', 'b', 'c']);
  assert.deepEqual(conditionAcls('if { path_end .css } is_x'), ['is_x']);
});

test('audit flags the planted problems with accurate lines', () => {
  const f = auditConfig(parseConfig(CFG));
  const ids = new Set(f.map((x) => x.id));
  for (const id of ['undefined-backend', 'undefined-acl', 'unused-acl', 'orphan-backend', 'single-server',
    'plaintext-userlist-password', 'userlist-password-not-hashed', 'weak-stats-credential', 'stats-exposed', 'tls-min-version']) {
    assert.ok(ids.has(id), `expected finding ${id}; got ${[...ids]}`);
  }
  const undef = f.find((x) => x.id === 'undefined-backend');
  assert.equal(CFG.split('\n')[undef.line - 1].trim().startsWith('use_backend ghost'), true);
  // `default-server check` means backend app servers are NOT flagged as missing checks
  assert.ok(!f.some((x) => x.id === 'server-no-check' && x.section === 'app'));
  assert.ok(f.every((x) => x.rule && x.severity && x.category));
});

test('audit: servers without checks are flagged unless default-server provides one', () => {
  const noDefault = parseConfig('backend b\n timeout server 1s\n timeout connect 1s\n server s1 1.1.1.1:80\n server s2 1.1.1.2:80 check\n');
  const flagged = auditConfig(noDefault).filter((x) => x.id === 'server-no-check');
  assert.equal(flagged.length, 1);
  assert.match(flagged[0].title, /s1/);
});

test('audit: clean config produces no errors', () => {
  const clean = `defaults\n mode http\n timeout connect 1s\n timeout client 1s\n timeout server 1s\nfrontend f\n bind :80\n default_backend b\nbackend b\n server s1 1.1.1.1:80 check\n server s2 1.1.1.2:80 check\n`;
  assert.equal(auditConfig(parseConfig(clean)).filter((x) => x.severity === 'error').length, 0);
});

test('audit: drift between file and running process', () => {
  const sections = parseConfig('frontend f\n bind :80\n default_backend b\nbackend b\n server s1 1.1.1.1:80 check\n server s2 1.1.1.2:80 check\n');
  const rows = parseStatsCsv('# pxname,svname,status,type\nf,FRONTEND,OPEN,0\nb,s1,UP,2\nb,sX,UP,2\nb,BACKEND,UP,1\n');
  const ids = auditConfig(sections, { runtime: { rows } }).map((x) => x.id);
  assert.ok(ids.includes('drift-server-not-running'));
  assert.ok(ids.includes('drift-server-unknown'));
});

test('redaction removes secrets but keeps structure and line count', () => {
  const out = redactConfig(CFG);
  assert.ok(!out.includes('hunter2')); assert.ok(!out.includes('admin:admin')); assert.ok(!out.includes('plaintextnothash'));
  assert.ok(out.includes('stats auth admin:***'));
  assert.equal(out.split('\n').length, CFG.split('\n').length);
});

test('stats CSV: quoted fields, typed rows, status classes', () => {
  assert.deepEqual(splitCsvLine('a,"b,c","d ""q"""'), ['a', 'b,c', 'd "q"']);
  const rows = parseStatsCsv('# pxname,svname,scur,stot,status,type,last_chk\nweb,FRONTEND,3,100,OPEN,0,\napp,s1,1,50,UP 1/3,2,"Layer7 wrong status, code 503"\n');
  assert.equal(rows[0].kind, 'frontend'); assert.equal(rows[0].stot, 100);
  assert.equal(rows[1].kind, 'server'); assert.equal(rows[1].last_chk, 'Layer7 wrong status, code 503');
  assert.deepEqual(['UP', 'UP 1/3', 'DOWN', 'MAINT (via a/b)', 'NOLB', 'no check', 'OPEN', 'weird'].map(statusClass),
    ['up', 'degraded', 'down', 'maint', 'drain', 'nocheck', 'up', 'unknown']);
  assert.deepEqual(parseStatsCsv('garbage'), []);
  assert.equal(parseInfo('Version: 2.8.5\nUptime_sec: 42\nIdle_pct: 97\n').uptimeSec, 42);
});

test('stats HTML page (real HAProxy 2.9 markup) yields version, pid, uptime, idle', () => {
  const { htmlToInfo } = require('../src/transport');
  const html = '<h1><a href="http://www.haproxy.org/">HAProxy version 2.9.15-e872a3f, released 2025/03/21</a></h1><h2>Statistics Report for pid 8</h2>'
    + '<h3>&gt; General process information</h3><table border=0><tr><td><p><b>pid = </b> 8 (process #1, nbproc = 1, nbthread = 12)<br>'
    + '<b>uptime = </b> 3d 15h53m12s; warnings = 2<br><b>maxconn = </b> 524256; <b>reached = </b> 0<br>'
    + 'current conns = 2; current pipes = 0/0; conn rate = 1/sec; bit rate = 129.973 kbps<br>Running tasks: 0/44 (0 niced); idle = 100 %<br>';
  const info = parseInfo(htmlToInfo(html));
  assert.equal(info.version, '2.9.15-e872a3f'); assert.equal(info.pid, '8');
  assert.equal(info.uptimeSec, 3 * 86400 + 15 * 3600 + 53 * 60 + 12);
  assert.equal(info.idlePct, 100); assert.equal(info.maxconn, 524256);
});

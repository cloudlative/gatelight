'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const apache = require('../src/products/apache');
const { parseBalancerManager, parseStatusAuto, memberStatus, sizeBytes } = require('../src/products/apache/live');
const { statusClass } = require('../src/statsParser');
const { startStub } = require('./helpers');
const { sniff: sniffHaproxy } = require('../src/logs/haproxy');

// mod_status ?auto output (modules/generators/mod_status.c, short_report)
const STATUS_AUTO = `localhost
ServerVersion: Apache/2.4.62 (Debian)
ServerMPM: event
Server Built: 2024-07-18T19:21:45
CurrentTime: Monday, 10-Nov-2026 08:15:02 UTC
RestartTime: Monday, 10-Nov-2026 06:00:00 UTC
ParentServerConfigGeneration: 1
ParentServerMPMGeneration: 0
ServerUptimeSeconds: 8102
ServerUptime: 2 hours 15 minutes 2 seconds
Load1: 0.12
Load5: 0.10
Load15: 0.05
Total Accesses: 48211
Total kBytes: 102400
Total Duration: 1203
CPUUser: 12.5
CPUSystem: 3.2
CPUChildrenUser: 0
CPUChildrenSystem: 0
CPULoad: .193
Uptime: 8102
ReqPerSec: 5.95054
BytesPerSec: 12941.9
BytesPerReq: 2174.94
DurationPerReq: .0249528
BusyWorkers: 3
GracefulWorkers: 0
IdleWorkers: 72
Processes: 3
Stopping: 0
ConnsTotal: 7
ConnsAsyncWriting: 0
ConnsAsyncKeepAlive: 4
ConnsAsyncClosing: 0
Scoreboard: __W_K___R____________________________________________________________..........
`;

// balancer-manager page (modules/proxy/mod_proxy_balancer.c balancer_display_page, HTML branch, with mod_proxy_hcheck)
const row = (bal, url, route, factor, status, elected, busy, load, to, from) => `<tr>\n<td><a href="/balancer-manager?b=${bal}&amp;w=${encodeURIComponent(url)}&amp;nonce=0f4bd2c5-1">${url}</a></td><td>${route}</td><td></td><td>${factor}</td><td>0</td><td>${status}</td><td>${elected}</td><td>${busy}</td><td>${load}</td><td>${to}</td><td>${from}</td><td>GET</td><td>10000ms</td><td>2 (0)</td><td>3 (0)</td><td>/healthz</td><td></td></tr>\n`;
const head = '\n\n<table><tr><th>Worker URL</th><th>Route</th><th>RouteRedir</th><th>Factor</th><th>Set</th><th>Status</th><th>Elected</th><th>Busy</th><th>Load</th><th>To</th><th>From</th><th>HC Method</th><th>HC Interval</th><th>Passes</th><th>Fails</th><th>HC uri</th><th>HC Expr</th></tr>\n';
const balTable = (name, sticky, method) => `<hr />\n<h3>LoadBalancer Status for <a href="/balancer-manager?b=${name}&amp;nonce=0f4bd2c5-1">balancer://${name}</a> [p0f4bd2c5_${name}]</h3>\n\n\n<table><tr><th>MaxMembers</th><th>StickySession</th><th>DisableFailover</th><th>Timeout</th><th>FailoverAttempts</th><th>Method</th><th>Path</th><th>Active</th></tr>\n<tr><td>3 [3 Used]</td>\n<td>${sticky}</td><td>Off</td>\n<td>0</td><td>2</td>\n<td>${method}</td>\n<td>/</td>\n<td>Yes</td>\n</tr>\n</table>\n<br />`;
const MANAGER = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">\n<html><head><title>Balancer Manager</title>\n<style type='text/css'>\ntable {\n border-width: 1px;\n}\n</style>\n</head>\n<body><h1>Load Balancer Manager for status.internal</h1>\n\n<dl><dt>Server Version: Apache/2.4.62 (Debian) OpenSSL/3.0.13</dt>\n<dt>Server Built: 2024-07-18T19:21:45</dt>\n<dt>Balancer changes will NOT persist on restart.</dt>\n<dt>Balancers are inherited from main server.</dt>\n<dt>ProxyPass settings are inherited from main server.</dt>\n</dl>\n`
  + `${balTable('web', 'ROUTEID', 'bybusyness')}${head}${row('web', 'http://10.0.1.11:8080', 'web1', '2.00', 'Init Ok ', 1200, 2, 0, '1.2M', ' 48M')}${row('web', 'http://10.0.1.12:8080', 'web2', '1.00', 'Init HcFl ', 300, 0, 0, '210K', '9.1M')}${row('web', 'http://10.0.1.13:8080', 'web3', '1.00', 'Init Stby Ok ', 0, 0, 0, '  0 ', '  0 ')}</table>\n`
  + `${balTable('api', ' (None) ', 'byrequests')}${head}${row('api', 'http://10.0.2.21:9000', '', '1.00', 'Init Dis ', 40, 0, 0, ' 12K', '200K')}${row('api', 'http://10.0.2.22:9000', '', '1.00', 'Init Drn Ok ', 41, 1, 0, ' 13K', '210K')}${row('api', 'http://10.0.2.23:9000', '', '1.00', 'Init Err ', 2, 0, 0, '  0 ', '  0 ')}</table>\n`
  + '<hr />\n</body></html>';

test('parsers: server-status?auto and balancer-manager HTML', () => {
  const st = parseStatusAuto(STATUS_AUTO);
  assert.equal(st.version, '2.4.62'); assert.equal(st.requestsTotal, 48211); assert.equal(st.busyWorkers, 3); assert.equal(st.idleWorkers, 72);
  assert.equal(st.uptimeSec, 8102); assert.equal(st.reqPerSec, 5.95054); assert.equal(st.bytesTotal, 102400 * 1024); assert.equal(st.mpm, 'event'); assert.equal(st.scoreboard.writing, 1);
  assert.equal(parseStatusAuto('<html>not it</html>'), null);
  const b = parseBalancerManager(MANAGER);
  assert.deepEqual(b.map((x) => [x.name, x.sticky, x.method, x.members.length]), [['web', 'ROUTEID', 'bybusyness', 3], ['api', null, 'byrequests', 3]]);
  assert.equal(b[0].members[0].name, '10.0.1.11:8080'); assert.equal(b[0].members[0].to, Math.round(1.2 * 1024 * 1024)); assert.equal(b[0].members[0].hcUri, '/healthz');
  assert.equal(sizeBytes('  0 '), 0); assert.equal(sizeBytes('210K'), 215040);
  assert.deepEqual(['Init Ok ', 'Init Err ', 'Init Dis ', 'Init Stby Ok ', 'Init Drn Ok ', 'Init HcFl ', 'Init Stop '].map((s) => memberStatus(s).status), ['UP', 'DOWN', 'MAINT', 'UP', 'DRAIN', 'DOWN', 'MAINT']);
});

test('live.collect against a stub httpd (GET only) — rows join the parsed config', async () => {
  const stub = await startStub((req, res) => {
    if (req.url === '/server-status?auto') { res.writeHead(200, { 'Content-Type': 'text/plain; charset=ISO-8859-1', Server: 'Apache/2.4.62 (Debian)' }); res.end(STATUS_AUTO); return; }
    if (req.url === '/balancer-manager') { res.writeHead(200, { 'Content-Type': 'text/html; charset=ISO-8859-1' }); res.end(MANAGER); return; }
    res.writeHead(404); res.end();
  });
  try {
    const inst = { statsUrl: `${stub.url}/server-status`, balancerUrl: `${stub.url}/balancer-manager`, timeoutMs: 2000 };
    assert.equal(apache.live.hasSource(inst), true); assert.deepEqual(apache.live.sources(inst), ['server-status', 'balancer-manager']);
    assert.equal(apache.live.hasSource({}), false);
    const ex = path.join(__dirname, '..', 'examples', 'apache');
    const parsed = apache.loadPath(path.join(ex, 'apache2.conf'), ex);
    const { rows, info } = await apache.live.collect(inst, null, { sections: parsed.sections });
    assert.ok(stub.hits.every((h) => h.method === 'GET'));
    assert.equal(info.version, '2.4.62'); assert.equal(info.requestsTotal, 48211); assert.equal(info.balancers, 2);
    const r = (p, n) => rows.find((x) => x.proxy === p && x.name === n);
    assert.equal(r('web', '10.0.1.11:8080').status, 'UP'); assert.equal(r('web', '10.0.1.11:8080').stot, 1200); assert.equal(r('web', '10.0.1.11:8080').scur, 2); assert.equal(r('web', '10.0.1.11:8080').weight, 2);
    assert.equal(r('web', '10.0.1.12:8080').status, 'DOWN'); assert.equal(r('web', '10.0.1.12:8080').check_status, 'health check failed');
    assert.equal(r('web', '10.0.1.13:8080').backup, true);
    assert.equal(r('api', '10.0.2.21:9000').status, 'MAINT'); assert.equal(r('api', '10.0.2.22:9000').status, 'DRAIN'); assert.equal(r('api', '10.0.2.23:9000').status, 'DOWN');
    const webBe = r('web', 'BACKEND'); assert.equal(webBe.kind, 'backend'); assert.equal(webBe.status, 'UP'); assert.equal(webBe.stot, 1500);
    // names match the parsed configuration so the topology can join them
    const cfg = new Set(parsed.sections.filter((s) => s.type === 'backend').flatMap((s) => s.servers.map((x) => `${s.name}/${x.name}`)));
    for (const x of rows.filter((y) => y.kind === 'server' && y.proxy === 'web')) assert.ok(cfg.has(`${x.proxy}/${x.name}`), x.name);
    // statusClass understands every status we emit
    assert.deepEqual(['10.0.1.11:8080', '10.0.1.12:8080'].map((n) => statusClass(r('web', n).status)), ['up', 'down']);
    assert.deepEqual(['10.0.2.21:9000', '10.0.2.22:9000'].map((n) => statusClass(r('api', n).status)), ['maint', 'drain']);
    // drift: api member 10.0.2.23 is only live
    assert.ok(apache.audit(parsed.sections, { rows }).some((f) => f.id === 'apache-live-drift' && /10\.0\.2\.23/.test(f.title)));
    // the poller passes its config cache as the second argument
    const viaCache = await apache.live.collect(inst, { sections: parsed.sections }, { demo: null });
    assert.ok(viaCache.rows.some((x) => x.proxy === 'web' && x.name === '10.0.1.11:8080'));
    // one source failing still returns the other
    const half = await apache.live.collect({ statsUrl: `${stub.url}/server-status`, balancerUrl: `${stub.url}/nope`, timeoutMs: 2000 }, null, {});
    assert.equal(half.rows.length, 0); assert.equal(half.info.busyWorkers, 3); assert.ok(half.warnings.some((w) => /balancer-manager: HTTP 404/.test(w)));
    await assert.rejects(apache.live.collect({ statsUrl: `${stub.url}/nope`, timeoutMs: 2000 }, null, {}), /server-status/);
  } finally { await stub.close(); }
});

const LOGS = [
  // vhost_combined (Debian other_vhosts_access.log) + %D
  'shop.example.com:443 203.0.113.9 - - [10/Nov/2026:08:15:02 +0000] "GET /api/items?id=1 HTTP/2.0" 200 1532 "-" "curl/8.0" 12345',
  'shop.example.com:443 203.0.113.10 - - [10/Nov/2026:08:15:03 +0000] "GET /api/items HTTP/2.0" 502 312 "-" "curl/8.0" 30001000 "http://10.0.1.11:8080"',
  // combined
  '10.0.0.1 - alice [10/Nov/2026:08:15:03 +0100] "POST /login HTTP/1.1" 302 - "https://shop.example.com/" "Mozilla/5.0"',
  // common
  '10.0.0.2 - - [10/Nov/2026:08:15:04 +0000] "GET / HTTP/1.1" 200 120',
  // error log (2.4 format)
  '[Mon Nov 10 08:15:05.123456 2026] [proxy:error] [pid 123:tid 456] (111)Connection refused: AH00957: http: attempt to connect to 10.0.1.11:8080 (10.0.1.11:8080) failed',
  '[Mon Nov 10 08:15:06.123456 2026] [proxy_http:error] [pid 123:tid 456] [client 1.2.3.4:5678] AH01114: HTTP: failed to make connection to backend: 10.0.1.12, referer: https://x/',
  '[Mon Nov 10 08:15:07.000001 2026] [mpm_event:notice] [pid 100:tid 101] AH00489: Apache/2.4.62 (Debian) configured -- resuming normal operations',
  '{"time":"2026-11-10T08:15:08+0000","remote_addr":"1.2.3.4","vhost":"shop.example.com","request":"GET /x HTTP/1.1","status":200,"bytes":10,"duration_us":2500,"balancer":"balancer://web","worker":"http://10.0.1.11:8080"}',
];

test('logs: combined, %D, vhost_combined, JSON and error-log lines are aggregated', () => {
  const a = apache.logs.createAggregator();
  assert.deepEqual(LOGS.map((l) => a.push(l)), LOGS.map(() => true));
  const r = a.finish({ source: 'test' });
  assert.equal(r.product, 'apache');
  assert.equal(r.stats.http, 5); assert.equal(r.stats.events, 3); assert.equal(r.stats.unparsed, 0);
  const fes = new Set(r.keys.map((k) => k.fe));
  assert.ok(fes.has('shop.example.com') && fes.has('(any host)'));
  const k502 = r.keys.findIndex((k) => k.cls === '5xx');
  assert.equal(r.keys[k502].srv, '10.0.1.11:8080', 'backend URL logged after the user agent');
  const i = r.facts.k.indexOf(k502);
  assert.equal(r.facts.tt[i], 30001, '%D microseconds -> ms');
  assert.ok(r.keys.some((k) => k.be === 'web' && k.srv === '10.0.1.11:8080'), 'JSON with balancer / worker');
  assert.ok(r.events.some((e) => e[1] === 'down' && /AH00957/.test(e[2])));
  assert.ok(r.events.some((e) => e[1] === 'info' && /resuming normal operations/.test(e[2])));
  // %T in seconds when told so
  const s = apache.logs.createAggregator({ timeUnit: 's' });
  s.push('10.0.0.2 - - [10/Nov/2026:08:15:04 +0000] "GET / HTTP/1.1" 200 120 "-" "x" 2');
  assert.equal(s.finish().facts.tt[0], 2000);
});

test('logs: sniff ratio high on Apache logs, low on HAProxy logs (and vice versa)', () => {
  const hap = ['Nov 10 08:15:02 lb haproxy[123]: 10.0.0.1:5678 [10/Nov/2026:08:15:02.123] fe be/srv 0/0/1/2/3 200 512 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"',
    'Nov 10 08:15:03 lb haproxy[123]: 10.0.0.1:5679 [10/Nov/2026:08:15:03.123] fe be/srv 0/0/1/2/3 404 512 - - ---- 1/1/0/0/0 0/0 "GET /x HTTP/1.1"'];
  assert.ok(apache.logs.sniff(LOGS).ratio > 0.9);
  assert.ok(apache.logs.sniff(hap).ratio < 0.1);
  assert.ok(sniffHaproxy(LOGS).ratio < 0.1);
});

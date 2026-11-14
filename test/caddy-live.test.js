'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startStub } = require('./helpers');
const caddy = require('../src/products/caddy');
const { parseMetrics } = require('../src/products/caddy/live');

const EX = path.join(__dirname, '..', 'examples', 'caddy');
const sections = () => caddy.parseFiles([
  { name: 'Caddyfile', content: fs.readFileSync(path.join(EX, 'Caddyfile'), 'utf8') },
  { name: 'sites/blog.caddy', content: fs.readFileSync(path.join(EX, 'sites', 'blog.caddy'), 'utf8') },
]).sections;

// Shapes as documented in https://caddyserver.com/docs/api#get-reverse-proxyupstreams and admin.go (upstreamStatus)
const UPSTREAMS = [
  { address: '10.0.1.11:8080', num_requests: 4, fails: 0 },
  { address: '10.0.1.12:8080', num_requests: 1, fails: 0 },
  { address: '10.0.1.13:8080', num_requests: 0, fails: 2 },
  { address: '10.0.2.21:9443', num_requests: 2, fails: 0 },
  { address: '10.0.2.22:9443', num_requests: 0, fails: 1 },
  { address: '10.0.4.10:8080', num_requests: 0, fails: 0 },
  { address: 'localhost:9000', num_requests: 3, fails: 0 },
  { address: '10.9.9.9:80', num_requests: 1, fails: 0 },
];
const METRICS = `# HELP caddy_reverse_proxy_upstreams_healthy Health status of reverse proxy upstreams.
# TYPE caddy_reverse_proxy_upstreams_healthy gauge
caddy_reverse_proxy_upstreams_healthy{upstream="10.0.1.11:8080"} 1
caddy_reverse_proxy_upstreams_healthy{upstream="10.0.1.12:8080"} 1
caddy_reverse_proxy_upstreams_healthy{upstream="10.0.1.13:8080"} 0
# HELP caddy_http_requests_total Counter of HTTP(S) requests made.
# TYPE caddy_http_requests_total counter
caddy_http_requests_total{handler="reverse_proxy",server="srv0"} 1200
caddy_http_requests_total{handler="file_server",server="srv0"} 34
caddy_http_request_duration_seconds_count{code="200",handler="reverse_proxy",method="GET",server="srv0"} 1100
caddy_http_request_duration_seconds_count{code="502",handler="reverse_proxy",method="GET",server="srv0"} 7
caddy_http_requests_in_flight{handler="reverse_proxy",server="srv0"} 5
process_start_time_seconds 1.7e9
go_goroutines 42
`;

test('live: admin API + metrics -> rows named after the parsed config, with statuses', async () => {
  const stub = await startStub((req, res) => {
    if (req.url === '/reverse_proxy/upstreams') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(UPSTREAMS)); return; }
    if (req.url === '/metrics') { res.setHeader('Content-Type', 'text/plain; version=0.0.4'); res.end(METRICS); return; }
    res.statusCode = 404; res.end('{"error":"not found"}');
  });
  try {
    const inst = { statsUrl: stub.url };
    assert.equal(caddy.live.hasSource(inst), true);
    assert.deepEqual(caddy.live.sources(inst), ['admin-api', 'metrics']);
    const { rows, info } = await caddy.live.collect(inst, { sections: sections() }, {});
    const row = (proxy, name) => rows.find((r) => r.proxy === proxy && r.name === name);
    assert.equal(row('shop.example.com', '10.0.1.11:8080').status, 'UP');
    assert.equal(row('shop.example.com', '10.0.1.11:8080').scur, 4);
    assert.equal(row('shop.example.com', '10.0.1.13:8080').status, 'DOWN', 'healthy=0 from active checks');
    assert.equal(row('shop.example.com', 'BACKEND').status, 'UP');
    assert.equal(row('shop.example.com/api', '10.0.2.22:9443').status, 'UP', 'no health checks configured, but failures seen');
    assert.match(row('shop.example.com/api', '10.0.2.22:9443').check_status, /1 recent failure/);
    assert.equal(row('10.0.4.10:8080', '10.0.4.10:8080').status, 'NO CHECK');
    assert.equal(row('localhost:9000', 'localhost:9000').scur, 3);
    assert.equal(row('(admin API)', '10.9.9.9:80').status, 'NO CHECK', 'unknown upstream kept, in its own backend');
    assert.ok(row('(admin API)', 'BACKEND'));
    assert.ok(rows.every((r) => ['UP', 'DOWN', 'NO CHECK', 'MAINT', 'OPEN'].includes(r.status) && ['server', 'backend', 'frontend'].includes(r.kind)));
    assert.equal(info.requestsTotal, 1234);
    assert.equal(info.responses['5xx'], 7);
    assert.equal(info.activeRequests, 5);
    assert.equal(info.upstreams, UPSTREAMS.length);
    assert.ok(stub.hits.every((h) => h.method === 'GET'), 'read-only');
  } finally { await stub.close(); }
});

test('live: passive health checks turn an upstream DOWN at max_fails; errors surface', async () => {
  const p = caddy.parseFiles([{ name: 'Caddyfile', content: 'a.example.com {\n\treverse_proxy 10.0.0.1:80 10.0.0.2:80 {\n\t\tfail_duration 30s\n\t\tmax_fails 2\n\t}\n}\n' }]);
  const stub = await startStub((req, res) => {
    if (req.url === '/reverse_proxy/upstreams') { res.end(JSON.stringify([{ address: '10.0.0.1:80', num_requests: 0, fails: 2 }, { address: '10.0.0.2:80', num_requests: 1, fails: 1 }])); return; }
    res.statusCode = 404; res.end('');
  });
  try {
    const { rows } = await caddy.live.collect({ statsUrl: stub.url }, { sections: p.sections });
    assert.equal(rows.find((r) => r.name === '10.0.0.1:80').status, 'DOWN');
    assert.equal(rows.find((r) => r.name === '10.0.0.2:80').status, 'UP');
    assert.match(rows.find((r) => r.name === '10.0.0.2:80').check_status, /degraded/);
  } finally { await stub.close(); }
  const dead = await startStub((req, res) => { res.statusCode = 403; res.end('forbidden'); });
  try { await assert.rejects(caddy.live.collect({ statsUrl: dead.url }, { sections: p.sections }), /HTTP 403/); } finally { await dead.close(); }
});

test('metrics parser keeps only Caddy families', () => {
  const m = parseMetrics(METRICS);
  assert.ok(m.some((x) => x.name === 'caddy_reverse_proxy_upstreams_healthy' && x.labels.upstream === '10.0.1.13:8080' && x.value === 0));
  assert.ok(!m.some((x) => x.name === 'go_goroutines'));
});

// ------------------------------------------------------------------------------------------------ logs
const t0 = 1762000000;
const access = (i, o = {}) => JSON.stringify({
  level: 'info', ts: t0 + i * 0.5, logger: 'http.log.access.log0', msg: 'handled request',
  request: { remote_ip: '203.0.113.7', remote_port: '51234', client_ip: `198.51.100.${i % 5}`, proto: 'HTTP/2.0', method: 'GET', host: 'shop.example.com', uri: `/api/orders/${1000 + i}?token=SECRET${i}`, headers: { 'User-Agent': ['Mozilla/5.0 secret-agent'] } },
  bytes_read: 0, user_id: '', duration: 0.0125, size: 512, status: i % 10 === 0 ? 502 : 200, resp_headers: { 'Content-Type': ['application/json'] }, ...o,
});

test('logs: Caddy JSON access logs aggregated; query strings and user agents never stored', () => {
  const a = caddy.logs.createAggregator();
  const lines = [...Array.from({ length: 40 }, (_, i) => access(i)),
    access(41, { upstream_hostport: '10.0.1.11:8080', duration: '6.31ms' }),
    '2026/11/01 10:00:00.123\tINFO\thttp.log.access.log1\thandled request\t{"request":{"remote_ip":"10.0.0.9","method":"POST","host":"api.example.com","uri":"/v1/x?k=v","proto":"HTTP/1.1"},"duration":0.2,"size":10,"status":201}',
    JSON.stringify({ level: 'error', ts: t0 + 30, logger: 'http.handlers.reverse_proxy.health_checker.active', msg: 'host is down', host: '10.0.1.13:8080' }),
    'garbage line that is not a log entry'];
  const ok = lines.map((l) => a.push(l));
  assert.equal(ok.filter(Boolean).length, lines.length - 1);
  const res = a.finish({ source: 'test' });
  const dump = JSON.stringify(res);
  assert.ok(!dump.includes('SECRET'), 'query strings stripped');
  assert.ok(!dump.includes('secret-agent'), 'user agents not kept');
  assert.equal(res.product, 'caddy');
  assert.ok(dump.includes('shop.example.com') && dump.includes('api.example.com'));
  assert.ok(dump.includes('10.0.1.11:8080'), 'log_append upstream field used');
  assert.ok(dump.includes('host is down'));
  assert.equal(a.stats.http, 42);
});

test('logs: sniff prefers Caddy JSON over NGINX JSON / combined and HAProxy', () => {
  const caddyLines = Array.from({ length: 20 }, (_, i) => access(i));
  assert.ok(caddy.logs.sniff(caddyLines).ratio > 0.9);
  const nginxJson = Array.from({ length: 20 }, (_, i) => JSON.stringify({ time_iso8601: '2026-11-01T10:00:00+00:00', remote_addr: '1.2.3.4', request: `GET /x${i} HTTP/1.1`, status: 200, body_bytes_sent: 10, request_time: 0.01 }));
  assert.ok(caddy.logs.sniff(nginxJson).ratio < 0.1);
  const combined = Array.from({ length: 20 }, (_, i) => `1.2.3.4 - - [01/Nov/2026:10:00:${String(i).padStart(2, '0')} +0000] "GET /x HTTP/1.1" 200 12 "-" "curl/8"`);
  assert.ok(caddy.logs.sniff(combined).ratio < 0.1);
  const hap = Array.from({ length: 20 }, () => '10.0.0.1:5000 [01/Nov/2026:10:00:00.000] fe be/s1 0/0/1/2/3 200 100 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"');
  assert.ok(caddy.logs.sniff(hap).ratio < 0.1);
  const { sniff: nginxSniff } = require('../src/logs/nginx');
  assert.ok(caddy.logs.sniff(caddyLines).ratio > nginxSniff(caddyLines).ratio - 1e-9);
});

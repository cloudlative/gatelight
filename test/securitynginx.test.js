'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { assessConfig } = require('../src/improve/assess');

const wrap = (body) => `events {}\nhttp {\n  upstream backend { server 127.0.0.1:8080; }\n  server {\n    listen 80;\n    server_name example.com;\n${body}\n  }\n}\n`;
const ids = (body) => assessConfig({ product: 'nginx', files: [{ name: 'nginx.conf', content: wrap(body) }] }).findings.filter((f) => /^sec-nginx-/.test(f.id));
const has = (list, id) => list.some((f) => f.id === `sec-nginx-${id}`);

test('SSRF: request data in the proxy_pass host', () => {
  assert.ok(has(ids('location /p/ { proxy_pass http://some${arg_la}.example; }'), 'ssrf'));
  assert.ok(has(ids('location /p/ { proxy_pass $arg_some; }'), 'ssrf'));
  assert.ok(has(ids('location ~ /proxy/(.*)/(.*)$ { set $h $1; proxy_pass http://$h/x; }'), 'ssrf'), 'follows set');
  const f = ids('location /p/ { proxy_pass $http_proxy_scheme://some/file; }').find((x) => x.id === 'sec-nginx-ssrf');
  assert.strictEqual(f.severity, 'high'); assert.match(f.fix, /map/);
});
test('SSRF: no finding for fixed targets, path-only variables, map results and internal locations', () => {
  assert.ok(!has(ids('location / { proxy_pass http://backend; }'), 'ssrf'));
  assert.ok(!has(ids('location / { proxy_pass http://backend$request_uri; }'), 'ssrf'));
  assert.ok(!has(ids('location /p/ { internal; proxy_pass $arg_some; }'), 'ssrf'));
  assert.ok(!has(wrapMap('proxy_pass http://$be;'), 'ssrf'));
});
function wrapMap(inner) {
  const text = `events {}\nhttp {\n  map $arg_site $be { default ""; a "10.0.0.1:80"; }\n  upstream backend { server 127.0.0.1:8080; }\n  server { listen 80; location / { ${inner} } }\n}\n`;
  return assessConfig({ product: 'nginx', files: [{ name: 'nginx.conf', content: text }] }).findings.filter((f) => /^sec-nginx-/.test(f.id));
}

test('Host header: client-chosen value is flagged, $host is not', () => {
  assert.strictEqual(ids('location / { proxy_pass http://backend; proxy_set_header Host $http_host; }').find((f) => f.id === 'sec-nginx-host-header').severity, 'low');
  assert.strictEqual(ids('location / { proxy_pass http://backend; proxy_set_header host $arg_host; }').find((f) => f.id === 'sec-nginx-host-header').severity, 'medium');
  assert.ok(!has(ids('location / { proxy_pass http://backend; proxy_set_header Host $host; }'), 'host-header'));
});

test('HTTP splitting: $uri in redirects and headers, loose captures in proxied URLs', () => {
  assert.ok(has(ids('return 301 https://$host$uri;'), 'http-splitting'));
  assert.ok(has(ids('add_header X-Uri $uri;'), 'http-splitting'));
  assert.ok(has(ids('location ~* ^/t/([^/]+)/ { proxy_pass http://10.0.0.1/$1; }'), 'http-splitting'));
  assert.ok(!has(ids('return 301 https://$host$request_uri;'), 'http-splitting'));
  assert.ok(!has(ids('location ~* ^/t/([\\w.-]+)/ { proxy_pass http://10.0.0.1/$1; }'), 'http-splitting'));
});

test('Origin and Referer regexes', () => {
  const weak = ids(`if ($http_origin !~ 'https://example.com') { return 403; }`).find((f) => f.id === 'sec-nginx-origin-check');
  assert.ok(weak); assert.match(weak.detail, /not anchored/); assert.match(weak.fix, /map \$http_origin/);
  assert.ok(!has(ids(`if ($http_referer !~ '^https://example\\.com/') { return 403; }`), 'origin-check'));
  assert.ok(has(ids(`if ($http_referer !~ '^https://a\\.com/|b\\.com/') { return 403; }`), 'origin-check'), 'unanchored alternative');
});

test('valid_referers and multi-line headers', () => {
  assert.ok(has(ids('valid_referers none server_names *.example.com;'), 'referers-none'));
  assert.ok(!has(ids('valid_referers server_names *.example.com;'), 'referers-none'));
  assert.ok(has(ids(`add_header Content-Security-Policy "\n default-src 'none';\n font-src data:;";`), 'multiline-header'));
  assert.ok(!has(ids(`add_header Content-Security-Policy "default-src 'none'";`), 'multiline-header'));
});

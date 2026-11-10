'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { detectProduct, improveConfig } = require('../src/improve');

test('auto-detect: complete NGINX configs and bare fragments are NGINX', () => {
  assert.equal(detectProduct('events {}\nhttp {\n  server {\n    listen 80;\n  }\n}\n'), 'nginx');
  assert.equal(detectProduct('http {\nif ($http_origin !~ "^https?://x") {\n\n}\n}'), 'nginx', 'blocks with no ; still count');
  assert.equal(detectProduct('add_header Content-Security-Policy "\n    default-src: \'none\';";'), 'nginx', 'a bare multi-line directive');
  assert.equal(detectProduct('location / {\n  proxy_pass http://some$uri;\n}'), 'nginx', 'a location fragment');
});
test('auto-detect: HAProxy stays HAProxy, unknown text is not guessed', () => {
  assert.equal(detectProduct('global\n  maxconn 10\nfrontend f\n  bind :80\n  default_backend b\nbackend b\n  server s1 10.0.0.1:80 check'), 'haproxy');
  assert.equal(detectProduct('listen stats\n  bind :8404\n  mode http'), 'haproxy');
  assert.equal(detectProduct('server s1 10.0.0.1:80 check'), null, 'a lone "server" line is ambiguous');
  assert.equal(detectProduct('hello world'), null);
});
test('improveConfig analyses a bare NGINX fragment without a product', () => {
  const r = improveConfig({ files: [{ name: 'x.conf', content: 'location / {\n  proxy_pass http://some$uri;\n}\n' }] });
  assert.equal(r.product, 'nginx');
});

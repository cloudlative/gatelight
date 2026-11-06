'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseConfig, describeAcl } = require('../src/haproxyConfig');
const { parseNginxFiles } = require('../src/nginxConfig');

test('HAProxy: ACL names resolve to readable host / path matchers', () => {
  const [fe] = parseConfig([
    'frontend f', ' acl h hdr(host) -i a.example.com b.example.com', ' acl api path_beg /api', ' acl css path_end .css .js',
    ' use_backend x if h api', ' use_backend y if { path /health } or css', ' use_backend z unless api', ' default_backend d',
  ].join('\n'));
  const [x, y, z, d] = fe.routes;
  assert.equal(x.match, 'Host is a.example.com or b.example.com AND Path begins with /api');
  assert.deepEqual(x.hosts, ['a.example.com', 'b.example.com']);
  assert.equal(x.short, 'a.example.com, b.example.com + /api*');
  assert.match(y.match, /Path is \/health OR Path ends with \.css or \.js/);
  assert.match(z.match, /^NOT \(/);
  assert.equal(d.match, '');
  assert.equal(describeAcl('hdr_dom(host) example.com').text, 'Host has domain example.com');
});

test('NGINX: routes carry the proxy_pass URL, URI rewrite note, rewrite rules and hosts; credentials in the URL are masked', () => {
  const { sections } = parseNginxFiles([{ name: 'nginx.conf', content: [
    'events {}', 'http {', ' upstream api_pool { server 10.0.0.1:80; }',
    ' server { listen 80; server_name a.example.com;',
    '  location /api/ { rewrite ^/api/v1/(.*) /$1 break; proxy_pass http://api_pool/v1/; }',
    '  location = /x { proxy_pass http://user:pw@api_pool; }', ' }', '}',
  ].join('\n') }]);
  const routes = sections.find((s) => s.routes && s.routes.length).routes;
  const api = routes.find((r) => r.condition === 'location /api/');
  assert.equal(api.match, 'Path begins with /api/');
  assert.equal(api.passUrl, 'http://api_pool/v1/');
  assert.equal(api.rewriteNote, 'Prefix /api/ is replaced by /v1/');
  assert.deepEqual(api.rewrites, ['^/api/v1/(.*) /$1 break']);
  assert.deepEqual(api.hosts, ['a.example.com']);
  const x = routes.find((r) => r.condition === 'location = /x');
  assert.equal(x.short, '= /x');
  assert.ok(!x.passUrl.includes('pw') && !x.passUrl.includes('user'));
});

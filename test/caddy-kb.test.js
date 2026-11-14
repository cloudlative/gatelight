'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const kb = require('../src/kb/caddy.json');
const { goFuncs, subdirectives, syntaxBlock } = require('../tools/kb/caddy');
const { orderFor } = require('../src/products/caddy/kb');

test('knowledge base: versions, lifecycle facts from the release tags', () => {
  assert.ok(fs.statSync(path.join(__dirname, '..', 'src', 'kb', 'caddy.json')).size < 1024 * 1024);
  assert.equal(kb.versions[kb.versions.length - 1], '2.0.0');
  assert.ok(kb.versions.every((v) => /^2\.\d+\.\d+$/.test(v)), 'stable releases only');
  assert.equal(kb.latest, kb.versions[0]);
  assert.equal(kb.directives.basic_auth.since, '2.8.0');
  assert.equal(kb.directives.basicauth.since, '2.0.0');
  assert.equal(kb.directives.invoke.since, '2.7.0');
  assert.equal(kb.directives.handle_path.since, '2.1.0');
  assert.equal(kb.directives.reverse_proxy.docs, 'https://caddyserver.com/docs/caddyfile/directives/reverse_proxy');
  assert.match(kb.directives.reverse_proxy.syntax, /reverse_proxy \[<matcher>\]/);
  const rp = kb.directives.reverse_proxy.sub;
  assert.equal(rp.health_uri.since, '2.4.0');
  assert.equal(rp.health_passes.since, '2.8.0');
  assert.equal(rp.buffer_requests.until, '2.7.6');
  assert.ok(rp['transport http>tls_insecure_skip_verify']);
  assert.equal(kb.matchers.client_ip.since, '2.7.0');
  assert.equal(kb.lbPolicies.weighted_round_robin.since, '2.7.0');
  assert.equal(kb.options.servers.sub.trusted_proxies.since, '2.6.3');
  assert.ok(kb.options.servers.sub['timeouts>read_header']);
  // the directive order changed between releases
  assert.ok(!orderFor('2.0.0').includes('handle_path'));
  assert.ok(orderFor('2.1.0').includes('handle_path'));
  assert.ok(orderFor('2.8.0').includes('basic_auth') && !orderFor('2.7.6').includes('basic_auth'));
  assert.ok(orderFor(kb.latest).indexOf('handle') < orderFor(kb.latest).indexOf('respond'));
});

test('KB builder parsers: Go unmarshalers and doc syntax blocks', () => {
  const go = [
    'func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {',
    '\tfor d.NextBlock(0) {',
    '\t\tswitch d.Val() {',
    '\t\tcase "to":',
    '\t\t\tswitch subdir {',
    '\t\t\tcase "inner":',
    '\t\t\t}',
    '\t\tcase "lb_policy", "lb_retries":',
    '\t\t\tswitch len(args) {',
    '\t\t\tcase 1:',
    '\t\t\t}',
    '\t\t}',
    '\t}',
    '}',
    'func (ServerType) evaluateGlobalOptionsBlock(x int) {',
    '}',
  ].join('\n');
  const fns = goFuncs(go);
  assert.deepEqual(fns.map((f) => [f.recv, f.name]), [['Handler', 'UnmarshalCaddyfile'], ['ServerType', 'evaluateGlobalOptionsBlock']]);
  assert.deepEqual(subdirectives(fns[0]), ['to', 'to>inner', 'lb_policy', 'lb_retries']);
  assert.equal(syntaxBlock('# x\n## Syntax\n\n```caddy-d\nencode [<matcher>] <formats...>\n```\n'), 'encode [<matcher>] <formats...>');
});

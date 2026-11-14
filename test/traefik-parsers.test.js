'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const YAML = require('../src/products/traefik/yaml');
const TOML = require('../src/products/traefik/toml');
const rules = require('../src/products/traefik/rules');
const E = require('../src/products/traefik/edit');

// ------------------------------------------------------------------------------------------------ YAML
test('yaml: block mappings, sequences, backticks in rules, comments and line numbers', () => {
  const r = YAML.parse([
    '# dynamic config', // 1
    'http:', // 2
    '  routers:', // 3
    '    shop:', // 4
    '      rule: Host(`shop.example.com`) && PathPrefix(`/api`)   # trailing comment', // 5
    '      entryPoints:', // 6
    '        - websecure', // 7
    '      middlewares: [a@file, "b"]', // 8
    '  services:', // 9
    '    s:', // 10
    '      loadBalancer:', // 11
    '        servers:', // 12
    '        - url: http://10.0.0.1:80/', // 13
    '        - url: \'http://10.0.0.2:80\'', // 14
    '          weight: 2', // 15
  ].join('\n'));
  assert.equal(r.data.http.routers.shop.rule, 'Host(`shop.example.com`) && PathPrefix(`/api`)');
  assert.deepEqual(r.data.http.routers.shop.entryPoints, ['websecure']);
  assert.deepEqual(r.data.http.routers.shop.middlewares, ['a@file', 'b']);
  assert.deepEqual(r.data.http.services.s.loadBalancer.servers, [{ url: 'http://10.0.0.1:80/' }, { url: 'http://10.0.0.2:80', weight: 2 }]);
  assert.equal(YAML.lineOf(r.lines, ['http', 'routers', 'shop', 'rule']), 5);
  assert.equal(YAML.lineOf(r.lines, ['http', 'routers', 'shop', 'entryPoints', 0]), 7);
  assert.equal(YAML.lineOf(r.lines, ['http', 'services', 's', 'loadBalancer', 'servers', 1, 'weight']), 15);
});

test('yaml: scalars, quoting, escapes, a # inside values, types', () => {
  const r = YAML.parse('a: "x # not a comment"\nb: \'it\'\'s\'\nc: "tab\\tnew\\nline \\u00e9"\nd: 42\ne: 1.5\nf: true\ng: ~\nh: "42"\ni: 0x1F\nj: url#frag\nk: :80\nl: "$apr1$x$y"\nm: -1\n');
  assert.deepEqual(r.data, { a: 'x # not a comment', b: "it's", c: 'tab\tnew\nline é', d: 42, e: 1.5, f: true, g: null, h: '42', i: 31, j: 'url#frag', k: ':80', l: '$apr1$x$y', m: -1 });
});

test('yaml: multi-line strings (| > with chomping, folded plain and quoted scalars)', () => {
  const r = YAML.parse('lit: |\n  line1\n  line2\nkeep: |+\n  a\n\nstrip: >-\n  one\n  two\n\n  three\nplain: this is\n  continued\nq: "first\n  second"\nnext: 1\n');
  assert.equal(r.data.lit, 'line1\nline2\n');
  assert.equal(r.data.keep, 'a\n\n');
  assert.equal(r.data.strip, 'one two\nthree');
  assert.equal(r.data.plain, 'this is continued');
  assert.equal(r.data.q, 'first second');
  assert.equal(r.data.next, 1);
});

test('yaml: flow collections across lines, nested, empty', () => {
  const r = YAML.parse('a: {x: 1, y: [1, 2, {z: "q"}]}\nb: [\n  one,\n  two,\n]\nc: {}\nd: []\ne: [Host(`a`), "b,c"]\n');
  assert.deepEqual(r.data, { a: { x: 1, y: [1, 2, { z: 'q' }] }, b: ['one', 'two'], c: {}, d: [], e: ['Host(`a`)', 'b,c'] });
});

test('yaml: anchors, aliases and merge keys; sequences of sequences; document marker', () => {
  const r = YAML.parse('---\nbase: &b\n  interval: 10s\n  path: /h\nsvc:\n  <<: *b\n  path: /override\nlist: &l [1, 2]\nother: *l\nnested:\n- - a\n  - b\n- c\n');
  assert.deepEqual(r.data.svc, { path: '/override', interval: '10s' });
  assert.deepEqual(r.data.other, [1, 2]);
  assert.deepEqual(r.data.nested, [['a', 'b'], 'c']);
});

test('yaml: docker-compose label lists with = and $$', () => {
  const r = YAML.parse('services:\n  app:\n    labels:\n      - "traefik.http.routers.app.rule=Host(`a.example.com`)"\n      - traefik.http.middlewares.x.basicauth.users=u:$$apr1$$abc\n    ports: ["80:80"]\n');
  assert.equal(r.data.services.app.labels[0], 'traefik.http.routers.app.rule=Host(`a.example.com`)');
  assert.equal(r.data.services.app.labels[1], 'traefik.http.middlewares.x.basicauth.users=u:$$apr1$$abc');
  assert.equal(YAML.lineOf(r.lines, ['services', 'app', 'labels', 1]), 5);
});

test('yaml: clear errors with line numbers', () => {
  const cases = [
    ['a:\n  b: 1\n c: 2\n', 3, /indentation/],
    ['a: 1\na: 2\n', 2, /duplicate key "a"/],
    ['a: "unterminated\nb: 1\n', 1, /unterminated/],
    ['a: [1, 2\n', 1, /unterminated flow/],
    ['a: *nope\n', 1, /unknown alias/],
    ['a:\n\t- x\n', 2, /tab/],
    ['? complex\n: v\n', 1, /complex mapping keys|expected/],
    ['a: b: c\n', 1, /": "/],
  ];
  for (const [text, line, re] of cases) {
    assert.throws(() => YAML.parse(text), (e) => { assert.ok(e instanceof YAML.YAMLError, text); assert.equal(e.line, line, text); assert.match(e.message, re); return true; });
  }
  assert.doesNotThrow(() => YAML.parse('a: 1\na: 2\n', { allowDuplicateKeys: true }));
});

test('yaml: stringify round-trips through parse', () => {
  const data = { http: { routers: { r: { rule: 'Host(`a`) || Host(`b`)', entryPoints: ['web'], tls: {} } }, middlewares: { m: { headers: { customRequestHeaders: { 'X-A': '' } } } } }, n: ':80', b: 'true', l: [{ url: 'http://x:1' }] };
  assert.deepEqual(YAML.parse(YAML.stringify(data)).data, data);
});

// ------------------------------------------------------------------------------------------------ TOML
test('toml: tables, array tables, dotted keys, strings, arrays, inline tables, numbers, line numbers', () => {
  const r = TOML.parse([
    '# static', // 1
    '[entryPoints]', // 2
    '  [entryPoints.web]', // 3
    '    address = ":80"', // 4
    '    http.redirections.entryPoint.to = "websecure"', // 5
    '[http.routers.shop]', // 6
    '  rule = "Host(`shop.example.com`) && PathPrefix(`/api`)"', // 7
    '  entryPoints = ["websecure", # comment', // 8
    '    "web",', // 9
    '  ]', // 10
    '  tls = { certResolver = "le", domains = [{ main = "a.com" }] }', // 11
    '[[http.services.s.loadBalancer.servers]]', // 12
    '  url = \'http://10.0.0.1:80\'', // 13
    '[[http.services.s.loadBalancer.servers]]', // 14
    '  url = "http://10.0.0.2:80"', // 15
    '[x]', // 16
    '  i = 1_000', // 17
    '  h = 0xff', // 18
    '  f = 1.5e2', // 19
    '  b = false', // 20
    '  d = 1979-05-27T07:32:00Z', // 21
    '  m = """', // 22
    'two', // 23
    'lines"""', // 24
    '  lit = \'\'\'C:\\path\'\'\'', // 25
    '  "quoted key" = "\\u00e9\\t"', // 26
  ].join('\n'));
  assert.equal(r.data.entryPoints.web.http.redirections.entryPoint.to, 'websecure');
  assert.equal(r.data.http.routers.shop.rule, 'Host(`shop.example.com`) && PathPrefix(`/api`)');
  assert.deepEqual(r.data.http.routers.shop.entryPoints, ['websecure', 'web']);
  assert.deepEqual(r.data.http.routers.shop.tls, { certResolver: 'le', domains: [{ main: 'a.com' }] });
  assert.deepEqual(r.data.http.services.s.loadBalancer.servers, [{ url: 'http://10.0.0.1:80' }, { url: 'http://10.0.0.2:80' }]);
  assert.deepEqual(r.data.x, { i: 1000, h: 255, f: 150, b: false, d: '1979-05-27T07:32:00Z', m: 'two\nlines', lit: 'C:\\path', 'quoted key': 'é\t' });
  assert.equal(YAML.lineOf(r.lines, ['http', 'routers', 'shop', 'rule']), 7);
  assert.equal(YAML.lineOf(r.lines, ['entryPoints', 'web', 'http', 'redirections', 'entryPoint', 'to']), 5);
  assert.equal(YAML.lineOf(r.lines, ['http', 'services', 's', 'loadBalancer', 'servers', 1]), 14);
  assert.equal(YAML.lineOf(r.lines, ['http', 'services', 's', 'loadBalancer', 'servers', 1, 'url']), 15);
});

test('toml: errors with line numbers', () => {
  const cases = [
    ['[a]\nx = 1\n[a]\n', 3, /defined twice/],
    ['x = 1\nx = 2\n', 2, /duplicate key/],
    ['rule = Host(`a`)\n', 1, /must be quoted/],
    ['a = "open\n', 1, /unterminated/],
    ['a = [1, 2\n', 1, /unterminated array/],
    ['a = 1 b = 2\n', 1, /end of the line/],
    ['a = "\\q"\n', 1, /invalid escape/],
    ['t = { a = 1 }\n[t.b]\n', 2, /inline table/],
  ];
  for (const [text, line, re] of cases) assert.throws(() => TOML.parse(text), (e) => { assert.ok(e instanceof TOML.TOMLError, text); assert.equal(e.line, line, text); assert.match(e.message, re); return true; });
});

test('toml: stringify round-trips', () => {
  const data = { entryPoints: { web: { address: ':80' } }, http: { services: { s: { loadBalancer: { servers: [{ url: 'http://a:1' }, { url: 'http://b:1' }] } } } } };
  assert.deepEqual(TOML.parse(TOML.stringify(data)).data, data);
});

// ------------------------------------------------------------------------------------------------ rules
test('rules: parse, operators, precedence, negation, DNF expansion', () => {
  const t = rules.parseRule('Host(`a.com`) || (Host(`b.com`) && !PathPrefix(`/admin`))');
  assert.equal(t.type, 'or');
  const b = rules.branches('Host(`a.com`) || (Host(`b.com`) && !PathPrefix(`/admin`))', 'v3').branches;
  assert.equal(b.length, 2);
  assert.deepEqual(b[0].hosts, ['a.com']);
  assert.deepEqual(b[1].matchers.map((m) => [m.field, m.op, m.negated]), [['Host', 'is', false], ['Path', 'begins with', true]]);
  // De Morgan: !(A || B) -> !A && !B
  const n = rules.branches('!(Path(`/a`) || Path(`/b`))').branches;
  assert.equal(n.length, 1); assert.ok(n[0].matchers.every((m) => m.negated));
  // distribution: (A || B) && C -> 2 branches
  assert.equal(rules.branches('(Host(`a`) || Host(`b`)) && PathPrefix(`/x`)').branches.length, 2);
  // double-quoted values
  assert.deepEqual(rules.parseRule('Host("a.com")').args, ['a.com']);
});

test('rules: v2 vs v3 matcher semantics and checks against the KB', () => {
  const kb = require('../src/kb/traefik.json');
  const v3 = (r) => rules.checkRule(r, { syntax: 'v3', kbMatchers: kb.matchers.http });
  const v2 = (r) => rules.checkRule(r, { syntax: 'v2', kbMatchers: kb.matchers.http });
  assert.deepEqual(v3('Host(`a`) && Header(`X`, `1`) && PathRegexp(`^/v[0-9]+`)'), []);
  assert.match(v3('Headers(`X`, `1`)')[0].msg, /v2-syntax matcher.*Header/);
  assert.match(v3('Host(`a`, `b`)')[0].msg, /single value/);
  assert.match(v3('HostRegexp(`{sub:[a-z]+}.example.com`)')[0].msg, /v2 "\{name:regex\}" template/);
  assert.match(v2('Header(`X`, `1`)')[0].msg, /v3-syntax matcher/);
  assert.deepEqual(v2('Host(`a`, `b`) && Headers(`X`, `1`) && PathPrefix(`/a/{id:[0-9]+}`)'), []);
  assert.match(v3('host(`a`)')[0].msg, /case-sensitive/);
  assert.match(v3("Host('a')")[0].msg, /single quotes/);
  assert.match(v3('Host(`a`) &&')[0].msg, /syntax error/);
  assert.match(v3('PathPrefix(`api`)')[0].msg, /start with "\/"/);
  assert.match(rules.checkRule('HostSNI(`a`)', { syntax: 'v3', kbMatchers: kb.matchers.http })[0].msg, /TCP router matcher/);
  // v2 multi-value matcher -> one matcher with alternatives; Query pairs
  const br = rules.branches('Host(`a`, `b`) && Query(`x=1`, `y=2`)', 'v2').branches[0];
  assert.deepEqual(br.matchers[0].values, ['a', 'b']);
  assert.deepEqual(br.matchers.slice(1).map((m) => m.name), ['x', 'y']);
});

test('rules: migrate v2 rules to v3 when mechanical', () => {
  assert.equal(rules.migrateRule('Host(`a`, `b`) && Headers(`X`, `1`)'), '(Host(`a`) || Host(`b`)) && Header(`X`, `1`)');
  assert.equal(rules.migrateRule('HostHeader(`a`)'), 'Host(`a`)');
  assert.equal(rules.migrateRule('PathPrefix(`/a/{id:[0-9]+}`)'), null, 'templates need a human');
});

test('rules: evaluation (v2 templates, v3 regexps, wildcards, ClientIP, unknowns)', () => {
  const ev = (r, req, s = 'v3') => rules.evaluate(rules.parseRule(r), req, s);
  assert.equal(ev('Host(`a.com`) && PathPrefix(`/api`)', { host: 'A.com:443', path: '/api/x?q=1' }), true);
  assert.equal(ev('Host(`a.com`) && !PathPrefix(`/api`)', { host: 'a.com', path: '/api' }), false);
  assert.equal(ev('HostRegexp(`^[a-z]+\\.example\\.com$`)', { host: 'shop.example.com' }), true);
  assert.equal(ev('HostRegexp(`{sub:[a-z]+}.example.com`)', { host: 'shop.example.com' }, 'v2'), true);
  assert.equal(ev('Host(`*.example.com`)', { host: 'x.example.com' }), true);
  assert.equal(ev('ClientIP(`10.0.0.0/8`)', { clientIp: '10.1.2.3' }), true);
  assert.equal(ev('Header(`X`, `1`)', { host: 'a' }), null, 'unknown without headers');
  assert.equal(ev('Header(`X`, `1`) || Host(`a`)', { host: 'a' }), true);
  assert.equal(rules.defaultPriority('Host(`a.com`)'), 13);
});

// ------------------------------------------------------------------------------------------------ text edits
test('edit: YAML and TOML edits keep comments and compose', () => {
  let y = '# top\nentryPoints:\n  web:\n    address: ":80"   # plain\nlog:\n  level: DEBUG # noisy\nhttp:\n  routers:\n    r:\n      middlewares: [a]\n      tls: {}\n';
  y = E.yamlSet(y, ['entryPoints', 'web', 'http', 'redirections', 'entryPoint', 'to'], 'websecure');
  y = E.yamlSet(y, ['log', 'level'], 'INFO');
  y = E.yamlSet(y, ['accessLog', 'format'], 'json');
  y = E.yamlAppend(y, ['http', 'routers', 'r', 'middlewares'], 'b@file');
  y = E.yamlSet(y, ['http', 'routers', 'r', 'tls', 'options'], 'modern');
  assert.match(y, /# top/); assert.match(y, /address: ":80" {3}# plain/); assert.match(y, /level: INFO # noisy/);
  const d = YAML.parse(y).data;
  assert.equal(d.entryPoints.web.http.redirections.entryPoint.to, 'websecure');
  assert.deepEqual(d.accessLog, { format: 'json' });
  assert.deepEqual(d.http.routers.r, { middlewares: ['a', 'b@file'], tls: { options: 'modern' } });
  assert.deepEqual(YAML.parse(E.yamlRename(y, ['log', 'level'], 'lvl')).data.log, { lvl: 'INFO' });
  assert.equal(YAML.parse(E.yamlDelete(y, ['log'])).data.log, undefined);
  let t = '[entryPoints.web]\n  address = ":80" # x\n[log]\n  level = "DEBUG"\n';
  t = E.tomlSet(t, ['entryPoints', 'web', 'http', 'redirections', 'entryPoint', 'to'], 'websecure');
  t = E.tomlSet(t, ['log', 'level'], 'INFO');
  t = E.tomlSet(t, ['accessLog', 'format'], 'json');
  assert.match(t, /# x/);
  assert.deepEqual(TOML.parse(t).data, { entryPoints: { web: { address: ':80', http: { redirections: { entryPoint: { to: 'websecure' } } } } }, log: { level: 'INFO' }, accessLog: { format: 'json' } });
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const caddy = require('../src/products/caddy');
const { lex, parseTree, redact } = require('../src/products/caddy/caddyfile');
const { parseAddress, sortDirectives } = require('../src/products/caddy/model');
const { EXAMPLE_SPEC } = require('../src/build/spec');

const EX = path.join(__dirname, '..', 'examples', 'caddy');
const exampleFiles = () => [
  { name: 'Caddyfile', content: fs.readFileSync(path.join(EX, 'Caddyfile'), 'utf8') },
  { name: 'sites/blog.caddy', content: fs.readFileSync(path.join(EX, 'sites', 'blog.caddy'), 'utf8') },
];
const fe = (r, name) => r.sections.find((s) => s.type === 'frontend' && s.name === name);
const be = (r, name) => r.sections.find((s) => s.type === 'backend' && s.name === name);
const ids = (f) => new Set(f.map((x) => x.id));
const errors = (r) => r.findings.filter((f) => f.severity === 'error');

test('contract surface', () => {
  for (const k of ['type', 'name', 'short', 'labels', 'defaultFile', 'example', 'fileFormats', 'detect', 'parseFiles', 'loadPath', 'redact', 'audit', 'versions', 'validate', 'improve', 'flow', 'live', 'logs', 'build']) assert.ok(caddy[k] !== undefined, k);
  assert.equal(caddy.type, 'caddy');
  assert.ok(fs.existsSync(caddy.example));
  assert.equal(caddy.flow.defaultPort('https'), 443);
  assert.equal(caddy.flow.defaultPort('http'), 80);
  const v = caddy.versions();
  assert.ok(v.list.length > 40 && v.list[0] === v.latest && v.list.includes('2.0.0') && v.list.includes('2.7.6'));
});

test('lexer: quotes, backticks, heredoc, comments, escaped newline, env defaults', () => {
  const { tokens, errors: e } = lex('a "b c" `{"x": 1}` # comment\nrespond <<HTML\n\t<p>hi</p>\n\tHTML 200\nreverse_proxy a \\\n  b\nc d#e #comment');
  assert.deepEqual(e, []);
  assert.deepEqual(tokens.map((t) => t.text), ['a', 'b c', '{"x": 1}', 'respond', '<p>hi</p>', '200', 'reverse_proxy', 'a', 'b', 'c', 'd#e']);
  assert.equal(tokens.find((t) => t.text === 'b').nl, false, 'escaped newline continues the line');
  assert.equal(tokens.find((t) => t.text === 'respond').nl, true);
  const tree = parseTree(lex('{\n\temail a@b.c\n}\nexample.com {\n\thandle /x* {\n\t\trespond 1\n\t}\n}\n').tokens);
  assert.equal(tree.nodes.length, 2);
  assert.equal(tree.nodes[1].block[0].block[0].name, 'respond');
  assert.ok(parseTree(lex('a {\n b\n').tokens).errors.some((x) => /Unclosed/.test(x.msg)));
});

test('site addresses and Automatic HTTPS ports', () => {
  assert.deepEqual((({ host, port, tls }) => ({ host, port, tls }))(parseAddress('example.com')), { host: 'example.com', port: '443', tls: true });
  assert.deepEqual((({ port, tls }) => ({ port, tls }))(parseAddress('http://example.com')), { port: '80', tls: false });
  assert.deepEqual((({ port, tls }) => ({ port, tls }))(parseAddress(':8080')), { port: '8080', tls: false });
  assert.deepEqual((({ port, tls }) => ({ port, tls }))(parseAddress('localhost:8443')), { port: '8443', tls: true });
  assert.equal(parseAddress('*.example.com').hostname, '*.example.com');
  assert.ok(parseAddress('ftp://x.com').error);
  assert.ok(parseAddress('example.com:99999').error);
});

test('directive sorting follows Caddy (order, then path specificity, no-matcher last)', () => {
  const mk = (dir, m) => ({ dir, matcherToken: m || null, nd: {} });
  const order = ['redir', 'rewrite', 'handle', 'route', 'respond', 'reverse_proxy', 'file_server'];
  const out = sortDirectives([mk('file_server'), mk('reverse_proxy', '/api/*'), mk('respond', '/a'), mk('reverse_proxy'), mk('reverse_proxy', '/api/v2/*'), mk('handle'), mk('handle', '/x'), mk('handle_path', '/static/*'), mk('redir', '/old')], order, new Map());
  assert.deepEqual(out.map((d) => `${d.dir} ${d.matcherToken || ''}`.trim()), ['redir /old', 'handle_path /static/*', 'handle /x', 'handle', 'respond /a', 'reverse_proxy /api/v2/*', 'reverse_proxy /api/*', 'reverse_proxy', 'file_server']);
});

test('example: frontends, binds (auto HTTPS), snippets and file imports expanded', () => {
  const r = caddy.parseFiles(exampleFiles());
  assert.deepEqual(r.files.map((f) => f.name).sort(), ['Caddyfile', 'sites/blog.caddy']);
  const shop = fe(r, 'shop.example.com, www.shop.example.com');
  assert.deepEqual(shop.serverNames, ['shop.example.com', 'www.shop.example.com']);
  assert.deepEqual(shop.binds.map((b) => [b.port, b.ssl]), [['443', true]]);
  assert.deepEqual(fe(r, 'http://status.example.com').binds.map((b) => [b.port, b.ssl]), [['80', false]]);
  assert.deepEqual(fe(r, ':8080').binds.map((b) => [b.port, b.ssl]), [['8080', false]]);
  assert.deepEqual(fe(r, '*.preview.example.com').serverNames, ['*.preview.example.com']);
  assert.ok(fe(r, 'blog.example.com'), 'site from import sites/*.caddy');
  const redirect = r.sections.find((s) => s.type === 'frontend' && s.implicit);
  assert.equal(redirect.binds[0].port, '80');
  assert.ok(redirect.serverNames.includes('shop.example.com') && !redirect.serverNames.includes('status.example.com'));
  assert.equal(redirect.routes[0].transforms[0].action, 'redirect');
  // snippet expanded: the shop site's header + log come from (security_headers) / (access_log)
  assert.ok(shop.directives.some((d) => d.keyword === 'Strict-Transport-Security' && d.snippet === 'security_headers'));
  assert.ok(shop.directives.some((d) => d.keyword === 'output' && d.args.includes('/var/log/caddy/shop.access.log')), '{args[0]} substituted');
});

test('example: routes in Caddy evaluation order with matchers and transforms', () => {
  const r = caddy.parseFiles(exampleFiles());
  const shop = fe(r, 'shop.example.com, www.shop.example.com');
  assert.deepEqual(shop.routes.map((x) => x.directive), ['redir', 'file_server', 'reverse_proxy', 'reverse_proxy', 'respond'], 'redir < handle (sorted by path) < respond');
  const [redir, stat, api, app] = shop.routes;
  assert.ok(redir.terminal && redir.transforms[0].action === 'redirect' && redir.transforms[0].args[0] === '/checkout');
  assert.deepEqual(redir.matchers[0], { field: 'Path', op: 'is', values: ['/old-checkout', '/cart.php'], negated: false });
  assert.equal(stat.transforms[0].action, 'strip-prefix'); assert.deepEqual(stat.transforms[0].args, ['/static']);
  assert.equal(stat.matchers[0].op, 'begins with');
  assert.equal(api.target, 'shop.example.com/api');
  assert.deepEqual(api.transforms.map((t) => t.action), ['strip-prefix', 'set-header']);
  assert.equal(app.type, 'default'); assert.equal(app.target, 'shop.example.com');
  const internal = shop.routes[4];
  assert.ok(internal.matchers.some((m) => m.field === 'ClientIP' && m.negated));
  const api2 = fe(r, 'api.example.com');
  assert.deepEqual(api2.routes.map((x) => x.target), ['10.0.3.50:7100', '10.0.3.31:7000', 'api.example.com/v2'], 'route before reverse_proxy; /legacy/* (longer) before /v2/*');
  const admin = fe(r, 'admin.example.com');
  assert.deepEqual(admin.routes.map((x) => x.directive), ['reverse_proxy', 'file_server'], 'reverse_proxy sorts before file_server');
});

test('example: backends with servers, policies and health checks', () => {
  const r = caddy.parseFiles(exampleFiles());
  const app = be(r, 'shop.example.com');
  assert.equal(app.balance, 'least_conn');
  assert.deepEqual(app.servers.map((s) => s.address), ['10.0.1.11:8080', '10.0.1.12:8080', '10.0.1.13:8080']);
  assert.ok(app.servers.every((s) => s.check));
  assert.deepEqual(app.healthCheck, { path: '/healthz', port: null, interval: '10s', timeout: '2s', passes: null, fails: null });
  const api = be(r, 'shop.example.com/api');
  assert.ok(api.servers.every((s) => s.scheme === 'https' && !s.check));
  assert.equal(api.transport.insecureSkipVerify, true);
  assert.equal(be(r, 'api.example.com/v2').sticky, true);
  assert.equal(be(r, '10.0.5.20:2368').healthCheck.interval, '30s', 'default health_interval');
  assert.ok(be(r, '{labels.2}.preview.internal:3000').dynamic);
});

test('redaction: basic auth hashes, header_up secrets, DNS tokens, JSON secrets', () => {
  const r = caddy.parseFiles(exampleFiles());
  const raw = r.files.find((f) => f.name === 'Caddyfile').raw;
  assert.ok(!raw.includes('sk_live_0123456789abcdef'));
  assert.ok(!raw.includes('k3y-Abc123'));
  assert.ok(!raw.includes('$2a$14$Zkx19'));
  assert.ok(raw.includes('header_up X-Request-ID {http.request.uuid}'), 'placeholders untouched');
  assert.equal(raw.split('\n').length, exampleFiles()[0].content.split('\n').length, 'line numbers kept');
  assert.match(redact('x {\n\theader_up Authorization {env.TOKEN}\n}'), /\{env\.TOKEN\}/);
  const json = caddy.parseFiles([{ name: 'caddy.json', content: fs.readFileSync(path.join(EX, 'caddy.json'), 'utf8') }]).files[0].raw;
  assert.ok(!json.includes('not-a-real-token'));
});

test('Caddy JSON config is detected and mapped to the same model', () => {
  const text = fs.readFileSync(path.join(EX, 'caddy.json'), 'utf8');
  assert.ok(caddy.detect(text) > 0.9);
  const r = caddy.parseFiles([{ name: 'caddy.json', content: text }]);
  const shop = fe(r, 'shop.example.com');
  assert.deepEqual(shop.binds.map((b) => [b.port, b.ssl]), [['443', true]]);
  assert.deepEqual(shop.routes.map((x) => x.kind), ['proxy', 'redirect', 'proxy']);
  assert.deepEqual(shop.routes[0].transforms.map((t) => t.action), ['strip-prefix']);
  const api = be(r, shop.routes[0].target);
  assert.equal(api.balance, 'least_conn'); assert.equal(api.healthCheck.path, '/health'); assert.equal(api.servers.length, 2);
  assert.ok(r.sections.some((s) => s.implicit && s.binds[0].port === '80'));
});

test('detect: Caddyfile high, other products low', () => {
  assert.ok(caddy.detect(exampleFiles()[0].content) > 0.8);
  assert.ok(caddy.detect('example.com {\n\treverse_proxy localhost:8080\n}\n') > 0.5);
  assert.ok(caddy.detect(fs.readFileSync(path.join(__dirname, '..', 'examples', 'nginx', 'nginx.conf'), 'utf8')) < 0.3);
  assert.ok(caddy.detect(fs.readFileSync(path.join(__dirname, '..', 'examples', 'haproxy', 'haproxy.cfg'), 'utf8')) < 0.3);
  assert.ok(caddy.detect('http:\n  routers:\n    app:\n      rule: "Host(`a.com`)"\n      service: app\n') < 0.3);
  assert.ok(caddy.detect('<VirtualHost *:80>\n  ServerName a.com\n  ProxyPass / http://b/\n</VirtualHost>\n') < 0.3);
});

test('loadPath: imports from disk stay inside the root', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'caddy-'));
  fs.mkdirSync(path.join(dir, 'root'));
  fs.writeFileSync(path.join(dir, 'secret.caddy'), 'leaked.example.com {\n\trespond 1\n}\n');
  fs.writeFileSync(path.join(dir, 'root', 'Caddyfile'), `import ../secret.caddy\nimport ${path.join(dir, 'secret.caddy')}\nok.example.com {\n\treverse_proxy 10.0.0.1:80\n}\n`);
  const r = caddy.loadPath(path.join(dir, 'root', 'Caddyfile'), path.join(dir, 'root'));
  assert.deepEqual(r.sections.filter((s) => s.type === 'frontend' && !s.implicit).map((s) => s.name), ['ok.example.com']);
  assert.ok(r.notes.some((n) => /outside the config root/.test(n.msg)));
});

test('audit: planted weak spots found, every finding has a location and a docs link', () => {
  const r = caddy.parseFiles(exampleFiles());
  const f = caddy.audit(r.sections, { notes: r.notes });
  for (const id of ['caddy-admin-exposed', 'caddy-no-health-check', 'caddy-upstream-tls-insecure', 'caddy-tls-internal-public', 'caddy-no-access-log', 'caddy-redundant-header-up', 'caddy-basicauth-deprecated', 'caddy-file-browse', 'caddy-unused-snippet', 'caddy-inline-secret', 'caddy-unreachable-route', 'caddy-single-upstream']) assert.ok(ids(f).has(id), `missing ${id}`);
  assert.ok(!ids(f).has('caddy-client-ip-untrusted'), 'trusted_proxies is configured');
  assert.ok(f.every((x) => x.file && x.line && /^https:\/\/caddyserver\.com\/docs\//.test(x.docs)));
  const bad = caddy.parseFiles([{ name: 'Caddyfile', content: 'a.example.com {\n\trespond @nope 403\n\t@ip client_ip 10.0.0.0/8\n\tabort @ip\n\treverse_proxy 10.0.0.1:80\n}\na.example.com {\n\treverse_proxy 10.0.0.2:80\n}\nimport missing_snippet\n' }]);
  const g = caddy.audit(bad.sections, { notes: bad.notes });
  for (const id of ['caddy-undefined-matcher', 'caddy-duplicate-site', 'caddy-client-ip-untrusted', 'caddy-include-note']) assert.ok(ids(g).has(id), `missing ${id}`);
});

test('validate: no false-positive errors on the example (latest), version-aware on old releases', () => {
  const latest = caddy.validate({ files: exampleFiles() });
  assert.equal(latest.target.version, caddy.versions().latest);
  assert.deepEqual(errors(latest), []);
  assert.ok(latest.findings.some((f) => f.id === 'compat-deprecated' && /basicauth/.test(f.title)));
  const old = caddy.validate({ files: exampleFiles(), version: '2.6.0' });
  assert.ok(errors(old).some((f) => f.id === 'compat-too-new' && /basic_auth/.test(f.title) && f.since === '2.8.0'));
  assert.ok(errors(old).some((f) => /client_ip/.test(f.title)), 'client_ip matcher is 2.7+');
  assert.ok(old.findings.every((f) => f.file && f.line));
});

test('validate: injected mistakes', () => {
  const base = exampleFiles();
  const inject = (find, repl) => [{ ...base[0], content: base[0].content.replace(find, repl) }, base[1]];
  const typo = caddy.validate({ files: inject('encode zstd gzip', 'encode zstd gzip\n\treverse_prxy 10.0.0.9:80') });
  const u = errors(typo).find((f) => f.id === 'compat-unknown-directive');
  assert.ok(u && /reverse_proxy/.test(u.fix), 'did-you-mean');
  const sub = caddy.validate({ files: inject('lb_policy least_conn', 'lb_policy least_conn\n\t\tlb_try_duraton 5s') });
  assert.ok(errors(sub).some((f) => f.id === 'compat-unknown-subdirective' && /lb_try_duration/.test(f.fix)));
  const tooNew = caddy.validate({ files: inject('encode zstd gzip', 'encode zstd gzip\n\tfs mystore'), version: '2.6.4' });
  assert.ok(errors(tooNew).some((f) => f.id === 'compat-too-new' && /"fs"/.test(f.title)));
  const plugin = caddy.validate({ files: inject('encode zstd gzip', 'encode zstd gzip\n\trate_limit {\n\t\tzone z {\n\t\t\tkey {remote_host}\n\t\t\tevents 10\n\t\t\twindow 1s\n\t\t}\n\t}') });
  assert.ok(errors(plugin).some((f) => f.id === 'compat-unordered-directive' && /rate_limit/.test(f.title)));
  assert.ok(plugin.findings.some((f) => f.id === 'compat-third-party'));
  const ordered = caddy.validate({ files: inject('email ops@example.com', 'email ops@example.com\n\torder rate_limit before basic_auth').map((f, i) => (i ? f : { ...f, content: f.content.replace('encode zstd gzip', 'encode zstd gzip\n\trate_limit {\n\t}') })) });
  assert.ok(!ordered.findings.some((f) => f.id === 'compat-unordered-directive'), 'order global option makes it legal');
  const syntax = caddy.validate({ files: [{ name: 'Caddyfile', content: 'a.example.com {\n\treverse_proxy 10.0.0.1:80 { lb_policy first\n\t}\n' }] });
  assert.ok(errors(syntax).some((f) => f.id === 'syntax-caddy' && /same line/.test(f.title)));
  assert.ok(errors(syntax).some((f) => f.id === 'syntax-caddy' && /Unclosed/.test(f.title)));
  const misc = caddy.validate({ files: [{ name: 'Caddyfile', content: '{\n\temal a@b.c\n}\nexample.com:99999 {\n\treverse_proxy @gone 10.0.0.1:80 {\n\t\tlb_policy round_robbin\n\t}\n\t@m {\n\t\tpaht /x\n\t}\n}\n' }] });
  for (const id of ['compat-unknown-option', 'caddy-bad-address', 'caddy-undefined-matcher', 'compat-bad-arguments', 'compat-unknown-matcher']) assert.ok(errors(misc).some((f) => f.id === id), `missing ${id}`);
  assert.ok(errors(misc).find((f) => f.id === 'compat-unknown-option').fix.includes('email'));
});

test('Config Doctor: proposes the expected rewrites and is idempotent', () => {
  const r = caddy.improve({ files: exampleFiles() });
  const rules = new Set(r.changes.map((c) => c.rule));
  for (const id of ['caddy-encode', 'caddy-security-headers', 'caddy-lb-retry', 'caddy-passive-health', 'caddy-active-health', 'caddy-basic-auth-rename', 'caddy-log', 'caddy-file-browse', 'caddy-header-up-default', 'caddy-admin-local', 'caddy-tls-verify', 'caddy-zstd']) assert.ok(rules.has(id), `missing ${id}`);
  assert.ok(r.changes.every((c) => c.key && c.category && c.severity && c.title && c.why && Array.isArray(c.ops)));
  const out = r.render((c) => c.on);
  assert.ok(out[0].content.includes('# ---- snippets'), 'comments preserved');
  assert.ok(out[0].content.includes('basic_auth {') && !/\bbasicauth\b/.test(out[0].content.replace(/#.*$/gm, '')));
  const again = caddy.improve({ files: out });
  assert.deepEqual(again.changes.filter((c) => c.auto && c.on).map((c) => c.rule), []);
  const all = r.render(() => true);
  assert.deepEqual(caddy.improve({ files: all }).changes.filter((c) => c.auto).map((c) => c.rule), []);
  assert.deepEqual(errors(caddy.validate({ files: all })), [], 'rewritten config still validates');
  // an older target: no basic_auth rename, no health_passes
  const old = caddy.improve({ files: exampleFiles(), version: '2.7.6' });
  assert.ok(!old.changes.some((c) => c.rule === 'caddy-basic-auth-rename'));
  assert.ok(!old.changes.some((c) => c.ops.some((o) => /health_passes/.test(o.text || ''))));
  // a config without a global block gets one
  const bare = caddy.improve({ files: [{ name: 'Caddyfile', content: 'a.example.com {\n\treverse_proxy 10.0.0.1:80 10.0.0.2:80\n}\n' }] });
  const bareOut = bare.render((c) => c.on)[0].content;
  assert.match(bareOut, /^\{\n\tservers \{\n\t\ttimeouts \{/);
  assert.match(bareOut, /reverse_proxy 10\.0\.0\.1:80 10\.0\.0\.2:80 \{\n\t\tlb_try_duration 5s\n\t\tfail_duration 30s\n\t\}/);
  assert.deepEqual(errors(caddy.validate({ files: [{ name: 'Caddyfile', content: bareOut }] })), []);
});

test('Config Builder: EXAMPLE_SPEC parses, validates (latest and 2.7.6), audits and improves cleanly', () => {
  for (const version of [undefined, '2.7.6']) {
    const b = caddy.build({ ...EXAMPLE_SPEC, version });
    assert.equal(b.files[0].name, 'Caddyfile');
    const p = caddy.parseFiles(b.files);
    const shop = fe(p, 'shop.example.com, www.shop.example.com');
    assert.deepEqual(shop.routes.map((x) => x.target), ['static', 'api', 'web'].map((n) => p.sections.find((s) => s.type === 'backend' && s.servers.length && s.servers[0].address === EXAMPLE_SPEC.pools.find((q) => q.name === n).servers[0].address).name));
    assert.equal(shop.routes[1].transforms[0].action, 'strip-prefix');
    assert.deepEqual(errors(caddy.validate({ files: b.files, version })), [], `validate ${version}`);
    assert.deepEqual(caddy.audit(p.sections, { notes: p.notes }).filter((f) => f.severity === 'error'), []);
    assert.deepEqual(caddy.improve({ files: b.files, version }).changes.filter((c) => c.auto && c.severity === 'high'), []);
    assert.ok(b.unsupported.some((u) => /rate limit/i.test(u) && /caddy-ratelimit/.test(u)));
    assert.ok(b.unsupported.some((u) => /backup/.test(u)));
    assert.match(b.files[0].content, /lb_policy cookie/);
    assert.match(b.files[0].content, /tls \/etc\/ssl\/shop\/fullchain\.pem \/etc\/ssl\/shop\/privkey\.pem/);
    assert.match(b.files[0].content, /max_size 10MB/);
  }
});

test('Config Builder: ACME, websocket, basic auth and a redirect-only site; version-aware output', () => {
  const hash = `$2y$10$${'a'.repeat(53)}`;
  const spec = {
    sites: [
      { name: 'app', hosts: ['app.example.com'], tls: { mode: 'acme', email: 'ops@example.com' }, defaultPool: 'web', websocket: true, basicAuth: { realm: 'Team', users: [{ user: 'alice', hash }] }, routes: [{ path: '/v1/', pool: 'web', rewriteTo: '/api/v1/' }] },
      { name: 'old', hosts: ['old.example.com'], tls: { mode: 'acme' }, redirectTo: 'https://app.example.com/' },
      { name: 'plain', hosts: ['intranet.local'], tls: { mode: 'none' }, defaultPool: 'web' },
    ],
    pools: [{ name: 'web', balance: 'roundrobin', servers: [{ address: '10.0.0.1:8080', weight: 3 }, { address: '10.0.0.2:8080', weight: 1 }], healthCheck: { path: '/hz' } }],
  };
  const b = caddy.build(spec);
  const c = b.files[0].content;
  assert.match(c, /email ops@example\.com/);
  assert.match(c, /basic_auth bcrypt Team \{\n\t\talice \$2y\$10\$a+\n/);
  assert.match(c, /redir https:\/\/app\.example\.com\{uri\} 301/);
  assert.match(c, /lb_policy weighted_round_robin 3 1/);
  assert.match(c, /http:\/\/intranet\.local \{/);
  assert.ok(b.notes.some((n) => /WebSockets/.test(n)));
  const p = caddy.parseFiles(b.files);
  assert.ok(fe(p, 'old.example.com').routes[0].transforms[0].action === 'redirect');
  assert.deepEqual(fe(p, 'app.example.com').routes[0].transforms.map((t) => t.action), ['strip-prefix', 'set-path']);
  assert.deepEqual(errors(caddy.validate({ files: b.files })), []);
  // Caddy 2.5: basicauth spelling, base64 hashes, no weighted policy, no health_passes
  const old = caddy.build({ ...spec, version: '2.5.0' });
  const oc = old.files[0].content;
  assert.match(oc, /basicauth bcrypt Team/);
  assert.ok(oc.includes(Buffer.from(hash).toString('base64')));
  assert.ok(!/weighted_round_robin|health_passes/.test(oc));
  assert.ok(old.unsupported.some((u) => /weights/.test(u)));
  assert.deepEqual(errors(caddy.validate({ files: old.files, version: '2.5.0' })), []);
  assert.throws(() => caddy.build({ sites: [] }), /Add at least one site/);
});

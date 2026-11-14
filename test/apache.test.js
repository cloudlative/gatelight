'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const apache = require('../src/products/apache');
const { lex, redact } = require('../src/products/apache/parse');
const kb = require('../src/kb/apache.json');
const { parseModule, sinceFromCompat, releasedFrom } = require('../tools/kb/apache');

const DEB = path.join(__dirname, '..', 'examples', 'apache');
const RHEL = path.join(__dirname, '..', 'examples', 'apache-rhel');
const readTree = (dir) => { const out = []; (function w(d) { for (const f of fs.readdirSync(d).sort()) { const p = path.join(d, f); if (fs.statSync(p).isDirectory()) w(p); else out.push({ name: path.relative(dir, p).split(path.sep).join('/'), content: fs.readFileSync(p, 'utf8') }); } })(dir); return out; };
const fe = (r, name) => r.sections.find((s) => s.type === 'frontend' && s.name === name);
const be = (r, name) => r.sections.find((s) => s.type === 'backend' && s.name === name);
const ids = (f) => new Set(f.map((x) => x.id));

test('contract surface', () => {
  for (const k of ['type', 'name', 'short', 'labels', 'defaultFile', 'example', 'fileFormats', 'detect', 'parseFiles', 'loadPath', 'redact', 'audit', 'versions', 'validate', 'improve', 'flow', 'live', 'logs', 'build']) assert.ok(apache[k] !== undefined, k);
  assert.equal(apache.type, 'apache');
  assert.ok(fs.existsSync(apache.example));
  assert.ok(fs.existsSync(apache.examples.rhel));
  assert.equal(apache.flow.defaultPort('https'), 443);
  assert.equal(apache.flow.defaultPort('http'), 80);
  assert.equal(apache.flow.defaultPort('ajp'), 8009);
});

test('lexer: continuation lines, quotes, comments, sections', () => {
  const L = lex('# c\nProxyPass "/a b" \\\n   http://x/ retry=0\n<VirtualHost *:80>\n</VirtualHost>\n');
  assert.equal(L[0].kind, 'comment');
  assert.equal(L[1].name, 'ProxyPass'); assert.deepEqual(L[1].args, ['/a b', 'http://x/', 'retry=0']); assert.equal(L[1].line, 2); assert.equal(L[1].endLine, 3);
  assert.equal(L[2].kind, 'open'); assert.equal(L[2].name, 'VirtualHost'); assert.deepEqual(L[2].args, ['*:80']);
  assert.equal(L[3].kind, 'close');
});

test('Debian layout: apache2.conf, mods-enabled, ports.conf, envvars, sites-enabled', () => {
  const r = apache.loadPath(path.join(DEB, 'apache2.conf'), DEB);
  const g = r.sections.find((s) => s.type === 'global');
  assert.equal(g.layout, 'debian');
  assert.ok(g.loadedModules.includes('proxy_balancer_module'), 'LoadModule lines from mods-enabled/*.load');
  assert.ok(r.files.some((f) => f.name === 'sites-enabled/shop.conf'));
  assert.ok(r.notes.some((n) => /Layout: Debian/.test(n.msg) && /envvars/.test(n.msg)));
  // ${APACHE_LOG_DIR} from envvars (with $SUFFIX dropped)
  assert.ok(g.directives.some((d) => d.keyword === 'ErrorLog' && d.args[0] === '/var/log/apache2/error.log'));
  assert.deepEqual(g.listens.map((l) => l.address), ['*:80', '127.0.0.1:8081', '*:443']);

  const shop = fe(r, 'shop.example.com:443');
  assert.deepEqual(shop.serverNames, ['shop.example.com', 'www.shop.example.com']);
  assert.equal(shop.binds[0].address, '*:443'); assert.equal(shop.binds[0].ssl, true);
  // evaluation order: RewriteRule [P] (mod_rewrite first), Location ProxyPass (last Location first), inherited main-server
  // ProxyPass "!" before the vhost's own list, then the vhost ProxyPass list in file order
  assert.deepEqual(shop.routes.map((x) => x.target), ['10.0.4.40:8080', '10.0.6.60:8081', '10.0.5.50:3000', null, 'api', null, 'web']);
  const [rw, ws, reports, acme, api, stat, web] = shop.routes;
  assert.equal(rw.directive, 'RewriteRule'); assert.deepEqual(rw.matchers.find((m) => m.field === 'Path'), { field: 'Path', op: 'matches', values: ['^/old-shop/(.*)$'], negated: false });
  assert.deepEqual(rw.transforms[0].args, ['^/old-shop/(.*)$', '/shop/$1']);
  assert.ok(ws.inLocation); assert.equal(ws.passUrl, 'ws://10.0.6.60:8081/ws/');
  assert.equal(reports.passUrl, 'http://reports:***@10.0.5.50:3000/', 'credentials masked');
  assert.deepEqual(reports.transforms.map((t) => t.action), ['strip-prefix']);
  assert.ok(acme.terminal && acme.inherited); assert.equal(acme.paths[0], '/.well-known/acme-challenge/');
  assert.deepEqual(api.matchers, [{ field: 'Host', op: 'is', values: ['shop.example.com', 'www.shop.example.com'], negated: false }, { field: 'Path', op: 'begins with', values: ['/api/'], negated: false }]);
  assert.equal(api.match, 'Host is one of shop.example.com, www.shop.example.com and path begins with /api/');
  assert.deepEqual(api.transforms[0], { action: 'replace-path-regex', args: ['^/api/(.*)$', '/v2/$1'], line: api.line, text: 'Prefix /api/ is replaced by /v2/' });
  assert.ok(stat.terminal && stat.exclusion);
  assert.equal(web.passUrl, 'balancer://web/'); assert.deepEqual(web.transforms, []);
  assert.deepEqual(shop.routes.map((x) => x.priority), [1, 2, 3, 4, 5, 6, 7]);

  const http = fe(r, 'shop.example.com:80');
  assert.ok(http.routes[0].terminal); assert.equal(http.routes[0].transforms[0].action, 'redirect'); assert.equal(http.routes[0].transforms[0].args[0], '301');
  const legacy = fe(r, 'legacy.example.com:80');
  const php = legacy.routes.find((x) => x.target === '127.0.0.1:9000');
  assert.equal(php.matchers[1].op, 'matches'); assert.deepEqual(php.transforms[0].args, ['^/app/(.*\\.php)$', '/var/www/legacy/$1']);
  assert.ok(legacy.routes.some((x) => x.terminal && x.transforms[0].action === 'redirect' && x.transforms[0].args[1] === 'https://docs.example.com/'));

  const web2 = be(r, 'web');
  assert.equal(web2.balance, 'bybusyness'); assert.equal(web2.sticky, true);
  assert.deepEqual(web2.servers.map((s) => [s.name, s.weight, s.backup, s.check, s.route]), [['10.0.1.11:8080', 2, false, true, 'web1'], ['10.0.1.12:8080', null, false, true, 'web2'], ['10.0.1.13:8080', null, true, false, 'web3']]);
  assert.deepEqual(web2.healthCheck, { method: 'GET', path: '/healthz', interval: 10, passes: 2, fails: 3, expr: null });
  assert.equal(be(r, 'api').healthCheck, null);
  for (const n of ['127.0.0.1:9000', '10.0.4.40:8080', '10.0.6.60:8081', '10.0.5.50:3000']) assert.equal(be(r, n).implicit, true, n);
  assert.equal(be(r, '10.0.6.60:8081').servers[0].scheme, 'ws');
  // the Debian main-server <Location /server-status> (mods-enabled/status.conf) is visible in every virtual host
  assert.ok(shop.locations.some((l) => l.path === '/server-status' && l.inherited));
});

test('RHEL layout: conf/httpd.conf with ServerRoot, conf.modules.d and conf.d', () => {
  const r = apache.loadPath(path.join(RHEL, 'conf', 'httpd.conf'), RHEL);
  const g = r.sections.find((s) => s.type === 'global');
  assert.equal(g.layout, 'rhel');
  assert.ok(g.loadedModules.includes('proxy_hcheck_module') && g.loadedModules.includes('ssl_module'));
  assert.deepEqual(g.listens.map((l) => l.address), ['*:80', '*:443']);
  const app = fe(r, 'app.example.com:443');
  assert.deepEqual(app.routes.map((x) => x.target), ['app']);
  assert.equal(be(r, 'app').servers.length, 2);
  assert.ok(fe(r, 'app.example.com:80').routes[0].terminal);
  const f = apache.audit(r.sections, { notes: r.notes });
  assert.ok(ids(f).has('apache-selinux-proxy'), 'SELinux boolean hint on the RHEL layout');
  assert.ok(!f.some((x) => x.severity === 'error'));
  // same model kind as Debian
  const d = apache.loadPath(path.join(DEB, 'apache2.conf'), DEB);
  for (const s of [...r.sections, ...d.sections]) assert.ok(['global', 'frontend', 'backend'].includes(s.type));
});

test('parseFiles: uploaded trees resolve includes among the files only', () => {
  const r = apache.parseFiles(readTree(DEB));
  assert.ok(fe(r, 'shop.example.com:443'));
  assert.equal(r.mainFile, 'apache2.conf');
  assert.equal(r.sections.find((s) => s.type === 'global').layout, 'debian');
  assert.ok(r.files.every((f) => !/s3cretpass|s3cr3t-token/.test(f.raw)), 'redacted');
  const rh = apache.parseFiles(readTree(RHEL).map((f) => ({ ...f, name: `httpd/${f.name}` })));
  assert.equal(rh.sections.find((s) => s.type === 'global').layout, 'rhel');
  assert.ok(fe(rh, 'app.example.com:443'));
  // sites-available only (no sites-enabled folder uploaded): accepted with a note
  const files = readTree(DEB).map((f) => ({ ...f, name: f.name.replace(/^sites-enabled\//, 'sites-available/') }));
  const r2 = apache.parseFiles(files);
  assert.ok(fe(r2, 'shop.example.com:443'));
  assert.ok(r2.notes.some((n) => /sites-available/.test(n.msg)));
  // without envvars the Debian defaults are used, with a note
  const r3 = apache.parseFiles(readTree(DEB).filter((f) => f.name !== 'envvars'));
  assert.ok(r3.notes.some((n) => /envvars/.test(n.msg) && /APACHE_LOG_DIR=\/var\/log\/apache2/.test(n.msg)));
  assert.ok(r3.sections[0].directives.some((d) => d.keyword === 'ErrorLog' && d.args[0] === '/var/log/apache2/error.log'));
});

test('loadPath: follows sites-enabled symlinks inside the root, refuses links and includes outside it', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-apache-'));
  const root = path.join(tmp, 'apache2'); fs.mkdirSync(path.join(root, 'sites-available'), { recursive: true }); fs.mkdirSync(path.join(root, 'sites-enabled'));
  fs.writeFileSync(path.join(root, 'apache2.conf'), 'Listen 80\nIncludeOptional sites-enabled/*.conf\nInclude /etc/passwd\n');
  fs.writeFileSync(path.join(root, 'sites-available', 'a.conf'), '<VirtualHost *:80>\nServerName a.example.com\nProxyPass / http://10.0.0.1:8080/\nProxyPassReverse / http://10.0.0.1:8080/\n</VirtualHost>\n');
  fs.writeFileSync(path.join(tmp, 'outside.conf'), '<VirtualHost *:80>\nServerName evil.example.com\n</VirtualHost>\n');
  fs.symlinkSync('../sites-available/a.conf', path.join(root, 'sites-enabled', 'a.conf'));
  fs.symlinkSync(path.join(tmp, 'outside.conf'), path.join(root, 'sites-enabled', 'b.conf'));
  const r = apache.loadPath(path.join(root, 'apache2.conf'), root);
  assert.ok(fe(r, 'a.example.com:80'));
  assert.ok(!r.sections.some((s) => s.name && s.name.startsWith('evil')));
  assert.ok(r.notes.some((n) => /outside the config root/.test(n.msg)));
  assert.ok(!r.files.some((f) => /passwd/.test(f.name)));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('Define / ${VAR}, IfDefine negation, main server frontend without virtual hosts', () => {
  const r = apache.parseFiles([{ name: 'httpd.conf', content: 'Define BACK 10.0.0.9:8080\nListen 8080\nServerName api.local\n<IfDefine !BACK>\nProxyPass /never http://1.2.3.4/\n</IfDefine>\nProxyPass /api/ http://${BACK}/\nProxyPassReverse /api/ http://${BACK}/\n' }]);
  const m = r.sections.find((s) => s.type === 'frontend');
  assert.equal(m.main, true); assert.equal(m.name, 'api.local:8080');
  assert.deepEqual(m.routes.map((x) => x.target), ['10.0.0.9:8080']);
  assert.deepEqual(m.routes[0].transforms.map((t) => [t.action, ...t.args]), [['strip-prefix', '/api']]);
});

test('RewriteCond [OR] splits into one route per alternative; Host and Header matchers', () => {
  const r = apache.parseFiles([{ name: 'httpd.conf', content: '<VirtualHost *:80>\nServerName a.example.com\nRewriteEngine On\nRewriteCond %{HTTP_HOST} ^b\\. [NC,OR]\nRewriteCond %{HTTP:X-Beta} =1\nRewriteRule ^/(.*)$ http://10.0.0.2:80/$1 [P]\n</VirtualHost>\n' }]);
  const routes = r.sections.find((s) => s.type === 'frontend').routes;
  assert.equal(routes.length, 2);
  assert.ok(routes[0].matchers.some((m) => m.field === 'Host' && m.op === 'matches' && m.values[0] === '^b\\.'));
  assert.ok(routes[1].matchers.some((m) => m.field === 'Header' && m.name === 'X-Beta' && m.op === 'is'));
});

test('redaction', () => {
  const t = redact('BalancerMember http://u:pw@10.0.0.1:80\nAuthLDAPBindPassword hunter2\nRequestHeader set Authorization "Basic abc"\nSetEnv API_TOKEN xyz\nHeader add Set-Cookie "ROUTEID=.%{BALANCER_WORKER_ROUTE}e; path=/"\nSSLCertificateKeyFile /etc/ssl/k.pem\nDBDParams "host=db user=a password=secret"');
  assert.ok(!/pw@|hunter2|Basic abc|xyz|password=secret/.test(t), t);
  assert.ok(/ROUTEID=\.%\{BALANCER_WORKER_ROUTE\}e/.test(t), 'templates are not secrets');
  assert.ok(/SSLCertificateKeyFile \/etc\/ssl\/k\.pem/.test(t), 'paths stay');
  assert.equal(t.split('\n').length, 7);
});

test('audit on the Debian example', () => {
  const r = apache.loadPath(path.join(DEB, 'apache2.conf'), DEB);
  const f = apache.audit(r.sections, { notes: r.notes });
  const got = ids(f);
  for (const id of ['apache-indexes', 'apache-server-tokens', 'apache-server-signature', 'apache-weak-tls', 'apache-no-healthcheck', 'apache-orphan-balancer', 'apache-single-member', 'apache-inline-secret', 'apache-no-proxypassreverse', 'apache-status-open']) assert.ok(got.has(id), id);
  assert.ok(!got.has('apache-trace-enable'), 'Debian security.conf sets TraceEnable Off');
  assert.ok(!got.has('apache-sticky-config'), 'ROUTEID cookie is set with mod_headers');
  assert.ok(f.every((x) => x.docs && x.docs.startsWith('https://httpd.apache.org/docs/2.4/')), 'every finding cites the docs');
  assert.ok(f.find((x) => x.id === 'apache-no-proxypassreverse').title.includes('/reports/'));
});

test('audit: structural rules on small configs', () => {
  const run = (c) => { const r = apache.parseFiles([{ name: 'httpd.conf', content: c }]); return apache.audit(r.sections, { notes: r.notes }); };
  let f = run('ProxyRequests On\nListen 80\n<VirtualHost *:80>\nServerName a\nProxyPass / balancer://nope/\n</VirtualHost>\n<VirtualHost *:80>\nServerName a\n</VirtualHost>\n<Proxy balancer://empty>\n</Proxy>\n');
  assert.ok(ids(f).has('apache-open-proxy') && ids(f).has('apache-undefined-balancer') && ids(f).has('apache-duplicate-servername') && ids(f).has('apache-empty-balancer'));
  assert.equal(f.find((x) => x.id === 'apache-open-proxy').severity, 'error');
  f = run('<VirtualHost *:443>\nServerName s.example.com\nSSLEngine on\nSSLProtocol all\n</VirtualHost>\n<VirtualHost *:80>\nServerName s.example.com\nProxyPass /api /x\nProxyPass / http://10.0.0.1/\nProxyPass /api/ http://10.0.0.2/\n</VirtualHost>\n');
  assert.ok(ids(f).has('apache-ssl-no-cert') && ids(f).has('apache-weak-tls') && ids(f).has('apache-no-http-redirect') && ids(f).has('apache-proxypass-shadowed'));
  assert.equal(f.find((x) => x.id === 'apache-weak-tls').severity, 'error', 'SSLv3 through "all"');
  f = run('LoadModule proxy_module m.so\n<VirtualHost *:80>\nProxyPass /a/ http://10.0.0.1:8080\n</VirtualHost>\n');
  assert.ok(ids(f).has('apache-module-missing') && ids(f).has('apache-proxypass-slash'));
  // live drift: a member only the running server knows
  const r = apache.parseFiles([{ name: 'httpd.conf', content: '<Proxy balancer://p>\nBalancerMember http://10.0.0.1:80\n</Proxy>\nProxyPass / balancer://p/\n' }]);
  f = apache.audit(r.sections, { rows: [{ proxy: 'p', name: '10.0.0.9:80', kind: 'server' }] });
  assert.ok(ids(f).has('apache-live-drift'));
});

test('knowledge base: built from the official docs at release tags', () => {
  assert.equal(kb.product, 'apache');
  assert.ok(kb.versions.length > 50 && kb.versions[0] === '2.4.0' && kb.versions.includes('2.4.62'));
  assert.ok(!kb.versions.includes('2.4.8') && !kb.versions.includes('2.4.30'), '"(not released)" tags are excluded');
  assert.ok(Object.keys(kb.directives).length > 600);
  assert.equal(kb.directives.Protocols[0].since, '2.4.17');
  assert.equal(kb.directives.ProxyHCExpr[0].since, '2.4.21');
  assert.equal(kb.directives.MDContactEmail[0].since, '2.4.42');
  assert.equal(kb.directives.ProxyPass[0].since, undefined, 'parameter-only compatibility notes do not date the directive');
  assert.equal(kb.directives.ProxyPass[0].ctx, 'svd');
  assert.equal(kb.directives.ProxyPass[0].docs, 'https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxypass');
  assert.deepEqual(kb.directives.ProxyPreserveHost[0].vals, ['on', 'off']);
  assert.equal(kb.lifecycle.SSLMutex.kind, 'removed');
  assert.equal(kb.params.hcmethod.since, '2.4.21');
  assert.ok(fs.statSync(path.join(__dirname, '..', 'src', 'kb', 'apache.json')).size < 1024 * 1024);
  // builder helpers
  assert.equal(sinceFromCompat('Available in Apache HTTP Server 2.4.17, with a kernel supporting SO_REUSEPORT'), '2.4.17');
  assert.equal(sinceFromCompat('Unix Domain Socket (UDS) support added in 2.4.7'), null);
  assert.equal(sinceFromCompat('Available in version 2.2 and later'), null);
  assert.deepEqual(releasedFrom('Changes with Apache 2.4.3\nChanges with Apache 2.4.2 (not released)\nChanges with Apache 2.4.1\n', ['2.4.1', '2.4.2', '2.4.3']), ['2.4.1', '2.4.3']);
  const m = parseModule('<modulesynopsis><name>mod_x</name><status>Extension</status><identifier>x_module</identifier><compatibility>Available in 2.4.30 and later</compatibility><directivesynopsis><name>XOn</name><syntax>XOn On|Off</syntax><default>XOn Off</default><contextlist><context>server config</context><context>virtual host</context></contextlist></directivesynopsis></modulesynopsis>', 'mod_x.xml');
  assert.deepEqual([m.meta.since, m.dirs[0].ctx, m.dirs[0].vals], ['2.4.30', 'sv', ['on', 'off']]);
});

test('versions()', () => {
  const v = apache.versions();
  assert.equal(v.list[0], kb.latest); assert.equal(v.latest, kb.latest); assert.ok(v.source.includes('github.com/apache/httpd'));
});

test('validate: the examples have no errors (latest, 2.4.41)', () => {
  for (const dir of [DEB, RHEL]) for (const version of [undefined, '2.4.41']) {
    const r = apache.validate({ files: readTree(dir), version });
    assert.ok(r.target.version && r.kb.latest);
    const errors = r.findings.filter((f) => f.severity === 'error');
    assert.deepEqual(errors, [], `${dir} ${version}`);
  }
  const d = apache.validate({ files: readTree(DEB) });
  assert.ok(d.findings.some((f) => f.id === 'compat-deprecated' && /Order/.test(f.title)), 'mod_access_compat');
});

test('validate: injected mistakes', () => {
  const base = readTree(DEB);
  const shop = base.find((f) => f.name === 'sites-enabled/shop.conf');
  shop.content = shop.content
    .replace('ProxyPreserveHost On', 'ProxyPreserveHost On\n\tProxyPreservHost On\n\tListen 9999\n\tH2EarlyHints on')
    .replace('Header always set', 'NameVirtualHost *:443\n\tHeader always set');
  const r = apache.validate({ files: base, version: '2.4.20' });
  const f = (re) => r.findings.find((x) => re.test(x.title));
  const unk = f(/Unknown directive "ProxyPreservHost"/);
  assert.equal(unk.severity, 'error'); assert.match(unk.fix, /Did you mean "ProxyPreserveHost"/);
  assert.equal(f(/"Listen" is not allowed in virtual host/).severity, 'error');
  const tooNew = f(/"H2EarlyHints" needs httpd 2\.4\.24\+/);
  assert.equal(tooNew.severity, 'error'); assert.equal(tooNew.docs, 'https://httpd.apache.org/docs/2.4/mod/mod_http2.html#h2earlyhints');
  assert.ok(f(/hcmethod" of BalancerMember needs httpd 2\.4\.21\+/), 'hcheck parameters are too new for 2.4.20');
  assert.ok(f(/NameVirtualHost/));
  const latest = apache.validate({ files: base });
  assert.ok(!latest.findings.some((x) => /H2EarlyHints/.test(x.title)), 'fine on the latest release');
  // syntax
  const s = apache.validate({ files: [{ name: 'httpd.conf', content: '<VirtualHost *:80>\n<Location /x>\n</VirtualHost>\n<Directory /y\n' }] });
  assert.ok(s.hasSyntaxErrors);
  assert.ok(s.findings.some((x) => /closes <Location>/.test(x.title)));
  assert.ok(s.findings.some((x) => /missing ">"/.test(x.title)));
  // removed / renamed / module not loaded / bad value
  const m = apache.validate({ files: [{ name: 'httpd.conf', content: 'LoadModule proxy_module modules/mod_proxy.so\nSSLMutex default\nMaxClients 10\nRequestHeader set X 1\nProxyPreserveHost Maybe\n' }] });
  assert.ok(m.findings.some((x) => x.id === 'compat-removed' && /SSLMutex/.test(x.title)));
  assert.ok(m.findings.some((x) => x.id === 'compat-deprecated' && /MaxRequestWorkers/.test(x.title)));
  assert.ok(m.findings.some((x) => x.id === 'compat-module-not-loaded' && /mod_headers/.test(x.title)));
  assert.ok(m.findings.some((x) => x.id === 'compat-bad-value'));
  // Debian: module hint uses a2enmod
  const deb = readTree(DEB).filter((f) => f.name !== 'mods-enabled/headers.load');
  const h = apache.validate({ files: deb }).findings.find((x) => x.id === 'compat-module-not-loaded');
  assert.match(h.fix, /a2enmod headers/);
});

test('improve: Config Doctor on both layouts, comments kept, idempotent', () => {
  for (const dir of [DEB, RHEL]) {
    const files = readTree(dir);
    const a = apache.improve({ files });
    assert.ok(a.changes.length > 3);
    for (const c of a.changes) { assert.ok(['high', 'medium', 'low', 'info'].includes(c.severity)); assert.ok(Array.isArray(c.ops)); }
    const out = a.render((c) => c.auto);
    const again = apache.improve({ files: out });
    assert.deepEqual(again.changes.filter((c) => c.auto).map((c) => c.title), [], `${dir}: second pass proposes no automatic change`);
    // comments survive
    for (const f of files) for (const l of f.content.split('\n').filter((x) => /^\s*#/.test(x))) assert.ok(out.find((o) => o.name === f.name).content.includes(l), l);
    assert.deepEqual(apache.validate({ files: out }).findings.filter((x) => x.severity === 'error'), []);
  }
  const a = apache.improve({ files: readTree(DEB) });
  const rules = new Set(a.changes.map((c) => c.rule));
  for (const r of ['ap-server-tokens', 'ap-ssl-protocol', 'ap-indexes', 'ap-status-restrict', 'ap-proxypassreverse', 'ap-access-compat']) assert.ok(rules.has(r), r);
  const out = a.render((c) => c.on);
  const ssl = out.find((f) => f.name === 'mods-enabled/ssl.conf').content;
  assert.match(ssl, /\tSSLProtocol -all \+TLSv1\.2 \+TLSv1\.3\n/, 'indentation kept');
  assert.match(out.find((f) => f.name === 'sites-enabled/shop.conf').content, /ProxyPassReverse http:\/\/10\.0\.5\.50:3000\//);
  assert.match(out.find((f) => f.name === 'sites-enabled/legacy.conf').content, /Require all granted/);
  // version aware: no TLS 1.3 before 2.4.36, HTTP/2 not offered before 2.4.17
  const old = apache.improve({ files: readTree(DEB), version: '2.4.10' });
  assert.ok(old.changes.find((c) => c.rule === 'ap-ssl-protocol').ops[0].text === 'SSLProtocol -all +TLSv1.2');
  assert.ok(!apache.improve({ files: readTree(RHEL), version: '2.4.16' }).changes.some((c) => c.rule === 'ap-http2'));
  // untouched input stays byte-identical
  const none = a.render(() => false);
  assert.deepEqual(none.map((f) => f.content), readTree(DEB).map((f) => f.content));
});

test('detect: Apache configs score high, other products low', () => {
  const t = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  assert.ok(apache.detect(t('examples/apache/apache2.conf')) >= 0.8);
  assert.ok(apache.detect(t('examples/apache/sites-enabled/shop.conf')) >= 0.8);
  assert.ok(apache.detect(t('examples/apache-rhel/conf/httpd.conf')) >= 0.8);
  assert.ok(apache.detect(t('examples/nginx/nginx.conf')) < 0.2);
  assert.ok(apache.detect(t('examples/haproxy/haproxy.cfg')) < 0.2);
  assert.ok(apache.detect('http:\n  routers:\n    web:\n      rule: Host(`a`)\n') < 0.2);
  assert.ok(apache.detect('example.com {\n  reverse_proxy 10.0.0.1:8080\n}\n') < 0.2);
  assert.ok(apache.detect('[entryPoints.web]\n  address = ":80"\n') < 0.2);
});

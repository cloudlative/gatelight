'use strict';
/** Static audit rules for NGINX configurations (shares the finding format of audit.js). */
const { SEVERITY_ORDER } = require('./audit');

const RULE_TITLES = {
  'nginx-undefined-upstream': 'proxy_pass to a possibly undefined upstream', 'nginx-orphan-upstream': 'Upstreams that nothing routes to',
  'nginx-empty-upstream': 'Upstreams without servers', 'nginx-single-server': 'Single-server upstreams (no redundancy)',
  'nginx-ssl-no-cert': 'ssl listeners without a certificate', 'nginx-weak-tls': 'Legacy TLS protocols enabled',
  'nginx-no-tls-protocols': 'No explicit ssl_protocols', 'nginx-stub-status-open': 'stub_status without access restriction',
  'nginx-autoindex': 'Directory listing enabled', 'nginx-alias-traversal': 'alias/location trailing-slash mismatch (path traversal)',
  'nginx-server-tokens': 'NGINX version exposed', 'nginx-duplicate-server': 'Conflicting server blocks', 'nginx-include-note': 'Include problems',
  'nginx-inline-secret': 'Secrets stored in config', 'nginx-all-backup': 'Upstreams with only backup/down servers',
  'nginx-no-http-redirect': 'HTTP listener serves content without HTTPS redirect', 'nginx-if-proxy': '`if` combined with proxy_pass',
};

function auditNginx(sections, { notes = [] } = {}) {
  const findings = [];
  const add = (f) => findings.push({ category: 'hygiene', detail: '', fix: '', ...f });
  const upstreams = sections.filter((s) => s.type === 'backend' && !s.implicit);
  const frontends = sections.filter((s) => s.type === 'frontend');
  const upstreamNames = new Set(upstreams.map((u) => u.name));
  const referenced = new Set();

  for (const n of notes) {
    add({ id: 'nginx-include-note', severity: 'info', section: 'global', file: n.file, line: 1, title: n.msg, detail: 'Part of the configuration could not be analysed.', fix: 'Mount the full config tree (including conf.d / sites-enabled) into the container.' });
  }

  for (const fe of frontends) {
    for (const r of fe.routes) {
      referenced.add(r.target);
      if (r.maybeUpstream && !upstreamNames.has(r.target)) {
        const bare = r.target.replace(/:\d+$/, '');
        add({
          id: 'nginx-undefined-upstream', severity: 'error', category: 'correctness', section: fe.name, file: r.file, line: r.line,
          title: `${r.passDirective} targets "${bare}", which is not a defined upstream`,
          detail: 'The name has no dot or explicit port and no matching `upstream` block; nginx will try to resolve it as a hostname at startup and may fail to start ("host not found in upstream").',
          fix: `Define \`upstream ${bare} { server ...; }\` or use an explicit host:port.`,
        });
      }
    }
    const sslBinds = fe.binds.filter((b) => b.ssl);
    const d = (name) => fe.directives.filter((x) => x.keyword === name);
    // a server with `ssl_reject_handshake on` refuses every handshake and needs no certificate (nginx 1.19.4+)
    if (sslBinds.length && !d('ssl_certificate').length && !d('ssl_reject_handshake').some((x) => x.args[0] === 'on')) {
      add({ id: 'nginx-ssl-no-cert', severity: 'error', category: 'correctness', section: fe.name, file: fe.file, line: fe.line, title: `Server "${fe.name}" listens with ssl but has no ssl_certificate`, detail: 'The server block may still inherit it from the http{} level, in which case ignore this.', fix: 'Add `ssl_certificate` and `ssl_certificate_key`.' });
    }
    if (sslBinds.length) {
      const protoDir = d('ssl_protocols')[0];
      if (protoDir && protoDir.args.some((p) => /^(SSLv2|SSLv3|TLSv1|TLSv1\.1)$/.test(p))) {
        add({ id: 'nginx-weak-tls', severity: 'warning', category: 'security', section: fe.name, file: protoDir.file, line: protoDir.line, title: `Legacy TLS protocols enabled: ${protoDir.args.filter((p) => /^(SSLv|TLSv1$|TLSv1\.1)/.test(p)).join(', ')}`, detail: 'TLS 1.0/1.1 are deprecated (RFC 8996) and fail most compliance scans.', fix: 'Use `ssl_protocols TLSv1.2 TLSv1.3;`.' });
      } else if (!protoDir) {
        add({ id: 'nginx-no-tls-protocols', severity: 'info', category: 'security', section: fe.name, file: fe.file, line: fe.line, title: 'No explicit ssl_protocols', detail: 'Defaults depend on the NGINX/OpenSSL version (older builds allow TLS 1.0/1.1). Could also be set in http{}.', fix: 'Set `ssl_protocols TLSv1.2 TLSv1.3;`.' });
      }
    }
    for (const dd of d('autoindex')) if (dd.args[0] === 'on') add({ id: 'nginx-autoindex', severity: 'warning', category: 'security', section: fe.name, file: dd.file, line: dd.line, title: 'Directory listing (autoindex on) is enabled', detail: 'Exposes file names under the served directory.', fix: 'Remove `autoindex on` unless intentional.' });
    for (const dd of d('proxy_set_header')) {
      if (/authorization|token|secret|api[-_]?key/i.test(dd.args[0] || '') && dd.args[1] && !/^\$/.test(dd.args[1])) {
        add({ id: 'nginx-inline-secret', severity: 'warning', category: 'security', section: fe.name, file: dd.file, line: dd.line, title: `Credential hard-coded in proxy_set_header ${dd.args[0]}`, detail: 'Secrets in config files tend to leak through repos and backups.', fix: 'Load the secret from a file / environment-templated include with restricted permissions.' });
      }
    }
    for (const loc of fe.locations || []) {
      if (loc.kind === 'stub_status') {
        const dirs = fe.directives.filter((x) => x.line >= loc.line && x.within.some((w) => w.startsWith('location') && w.includes(loc.path || '')));
        const restricted = dirs.some((x) => x.keyword === 'auth_basic' && x.args[0] !== 'off')
          || dirs.some((x) => x.keyword === 'deny' && x.args[0] === 'all')
          || dirs.some((x) => x.keyword === 'allow' && x.args[0] !== 'all');
        if (!restricted) {
          add({ id: 'nginx-stub-status-open', severity: 'error', category: 'security', section: fe.name, file: loc.file, line: loc.line, title: `stub_status at "${loc.path}" has no effective allow/deny or auth`, detail: 'Anyone who can reach this server block can read connection and request counters.', fix: 'Add `allow 127.0.0.1; deny all;` (or auth_basic).' });
        }
      }
      if (loc.kind === 'static' && loc.modifier === '' && loc.path && !loc.path.endsWith('/')) {
        const alias = fe.directives.find((x) => x.keyword === 'alias' && x.line >= loc.line && x.within.some((w) => w.startsWith('location')));
        if (alias && alias.args[0] && alias.args[0].endsWith('/')) {
          add({ id: 'nginx-alias-traversal', severity: 'error', category: 'security', section: fe.name, file: loc.file, line: loc.line, title: `location "${loc.path}" has no trailing slash but alias "${alias.args[0]}" does`, detail: 'Classic off-by-slash flaw: /files../secret may escape the aliased directory.', fix: `Make both end with a slash: \`location ${loc.path}/ { alias ${alias.args[0]}; }\`.` });
        }
      }
    }
    for (const dd of fe.directives) {
      if (dd.keyword === 'server_tokens' && dd.args[0] === 'on') add({ id: 'nginx-server-tokens', severity: 'info', category: 'security', section: fe.name, file: dd.file, line: dd.line, title: 'server_tokens on exposes the NGINX version', detail: '', fix: 'Set `server_tokens off;`.' });
    }
    // `if` + proxy_pass in same block is fragile
    const ifProxy = fe.directives.find((x) => ['proxy_pass'].includes(x.keyword) && x.within.some((w) => w.startsWith('if ')));
    if (ifProxy) add({ id: 'nginx-if-proxy', severity: 'info', category: 'reliability', section: fe.name, file: ifProxy.file, line: ifProxy.line, title: 'proxy_pass inside `if` block', detail: '`if` in location context has well-known pitfalls ("If is evil").', fix: 'Prefer `map` + variable, or separate location blocks.' });
    // HTTP-only server serving app content without redirect
    const plain = fe.binds.filter((b) => !b.ssl && !fe.isStream);
    if (plain.length && !sslBinds.length && fe.routes.length && !fe.directives.some((x) => (x.keyword === 'return' && /^30[12378]$/.test(x.args[0] || '')) || x.keyword === 'rewrite')) {
      const names = new Set(frontends.filter((o) => o !== fe && o.binds.some((b) => b.ssl)).flatMap((o) => o.serverNames || []));
      if ((fe.serverNames || []).some((n) => names.has(n))) {
        add({ id: 'nginx-no-http-redirect', severity: 'warning', category: 'security', section: fe.name, file: fe.file, line: fe.line, title: 'Plain-HTTP server proxies content though an HTTPS server exists for the same name', detail: 'Clients can bypass TLS by using http://.', fix: 'Redirect with `return 301 https://$host$request_uri;`.' });
      }
    }
  }

  // Duplicate (listen, server_name) combos
  const seen = new Map();
  for (const fe of frontends) {
    for (const b of fe.binds) for (const n of fe.serverNames && fe.serverNames.length ? fe.serverNames : ['_']) {
      const k = `${b.address}|${n}`;
      if (seen.has(k) && n !== '_') add({ id: 'nginx-duplicate-server', severity: 'warning', category: 'correctness', section: fe.name, file: fe.file, line: fe.line, title: `Duplicate server_name "${n}" on ${b.address}`, detail: `Also defined at ${seen.get(k)}. NGINX ignores the later block ("conflicting server name").`, fix: 'Remove or merge one of the server blocks.' });
      else seen.set(k, `${fe.file}:${fe.line}`);
    }
  }

  for (const up of upstreams) {
    const live = up.servers.filter((s) => !s.backup && !s.disabled);
    if (!up.servers.length && !up.hasResolve) add({ id: 'nginx-empty-upstream', severity: 'error', category: 'reliability', section: up.name, file: up.file, line: up.line, title: `Upstream "${up.name}" has no servers`, detail: 'Requests routed to it fail with 502.', fix: 'Add `server` lines.' });
    else if (up.servers.length === 1) add({ id: 'nginx-single-server', severity: 'info', category: 'reliability', section: up.name, file: up.file, line: up.line, title: `Upstream "${up.name}" has a single server`, detail: 'No redundancy.', fix: 'Add another server or a `backup` peer.' });
    else if (up.servers.length && !live.length) add({ id: 'nginx-all-backup', severity: 'warning', category: 'reliability', section: up.name, file: up.file, line: up.line, title: `All servers of "${up.name}" are backup/down`, detail: '', fix: 'Enable at least one active server.' });
    if (!referenced.has(up.name)) add({ id: 'nginx-orphan-upstream', severity: 'warning', category: 'hygiene', section: up.name, file: up.file, line: up.line, title: `Upstream "${up.name}" is never used`, detail: 'No proxy_pass/fastcgi_pass/... (or stream proxy_pass) references it. It may be referenced only via a variable/map.', fix: 'Remove it if unused.' });
  }

  for (const f of findings) f.rule = RULE_TITLES[f.id] || f.id;
  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || ((a.line || 0) - (b.line || 0)));
  return findings;
}

module.exports = { auditNginx };

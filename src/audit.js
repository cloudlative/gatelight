'use strict';
/**
 * Static + runtime audit of a parsed HAProxy configuration.
 *
 * Every finding: { id, severity, category, title, detail, fix, section, line }
 *   severity: error | warning | info
 *   category: reliability | security | correctness | hygiene | drift
 */
const { isFrontendLike, isBackendLike, conditionAcls, redactConfig } = require('./haproxyConfig');

const WEAK_SECRETS = new Set(['admin', 'password', 'pass', '1234', '12345', '123456', 'haproxy', 'secret', 'changeme', 'test', 'root', 'admin123']);
const DEPRECATED = {
  block: 'Removed in HAProxy 2.1; use `http-request deny`.',
  reqrep: 'Legacy rewrite directive (deprecated 1.7, rejected by modern HAProxy); use `http-request replace-path/replace-header`.',
  reqirep: 'Legacy rewrite directive; use `http-request replace-header`.',
  reqadd: 'Legacy directive; use `http-request add-header`.',
  reqdel: 'Legacy directive; use `http-request del-header`.',
  reqidel: 'Legacy directive; use `http-request del-header`.',
  reqallow: 'Legacy directive; use `http-request allow`.',
  reqdeny: 'Legacy directive; use `http-request deny`.',
  rspadd: 'Legacy directive; use `http-response add-header`.',
  rspdel: 'Legacy directive; use `http-response del-header`.',
  rspidel: 'Legacy directive; use `http-response del-header`.',
  rsprep: 'Legacy directive; use `http-response replace-header`.',
  rspirep: 'Legacy directive; use `http-response replace-header`.',
};

const SEVERITY_ORDER = { error: 0, warning: 1, info: 2 };
const RULE_TITLES = {
  'duplicate-section': 'Duplicate proxy names', 'undefined-backend': 'Routes to undefined backends', 'mode-mismatch': 'TCP/HTTP mode mismatches',
  'orphan-backend': 'Backends that are never routed to', 'undefined-acl': 'ACLs used but not defined', 'unused-acl': 'ACLs defined but never used',
  'backend-no-servers': 'Backends without servers', 'duplicate-server': 'Duplicate server names', 'server-no-check': 'Servers without health checks',
  'single-server': 'Single-server backends (no redundancy)', 'only-backup': 'Backends with only backup/disabled servers', 'missing-timeout': 'Missing timeouts',
  'deprecated-directive': 'Deprecated / removed directives', 'weak-stats-credential': 'Weak stats credentials', 'inline-stats-credential': 'Plain-text stats credentials',
  'plaintext-userlist-password': 'Plain-text userlist passwords', 'userlist-password-not-hashed': 'Userlist passwords that are not hashes',
  'stats-exposed': 'Stats page exposed on all interfaces', 'tls-min-version': 'No minimum TLS version', 'drift-proxy-not-running': 'Config proxies missing from running process',
  'drift-server-not-running': 'Config servers missing from running process', 'drift-server-unknown': 'Running servers missing from config file',
};

function auditConfig(sections, { runtime } = {}) {
  const findings = [];
  const add = (f) => findings.push({ category: 'hygiene', detail: '', fix: '', ...f });

  const frontends = sections.filter(isFrontendLike);
  const backends = sections.filter(isBackendLike);
  const backendByName = new Map();
  for (const b of backends) {
    if (backendByName.has(b.name)) {
      add({
        id: 'duplicate-section', severity: 'error', category: 'correctness', section: b.name, line: b.line,
        title: `Duplicate proxy name "${b.name}"`,
        detail: `Already defined at line ${backendByName.get(b.name).line}. HAProxy rejects duplicate names within the same type.`,
        fix: 'Rename one of the sections.',
      });
    } else backendByName.set(b.name, b);
  }

  // --- Routing integrity -------------------------------------------------
  const referenced = new Set();
  for (const fe of frontends) {
    for (const r of fe.routes) {
      if (r.commented) continue;
      if (r.dynamic) continue;
      referenced.add(r.target);
      const be = backendByName.get(r.target);
      if (!be || be.type === 'frontend') {
        add({
          id: 'undefined-backend', severity: 'error', category: 'correctness', section: fe.name, line: r.line,
          title: `Route targets undefined backend "${r.target}"`,
          detail: `${fe.name} routes to "${r.target}" which has no backend/listen section.`,
          fix: `Define \`backend ${r.target}\` or correct the name.`,
        });
      } else if (fe.effective.mode === 'tcp' && be.effective.mode === 'http') {
        add({
          id: 'mode-mismatch', severity: 'error', category: 'correctness', section: fe.name, line: r.line,
          title: `TCP frontend routes to HTTP backend "${be.name}"`,
          detail: 'A tcp-mode frontend cannot be connected to an http-mode backend.',
          fix: `Set \`mode tcp\` on backend ${be.name} (or \`mode http\` on the frontend).`,
        });
      }
    }
  }

  for (const be of backends) {
    if (be.type === 'listen') continue;
    if (!referenced.has(be.name)) {
      add({
        id: 'orphan-backend', severity: 'warning', category: 'hygiene', section: be.name, line: be.line,
        title: `Backend "${be.name}" is never routed to`,
        detail: 'No active use_backend/default_backend references it. It receives no traffic from any frontend.',
        fix: 'Remove it, or add the missing routing rule (it may have been commented out).',
      });
    }
  }

  // --- ACL hygiene --------------------------------------------------------
  for (const s of sections.filter((x) => ['frontend', 'backend', 'listen'].includes(x.type))) {
    const defined = new Set(s.acls.filter((a) => !a.commented).map((a) => a.name));
    const used = new Set();
    for (const d of s.directives) {
      const idx = d.args.findIndex((t) => t === 'if' || t === 'unless');
      if (idx >= 0) {
        const cond = d.args.slice(idx).join(' ');
        for (const name of conditionAcls(cond)) {
          used.add(name);
          if (!defined.has(name) && !/^(TRUE|FALSE|HTTP|HTTP_1\.0|HTTP_1\.1|METH_[A-Z]+|HTTP_URL_[A-Z]+|REQ_CONTENT|WAIT_END|LOCALHOST|HTTP_CONTENT|RDP_COOKIE|SSL_FC.*)$/.test(name)) {
            add({
              id: 'undefined-acl', severity: 'error', category: 'correctness', section: s.name, line: d.line,
              title: `ACL "${name}" is used but not defined`,
              detail: `\`${redactConfig(d.raw)}\` references an ACL that is not declared in ${s.type} ${s.name}.`,
              fix: `Add \`acl ${name} ...\` to this section.`,
            });
          }
        }
      }
    }
    for (const a of s.acls) {
      if (!a.commented && !used.has(a.name)) {
        add({
          id: 'unused-acl', severity: 'info', category: 'hygiene', section: s.name, line: a.line,
          title: `ACL "${a.name}" is defined but never used`,
          detail: 'Dead ACLs are often leftovers from removed routing rules.',
          fix: 'Delete the ACL or wire it into a rule.',
        });
      }
    }
  }

  // --- Backend / server health -------------------------------------------
  for (const be of backends) {
    const servers = be.servers.filter((s) => !s.commented);
    const hasTemplate = servers.some((s) => s.template);
    if (be.type === 'backend' && servers.length === 0 && !hasTemplate) {
      add({
        id: 'backend-no-servers', severity: 'error', category: 'reliability', section: be.name, line: be.line,
        title: `Backend "${be.name}" has no servers`,
        detail: 'All requests routed here will receive 503.',
        fix: 'Add `server` lines (or `server-template`).',
      });
      continue;
    }
    const names = new Map();
    for (const s of servers) {
      if (names.has(s.name)) {
        add({
          id: 'duplicate-server', severity: 'error', category: 'correctness', section: be.name, line: s.line,
          title: `Duplicate server name "${s.name}" in ${be.name}`, detail: `First defined at line ${names.get(s.name)}.`,
          fix: 'Use unique server names per backend.',
        });
      }
      names.set(s.name, s.line);
    }
    const defaultCheck = Boolean(be.effective.defaultServer && be.effective.defaultServer.check);
    for (const s of servers) {
      if (!s.check && !defaultCheck && !s.disabled && !s.opts.track) {
        add({
          id: 'server-no-check', severity: 'warning', category: 'reliability', section: be.name, line: s.line,
          title: `Server "${s.name}" has no health check`,
          detail: 'Without `check`, HAProxy keeps sending traffic to the server even if it is dead.',
          fix: `Append \`check\` to the server line (and consider \`inter\`/\`fall\`/\`rise\`).`,
        });
      }
    }
    const live = servers.filter((s) => !s.backup && !s.disabled);
    if (servers.length === 1 && be.type === 'backend') {
      add({
        id: 'single-server', severity: 'info', category: 'reliability', section: be.name, line: servers[0].line,
        title: `Backend "${be.name}" has a single server`,
        detail: 'No redundancy: a failure of this server takes the whole pool down.',
        fix: 'Add a second server or a `backup` server.',
      });
    }
    if (servers.length > 0 && live.length === 0) {
      add({
        id: 'only-backup', severity: 'warning', category: 'reliability', section: be.name, line: be.line,
        title: `All servers in "${be.name}" are backup/disabled`,
        detail: 'Backup servers only receive traffic when active servers are down; with none active they take all traffic.',
        fix: 'Mark at least one server as active.',
      });
    }
  }

  // --- Timeouts -----------------------------------------------------------
  for (const s of sections.filter((x) => ['frontend', 'backend', 'listen'].includes(x.type))) {
    const t = s.effective.timeouts || {};
    const missing = [];
    if (isFrontendLike(s) && !t.client) missing.push('timeout client');
    if (isBackendLike(s) && !t.server) missing.push('timeout server');
    if (isBackendLike(s) && !t.connect) missing.push('timeout connect');
    if (missing.length) {
      add({
        id: 'missing-timeout', severity: 'warning', category: 'reliability', section: s.name, line: s.line,
        title: `${s.type} "${s.name}" is missing ${missing.join(', ')}`,
        detail: 'Without timeouts, stuck connections accumulate and exhaust maxconn.',
        fix: 'Set the missing timeouts in the section or in `defaults`.',
      });
    }
  }

  // --- Deprecated / removed directives -------------------------------------
  for (const s of sections) {
    for (const d of s.directives) {
      const key = d.keyword.replace(/^no\s+/, '');
      if (DEPRECATED[key]) {
        add({
          id: 'deprecated-directive', severity: 'warning', category: 'correctness', section: s.name, line: d.line,
          title: `Deprecated directive \`${d.keyword}\``, detail: DEPRECATED[key], fix: 'Migrate before upgrading HAProxy.',
        });
      }
    }
  }

  // --- Security -----------------------------------------------------------
  for (const s of sections) {
    for (const d of s.directives) {
      if (d.keyword === 'stats' && d.args[0] === 'auth' && d.args[1]) {
        const [user, ...rest] = d.args[1].split(':');
        const pass = rest.join(':');
        const weak = WEAK_SECRETS.has(pass.toLowerCase()) || pass.length < 8;
        add({
          id: weak ? 'weak-stats-credential' : 'inline-stats-credential',
          severity: weak ? 'error' : 'warning', category: 'security', section: s.name, line: d.line,
          title: weak ? `Weak stats password for user "${user}"` : `Stats credentials stored in plain text (user "${user}")`,
          detail: weak ? 'Password is short or on common-password lists.' : '`stats auth` stores the secret verbatim in the config file.',
          fix: 'Use a long random password, restrict file permissions (0640), and keep the config out of source control.',
        });
      }
    }
    for (const u of s.users || []) {
      if (u.passwordKind === 'insecure-password') {
        add({
          id: 'plaintext-userlist-password', severity: 'warning', category: 'security', section: s.name, line: u.line,
          title: `Plain-text password for userlist user "${u.name}"`, detail: '`insecure-password` stores the secret verbatim.',
          fix: 'Switch to `password` with a hash from `mkpasswd -m sha-512`.',
        });
      } else if (u.passwordKind === 'password' && !u.passwordHashed) {
        add({
          id: 'userlist-password-not-hashed', severity: 'error', category: 'security', section: s.name, line: u.line,
          title: `Userlist password for "${u.name}" is not a crypt(3) hash`,
          detail: '`password` expects a hash (e.g. `$6$...`). A plain-text value is a leaked secret and will not authenticate correctly.',
          fix: 'Generate a hash with `mkpasswd -m sha-512` or use `insecure-password` deliberately.',
        });
      }
    }
    if (isFrontendLike(s)) {
      const hasStats = s.directives.some((d) => d.keyword === 'stats' && ['enable', 'uri'].includes(d.args[0]));
      const hasAuth = s.directives.some((d) => d.keyword === 'stats' && d.args[0] === 'auth');
      let tlsReported = false;
      for (const b of s.binds.filter((x) => !x.commented)) {
        const exposed = b.addresses.some((a) => /^(\*|0\.0\.0\.0|:::?|\[::\])?:\d+$/.test(a) || /^\d+$/.test(a) || /^:\d+$/.test(a));
        if (hasStats && exposed && !b.ssl) {
          add({
            id: 'stats-exposed', severity: hasAuth ? 'warning' : 'error', category: 'security', section: s.name, line: b.line,
            title: `Stats page bound to all interfaces over plain HTTP (${b.addresses.join(', ')})`,
            detail: 'Credentials and operational data are sent in clear text on a publicly reachable port.',
            fix: 'Bind to a management interface (e.g. 127.0.0.1 / private IP), add `ssl crt`, and firewall the port.',
          });
        }
        if (b.ssl && !tlsReported && !b.options['ssl-min-ver'] && !b.options['no-tlsv10'] && !b.options['no-tlsv11']) {
          const globalHasMin = sections.some((g) => g.type === 'global' && g.directives.some((d) =>
            (d.keyword === 'ssl-default-bind-options' && d.args.some((a) => a === 'ssl-min-ver' || a === 'no-tlsv10' || a === 'no-tlsv11'))));
          if (!globalHasMin) {
            tlsReported = true;
            add({
              id: 'tls-min-version', severity: 'info', category: 'security', section: s.name, line: b.line,
              title: 'No minimum TLS version enforced',
              detail: 'Legacy protocols (TLS 1.0/1.1) may still be accepted.',
              fix: 'Add `ssl-min-ver TLSv1.2` to the bind line or `ssl-default-bind-options`.',
            });
          }
        }
      }
    }
  }

  // --- Runtime drift ------------------------------------------------------
  if (runtime && runtime.rows && runtime.rows.length) {
    const rt = new Map();
    for (const r of runtime.rows) {
      if (r.kind === 'server') {
        if (!rt.has(r.proxy)) rt.set(r.proxy, new Set());
        rt.get(r.proxy).add(r.name);
      }
    }
    const proxiesInRuntime = new Set(runtime.rows.map((r) => r.proxy));
    for (const s of sections.filter((x) => ['frontend', 'backend', 'listen'].includes(x.type))) {
      if (!proxiesInRuntime.has(s.name)) {
        add({
          id: 'drift-proxy-not-running', severity: 'warning', category: 'drift', section: s.name, line: s.line,
          title: `${s.type} "${s.name}" is in the file but not in the running process`,
          detail: 'The loaded config may be older than this file — pending reload, or the file belongs to a different instance.',
          fix: 'Validate with `haproxy -c -f` and reload HAProxy.',
        });
        continue;
      }
      const running = rt.get(s.name) || new Set();
      for (const srv of s.servers.filter((x) => !x.commented && !x.template)) {
        if (!running.has(srv.name)) {
          add({
            id: 'drift-server-not-running', severity: 'warning', category: 'drift', section: s.name, line: srv.line,
            title: `Server "${srv.name}" in ${s.name} is not present in the running process`,
            detail: 'Config on disk differs from what HAProxy is running.', fix: 'Reload HAProxy to apply the file.',
          });
        }
      }
      const known = new Set(s.servers.filter((x) => !x.template).map((x) => x.name));
      const hasTemplate = s.servers.some((x) => x.template);
      for (const name of running) {
        if (!known.has(name) && !hasTemplate) {
          add({
            id: 'drift-server-unknown', severity: 'info', category: 'drift', section: s.name, line: s.line,
            title: `Running server "${name}" in ${s.name} is not in the config file`,
            detail: 'Added via the runtime API or the running config is newer than this file.',
            fix: 'Persist runtime changes into the config file.',
          });
        }
      }
    }
  }

  for (const f of findings) f.rule = RULE_TITLES[f.id] || f.id;
  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || ((a.line || 0) - (b.line || 0)));
  return findings;
}

function summarize(findings) {
  const out = { error: 0, warning: 0, info: 0, total: findings.length };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

module.exports = { auditConfig, summarize, SEVERITY_ORDER };

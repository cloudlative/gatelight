'use strict';
/**
 * Config Forge: assess a HAProxy or NGINX configuration and rewrite it to current best practice.
 * Rule-based and deterministic (no network, no model): every change has a reason, a before/after, a switch,
 * and the result is checked by running the rules again on the output (it must propose nothing new).
 */
const { score, grade, diffLines, CATEGORIES } = require('./common');
const haproxy = require('./haproxy');
const nginx = require('./nginx');
const V = require('../validate/version');

const MAX_BYTES = 2 * 1024 * 1024;

// Words that start a line only in one product's configuration. HAProxy: sections and its keywords. NGINX: block names and its directives.
const HAP_LINE = /^\s*(global|defaults|frontend|backend|listen|userlist|resolvers|peers|bind|acl|use_backend|default_backend|use-server|balance|option|timeout|maxconn|stick-table|stick|tcp-request|http-request|http-response|capture|server-template|default-server|http-check|tcp-check|log-format|redirect|reqadd|rspadd|errorfile)\b/;
const NGX_LINE = /^\s*(events|http|stream|upstream|server|location|map|geo|types|worker_processes|worker_connections|error_log|access_log|log_format|server_name|listen|root|alias|index|try_files|return|rewrite|proxy_pass|proxy_set_header|proxy_redirect|proxy_http_version|proxy_[a-z_]+|fastcgi_[a-z_]+|uwsgi_[a-z_]+|add_header|more_set_headers|more_clear_headers|ssl_[a-z_]+|valid_referers|resolver|client_max_body_size|keepalive_[a-z_]+|sendfile|gzip[a-z_]*|limit_[a-z_]+|auth_basic[a-z_]*|allow|deny|include|set|if|internal|expires|charset|real_ip_header|set_real_ip_from)\b/;
function detectProduct(text) {
  const t = String(text || '');
  let hap = 0; let ngx = 0;
  for (const raw of t.split('\n')) {
    const l = raw.replace(/#.*/, '');
    if (!l.trim()) continue;
    const nginxish = /[;{}]\s*$/.test(l.trim());           // NGINX lines end in ; { or }
    if (HAP_LINE.test(l) && !/[;{]\s*$/.test(l.trim())) hap++;
    else if (NGX_LINE.test(l) && (nginxish || /\$\w+/.test(l) || !/^\s*(server|listen|http|stream|map|index|set|if|include|allow|deny|return|redirect|resolver|upstream|events|types|geo)\b/.test(l))) ngx++;
  }
  if (/^\s*(http|server|events|upstream)\s*\{/m.test(t)) ngx += 3;
  if (/^\s*(global|defaults)\s*$/m.test(t) || /^\s*(frontend|backend|listen)\s+\S+\s*$/m.test(t)) hap += 3;
  if (!hap && !ngx) return null;
  return ngx > hap ? 'nginx' : hap > ngx ? 'haproxy' : null;
}

const preview = (c) => c.ops.map((o) => (o.kind === 'add' ? { k: 'add', after: o.text } : o.kind === 'mod' ? { k: 'mod', before: o.before, after: o.text } : { k: 'del', before: o.before }));
const pub = (c, applied) => ({ key: c.key, rule: c.rule, category: c.category, severity: c.severity, title: c.title, why: c.why, section: c.section, line: c.line || null, auto: c.auto, on: c.on, applied, diff: preview(c) });
const open = (cs) => cs.filter((c) => c.on || !c.auto);

/**
 * @param {{product?:'haproxy'|'nginx', version?:string, config?:string, files?:{name:string,content:string}[], toggles?:Record<string,boolean>}} o
 */
function improveConfig(o) {
  const files = (o.files && o.files.length ? o.files : [{ name: o.product === 'nginx' ? 'nginx.conf' : 'haproxy.cfg', content: String(o.config || '') }]).map((f) => ({ name: String(f.name || 'config').slice(0, 200), content: String(f.content || '') }));
  const size = files.reduce((a, f) => a + Buffer.byteLength(f.content), 0);
  if (!size || !files.some((f) => f.content.trim())) throw Object.assign(new Error('Paste or upload a configuration first.'), { status: 400 });
  if (size > MAX_BYTES) throw Object.assign(new Error(`The configuration is ${(size / 1048576).toFixed(1)} MB; the limit is ${MAX_BYTES / 1048576} MB.`), { status: 413 });
  const product = o.product || detectProduct(files.map((f) => f.content).join('\n'));
  if (product !== 'haproxy' && product !== 'nginx') throw Object.assign(new Error('Could not tell whether this is a HAProxy or an NGINX configuration. Choose the product.'), { status: 422 });
  const version = o.version ? String(o.version).slice(0, 64) : null; const toggles = o.toggles && typeof o.toggles === 'object' ? o.toggles : {};
  const decide = (c) => (Object.prototype.hasOwnProperty.call(toggles, c.key) ? Boolean(toggles[c.key]) : c.on);

  let a; let originals; let improved;
  if (product === 'haproxy') {
    const text = files.length === 1 ? files[0].content : [...files].sort((x, y) => x.name.localeCompare(y.name)).map((f) => f.content).join('\n');
    a = haproxy.analyze(text, { version }); originals = [{ name: files.length === 1 ? files[0].name : 'haproxy.cfg', content: text }];
    const normalized = [{ name: originals[0].name, content: a.normalized }];
    const out = a.render(decide); improved = [{ name: originals[0].name, content: out }];
    a.normalizedFiles = normalized;
  } else {
    a = nginx.analyze(files, { version }); originals = files; a.normalizedFiles = a.normalized; improved = a.render(decide);
  }
  const applied = (c) => c.auto && decide(c);
  const changes = a.changes.map((c) => pub(c, applied(c)));
  // second pass on the result: whatever is still open (disabled changes, advice) is what the user has left
  const again = product === 'haproxy' ? haproxy.analyze(improved[0].content, { version }) : nginx.analyze(improved, { version });
  const before = score(open(a.changes)); const after = score(open(again.changes));
  const stillAuto = again.changes.filter((c) => c.auto && c.on).length;
  const fileOut = improved.map((f, i) => {
    const base = a.normalizedFiles[i] ? a.normalizedFiles[i].content : originals[i].content;
    const d = diffLines(base.split('\n'), f.content.split('\n'));
    return { name: f.name, original: originals[i] ? originals[i].content : '', improved: f.content, changed: d.added + d.removed > 0, formatting: base !== (originals[i] || {}).content, diff: d };
  });
  const byCat = Object.fromEntries(CATEGORIES.map((c) => [c, { total: 0, applied: 0 }]));
  changes.forEach((c) => { byCat[c.category].total++; if (c.applied) byCat[c.category].applied++; });
  const notes = [];
  if (!version) notes.push(`No version was given, so the newest supported release (${a.target}) is assumed. Pick your version to get output that is valid on it.`);
  if (product === 'haproxy' && files.length > 1) notes.push('The files were joined in name order into one configuration (the way `haproxy -f <directory>` reads them).');
  return {
    product, target: a.target, versionKnown: Boolean(version),
    score: { before, after, gradeBefore: grade(before), gradeAfter: grade(after) },
    summary: { total: changes.length, auto: changes.filter((c) => c.auto).length, applied: changes.filter((c) => c.applied).length, advice: changes.filter((c) => !c.auto).length, optional: changes.filter((c) => c.auto && !c.on).length, byCategory: byCat, stable: stillAuto === 0 },
    changes, files: fileOut, notes,
  };
}

module.exports = { improveConfig, detectProduct, MAX_BYTES, versions: () => V };

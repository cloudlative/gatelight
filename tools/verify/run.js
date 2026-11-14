#!/usr/bin/env node
'use strict';
/**
 * Verify generated and rewritten configurations with the REAL programs, not only with GateLight's own validator.
 *
 * For every product and every image version in the matrix it:
 *   1. asks the image which exact version it runs (nginx -v, haproxy -v, httpd -v, caddy version, traefik version),
 *   2. builds every spec in tools/verify/specs.js for that exact version with the Config Builder,
 *   3. takes the bundled example and Config Doctor's rewrite of it,
 *   4. runs the product's own config test inside the official image: nginx -t, haproxy -c, apachectl -t / httpd -t,
 *      caddy validate, and for Traefik (which has no check command) a short start with its log scanned for errors.
 * Certificates, keys and log directories the configs reference are created inside the container (self-signed,
 * throw-away), and host names are mapped to 127.0.0.1, so the check is about the configuration, not the machine.
 *
 *   node tools/verify/run.js [--product nginx,caddy] [--quick] [--keep] [--json report.json]
 *
 * Needs Docker. Images come from VERIFY_REGISTRY (default: public.ecr.aws/docker/library/, the AWS mirror of the
 * Docker official images, which has no anonymous pull limit). Exit code 1 when any check fails.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildConfig } = require('../../src/build');
const { improveConfig } = require('../../src/improve');
const SPECS = require('./specs');

const ROOT = path.join(__dirname, '..', '..');
const argv = process.argv.slice(2);
const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : null);
const only = opt('--product') ? opt('--product').split(',') : null;
const quick = argv.includes('--quick'); // newest image of each product only
const keep = argv.includes('--keep');
const REG = process.env.VERIFY_REGISTRY ?? 'public.ecr.aws/docker/library/';

// ------------------------------------------------------------------------------------------------ the matrix
const PRODUCTS = {
  haproxy: {
    images: ['haproxy:2.0-alpine', 'haproxy:2.4-alpine', 'haproxy:2.8-alpine', 'haproxy:3.0-alpine', 'haproxy:3.2-alpine'],
    version: "haproxy -v | head -1 | sed -E 's/.*version ([0-9]+\\.[0-9]+(\\.[0-9]+)?).*/\\1/'",
    root: '/usr/local/etc/haproxy',
    check: 'haproxy -c -dr -f /usr/local/etc/haproxy/haproxy.cfg', // -dr: an unresolvable server name is not a config error
    example: 'examples/haproxy',
  },
  nginx: {
    images: ['nginx:1.18-alpine', 'nginx:1.24-alpine', 'nginx:1.27-alpine'],
    version: "nginx -v 2>&1 | sed -E 's#.*nginx/([0-9.]+).*#\\1#'",
    root: '/etc/nginx',
    prep: 'rm -f /etc/nginx/conf.d/default.conf',
    check: 'nginx -t',
    example: 'examples/nginx',
    // the example shows NGINX Plus status zones on purpose; the official images are open source, which rejects them
    exampleFilter: (f) => ({ ...f, content: f.content.replace(/^\s*status_zone\s+[^;]*;\s*$/gm, '    # status_zone (NGINX Plus only) removed for the open-source check') }),
  },
  'apache-standalone': {
    product: 'apache', layout: 'standalone',
    images: ['httpd:2.4-alpine'],
    version: "httpd -v | sed -n -E 's#.*Apache/([0-9.]+).*#\\1#p'",
    root: '/usr/local/apache2/conf',
    check: 'httpd -t',
  },
  'apache-debian': {
    product: 'apache', layout: 'debian',
    // Canonical's apache2 image: Debian/Ubuntu packaging (apache2.conf, a2enmod, sites-available), as on a server
    images: ['ubuntu/apache2:2.4-22.04_beta', 'ubuntu/apache2:2.4-24.04_beta'],
    version: "apache2 -v | sed -n -E 's#.*Apache/([0-9.]+).*#\\1#p'",
    root: '/etc/apache2',
    // what the builder's notes tell an admin to run, then the config test
    enable: (out) => {
      const sites = out.files.map((f) => (f.name.match(/^sites-available\/(.+)\.conf$/) || [])[1]).filter(Boolean);
      const confs = out.files.map((f) => (f.name.match(/^conf-available\/(.+)\.conf$/) || [])[1]).filter(Boolean);
      return [out.modules && out.modules.length ? `a2enmod -q ${out.modules.join(' ')}` : '', ...confs.map((c) => `a2enconf -q ${c}`), ...sites.map((s) => `a2ensite -q ${s}`), 'a2dissite -q 000-default || true'].filter(Boolean).join(' && ');
    },
    check: 'apache2ctl -t',
    example: 'examples/apache',
  },
  'apache-rhel': {
    product: 'apache', layout: 'rhel',
    build: { tag: 'gatelight-verify/httpd:el9', from: 'almalinux:9-minimal', run: 'microdnf install -y httpd mod_ssl mod_http2 mod_md && microdnf clean all', pkg: 'microdnf' },
    version: "httpd -v | sed -n -E 's#.*Apache/([0-9.]+).*#\\1#p'",
    root: '/etc/httpd',
    prep: 'rm -f /etc/httpd/conf.d/welcome.conf',
    check: 'httpd -t',
    example: 'examples/apache-rhel',
  },
  caddy: {
    images: ['caddy:2.6-alpine', 'caddy:2.7-alpine', 'caddy:2.8-alpine', 'caddy:2.10-alpine'],
    version: "caddy version | sed -E 's/^v?([0-9.]+).*/\\1/'",
    root: '/etc/caddy',
    check: 'caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile',
    example: 'examples/caddy',
    exampleSkip: (name) => name.endsWith('.json'),
    // the example uses the Cloudflare DNS plugin on purpose; the official image is the standard build without plugins
    exampleFilter: (f) => ({ ...f, content: f.content.replace(/^(\s*)tls\s*\{\s*\n\s*dns\s+cloudflare\b[^\n]*\n\s*\}/gm, '$1tls internal # (dns cloudflare plugin is not in the standard build)') }),
  },
  traefik: {
    images: ['traefik:v2.11', 'traefik:v3.0', 'traefik:v3.4'],
    version: "traefik version | sed -n -E 's/^Version: *v?([0-9.]+).*/\\1/p'",
    root: '/etc/traefik',
    // Traefik has no "check config" command: start it briefly and read its log. Static errors stop it at once,
    // dynamic (file provider) errors are logged. ACME cannot reach Let's Encrypt here, so ACME errors are ignored.
    check: 'S=$(date +%s); timeout 8 traefik --configFile=/etc/traefik/traefik.yml > /tmp/t.log 2>&1; E=$(date +%s); '
      // it ran until the timeout: anything shorter means it stopped on its own (static config errors do that)
      + 'if [ $((E - S)) -lt 7 ]; then cat /tmp/t.log; echo "TRAEFIK STOPPED BY ITSELF after $((E - S))s"; exit 1; fi; '
      // only what was logged before the shutdown counts ("closed network connection" while stopping is normal)
      // colour codes around "ERR" are stripped first, or the level would never match
      + "tr -d '\\033' < /tmp/t.log | sed -E 's/\\[[0-9;]*m//g' | sed '/I have to go\\|Stopping server gracefully/,$d' > /tmp/run.log; "
      + "if grep -iE 'level=error|\"level\":\"error\"| ERR ' /tmp/run.log | grep -viE 'acme|certificate.*resolver|letsencrypt|no such host|lookup .* on|i/o timeout|dial tcp|connect: |cannot (get|obtain)|unable to obtain|providerName=docker|docker|dial unix'; then echo 'TRAEFIK LOGGED ERRORS'; exit 1; fi; echo 'traefik ran cleanly'",
    example: 'examples/traefik',
    exampleSkip: (name) => /docker-compose/.test(name),
  },
};

// ------------------------------------------------------------------------------------------------ helpers
const sh = (cmd, args, o = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...o });
function docker(args, o) { return sh('docker', args, o); }
const image = (name) => (name.startsWith('gatelight-verify/') ? name : `${REG}${name}`);
const FALLBACK = 'docker.io/library/';
const short = (t) => String(t || '').replace(/\S{160,}/g, (x) => `${x.slice(0, 60)}…`).trim();
/** Pull from VERIFY_REGISTRY, falling back to Docker Hub; returns the reference that worked, or { error }. */
function pullImage(name) {
  if (name.startsWith('gatelight-verify/')) return name;
  // "owner/image" is not an official image: Docker Hub only
  const tries = name.includes('/') ? [`docker.io/${name}`] : [...new Set([`${REG}${name}`, `${FALLBACK}${name}`])];
  let last = '';
  for (const ref of tries) {
    if (docker(['image', 'inspect', ref]).status === 0) return ref;
    const r = docker(['pull', '-q', ref]);
    if (r.status === 0) return ref;
    last = short((r.stderr || r.stdout).split('\n').slice(-1)[0]);
  }
  return { error: `could not pull ${name}: ${last}` };
}

function ensureImage(p) {
  if (!p.build) return p.images;
  const exists = docker(['image', 'inspect', p.build.tag]).status === 0;
  if (!exists) {
    // package managers fetch over plain HTTP too: reuse the HTTPS proxy for it when only that one is set
    const env = { ...process.env };
    const px = env.HTTP_PROXY || env.http_proxy || env.HTTPS_PROXY || env.https_proxy;
    if (px) { env.HTTP_PROXY = env.HTTP_PROXY || px; env.http_proxy = env.http_proxy || px; }
    const proxy = ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy'].filter((k) => env[k]).flatMap((k) => ['--build-arg', `${k}=${env[k]}`]);
    const base = pullImage(p.build.from);
    if (base.error) return base;
    const df = `FROM ${base}\nRUN ${p.build.run}\n`;
    const r = docker(['build', '-q', '--network', 'host', ...proxy, '-t', p.build.tag, '-'], { input: df });
    if (r.status !== 0) return { error: `could not build ${p.build.tag}: ${short((r.stderr || r.stdout).trim().split('\n').slice(-3).join(' '))}` };
  }
  return [p.build.tag];
}

let FIX = null;
/** One throw-away self-signed certificate (and a combined PEM, which HAProxy wants) for every path a config references. */
function fixtures() {
  if (FIX) return FIX;
  FIX = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-verify-fx-'));
  const r = sh('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=gatelight-verify', '-addext', 'subjectAltName=DNS:*.example.com,DNS:example.com,DNS:localhost',
    '-keyout', path.join(FIX, 'key.pem'), '-out', path.join(FIX, 'cert.pem')]);
  if (r.status !== 0) throw new Error(`openssl failed: ${r.stderr}`);
  fs.writeFileSync(path.join(FIX, 'combined.pem'), fs.readFileSync(path.join(FIX, 'cert.pem'), 'utf8') + fs.readFileSync(path.join(FIX, 'key.pem'), 'utf8'));
  fs.writeFileSync(path.join(FIX, 'htpasswd'), `admin:$2y$05$${'a'.repeat(53)}\n`);
  return FIX;
}

const CERT_RE = /(?:^|[\s"'=:])(\/[\w.@\/-]+\.(?:pem|crt|cer|key|der|p12|bundle))(?=[\s"';,]|$)/gm;
const DIR_RE = /(?:^|[\s"'=:])(\/(?:var\/log|var\/lib|var\/cache|run|var\/run|srv|data)\/[\w.@\/-]+)/gm;
const HOST_RE = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi;
const NOT_HOST = /\.(conf|cfg|pem|crt|key|log|html?|json|ya?ml|toml|sock|load|types|js|css|php|txt|map|lua|caddy|d|so|pid|db|ico|png|svg|xml|gz|htpasswd|bundle|der|lock|socket)$/i;

/** Shell that places the files and the throw-away fixtures inside the container. */
function prelude(p, files) {
  const text = files.map((f) => f.content).join('\n');
  const certs = [...new Set([...text.matchAll(CERT_RE)].map((m) => m[1]))];
  const dirs = [...new Set([...text.matchAll(DIR_RE)].map((m) => (/\.\w{2,5}$/.test(m[1]) ? path.posix.dirname(m[1]) : m[1])))];
  const lines = ['set -e', `mkdir -p ${p.root}`, `cp -r /gl/cfg/. ${p.root}/`];
  if (p.prep) lines.push(p.prep);
  for (const d of dirs) lines.push(`mkdir -p '${d}'`);
  for (const c of certs) {
    const src = /key/i.test(path.posix.basename(c)) ? 'key.pem' : /chain|ca[-_.]|bundle|trust/i.test(path.posix.basename(c)) ? 'cert.pem' : 'combined.pem';
    lines.push(`mkdir -p '${path.posix.dirname(c)}'`, `[ -e '${c}' ] || cp /glfx/${src} '${c}'`);
  }
  // HAProxy error pages ("errorfile 503 /etc/haproxy/errors/503.http") must exist and be a raw HTTP response
  for (const m of text.matchAll(/^\s*errorfile\s+(\d{3})\s+(\/\S+)/gm)) {
    lines.push(`mkdir -p '${path.posix.dirname(m[2])}'`, `[ -e '${m[2]}' ] || printf 'HTTP/1.0 ${m[1]} Error\\r\\nContent-Type: text/plain\\r\\n\\r\\n${m[1]}\\n' > '${m[2]}'`);
  }
  return lines.join('\n');
}
function hostArgs(files) {
  const text = files.map((f) => f.content).join('\n');
  const hosts = [...new Set([...text.matchAll(HOST_RE)].map((m) => m[1].toLowerCase()))].filter((h) => !NOT_HOST.test(h) && !/^\d+(\.\d+)+$/.test(h) && !/^(www\.)?(w3|apache|nginx|haproxy|caddyserver|traefik|letsencrypt|github)\.(org|com|io)$/.test(h)).slice(0, 200);
  return hosts.flatMap((h) => ['--add-host', `${h}:127.0.0.1`]);
}

function runCheck(p, img, files, extra = '') {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-verify-'));
  for (const f of files) { const t = path.join(work, 'cfg', f.name); fs.mkdirSync(path.dirname(t), { recursive: true }); fs.writeFileSync(t, f.content); }
  const script = `${prelude(p, files)}\n${extra ? `${extra}\n` : ''}${p.check}\n`;
  fs.writeFileSync(path.join(work, 'run.sh'), script);
  const r = docker(['run', '--rm', '--user', '0', '--network', 'none', ...hostArgs(files), '-v', `${work}:/gl:ro`, '-v', `${fixtures()}:/glfx:ro`, '--entrypoint', 'sh', img, '/gl/run.sh'], { timeout: 120000 });
  if (!keep) fs.rmSync(work, { recursive: true, force: true });
  const out = `${r.stdout || ''}${r.stderr || ''}`.trim();
  return { ok: r.status === 0, out, work: keep ? work : undefined };
}

function readTree(dir, skip) {
  const out = [];
  const walk = (d, pre) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const rel = `${pre}${e.name}`; if (e.isDirectory()) walk(path.join(d, e.name), `${rel}/`); else if (!(skip && skip(rel))) out.push({ name: rel, content: fs.readFileSync(path.join(d, e.name), 'utf8') }); } };
  walk(dir, '');
  return out;
}
const isData = (f) => /(^|\/)htpasswd(\/|$)|\.htpasswd$/.test(f.name);

/** Where the real program says the problem is: "in /etc/nginx/x.conf:27", "at /etc/caddy/Caddyfile:113", "line 69 of /…", "[/…/haproxy.cfg:12]". */
function errorLocation(all) {
  // the fatal line, not a warning before it
  const out = all.split('\n').filter((l) => /emerg|error|alert|fatal|syntax/i.test(l) && !/\[warn\]|\bwarning\b/i.test(l)).join('\n') || all;
  const m = out.match(/(?:in|at) (\/[^\s:]+):(\d+)/) || out.match(/\[(\/[^\s:\]]+):(\d+)\]/);
  if (m) return { file: m[1].split('/').pop(), line: Number(m[2]) };
  const a = out.match(/line (\d+) of (\/\S+?):?\s/);
  return a ? { file: a[2].split('/').pop(), line: Number(a[1]) } : null;
}

/** Error-level findings GateLight itself reports (validator + audit) for a set of files; with `at`, only those within a line of it. */
function gatelightErrors(product, version, files, at = null) {
  const products = require('../../src/products');
  const { validateConfig } = require('../../src/validate');
  const mod = products.get(product);
  const cfg = files.filter((f) => !isData(f));
  const out = [];
  const near = (f) => !at || (f.line != null && Math.abs(Number(f.line) - at.line) <= 1 && (!f.file || String(f.file).split('/').pop() === at.file));
  try { for (const f of validateConfig({ product, version, files: cfg, config: product === 'haproxy' ? cfg[0].content : undefined }).findings) if (f.severity === 'error' && near(f)) out.push(`${f.title} (line ${f.line})`); } catch (e) { out.push(`validator: ${e.message}`); }
  try { const parsed = mod.parseFiles(cfg); for (const f of mod.audit(parsed.sections, { notes: parsed.notes || [], rows: [], files: parsed.files })) if (f.severity === 'error' && near(f)) out.push(`${f.title} (line ${f.line})`); } catch (e) { out.push(`audit: ${e.message}`); }
  return out;
}

// ------------------------------------------------------------------------------------------------ run
function main() {
  if (docker(['info']).status !== 0) { console.error('Docker is not available: start the Docker daemon first.'); process.exit(2); }
  const results = [];
  for (const [key, p] of Object.entries(PRODUCTS)) {
    const product = p.product || key;
    if (only && !only.includes(key) && !only.includes(product)) continue;
    let imgs = ensureImage(p);
    if (imgs.error) { results.push({ key, image: '-', case: 'image', ok: false, out: imgs.error }); continue; }
    if (quick) imgs = imgs.slice(-1);
    for (const img of imgs) {
      const ref = pullImage(img);
      if (ref.error) { results.push({ key, image: img, case: 'pull', ok: false, out: ref.error }); continue; }
      const v = docker(['run', '--rm', '--entrypoint', 'sh', ref, '-c', p.version]);
      const version = (v.stdout || '').trim().split('\n')[0] || null;
      const cases = [];
      for (const [name, spec] of Object.entries(SPECS)) {
        try {
          const s = { ...spec, options: { ...(spec.options || {}), ...(p.layout ? { layout: p.layout } : {}) } };
          const out = buildConfig(product, { ...s, version }, { check: false });
          const mod = require('../../src/products').get(product);
          const raw = mod.build({ ...require('../../src/build/spec').normalizeSpec(s), version: out.target }); // for apache: modules
          cases.push({ name: `build:${name}`, files: out.files, extra: p.enable ? p.enable(raw) : '' });
        } catch (e) { results.push({ key, image: img, version, case: `build:${name}`, ok: false, out: `builder threw: ${e.message}` }); }
      }
      if (p.example && fs.existsSync(path.join(ROOT, p.example))) {
        const ex = readTree(path.join(ROOT, p.example), p.exampleSkip).map(p.exampleFilter || ((f) => f));
        cases.push({ name: 'example', files: ex, extra: '', agree: true });
        try {
          const imp = improveConfig({ product, version, files: ex.filter((f) => !/\.(md|txt)$/.test(f.name)) });
          const improved = ex.map((f) => { const g = imp.files.find((x) => x.name === f.name); return g ? { name: f.name, content: g.improved } : f; });
          cases.push({ name: 'doctor:example', files: improved, extra: '', agree: true });
        } catch (e) { results.push({ key, image: img, version, case: 'doctor:example', ok: false, out: `Config Doctor threw: ${e.message}` }); }
      }
      for (const c of cases) {
        const files = c.files.map((f) => ({ name: f.name, content: f.content }));
        const r = runCheck(p, ref, files, c.extra);
        let ok = r.ok; let note = '';
        // Examples carry deliberate mistakes. There the question is whether GateLight AGREES with the real program:
        // when the program rejects the config, GateLight must have reported at least one error for it.
        if (!r.ok && c.agree) {
          const at = errorLocation(r.out);
          const errs = gatelightErrors(product, version, files, at);
          if (errs.length) { ok = true; note = `expected: rejected by the real program and GateLight reports ${errs.length} error(s): ${errs.slice(0, 3).join(' | ')}`; }
          else note = `GATELIGHT MISSED IT: the real program rejects this configuration${at ? ` at ${at.file}:${at.line}` : ''}, but GateLight reported no error there`;
        }
        results.push({ key, image: img, version, case: c.name, ok, note, out: ok ? '' : `${note ? `${note}\n` : ''}${r.out.split('\n').slice(-12).join('\n')}`, work: r.work });
        process.stdout.write(ok ? (note ? 'e' : '.') : 'F');
      }
    }
  }
  process.stdout.write('\n\n');
  const failed = results.filter((r) => !r.ok);
  const by = new Map();
  for (const r of results) { const k = `${r.key} ${r.image.replace(REG, '')}${r.version ? ` (${r.version})` : ''}`; const e = by.get(k) || { ok: 0, fail: 0 }; e[r.ok ? 'ok' : 'fail']++; by.set(k, e); }
  for (const [k, e] of by) console.log(`${e.fail ? '✗' : '✓'} ${k.padEnd(52)} ${e.ok} passed${e.fail ? `, ${e.fail} FAILED` : ''}`);
  for (const f of failed) console.log(`\n--- FAILED ${f.key} ${f.image} ${f.version || ''} ${f.case}\n${f.out}${f.work ? `\n(files kept in ${f.work})` : ''}`);
  const agreed = results.filter((r) => r.ok && r.note);
  if (agreed.length) { console.log('\nRejected by the real program, and GateLight agrees (deliberate mistakes in the examples):'); for (const a of agreed) console.log(`  ${a.key} ${a.version || ''} ${a.case}: ${a.note}`); }
  if (opt('--json')) fs.writeFileSync(opt('--json'), JSON.stringify({ generated: new Date().toISOString(), results }, null, 2));
  console.log(`\n${results.length - failed.length}/${results.length} checks passed with the real programs.`);
  if (FIX) fs.rmSync(FIX, { recursive: true, force: true });
  process.exit(failed.length ? 1 : 0);
}

module.exports = { prelude, hostArgs, PRODUCTS, isData, runCheck, image, ensureImage, pullImage, gatelightErrors, errorLocation };
if (require.main === module) main();

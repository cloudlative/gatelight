#!/usr/bin/env node
'use strict';
/**
 * Builds src/kb/caddy.json from Caddy's official sources:
 *
 *   1. Caddy's own source code at every stable release tag (v2.0.0 .. latest, no betas / release candidates):
 *        caddyconfig/httpcaddyfile/directives.go   the default directive ORDER (it changes between releases)
 *        Register(Handler)Directive / RegisterGlobalOption calls in the files listed in SRC_FILES
 *                                                  -> which directives and global options exist in that release
 *        `case "...":` labels of the Caddyfile unmarshalers (switch d.Val()) -> subdirectives of each directive / option
 *        `ID: "http.matchers.<name>"` module IDs   -> request matchers
 *      Comparing the releases gives, for every name, the first release it exists in (`since`) and, when it was
 *      removed, the last one (`until`).
 *   2. The documentation (github.com/caddyserver/website, the source of caddyserver.com/docs): the syntax block of every
 *      directive page, the global options page and the directive descriptions. Doc links point at caddyserver.com.
 *
 *   node tools/kb/caddy.js [--cache DIR] [--offline] [--git BARE_REPO]
 *
 * --git reads the tagged sources from a local clone (`git clone --bare https://github.com/caddyserver/caddy`) instead
 * of raw.githubusercontent.com; the result is the same. Tags come from `git ls-remote --tags` (the GitHub API is not
 * needed). Everything is cached in the cache directory, so --offline rebuilds without network access.
 * Sources are only read as text; nothing is executed.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const argv = process.argv.slice(2);
const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : null);
const cacheDir = path.resolve(opt('--cache') || path.join(os.tmpdir(), 'gatelight-kb', 'caddy'));
const offline = argv.includes('--offline');
const gitDir = opt('--git');
const OUT = path.join(__dirname, '..', '..', 'src', 'kb', 'caddy.json');
const REPO = 'https://github.com/caddyserver/caddy';
const RAW_SRC = 'https://raw.githubusercontent.com/caddyserver/caddy';
const RAW_DOCS = 'https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown';
const DOCS = 'https://caddyserver.com/docs';

// Files that register Caddyfile directives / global options or hold their unmarshalers, at any release.
const SRC_FILES = [
  'caddyconfig/httpcaddyfile/directives.go', 'caddyconfig/httpcaddyfile/builtins.go', 'caddyconfig/httpcaddyfile/options.go',
  'caddyconfig/httpcaddyfile/serveroptions.go', 'caddyconfig/httpcaddyfile/pkiapp.go', 'caddyconfig/httpcaddyfile/httptype.go',
  'modules/caddyevents/eventsconfig/caddyfile.go', 'modules/caddyfs/filesystem.go',
  'modules/caddyhttp/caddyauth/caddyfile.go', 'modules/caddyhttp/encode/caddyfile.go', 'modules/caddyhttp/fileserver/caddyfile.go',
  'modules/caddyhttp/headers/caddyfile.go', 'modules/caddyhttp/intercept/intercept.go', 'modules/caddyhttp/logging/caddyfile.go',
  'modules/caddyhttp/map/caddyfile.go', 'modules/caddyhttp/push/caddyfile.go', 'modules/caddyhttp/requestbody/caddyfile.go',
  'modules/caddyhttp/reverseproxy/caddyfile.go', 'modules/caddyhttp/reverseproxy/fastcgi/caddyfile.go',
  'modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go', 'modules/caddyhttp/rewrite/caddyfile.go',
  'modules/caddyhttp/templates/caddyfile.go', 'modules/caddyhttp/timeouts/caddyfile.go', 'modules/caddyhttp/tracing/module.go',
  'modules/caddypki/acmeserver/caddyfile.go', 'modules/metrics/metrics.go',
];
const POLICY_FILE = 'modules/caddyhttp/reverseproxy/selectionpolicies.go';
const ENCODER_FILES = ['modules/caddyhttp/encode/gzip/gzip.go', 'modules/caddyhttp/encode/zstd/zstd.go', 'modules/caddyhttp/encode/brotli/brotli.go'];
const MATCHER_FILES = ['modules/caddyhttp/matchers.go', 'modules/caddyhttp/ip_matchers.go', 'modules/caddyhttp/vars.go', 'modules/caddyhttp/celmatcher.go', 'modules/caddyhttp/fileserver/matcher.go', 'modules/caddyhttp/urlpatternmatcher.go'];
// Unmarshalers that are shared helpers rather than registered functions.
const HELPERS = { parseLogHelper: [['directives', 'log'], ['options', 'log']], unmarshalCaddyfileServerOptions: [['options', 'servers']] };
// Unmarshaler methods whose receiver is a sub-module configured inside another directive.
const RECEIVER_OWNER = {
  'modules/caddyhttp/reverseproxy/caddyfile.go': { Handler: 'reverse_proxy', HTTPTransport: 'reverse_proxy>transport http' },
  'modules/caddyhttp/reverseproxy/fastcgi/caddyfile.go': { Transport: 'reverse_proxy>transport fastcgi' },
};

// ------------------------------------------------------------------------------------------------ fetching + cache
const get = (url) => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'User-Agent': 'gatelight-kb-builder' } }, (res) => {
    if (res.statusCode === 404) { res.resume(); return resolve(null); }
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url} -> ${res.statusCode}`)); }
    const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  }).on('error', reject);
});
const MISSING = '\u0000missing';
async function cached(key, fetcher) {
  fs.mkdirSync(cacheDir, { recursive: true });
  const f = path.join(cacheDir, key.replace(/[^A-Za-z0-9._-]+/g, '_'));
  if (fs.existsSync(f)) { const t = fs.readFileSync(f, 'utf8'); return t === MISSING ? null : t; }
  if (offline) throw new Error(`missing ${f} (offline)`);
  let body = null;
  for (let attempt = 0; ; attempt++) {
    try { body = await fetcher(); break; } catch (e) { if (attempt >= 3) throw e; await new Promise((r) => setTimeout(r, 500 * (attempt + 1))); }
  }
  fs.writeFileSync(f, body === null ? MISSING : body);
  return body;
}
function gitShow(tag, file) {
  try { return execFileSync('git', ['--git-dir', gitDir, 'show', `${tag}:${file}`], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return null; }
}
const src = (tag, file) => cached(`src_${tag}_${file}`, () => (gitDir ? Promise.resolve(gitShow(tag, file)) : get(`${RAW_SRC}/${tag}/${file}`)));
const doc = (rel) => cached(`docs_${rel}`, () => get(`${RAW_DOCS}/${rel}`));

async function tags() {
  return JSON.parse(await cached('tags.json', async () => {
    const out = gitDir ? execFileSync('git', ['--git-dir', gitDir, 'tag'], { encoding: 'utf8' }) : execFileSync('git', ['ls-remote', '--tags', REPO], { encoding: 'utf8' });
    const list = [...new Set(out.split('\n').map((l) => l.trim().split(/\s+/).pop()).filter(Boolean).map((r) => r.replace(/^refs\/tags\//, '').replace(/\^\{\}$/, '')))]
      .filter((t) => /^v2\.\d+\.\d+$/.test(t));
    return JSON.stringify(list.sort(verCmp));
  }));
}

/** Run promise-returning jobs with bounded concurrency. */
async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

// ------------------------------------------------------------------------------------------------ Go source parsing
const verCmp = (a, b) => { const x = a.replace(/^v/, '').split('.').map(Number); const y = b.replace(/^v/, '').split('.').map(Number); for (let i = 0; i < 3; i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };
const stripComment = (l) => l.replace(/\s*\/\/.*$/, '');

/** Top-level functions of a Go file: [{ name, recv, lines }]. */
function goFuncs(text) {
  const out = []; let cur = null;
  for (const line of text.split('\n')) {
    const m = /^func\s+(?:\(\s*(?:\w+\s+)?\*?(\w+)\s*\)\s*)?(\w+)\s*\(/.exec(line);
    if (m) { cur = { recv: m[1] || null, name: m[2], lines: [] }; out.push(cur); continue; }
    if (/^\S/.test(line) && !/^}/.test(line)) cur = null;
    if (cur) cur.lines.push(line);
  }
  return out;
}
const caseNames = (line) => { const m = /^\s*case\s+((?:"[^"]*"\s*,?\s*)+):/.exec(line); return m ? [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]).filter(Boolean) : []; };

/**
 * Subdirective names of one unmarshaler: the `case` labels of its outermost `switch d.Val()` (or h.Val(), or a variable
 * holding it), plus nested `switch d.Val()` blocks recorded as "parent>child".
 */
function subdirectives(fn) {
  const sw = /^(\t*)switch\s+(?:\w+\s*:=\s*)?(?:d|h|disp)\.Val\(\)\s*(?:;\s*\w+\s*)?\{|^(\t*)switch\s+(?:subdir|dir|name|optName|opt)\s*\{/;
  const lines = fn.lines.map(stripComment);
  const switches = [];
  lines.forEach((l, i) => { const m = sw.exec(l); if (m) switches.push({ i, ind: (m[1] || m[2] || '').length }); });
  if (!switches.length) return [];
  const top = Math.min(...switches.map((s) => s.ind));
  const out = []; const stack = []; // open switches: { ind, nested, parent }
  let lastTop = null;
  lines.forEach((l, i) => {
    const s = switches.find((x) => x.i === i);
    const ind = (/^\t*/.exec(l) || [''])[0].length;
    while (stack.length && /^\t*}\s*$/.test(l) && ind === stack[stack.length - 1].ind) { stack.pop(); return; }
    if (s) { stack.push({ ind: s.ind, top: s.ind === top, parent: s.ind === top ? null : lastTop }); return; }
    const open = stack[stack.length - 1];
    if (!open) return;
    const names = caseNames(l);
    if (!names.length || ind !== open.ind) return;
    if (open.top) { lastTop = names[0]; out.push(...names); } else if (open.parent) out.push(...names.map((n) => `${open.parent}>${n}`));
  });
  return [...new Set(out)];
}

const REG_RE = /Register(Handler)?Directive\(\s*"([^"]+)"\s*,\s*(\w+)?/g;
const OPT_RE = /RegisterGlobalOption\(\s*"([^"]+)"\s*,\s*(\w+)?/g;

/** Facts of one release. */
async function release(tag) {
  const files = await Promise.all(SRC_FILES.map(async (f) => [f, await src(tag, f)]));
  const matcherFiles = await Promise.all(MATCHER_FILES.map((f) => src(tag, f)));
  const policyText = await src(tag, POLICY_FILE);
  const encoderTexts = await Promise.all(ENCODER_FILES.map((f) => src(tag, f)));
  const directives = {}; const options = {}; const matchers = {}; const policies = {}; const encoders = {};
  if (policyText) for (const m of policyText.matchAll(/ID:\s*"http\.reverse_proxy\.selection_policies\.([a-z_0-9]+)"/g)) policies[m[1]] = true;
  for (const t of encoderTexts) if (t) for (const m of t.matchAll(/ID:\s*"http\.encoders\.([a-z_0-9]+)"/g)) encoders[m[1]] = true;
  let order = [];
  const fnOwner = new Map(); // "file|fn" or "*|fn" -> [[kind, name]]
  const own = (k, kind, name) => { const l = fnOwner.get(k) || []; l.push([kind, name]); fnOwner.set(k, l); };
  for (const [file, text] of files) {
    if (!text) continue;
    for (const m of text.matchAll(REG_RE)) { if (/_test\.go$/.test(file)) continue; directives[m[2]] = { sub: {} }; if (m[3]) { own(`${file}|${m[3]}`, 'directives', m[2]); own(`*|${m[3]}`, 'directives', m[2]); } }
    for (const m of text.matchAll(OPT_RE)) { options[m[1]] = { sub: {} }; if (m[2]) { own(`${file}|${m[2]}`, 'options', m[1]); own(`*|${m[2]}`, 'options', m[1]); } }
    if (file.endsWith('directives.go')) {
      const om = /var\s+(?:default)?[dD]irectiveOrder\s*=\s*\[\]string\{([\s\S]*?)\n\}/.exec(text);
      if (om) order = [...om[1].split('\n').map(stripComment).join('\n').matchAll(/"([^"]+)"/g)].map((x) => x[1]);
    }
  }
  // v2.0 / v2.1: global options were a switch in httptype.go (evaluateGlobalOptionsBlock)
  const ht = files.find(([f]) => f.endsWith('httptype.go'))[1];
  if (ht) {
    const ev = goFuncs(ht).find((f) => f.name === 'evaluateGlobalOptionsBlock');
    if (ev) {
      const sw = ev.lines.findIndex((l) => /switch dir \{/.test(l));
      const ind = sw >= 0 ? /^\t*/.exec(ev.lines[sw])[0].length : -1;
      if (sw >= 0) for (const l of ev.lines.slice(sw + 1)) { const li = /^\t*/.exec(l)[0].length; if (li === ind && /^\t*}/.test(l)) break; if (li === ind) for (const n of caseNames(l)) options[n] = options[n] || { sub: {} }; }
      for (const [k, v] of Object.entries({ parseOptAdmin: 'admin', parseOptOnDemand: 'on_demand_tls', parseOptStorage: 'storage', parseOptOrder: 'order' })) own(`*|${k}`, 'options', v);
    }
  }
  // subdirectives from each unmarshaler
  const tables = { directives, options };
  for (const [file, text] of files) {
    if (!text || /_test\.go$/.test(file)) continue;
    const funcs = goFuncs(text);
    const generic = fnOwner.get(`${file}|parseCaddyfile`);
    for (const fn of funcs) {
      let owners = fnOwner.get(`${file}|${fn.name}`) || fnOwner.get(`*|${fn.name}`) || HELPERS[fn.name] || null;
      if (!owners && fn.name === 'UnmarshalCaddyfile' && fn.recv) {
        const ro = RECEIVER_OWNER[file] && RECEIVER_OWNER[file][fn.recv];
        if (ro) owners = [['directives', ro]];
        else if (generic && /^(Handler|Encode|FileServer|Templates|Metrics|Tracing|Intercept|LogAppend|MapHandler|RequestBody|Handler)$/.test(fn.recv)) owners = generic;
        else if (generic && funcs.filter((f) => f.name === 'UnmarshalCaddyfile').length === 1) owners = generic;
      }
      if (!owners) continue;
      const subs = subdirectives(fn);
      if (!subs.length) continue;
      for (const [kind, nameRaw] of owners) {
        const [name, via] = nameRaw.split('>');
        const t = tables[kind]; if (!t[name]) t[name] = { sub: {}, virtual: true };
        for (const s of subs) t[name].sub[via ? `${via}>${s}` : s] = true;
      }
    }
  }
  for (const text of matcherFiles) if (text) for (const m of text.matchAll(/ID:\s*"http\.matchers\.([a-z_0-9]+)"/g)) matchers[m[1]] = true;
  return { tag, directives, options, matchers, order, policies, encoders };
}

// ------------------------------------------------------------------------------------------------ docs
function syntaxBlock(md) {
  const at = md.search(/^##\s+Syntax/m);
  const from = at >= 0 ? md.slice(at) : md;
  const m = /```caddy(?:-d)?\n([\s\S]*?)```/.exec(from);
  return m ? m[1].replace(/\t/g, '  ').replace(/\s+$/, '').slice(0, 1500) : null;
}
/** "since v2.x" style annotations next to subdirective bullets: { sub: '2.8.0' }. */
function docSince(md) {
  const out = {};
  for (const line of md.split('\n')) {
    const m = /^\s*-\s+\*\*([a-z_0-9]+)\*\*.*?\bv?(2\.\d+(?:\.\d+)?)(?:\.x)?\+?/.exec(line);
    if (m && /(since|added|v2\.\d+)/i.test(line)) out[m[1]] = m[2];
  }
  return out;
}

async function main() {
  const all = await tags();
  process.stderr.write(`${all.length} release tags: ${all[0]} .. ${all[all.length - 1]}\n`);
  const rels = await pool(all, gitDir ? 4 : 12, async (t) => { const r = await release(t); process.stderr.write(`${t}: ${Object.keys(r.directives).length} directives, ${Object.keys(r.options).length} options, ${Object.keys(r.matchers).length} matchers\n`); return r; });
  const versions = all.map((t) => t.slice(1));
  const latest = versions[versions.length - 1];

  // since / until for every name
  const life = (get) => {
    const out = {};
    rels.forEach((r, i) => {
      for (const name of Object.keys(get(r))) {
        const e = out[name] || (out[name] = { since: versions[i], present: [] });
        e.present.push(i);
      }
    });
    for (const e of Object.values(out)) {
      const last = e.present[e.present.length - 1];
      if (last < rels.length - 1) e.until = versions[last];
      if (e.present.length !== e.present[e.present.length - 1] - e.present[0] + 1) e.gaps = true;
      delete e.present; delete e.gaps;
    }
    return out;
  };
  const dirLife = life((r) => Object.fromEntries(Object.entries(r.directives).filter(([, v]) => !v.virtual)));
  const optLife = life((r) => Object.fromEntries(Object.entries(r.options).filter(([, v]) => !v.virtual)));
  const subLife = (kind, name) => life((r) => (r[kind][name] ? r[kind][name].sub : {}));

  // docs
  const index = (await doc('caddyfile/directives.md')) || '';
  const descr = {};
  for (const m of index.matchAll(/^\*\*\[([a-z_]+)\]\([^)]*\)\*\*\s*\|\s*(.+)$/gm)) descr[m[1]] = m[2].trim();
  const directives = {};
  for (const [name, l] of Object.entries(dirLife).sort()) {
    const page = name === 'basicauth' ? 'basic_auth' : name;
    const md = await doc(`caddyfile/directives/${page}.md`).catch(() => null);
    const sub = subLife('directives', name);
    const ds = md ? docSince(md) : {};
    for (const [s, v] of Object.entries(ds)) if (sub[s]) sub[s].doc = v;
    directives[name] = {
      since: l.since, ...(l.until ? { until: l.until } : {}), docs: `${DOCS}/caddyfile/directives/${page}`,
      ...(descr[page] ? { description: descr[page] } : {}), ...(md && syntaxBlock(md) ? { syntax: syntaxBlock(md) } : {}),
      ...(Object.keys(sub).length ? { sub } : {}),
    };
  }
  const optMd = (await doc('caddyfile/options.md')) || '';
  const options = {};
  for (const [name, l] of Object.entries(optLife).sort()) {
    const sub = subLife('options', name);
    options[name] = { since: l.since, ...(l.until ? { until: l.until } : {}), docs: `${DOCS}/caddyfile/options#${name.replace(/_/g, '-')}`, ...(Object.keys(sub).length ? { sub } : {}) };
  }
  const optSyntax = (/```caddy\n\{\n\t# General Options([\s\S]*?)\n\}\n```/.exec(optMd) || [])[1];
  const matchers = life((r) => r.matchers);
  const lbPolicies = life((r) => r.policies);
  const encoders = life((r) => r.encoders);
  for (const [n, m] of Object.entries(matchers)) m.docs = `${DOCS}/caddyfile/matchers#${n.replace(/_/g, '-')}`;
  // directive order: store one entry per change
  const orders = [];
  rels.forEach((r, i) => { const prev = orders[orders.length - 1]; if (!prev || prev.order.join() !== r.order.join()) orders.push({ since: versions[i], order: r.order }); });

  const kb = {
    product: 'caddy', generated: new Date().toISOString().slice(0, 10),
    source: `${REPO} (release tags) + https://github.com/caddyserver/website (docs)`, docs: DOCS,
    latest, versions: [...versions].reverse(), orders, directives, options, matchers, lbPolicies, encoders,
    optionsSyntax: optSyntax ? `# General Options${optSyntax}`.replace(/\t/g, '  ').slice(0, 6000) : null,
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(kb)}\n`);
  const subs = Object.values(directives).reduce((a, d) => a + Object.keys(d.sub || {}).length, 0);
  console.error(`wrote ${path.relative(process.cwd(), OUT)}: ${versions.length} releases (latest ${latest}), ${Object.keys(directives).length} directives (${subs} subdirectives), ${Object.keys(options).length} global options, ${Object.keys(matchers).length} matchers, ${Object.keys(lbPolicies).length} lb policies, ${orders.length} directive orders, ${fs.statSync(OUT).size} bytes`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { goFuncs, subdirectives, syntaxBlock, verCmp };

#!/usr/bin/env node
'use strict';
/**
 * Builds src/kb/apache.json from the official Apache HTTP Server documentation SOURCE at release tags
 * (https://github.com/apache/httpd, docs/manual/mod/*.xml; the same XML that renders https://httpd.apache.org/docs/2.4/).
 *
 *   - release list: `git ls-remote --tags` + the CHANGES file of the newest tag ("(not released)" tags are dropped)
 *   - every module of docs/manual/mod/allmodules.xml at the newest release: module status / identifier / compatibility,
 *     and per directive: syntax, default, contexts, override class, <compatibility> text ("Available in 2.4.17 and later")
 *   - first release whose documentation lists a directive (sampled tags + binary search between them), and directives
 *     that disappeared from the docs
 *   - lifecycle notes: docs/manual/upgrading.xml (removed / renamed directives) and deprecation sentences in <usage>
 *
 *   node tools/kb/apache.js [--cache DIR] [--offline] [--concurrency N]
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const argv = process.argv.slice(2);
const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : null);
const cacheDir = path.resolve(opt('--cache') || path.join(os.tmpdir(), 'gatelight-kb', 'apache'));
const offline = argv.includes('--offline');
const CONC = Number(opt('--concurrency')) || 12;
const OUT = path.join(__dirname, '..', '..', 'src', 'kb', 'apache.json');
const REPO = 'https://github.com/apache/httpd';
const RAW = 'https://raw.githubusercontent.com/apache/httpd';
const DOCS = 'https://httpd.apache.org/docs/2.4/mod/';

// ------------------------------------------------------------------------------------------- fetching with a cache
const get = (url) => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'User-Agent': 'gatelight-kb-builder' } }, (res) => {
    if (res.statusCode === 404) { res.resume(); return resolve(null); }
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url} -> ${res.statusCode}`)); }
    const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  }).on('error', reject);
});
const MISSING = '\u0000missing';
async function load(tag, rel) {
  const f = path.join(cacheDir, tag, rel.replace(/[/#]/g, '_'));
  if (fs.existsSync(f)) { const t = fs.readFileSync(f, 'utf8'); return t === MISSING ? null : t; }
  if (offline) throw new Error(`missing ${f} (offline)`);
  let body; let tries = 0;
  for (;;) { try { body = await get(`${RAW}/${tag}/${rel}`); break; } catch (e) { if (++tries > 3) throw e; await new Promise((r) => setTimeout(r, 500 * tries)); } }
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, body === null ? MISSING : body);
  return body;
}
async function pool(items, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(CONC, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

// ------------------------------------------------------------------------------------------- versions
const verCmp = (a, b) => { const x = a.split('.').map(Number); const y = b.split('.').map(Number); for (let i = 0; i < 3; i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };

function listTags() {
  const f = path.join(cacheDir, 'tags.txt');
  let text;
  if (fs.existsSync(f) && (offline || argv.includes('--cached-tags'))) text = fs.readFileSync(f, 'utf8');
  else {
    if (offline) throw new Error(`missing ${f} (offline)`);
    text = execFileSync('git', ['ls-remote', '--tags', REPO], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    fs.mkdirSync(cacheDir, { recursive: true }); fs.writeFileSync(f, text);
  }
  return [...new Set([...text.matchAll(/refs\/tags\/(2\.4\.\d+)$/gm)].map((m) => m[1]))].sort(verCmp);
}

/** Released 2.4.x versions according to CHANGES of the newest tag (entries marked "(not released)" are skipped). */
function releasedFrom(changes, tags) {
  const notReleased = new Set([...changes.matchAll(/^Changes with Apache (2\.4\.\d+) \(not released\)/gm)].map((m) => m[1]));
  const mentioned = new Set([...changes.matchAll(/^Changes with Apache (2\.4\.\d+)/gm)].map((m) => m[1]));
  return tags.filter((t) => mentioned.has(t) && !notReleased.has(t));
}

// ------------------------------------------------------------------------------------------- XML helpers
const ENT = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&nbsp;': ' ', '&#39;': "'", '&apos;': "'" };
const unent = (s) => s.replace(/&(lt|gt|amp|quot|nbsp|#39|apos);/g, (m) => ENT[m]);
const text = (s) => unent(String(s || '').replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
const tagText = (xml, tag) => { const m = xml.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`)); return m ? text(m[1]) : ''; };
const CTX = { 'server config': 's', 'virtual host': 'v', directory: 'd', '.htaccess': 'h', 'proxy section': 'p' };

/** "Available in Apache HTTP Server 2.4.17 and later" -> "2.4.17" (whole-directive availability only). */
function sinceFromCompat(c) {
  if (!c) return null;
  // whole-directive availability only: "Available in ...", "Added in ...", "X is only available in ...", "2.4.47 and later"
  if (!/^(?:(?:Only )?available|Added|Directive supported|[A-Z][A-Za-z]+ is only available|Apache HTTP Server|\d)/i.test(c)) return null;
  if (/\b(argument|parameter|option|context|default|nested|value|behaviou?r|status codes|support)\b/i.test(c.split(/\d+\.\d+(?:\.\d+)?/)[0])) return null;
  const m = c.match(/\b(\d+\.\d+(?:\.\d+)?)\b/); // the first version mentioned is the one the directive appeared in
  const v = m && m[1];
  if (!v) return null;
  const full = v.split('.').length === 2 ? `${v}.0` : v;
  return verCmp(full, '2.4.0') <= 0 ? null : full; // everything older than 2.4.0 is simply "available in 2.4"
}

const DEPRECATION = /\b(is deprecated|has been deprecated|is obsolete|became obsolete|currently has no effect|no longer has any effect|is no longer supported|will be removed)\b/i;

function parseModule(xml, file) {
  const mod = file.replace(/\.xml$/, '');
  const head = xml.split('<directivesynopsis')[0];
  const meta = {
    name: tagText(head, 'name') || mod, status: tagText(head, 'status'), id: tagText(head, 'identifier') || undefined,
    compat: tagText(head, 'compatibility') || undefined,
  };
  meta.since = sinceFromCompat(meta.compat) || undefined;
  const dirs = [];
  for (const m of xml.matchAll(/<directivesynopsis([^>]*)>([\s\S]*?)<\/directivesynopsis>/g)) {
    if (/\blocation=/.test(m[1])) continue; // a pointer to a directive documented in another module (MPM pages)
    const body = m[2];
    const name = tagText(body, 'name');
    if (!name) continue;
    const usage = (body.match(/<usage>([\s\S]*?)<\/usage>/) || [])[1] || '';
    const compat = tagText(body, 'compatibility');
    const sentences = text(usage).split(/(?<=\.)\s+/);
    // only sentences whose subject is the directive itself ("X is deprecated", "This directive currently has no effect")
    const dep = sentences.find((s) => DEPRECATION.test(s) && new RegExp(`^(?:${name}|This directive|The ${name} directive)\\b`).test(s));
    const ctx = [...body.matchAll(/<context>([^<]+)<\/context>/g)].map((c) => CTX[c[1].trim()] || c[1].trim());
    dirs.push({
      name, section: /type="section"/.test(m[1]) || undefined,
      syntax: tagText(body, 'syntax').slice(0, 300), def: tagText(body, 'default').slice(0, 160) || undefined,
      ctx: ctx.join(''), ov: tagText(body, 'override') || undefined,
      compat: compat ? compat.slice(0, 200) : undefined, since: sinceFromCompat(compat) || undefined,
      dep: dep ? dep.slice(0, 240) : undefined,
    });
  }
  return { mod, meta, dirs };
}

/** upgrading.xml: directives removed / renamed when moving from 2.2 to 2.4. */
function parseUpgrading(xml) {
  const t = text(xml);
  const out = {};
  const listOf = (s) => s.replace(/\band\b/g, ',').split(',').map((x) => x.trim()).filter((x) => /^[A-Z][A-Za-z]+$/.test(x));
  const removed = t.match(/have been removed: This includes ([^.]+?)\. These directives have been replaced by the more expressive ([^.]+)\./);
  if (removed) for (const n of listOf(removed[1])) out[n] = { kind: 'removed', note: `Removed in 2.4: authorization modules no longer have *Authoritative switches; use ${removed[2].replace(/\s+/g, ' ')} instead.`, repl: 'RequireAny / RequireAll / RequireNone' };
  const mutex = t.match(/Directives ([A-Za-z, ]+?) have been replaced with a single Mutex directive/);
  if (mutex) for (const n of listOf(mutex[1])) out[n] = { kind: 'removed', note: 'Removed in 2.4: replaced by the single Mutex directive.', repl: 'Mutex' };
  for (const m of t.matchAll(/([A-Z][A-Za-z]+) has been renamed to ([A-Z][A-Za-z]+),[^.]*\.[^.]*?The old name is still supported\./g)) out[m[1]] = { kind: 'renamed', note: `Renamed to ${m[2]} in 2.4; the old name is still accepted.`, repl: m[2] };
  for (const m of t.matchAll(/([A-Z][A-Za-z]+) is no longer supported\./g)) out[m[1]] = { kind: 'removed', note: `${m[1]} is no longer supported in 2.4.`, repl: null };
  const dt = t.match(/The DefaultType directive no longer has any effect[^.]*\./);
  if (dt) out.DefaultType = { kind: 'noeffect', note: dt[0], repl: null };
  const nvh = t.match(/The NameVirtualHost directive[^.]*\.[^.]*\./);
  if (nvh) out.NameVirtualHost = { kind: 'noeffect', note: nvh[0], repl: null };
  return out;
}

// ------------------------------------------------------------------------------------------- main
async function main() {
  const tags = listTags();
  const newest = tags[tags.length - 1];
  const changes = await load(newest, 'CHANGES');
  const released = releasedFrom(changes, tags);
  const latest = released[released.length - 1];
  process.stderr.write(`${tags.length} 2.4.x tags, ${released.length} released, latest ${latest}\n`);

  const modFiles = async (tag) => { const x = await load(tag, 'docs/manual/mod/allmodules.xml'); return x ? [...x.matchAll(/<modulefile>([^<]+)<\/modulefile>/g)].map((m) => m[1]) : []; };
  const files = await modFiles(latest);
  const parsed = {};
  await pool(files, async (f) => { const x = await load(latest, `docs/manual/mod/${f}`); if (x) parsed[f] = parseModule(x, f); });

  // ---- first documented release: coarse samples, then a binary search between neighbours
  const samples = [...new Set([released[0], ...released.filter((v, i) => i % 8 === 0), latest])].sort(verCmp);
  const namesAt = new Map(); // `${tag}|${file}` -> Set(lowercase names) | null
  const namesOf = async (tag, file) => {
    const k = `${tag}|${file}`;
    if (!namesAt.has(k)) { const x = await load(tag, `docs/manual/mod/${file}`); namesAt.set(k, x ? new Set(parseModule(x, file).dirs.map((d) => d.name.toLowerCase())) : null); }
    return namesAt.get(k);
  };
  const allFiles = new Set(files);
  for (const t of samples) for (const f of await modFiles(t)) allFiles.add(f);
  await pool(samples.flatMap((t) => [...allFiles].map((f) => [t, f])), ([t, f]) => namesOf(t, f));
  const has = (tag, file, name) => { const s = namesAt.get(`${tag}|${file}`); return Boolean(s && s.has(name)); };
  const docSince = {};
  await pool(Object.values(parsed).flatMap((p) => p.dirs.map((d) => [p, d])), async ([p, d]) => {
    const file = `${p.mod}.xml`; const n = d.name.toLowerCase();
    const k = samples.findIndex((t) => has(t, file, n));
    if (k <= 0) return; // documented from the first release on
    let lo = released.indexOf(samples[k - 1]); let hi = released.indexOf(samples[k]); // absent at lo, present at hi
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; const s = await namesOf(released[mid], file); if (s && s.has(n)) hi = mid; else lo = mid; }
    docSince[`${p.mod}|${d.name}`] = released[hi];
  });
  // directives documented in an earlier release but no longer
  const gone = {};
  const current = new Set(Object.values(parsed).flatMap((p) => p.dirs.map((d) => d.name.toLowerCase())));
  for (const t of samples) {
    for (const f of allFiles) {
      const s = namesAt.get(`${t}|${f}`); if (!s) continue;
      for (const n of s) if (!current.has(n)) gone[n] = { mod: f.replace(/\.xml$/, ''), last: t };
    }
  }
  const goneNames = {};
  for (const [n, g] of Object.entries(gone)) {
    const x = await load(g.last, `docs/manual/mod/${g.mod}.xml`);
    const d = x && parseModule(x, `${g.mod}.xml`).dirs.find((y) => y.name.toLowerCase() === n);
    const after = samples[samples.indexOf(g.last) + 1];
    if (d) goneNames[d.name] = { mod: g.mod, lastDocumented: g.last, goneBy: after, syntax: d.syntax };
  }

  // ---- lifecycle from upgrading.xml
  const lifecycle = parseUpgrading(await load(latest, 'docs/manual/upgrading.xml') || '');

  const modules = {}; const directives = {};
  for (const f of files) {
    const p = parsed[f]; if (!p) continue;
    modules[p.mod] = { status: p.meta.status, id: p.meta.id, since: p.meta.since, compat: p.meta.compat ? p.meta.compat.slice(0, 160) : undefined, n: p.dirs.length };
    for (const d of p.dirs) {
      const ds = docSince[`${p.mod}|${d.name}`];
      const since = [d.since, p.meta.since].filter(Boolean).sort(verCmp).pop();
      const e = { mod: p.mod, syntax: d.syntax, def: d.def, ctx: d.ctx, ov: d.ov, since, docSince: ds && (!since || verCmp(ds, since) > 0) ? ds : undefined, compat: d.compat, dep: d.dep, section: d.section, docs: `${DOCS}${p.mod}.html#${d.name.toLowerCase()}` };
      (directives[d.name] = directives[d.name] || []).push(JSON.parse(JSON.stringify(e)));
    }
  }
  const kb = {
    product: 'apache', generated: new Date().toISOString().slice(0, 10), source: `${REPO} docs/manual (tag ${latest})`, docsBase: DOCS,
    latest, versions: released, tagsSampled: samples, contexts: { s: 'server config', v: 'virtual host', d: 'directory', h: '.htaccess', p: 'proxy section' },
    modules, directives, removedFromDocs: goneNames, lifecycle,
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(kb)}\n`);
  console.error(`wrote ${path.relative(process.cwd(), OUT)}: ${Object.keys(directives).length} directives from ${Object.keys(modules).length} modules, ${released.length} releases (latest ${latest}), ${Object.keys(docSince).length} first-documented dates, ${Object.keys(goneNames).length} directives gone from the docs, ${(fs.statSync(OUT).size / 1024).toFixed(0)} KB`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { parseModule, parseUpgrading, sinceFromCompat, releasedFrom, verCmp };

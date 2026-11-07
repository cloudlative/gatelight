#!/usr/bin/env node
'use strict';
/**
 * Builds src/kb/nginx.json from the official NGINX documentation (https://nginx.org/en/docs/):
 *   - the directive index and every module page: syntax, default, context(s), "appeared in version",
 *     required build flag ("--with-..."), commercial-only (NGINX Plus) marks
 *   - https://nginx.org/en/CHANGES: when directives / parameters were renamed, deprecated or removed,
 *     and when important defaults changed.
 *
 *   node tools/kb/nginx.js [--cache DIR] [--offline]
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');

const argv = process.argv.slice(2);
const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : null);
const cacheDir = path.resolve(opt('--cache') || path.join(os.tmpdir(), 'gatelight-kb', 'nginx'));
const offline = argv.includes('--offline');
const OUT = path.join(__dirname, '..', '..', 'src', 'kb', 'nginx.json');

const get = (url) => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'User-Agent': 'gatelight-kb-builder' } }, (res) => {
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url} -> ${res.statusCode}`)); }
    const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  }).on('error', reject);
});
async function load(rel) {
  fs.mkdirSync(cacheDir, { recursive: true });
  const f = path.join(cacheDir, rel.replace(/[/#]/g, '_'));
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8');
  if (offline) throw new Error(`missing ${f} (offline)`);
  const body = await get(`https://nginx.org/${rel}`);
  fs.writeFileSync(f, body);
  return body;
}

const ENT = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&nbsp;': ' ', '&#39;': "'" };
const unent = (s) => s.replace(/&(lt|gt|amp|quot|nbsp|#39);/g, (m) => ENT[m]);
const text = (s) => unent(s.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();

/** Directive blocks of one module page. */
function parseModule(html, mod) {
  const out = [];
  const re = /<a name="([^"]+)"><\/a><div class="directive">([\s\S]*?)<\/table>/g;
  const blocks = [...html.matchAll(re)];
  const pageHasFlag = html.match(/not built by default[^]*?<code>(--with-[a-z0-9_-]+)<\/code>/i);
  const flag = pageHasFlag ? pageHasFlag[1] : null;
  const isCommercial = /This module is available as part of (?:our\s+)?<a[^>]*>commercial subscription/i.test(html);
  blocks.forEach((b, i) => {
    const table = b[2];
    const rows = [...table.matchAll(/<th>\s*([^<]+?):?\s*<\/th>\s*<td>([\s\S]*?)<\/td>/g)];
    const row = (n) => (rows.find((r) => r[1].trim().replace(/:$/, '') === n) || [])[2] || '';
    const syntax = row('Syntax').split(/<br>/i).map((x) => text(x)).filter(Boolean);
    if (!syntax.length) return;
    const ctx = [...row('Context').matchAll(/<code>([^<]+)<\/code>/g)].map((m) => unent(m[1]).trim());
    const def = text(row('Default'));
    const after = html.slice(b.index + b[0].length, i + 1 < blocks.length ? blocks[i + 1].index : undefined);
    const since = (after.match(/appeared in version ([0-9]+(?:\.[0-9]+)+)/) || [])[1] || null;
    const commercial = /This directive is available as part of (?:our\s+)?<a[^>]*>commercial subscription/i.test(after.slice(0, 500));
    for (const sx of syntax) {
      const name = sx.match(/^([A-Za-z0-9_$.-]+)/);
      if (!name) continue;
      out.push({ name: name[1], syntax: sx, def: def === '—' ? '' : def, ctx, mod, since, flag, commercial: commercial || isCommercial });
    }
  });
  return out;
}

/** Embedded variables of one module page ($name, with "(1.x.y)" availability notes). */
function parseVariables(html, mod) {
  const out = [];
  for (const m of html.matchAll(/<dt id="var_([^"]+)">[\s\S]*?<\/dt>\s*<dd>([\s\S]*?)<\/dd>/g)) {
    const v = (text(m[2]).match(/\((\d+\.\d+\.\d+)(?:[,)])/) || [])[1];
    out.push({ name: m[1], mod, since: v || undefined });
  }
  return out;
}

const verCmp = (a, b) => { const x = a.split('.').map(Number); const y = b.split('.').map(Number); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };

/** Lifecycle events from the changelog (deprecations, removals, renames, default changes). */
function parseChanges(txt) {
  const events = []; const params = [];
  for (const block of txt.split(/\n(?=Changes with nginx )/)) {
    const m = block.match(/^Changes with nginx (\S+)/);
    if (!m) continue;
    const ver = m[1];
    for (const raw of block.split(/\n    \*\) /).slice(1)) {
      const e = raw.replace(/\s+/g, ' ').trim();
      if (/^Feature:/.test(e)) {
        for (const pm of e.matchAll(/"([^"]+)"(?:, "([^"]+)")*(?: and "([^"]+)")? (?:parameter|parameters|option|flag)s? (?:of|in) the "([a-z_0-9]+)" directive/g)) {
          for (const prm of [pm[1], pm[2], pm[3]].filter(Boolean)) { const ex = params.find((x) => x.directive === pm[4] && x.param === prm); if (ex) ex.ver = ver; else params.push({ ver, directive: pm[4], param: prm }); } // file is newest-first: keep the oldest mention
        }
      }
      if (!/^Change:/.test(e)) continue;
      const names = [...e.matchAll(/"([a-z][a-z0-9_]*)"/g)].map((x) => x[1]);
      const kind = /renamed to/i.test(e) ? 'renamed' : /(not supported anymore|have been removed|has been removed|were removed|was removed|removed)/i.test(e) ? 'removed' : /deprecated|obsolete/i.test(e) ? 'deprecated' : /by default|turned (on|off) by default|disabled by default|enabled by default/i.test(e) ? 'default' : null;
      if (kind) events.push({ ver, kind, names, note: e.replace(/^Change: /, '').slice(0, 300) });
    }
  }
  events.params = params;
  return events;
}

async function main() {
  const idx = await load('en/docs/dirindex.html');
  const pages = [...new Set([...idx.matchAll(/href="((?:http|stream|mail)\/[a-z0-9_]+\.html|ngx_[a-z0-9_]+\.html)[^"]*"/g)].map((m) => m[1]))].sort();
  const directives = {};
  const modules = {};
  const variables = {};
  for (const page of pages) {
    process.stderr.write(`${page} `);
    let html;
    try { html = await load(`en/docs/${page}`); } catch (e) { process.stderr.write(`(skip: ${e.message})\n`); continue; }
    const mod = page.replace(/^.*\//, '').replace(/\.html$/, '');
    const found = parseModule(html, mod);
    for (const v of parseVariables(html, mod)) variables[v.name] = { mod: v.mod, since: v.since };
    const flag = (html.match(/not built by default[^]*?<code>(--with-[a-z0-9_-]+)<\/code>/i) || [])[1] || null;
    const scope = page.startsWith('stream/') ? 'stream' : page.startsWith('mail/') ? 'mail' : page.startsWith('http/') ? 'http' : 'core';
    modules[mod] = { scope, flag, directives: found.length };
    for (const d of found) {
      const key = d.name;
      const entry = { syntax: d.syntax, ctx: d.ctx, def: d.def || undefined, mod, since: d.since || undefined, flag: d.flag || undefined, plus: d.commercial || undefined };
      (directives[key] = directives[key] || []).push(entry);
    }
    process.stderr.write(`${found.length}\n`);
  }
  const changes = parseChanges(await load('en/CHANGES'));
  const current = (await load('en/CHANGES')).match(/^Changes with nginx (\S+)/m)[1];
  const params = changes.params; delete changes.params;
  const kb = { product: 'nginx', generated: new Date().toISOString().slice(0, 10), source: 'https://nginx.org/en/docs/', latest: current, modules, directives, variables, params, changes };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(kb)}\n`);
  console.error(`wrote ${path.relative(process.cwd(), OUT)}: ${Object.keys(directives).length} directives from ${Object.keys(modules).length} modules, ${changes.length} lifecycle events (latest ${current})`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { parseModule, parseVariables, parseChanges, verCmp };

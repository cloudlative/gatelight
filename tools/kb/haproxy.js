#!/usr/bin/env node
'use strict';
/**
 * Builds src/kb/haproxy.json from the official HAProxy configuration manuals
 * (https://docs.haproxy.org/<version>/configuration.html), versions 1.7 .. latest.
 *
 *   node tools/kb/haproxy.js [--cache DIR] [--offline]
 *
 * Per version it extracts, from the manual's own anchors and tables:
 *   global     keywords of section 3.x ("global")
 *   proxy      keywords of 4.2 plus the "which section types accept it" matrix of 4.1 (+ deprecated / invertible marks)
 *   actions    rule actions (http-request <action>, tcp-request ..., http-response ...)
 *   bind       bind options (5.1)         server  server / default-server options (5.2)
 *   <section>  keywords of the other sections (peers, userlist, resolvers, mailers, cache, ring, ...)
 * and then diffs the versions to derive, for every keyword: since / removed-after / deprecated-since.
 * The manuals are only parsed as text; nothing in them is executed.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');

const VERSIONS = ['1.7', '1.8', '1.9', '2.0', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7', '2.8', '2.9', '3.0', '3.1', '3.2', '3.3', '3.4'];
const argv = process.argv.slice(2);
const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : null);
const cacheDir = path.resolve(opt('--cache') || path.join(os.tmpdir(), 'gatelight-kb', 'haproxy'));
const offline = argv.includes('--offline');
const OUT = path.join(__dirname, '..', '..', 'src', 'kb', 'haproxy.json');

const get = (url) => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'User-Agent': 'gatelight-kb-builder' } }, (res) => {
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url} -> ${res.statusCode}`)); }
    const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  }).on('error', reject);
});

const ENT = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&nbsp;': ' ', '&#39;': "'" };
const unent = (s) => s.replace(/&(lt|gt|amp|quot|nbsp|#39);/g, (m) => ENT[m]);
const stripTags = (s) => unent(s.replace(/<[^>]+>/g, ''));

async function loadHtml(v) {
  fs.mkdirSync(cacheDir, { recursive: true });
  const f = path.join(cacheDir, `${v}.html`);
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8');
  if (offline) throw new Error(`missing ${f} (offline)`);
  const html = await get(`https://docs.haproxy.org/${v}/configuration.html`);
  fs.writeFileSync(f, html);
  return html;
}

/** Map "3.4" -> title, from the plain-text rendering ("3.4. Peers"). */
function headings(text) {
  const map = new Map();
  for (const m of text.matchAll(/^(\d+(?:\.\d+){0,2})\. ([A-Z][^\n]{2,80})$/gm)) map.set(m[1], m[2].trim());
  return map;
}

// section titles of chapter 3 -> the config section type they describe
const SECTION_OF_TITLE = [
  [/^userlists?/i, 'userlist'], [/^peers/i, 'peers'], [/^resolvers|dns resolution/i, 'resolvers'], [/^mailers/i, 'mailers'],
  [/^programs?/i, 'program'], [/^http-errors/i, 'http-errors'], [/^rings?/i, 'ring'], [/^log.?forward/i, 'log-forward'],
  [/^cache/i, 'cache'], [/^fcgi/i, 'fcgi-app'], [/^certificate storage|^crt-store/i, 'crt-store'], [/^acme/i, 'acme'],
  [/^traces?$/i, 'traces'], [/^opentracing|^otel/i, 'opentracing'], [/^log profiles?/i, 'log-profile'], [/^stick-tables? declaration/i, 'stick-table'],
  [/^bandwidth limitation/i, 'bwlim'], [/^load options/i, 'load'], [/^peers declaration/i, 'peers'], [/^healthchecks?/i, 'healthchecks'],
];

function parseMatrix(html) {
  const out = new Map();
  const starts = [...html.matchAll(/Proxy keywords matrix/g)];
  if (!starts.length) return out;
  const from = starts[starts.length - 1].index;
  const tbl = html.slice(from, html.indexOf('</table>', from));
  for (const row of tbl.split('<tr>').slice(1)) {
    const cells = row.split(/<\/td>/).slice(0, 5);
    if (cells.length < 5) continue;
    let name = stripTags(cells[0]).replace(/\s+/g, ' ').trim();
    if (!name) continue;
    const deprecated = /\(deprecated\)/i.test(name);
    const invertible = /\(\*\)/.test(name);
    name = name.replace(/\(deprecated\)/ig, '').replace(/\(\*\)/g, '').trim();
    const mask = cells.slice(1, 5).map((c) => /alt="X/.test(c) || /title="yes/.test(c)).map((b, i) => (b ? 'dflb'[i] : '')).join('');
    out.set(name, { mask, deprecated, invertible });
  }
  return out;
}

function extract(html) {
  const text = stripTags(html);
  const heads = headings(text);
  const titleChain = (sec) => { const parts = sec.split('.'); const out = []; for (let i = parts.length; i >= 1; i--) out.push(heads.get(parts.slice(0, i).join('.')) || ''); return out; };
  const anchors = [...html.matchAll(/\bname="(\d+(?:\.\d+)*)-([^"]+)"/g)].map((m) => [m[1], unent(m[2])]);
  const matrix = parseMatrix(html);
  const sets = { global: new Set(), proxy: new Set(), actions: new Set(), bind: new Set(), server: new Set(), fetches: new Set(), converters: new Set(), unmatched: new Set(), sections: {} };
  const argc = {}; // option name -> number of mandatory <args> (from the entry's first line)
  const rootsOfMatrix = new Set([...matrix.keys()].map((k) => k.split(' ')[0]));
  const a44 = new Set(anchors.filter(([sec]) => sec === '4.4').map(([, k]) => k.replace(/\(.*$/, '')));
  for (const [sec, kw] of anchors) {
    const top = sec.split('.')[0];
    const kwN = kw.trim();
    if (!kwN || /\s{2,}|[<>]/.test(kwN)) continue;
    if (sec === '3' || sec === '5') continue; // chapter-level anchors duplicate every keyword of the chapter
    const mapped = titleChain(sec).map((t) => SECTION_OF_TITLE.find(([re]) => re.test(t))).find(Boolean);
    if (mapped && top !== '4' && top !== '5') { (sets.sections[mapped[1]] = sets.sections[mapped[1]] || new Set()).add(kwN); continue; }
    if (top === '3') sets.global.add(kwN);
    else if (sec === '4.2' || sec === '4') {
      const bare = kwN.replace(/^no /, '');
      if (/^tcp-resposne/.test(bare)) continue; // typo in the 2.x manuals
      const m = bare.match(/^(http-request|http-response|http-after-response|tcp-request(?: \w+)?|tcp-response) ([a-z0-9-]+)/);
      if (m) sets.actions.add(m[2]);
      else if (matrix.has(bare) || (rootsOfMatrix.has(bare.split(' ')[0]) && !a44.has(bare))) sets.proxy.add(bare);
      else if (!a44.has(bare) && !/\s/.test(bare)) sets.unmatched.add(bare); // decided once all versions are known (see main)
    } else if (sec === '4.4') sets.actions.add(kwN.replace(/\(.*$/, ''));
    else if (sec === '5.1' || sec === '5.2') {
      (sec === '5.1' ? sets.bind : sets.server).add(kwN);
      const at = html.indexOf(`name="${sec}-${kw.replace(/&/g, '&amp;')}"`);
      const dv = html.indexOf('<div class="keyword">', at); const dEnd = dv >= 0 ? html.indexOf('</div>', dv) : -1;
      const head = dv >= 0 && dv - at < 600 ? stripTags(html.slice(dv, dEnd)).slice(kwN.length).trim() : '';
      const choice = /^\[[^\]]*\|[^\]]*\]/.test(head); // "[ SSLv3 | TLSv1.0 | ... ]" is a mandatory choice
      const hd = head.replace(/\[[^\]]*\]/g, '').trim(); const m = [hd];
      argc[`${sec === '5.1' ? 'b' : 's'}:${kwN}`] = choice ? 1 : !hd ? 0 : /\|/.test(hd) ? 1 : hd.split(/\s+/).length;
    }
    else if (sec === '7.3.1') sets.converters.add(kwN.replace(/\(.*$/, ''));
    else if (/^7\.3\.[2-7]$/.test(sec)) sets.fetches.add(kwN.replace(/\(.*$/, ''));
    else if (sec.startsWith('5.3')) (sets.sections.resolvers = sets.sections.resolvers || new Set()).add(kwN);
    else if (top === '6') (sets.sections.cache = sets.sections.cache || new Set()).add(kwN);
  }
  // ACL derivatives (path_beg, hdr_end, ...) are only listed inside each fetch's description
  for (const m of text.matchAll(/ACL derivatives\s*:\s*\n((?:[ \t]+[a-z][^\n]*\n|[ \t]*\n(?=[ \t]+[a-z0-9_.-]+(?:\([^)]*\))?[ \t]+:))+)/g)) {
    for (const l of m[1].matchAll(/^[ \t]+([a-z][a-z0-9_.-]*)(?:\([^)]*\))?[ \t]+:/gm)) sets.fetches.add(l[1]);
  }
  // global keywords also appear as the bullet summary of section 3 (covers ones without an own anchor)
  const s3 = text.search(/The following keywords are supported in the "global" section/);
  if (s3 > 0) for (const m of text.slice(s3, s3 + 20000).matchAll(/^\s+- ([a-z0-9][a-z0-9_.-]*)\s*$/gm)) sets.global.add(m[1]);
  return { matrix, argc, ...sets };
}

const cmpVer = (a, b) => VERSIONS.indexOf(a) - VERSIONS.indexOf(b);

function collapse(perVersion, pick, withMeta) {
  const names = new Set();
  for (const v of VERSIONS) for (const k of pick(perVersion[v])) names.add(k);
  const out = {};
  const latest = VERSIONS[VERSIONS.length - 1];
  for (const k of [...names].sort()) {
    const have = VERSIONS.filter((v) => pick(perVersion[v]).has(k));
    const e = { s: have[0] };
    if (have[have.length - 1] !== latest) e.r = have[have.length - 1]; // last version that still knows it
    if (withMeta) {
      let prevMask = null; const ch = [];
      for (const v of have) {
        const m = perVersion[v].matrix.get(k);
        if (!m) continue;
        if (m.mask !== prevMask) { ch.push([v, m.mask]); prevMask = m.mask; }
        if (m.deprecated && !e.d) e.d = v;
        if (m.invertible) e.n = 1;
      }
      if (ch.length) { e.c = ch[ch.length - 1][1]; if (ch.length > 1) e.cc = ch; }
    }
    out[k] = e;
  }
  return out;
}

async function main() {
  const perVersion = {};
  for (const v of VERSIONS) {
    process.stderr.write(`HAProxy ${v}: `);
    const x = extract(await loadHtml(v));
    // the matrix is authoritative for proxy keywords (multi-word ones like "option httplog" only exist there)
    for (const k of x.matrix.keys()) if (!/^tcp-resposne/.test(k)) x.proxy.add(k); // (the manual has a typo'd row in 2.x)
    perVersion[v] = x;
    process.stderr.write(`${x.proxy.size} proxy, ${x.actions.size} actions, ${x.global.size} global, ${x.bind.size} bind, ${x.server.size} server, ${Object.keys(x.sections).length} section kinds\n`);
  }
  // mandatory-argument counts of bind/server options: take the newest documented value
  const argc = {}; for (const v of VERSIONS) Object.assign(argc, perVersion[v].argc);
  // 4.2 anchors that are neither in the matrix nor documented actions (e.g. dynamic-cookie-key, ssl-f-use) are real keywords;
  // before 4.4 existed the manuals mixed action names in here, so exclude every name that is an action in any version.
  const everAction = new Set(); for (const v of VERSIONS) for (const a of perVersion[v].actions) everAction.add(a);
  for (const v of VERSIONS) for (const k of perVersion[v].unmatched) if (!everAction.has(k)) perVersion[v].proxy.add(k);
  const sectionNames = new Set(); VERSIONS.forEach((v) => Object.keys(perVersion[v].sections).forEach((s) => sectionNames.add(s)));
  const kb = {
    product: 'haproxy', versions: VERSIONS, generated: new Date().toISOString().slice(0, 10), source: 'https://docs.haproxy.org/',
    global: collapse(perVersion, (p) => p.global, false),
    proxy: collapse(perVersion, (p) => p.proxy, true),
    actions: collapse(perVersion, (p) => p.actions, false),
    bind: collapse(perVersion, (p) => p.bind, false),
    server: collapse(perVersion, (p) => p.server, false),
    fetches: collapse(perVersion, (p) => p.fetches, false),
    converters: collapse(perVersion, (p) => p.converters, false),
    argc,
    sections: {},
  };
  // a bare family word ("capture") that stopped having its own row, while its sub-keywords ("capture request") live on, was not removed
  for (const [k, e] of Object.entries(kb.proxy)) if (e.r && Object.keys(kb.proxy).some((o) => o.startsWith(`${k} `) && !kb.proxy[o].r)) delete e.r;
  for (const s of [...sectionNames].sort()) {
    const withSet = Object.fromEntries(VERSIONS.map((v) => [v, { ...perVersion[v], x: perVersion[v].sections[s] || new Set() }]));
    kb.sections[s] = collapse(withSet, (p) => p.x, false);
  }
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(kb)}\n`);
  const n = (o) => Object.keys(o).length;
  console.error(`wrote ${path.relative(process.cwd(), OUT)}: ${n(kb.global)} global, ${n(kb.proxy)} proxy, ${n(kb.actions)} actions, ${n(kb.bind)} bind, ${n(kb.server)} server, ${n(kb.fetches)} fetches, ${n(kb.converters)} converters, ${Object.keys(kb.sections).length} extra sections`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { VERSIONS, extract, cmpVer };

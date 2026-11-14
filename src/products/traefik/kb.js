'use strict';
/** Knowledge-base helpers: versions, availability of options / matchers, documentation links, option path lookup. */
const kb = require('../../kb/traefik.json');
const V = require('../../validate/version');

const minorOf = (v) => { const p = V.parse(v); return p ? `${p[0]}.${p[1]}` : null; };
const MINORS = kb.versions.map(minorOf);

function versions() {
  return { list: [...kb.versions].reverse(), latest: kb.latest, generated: kb.generated, source: kb.source };
}

/** Requested version -> { requested, version, minor, major, note }. Unknown / newer / older fall back with a note. */
function resolveVersion(requested) {
  const req = requested ? String(requested).trim() : null;
  const p = V.parse(req);
  const latestMinor = minorOf(kb.latest);
  if (!req) return { requested: null, version: kb.latest, minor: latestMinor, major: kb.latest.split('.')[0], note: null };
  if (!p) return { requested: req, version: kb.latest, minor: latestMinor, major: kb.latest.split('.')[0], note: `Could not read "${req}" as a version; using the latest documented release (${kb.latest}).` };
  const m = `${p[0]}.${p[1]}`;
  if (MINORS.includes(m)) return { requested: req, version: /^\D*\d+\.\d+\.\d+/.test(req) ? p.join('.') : kb.versions[MINORS.indexOf(m)], minor: m, major: String(p[0]), note: null };
  if (V.cmp(p, kb.latest) > 0) return { requested: req, version: p.join('.'), minor: latestMinor, major: kb.latest.split('.')[0], note: `${req} is newer than the newest documented release (${kb.latest}); options added after it may be reported as unknown.` };
  if (p[0] < 2) return { requested: req, version: kb.versions[0], minor: MINORS[0], major: '2', note: `Traefik ${req} (v1) uses a different configuration format; validating against ${kb.versions[0]}, the oldest v2 release. See the v1 to v2 migration guide.` };
  // a minor between documented ones (should not happen) -> nearest older
  const older = MINORS.filter((x) => V.cmp(x, m) <= 0).pop() || MINORS[0];
  return { requested: req, version: p.join('.'), minor: older, major: String(p[0]), note: null };
}

const idx = (m) => MINORS.indexOf(m);
/** Is a KB entry ({ s, u, r }) available in a minor version? */
function available(e, minor) {
  if (!e) return false;
  const i = idx(minor);
  const inRange = (s, u) => idx(s) <= i && (u == null || i < idx(u));
  if (e.r) return e.r.some(([s, u]) => inRange(s, u));
  return inRange(e.s, e.u);
}

/** Documentation URL for a topic (see kb.docs pages) for the major version of the target. */
function docsUrl(topic, major = kb.latest.split('.')[0], anchor = '') {
  const d = kb.docs[`v${major}`] || kb.docs[`v${kb.latest.split('.')[0]}`];
  if (!d) return undefined;
  const page = d.pages[topic] || d.pages[topic.replace(/^mw\./, 'http.mw.')];
  if (!page) return d.base;
  return `${d.base}${page}${anchor ? `#${anchor}` : ''}`;
}
const middlewareDocs = (type, major, proto = 'http') => docsUrl(`${proto}.mw.${type}`, major) || docsUrl('middlewares', major);

// ------------------------------------------------------------------------------------------------ option path trie
function trie(table) {
  const root = { kids: new Map(), e: null, path: '' };
  for (const [p, e] of Object.entries(table)) {
    const segs = p.split('.').flatMap((s) => (s.endsWith('[]') ? [s.slice(0, -2), '[]'] : [s]));
    let n = root; let acc = '';
    for (const s of segs) {
      acc = acc ? (s === '[]' ? `${acc}[]` : `${acc}.${s}`) : s;
      if (!n.kids.has(s)) n.kids.set(s, { kids: new Map(), e: null, path: acc });
      n = n.kids.get(s);
    }
    n.e = e;
  }
  return root;
}
const TRIES = { static: trie(kb.static), dynamic: trie(kb.dynamic) };
const OPEN = /^(http\.middlewares\.<name>\.plugin\.<name>|experimental\.(plugins|localPlugins)\.<name>\.settings|providers\.plugin\.<name>)/;

/**
 * Find the KB node for a user option path (array indexes as numbers). Returns
 * { node, kbPath, exact } or { missingAt: index, parent: node } when a segment is unknown.
 * Matching is case-insensitive like Traefik's own decoder; `caseMismatch` lists segments written in another case.
 */
function lookup(kind, segs) {
  let n = TRIES[kind]; const caseMismatch = [];
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    if (typeof s === 'number' || /^\d+$/.test(String(s)) && n.kids.has('[]')) { if (n.kids.has('[]')) { n = n.kids.get('[]'); continue; } if (/^list/.test((n.e || {}).t || '')) return { node: n, kbPath: n.path, item: true }; return { missingAt: i, parent: n }; }
    if (OPEN.test(n.path)) return { node: n, kbPath: n.path, open: true };
    let next = n.kids.get(s);
    if (!next) { const k = [...n.kids.keys()].find((x) => x.toLowerCase() === String(s).toLowerCase()); if (k && k !== '<name>') { next = n.kids.get(k); caseMismatch.push({ at: i, written: s, canonical: k }); } }
    if (!next && n.kids.has('<name>')) next = n.kids.get('<name>');
    if (!next) return { missingAt: i, parent: n, caseMismatch };
    n = next;
  }
  return { node: n, kbPath: n.path, caseMismatch };
}
/** Known child names under a node (for did-you-mean). */
const childNames = (node) => [...node.kids.keys()].filter((k) => k !== '<name>' && k !== '[]');

/** Deprecation entry for a KB path, if any. */
function deprecation(kbPath) {
  for (const d of kb.deprecated || []) if (new RegExp(d.re).test(kbPath)) return d;
  return null;
}

module.exports = { kb, versions, resolveVersion, available, docsUrl, middlewareDocs, lookup, childNames, deprecation, minorOf, MINORS };

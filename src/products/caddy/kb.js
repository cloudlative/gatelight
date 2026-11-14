'use strict';
/** Knowledge-base helpers (src/kb/caddy.json, built by tools/kb/caddy.js from Caddy's release tags and docs). */
const kb = require('../../kb/caddy.json');
const V = require('../../validate/version');

const DOCS = 'https://caddyserver.com/docs';

/** Resolve a requested version to { requested, version, note } (default: latest documented release). */
function target(requested) {
  const p = V.parse(requested);
  if (!requested) return { requested: null, version: kb.latest, note: null };
  if (!p) return { requested, version: kb.latest, note: `Could not read "${requested}" as a version; using the latest documented release (${kb.latest}).` };
  const v = p.join('.');
  if (V.cmp(v, kb.latest) > 0) return { requested, version: v, note: `${requested} is newer than the newest release in the knowledge base (${kb.latest}); newer directives may be reported as unknown.` };
  if (V.cmp(v, kb.versions[kb.versions.length - 1]) < 0) return { requested, version: v, note: `Caddy ${requested} predates v2 (the knowledge base covers ${kb.versions[kb.versions.length - 1]} and later).` };
  return { requested, version: v, note: null };
}

/** Default directive order of a release. */
function orderFor(version) {
  let o = kb.orders[0].order;
  for (const e of kb.orders) if (V.gte(version, e.since)) o = e.order;
  return o;
}

/** Is a KB entry ({since, until}) available in `version`? */
const available = (e, version) => Boolean(e) && V.gte(version, e.since) && (!e.until || V.cmp(version, e.until) <= 0);

const directiveDocs = (name) => (kb.directives[name] ? kb.directives[name].docs : `${DOCS}/caddyfile/directives/${name}`);
const optionDocs = (name) => (kb.options[name] ? kb.options[name].docs : `${DOCS}/caddyfile/options#${String(name).replace(/_/g, '-')}`);
const matcherDocs = (name) => `${DOCS}/caddyfile/matchers#${String(name).replace(/_/g, '-')}`;

module.exports = { kb, V, DOCS, target, orderFor, available, directiveDocs, optionDocs, matcherDocs };

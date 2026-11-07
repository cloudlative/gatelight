'use strict';
/** Version parsing / comparison shared by the validators. */

const parse = (v) => {
  const m = String(v == null ? '' : v).match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] || 0)] : null;
};

/** -1 / 0 / 1 like a comparator; unparsable values compare as equal. */
function cmp(a, b) {
  const x = Array.isArray(a) ? a : parse(a); const y = Array.isArray(b) ? b : parse(b);
  if (!x || !y) return 0;
  for (let i = 0; i < 3; i++) { if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1; }
  return 0;
}
const lt = (a, b) => cmp(a, b) < 0;
const gte = (a, b) => cmp(a, b) >= 0;

/** Pull a version out of free text: "HAProxy version 2.8.5-1ubuntu", "nginx/1.24.0 (Ubuntu)", "2.8". */
function detect(text) {
  const t = String(text || '');
  const h = t.match(/HA-?Proxy[^0-9]{0,20}(\d+\.\d+(?:\.\d+)?)/i);
  if (h) return h[1];
  const n = t.match(/nginx[\/ version:]*\s*(\d+\.\d+(?:\.\d+)?)/i);
  if (n) return n[1];
  const any = t.match(/\b(\d+\.\d+(?:\.\d+)?)\b/);
  return any ? any[1] : null;
}

/** Map an installed HAProxy version to the newest documented branch that is not newer (2.8.5 -> "2.8"). */
function haproxyBranch(v, versions) {
  const p = parse(v); if (!p) return null;
  let best = null;
  for (const b of versions) { const bp = parse(b); if (bp[0] < p[0] || (bp[0] === p[0] && bp[1] <= p[1])) best = b; }
  return best || versions[0];
}

module.exports = { parse, cmp, lt, gte, detect, haproxyBranch };

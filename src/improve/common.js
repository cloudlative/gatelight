'use strict';
/** Shared helpers for the config improver (Config Forge): change bookkeeping, scoring and a line diff. */

const SEV_W = { high: 6, medium: 2.5, low: 1, info: 0.25 };
const CATEGORIES = ['security', 'reliability', 'performance', 'observability', 'compatibility', 'hygiene'];

/** Score 0..100 from the findings that are still open. Each rule counts at most 3 times so one noisy rule cannot zero the score. */
function score(findings) {
  const seen = new Map(); let pen = 0;
  for (const f of findings) {
    const key = f.rule || f.id; const n = (seen.get(key) || 0) + 1; seen.set(key, n);
    if (n <= 3) pen += SEV_W[f.severity] || 1;
  }
  return Math.max(0, Math.round(100 - pen));
}
const grade = (s) => (s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F');

/** Myers-style line diff (common prefix/suffix trimmed, then LCS on the middle). Returns hunks with 3 lines of context. */
function diffLines(a, b, context = 3) {
  let s = 0; while (s < a.length && s < b.length && a[s] === b[s]) s++;
  let ea = a.length; let eb = b.length; while (ea > s && eb > s && a[ea - 1] === b[eb - 1]) { ea--; eb--; }
  const A = a.slice(s, ea); const B = b.slice(s, eb);
  const ops = []; // {t:' '|'-'|'+', text}
  for (let i = 0; i < s; i++) ops.push({ t: ' ', text: a[i] });
  if (A.length * B.length > 4e6) { A.forEach((x) => ops.push({ t: '-', text: x })); B.forEach((x) => ops.push({ t: '+', text: x })); } else {
    const n = A.length; const m = B.length; const w = m + 1; const L = new Uint32Array((n + 1) * w);
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i * w + j] = A[i] === B[j] ? L[(i + 1) * w + j + 1] + 1 : Math.max(L[(i + 1) * w + j], L[i * w + j + 1]);
    let i = 0; let j = 0;
    while (i < n && j < m) { if (A[i] === B[j]) { ops.push({ t: ' ', text: A[i] }); i++; j++; } else if (L[(i + 1) * w + j] >= L[i * w + j + 1]) { ops.push({ t: '-', text: A[i++] }); } else ops.push({ t: '+', text: B[j++] }); }
    while (i < n) ops.push({ t: '-', text: A[i++] }); while (j < m) ops.push({ t: '+', text: B[j++] });
  }
  for (let i = ea; i < a.length; i++) ops.push({ t: ' ', text: a[i] });
  // number the lines, then cut into hunks
  let la = 1; let lb = 1; const rows = ops.map((o) => { const r = { ...o, a: o.t === '+' ? null : la, b: o.t === '-' ? null : lb }; if (o.t !== '+') la++; if (o.t !== '-') lb++; return r; });
  const hunks = []; let cur = null; let quiet = 0;
  rows.forEach((r, i) => {
    if (r.t !== ' ') { if (!cur) { cur = { rows: [] }; for (let k = Math.max(0, i - context); k < i; k++) cur.rows.push(rows[k]); } cur.rows.push(r); quiet = 0; } else if (cur) { cur.rows.push(r); quiet++; if (quiet > context * 2) { cur.rows.length -= context; hunks.push(cur); cur = null; } }
  });
  if (cur) { let drop = 0; for (let k = cur.rows.length - 1; k >= 0 && cur.rows[k].t === ' ' && drop < Math.max(0, quiet - context); k--) drop++; cur.rows.length -= drop; hunks.push(cur); }
  const added = rows.filter((r) => r.t === '+').length; const removed = rows.filter((r) => r.t === '-').length;
  return { hunks, added, removed };
}

/** Split a line into tokens, honouring "double" and 'single' quotes; stops at an unquoted # that starts a token. */
function tokens(line) {
  const out = []; let i = 0; const n = line.length;
  while (i < n) {
    while (i < n && /\s/.test(line[i])) i++;
    if (i >= n || line[i] === '#') break;
    let t = '';
    while (i < n && !/\s/.test(line[i])) {
      const c = line[i];
      if (c === '"' || c === "'") { const q = c; t += c; i++; while (i < n && line[i] !== q) { if (line[i] === '\\' && i + 1 < n) { t += line[i++]; } t += line[i++]; } if (i < n) { t += q; i++; } } else { t += c; i++; }
    }
    out.push(t);
  }
  return out;
}
const unq = (s) => String(s).replace(/^(["'])(.*)\1$/, '$2');

module.exports = { SEV_W, CATEGORIES, score, grade, diffLines, tokens, unq };

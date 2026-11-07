'use strict';
/** "Did you mean" helper: nearest candidates by edit distance (bounded, so it stays cheap on big keyword sets). */
function distance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i]; let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (cur[j] < best) best = cur[j];
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

function suggest(word, candidates, limit = 3) {
  const w = String(word).toLowerCase();
  const max = Math.max(1, Math.min(3, Math.floor(w.length / 3)));
  const out = [];
  for (const c of candidates) {
    const d = distance(w, c.toLowerCase(), max);
    if (d <= max) out.push([d, c]);
  }
  return out.sort((a, b) => a[0] - b[0] || a[1].localeCompare(b[1])).slice(0, limit).map((x) => x[1]);
}

module.exports = { suggest, distance };

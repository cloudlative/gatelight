'use strict';
/**
 * Minimal, comment-preserving edits of YAML / TOML configuration text by option path (used by Config Doctor).
 * Every operation re-reads the current text, so edits compose in any order. Operations throw EditError when the
 * layout is too unusual to edit safely (e.g. a non-empty flow mapping); the caller then leaves the file unchanged.
 */
const YAML = require('./yaml');
const TOML = require('./toml');

class EditError extends Error {}
const isToml = (name) => /\.toml$/i.test(name);

// ------------------------------------------------------------------------------------------------ values
function yamlValue(v) {
  if (Array.isArray(v)) return `[${v.map((x) => YAML.scalar(x)).join(', ')}]`;
  if (v && typeof v === 'object') return Object.keys(v).length ? `{ ${Object.entries(v).map(([k, x]) => `${k}: ${yamlValue(x)}`).join(', ')} }` : '{}';
  return YAML.scalar(v);
}
function tomlValue(v) {
  if (Array.isArray(v)) return `[${v.map(tomlValue).join(', ')}]`;
  if (typeof v === 'string') return JSON.stringify(v);
  if (v && typeof v === 'object') return `{ ${Object.entries(v).map(([k, x]) => `${k} = ${tomlValue(x)}`).join(', ')} }`;
  return String(v);
}

// ------------------------------------------------------------------------------------------------ YAML
const indentOf = (l) => (/^ */.exec(l) || [''])[0].length;
const blankOrComment = (l) => !l.trim() || /^\s*#/.test(l);
function unitOf(lines) {
  const counts = new Map(); let prev = 0;
  for (const l of lines) { if (blankOrComment(l)) continue; const i = indentOf(l); if (i > prev) counts.set(i - prev, (counts.get(i - prev) || 0) + 1); prev = i; }
  let best = 2; let n = 0; for (const [k, c] of counts) if (c > n && k <= 8) { best = k; n = c; }
  return best;
}
function yamlLines(text) { return YAML.parse(text, { allowDuplicateKeys: true }).lines; }
/** Last line index (0-based) of the block that starts at line index i (the key line). */
function blockEnd(lines, i) {
  const ind = indentOf(lines[i]); let end = i;
  for (let k = i + 1; k < lines.length; k++) {
    const l = lines[k];
    if (blankOrComment(l)) continue;
    if (indentOf(l) > ind || (indentOf(l) === ind && /^\s*-( |$)/.test(l) && !/^\s*-/.test(lines[i]))) end = k; else break;
  }
  return end;
}
/** Replace the value written after "key:" on a line, keeping the key and a trailing comment. */
function replaceInline(line, valueText) {
  const m = /^(\s*(?:-\s+)?(?:"[^"]*"|'[^']*'|[^:#]+?)\s*:)(\s*)(.*)$/.exec(line);
  if (!m) throw new EditError('cannot locate the value');
  const c = YAML.stripComment(m[3]); const comment = m[3].slice(c.length);
  return `${m[1]} ${valueText}${comment}`;
}

function yamlSet(text, segs, value) {
  const lines = text.split('\n');
  const map = yamlLines(text);
  const unit = unitOf(lines);
  const full = YAML.lineOf(map, segs);
  const vt = yamlValue(value);
  if (full) {
    const i = full - 1;
    const end = blockEnd(lines, i);
    if (end > i) lines.splice(i + 1, end - i); // nested block replaced by the new scalar / flow value
    lines[i] = replaceInline(lines[i], vt);
    return lines.join('\n');
  }
  let k = segs.length - 1;
  while (k > 0 && !YAML.lineOf(map, segs.slice(0, k))) k--;
  const rest = segs.slice(k);
  let at; let ind;
  if (k === 0) {
    at = lines.length; while (at > 0 && !lines[at - 1].trim()) at--;
    ind = 0;
    const block = rest.map((s, j) => `${' '.repeat(ind + j * unit)}${keyText(s)}:${j === rest.length - 1 ? ` ${vt}` : ''}`);
    lines.splice(at, 0, ...(at > 0 ? [''] : []), ...block);
    return lines.join('\n').replace(/\n*$/, '\n');
  }
  const pi = YAML.lineOf(map, segs.slice(0, k)) - 1;
  const pline = lines[pi];
  const after = YAML.stripComment(pline.replace(/^(\s*(?:-\s+)?(?:"[^"]*"|'[^']*'|[^:#]+?)\s*:)/, '')).trim();
  if (after === '{}' || after === 'null' || after === '~') lines[pi] = pline.replace(/:\s*(\{\}|null|~)/, ':');
  else if (after && !/^[&!]/.test(after)) throw new EditError(`"${segs.slice(0, k).join('.')}" is written inline; edit it by hand`);
  const end = blockEnd(lines, pi);
  // indentation of existing children, else parent + unit (a "- key:" parent indents its children past the dash)
  let cind = null;
  for (let q = pi + 1; q <= end; q++) if (!blankOrComment(lines[q])) { cind = indentOf(lines[q]); break; }
  if (cind === null) { const dash = /^(\s*)-\s+/.exec(pline); cind = dash ? dash[0].length + unit : indentOf(pline) + unit; }
  at = end + 1;
  const block = rest.map((s, j) => `${' '.repeat(cind + j * unit)}${keyText(s)}:${j === rest.length - 1 ? ` ${vt}` : ''}`);
  lines.splice(at, 0, ...block);
  return lines.join('\n');
}
const keyText = (k) => (/^[A-Za-z0-9_.-]+$/.test(k) && !/^\d+$/.test(k) ? k : JSON.stringify(k));

function yamlRename(text, segs, newKey) {
  const lines = text.split('\n'); const l = YAML.lineOf(yamlLines(text), segs);
  if (!l) throw new EditError('key not found');
  const old = segs[segs.length - 1];
  const re = new RegExp(`^(\\s*(?:-\\s+)?)(["']?)${old.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\2(\\s*:)`);
  if (!re.test(lines[l - 1])) throw new EditError('key not on its line');
  lines[l - 1] = lines[l - 1].replace(re, `$1$2${newKey}$2$3`);
  return lines.join('\n');
}
function yamlDelete(text, segs) {
  const lines = text.split('\n'); const l = YAML.lineOf(yamlLines(text), segs);
  if (!l) return text;
  const end = blockEnd(lines, l - 1);
  lines.splice(l - 1, end - l + 2);
  return lines.join('\n');
}
/** Append an item to a list (block or flow); creates the list when missing. */
function yamlAppend(text, segs, item) {
  const lines = text.split('\n'); const map = yamlLines(text);
  const l = YAML.lineOf(map, segs);
  if (!l) return yamlSet(text, segs, [item]);
  const i = l - 1;
  const inline = YAML.stripComment(lines[i].replace(/^(\s*(?:-\s+)?(?:"[^"]*"|'[^']*'|[^:#]+?)\s*:)/, '')).trim();
  if (/^\[.*\]$/.test(inline)) {
    const inner = inline.slice(1, -1).trim();
    lines[i] = replaceInline(lines[i], `[${inner ? `${inner}, ` : ''}${YAML.scalar(item)}]`);
    return lines.join('\n');
  }
  if (inline) throw new EditError('list written inline in an unusual way');
  const end = blockEnd(lines, i);
  let dashInd = null; for (let q = i + 1; q <= end; q++) if (/^\s*-/.test(lines[q])) { dashInd = indentOf(lines[q]); break; }
  if (dashInd === null) dashInd = indentOf(lines[i]) + unitOf(lines);
  lines.splice(end + 1, 0, `${' '.repeat(dashInd)}- ${YAML.scalar(item)}`);
  return lines.join('\n');
}
/** Replace a list item value (by index). */
function yamlSetItem(text, segs, index, value) {
  const lines = text.split('\n'); const l = YAML.lineOf(yamlLines(text), [...segs, index]);
  if (!l) throw new EditError('item not found');
  const line = lines[l - 1];
  const parentLine = YAML.lineOf(yamlLines(text), segs);
  if (l === parentLine) { // flow list on the parent line
    const data = YAML.parse(text, { allowDuplicateKeys: true }).data; let v = data; for (const s of segs) v = v[s];
    const copy = [...v]; copy[index] = value;
    lines[l - 1] = replaceInline(line, `[${copy.map((x) => YAML.scalar(x)).join(', ')}]`);
    return lines.join('\n');
  }
  lines[l - 1] = line.replace(/^(\s*-\s*).*$/, (m, pre) => { const c = YAML.stripComment(line.slice(pre.length)); return `${pre}${YAML.scalar(value)}${line.slice(pre.length + c.length)}`; });
  return lines.join('\n');
}

// ------------------------------------------------------------------------------------------------ TOML
const tomlKey = (k) => (/^[A-Za-z0-9_-]+$/.test(k) ? k : JSON.stringify(k));
function tomlHeaders(lines) {
  const out = [];
  lines.forEach((l, i) => { const m = /^\s*\[(?!\[)\s*([^\]]+?)\s*\]\s*(#.*)?$/.exec(l); if (m) out.push({ i, path: splitDotted(m[1]) }); const a = /^\s*\[\[\s*([^\]]+?)\s*\]\]/.exec(l); if (a) out.push({ i, path: splitDotted(a[1]), array: true }); });
  return out;
}
function splitDotted(s) { const out = []; const re = /\s*("([^"]*)"|'([^']*)'|[A-Za-z0-9_-]+)\s*(\.|$)/g; let m; while ((m = re.exec(s)) && m[0]) { out.push(m[2] ?? m[3] ?? m[1]); if (!m[4]) break; } return out; }
const samePath = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function tomlSet(text, segs, value) {
  const lines = text.split('\n'); const parsed = TOML.parse(text);
  const full = YAML.lineOf(parsed.lines, segs);
  if (full) {
    const i = full - 1;
    const last = segs[segs.length - 1];
    const re = new RegExp(`^(\\s*(?:[A-Za-z0-9_."'-]+\\.)?["']?${last.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?\\s*=\\s*)(.*)$`);
    const m = re.exec(lines[i]);
    if (!m) throw new EditError('value is not on a simple "key = value" line');
    const comment = (/\s+#.*$/.exec(m[2]) || [''])[0];
    lines[i] = `${m[1]}${tomlValue(value)}${comment}`;
    return lines.join('\n');
  }
  const headers = tomlHeaders(lines);
  let best = null;
  for (const h of headers) if (!h.array && h.path.length < segs.length && samePath(h.path, segs.slice(0, h.path.length)) && (!best || h.path.length > best.path.length)) best = h;
  if (best) {
    const next = headers.find((h) => h.i > best.i);
    let at = next ? next.i : lines.length; while (at > best.i + 1 && !lines[at - 1].trim()) at--;
    const ind = (/^\s*/.exec(lines[best.i + 1] || '') || [''])[0] || '  ';
    lines.splice(at, 0, `${lines[best.i + 1] && lines[best.i + 1].trim() && !/^\s*\[/.test(lines[best.i + 1]) ? ind : '  '}${segs.slice(best.path.length).map(tomlKey).join('.')} = ${tomlValue(value)}`);
    return lines.join('\n');
  }
  let at = lines.length; while (at > 0 && !lines[at - 1].trim()) at--;
  lines.splice(at, 0, ...(at ? [''] : []), `[${segs.slice(0, -1).map(tomlKey).join('.')}]`, `  ${tomlKey(segs[segs.length - 1])} = ${tomlValue(value)}`);
  return `${lines.join('\n').replace(/\n*$/, '')}\n`;
}
function tomlRename(text, segs, newKey) {
  const lines = text.split('\n');
  const old = segs[segs.length - 1];
  const esc = old.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let changed = false;
  // table headers containing the key path, and "key = " lines
  const prefix = segs.slice(0, -1);
  for (const h of tomlHeaders(lines)) {
    if (h.path.length >= segs.length && samePath(h.path.slice(0, segs.length), segs)) { lines[h.i] = lines[h.i].replace(new RegExp(`(\\.|\\[)\\s*${esc}\\s*(\\.|\\])`), `$1${newKey}$2`); changed = true; }
  }
  const l = YAML.lineOf(TOML.parse(text).lines, segs);
  if (l && !tomlHeaders(lines).some((h) => h.i === l - 1)) { lines[l - 1] = lines[l - 1].replace(new RegExp(`^(\\s*(?:[A-Za-z0-9_-]+\\.)*)${esc}(\\s*[.=])`), `$1${newKey}$2`); changed = true; }
  void prefix;
  if (!changed) throw new EditError('key not found');
  return lines.join('\n');
}
function tomlDelete(text, segs) {
  const lines = text.split('\n'); const l = YAML.lineOf(TOML.parse(text).lines, segs);
  if (!l) return text;
  const h = tomlHeaders(lines).find((x) => x.i === l - 1);
  if (h) { const next = tomlHeaders(lines).find((x) => x.i > h.i && !samePath(x.path.slice(0, segs.length), segs)); lines.splice(h.i, (next ? next.i : lines.length) - h.i); }
  else lines.splice(l - 1, 1);
  return lines.join('\n');
}
function tomlAppend(text, segs, item) {
  const parsed = TOML.parse(text); let v = parsed.data; for (const s of segs) v = v && v[s];
  return tomlSet(text, segs, [...(Array.isArray(v) ? v : []), item]);
}

// ------------------------------------------------------------------------------------------------ dispatch
const set = (name, text, segs, value) => (isToml(name) ? tomlSet(text, segs, value) : yamlSet(text, segs, value));
const renameKey = (name, text, segs, newKey) => (isToml(name) ? tomlRename(text, segs, newKey) : yamlRename(text, segs, newKey));
const del = (name, text, segs) => (isToml(name) ? tomlDelete(text, segs) : yamlDelete(text, segs));
const append = (name, text, segs, item) => (isToml(name) ? tomlAppend(text, segs, item) : yamlAppend(text, segs, item));

module.exports = { set, renameKey, del, append, yamlSet, yamlRename, yamlDelete, yamlAppend, yamlSetItem, tomlSet, tomlRename, tomlDelete, EditError, yamlValue, tomlValue, isToml };

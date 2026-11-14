'use strict';
/**
 * A small YAML reader for the subset Traefik configurations (and docker-compose files) use, with line numbers.
 *
 *   - block mappings and sequences (incl. "- key: value" items and sequences at the same indent as their key)
 *   - flow collections [a, b] and {a: 1, b: [x]} (may span lines)
 *   - plain, 'single' and "double" quoted scalars (escapes, line folding), backticks inside plain scalars
 *   - multi-line plain scalars, block scalars | and > with chomping (-, +) and indentation indicators
 *   - comments, document markers (--- / ...), anchors (&a), aliases (*a), merge keys (<<: *a), !!str / !!int tags
 *
 * Not supported (reported as a YAMLError with the line): complex keys (? key), multiple documents with content
 * after the first one (ignored with a warning), directives (%YAML), tabs used for indentation.
 *
 * parse(text) -> { data, lines, warnings }
 *   data:  plain JS values (objects, arrays, strings, numbers, booleans, null)
 *   lines: Map(pathKey -> line) for every mapping key and sequence item; pathKey = path segments joined by "\u0000"
 *          (sequence indexes are numbers turned into strings), so `lineOf(lines, ['http','routers','r1','rule'])` works.
 */

class YAMLError extends Error {
  constructor(msg, line, col) { super(`${msg} (line ${line})`); this.reason = msg; this.line = line; this.col = col; }
}

const SEP = '\u0000';
const keyOf = (path) => path.map(String).join(SEP);
const lineOf = (lines, path) => lines.get(keyOf(path)) || null;

/** Remove a trailing comment (a # preceded by whitespace, outside quotes). Backticks are ordinary characters. */
function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (q === '"' && c === '\\') { i++; continue; }
      if (c === q) { if (q === "'" && s[i + 1] === "'") { i++; continue; } q = null; }
      continue;
    }
    if ((c === '"' || c === "'") && (i === 0 || /[\s[{,:]/.test(s[i - 1]))) { q = c; continue; }
    if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).replace(/\s+$/, '');
  }
  return s.replace(/\s+$/, '');
}

const INT_RE = /^[-+]?(0|[1-9][0-9_]*)$/;
const HEX_RE = /^0x[0-9a-fA-F_]+$/;
const OCT_RE = /^0o[0-7_]+$/;
const FLOAT_RE = /^[-+]?(\.[0-9]+|[0-9][0-9_]*(\.[0-9_]*)?)([eE][-+]?[0-9]+)?$/;

/** Resolve a plain scalar to its JS value (YAML 1.2 core schema). */
function plainValue(s) {
  if (s === '' || s === '~' || /^(null|Null|NULL)$/.test(s)) return null;
  if (/^(true|True|TRUE)$/.test(s)) return true;
  if (/^(false|False|FALSE)$/.test(s)) return false;
  if (INT_RE.test(s)) { const n = Number(s.replace(/_/g, '')); return Number.isSafeInteger(n) ? n : s; }
  if (HEX_RE.test(s)) return parseInt(s.slice(2).replace(/_/g, ''), 16);
  if (OCT_RE.test(s)) return parseInt(s.slice(2).replace(/_/g, ''), 8);
  if (FLOAT_RE.test(s) && /[0-9]/.test(s)) return Number(s.replace(/_/g, ''));
  if (/^[-+]?\.(inf|Inf|INF)$/.test(s)) return s[0] === '-' ? -Infinity : Infinity;
  if (/^\.(nan|NaN|NAN)$/.test(s)) return NaN;
  return s;
}

const ESC = { 0: '\0', a: '\x07', b: '\b', t: '\t', '\t': '\t', n: '\n', v: '\v', f: '\f', r: '\r', e: '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\u0085', _: ' ', L: ' ', P: ' ' };

function deepMerge(a, b) {
  for (const [k, v] of Object.entries(b)) {
    if (a[k] && v && typeof a[k] === 'object' && typeof v === 'object' && !Array.isArray(v)) deepMerge(a[k], v); else a[k] = v;
  }
  return a;
}

class Parser {
  constructor(text, opts = {}) {
    this.opts = opts;
    const src = String(text == null ? '' : text).replace(/^﻿/, '').replace(/\r\n?/g, '\n');
    this.raw = src.split('\n');
    this.lines = new Map();
    this.anchors = new Map();
    this.warnings = [];
    this.docEnd = this.raw.length;
  }

  err(msg, line) { throw new YAMLError(msg, line); }

  /** Logical line i: { indent, text (comment stripped, no indent), num } or null for blank/comment-only lines. */
  info(i) {
    const l = this.raw[i];
    if (l === undefined) return null;
    const m = /^( *)(.*)$/.exec(l);
    if (/^\t/.test(m[2]) && m[2].trim() && !m[2].trim().startsWith('#')) this.err('tab characters cannot be used for indentation', i + 1);
    const body = stripComment(m[2]);
    if (!body.trim()) return null;
    return { indent: m[1].length, text: body, num: i + 1 };
  }

  /** Index of the next non-blank line at or after i (within the current document), or -1. */
  next(i) { for (let k = i; k < this.docEnd; k++) if (this.info(k)) return k; return -1; }

  parseDocument() {
    // directives / document start
    let i = 0;
    while (i < this.raw.length) {
      const inf = this.info(i);
      if (!inf) { i++; continue; }
      if (inf.indent === 0 && /^%/.test(inf.text)) this.err('YAML directives (%YAML, %TAG) are not supported', inf.num);
      break;
    }
    // first document start marker may carry content ("--- {a: 1}") but usually stands alone
    let start = this.next(0);
    let inline = null;
    if (start >= 0) {
      const inf = this.info(start);
      if (inf.indent === 0 && /^---(\s|$)/.test(inf.text)) {
        const rest = inf.text.slice(3).trim();
        if (rest) inline = { start, rest };
        else start = this.next(start + 1);
      }
    }
    // end of the first document: a second "---" or "..."
    for (let k = (inline ? inline.start : (start < 0 ? 0 : start)) + 1; k < this.raw.length; k++) {
      if (/^(---|\.\.\.)(\s|$)/.test(this.raw[k])) {
        const rest = this.raw.slice(k + 1).some((l) => { const t = stripComment(l).trim(); return t && !/^(---|\.\.\.)$/.test(t); });
        if (/^---/.test(this.raw[k]) && rest) this.warnings.push({ line: k + 1, msg: 'only the first YAML document of the file is read' });
        this.docEnd = k; break;
      }
    }
    if (inline) {
      this.raw[inline.start] = `    ${inline.rest}`;
      start = inline.start;
    }
    if (start < 0 || start >= this.docEnd) return { value: null, end: this.docEnd };
    const first = this.info(start);
    const r = this.parseNode(start, first.indent, [], first);
    const after = this.next(r.end);
    if (after >= 0) {
      const inf = this.info(after);
      this.err(inf.indent < first.indent ? 'bad indentation: this line is less indented than the start of the document' : `unexpected content "${inf.text.slice(0, 40)}" (check the indentation)`, inf.num);
    }
    return r;
  }

  /**
   * Parse the node that starts at line index i with indentation `indent`. `inf` may be a virtual line (content after
   * "- "). Returns { value, end } where end is the index of the first line after the node.
   */
  parseNode(i, indent, path, inf) {
    const t = inf.text;
    if (/^\?( |$)/.test(t)) this.err('complex mapping keys ("? key") are not supported', inf.num);
    if (/^-( |$)/.test(t)) return this.parseSeq(i, inf.indent, path, inf);
    if (this.keyMatch(t)) return this.parseMap(i, inf.indent, path, inf);
    // a scalar / flow / alias / block scalar standing alone
    return this.parseValue(t, i, inf.indent - 1, path, inf.num);
  }

  /** "key: value" / "key:" detection. Returns { key, rest, quoted } or null. */
  keyMatch(t) {
    let key; let rest; let k = 0;
    if (t[0] === '"' || t[0] === "'") {
      const q = t[0]; let j = 1; let s = '';
      while (j < t.length && t[j] !== q) {
        if (q === '"' && t[j] === '\\') { s += ESC[t[j + 1]] !== undefined ? ESC[t[j + 1]] : t[j + 1]; j += 2; continue; }
        if (q === "'" && t[j] === "'" && t[j + 1] === "'") { s += "'"; j += 2; continue; }
        s += t[j++];
      }
      if (j >= t.length) return null;
      k = j + 1;
      const m = /^\s*:(\s+|$)/.exec(t.slice(k));
      if (!m) return null;
      key = s; rest = t.slice(k + m[0].length);
      return { key, rest: rest.trim(), quoted: true };
    }
    if (/^[[{&*!|>%@`?]/.test(t)) return null;
    const m = /^([^\s#:][^:]*?|[^\s#:]*(?::[^\s]+)+?)\s*:(\s+|$)/.exec(t);
    if (!m) return null;
    key = m[1];
    // a colon inside the key text is allowed when not followed by a space (e.g. "a:b: 1" -> key "a:b")
    if (/^[&*!]/.test(key)) return null;
    rest = t.slice(m[0].length);
    return { key, rest: rest.trim(), quoted: false };
  }

  parseMap(i, indent, path, firstInf) {
    const obj = {};
    const merges = [];
    let k = i; let inf = firstInf;
    while (true) {
      if (inf.indent !== indent) this.err('bad indentation of a mapping entry', inf.num);
      if (/^-( |$)/.test(inf.text)) this.err('a sequence item cannot appear here (a mapping was expected; check the indentation)', inf.num);
      const km = this.keyMatch(inf.text);
      if (!km) {
        if (/^\?( |$)/.test(inf.text)) this.err('complex mapping keys ("? key") are not supported', inf.num);
        this.err(`expected "key: value", found "${inf.text.slice(0, 40)}"`, inf.num);
      }
      const key = km.key;
      const dup = Object.prototype.hasOwnProperty.call(obj, key) && key !== '<<';
      if (dup && !this.opts.allowDuplicateKeys) this.err(`duplicate key "${key}"`, inf.num);
      const childPath = [...path, key];
      if (key !== '<<') this.lines.set(keyOf(childPath), inf.num);
      let r;
      if (km.rest === '' || /^&\S+$/.test(km.rest) || /^!\S+$/.test(km.rest) || /^!\S+\s+&\S+$/.test(km.rest) || /^&\S+\s+!\S+$/.test(km.rest)) {
        // value on the following lines (nested block), optionally anchored / tagged
        const props = km.rest;
        const anchor = (props.match(/&(\S+)/) || [])[1];
        const nx = this.next(k + 1);
        const ninf = nx >= 0 ? this.info(nx) : null;
        if (ninf && (ninf.indent > indent || (ninf.indent === indent && /^-( |$)/.test(ninf.text)))) {
          r = this.parseNode(nx, ninf.indent, childPath, ninf);
        } else r = { value: null, end: k + 1 };
        if (anchor) this.anchors.set(anchor, r.value);
        if (/!!str/.test(props) && r.value !== null && typeof r.value !== 'object') r.value = String(r.value);
      } else {
        r = this.parseValue(km.rest, k, indent, childPath, inf.num, inf);
      }
      if (key === '<<') merges.push({ value: r.value, line: inf.num });
      else if (dup && obj[key] && r.value && typeof obj[key] === 'object' && typeof r.value === 'object') { this.warnings.push({ line: inf.num, msg: `duplicate key "${key}" merged` }); deepMerge(obj[key], r.value); }
      else obj[key] = r.value;
      const nx = this.next(r.end);
      if (nx < 0) { k = this.docEnd; break; }
      const ninf = this.info(nx);
      if (ninf.indent < indent) { k = nx; break; }
      if (ninf.indent > indent) this.err(`bad indentation: unexpected "${ninf.text.slice(0, 40)}"`, ninf.num);
      k = nx; inf = ninf;
    }
    // merge keys: explicit keys win, earlier merges win over later ones
    for (const m of merges) {
      const srcs = Array.isArray(m.value) ? m.value : [m.value];
      for (const s of srcs) {
        if (!s || typeof s !== 'object' || Array.isArray(s)) this.err('a merge key (<<) needs a mapping or a list of mappings', m.line);
        for (const [kk, vv] of Object.entries(s)) if (!Object.prototype.hasOwnProperty.call(obj, kk)) { obj[kk] = vv; this.lines.set(keyOf([...path, kk]), m.line); }
      }
    }
    return { value: obj, end: k };
  }

  parseSeq(i, indent, path, firstInf) {
    const arr = [];
    let k = i; let inf = firstInf;
    while (true) {
      if (inf.indent !== indent || !/^-( |$)/.test(inf.text)) {
        if (inf.indent === indent) this.err('expected a sequence item ("- ...")', inf.num);
        break;
      }
      const idx = arr.length; const childPath = [...path, idx];
      this.lines.set(keyOf(childPath), inf.num);
      const rest = inf.text.replace(/^-\s*/, '');
      const off = inf.text.length - rest.length;
      let r;
      if (rest === '' || /^&\S+$/.test(rest) || /^!\S+$/.test(rest)) {
        const anchor = (rest.match(/^&(\S+)/) || [])[1];
        const nx = this.next(k + 1);
        const ninf = nx >= 0 ? this.info(nx) : null;
        if (ninf && ninf.indent > indent) r = this.parseNode(nx, ninf.indent, childPath, ninf);
        else r = { value: null, end: k + 1 };
        if (anchor) this.anchors.set(anchor, r.value);
      } else {
        // the item content is a virtual line starting after "- "
        const vinf = { indent: indent + off, text: rest, num: inf.num };
        if (/^-( |$)/.test(rest) || this.keyMatch(rest)) {
          const saved = this.raw[k];
          this.raw[k] = `${' '.repeat(indent + off)}${rest}`; // re-read as if the dash were spaces
          try { r = this.parseNode(k, indent + off, childPath, this.info(k)); } finally { this.raw[k] = saved; }
        } else r = this.parseValue(rest, k, indent, childPath, inf.num, vinf);
      }
      arr.push(r.value);
      const nx = this.next(r.end);
      if (nx < 0) { k = this.docEnd; break; }
      const ninf = this.info(nx);
      if (ninf.indent < indent) { k = nx; break; }
      if (ninf.indent > indent) this.err(`bad indentation: unexpected "${ninf.text.slice(0, 40)}"`, ninf.num);
      if (!/^-( |$)/.test(ninf.text)) { k = nx; break; } // a key at the same indent ends a "key:\n- a" sequence
      k = nx; inf = ninf;
    }
    return { value: arr, end: k };
  }

  /**
   * A value written after "key: " / "- " on line index k. `parentIndent` is the indentation of the owning entry:
   * continuation lines (multi-line plain / quoted scalars, flow collections) must be indented more than it.
   */
  parseValue(text, k, parentIndent, path, num) {
    let t = text;
    let anchor = null; let tag = null;
    for (;;) {
      const a = /^&([^\s,[\]{}]+)\s*/.exec(t);
      if (a) { anchor = a[1]; t = t.slice(a[0].length); continue; }
      const g = /^!(!?[^\s]*)\s*/.exec(t);
      if (g && !/^!=/.test(t)) { tag = g[1]; t = t.slice(g[0].length); continue; }
      break;
    }
    let r;
    if (t === '') {
      const nx = this.next(k + 1); const ninf = nx >= 0 ? this.info(nx) : null;
      if (ninf && ninf.indent > parentIndent) r = this.parseNode(nx, ninf.indent, path, ninf);
      else r = { value: null, end: k + 1 };
    } else if (t[0] === '*') {
      const name = t.slice(1).trim();
      if (!this.anchors.has(name)) this.err(`unknown alias *${name}`, num);
      const v = this.anchors.get(name);
      r = { value: v && typeof v === 'object' ? structuredClone(v) : v, end: k + 1 };
    } else if (t[0] === '|' || t[0] === '>') {
      r = this.blockScalar(t, k, parentIndent, num);
    } else if (t[0] === '[' || t[0] === '{') {
      r = this.flow(t, k, parentIndent, path, num);
    } else if (t[0] === '"' || t[0] === "'") {
      r = this.quoted(t, k, parentIndent, num);
    } else {
      if (/^[@`]/.test(t) && t[0] === '@') this.err(`"${t[0]}" cannot start a plain value; quote it`, num);
      // a key: value on the same line after "- " was handled by the caller; here a plain scalar, maybe multi-line
      let s = t; let end = k + 1;
      if (/:\s/.test(s) && !/^[^:]*`[^`]*:\s[^`]*`/.test(s) && this.looksLikeNestedMap(s)) this.err(`unexpected ": " inside a value; quote the value or fix the indentation`, num);
      for (let j = k + 1; j < this.docEnd; j++) {
        const raw = this.raw[j];
        if (!raw.trim()) { const nx = this.next(j); if (nx < 0) break; const ni = this.info(nx); if (ni.indent > parentIndent && !this.keyMatch(ni.text) && !/^-( |$)/.test(ni.text)) { s += '\n'; continue; } break; }
        const inf = this.info(j);
        if (!inf) { if (/^\s*#/.test(raw)) break; continue; }
        if (inf.indent <= parentIndent) break;
        if (this.keyMatch(inf.text) || /^-( |$)/.test(inf.text)) break;
        s += (s.endsWith('\n') ? '' : ' ') + inf.text.trim(); end = j + 1;
      }
      s = s.replace(/ ?\n ?/g, '\n');
      r = { value: tag === '!str' ? s : plainValue(s.trim()), end, plain: true };
    }
    if (tag === '!str' && r.value !== null && typeof r.value !== 'object') r.value = String(r.value);
    else if (tag === '!int' && typeof r.value === 'string' && INT_RE.test(r.value)) r.value = Number(r.value);
    else if (tag && !/^!(str|int|float|bool|null|map|seq|binary|timestamp)$/.test(tag) && !/^(str|int|float|bool|null|map|seq)$/.test(tag)) this.warnings.push({ line: num, msg: `tag !${tag} ignored` });
    if (anchor) this.anchors.set(anchor, r.value);
    return r;
  }

  looksLikeNestedMap(s) { return /^[A-Za-z_][\w.-]*:\s+\S/.test(s) && !/[`"'(]/.test(s.split(':')[0]); }

  quoted(t, k, parentIndent, num) {
    const q = t[0];
    let out = ''; let j = 1; let line = k; let src = t;
    let pendingBreak = 0;
    for (;;) {
      if (j >= src.length) {
        // continues on the next line (folding: one line break -> space, blank lines -> newlines)
        line++;
        if (line >= this.docEnd) this.err(`unterminated ${q === '"' ? 'double' : 'single'}-quoted string`, num);
        const raw = this.raw[line];
        if (!raw.trim()) { pendingBreak++; src = ''; j = 0; continue; }
        out = out.replace(/[ \t]+$/, '');
        out += pendingBreak ? '\n'.repeat(pendingBreak) : ' ';
        pendingBreak = 0;
        src = raw.replace(/^\s+/, ''); j = 0;
        continue;
      }
      const c = src[j];
      if (q === '"' && c === '\\') {
        const n = src[j + 1];
        if (n === undefined) { j++; line++; if (line >= this.docEnd) this.err('unterminated double-quoted string', num); src = this.raw[line].replace(/^\s+/, ''); j = 0; continue; }
        if (n === 'x') { out += String.fromCharCode(parseInt(src.substr(j + 2, 2), 16)); j += 4; continue; }
        if (n === 'u') { out += String.fromCharCode(parseInt(src.substr(j + 2, 4), 16)); j += 6; continue; }
        if (n === 'U') { out += String.fromCodePoint(parseInt(src.substr(j + 2, 8), 16)); j += 10; continue; }
        if (ESC[n] === undefined) this.err(`invalid escape "\\${n}" in a double-quoted string (write \\\\ for a backslash)`, line + 1);
        out += ESC[n]; j += 2; continue;
      }
      if (c === q) {
        if (q === "'" && src[j + 1] === "'") { out += "'"; j += 2; continue; }
        j++;
        const after = stripComment(src.slice(j)).trim();
        if (after && !/^[,\]}]/.test(after) && !/^:(\s|$)/.test(after)) this.err(`unexpected text after the closing quote: "${after.slice(0, 30)}"`, line + 1);
        return { value: out, end: line + 1, rest: src.slice(j) };
      }
      out += c; j++;
    }
  }

  blockScalar(t, k, parentIndent, num) {
    const m = /^([|>])([1-9]?)([-+]?)([1-9]?)\s*$/.exec(t);
    if (!m) this.err(`bad block scalar header "${t}"`, num);
    const folded = m[1] === '>'; const chomp = m[3]; const explicit = Number(m[2] || m[4]) || 0;
    const body = []; let end = k + 1; let ind = explicit ? parentIndent + explicit : 0;
    if (explicit && parentIndent < 0) ind = explicit;
    for (let j = k + 1; j < this.docEnd; j++) {
      const raw = this.raw[j];
      if (!raw.trim()) { body.push(''); continue; }
      const sp = /^ */.exec(raw)[0].length;
      if (!ind) { if (sp <= parentIndent) break; ind = sp; }
      if (sp < ind) break;
      body.push(raw.slice(ind)); end = j + 1;
    }
    // trailing blank lines belong to chomping only
    let trail = 0; while (body.length && body[body.length - 1] === '' ) { body.pop(); trail++; }
    // the blank lines we consumed past the last content line are not part of the node
    let text;
    if (!folded) text = body.join('\n');
    else {
      text = '';
      body.forEach((l, i) => {
        if (i === 0) { text = l; return; }
        const prev = body[i - 1];
        if (l === '') text += '\n';
        else if (prev === '' || /^\s/.test(l) || /^\s/.test(prev)) text += (prev === '' ? '' : '\n') + l;
        else text += ` ${l}`;
      });
    }
    if (chomp === '-') { /* strip */ } else if (chomp === '+') text += `\n${'\n'.repeat(trail)}`; else if (body.length) text += '\n';
    return { value: text, end };
  }

  /** Flow collection, possibly spanning several lines. */
  flow(t, k, parentIndent, path, num) {
    let src = t; let end = k + 1;
    const balanced = (s) => {
      let depth = 0; let q = null;
      for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (q) { if (q === '"' && c === '\\') { i++; continue; } if (c === q) { if (q === "'" && s[i + 1] === "'") { i++; continue; } q = null; } continue; }
        if (c === '"' || c === "'") { if (i === 0 || /[\s[{,:]/.test(s[i - 1])) q = c; continue; }
        if (c === '[' || c === '{') depth++;
        else if (c === ']' || c === '}') { depth--; if (depth === 0) return i; }
      }
      return -1;
    };
    let close = balanced(src);
    while (close < 0) {
      if (end >= this.docEnd) this.err(`unterminated flow collection (missing "${t[0] === '[' ? ']' : '}'}")`, num);
      const raw = this.raw[end];
      src += ` ${stripComment(raw).trim()}`; end++;
      close = balanced(src);
    }
    const tail = src.slice(close + 1).trim();
    if (tail) this.err(`unexpected text after the flow collection: "${tail.slice(0, 30)}"`, end);
    const fp = new FlowParser(src.slice(0, close + 1), num, this, path);
    const value = fp.parseAny();
    return { value, end };
  }
}

class FlowParser {
  constructor(s, line, parent, path) { this.s = s; this.i = 0; this.line = line; this.p = parent; this.path = path; }
  err(msg) { throw new YAMLError(msg, this.line); }
  ws() { while (this.i < this.s.length && /\s/.test(this.s[this.i])) this.i++; }
  parseAny(path = this.path) {
    this.ws();
    const c = this.s[this.i];
    if (c === '[') return this.seq(path);
    if (c === '{') return this.map(path);
    if (c === '"' || c === "'") return this.quoted();
    if (c === '*') { const m = /^\*([^\s,[\]{}]+)/.exec(this.s.slice(this.i)); this.i += m[0].length; if (!this.p.anchors.has(m[1])) this.err(`unknown alias *${m[1]}`); return this.p.anchors.get(m[1]); }
    return this.plain();
  }
  quoted() {
    const q = this.s[this.i]; let out = ''; this.i++;
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (q === '"' && c === '\\') { const n = this.s[this.i + 1]; if (n === 'u') { out += String.fromCharCode(parseInt(this.s.substr(this.i + 2, 4), 16)); this.i += 6; continue; } if (ESC[n] === undefined) this.err(`invalid escape "\\${n}"`); out += ESC[n]; this.i += 2; continue; }
      if (c === q) { if (q === "'" && this.s[this.i + 1] === "'") { out += "'"; this.i += 2; continue; } this.i++; return out; }
      out += c; this.i++;
    }
    return this.err('unterminated quoted string in a flow collection');
  }
  plain() {
    let j = this.i; let depthParen = 0;
    while (j < this.s.length) {
      const c = this.s[j];
      if (c === '(') depthParen++;
      if (c === ')') depthParen--;
      if (c === '`') { const e = this.s.indexOf('`', j + 1); if (e > 0) { j = e + 1; continue; } }
      if (depthParen <= 0 && (c === ',' || c === ']' || c === '}')) break;
      if (c === ':' && /[\s,\]}]/.test(this.s[j + 1] || ' ') && depthParen <= 0) break;
      j++;
    }
    const raw = this.s.slice(this.i, j).trim(); this.i = j;
    return plainValue(raw);
  }
  seq(path) {
    this.i++; const arr = [];
    for (;;) {
      this.ws();
      if (this.s[this.i] === ']') { this.i++; return arr; }
      if (this.i >= this.s.length) this.err('missing "]"');
      this.p.lines.set(keyOf([...path, arr.length]), this.line);
      arr.push(this.parseAny([...path, arr.length]));
      this.ws();
      if (this.s[this.i] === ',') { this.i++; continue; }
      if (this.s[this.i] === ']') { this.i++; return arr; }
      this.err(`expected "," or "]" in a flow sequence, found "${this.s.slice(this.i, this.i + 15)}"`);
    }
  }
  map(path) {
    this.i++; const obj = {};
    for (;;) {
      this.ws();
      if (this.s[this.i] === '}') { this.i++; return obj; }
      if (this.i >= this.s.length) this.err('missing "}"');
      const c = this.s[this.i];
      const key = c === '"' || c === "'" ? this.quoted() : (() => { const m = /^[^:,{}[\]]+/.exec(this.s.slice(this.i)); if (!m) this.err('expected a key in a flow mapping'); this.i += m[0].length; return m[0].trim(); })();
      this.ws();
      let val = null;
      if (this.s[this.i] === ':') { this.i++; this.ws(); if (this.s[this.i] !== ',' && this.s[this.i] !== '}') val = this.parseAny([...path, key]); }
      if (Object.prototype.hasOwnProperty.call(obj, key)) this.err(`duplicate key "${key}"`);
      obj[key] = val; this.p.lines.set(keyOf([...path, key]), this.line);
      this.ws();
      if (this.s[this.i] === ',') { this.i++; continue; }
      if (this.s[this.i] === '}') { this.i++; return obj; }
      this.err(`expected "," or "}" in a flow mapping, found "${this.s.slice(this.i, this.i + 15)}"`);
    }
  }
}

function parse(text, opts) {
  const p = new Parser(text, opts);
  const r = p.parseDocument();
  return { data: r.value, lines: p.lines, warnings: p.warnings };
}

// ------------------------------------------------------------------------------------------------ writer
const needsQuote = (s) => s === '' || /^[\s]|[\s]$/.test(s) || /^[-?:,[\]{}#&*!|>'"%@`]/.test(s) || /: |\s#/.test(s) || /:$/.test(s)
  || plainValue(s) !== s || /[\n\t]/.test(s) || /`|\$\{/.test(s); // rules and ${1} replacements are quoted for readability
/** Quote a string for YAML only when needed (double quotes with escapes). */
function scalar(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  const s = String(v);
  return needsQuote(s) ? JSON.stringify(s) : s;
}
/** Serialise plain data as block YAML (2-space indent). */
function stringify(data, indent = 0) {
  const pad = ' '.repeat(indent);
  const out = [];
  const emptyFlow = (v) => (Array.isArray(v) ? '[]' : '{}');
  if (Array.isArray(data)) {
    for (const v of data) {
      if (v && typeof v === 'object' && Object.keys(v).length) {
        const inner = stringify(v, indent + 2).split('\n');
        out.push(`${pad}- ${inner[0].trimStart()}`, ...inner.slice(1));
      } else out.push(`${pad}- ${v && typeof v === 'object' ? emptyFlow(v) : scalar(v)}`);
    }
  } else if (data && typeof data === 'object') {
    for (const [k, v] of Object.entries(data)) {
      const key = needsQuote(k) ? JSON.stringify(k) : k;
      if (v && typeof v === 'object' && Object.keys(v).length) {
        out.push(`${pad}${key}:`);
        out.push(stringify(v, Array.isArray(v) ? indent + 2 : indent + 2));
      } else out.push(`${pad}${key}: ${v && typeof v === 'object' ? emptyFlow(v) : scalar(v)}`);
    }
  }
  return out.join('\n');
}

module.exports = { parse, stringify, scalar, YAMLError, lineOf, keyOf, SEP, plainValue, stripComment };

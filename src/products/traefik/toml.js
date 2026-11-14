'use strict';
/**
 * A TOML 1.0 reader for Traefik configuration files, with line numbers.
 *
 *   tables [a.b], array tables [[a.b]], dotted / quoted keys, basic and literal strings (incl. multi-line """ / '''),
 *   integers (decimal, hex, octal, binary, underscores), floats, booleans, dates/times (kept as strings),
 *   arrays (multi-line, trailing comma, comments inside) and inline tables.
 *
 * parse(text) -> { data, lines, warnings }  (same shape as yaml.js: lines maps "a\0b\0c" -> line of the key).
 * Errors throw TOMLError with .line.
 */
const { keyOf } = require('./yaml');

class TOMLError extends Error {
  constructor(msg, line) { super(`${msg} (line ${line})`); this.reason = msg; this.line = line; }
}

const BARE = /^[A-Za-z0-9_-]+/;
const ESC = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', e: '\x1b', '"': '"', '\\': '\\' };

class Parser {
  constructor(text) {
    this.s = String(text == null ? '' : text).replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
    this.i = 0; this.line = 1;
    this.data = {};
    this.lines = new Map();
    this.warnings = [];
    this.defined = new Set();   // tables defined explicitly with [header]
    this.inline = new Set();    // objects that come from inline tables / values (cannot be extended)
    this.arrTables = new Set(); // arrays created by [[...]]
  }

  err(msg, line = this.line) { throw new TOMLError(msg, line); }
  peek(n = 0) { return this.s[this.i + n]; }
  eof() { return this.i >= this.s.length; }

  /** Skip spaces/tabs (and, with nl, newlines and comments). */
  ws(nl = false) {
    for (;;) {
      const c = this.peek();
      if (c === ' ' || c === '\t') { this.i++; continue; }
      if (nl && c === '\n') { this.i++; this.line++; continue; }
      if (nl && c === '\r') { this.i++; continue; }
      if (nl && c === '#') { this.comment(); continue; }
      break;
    }
  }
  comment() { while (!this.eof() && this.peek() !== '\n') this.i++; }
  eol() {
    this.ws();
    if (this.peek() === '#') this.comment();
    if (this.eof()) return;
    if (this.peek() === '\n') { this.i++; this.line++; return; }
    this.err(`unexpected "${this.s.slice(this.i, this.i + 20).split('\n')[0]}" (expected the end of the line)`);
  }

  parse() {
    let cur = this.data; let curPath = [];
    for (;;) {
      this.ws(true);
      if (this.eof()) break;
      const line = this.line;
      if (this.peek() === '[') {
        const arr = this.peek(1) === '[';
        this.i += arr ? 2 : 1; this.ws();
        const path = this.key();
        this.ws();
        if (arr) { if (this.s.slice(this.i, this.i + 2) !== ']]') this.err('missing "]]" after the array table name'); this.i += 2; } else { if (this.peek() !== ']') this.err('missing "]" after the table name'); this.i++; }
        this.eol();
        ({ obj: cur, path: curPath } = arr ? this.arrayTable(path, line) : this.table(path, line));
        continue;
      }
      this.keyValue(cur, curPath, line);
      this.eol();
    }
    return this.data;
  }

  /** Walk (creating) to a container for a dotted path; intermediate arrays of tables resolve to their last element. */
  walk(path, line, forTable) {
    let o = this.data; const real = [];
    for (let k = 0; k < path.length; k++) {
      const key = path[k];
      real.push(key);
      if (!Object.prototype.hasOwnProperty.call(o, key)) { o[key] = {}; if (!this.lines.has(keyOf(real))) this.lines.set(keyOf(real), line); }
      let v = o[key];
      if (Array.isArray(v)) {
        if (!this.arrTables.has(v)) this.err(`"${real.join('.')}" is an array value, not a table`, line);
        real.push(v.length - 1); v = v[v.length - 1];
      } else if (!v || typeof v !== 'object') this.err(`"${real.join('.')}" is already a value, not a table`, line);
      if (this.inline.has(v) && (forTable || k < path.length - 1)) this.err(`"${real.join('.')}" was defined as an inline table and cannot be extended`, line);
      o = v;
    }
    return { obj: o, path: real };
  }

  table(path, line) {
    const parent = this.walk(path.slice(0, -1), line, true);
    const key = path[path.length - 1];
    const realPath = [...parent.path, key];
    let o = parent.obj[key];
    if (o === undefined) { o = {}; parent.obj[key] = o; }
    else if (Array.isArray(o)) this.err(`table [${path.join('.')}] was already defined as an array of tables`, line);
    else if (!o || typeof o !== 'object' || this.inline.has(o)) this.err(`"${path.join('.')}" is already defined as a value`, line);
    const id = keyOf(realPath);
    if (this.defined.has(id)) this.err(`table [${path.join('.')}] is defined twice`, line);
    this.defined.add(id);
    this.lines.set(id, line);
    return { obj: o, path: realPath };
  }

  arrayTable(path, line) {
    const parent = this.walk(path.slice(0, -1), line, true);
    const key = path[path.length - 1];
    let a = parent.obj[key];
    if (a === undefined) { a = []; parent.obj[key] = a; this.arrTables.add(a); this.lines.set(keyOf([...parent.path, key]), line); }
    else if (!Array.isArray(a) || !this.arrTables.has(a)) this.err(`"${path.join('.')}" is already defined and is not an array of tables`, line);
    const o = {}; a.push(o);
    const realPath = [...parent.path, key, a.length - 1];
    this.lines.set(keyOf(realPath), line);
    return { obj: o, path: realPath };
  }

  /** A key: bare, "basic", 'literal', dotted. Returns segments. */
  key() {
    const parts = [];
    for (;;) {
      this.ws();
      const c = this.peek();
      if (c === '"') parts.push(this.basicString());
      else if (c === "'") parts.push(this.literalString());
      else {
        const m = BARE.exec(this.s.slice(this.i));
        if (!m) this.err(`invalid key "${this.s.slice(this.i, this.i + 15).split('\n')[0]}"`);
        parts.push(m[0]); this.i += m[0].length;
      }
      this.ws();
      if (this.peek() === '.') { this.i++; continue; }
      return parts;
    }
  }

  keyValue(obj, basePath, line) {
    const path = this.key();
    this.ws();
    if (this.peek() !== '=') this.err(`expected "=" after the key "${path.join('.')}"`);
    this.i++; this.ws();
    const fullPath = [...basePath, ...path];
    const value = this.value(fullPath);
    // dotted keys create intermediate tables
    let o = obj; const real = [...basePath];
    for (let k = 0; k < path.length - 1; k++) {
      const p = path[k]; real.push(p);
      if (!Object.prototype.hasOwnProperty.call(o, p)) { o[p] = {}; this.lines.set(keyOf(real), line); }
      else if (!o[p] || typeof o[p] !== 'object' || Array.isArray(o[p]) || this.inline.has(o[p])) this.err(`"${real.join('.')}" is already a value`, line);
      else if (this.defined.has(keyOf(real))) this.err(`table "${real.join('.')}" cannot be extended with dotted keys after its [header]`, line);
      o = o[p];
    }
    const last = path[path.length - 1];
    if (Object.prototype.hasOwnProperty.call(o, last)) this.err(`duplicate key "${[...path].join('.')}"`, line);
    o[last] = value;
    this.lines.set(keyOf([...real, last]), line);
  }

  value(path) {
    const c = this.peek();
    const line = this.line;
    if (c === '"') return this.s.startsWith('"""', this.i) ? this.mlBasic() : this.basicString();
    if (c === "'") return this.s.startsWith("'''", this.i) ? this.mlLiteral() : this.literalString();
    if (c === '[') return this.array(path);
    if (c === '{') return this.inlineTable(path);
    const m = /^[^\s,\]}#]+/.exec(this.s.slice(this.i));
    if (!m) this.err('missing value');
    let tok = m[0];
    // dates with a space separator: 1979-05-27 07:32:00Z
    const dt = /^\d{4}-\d\d-\d\d[ ]\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:\d\d)?/.exec(this.s.slice(this.i));
    if (dt && /^\d{4}-\d\d-\d\d$/.test(tok)) tok = dt[0];
    this.i += tok.length;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (/^[+-]?(0|[1-9](_?\d)*)$/.test(tok)) return Number(tok.replace(/_/g, ''));
    if (/^0x[0-9A-Fa-f](_?[0-9A-Fa-f])*$/.test(tok)) return parseInt(tok.slice(2).replace(/_/g, ''), 16);
    if (/^0o[0-7](_?[0-7])*$/.test(tok)) return parseInt(tok.slice(2).replace(/_/g, ''), 8);
    if (/^0b[01](_?[01])*$/.test(tok)) return parseInt(tok.slice(2).replace(/_/g, ''), 2);
    if (/^[+-]?(0|[1-9](_?\d)*)(\.\d(_?\d)*)?([eE][+-]?\d(_?\d)*)?$/.test(tok)) return Number(tok.replace(/_/g, ''));
    if (/^[+-]?(inf|nan)$/.test(tok)) return tok.endsWith('nan') ? NaN : (tok[0] === '-' ? -Infinity : Infinity);
    if (/^\d{4}-\d\d-\d\d([T ]\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:\d\d)?)?$/i.test(tok) || /^\d\d:\d\d:\d\d(\.\d+)?$/.test(tok)) return tok;
    if (/`/.test(tok) || /\(/.test(tok)) this.err(`strings must be quoted: write "${tok}..." (Traefik rules go in double quotes, with backticks inside)`, line);
    return this.err(`invalid value "${tok}" (strings must be quoted)`, line);
  }

  basicString() {
    const start = this.line; this.i++; let out = '';
    for (;;) {
      if (this.eof() || this.peek() === '\n') this.err('unterminated string', start);
      const c = this.s[this.i];
      if (c === '"') { this.i++; return out; }
      if (c === '\\') {
        const n = this.s[this.i + 1];
        if (n === 'u' || n === 'U') { const len = n === 'u' ? 4 : 8; const hex = this.s.substr(this.i + 2, len); if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) this.err('bad unicode escape'); out += String.fromCodePoint(parseInt(hex, 16)); this.i += 2 + len; continue; }
        if (ESC[n] === undefined) this.err(`invalid escape "\\${n}" (use \\\\ for a backslash, or a 'literal string')`);
        out += ESC[n]; this.i += 2; continue;
      }
      out += c; this.i++;
    }
  }
  literalString() {
    const start = this.line; this.i++;
    const e = this.s.indexOf("'", this.i); const nl = this.s.indexOf('\n', this.i);
    if (e < 0 || (nl >= 0 && nl < e)) this.err('unterminated string', start);
    const out = this.s.slice(this.i, e); this.i = e + 1; return out;
  }
  mlBasic() {
    const start = this.line; this.i += 3;
    if (this.peek() === '\n') { this.i++; this.line++; }
    let out = '';
    for (;;) {
      if (this.eof()) this.err('unterminated multi-line string', start);
      if (this.s.startsWith('"""', this.i)) {
        let q = 3; while (this.s[this.i + q] === '"' && q < 5) q++;
        out += '"'.repeat(q - 3); this.i += q; return out;
      }
      const c = this.s[this.i];
      if (c === '\\') {
        const n = this.s[this.i + 1];
        if (n === '\n' || n === ' ' || n === '\t') { // line-ending backslash: trim whitespace up to the next content
          let j = this.i + 1; while (j < this.s.length && /\s/.test(this.s[j])) { if (this.s[j] === '\n') this.line++; j++; }
          this.i = j; continue;
        }
        if (n === 'u' || n === 'U') { const len = n === 'u' ? 4 : 8; out += String.fromCodePoint(parseInt(this.s.substr(this.i + 2, len), 16)); this.i += 2 + len; continue; }
        if (ESC[n] === undefined) this.err(`invalid escape "\\${n}"`);
        out += ESC[n]; this.i += 2; continue;
      }
      if (c === '\n') this.line++;
      out += c; this.i++;
    }
  }
  mlLiteral() {
    const start = this.line; this.i += 3;
    if (this.peek() === '\n') { this.i++; this.line++; }
    const e = this.s.indexOf("'''", this.i);
    if (e < 0) this.err('unterminated multi-line string', start);
    let end = e; while (this.s[end + 3] === "'" && end - e < 2) end++;
    const out = this.s.slice(this.i, end);
    this.line += (out.match(/\n/g) || []).length;
    this.i = end + 3; return out;
  }

  array(path) {
    const start = this.line; this.i++; const arr = [];
    for (;;) {
      this.ws(true);
      if (this.eof()) this.err('unterminated array (missing "]")', start);
      if (this.peek() === ']') { this.i++; return arr; }
      this.lines.set(keyOf([...path, arr.length]), this.line);
      arr.push(this.value([...path, arr.length]));
      this.ws(true);
      if (this.peek() === ',') { this.i++; continue; }
      if (this.peek() === ']') { this.i++; return arr; }
      this.err(`expected "," or "]" in an array, found "${this.s.slice(this.i, this.i + 15).split('\n')[0]}"`);
    }
  }

  inlineTable(path) {
    const line = this.line; this.i++; const obj = {}; this.inline.add(obj);
    this.ws();
    if (this.peek() === '}') { this.i++; return obj; }
    for (;;) {
      this.ws();
      const keys = this.key(); this.ws();
      if (this.peek() !== '=') this.err(`expected "=" after "${keys.join('.')}" in an inline table`);
      this.i++; this.ws();
      const v = this.value([...path, ...keys]);
      let o = obj;
      for (let k = 0; k < keys.length - 1; k++) { if (!o[keys[k]]) o[keys[k]] = {}; o = o[keys[k]]; }
      if (Object.prototype.hasOwnProperty.call(o, keys[keys.length - 1])) this.err(`duplicate key "${keys.join('.')}"`, line);
      o[keys[keys.length - 1]] = v;
      this.lines.set(keyOf([...path, ...keys]), line);
      this.ws();
      if (this.peek() === ',') { this.i++; continue; }
      if (this.peek() === '}') { this.i++; return obj; }
      if (this.peek() === '\n') this.err('inline tables must stay on one line');
      this.err(`expected "," or "}" in an inline table, found "${this.s.slice(this.i, this.i + 15)}"`);
    }
  }
}

function parse(text) {
  const p = new Parser(text);
  const data = p.parse();
  return { data, lines: p.lines, warnings: p.warnings };
}

// ------------------------------------------------------------------------------------------------ writer
const bareKey = (k) => (/^[A-Za-z0-9_-]+$/.test(k) ? k : JSON.stringify(k));
const tval = (v) => {
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return `[${v.map(tval).join(', ')}]`;
  if (v && typeof v === 'object') return `{ ${Object.entries(v).map(([k, x]) => `${bareKey(k)} = ${tval(x)}`).join(', ')} }`;
  return '""';
};
/** Serialise plain data as TOML (tables for objects, [[...]] for arrays of objects). */
function stringify(data) {
  const out = [];
  const emit = (obj, path) => {
    const scalars = []; const tables = []; const arrTables = [];
    for (const [k, v] of Object.entries(obj)) {
      if (Array.isArray(v) && v.length && v.every((x) => x && typeof x === 'object' && !Array.isArray(x))) arrTables.push([k, v]);
      else if (v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length) tables.push([k, v]);
      else scalars.push([k, v]);
    }
    if (path.length && (scalars.length || (!tables.length && !arrTables.length))) out.push(`[${path.map(bareKey).join('.')}]`);
    for (const [k, v] of scalars) out.push(`${path.length ? '  ' : ''}${bareKey(k)} = ${v && typeof v === 'object' && !Array.isArray(v) ? '{}' : tval(v)}`);
    if (scalars.length) out.push('');
    for (const [k, v] of tables) emit(v, [...path, k]);
    for (const [k, list] of arrTables) for (const item of list) { out.push(`[[${[...path, k].map(bareKey).join('.')}]]`); for (const [kk, vv] of Object.entries(item)) out.push(`  ${bareKey(kk)} = ${tval(vv)}`); out.push(''); }
  };
  emit(data, []);
  return `${out.join('\n').replace(/\n{3,}/g, '\n\n').trim()}\n`;
}

module.exports = { parse, stringify, TOMLError };

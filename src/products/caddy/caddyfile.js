'use strict';
/**
 * Caddyfile reader (https://caddyserver.com/docs/caddyfile/concepts):
 *
 *   lex()        tokens like Caddy's lexer: whitespace separated, "quotes", `backticks`, heredocs (<<MARKER, since 2.7),
 *                # comments (only at the start of a token), "\" + newline continues a line; every token knows whether it
 *                starts a new line, because a Caddyfile directive ends at the end of its line.
 *   parseTree()  lines -> nodes { name, args, toks, line, file, block }, blocks opened by a trailing "{" and closed by "}".
 *   expand()     snippets `(name) { }` + `import name args...` with {args[n]} / {args[:]} / {args.n} and {block},
 *                and `import <file glob>` resolved among the uploaded files or on disk, sandboxed to the config root.
 *   {$VAR} / {$VAR:default} environment placeholders: the default is used when given; otherwise the placeholder is
 *                kept as written (the server's environment is unknown, and GateLight's own is never read).
 *
 * Nothing here interprets directives; see model.js for the shared section model.
 */
const fs = require('fs');
const path = require('path');

const MAX_FILES = 500;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_DEPTH = 12;
const MAX_NODES = 200000;

// ------------------------------------------------------------------------------------------------ lexer
/**
 * @returns {{tokens: Array<{text, line, file, quoted, nl, heredoc?}>, errors: Array<{line, msg}>}}
 *   quoted: '' | '"' | '`' | '<' (heredoc). nl: the token starts a new (logical) line.
 */
function lex(text, file = 'Caddyfile') {
  const src = String(text == null ? '' : text).replace(/^﻿/, '');
  const tokens = []; const errors = [];
  const n = src.length; let i = 0; let line = 1; let nl = true;
  const push = (t) => { tokens.push({ ...t, file, nl }); nl = false; };
  while (i < n) {
    const ch = src[i];
    if (ch === '\r') { i++; continue; }
    if (ch === '\n') { line++; nl = true; i++; continue; }
    if (ch === ' ' || ch === '\t' || ch === '\f' || ch === '\v') { i++; continue; }
    if (ch === '\\' && (src[i + 1] === '\n' || (src[i + 1] === '\r' && src[i + 2] === '\n'))) { // escaped newline: same logical line
      i += src[i + 1] === '\r' ? 3 : 2; line++; continue;
    }
    if (ch === '#') { while (i < n && src[i] !== '\n') i++; continue; }
    const start = line;
    if (ch === '"') {
      let s = ''; i++;
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < n) { if (src[i + 1] === '"') { s += '"'; i += 2; continue; } s += '\\'; i++; continue; }
        if (src[i] === '\n') line++;
        s += src[i++];
      }
      if (i >= n) errors.push({ line: start, msg: 'Unterminated quoted string: a " opened here is never closed' });
      i++; push({ text: s, line: start, quoted: '"' }); continue;
    }
    if (ch === '`') {
      let s = ''; i++;
      while (i < n && src[i] !== '`') { if (src[i] === '\n') line++; s += src[i++]; }
      if (i >= n) errors.push({ line: start, msg: 'Unterminated backtick string: a ` opened here is never closed' });
      i++; push({ text: s, line: start, quoted: '`' }); continue;
    }
    if (ch === '<' && src[i + 1] === '<' && /^<<[A-Za-z0-9_-]+\r?\n/.test(src.slice(i, i + 80))) {
      const m = /^<<([A-Za-z0-9_-]+)\r?\n/.exec(src.slice(i, i + 80));
      const marker = m[1]; i += m[0].length; line++;
      const bodyStart = i; let found = -1; let k = i;
      while (k < n) {
        const eol = src.indexOf('\n', k); const ln = src.slice(k, eol < 0 ? n : eol);
        const t = ln.replace(/\r$/, '');
        const mm = new RegExp(`^([ \\t]*)${marker}(?=\\s|$)`).exec(t);
        if (mm) { found = k; break; }
        if (eol < 0) break; k = eol + 1;
      }
      if (found < 0) { errors.push({ line: start, msg: `Incomplete heredoc <<${marker}: the closing marker ${marker} is missing` }); push({ text: src.slice(bodyStart), line: start, quoted: '<', heredoc: marker }); i = n; continue; }
      const closing = src.slice(found, src.indexOf('\n', found) < 0 ? n : src.indexOf('\n', found));
      const indent = /^[ \t]*/.exec(closing)[0];
      const body = src.slice(bodyStart, found).replace(/\r?\n$/, '');
      line += (src.slice(bodyStart, found).match(/\n/g) || []).length;
      const textOut = body.split('\n').map((l) => (l.startsWith(indent) ? l.slice(indent.length) : l.replace(/^[ \t]+/, ''))).join('\n');
      push({ text: textOut, line: start, quoted: '<', heredoc: marker });
      i = found + indent.length + marker.length; continue;
    }
    let s = '';
    while (i < n && !/\s/.test(src[i])) {
      if (src[i] === '\\' && i + 1 < n && !/\s/.test(src[i + 1])) { s += src[i] + src[i + 1]; i += 2; continue; }
      if (src[i] === '\\' && (src[i + 1] === '\n' || src[i + 1] === '\r')) break;
      s += src[i++];
    }
    if (s) push({ text: s, line: start, quoted: '' });
  }
  return { tokens, errors };
}

/** {$VAR} / {$VAR:default} -> default (or the placeholder as written when there is no default). */
function envReplace(text) {
  return String(text).replace(/\{\$([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}/g, (all, name, def) => (def !== undefined ? def : all));
}

// ------------------------------------------------------------------------------------------------ tree
const isOpen = (t) => t && !t.quoted && t.text === '{';
const isClose = (t) => t && !t.quoted && t.text === '}';

/**
 * Tokens -> nodes. A node is one logical line; a trailing "{" opens its block.
 * @returns {{nodes, errors}} errors: unbalanced braces etc. (lenient: the tree is still built)
 */
function parseTree(tokens, { topLevel = true } = {}) {
  const errors = []; let i = 0; const n = tokens.length;
  function body(depth, opener) {
    const out = [];
    while (i < n) {
      const t = tokens[i];
      if (isClose(t)) {
        i++;
        if (depth > 0) return { nodes: out, closeLine: t.line };
        errors.push({ line: t.line, file: t.file, msg: 'Unexpected "}": there is no open block to close' });
        continue;
      }
      const lineToks = [t]; i++;
      while (i < n && !tokens[i].nl && !isClose(tokens[i]) && !isOpen(lineToks[lineToks.length - 1])) lineToks.push(tokens[i++]);
      // site addresses may continue on the next line after a trailing comma
      while (topLevel && depth === 0 && i < n && /,$/.test(lineToks[lineToks.length - 1].text) && !lineToks[lineToks.length - 1].quoted) {
        lineToks.push(tokens[i++]);
        while (i < n && !tokens[i].nl && !isClose(tokens[i]) && !isOpen(lineToks[lineToks.length - 1])) lineToks.push(tokens[i++]);
      }
      const last = lineToks[lineToks.length - 1];
      const node = { name: '', args: [], toks: [], line: t.line, file: t.file, block: null, endLine: last.line };
      if (isOpen(last)) {
        node.toks = lineToks.slice(0, -1);
        if (i < n && !tokens[i].nl && !isClose(tokens[i])) { errors.push({ line: last.line, file: last.file, msg: 'Unexpected token after "{" on the same line: a block\'s content starts on the next line' }); tokens[i] = { ...tokens[i], nl: true }; }
        const inner = body(depth + 1, last);
        node.block = inner.nodes; node.endLine = inner.closeLine || node.line;
      } else node.toks = lineToks;
      node.name = node.toks.length ? node.toks[0].text : '';
      node.args = node.toks.slice(1).map((x) => x.text);
      out.push(node);
    }
    if (depth > 0) errors.push({ line: opener.line, file: opener.file, msg: 'Unclosed block: missing "}" for the "{" opened here' });
    return { nodes: out, closeLine: null };
  }
  const r = body(0, null);
  return { nodes: r.nodes, errors };
}

const clone = (nodes) => nodes.map((x) => ({ ...x, toks: x.toks.map((t) => ({ ...t })), args: [...x.args], block: x.block ? clone(x.block) : null }));

// ------------------------------------------------------------------------------------------------ import arguments
const ARG_RE = /\{args(?:\[(\d*)(?::(\d*))?\]|\.(\d+))\}/g;
function substituteArgs(nodes, args, block) {
  const subTok = (t) => {
    const whole = /^\{args\[(\d*):(\d*)\]\}$/.exec(t.text);
    if (whole && !t.quoted) {
      const a = whole[1] === '' ? 0 : Number(whole[1]); const b = whole[2] === '' ? args.length : Number(whole[2]);
      return args.slice(a, b).map((v) => ({ ...t, text: v }));
    }
    return [{ ...t, text: t.text.replace(ARG_RE, (all, idx, to, dot) => {
      if (dot !== undefined) return args[Number(dot)] ?? '';
      if (to !== undefined) { const a = idx === '' ? 0 : Number(idx); const b = to === '' ? args.length : Number(to); return args.slice(a, b).join(' '); }
      return args[Number(idx)] ?? '';
    }) }];
  };
  const out = [];
  for (const nd of nodes) {
    if (block && nd.toks.length === 1 && !nd.toks[0].quoted && /^\{block\}$/.test(nd.toks[0].text) && !nd.block) { out.push(...clone(block)); continue; }
    const toks = nd.toks.flatMap(subTok);
    if (!toks.length) continue;
    out.push({ ...nd, toks, name: toks[0].text, args: toks.slice(1).map((x) => x.text), block: nd.block ? substituteArgs(nd.block, args, block) : null });
  }
  return out;
}

/** Tag a node and its block with where it was imported from (inner imports keep their own, closer origin). */
function mark(nd, props) {
  const out = { ...nd };
  for (const [k, v] of Object.entries(props)) if (out[k] === undefined) out[k] = v;
  if (nd.block) out.block = nd.block.map((c) => mark(c, props));
  return out;
}

// ------------------------------------------------------------------------------------------------ loader
class Loader {
  /** @param vfs optional Map(posix abs path -> content) for uploaded files. */
  constructor(mainPath, rootDir, vfs) {
    this.vfs = vfs || null;
    this.mainPath = vfs ? path.posix.normalize(mainPath) : path.resolve(mainPath);
    this.root = vfs ? '/' : path.resolve(rootDir || path.dirname(mainPath));
    this.files = new Map(); this.notes = []; this.errors = []; this.snippets = new Map(); this.namedRoutes = new Map();
    this.snippetUse = new Map(); this.importsMissing = []; this.nodeCount = 0;
  }
  rel(abs) { return this.vfs ? abs.replace(/^\//, '') : (path.relative(this.root, abs) || path.basename(abs)); }
  inside(abs) { if (this.vfs) return true; const r = path.relative(this.root, abs); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); }
  _exists(p) { return this.vfs ? this.vfs.has(p) : fs.existsSync(p) && fs.statSync(p).isFile(); }
  _list(dir) {
    if (!this.vfs) return fs.readdirSync(dir);
    const prefix = dir === '/' ? '/' : `${dir}/`;
    return [...this.vfs.keys()].filter((k) => k.startsWith(prefix) && !k.slice(prefix.length).includes('/')).map((k) => k.slice(prefix.length));
  }
  read(abs) {
    if (this.files.has(abs)) return this.files.get(abs).raw;
    if (this.files.size >= MAX_FILES) throw new Error(`more than ${MAX_FILES} imported files`);
    let raw; let mtimeMs = 0;
    if (this.vfs) { raw = this.vfs.get(abs); if (raw === undefined) throw new Error(`${this.rel(abs)} not found`); } else {
      const st = fs.statSync(abs);
      if (!st.isFile() || st.size > MAX_FILE_BYTES) throw new Error(`${abs} is not a regular file or exceeds ${MAX_FILE_BYTES} bytes`);
      raw = fs.readFileSync(abs, 'utf8'); mtimeMs = st.mtimeMs;
    }
    this.files.set(abs, { name: this.rel(abs), raw, mtimeMs, abs });
    return raw;
  }
  /** Files matched by an import pattern (a path or a glob in the last segment), inside the sandbox. */
  resolve(pattern, fromFile) {
    const P = this.vfs ? path.posix : path;
    let p = pattern;
    if (!P.isAbsolute(p)) p = P.join(P.dirname(fromFile), p);
    else if (this.vfs) { if (!this.vfs.has(P.normalize(p))) p = P.join('/', p.replace(/^\/etc\/caddy\//, '')); } else if (!this.inside(p)) {
      const m = p.match(/^\/etc\/caddy\/(.*)$/); if (m) p = path.join(this.root, m[1]);
    }
    p = P.normalize(p);
    if (!this.inside(p)) { this.notes.push({ file: this.rel(fromFile), msg: `import "${pattern}" is outside the config root (${this.root}) and was skipped` }); return null; }
    const dir = P.dirname(p); const base = P.basename(p);
    if (/[*?[]/.test(dir)) { this.notes.push({ file: this.rel(fromFile), msg: `import "${pattern}": wildcards in directory names are not supported` }); return null; }
    if (!/[*?[]/.test(base)) return this._exists(p) ? [p] : [];
    const re = new RegExp(`^${base.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);
    let found = [];
    try { found = this._list(dir).filter((f) => re.test(f) && !f.startsWith('.')).sort().map((f) => P.join(dir, f)).filter((f) => this._exists(f)); } catch { /* missing dir */ }
    return found;
  }
  parseFile(abs, depth = 0) {
    const raw = this.read(abs);
    const { tokens, errors } = lex(raw, this.rel(abs));
    errors.forEach((e) => this.errors.push({ file: this.rel(abs), ...e }));
    for (const t of tokens) t.text = t.quoted === '`' ? t.text : envReplace(t.text);
    const tree = parseTree(tokens);
    tree.errors.forEach((e) => this.errors.push(e));
    return tree.nodes;
  }

  /** Collect snippet / named-route definitions from top-level nodes (removing them from the list). */
  collectDefs(nodes) {
    return nodes.filter((nd) => {
      const m = /^\((.+)\)$/.exec(nd.name); const r = /^&\((.+)\)$/.exec(nd.name);
      if (m && nd.toks.length === 1 && nd.block) { this.snippets.set(m[1], nd); if (!this.snippetUse.has(m[1])) this.snippetUse.set(m[1], 0); return false; }
      if (r && nd.toks.length === 1 && nd.block) { this.namedRoutes.set(r[1], nd); return false; }
      return true;
    });
  }

  /** Expand `import` lines in a node list. */
  expand(nodes, file, depth, stack) {
    const out = [];
    for (const nd of nodes) {
      if (++this.nodeCount > MAX_NODES) throw new Error('configuration too large');
      if (nd.name !== 'import' || !nd.args.length || nd.toks[0].quoted) {
        out.push(nd.block ? { ...nd, block: this.expand(nd.block, file, depth, stack) } : nd);
        continue;
      }
      const [pattern, ...args] = nd.args;
      const from = { file: nd.file, line: nd.line };
      if (depth >= MAX_DEPTH) { this.notes.push({ file: nd.file, msg: `import "${pattern}": nesting deeper than ${MAX_DEPTH} levels (import loop?)` }); continue; }
      if (this.snippets.has(pattern)) {
        if (stack.includes(`snippet:${pattern}`)) { this.notes.push({ file: nd.file, msg: `import "${pattern}": snippet imports itself` }); continue; }
        this.snippetUse.set(pattern, (this.snippetUse.get(pattern) || 0) + 1);
        const body = substituteArgs(clone(this.snippets.get(pattern).block), args, nd.block);
        out.push(...this.expand(body, file, depth + 1, [...stack, `snippet:${pattern}`]).map((x) => mark(x, { importedFrom: from, snippet: pattern })));
        continue;
      }
      const P = this.vfs ? path.posix : path;
      const fromAbs = this.vfs ? `/${nd.file}` : P.join(this.root, nd.file);
      const files = this.resolve(pattern, fromAbs);
      if (files === null) continue;
      if (!files.length) {
        this.importsMissing.push({ pattern, file: nd.file, line: nd.line, glob: /[*?[]/.test(pattern) });
        if (!/[*?[]/.test(pattern)) this.notes.push({ file: nd.file, msg: `import "${pattern}" is neither a snippet nor a file${this.vfs ? ' in the uploaded set' : ''}` });
        continue;
      }
      for (const f of files) {
        if (stack.includes(f)) { this.notes.push({ file: nd.file, msg: `import "${pattern}": import loop through ${this.rel(f)}` }); continue; }
        let parsed;
        try { parsed = this.parseFile(f, depth + 1); } catch (e) { this.notes.push({ file: nd.file, msg: `import "${pattern}": ${e.message}` }); continue; }
        parsed = this.collectDefs(parsed);
        const body = substituteArgs(parsed, args, nd.block);
        out.push(...this.expand(body, f, depth + 1, [...stack, f]).map((x) => mark(x, { importedFrom: from })));
      }
    }
    return out;
  }

  load() {
    let nodes = [];
    try { nodes = this.parseFile(this.mainPath, 0); } catch (e) { this.notes.push({ file: this.rel(this.mainPath), msg: e.message }); }
    nodes = this.collectDefs(nodes);
    let expanded = [];
    try { expanded = this.expand(nodes, this.mainPath, 0, [this.mainPath]); } catch (e) { this.notes.push({ file: this.rel(this.mainPath), msg: e.message }); }
    return {
      nodes: expanded, files: [...this.files.values()], notes: this.notes, errors: this.errors,
      snippets: [...this.snippets.entries()].map(([name, nd]) => ({ name, file: nd.file, line: nd.line, uses: this.snippetUse.get(name) || 0 })),
      namedRoutes: this.namedRoutes, importsMissing: this.importsMissing,
    };
  }
}

// ------------------------------------------------------------------------------------------------ redaction
const SECRET_KEY = /^(api_?token|api_?key|auth_?token|token|secret|secret_?key|password|passwd|mac_key|client_secret|access_key|access_key_id|secret_access_key|key_secret|hmac_key|shared_secret|credentials?)$/i;
const SECRET_HEADER = /(authorization|token|secret|passw|api[-_]?key|apikey|credential|cookie)/i;
const isPlaceholder = (v) => /^"?\{(\$|env\.|file\.|vars\.|http\.)/.test(v) || /^"?\{[a-z_.]+\}"?$/i.test(v);
function redactLine(line, ctx) {
  const m = /^(\s*)(\S+)(.*)$/.exec(line);
  if (!m) return line;
  const [, ind, word, rest0] = m;
  let rest = rest0.replace(/(:\/\/[^:/\s@]+:)([^@\s]+)(@)/g, '$1***$3');
  // inside basic_auth / basicauth: "<user> <hash> [salt]"
  if (ctx.basic > 0 && !/^[{}@]/.test(word) && word !== 'import' && !/^(realm|hash)$/.test(word)) {
    const parts = rest.trim().split(/\s+/);
    if (parts[0] && !isPlaceholder(parts[0])) return `${ind}${word} ***${parts.length > 1 ? ' ***' : ''}`;
    return line;
  }
  if (SECRET_KEY.test(word) && rest.trim() && !isPlaceholder(rest.trim().split(/\s+/)[0])) return `${ind}${word} "***"`;
  if (/^(header_up|header_down|request_header|header)$/.test(word)) {
    const toks = rest.trim().split(/\s+/);
    const hi = toks.findIndex((x) => /^[+-]?[A-Za-z0-9-]+$/.test(x) && SECRET_HEADER.test(x));
    if (hi >= 0 && toks[hi + 1] && !isPlaceholder(toks[hi + 1]) && !/^[-]/.test(toks[hi])) return `${ind}${word} ${toks.slice(0, hi + 1).join(' ')} "***"`;
  }
  if (ctx.headerBlock > 0 && SECRET_HEADER.test(word.replace(/^[+-]/, '')) && rest.trim() && !word.startsWith('-') && !isPlaceholder(rest.trim())) return `${ind}${word} "***"`;
  if (/^(dns|acme_dns)$/.test(word)) {
    const toks = rest.trim().split(/\s+/);
    if (toks.length > 1 && toks[1] !== '{' && !isPlaceholder(toks[1])) return `${ind}${word} ${toks[0]} "***"${toks[toks.length - 1] === '{' ? ' {' : ''}`;
  }
  if (/^(mac_key)$/.test(word)) return `${ind}${word} "***"`;
  return `${ind}${word}${rest}`;
}
/** Mask secrets in a Caddyfile (or a Caddy JSON config) while keeping its shape and line numbers. */
function redact(text) {
  if (typeof text !== 'string') return '';
  if (/^\s*\{\s*"/.test(text)) return redactJsonText(text);
  const out = []; const ctx = { basic: 0, headerBlock: 0, depth: 0 }; const stack = [];
  for (const line of text.split(/\r?\n/)) {
    const code = line.replace(/(^|\s)#.*$/, '');
    const t = code.trim();
    const red = /^\s*#/.test(line) ? line : redactLine(line, ctx);
    out.push(red);
    if (/\{\s*$/.test(t)) {
      const w = t.split(/\s+/)[0];
      const kind = /^(basic_?auth)$/.test(w) ? 'basic' : /^(header|request_header|header_up)$/.test(w) ? 'headerBlock' : null;
      stack.push(kind); if (kind) ctx[kind]++;
    } else if (/^\}/.test(t)) { const k = stack.pop(); if (k) ctx[k]--; }
  }
  return out.join('\n');
}
function redactJsonText(text) {
  try { return JSON.stringify(redactJson(JSON.parse(text)), null, 2); } catch { return text.replace(/("(?:password|api_token|token|secret|mac_key|api_key)"\s*:\s*)"[^"]*"/gi, '$1"***"'); }
}
function redactJson(v, key = '') {
  if (Array.isArray(v)) return v.map((x) => redactJson(x, key));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, (SECRET_KEY.test(k) || (SECRET_HEADER.test(k) && /headers|set|add|request|response/.test(key))) && typeof x !== 'object' ? '***' : (SECRET_HEADER.test(k) && Array.isArray(x) && x.every((y) => typeof y === 'string') ? x.map(() => '***') : redactJson(x, k))]));
  return v;
}

// ------------------------------------------------------------------------------------------------ entry points
/** Pick the main file of an uploaded set: "Caddyfile", else a file nothing imports. */
function normalizeUpload(input) {
  const list = (input || []).filter((f) => f && typeof f.name === 'string' && typeof f.content === 'string').slice(0, MAX_FILES);
  if (!list.length) throw new Error('No files provided');
  const norm = list.map((f) => ({ name: f.name.replace(/\\/g, '/').replace(/^\/+/, '').replace(/^(\.\/)+/, ''), content: f.content.slice(0, MAX_FILE_BYTES) }));
  const tops = new Set(norm.map((f) => f.name.split('/')[0]));
  if (norm.length > 1 && norm.every((f) => f.name.includes('/')) && tops.size === 1) norm.forEach((f) => { f.name = f.name.split('/').slice(1).join('/'); });
  const imported = new Set();
  norm.forEach((f) => { for (const m of f.content.matchAll(/^\s*import\s+(\S+)/gm)) imported.add(path.posix.basename(m[1])); });
  const main = norm.find((f) => path.posix.basename(f.name) === 'Caddyfile')
    || norm.find((f) => /caddyfile/i.test(path.posix.basename(f.name)))
    || norm.find((f) => !imported.has(path.posix.basename(f.name)) && !/^\s*\(/.test(f.content.trim()))
    || norm[0];
  return { norm, main };
}

function loadFiles(input) {
  const { norm, main } = normalizeUpload(input);
  const vfs = new Map(norm.map((f) => [`/${path.posix.normalize(f.name)}`, f.content]));
  const loader = new Loader(`/${path.posix.normalize(main.name)}`, '/', vfs);
  const r = loader.load();
  return { ...r, main: main.name, norm };
}

function loadDisk(mainPath, rootDir) { return new Loader(mainPath, rootDir).load(); }

module.exports = { lex, parseTree, envReplace, substituteArgs, Loader, loadFiles, loadDisk, normalizeUpload, redact, redactJson, clone, MAX_FILE_BYTES };

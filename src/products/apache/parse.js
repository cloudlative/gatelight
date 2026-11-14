'use strict';
/**
 * Apache HTTP Server (httpd 2.4) configuration parser.
 *
 *   lex(text)                       -> logical lines (continuations joined, comments / sections / directives classified)
 *   Loader                          -> directive tree with Include / IncludeOptional expansion (sandboxed), Define / ${VAR}
 *   buildModel(ast)                 -> the shared section model (VirtualHost = frontend, balancer = backend, routes)
 *
 * Semantics follow the httpd 2.4 documentation and source:
 *   - configuration files: https://httpd.apache.org/docs/2.4/configuring.html (one directive per line, "\" continues a
 *     line, "#" starts a comment only at the beginning of a line, directive names are case-insensitive)
 *   - Include: https://httpd.apache.org/docs/2.4/mod/core.html#include (relative to ServerRoot; wildcards; a directory
 *     includes all files in it; a wildcard without match is an error for Include, silently ignored for IncludeOptional)
 *   - routing order (mod_proxy.c proxy_trans, mod_rewrite.c / mod_alias.c hook registration): server-level mod_rewrite
 *     runs first (translate_name hook ordered before mod_proxy), then the ProxyPass of the last matching <Location>
 *     ("Ordering ProxyPass Directives in Locations"), then the server-level ProxyPass / ProxyPassMatch list in
 *     configuration order, first match wins (main-server entries are appended BEFORE the virtual host's), then mod_alias
 *     Redirect / RedirectMatch.  https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxypass
 */
const fs = require('fs');
const path = require('path');

const MAX_FILES = 500;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_DEPTH = 16;
const DOCS = 'https://httpd.apache.org/docs/2.4/';
const COND_SECTIONS = new Set(['ifmodule', 'ifdefine', 'ifversion', 'iffile', 'ifdirective', 'ifsection', 'else', 'elseif', 'if']);
const CONFIG_CONDS = new Set(['ifmodule', 'ifdefine', 'ifversion', 'iffile', 'ifdirective', 'ifsection']);
const DIR_SECTIONS = new Set(['location', 'locationmatch', 'directory', 'directorymatch', 'files', 'filesmatch', 'proxy', 'proxymatch', 'limit', 'limitexcept', 'requireall', 'requireany', 'requirenone', 'authnprovideralias', 'authzprovideralias', 'macro', 'mdomainset', 'mdomain']);

// ------------------------------------------------------------------------------------------------ lexer
/** Split a directive's argument string like ap_getword_conf: whitespace separated, "double" / 'single' quoted words. */
function splitArgs(s) {
  const out = []; let i = 0; const n = s.length;
  while (i < n) {
    while (i < n && /\s/.test(s[i])) i++;
    if (i >= n) break;
    const q = s[i];
    if (q === '"' || q === "'") {
      let w = ''; i++;
      while (i < n && s[i] !== q) { if (s[i] === '\\' && (s[i + 1] === q || s[i + 1] === '\\') && i + 1 < n) { w += s[i + 1]; i += 2; continue; } w += s[i++]; }
      i++; out.push({ v: w, q: true });
    } else { let w = ''; while (i < n && !/\s/.test(s[i])) w += s[i++]; out.push({ v: w, q: false }); }
  }
  return out;
}

/**
 * Logical lines. kind: 'blank' | 'comment' | 'open' (<Section args>) | 'close' (</Section>) | 'dir'.
 * Physical lines joined by a trailing backslash keep the number of their first line (and endLine).
 */
function lex(text) {
  const src = String(text || '').replace(/^﻿/, '').replace(/\r\n?/g, '\n').split('\n');
  if (src.length && src[src.length - 1] === '') src.pop();
  const out = [];
  for (let i = 0; i < src.length; i++) {
    const start = i; let t = src[i];
    const isComment = /^\s*#/.test(t);
    while (!isComment && /\\\s*$/.test(t) && !/\\\\\s*$/.test(t) && i + 1 < src.length) { t = t.replace(/\\\s*$/, ' ') + src[++i].replace(/^\s+/, ''); }
    const indent = (/^\s*/.exec(src[start]) || [''])[0];
    const body = t.trim();
    const L = { line: start + 1, endLine: i + 1, indent, text: body, kind: 'dir', name: '', args: [], quoted: [] };
    if (!body) L.kind = 'blank';
    else if (isComment) L.kind = 'comment';
    else if (/^<\//.test(body)) { L.kind = 'close'; const m = /^<\/\s*([^\s>]+)\s*>?/.exec(body); L.name = m ? m[1] : ''; L.unterminated = !/>\s*$/.test(body); }
    else if (/^</.test(body)) {
      L.kind = 'open'; const m = /^<\s*([^\s>]+)\s*([\s\S]*?)\s*(>?)\s*$/.exec(body);
      L.name = m ? m[1] : ''; const a = splitArgs(m ? m[2] : ''); L.args = a.map((x) => x.v); L.quoted = a.map((x) => x.q); L.unterminated = !(m && m[3]);
    } else { const m = /^(\S+)\s*([\s\S]*)$/.exec(body); L.name = m[1]; const a = splitArgs(m[2]); L.args = a.map((x) => x.v); L.quoted = a.map((x) => x.q); }
    out.push(L);
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ loader
const KNOWN_ROOTS = ['/etc/httpd/', '/etc/apache2/', '/usr/local/apache2/', '/usr/local/etc/apache24/', '/usr/local/etc/apache2/', '/opt/apache2/', '/opt/httpd/', '/etc/apache/', '/private/etc/apache2/', '/opt/homebrew/etc/httpd/', '/usr/local/etc/httpd/'];
// Debian / Ubuntu: apache2ctl sources /etc/apache2/envvars; these are its defaults when the file is not available.
const DEBIAN_ENV = { APACHE_RUN_USER: 'www-data', APACHE_RUN_GROUP: 'www-data', APACHE_PID_FILE: '/var/run/apache2/apache2.pid', APACHE_RUN_DIR: '/var/run/apache2', APACHE_LOCK_DIR: '/var/lock/apache2', APACHE_LOG_DIR: '/var/log/apache2' };
/** `export APACHE_LOG_DIR=/var/log/apache2$SUFFIX` lines of an envvars file. */
function parseEnvvars(text) {
  const env = {};
  for (const m of String(text || '').matchAll(/^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|(\S*))/gm)) {
    let v = m[3] ?? m[4] ?? m[5] ?? '';
    v = v.replace(/\$\{?SUFFIX\}?/g, '').replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (x, k) => (env[k] !== undefined ? env[k] : x));
    env[m[1]] = v;
  }
  return env;
}
/**
 * Packaging layout: 'debian' (apache2.conf, mods-enabled, sites-enabled, envvars), 'rhel' (/etc/httpd, conf.modules.d,
 * conf.d) or 'upstream' (/usr/local/apache2/conf/httpd.conf + conf/extra). Same httpd 2.4, different conventions.
 */
function detectLayout(mainName, names, mainText) {
  const n = names.map((x) => x.replace(/\\/g, '/'));
  const t = String(mainText || '');
  if (/(^|\/)apache2\.conf$/.test(mainName) || n.some((x) => /(^|\/)(mods-enabled|mods-available|sites-enabled|sites-available|conf-enabled)\//.test(x) || /(^|\/)envvars$/.test(x)) || /\$\{APACHE_(LOG|RUN|LOCK|PID)_/.test(t) || /^\s*Include(Optional)?\s+"?(mods|sites|conf)-enabled\//m.test(t)) return 'debian';
  if (/^\s*ServerRoot\s+"?\/etc\/httpd"?/m.test(t) || n.some((x) => /(^|\/)conf\.modules\.d\//.test(x)) || /^\s*Include(Optional)?\s+"?conf\.modules\.d\//m.test(t)) return 'rhel';
  if (/^\s*ServerRoot\s+"?\/usr\/local\/apache2"?/m.test(t) || n.some((x) => /(^|\/)extra\/httpd-[a-z-]+\.conf$/.test(x)) || /conf\/extra\/httpd-/.test(t)) return 'upstream';
  return 'unknown';
}
const LAYOUT = {
  debian: { name: 'Debian / Ubuntu (apache2)', main: '/etc/apache2/apache2.conf', siteDir: 'sites-available', test: 'apache2ctl configtest', reload: 'systemctl reload apache2', logDir: '/var/log/apache2', enable: (mods) => `a2enmod ${mods.join(' ')}`, enableSite: (s) => `a2ensite ${s}` },
  rhel: { name: 'RHEL / Fedora (httpd)', main: '/etc/httpd/conf/httpd.conf', siteDir: 'conf.d', test: 'httpd -t', reload: 'systemctl reload httpd', logDir: '/var/log/httpd', enable: (mods) => `add the LoadModule lines for ${mods.map((m) => `mod_${m}`).join(', ')} to /etc/httpd/conf.modules.d/ (most ship enabled in 00-base.conf / 00-proxy.conf)`, enableSite: () => 'files in conf.d are read automatically' },
  upstream: { name: 'upstream source build (/usr/local/apache2)', main: '/usr/local/apache2/conf/httpd.conf', siteDir: 'conf/extra', test: 'apachectl configtest', reload: 'apachectl graceful', logDir: '/usr/local/apache2/logs', enable: (mods) => `uncomment / add LoadModule lines for ${mods.map((m) => `mod_${m}`).join(', ')} in conf/httpd.conf`, enableSite: (s) => `Include conf/extra/${s}.conf in httpd.conf` },
};
LAYOUT.unknown = { ...LAYOUT.rhel, name: 'unknown layout', test: 'apachectl configtest', reload: 'apachectl graceful', enable: (mods) => `load ${mods.map((m) => `mod_${m}`).join(', ')} (a2enmod on Debian / Ubuntu, LoadModule in conf.modules.d on RHEL)` };
/** Modules Debian compiles into the apache2 binary (no LoadModule line needed). */
const STATIC_MODULES = { debian: ['core', 'so_module', 'watchdog_module', 'http_module', 'log_config_module', 'logio_module', 'version_module', 'unixd_module'], rhel: ['core', 'so_module', 'http_module'], upstream: ['core', 'so_module', 'http_module'], unknown: ['core', 'so_module', 'http_module'] };

const globRe = (seg) => new RegExp(`^${seg.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);

class Loader {
  /** @param vfs optional Map(posix path -> content): analyse an uploaded file set instead of the disk. */
  constructor(mainPath, rootDir, vfs) {
    this.vfs = vfs || null;
    this.P = vfs ? path.posix : path;
    this.mainPath = vfs ? path.posix.normalize(mainPath) : path.resolve(mainPath);
    this.root = vfs ? '/' : path.resolve(rootDir || path.dirname(mainPath));
    this.files = new Map();
    this.notes = [];
    this.defines = new Map();
    this.serverRoot = null;
    this.loaded = new Set();  // module identifiers / file names from LoadModule
    this.condNoted = false;
    this.env = {};             // envvars (Debian) used for ${VAR}
    this.layout = 'unknown';
    this.envNoted = false;
  }

  /** Read envvars next to the main file (Debian) and decide the layout before parsing. */
  prepare() {
    const P = this.P; const mainDir = P.dirname(this.mainPath);
    let names = [];
    if (this.vfs) names = [...this.vfs.keys()];
    else { for (const d of ['mods-enabled', 'sites-enabled', 'conf.modules.d', 'extra', 'envvars', '../conf.modules.d']) { const x = P.join(mainDir, d); if (this.inside(x) && fs.existsSync(x)) names.push(`${P.normalize(x)}${d === 'envvars' ? '' : '/x'}`); } }
    let mainText = '';
    try { mainText = this.vfs ? this.vfs.get(this.mainPath) || '' : fs.readFileSync(this.mainPath, 'utf8'); } catch { /* reported later */ }
    this.layout = detectLayout(P.basename(this.mainPath), names, mainText);
    const envPath = [P.join(mainDir, 'envvars'), ...(this.vfs ? [...this.vfs.keys()].filter((k) => /\/envvars$/.test(k)) : [])].find((f) => this.isFile(f) && this.inside(f));
    if (envPath) { try { this.env = parseEnvvars(this.vfs ? this.vfs.get(envPath) : fs.readFileSync(envPath, 'utf8')); this.envFile = this.rel(envPath); } catch { /* optional */ } }
  }

  rel(abs) { return this.vfs ? abs.replace(/^\//, '') : (path.relative(this.root, abs) || path.basename(abs)); }
  inside(abs) { if (this.vfs) return true; const r = path.relative(this.root, abs); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); }
  note(file, msg) { this.notes.push({ file: typeof file === 'string' && file.startsWith('/') ? this.rel(file) : file, msg }); }
  isFile(p) { if (this.vfs) return this.vfs.has(p); try { return fs.statSync(p).isFile(); } catch { return false; } }
  isDir(p) {
    if (this.vfs) { const pre = p.endsWith('/') ? p : `${p}/`; for (const k of this.vfs.keys()) if (k.startsWith(pre)) return true; return false; }
    try { return fs.statSync(p).isDirectory(); } catch { return false; }
  }
  list(dir) {
    if (!this.vfs) { try { return fs.readdirSync(dir); } catch { return []; } }
    const pre = dir === '/' ? '/' : `${dir.replace(/\/$/, '')}/`; const out = new Set();
    for (const k of this.vfs.keys()) if (k.startsWith(pre)) out.add(k.slice(pre.length).split('/')[0]);
    return [...out];
  }

  /** Candidate locations of a path written in the config (ServerRoot-relative, absolute for another machine...). */
  candidates(p, fromFile) {
    const P = this.P; const c = [];
    const sr = this.serverRoot ? this.serverRoot.replace(/\/?$/, '/') : null;
    if (P.isAbsolute(p)) {
      if (this.vfs) { if (this.vfs.has(P.normalize(p)) || this.isDir(P.normalize(p))) c.push(P.normalize(p)); } else if (this.inside(p)) c.push(p);
      for (const pre of [sr, ...KNOWN_ROOTS].filter(Boolean)) if (p.startsWith(pre)) c.push(P.join(this.root, p.slice(pre.length)));
      if (!c.length) c.push(P.join(this.root, p.replace(/^\/+/, ''))); // last resort: same layout below the root
    } else {
      c.push(P.join(this.root, p));
      const mainDir = P.dirname(this.mainPath);
      if (mainDir !== this.root) { c.push(P.join(mainDir, p)); c.push(P.join(P.dirname(mainDir), p)); }
      if (fromFile) c.push(P.join(P.dirname(fromFile), p));
    }
    return [...new Set(c.map((x) => P.normalize(x)))];
  }

  /** Expand a path with wildcards in any segment (sorted, like apr_match_glob). */
  glob(p) {
    const P = this.P; const isAbs = P.isAbsolute(p);
    const segs = p.split(/[\\/]/).filter((s, i) => s !== '' || i === 0);
    let cur = [isAbs ? (this.vfs ? '/' : path.parse(p).root) : ''];
    segs.forEach((seg, i) => {
      if (i === 0 && seg === '') return;
      const last = i === segs.length - 1;
      const next = [];
      for (const base of cur) {
        if (!/[*?[]/.test(seg)) { next.push(P.join(base, seg)); continue; }
        const re = globRe(seg);
        for (const f of this.list(base).sort()) { if (f.startsWith('.') && !seg.startsWith('.')) continue; const full = P.join(base, f); if (re.test(f) && (last || this.isDir(full))) next.push(full); }
      }
      cur = next;
    });
    return cur;
  }

  /** All regular files below a directory, in lexical order (Include of a directory). */
  walkDir(dir, depth = 0) {
    if (depth > 4) return [];
    const out = [];
    for (const f of this.list(dir).sort()) { const full = this.P.join(dir, f); if (this.isFile(full)) out.push(full); else if (this.isDir(full)) out.push(...this.walkDir(full, depth + 1)); }
    return out;
  }

  resolveQuiet(pattern, fromFile) {
    for (const cand of this.candidates(pattern, fromFile)) {
      if (!this.inside(cand)) continue;
      const hits = (/[*?[]/.test(cand) ? this.glob(cand) : [cand]).flatMap((h) => (this.isFile(h) ? [h] : this.isDir(h) ? this.walkDir(h) : []));
      if (hits.length) return hits;
    }
    return [];
  }

  resolveInclude(pattern, optional, fromFile) {
    const name = optional ? 'IncludeOptional' : 'Include';
    for (const cand of this.candidates(pattern, fromFile)) {
      if (!this.inside(cand)) continue;
      const wild = /[*?[]/.test(cand);
      if (!wild) {
        if (this.isFile(cand)) return [cand];
        if (this.isDir(cand)) return this.walkDir(cand);
        continue;
      }
      const hits = this.glob(cand).flatMap((h) => (this.isFile(h) ? [h] : this.isDir(h) ? this.walkDir(h) : []));
      if (hits.length) return hits;
    }
    if (this.vfs && /(sites|conf)-enabled/.test(pattern)) {
      const alt = pattern.replace(/(sites|conf)-enabled/, '$1-available');
      const hits = this.resolveQuiet(alt, fromFile);
      if (hits.length) { this.note(fromFile, `${name} "${pattern}" matched nothing in the upload; the files in ${alt.replace(/\/[^/]*$/, '')} were used instead (on the server only the enabled ones are read)`); return hits; }
    }
    const outside = !this.vfs && this.candidates(pattern, fromFile).every((c) => !this.inside(c));
    if (outside) this.note(fromFile, `${name} "${pattern}" is outside the config root (${this.root}) and was skipped`);
    else if (!optional) this.note(fromFile, `${name} "${pattern}" ${/[*?]/.test(pattern) ? 'matched no files' : 'not found'}${this.vfs ? ' in the uploaded files — upload the conf.d / sites-enabled folder too' : ''} (httpd refuses to start when an Include has no match; IncludeOptional is silently skipped)`);
    return [];
  }

  readFile(abs) {
    if (this.files.size >= MAX_FILES) throw new Error(`more than ${MAX_FILES} included files`);
    if (this.vfs) {
      const raw = this.vfs.get(abs); if (raw === undefined) throw new Error(`${abs} not found`);
      if (!this.files.has(abs)) this.files.set(abs, { name: this.rel(abs), raw, mtimeMs: 0, abs });
      return raw;
    }
    // sites-enabled entries are usually symlinks to sites-available: follow them, but never out of the root
    let real = abs; try { real = fs.realpathSync(abs); } catch { /* stat below reports it */ }
    let realRoot = this.root; try { realRoot = fs.realpathSync(this.root); } catch { /* keep */ }
    const rr = path.relative(realRoot, real);
    if (rr.startsWith('..') || path.isAbsolute(rr)) throw new Error(`${this.rel(abs)} is a link to ${real}, outside the config root; skipped`);
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) throw new Error(`${abs} is not a regular file or exceeds ${MAX_FILE_BYTES} bytes`);
    const raw = fs.readFileSync(abs, 'utf8');
    if (!this.files.has(abs)) this.files.set(abs, { name: this.rel(abs), raw, mtimeMs: st.mtimeMs, abs });
    return raw;
  }

  /** ${VAR} from Define (unknown names stay as written; httpd would take them from the environment). */
  subst(s) {
    return String(s).replace(/\$\{([A-Za-z0-9_.:-]+)\}/g, (m, k) => {
      if (this.defines.has(k)) return this.defines.get(k);
      if (this.env[k] !== undefined) return this.env[k];
      if (DEBIAN_ENV[k] !== undefined && (this.layout === 'debian' || /^APACHE_/.test(k))) {
        if (!this.envNoted) { this.envNoted = true; this.notes.push({ file: this.rel(this.mainPath), msg: `\${APACHE_*} variables come from /etc/apache2/envvars, which is not part of the analysed files; the Debian defaults are used (APACHE_LOG_DIR=${DEBIAN_ENV.APACHE_LOG_DIR}, APACHE_RUN_USER=${DEBIAN_ENV.APACHE_RUN_USER} ...)`, kind: 'envvars' }); }
        return DEBIAN_ENV[k];
      }
      return m;
    });
  }

  parseFile(abs, depth, stack) {
    if (depth > MAX_DEPTH || stack.includes(abs)) { this.note(abs, 'include loop / depth limit reached'); return []; }
    let raw;
    try { raw = this.readFile(abs); } catch (e) { this.note(abs, e.message); return []; }
    return this.parseLines(lex(raw), abs, depth, [...stack, abs]);
  }

  /** Is a conditional section active? Positive conditions are assumed true; negations only when we know better. */
  condActive(node) {
    const n = node.lname; const a = (node.args[0] || '').trim();
    if (!this.condNoted) { this.condNoted = true; this.note(node.file, `<IfModule> / <IfDefine> / <IfVersion> sections are evaluated against the LoadModule lines and Define names in the files; what GateLight cannot know (compiled-in modules, -D flags, the version) is analysed as active`); }
    if (n === 'ifmodule' && this.loaded.size) {
      // With a known packaging layout and LoadModule lines already seen, the module list is known (plus what the
      // distribution compiles in); otherwise positive conditions are assumed true.
      const neg = a.startsWith('!'); const m = neg ? a.slice(1) : a;
      const statics = STATIC_MODULES[this.layout] || [];
      const id = /\.c$/.test(m) ? `${m.replace(/\.c$/, '').replace(/^mod_/, '')}_module` : m;
      const known = this.loaded.has(m) || this.loaded.has(id) || statics.includes(id) || /^(core|http_core|mod_so|mod_core)(\.c)?$/.test(m);
      if (neg) return !known;
      if (this.layout === 'debian' || this.layout === 'rhel') return known;
      return true;
    }
    if (n === 'ifdefine' && a.startsWith('!')) return !this.defines.has(a.slice(1));
    return true;
  }

  parseLines(lines, file, depth, stack) {
    const name = this.rel(file);
    const root = []; const blocks = [{ children: root, node: null }];
    const top = () => blocks[blocks.length - 1];
    for (const L of lines) {
      if (L.kind === 'blank' || L.kind === 'comment') continue;
      if (L.kind === 'close') {
        const lname = L.name.toLowerCase();
        if (blocks.length > 1 && top().node.lname === lname) { const b = blocks.pop(); b.node.endLine = L.line; }
        else if (blocks.length > 1) { // mismatched: close the nearest matching one if any
          const idx = blocks.map((b) => b.node && b.node.lname).lastIndexOf(lname);
          if (idx > 0) while (blocks.length > idx) blocks.pop().node.endLine = L.line;
        }
        continue;
      }
      const args = L.args.map((a) => this.subst(a));
      const node = { name: L.kind === 'open' ? L.name : L.name, lname: L.name.toLowerCase(), args, line: L.line, file: name, abs: file, section: L.kind === 'open', children: L.kind === 'open' ? [] : null, endLine: L.endLine };
      if (L.kind === 'open') {
        if (CONFIG_CONDS.has(node.lname)) node.cond = true;
        if (node.cond && !this.condActive(node)) node.inactive = true;
        top().children.push(node); blocks.push({ children: node.children, node });
        continue;
      }
      const inactive = blocks.some((b) => b.node && b.node.inactive);
      if (!inactive) {
        if (node.lname === 'define' && args[0]) this.defines.set(args[0], args.length > 1 ? args.slice(1).join(' ') : '');
        if (node.lname === 'undefine' && args[0]) this.defines.delete(args[0]);
        if (node.lname === 'serverroot' && args[0]) this.serverRoot = args[0];
        if (node.lname === 'loadmodule' && args[0]) { this.loaded.add(args[0]); if (args[1]) this.loaded.add(path.posix.basename(args[1]).replace(/\.so$/, '.c')); }
      }
      if ((node.lname === 'include' || node.lname === 'includeoptional') && args[0] && !inactive) {
        const included = this.resolveInclude(args[0], node.lname === 'includeoptional', file);
        node.included = included.map((f) => this.rel(f));
        top().children.push(node);
        for (const f of included) for (const child of this.parseFile(f, depth + 1, stack)) top().children.push(child);
        continue;
      }
      top().children.push(node);
    }
    for (const b of blocks.slice(1)) b.node.unclosed = true;
    return root;
  }

  load() {
    this.prepare();
    const ast = this.parseFile(this.mainPath, 0, []);
    const L = LAYOUT[this.layout];
    this.notes.push({ file: this.rel(this.mainPath), msg: `Layout: ${L.name}${this.envFile ? `; variables from ${this.envFile}` : ''}. Test with \`${L.test}\`, apply with \`${L.reload}\`.`, kind: 'layout' });
    return { ast, files: [...this.files.values()], notes: this.notes, defines: this.defines, loaded: this.loaded, layout: this.layout, env: this.env };
  }
}

// ------------------------------------------------------------------------------------------------ helpers over the tree
/** Children of a node with active conditional sections flattened away. */
function flat(nodes) {
  const out = [];
  for (const n of nodes || []) {
    if (n.cond) { if (!n.inactive) out.push(...flat(n.children)); continue; }
    out.push(n);
  }
  return out;
}
/** Every directive below `nodes` (depth first), with the chain of (non-conditional) enclosing sections. */
function walk(nodes, fn, within = []) {
  for (const n of flat(nodes)) {
    fn(n, within);
    if (n.section && n.lname !== 'virtualhost') walk(n.children, fn, [...within, n]);
  }
}
const sectionLabel = (n) => `<${n.name}${n.args.length ? ` ${n.args.join(' ')}` : ''}>`;

// ------------------------------------------------------------------------------------------------ URLs, members
const DEFAULT_PORT = { http: 80, https: 443, ws: 80, wss: 443, h2c: 80, h2: 443, ajp: 8009, fcgi: 9000, scgi: 4000, uwsgi: 3031, ftp: 21 };
const defaultPort = (scheme) => DEFAULT_PORT[String(scheme || 'http').toLowerCase()] || 80;
const maskUrl = (u) => String(u || '').replace(/(\/\/[^/@\s:]*:)[^@\s/]*@/, '$1***@');

/** "http://user:pw@10.0.0.1:8080/app/" -> { scheme, host, port, hostPort, path, balancer, socket } */
function parseUrl(raw) {
  let u = String(raw || '');
  let socket = null;
  const uds = /^unix:([^|]+)\|(.*)$/i.exec(u);
  if (uds) { socket = uds[1]; u = uds[2]; }
  const m = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]*)(?::(\d+|\$\d+|\$\{[^}]+\}))?([^?#]*)?/i.exec(u);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  if (scheme === 'balancer') return { scheme, balancer: m[2], host: m[2], port: null, hostPort: m[2], path: m[4] || '', socket: null };
  const host = m[2]; const port = m[3] && /^\d+$/.test(m[3]) ? Number(m[3]) : (m[3] ? null : defaultPort(scheme));
  const dynamic = /\$/.test(host) || (m[3] && /\$/.test(m[3]));
  return { scheme, host, port, hostPort: socket ? `unix:${socket}` : `${host}${port ? `:${port}` : (m[3] ? `:${m[3]}` : '')}`, path: m[4] || '', socket, dynamic };
}

/** BalancerMember / ProxyPass key=value parameters. */
function kvParams(args) {
  const o = {};
  for (const a of args) { const i = a.indexOf('='); if (i > 0) o[a.slice(0, i).toLowerCase()] = a.slice(i + 1); else o[a.toLowerCase()] = true; }
  return o;
}
/** status=+H-D... -> flags */
function statusFlags(v) {
  const f = {}; if (!v) return f;
  let sign = '+';
  for (const c of String(v)) { if (c === '+' || c === '-') { sign = c; continue; } f[c.toUpperCase()] = sign === '+'; }
  return f;
}

function member(url, params, node) {
  const u = parseUrl(url) || { scheme: 'http', hostPort: url, path: '' };
  const o = kvParams(params);
  const st = statusFlags(o.status);
  const hc = o.hcmethod && String(o.hcmethod).toUpperCase() !== 'NONE';
  return {
    name: u.hostPort, address: u.hostPort, scheme: u.scheme, url: maskUrl(url), path: u.path || '',
    check: Boolean(hc || o.hctemplate), backup: Boolean(st.H), disabled: Boolean(st.D || st.S), drain: Boolean(st.N), standby: Boolean(st.R),
    weight: o.loadfactor != null && o.loadfactor !== true ? Number(o.loadfactor) : null, route: o.route && o.route !== true ? String(o.route) : null,
    opts: o, options: params.join(' '), line: node.line, file: node.file, commented: false,
  };
}

// ------------------------------------------------------------------------------------------------ RewriteRule
const FLAG_RE = /^\[(.*)\]$/;
function rewriteFlags(arg) {
  const m = FLAG_RE.exec(arg || ''); const f = {};
  if (!m) return f;
  for (const part of m[1].split(',')) { const [k, ...v] = part.trim().split('='); if (k) f[k.toLowerCase()] = v.length ? v.join('=') : true; }
  // long names
  const alias = { proxy: 'p', redirect: 'r', last: 'l', forbidden: 'f', gone: 'g', nocase: 'nc', passthrough: 'pt', end: 'end', skip: 's', chain: 'c', qsappend: 'qsa' };
  for (const [k, v] of Object.entries(alias)) if (f[k] !== undefined) f[v] = f[k];
  return f;
}
/** RewriteCond test string -> shared matcher (null when there is no equivalent). */
function condMatcher(testString, pattern, flags) {
  let neg = false; let pat = pattern;
  if (pat.startsWith('!')) { neg = true; pat = pat.slice(1); }
  const map = [[/^%\{HTTP_HOST\}$/i, 'Host'], [/^%\{REQUEST_URI\}$/i, 'Path'], [/^%\{REQUEST_METHOD\}$/i, 'Method'], [/^%\{QUERY_STRING\}$/i, 'Query'], [/^%\{REMOTE_ADDR\}$/i, 'ClientIP'], [/^%\{SERVER_NAME\}$/i, 'Host']];
  let field = null; let name;
  for (const [re, fld] of map) if (re.test(testString)) field = fld;
  const h = /^%\{HTTP:([^}]+)\}$/i.exec(testString) || /^%\{HTTP_([A-Z_]+)\}$/.exec(testString);
  if (!field && h) { field = 'Header'; name = h[1].replace(/_/g, '-'); }
  if (!field) return null;
  let op = 'matches'; let values = [pat];
  if (/^[<>=]/.test(pat) && !/^=$/.test(pat)) { if (pat[0] === '=') { op = 'is'; values = [pat.slice(1)]; } else return null; }
  else if (/^-/.test(pat)) return null; // file tests
  const out = { field, op, values, negated: neg };
  if (flags && /\bNC\b/i.test(flags)) out.caseInsensitive = true;
  if (name) out.name = name;
  return out;
}

// ------------------------------------------------------------------------------------------------ model
function parseVhostAddr(a, listenPorts) {
  const s = String(a);
  const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+|\*))?$/.exec(s);
  const host = m ? m[1] : s; const port = m && m[2] ? m[2] : null;
  return { host, port, address: port ? `${host}:${port}` : host, ports: port ? [port] : listenPorts };
}
function parseListen(args) {
  const a = args[0] || '';
  const m = /^(?:(\[[^\]]+\]|[^:]+):)?(\d+)$/.exec(a);
  return { address: m ? `${m[1] || '*'}:${m[2]}` : a, host: m ? m[1] || '*' : '', port: m ? m[2] : '', proto: (args[1] || '').toLowerCase() };
}
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function hostMatcher(names) {
  if (!names.length) return null;
  if (names.every((n) => !/[*?]/.test(n))) return { field: 'Host', op: 'is', values: [...names], negated: false };
  return { field: 'Host', op: 'matches', values: [`^(${names.map((n) => escRe(n).replace(/\\\*/g, '[^.]+').replace(/\\\?/g, '.')).join('|')})$`], negated: false, caseInsensitive: true };
}

function buildModel(ast, ctx = {}) {
  const top = flat(ast);
  const sections = [];
  const listens = top.filter((n) => n.lname === 'listen').map((n) => ({ ...parseListen(n.args), line: n.line, file: n.file }));
  const listenPorts = [...new Set(listens.map((l) => l.port).filter(Boolean))];
  const vhosts = top.filter((n) => n.lname === 'virtualhost' && n.section);
  const mainDirs = [];
  walk(ast, (n, within) => { if (!within.some((w) => w.lname === 'virtualhost')) mainDirs.push({ n, within }); });
  const loaded = new Set(); top.filter((n) => n.lname === 'loadmodule').forEach((n) => { loaded.add(n.args[0]); });
  const dlist = (pairs) => pairs.filter(({ n }) => !n.section || n.lname !== 'virtualhost').map(({ n, within }) => ({ keyword: n.name, lkeyword: n.lname, args: n.args, line: n.line, file: n.file, raw: n.section ? sectionLabel(n) : [n.name, ...n.args].join(' '), section: n.section || undefined, within: within.map(sectionLabel) }));

  sections.push({
    type: 'global', name: 'global', line: 1, endLine: 1, file: ast[0] ? ast[0].file : '', mode: null, balance: null, timeouts: {}, binds: [], acls: [], routes: [], servers: [], users: [], effective: {},
    directives: dlist(mainDirs), listens, loadedModules: [...loaded], staticModules: STATIC_MODULES[ctx.layout || 'unknown'], defines: ctx.defines ? Object.fromEntries(ctx.defines) : {}, layout: ctx.layout || 'unknown',
  });

  // ---------------- balancers (backends)
  const backends = new Map(); // name -> section
  const implicit = new Map();
  const hcTemplates = new Map();
  walk(ast, (n) => { if (n.lname === 'proxyhctemplate' && n.args[0]) hcTemplates.set(n.args[0], kvParams(n.args.slice(1))); });
  const balancerName = (u) => { const m = /^balancer:\/\/([^/\s]+)/i.exec(u || ''); return m ? m[1] : null; };
  const ensureBackend = (name, node, scope) => {
    let be = backends.get(name);
    if (!be) {
      be = { type: 'backend', name, line: node.line, endLine: node.endLine || node.line, file: node.file, mode: 'http', balance: 'byrequests', implicit: false, servers: [], healthCheck: null, sticky: false, stickysession: null,
        routes: [], binds: [], acls: [], users: [], timeouts: {}, effective: { mode: 'http', timeouts: {}, defaultServer: {} }, directives: [], params: {}, scope, url: `balancer://${name}` };
      backends.set(name, be);
    }
    return be;
  };
  const applyProxySet = (be, params) => {
    const o = kvParams(params); Object.assign(be.params, o);
    if (o.lbmethod) be.balance = String(o.lbmethod);
    if (o.stickysession) { be.sticky = true; be.stickysession = String(o.stickysession); }
    if (o.timeout) be.timeouts.server = Number(o.timeout);
    if (o.connectiontimeout) be.timeouts.connect = Number(o.connectiontimeout);
  };
  const addMember = (be, url, params, node) => {
    const m = member(url, params, node);
    if (be.servers.some((s) => s.name === m.name)) m.name = `${m.name}#${node.line}`;
    be.servers.push(m);
    be.directives.push({ keyword: node.name, args: node.args, line: node.line, file: node.file, raw: [node.name, ...node.args].join(' ') });
  };
  const collectBalancers = (nodes, scope) => {
    for (const n of flat(nodes)) {
      if (n.lname === 'proxy' && n.section) {
        const bn = balancerName(n.args[0]); if (!bn) continue;
        const be = ensureBackend(bn, n, scope); be.line = n.line; be.endLine = n.endLine; be.file = n.file; be.declared = true;
        walk(n.children, (d) => {
          if (d.lname === 'balancermember' && d.args.length) { const hasBal = balancerName(d.args[0]); addMember(be, hasBal ? d.args[1] : d.args[0], d.args.slice(hasBal ? 2 : 1), d); }
          else if (d.lname === 'proxyset') applyProxySet(be, d.args.filter((a) => !balancerName(a)));
          else if (!d.section) be.directives.push({ keyword: d.name, args: d.args, line: d.line, file: d.file, raw: [d.name, ...d.args].join(' ') });
        });
      } else if (n.lname === 'balancermember' && balancerName(n.args[0])) {
        const be = ensureBackend(balancerName(n.args[0]), n, scope); be.declared = true; addMember(be, n.args[1], n.args.slice(2), n);
      } else if (n.lname === 'proxyset' && balancerName(n.args[0])) {
        applyProxySet(ensureBackend(balancerName(n.args[0]), n, scope), n.args.slice(1));
      } else if (n.section && n.lname !== 'virtualhost' && !DIR_SECTIONS.has(n.lname)) collectBalancers(n.children, scope);
    }
  };
  collectBalancers(ast, 'main');
  for (const vh of vhosts) collectBalancers(vh.children, vh);
  for (const be of backends.values()) {
    const hcm = be.servers.find((s) => s.check);
    if (hcm) {
      const t = hcm.opts.hctemplate ? hcTemplates.get(hcm.opts.hctemplate) || {} : {};
      const o = { ...t, ...hcm.opts };
      be.healthCheck = { method: String(o.hcmethod || 'GET').toUpperCase(), path: o.hcuri && o.hcuri !== true ? String(o.hcuri) : '/', interval: o.hcinterval ? Number(o.hcinterval) : 30, passes: o.hcpasses ? Number(o.hcpasses) : 1, fails: o.hcfails ? Number(o.hcfails) : 1, expr: o.hcexpr || null };
    }
    if (be.servers.length && be.servers.every((s) => s.opts.route) && !be.sticky) be.routesNoSticky = true;
  }

  // ---------------- routes
  const targetOf = (url, node) => {
    const bn = balancerName(url);
    if (bn) { if (!backends.has(bn)) return { name: bn, kind: 'balancer', undefinedBalancer: true }; return { name: bn, kind: 'balancer' }; }
    const u = parseUrl(url);
    if (!u) return null;
    if (u.dynamic) return { name: u.hostPort, kind: 'dynamic', dynamic: true, scheme: u.scheme };
    const name = u.hostPort;
    if (!implicit.has(name)) {
      implicit.set(name, {
        type: 'backend', name, line: node.line, endLine: node.line, file: node.file, mode: 'http', balance: null, implicit: true, healthCheck: null, sticky: false,
        servers: [{ name, address: name, scheme: u.scheme, url: maskUrl(url), check: false, backup: false, disabled: false, weight: null, opts: {}, options: '', line: node.line, file: node.file, commented: false }],
        routes: [], binds: [], acls: [], users: [], timeouts: {}, effective: { mode: 'http', timeouts: {}, defaultServer: {} }, directives: [],
      });
    }
    return { name, kind: 'external', scheme: u.scheme };
  };

  /** Path mapping of ProxyPass prefix -> URL path ("Prefix /api/ is replaced by /v2/"). */
  const prefixTransforms = (prefix, url, node, regex) => {
    const u = parseUrl(url); const to = u ? u.path : '';
    if (regex) return [{ action: 'replace-path-regex', args: [prefix, to || '$0'], line: node.line, text: `${node.name} ${prefix} → ${to || '(path unchanged)'}` }].filter(() => to !== '');
    if (to === prefix) return [];
    if (to === '' || to === '/') { if (prefix === '/') return []; return [{ action: 'strip-prefix', args: [prefix.replace(/\/$/, '') || '/'], line: node.line, text: `Prefix ${prefix} is replaced by ${to || '(nothing)'}` }]; }
    if (prefix === '/') return [{ action: 'add-prefix', args: [to.replace(/\/$/, '')], line: node.line, text: `Prefix / is replaced by ${to}` }];
    return [{ action: 'replace-path-regex', args: [`^${escRe(prefix)}(.*)$`, `${to}$1`], line: node.line, text: `Prefix ${prefix} is replaced by ${to}` }];
  };

  const describe = (matchers) => matchers.map((m) => {
    const what = m.field === 'Header' ? `header ${m.name}` : m.field === 'Path' ? 'path' : m.field === 'Host' ? 'Host' : m.field.toLowerCase();
    const vals = m.values.length > 1 ? `one of ${m.values.join(', ')}` : m.values[0];
    return `${what}${m.negated ? ' does not' : ''} ${m.negated ? m.op.replace(/^is$/, 'equal').replace(/^matches$/, 'match').replace(/^begins with$/, 'begin with') : m.op} ${vals}`;
  }).join(' and ');
  const shortOf = (hosts, m) => {
    const h = hosts.length ? hosts[0] + (hosts.length > 1 ? '(+)' : '') : '';
    if (!m) return `${h}/*`;
    if (m.op === 'begins with') return `${h}${m.values[0]}*`;
    if (m.op === 'is') return `${h}= ${m.values[0]}`;
    return `${h}~ ${m.values[0]}`;
  };

  function routesFor(scope, names, mainScope) {
    const routes = [];
    const hosts = names;
    const hm = hostMatcher(names);
    const mk = (o) => {
      const matchers = [...(hm ? [hm] : []), ...(o.matchers || [])];
      const pathM = (o.matchers || []).find((m) => m.field === 'Path');
      return {
        target: null, type: 'conditional', priority: null, transforms: [], passUrl: null, terminal: false, commented: false, dynamic: false, external: false, hosts, paths: [], aclRefs: [],
        ...o, matchers, match: describe(matchers) || 'any request', short: o.short || shortOf(hosts, pathM),
      };
    };
    const nodesOf = (sc) => (sc === 'main' ? ast : sc.children);
    const scopes = mainScope ? [mainScope] : [];
    // 1. mod_rewrite at server / vhost level (not inherited unless RewriteOptions Inherit / InheritBefore)
    const rwBlocks = [];
    const rwEnabled = (sc) => { let on = false; for (const n of flat(nodesOf(sc))) if (n.lname === 'rewriteengine') on = /^on$/i.test(n.args[0] || ''); return on; };
    const rwOptions = (sc) => flat(nodesOf(sc)).filter((n) => n.lname === 'rewriteoptions').flatMap((n) => n.args.map((a) => a.toLowerCase()));
    if (scope !== 'main') {
      const opts = rwOptions(scope);
      if (opts.includes('inheritbefore') && rwEnabled('main')) rwBlocks.push({ sc: 'main', inherited: true });
      rwBlocks.push({ sc: scope });
      if (opts.includes('inherit') && rwEnabled('main')) rwBlocks.push({ sc: 'main', inherited: true });
    } else rwBlocks.push({ sc: 'main' });
    const pending = []; // non-terminal rewrites applied to every later route of this frontend
    for (const { sc, inherited } of rwBlocks) {
      if (!rwEnabled(sc)) continue;
      let conds = [];
      for (const n of flat(nodesOf(sc))) {
        if (n.lname === 'rewritecond') { conds.push(n); continue; }
        if (n.lname !== 'rewriterule') { continue; }
        const [pattern = '', subst = '', flagArg = ''] = n.args;
        const f = rewriteFlags(flagArg);
        const neg = pattern.startsWith('!');
        const pathM = { field: 'Path', op: 'matches', values: [neg ? pattern.slice(1) : pattern], negated: neg, ...(f.nc ? { caseInsensitive: true } : {}) };
        // RewriteCond: consecutive conditions are ANDed, [OR] joins with the next one -> one route per OR alternative
        const groups = [[]];
        conds.forEach((c, i) => {
          const m = condMatcher(c.args[0] || '', c.args[1] || '', c.args[2] || '');
          const item = { c, m };
          groups[groups.length - 1].push(item);
          if (!/\bOR\b/i.test(c.args[2] || '') || i === conds.length - 1) groups.push([]);
        });
        const andGroups = groups.filter((g) => g.length);
        let combos = [[]];
        for (const g of andGroups) { const next = []; for (const c of combos) for (const alt of g) next.push([...c, alt]); combos = next.slice(0, 8); }
        const condText = conds.map((c) => `RewriteCond ${c.args.join(' ')}`).join(' ; ');
        const approx = conds.some((c) => !condMatcher(c.args[0] || '', c.args[1] || '', c.args[2] || ''));
        conds = [];
        const base = { line: n.line, file: n.file, condition: `${condText ? `${condText} ; ` : ''}RewriteRule ${pattern}`, rawCondition: `RewriteRule ${n.args.join(' ')}`, directive: 'RewriteRule', inherited: Boolean(inherited), approximate: approx || undefined };
        const extraTransforms = [...pending];
        const emit = (o) => { for (const combo of combos) routes.push(mk({ ...base, ...o, matchers: [...combo.map((x) => x.m).filter(Boolean), pathM], transforms: [...extraTransforms, ...(o.transforms || [])] })); };
        if (f.p) {
          const t = targetOf(subst, n);
          if (!t) continue;
          const u = parseUrl(subst);
          emit({ target: t.name, dynamic: Boolean(t.dynamic), external: t.kind === 'external', undefinedBalancer: t.undefinedBalancer || undefined, passUrl: maskUrl(subst),
            transforms: [{ action: 'replace-path-regex', args: [neg ? '^(.*)$' : pattern, u ? u.path || '/' : subst], line: n.line, text: `RewriteRule ${pattern} → ${maskUrl(subst)} [P]` }] });
        } else if (f.r !== undefined || (/^https?:\/\//i.test(subst) && !f.p)) {
          const code = f.r && f.r !== true ? String(f.r) : '302';
          emit({ terminal: true, transforms: [{ action: 'redirect', args: [code, subst], line: n.line, text: `Redirect ${code} ${subst}` }] });
        } else if (f.f !== undefined) emit({ terminal: true, transforms: [{ action: 'deny', args: ['403'], line: n.line, text: 'RewriteRule [F] → 403 Forbidden' }] });
        else if (f.g !== undefined) emit({ terminal: true, transforms: [{ action: 'return', args: ['410'], line: n.line, text: 'RewriteRule [G] → 410 Gone' }] });
        else if (subst !== '-' && subst) pending.push({ action: 'replace-path-regex', args: [pattern, subst], line: n.line, text: `RewriteRule ${pattern} ${subst}${flagArg ? ` ${flagArg}` : ''}${condText ? ` (if ${condText})` : ''}`, conditional: Boolean(condText) || undefined });
      }
    }
    // 2. ProxyPass of the last matching <Location> / <LocationMatch> (main-server sections merge first, vhost ones after)
    const locs = [];
    const collectLocs = (sc, inherited) => {
      const visit = (nodes) => {
        for (const n of flat(nodes)) {
          if (n.section && (n.lname === 'location' || n.lname === 'locationmatch')) {
            const pp = flat(n.children).filter((d) => d.lname === 'proxypass' || d.lname === 'proxypassmatch');
            const rw = flat(n.children).filter((d) => d.lname === 'redirect' || d.lname === 'redirectmatch' || d.lname === 'redirectpermanent' || d.lname === 'redirecttemp');
            locs.push({ n, pp, rw, inherited });
          } else if (n.section && n.lname !== 'virtualhost' && !DIR_SECTIONS.has(n.lname)) visit(n.children);
        }
      };
      visit(sc === 'main' ? ast : sc.children);
    };
    if (scope !== 'main') collectLocs('main', true);
    collectLocs(scope, false);
    const locInfo = [];
    for (const { n, pp, rw, inherited } of locs) {
      const isRe = n.lname === 'locationmatch' || n.args[0] === '~';
      const p = n.args[0] === '~' ? n.args[1] : n.args[0];
      locInfo.push({ path: p, modifier: isRe ? '~' : '', line: n.line, file: n.file, kind: pp.length ? 'proxy' : rw.length ? 'return' : 'other', target: null, inherited, detail: (flat(n.children).find((d) => d.lname === 'sethandler') || { args: [] }).args[0] || undefined });
    }
    for (const { n, pp, inherited } of [...locs].reverse()) {
      const d = pp[pp.length - 1]; if (!d) continue; // httpd keeps the last ProxyPass in a Location
      const isRe = n.lname === 'locationmatch' || n.args[0] === '~';
      const p = n.args[0] === '~' ? n.args[1] : n.args[0];
      const url = d.args[0];
      const pathM = { field: 'Path', op: isRe ? 'matches' : 'begins with', values: [p], negated: false };
      const label = `${sectionLabel(n)} ${d.name} ${d.args.join(' ')}`;
      const info = locInfo.find((x) => x.line === n.line && x.file === n.file);
      if (url === '!') { routes.push(mk({ terminal: true, matchers: [pathM], paths: [p], condition: label, rawCondition: label, line: d.line, file: d.file, directive: d.name, inherited, transforms: [...pending, { action: 'return', args: ['local'], line: d.line, text: 'ProxyPass ! — served by httpd itself' }] })); continue; }
      const t = targetOf(url, d); if (!t) continue;
      if (info) info.target = t.name;
      routes.push(mk({ target: t.name, dynamic: Boolean(t.dynamic), external: t.kind === 'external', undefinedBalancer: t.undefinedBalancer || undefined, passUrl: maskUrl(url), matchers: [pathM], paths: [p], condition: label, rawCondition: label, line: d.line, file: d.file, directive: d.name, inherited, inLocation: true, params: kvParams(d.args.slice(1)),
        transforms: [...pending, ...prefixTransforms(p, url, d, isRe)] }));
    }
    // 3. server-level ProxyPass / ProxyPassMatch, main server first (unless ProxyPassInherit Off), first match wins
    const ppOf = (sc) => {
      const out = [];
      const visit = (nodes) => { for (const n of flat(nodes)) { if (n.lname === 'proxypass' || n.lname === 'proxypassmatch') out.push(n); else if (n.section && n.lname !== 'virtualhost' && !DIR_SECTIONS.has(n.lname)) visit(n.children); } };
      visit(sc === 'main' ? ast : sc.children); return out;
    };
    const inheritOff = scope !== 'main' && [...flat(scope.children), ...top].some((n) => n.lname === 'proxypassinherit' && /^off$/i.test(n.args[0] || ''));
    const ppList = [...(scope !== 'main' && !inheritOff ? ppOf('main').map((n) => ({ n, inherited: true })) : []), ...ppOf(scope).map((n) => ({ n, inherited: false }))];
    for (const { n, inherited } of ppList) {
      const isRe = n.lname === 'proxypassmatch';
      const [p, url = ''] = n.args;
      if (!p) continue;
      const pathM = { field: 'Path', op: isRe ? 'matches' : 'begins with', values: [p], negated: false };
      const label = `${n.name} ${n.args.map((a) => maskUrl(a)).join(' ')}`;
      if (url === '!') { routes.push(mk({ terminal: true, matchers: [pathM], paths: [p], condition: label, rawCondition: label, line: n.line, file: n.file, directive: n.name, inherited, exclusion: true, transforms: [...pending, { action: 'return', args: ['local'], line: n.line, text: `${n.name} ${p} ! — served by httpd itself` }] })); continue; }
      const t = targetOf(url, n); if (!t) continue;
      routes.push(mk({ target: t.name, dynamic: Boolean(t.dynamic), external: t.kind === 'external', undefinedBalancer: t.undefinedBalancer || undefined, passUrl: maskUrl(url), matchers: [pathM], paths: [p], condition: label, rawCondition: label, line: n.line, file: n.file, directive: n.name, inherited, params: kvParams(n.args.slice(2)),
        transforms: [...pending, ...prefixTransforms(p, url, n, isRe)] }));
    }
    // 4. mod_alias Redirect / RedirectMatch (vhost entries first, then main server ones), then those inside <Location>
    const redirOf = (sc) => {
      const out = [];
      const visit = (nodes) => { for (const n of flat(nodes)) { if (/^redirect(match|permanent|temp)?$/.test(n.lname)) out.push(n); else if (n.section && n.lname !== 'virtualhost' && !DIR_SECTIONS.has(n.lname)) visit(n.children); } };
      visit(sc === 'main' ? ast : sc.children); return out;
    };
    const redirs = [...redirOf(scope), ...(scope !== 'main' ? redirOf('main') : [])];
    const redirRoute = (n, locPath, locRe) => {
      let a = [...n.args]; let code = n.lname === 'redirectpermanent' ? '301' : '302';
      if (n.lname === 'redirect' || n.lname === 'redirectmatch') {
        if (/^(permanent|temp|seeother|gone|\d{3})$/i.test(a[0] || '')) { const s = a.shift().toLowerCase(); code = { permanent: '301', temp: '302', seeother: '303', gone: '410' }[s] || s; }
      }
      let p; let to;
      if (locPath != null && (a.length === 1 || (!/^3\d\d$/.test(code) && a.length === 0))) { p = locPath; to = a[0]; } else { p = a[0]; to = a[1]; }
      if (!p) return;
      const isRe = n.lname === 'redirectmatch' || (locRe && locPath === p);
      const pathM = { field: 'Path', op: isRe ? 'matches' : 'begins with', values: [p], negated: false };
      const label = `${n.name} ${n.args.join(' ')}`;
      routes.push(mk({ terminal: true, matchers: [pathM], paths: [p], condition: label, rawCondition: label, line: n.line, file: n.file, directive: n.name,
        transforms: [...pending, !/^3\d\d$/.test(code) ? { action: 'return', args: [code], line: n.line, text: `${n.name} → ${code}` } : { action: 'redirect', args: [code, to || ''], line: n.line, text: `Redirect ${code} ${to || ''}`.trim() }] }));
    };
    redirs.forEach((n) => redirRoute(n));
    for (const { n, rw } of locs) for (const r of rw) redirRoute(r, n.args[0] === '~' ? n.args[1] : n.args[0], n.lname === 'locationmatch' || n.args[0] === '~');
    routes.forEach((r, i) => { r.priority = i + 1; if (!r.paths.length) r.paths = r.matchers.filter((m) => m.field === 'Path').flatMap((m) => m.values); });
    return { routes, locations: locInfo };
  }

  // ---------------- frontends
  const flatDirs = (sc) => { const out = []; walk(sc.children, (n, within) => out.push({ n, within })); return dlist(out); };
  const sslOf = (nodes) => { let v = null; for (const n of flat(nodes)) if (n.lname === 'sslengine') v = /^on$/i.test(n.args[0] || '') ? true : /^optional$/i.test(n.args[0] || '') ? 'optional' : false; return v; };
  const mainSsl = sslOf(ast);
  const valueOf = (nodes, lname) => { let v = null; for (const n of flat(nodes)) if (n.lname === lname) v = n; return v; };
  const timeoutsOf = (nodes, inherit = {}) => {
    const t = { ...inherit };
    const pt = valueOf(nodes, 'proxytimeout'); if (pt) t.server = Number(pt.args[0]);
    const to = valueOf(nodes, 'timeout'); if (to) t.client = Number(to.args[0]);
    return t;
  };
  const mainTimeouts = timeoutsOf(ast);
  const names = new Map();
  const uniq = (n) => { let x = n; if (names.has(x)) x = `${n}#${names.get(n) + 1}`; names.set(n, (names.get(n) || 0) + 1); return x; };
  const sn = (v) => String(v || '').replace(/^[a-z]+:\/\//i, '').replace(/:\d+$/, '').toLowerCase();
  const mainServerName = valueOf(ast, 'servername');

  const covered = new Set();
  for (const vh of vhosts) {
    const addrs = vh.args.map((a) => parseVhostAddr(a, listenPorts));
    addrs.forEach((a) => a.ports.forEach((p) => covered.add(p === '*' ? '*' : p)));
    const nm = flat(vh.children).filter((n) => n.lname === 'servername').pop();
    const aliases = flat(vh.children).filter((n) => n.lname === 'serveralias').flatMap((n) => n.args.map((a) => a.toLowerCase()));
    const serverNames = [...new Set([...(nm ? [sn(nm.args[0])] : []), ...aliases])].filter(Boolean);
    const vssl = sslOf(vh.children); const ssl = vssl === null ? mainSsl === true : vssl === true;
    const ports = [...new Set(addrs.flatMap((a) => a.ports))];
    const name = uniq(`${serverNames[0] || '_default_'}:${ports.join('+') || '*'}`);
    const binds = addrs.flatMap((a) => (a.port ? [a] : (a.ports.length ? a.ports.map((p) => ({ ...a, port: p, address: `${a.host}:${p}` })) : [a]))).map((a) => ({ address: a.address, addresses: [a.address], host: a.host, port: a.port || '', ssl, options: {}, line: vh.line, file: vh.file, commented: false }));
    const { routes, locations } = routesFor(vh, serverNames);
    sections.push({
      type: 'frontend', name, line: vh.line, endLine: vh.endLine, file: vh.file, mode: 'http', balance: null, binds, serverNames, routes, locations, acls: [], servers: [], users: [],
      timeouts: timeoutsOf(vh.children, mainTimeouts), effective: { mode: 'http', timeouts: timeoutsOf(vh.children, mainTimeouts), defaultServer: {} }, directives: flatDirs(vh), ssl, vhostArgs: vh.args,
      documentRoot: (valueOf(vh.children, 'documentroot') || { args: [] }).args[0] || null,
    });
  }
  const uncovered = !covered.has('*') && listenPorts.some((p) => !covered.has(p));
  const mainRoutes = routesFor('main', mainServerName ? [sn(mainServerName.args[0])] : []);
  if (!vhosts.length || (uncovered && (mainRoutes.routes.length || valueOf(ast, 'documentroot')))) {
    const ports = vhosts.length ? listenPorts.filter((p) => !covered.has(p)) : listenPorts;
    const serverNames = mainServerName ? [sn(mainServerName.args[0])] : [];
    sections.push({
      type: 'frontend', name: uniq(`${serverNames[0] || 'main'}:${ports.join('+') || '80'}`), line: (top.find((n) => n.lname === 'listen') || { line: 1 }).line, endLine: 1, file: ast[0] ? ast[0].file : '', mode: 'http', balance: null, main: true,
      binds: listens.filter((l) => ports.includes(l.port)).map((l) => ({ address: l.address, addresses: [l.address], host: l.host, port: l.port, ssl: l.proto === 'https' || mainSsl === true, options: l.proto ? { [l.proto]: true } : {}, line: l.line, file: l.file, commented: false })),
      serverNames, routes: mainRoutes.routes, locations: mainRoutes.locations, acls: [], servers: [], users: [], timeouts: mainTimeouts, effective: { mode: 'http', timeouts: mainTimeouts, defaultServer: {} },
      directives: dlist(mainDirs), ssl: mainSsl === true, documentRoot: (valueOf(ast, 'documentroot') || { args: [] }).args[0] || null,
    });
  }
  for (const fe of sections.filter((s) => s.type === 'frontend')) for (const r of fe.routes) if (r.target && backends.has(r.target)) backends.get(r.target).routes.push({ from: fe.name, line: r.line });
  for (const be of backends.values()) { be.timeouts = { ...mainTimeouts, ...be.timeouts }; be.effective.timeouts = be.timeouts; be.scope = be.scope === 'main' ? 'main' : (be.scope.args || []).join(' '); }
  sections.push(...backends.values(), ...implicit.values());
  return sections;
}

// ------------------------------------------------------------------------------------------------ redaction
const SECRET_NAME = /(authorization|token|secret|passw|pwd|api[-_]?key|apikey|credential|private[-_]?key|cookie|session[-_]?key|hmac)/i;
function redactLine(line) {
  if (/^\s*#/.test(line)) return line.replace(/(:\/\/[^:/\s@]+:)([^@\s]+)(@)/g, '$1***$3');
  let m = /^(\s*(?:AuthLDAPBindPassword|ProxyHCExpr\s+\S+\s+|SSLProxyMachineCertificatePassword|MDExternalAccountBinding\s+\S+)\s+)(.+)$/i.exec(line);
  if (m && /^\s*AuthLDAPBindPassword/i.test(line)) return `${m[1]}"***"`;
  if (m && /^\s*MDExternalAccountBinding/i.test(line) && !/^none$/i.test(m[2].trim())) return `${m[1]}"***"`;
  m = /^(\s*(?:Request)?Header\s+(?:always\s+|onsuccess\s+)?(?:set|append|add|setifempty|merge)\s+("?)([^\s"]+)\2\s+)("(?:[^"\\]|\\.)*"|'[^']*'|\S+)(.*)$/i.exec(line);
  if (m && SECRET_NAME.test(m[3]) && !/%\{|^"?\$/.test(m[4])) return `${m[1]}"***"${m[5]}`;
  m = /^(\s*(?:SetEnv|Define|PassEnv|SetEnvIf\S*\s+\S+\s+\S+)\s+("?)([^\s"=]+)\2\s+)("(?:[^"\\]|\\.)*"|'[^']*'|\S+)(.*)$/i.exec(line);
  if (m && SECRET_NAME.test(m[3])) return `${m[1]}"***"${m[5]}`;
  m = /^(\s*SetEnvIf\S*\s+.*?\s)([A-Za-z_]*(?:TOKEN|SECRET|PASSW|API_?KEY)[A-Za-z_]*=)(\S+)(.*)$/i.exec(line);
  if (m) return `${m[1]}${m[2]}***${m[4]}`;
  if (/^\s*DBDParams\b/i.test(line)) return line.replace(/(\bpass(?:word)?=)([^\s,"']+)/gi, '$1***');
  return line.replace(/(:\/\/[^:/\s@]+:)([^@\s]+)(@)/g, '$1***$3');
}
const redact = (raw) => (typeof raw === 'string' ? raw.split(/\r?\n/).map(redactLine).join('\n') : '');

// ------------------------------------------------------------------------------------------------ public
function normFiles(input) {
  const list = (input || []).filter((f) => f && typeof f.name === 'string' && typeof f.content === 'string').slice(0, MAX_FILES);
  if (!list.length) throw new Error('No files provided');
  const norm = list.map((f) => ({ name: f.name.replace(/\\/g, '/').replace(/^\/+/, '').replace(/^(\.\/)+/, ''), content: f.content.slice(0, MAX_FILE_BYTES) }));
  const tops = new Set(norm.map((f) => f.name.split('/')[0]));
  if (norm.length > 1 && norm.every((f) => f.name.includes('/')) && tops.size === 1) norm.forEach((f) => { f.name = f.name.split('/').slice(1).join('/'); });
  return norm;
}
const looksMain = (c) => /^\s*(LoadModule|ServerRoot|Listen|ServerTokens|User|Group|IncludeOptional\s+mods-enabled)\b/im.test(c);
function pickMain(norm) {
  const included = new Set();
  norm.forEach((f) => { for (const m of f.content.matchAll(/^\s*Include(?:Optional)?\s+"?([^"\s]+)/gim)) included.add(path.posix.basename(m[1])); });
  return norm.find((f) => /(^|\/)(httpd|apache2|apache)\.conf$/.test(f.name))
    || norm.find((f) => looksMain(f.content) && !included.has(path.posix.basename(f.name)))
    || norm.find((f) => looksMain(f.content)) || norm[0];
}

/** AST of an uploaded file set; includes resolve between the files only. */
function astFromFiles(input) {
  const norm = normFiles(input);
  const vfs = new Map(norm.map((f) => [`/${path.posix.normalize(f.name)}`, f.content]));
  const main = pickMain(norm);
  const loader = new Loader(`/${path.posix.normalize(main.name)}`, '/', vfs);
  const r = loader.load();
  // A set of fragments (conf.d / sites-available files) whose main file includes nothing: read every file, in name
  // order, as httpd would after `IncludeOptional conf.d/*.conf`.
  const includes = /^\s*Include(Optional)?\s/im.test(main.content);
  if (!includes && norm.length > 1) {
    const done = new Set(r.files.map((f) => f.abs));
    const rest = norm.filter((f) => !done.has(`/${path.posix.normalize(f.name)}`) && !/(^|\/)envvars$/.test(f.name) && /\.(conf|load|htaccess)$|(^|\/)\.htaccess$/.test(f.name)).sort((a, b) => a.name.localeCompare(b.name));
    for (const f of rest) r.ast.push(...loader.parseFile(`/${path.posix.normalize(f.name)}`, 1, []));
    if (rest.length) r.notes.push({ file: main.name, msg: `${rest.length + 1} configuration fragments without a main file including them; analysed together in name order (as IncludeOptional conf.d/*.conf would read them)`, kind: 'fragments' });
    r.files = [...loader.files.values()];
  }
  return { ...r, main, norm };
}

function finish(r, extraFiles = []) {
  const red = (raw) => redact(raw);
  // the model is built from the redacted text, so no secret reaches sections / routes / directives
  const sections = buildModel(r.redactedAst || r.ast, { defines: r.defines, layout: r.layout });
  return { sections, notes: r.notes, files: [...r.files.map((f) => ({ name: f.name, raw: red(f.raw), mtimeMs: f.mtimeMs || 0, ...(r.fromDisk ? { abs: f.abs } : {}) })), ...extraFiles] };
}

function parseFiles(input) {
  const norm = normFiles(input);
  const redacted = norm.map((f) => ({ name: f.name, content: redact(f.content) }));
  const r = astFromFiles(redacted);
  const loaded = new Set(r.files.map((f) => f.name));
  const extra = norm.filter((f) => !loaded.has(path.posix.normalize(f.name))).map((f) => ({ name: f.name, raw: redact(f.content), mtimeMs: 0, unused: true }));
  if (!flat(r.ast).some((n) => n.lname === 'virtualhost') && !flat(r.ast).some((n) => /^(listen|loadmodule|serverroot)$/.test(n.lname))) r.notes.push({ file: r.main.name, msg: 'No <VirtualHost> and no Listen / LoadModule found — analysed as a fragment of the main server config.' });
  const out = finish(r, extra);
  out.mainFile = r.main.name;
  return out;
}

function loadPath(mainPath, rootDir) {
  const loader = new Loader(mainPath, rootDir);
  // read and redact on the fly: parse a redacted virtual copy of each file
  const origRead = loader.readFile.bind(loader);
  loader.readFile = (abs) => redact(origRead(abs));
  const r = loader.load();
  r.files = r.files.map((f) => ({ ...f }));
  r.fromDisk = true; // keep absolute paths so the poller can notice edits (mtime) — never sent to the browser by parseFiles
  const out = finish(r);
  out.mainFile = loader.rel(loader.mainPath);
  return out;
}

module.exports = { detectLayout, parseEnvvars, LAYOUT, DEBIAN_ENV, STATIC_MODULES, lex, splitArgs, Loader, astFromFiles, normFiles, pickMain, buildModel, parseFiles, loadPath, redact, redactLine, flat, walk, sectionLabel, parseUrl, kvParams, statusFlags, defaultPort, maskUrl, rewriteFlags, DOCS, COND_SECTIONS, CONFIG_CONDS, DIR_SECTIONS };

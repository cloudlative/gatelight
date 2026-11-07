'use strict';
/**
 * NGINX configuration parser.
 *
 * 1. tokenise + parse into a directive tree (with `include` expansion, sandboxed to the config root)
 * 2. build the same topology model used for HAProxy:
 *      server block  -> section type "frontend"  (routes = locations that proxy somewhere)
 *      upstream      -> section type "backend"   (servers = upstream members)
 *    so the UI, audit plumbing, stats correlation and topology are shared.
 */
const fs = require('fs');
const path = require('path');

const MAX_FILES = 500;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_DEPTH = 10;
const PASS_DIRECTIVES = ['proxy_pass', 'fastcgi_pass', 'uwsgi_pass', 'scgi_pass', 'grpc_pass'];

// ---------------------------------------------------------------- tokenizer
function tokenize(text) {
  const toks = [];
  let i = 0; let line = 1;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '\n') { line++; i++; continue; }
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '#') { while (i < n && text[i] !== '\n') i++; continue; }
    if (ch === '{' || ch === '}' || ch === ';') { toks.push({ t: ch, line }); i++; continue; }
    if (ch === '"' || ch === "'") {
      const q = ch; let s = ''; const startLine = line; i++;
      while (i < n && text[i] !== q) {
        if (text[i] === '\\' && i + 1 < n) { s += text[i] === '\\' && text[i + 1] === q ? q : `\\${text[i + 1]}`; i += 2; continue; }
        if (text[i] === '\n') line++;
        s += text[i++];
      }
      i++;
      toks.push({ t: 'w', v: s, line: startLine, quoted: true });
      continue;
    }
    let s = ''; const startLine = line;
    while (i < n && !/[\s;{}]/.test(text[i]) ) {
      if (text[i] === '$' && text[i + 1] === '{') { while (i < n && text[i] !== '}') s += text[i++]; s += text[i++] || ''; continue; }
      s += text[i++];
    }
    if (s === '' ) { i++; continue; }
    toks.push({ t: 'w', v: s, line: startLine });
  }
  return toks;
}

// ------------------------------------------------------------------- parser
// Standard files shipped with nginx packages that people rarely upload with their config.
const QUIET_MISSING = new Set(['mime.types', 'fastcgi_params', 'fastcgi.conf', 'scgi_params', 'uwsgi_params', 'proxy_params']);

class Loader {
  /** @param vfs optional Map(posix path -> content): analyse an uploaded file set instead of the disk. */
  constructor(mainPath, rootDir, vfs) {
    this.vfs = vfs || null;
    this.mainPath = vfs ? path.posix.normalize(mainPath) : path.resolve(mainPath);
    this.root = vfs ? '/' : path.resolve(rootDir || path.dirname(mainPath));
    this.files = new Map();       // abs path -> {name, raw, mtimeMs}
    this.notes = [];              // include problems surfaced as info findings
  }

  rel(abs) { return this.vfs ? abs.replace(/^\//, '') : (path.relative(this.root, abs) || path.basename(abs)); }

  _exists(p) { return this.vfs ? this.vfs.has(p) : fs.existsSync(p); }

  _list(dir) {
    if (!this.vfs) return fs.readdirSync(dir);
    const prefix = dir === '/' ? '/' : `${dir}/`;
    return [...this.vfs.keys()].filter((k) => k.startsWith(prefix) && !k.slice(prefix.length).includes('/')).map((k) => k.slice(prefix.length));
  }

  inside(abs) { if (this.vfs) return true; const r = path.relative(this.root, abs); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); }

  /** Expand an include pattern to existing files inside the sandbox root. */
  resolveInclude(pattern, fromFile) {
    const P = this.vfs ? path.posix : path;
    let p = pattern;
    if (!P.isAbsolute(p)) p = P.join(this.root, p);
    else if (this.vfs) { if (!this.vfs.has(P.normalize(p))) p = P.join('/', p.replace(/^\/etc\/nginx\//, '')); }
    else if (!this.inside(p)) {
      // Config written for /etc/nginx but mounted elsewhere: rebase well-known prefixes.
      const m = p.match(/^\/etc\/nginx\/(.*)$/);
      if (m) p = path.join(this.root, m[1]);
    }
    p = P.normalize(p);
    if (!this.inside(p)) { this.notes.push({ file: this.rel(fromFile), msg: `include "${pattern}" is outside the config root (${this.root}) and was skipped` }); return []; }
    const dir = P.dirname(p); const base = P.basename(p);
    if (dir.includes('*') || dir.includes('?')) { this.notes.push({ file: this.rel(fromFile), msg: `include "${pattern}": wildcards in directory names are not supported` }); return []; }
    if (!/[*?]/.test(base)) {
      if (this._exists(p)) return [p];
      if (!QUIET_MISSING.has(base)) this.notes.push({ file: this.rel(fromFile), msg: `include "${pattern}" not found${this.vfs ? ' in the uploaded files' : ''}` });
      return [];
    }
    const re = new RegExp(`^${base.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
    let found = [];
    try { found = this._list(dir).filter((f) => re.test(f)).sort().map((f) => P.join(dir, f)); } catch { /* dir missing */ }
    if (!found.length) this.notes.push({ file: this.rel(fromFile), msg: `include "${pattern}" matched no files${this.vfs ? ' in the uploaded set — upload the conf.d / sites-enabled folder too' : ''}` });
    return found;
  }

  readFile(abs) {
    if (this.files.size >= MAX_FILES) throw new Error(`more than ${MAX_FILES} included files`);
    if (this.vfs) {
      const raw = this.vfs.get(abs);
      if (raw === undefined) throw new Error(`${abs} not found`);
      this.files.set(abs, { name: this.rel(abs), raw, mtimeMs: 0, abs });
      return raw;
    }
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) throw new Error(`${abs} is not a regular file or exceeds ${MAX_FILE_BYTES} bytes`);
    const raw = fs.readFileSync(abs, 'utf8');
    this.files.set(abs, { name: this.rel(abs), raw, mtimeMs: st.mtimeMs, abs });
    return raw;
  }

  parseFile(abs, depth, stack) {
    if (depth > MAX_DEPTH || stack.includes(abs)) { this.notes.push({ file: this.rel(abs), msg: 'include loop / depth limit reached' }); return []; }
    let raw;
    try { raw = this.readFile(abs); } catch (e) { this.notes.push({ file: this.rel(abs), msg: e.message }); return []; }
    return this.parseTokens(tokenize(raw), abs, depth, [...stack, abs]);
  }

  parseTokens(toks, file, depth, stack) {
    const rootNodes = []; const blocks = [rootNodes]; let cur = [];
    const name = this.rel(file);
    const push = (node) => blocks[blocks.length - 1].push(node);
    for (const tk of toks) {
      if (tk.t === 'w') { cur.push(tk); continue; }
      if (tk.t === ';' || tk.t === '{') {
        if (cur.length) {
          const node = { name: cur[0].v, args: cur.slice(1).map((x) => x.v), line: cur[0].line, file: name, children: tk.t === '{' ? [] : null };
          if (tk.t === ';' && node.name === 'include' && node.args[0]) {
            for (const f of this.resolveInclude(node.args[0], file)) for (const child of this.parseFile(f, depth + 1, stack)) push(child);
          } else {
            push(node);
            if (tk.t === '{') blocks.push(node.children);
          }
        } else if (tk.t === '{') blocks.push([]); // anonymous block; tolerate
        cur = [];
      } else if (tk.t === '}') {
        cur = [];
        if (blocks.length > 1) blocks.pop();
      }
    }
    return rootNodes;
  }

  load() {
    const ast = this.parseFile(this.mainPath, 0, []);
    return { ast, files: [...this.files.values()], notes: this.notes };
  }
}

// -------------------------------------------------------------------- model
const kids = (node, name) => (node.children || []).filter((c) => c.name === name);
const first = (node, name) => kids(node, name)[0];

function parseListen(args) {
  const addr = args[0] || '';
  const flags = args.slice(1);
  let host = ''; let port = '';
  if (addr.startsWith('unix:')) { host = addr; } else {
    const m = addr.match(/^(\[[^\]]+\]|[^:]+)?:?(\d+)?$/);
    if (/^\d+$/.test(addr)) port = addr; else if (m) { host = m[1] || ''; port = m[2] || ''; }
  }
  return { def: args.join(' '), address: addr, host, port: port || '80', ssl: flags.includes('ssl'), flags, addresses: [addr] };
}

function splitUpstreamServer(node) {
  const [address, ...params] = node.args;
  const opts = {};
  for (const p of params) { const [k, v] = p.split('='); opts[k] = v === undefined ? true : v; }
  return {
    name: address, address, options: params.join(' '), opts, check: true, // health = passive/probe; treat as checkable
    backup: Boolean(opts.backup), disabled: Boolean(opts.down), weight: opts.weight ? Number(opts.weight) : null,
    commented: false, line: node.line, file: node.file,
  };
}

/** Resolve a *_pass argument to a target description. */
function resolvePass(directive, arg, upstreamNames, isStream) {
  let a = arg;
  if (!a) return null;
  let scheme = '';
  const m = a.match(/^([a-z]+):\/\/(.*)$/i);
  if (m && !a.startsWith('unix:')) { scheme = m[1]; a = m[2]; }
  if (a.startsWith('unix:')) return { kind: 'external', address: a.replace(/^unix:/, 'unix:').split('/').slice(0, 99).join('/'), dynamic: false, scheme: 'unix' };
  const hostPort = a.split('/')[0];
  if (/\$/.test(hostPort)) return { kind: 'dynamic', address: hostPort, dynamic: true, scheme };
  const bare = hostPort.replace(/:\d+$/, '');
  if (upstreamNames.has(hostPort) || upstreamNames.has(bare)) return { kind: 'upstream', name: upstreamNames.has(hostPort) ? hostPort : bare, dynamic: false, scheme };
  const port = /:\d+$/.test(hostPort) ? '' : (directive === 'fastcgi_pass' ? ':9000' : scheme === 'https' || scheme === 'grpcs' ? ':443' : isStream ? '' : ':80');
  return { kind: 'external', address: `${hostPort}${port}`, dynamic: false, scheme, maybeUpstream: !/[.:]/.test(hostPort) && !/^localhost$/i.test(hostPort) };
}


const MOD_TEXT = { '': 'begins with', '^~': 'begins with', '=': 'is exactly', '~': 'matches regex', '~*': 'matches regex (case-insensitive)' };
const MOD_SHORT = { '': (p) => `${p}*`, '^~': (p) => `${p}*`, '=': (p) => `= ${p}`, '~': (p) => `~ ${p}`, '~*': (p) => `~* ${p}` };

/** URL/URI mapping facts for one *_pass: what is matched, where it goes, and how the path is rewritten. */
function urlMapping(d, meta, sec) {
  const raw = d.args[0] || '';
  const url = raw.replace(/\/\/[^/@\s]+@/, '//***@'); // never expose credentials embedded in a proxy_pass URL
  const m = url.match(/^[a-z]+:\/\/[^/]+(\/.*)?$/i);
  const passUri = d.name === 'proxy_pass' && m && m[1] ? m[1] : null; // a URI part replaces the matched location prefix
  const out = { passUrl: url, passUri, rewrites: meta.rewrites || [], hosts: sec.serverNames || [] };
  if (meta.path !== undefined && meta.path !== null) {
    const mod = meta.modifier || '';
    out.matchModifier = mod; out.paths = [meta.path];
    out.match = `Path ${MOD_TEXT[mod]} ${meta.path}`;
    out.short = MOD_SHORT[mod](meta.path);
    if (passUri != null && !/^[~]/.test(mod)) out.rewriteNote = `Prefix ${meta.path} is replaced by ${passUri}`;
    else if (passUri != null) out.rewriteNote = `Request URI is replaced by ${passUri}`;
  }
  return out;
}

function walkDirectives(node, fn, within = []) {
  for (const c of node.children || []) {
    fn(c, within);
    if (c.children) walkDirectives(c, fn, [...within, c]);
  }
}

function buildModel(ast) {
  const sections = [];
  const upstreamNames = new Set();
  const upstreams = [];
  const servers = [];

  // Protocol context: `server`/`upstream` live inside http{} (stream=false) or stream{} (stream=true).
  const walkProto = (nodes, stream) => {
    for (const n of nodes) {
      if (n.name === 'upstream' && n.children) { upstreams.push({ node: n, stream }); upstreamNames.add(n.args[0]); }
      else if (n.name === 'server' && n.children) servers.push({ node: n, stream });
      else if ((n.name === 'http' || n.name === 'stream') && n.children) walkProto(n.children, n.name === 'stream');
    }
  };
  walkProto(ast, false);

  const implicit = new Map(); // external target -> backend section

  const globalNode = { children: ast };
  sections.push({
    type: 'global', name: 'global', line: 1, endLine: 1, mode: null, balance: null, cookie: null, timeouts: {}, binds: [], acls: [], routes: [], servers: [],
    users: [], effective: {}, directives: [], file: ast[0] ? ast[0].file : '', events: first(globalNode, 'events') ? true : false,
    worker: { processes: (first(globalNode, 'worker_processes') || {}).args, connections: ((first(first(globalNode, 'events') || { children: [] }, 'worker_connections')) || {}).args },
  });

  for (const { node, stream } of upstreams) {
    const name = node.args[0];
    const dirs = node.children || [];
    const balanceDir = dirs.find((d) => ['least_conn', 'ip_hash', 'random', 'hash', 'least_time'].includes(d.name));
    sections.push({
      type: 'backend', name, line: node.line, endLine: node.line, file: node.file, mode: stream ? 'tcp' : 'http',
      balance: balanceDir ? `${balanceDir.name}${balanceDir.args.length ? ` ${balanceDir.args.join(' ')}` : ''}` : 'round_robin',
      cookie: null, timeouts: {}, binds: [], acls: [], routes: [], users: [],
      servers: dirs.filter((d) => d.name === 'server' && d.args.length).map(splitUpstreamServer),
      zone: (dirs.find((d) => d.name === 'zone') || {}).args ? dirs.find((d) => d.name === 'zone').args[0] : null,
      keepalive: Boolean(dirs.find((d) => d.name === 'keepalive')), hasResolve: dirs.some((d) => d.name === 'server' && d.args.includes('resolve')),
      directives: dirs.filter((d) => !d.children).map((d) => ({ keyword: d.name, args: d.args, line: d.line, raw: [d.name, ...d.args].join(' ') })),
      effective: { mode: stream ? 'tcp' : 'http', timeouts: {}, defaultServer: {} },
    });
  }

  const feNames = new Map();
  for (const { node, stream } of servers) {
    const listens = kids(node, 'listen').map((l) => parseListen(l.args));
    const names = kids(node, 'server_name').flatMap((d) => d.args);
    const ports = [...new Set(listens.map((l) => l.port))];
    let name = `${names[0] || '_'}:${ports.join('+') || (stream ? '?' : '80')}`;
    if (feNames.has(name)) name = `${name}#${node.line}`;
    feNames.set(name, true);

    const sec = {
      type: 'frontend', name, line: node.line, endLine: node.line, file: node.file, mode: stream ? 'tcp' : 'http', balance: null, cookie: null, timeouts: {},
      binds: listens.map((l) => ({ ...l, ssl: l.flags.includes('ssl'), commented: false, line: node.line, file: node.file, options: Object.fromEntries(l.flags.map((f) => [f, true])) })),
      acls: [], routes: [], servers: [], users: [], serverNames: names, locations: [], zone: (first(node, 'status_zone') || {}).args ? first(node, 'status_zone').args[0] : null,
      directives: [], effective: { mode: stream ? 'tcp' : 'http', timeouts: {}, defaultServer: {} }, isStream: stream,
    };
    // plain directive list for audit (all depths, flat)
    const flat = [];
    walkDirectives(node, (d, within) => { if (!d.children) flat.push({ keyword: d.name, args: d.args, line: d.line, file: d.file, raw: [d.name, ...d.args].join(' '), within: within.map((w) => `${w.name} ${w.args.join(' ')}`.trim()) }); });
    sec.directives = flat;

    const addRoute = (d, conditionLabel, type, loc, meta = {}) => {
      const target = resolvePass(d.name, d.args[0], upstreamNames, stream);
      if (!target) return;
      let targetName;
      if (target.kind === 'upstream') targetName = target.name;
      else if (target.kind === 'dynamic') targetName = target.address;
      else {
        targetName = `${target.address}`;
        if (!implicit.has(targetName)) {
          const be = {
            type: 'backend', name: targetName, line: d.line, endLine: d.line, file: d.file, mode: stream ? 'tcp' : 'http', balance: null, cookie: null, timeouts: {}, binds: [], acls: [], routes: [], users: [],
            servers: [{ name: target.address, address: target.address, options: '', opts: {}, check: true, backup: false, disabled: false, weight: null, commented: false, line: d.line, file: d.file }],
            implicit: true, directives: [], effective: { mode: stream ? 'tcp' : 'http', timeouts: {}, defaultServer: {} },
          };
          implicit.set(targetName, be);
        }
      }
      sec.routes.push({
        target: targetName, dynamic: target.kind === 'dynamic', condition: conditionLabel, rawCondition: conditionLabel, aclRefs: [], type, commented: false,
        line: d.line, file: d.file, passDirective: d.name, maybeUpstream: Boolean(target.maybeUpstream), external: target.kind === 'external',
        ...urlMapping(d, meta, sec),
      });
      if (loc) loc.target = targetName;
    };

    // server-level pass (stream servers, or `if` blocks at server level)
    if (stream) {
      const d = PASS_DIRECTIVES.map((p) => first(node, p)).find(Boolean) || first(node, 'proxy_pass');
      if (d) addRoute(d, 'DEFAULT', 'default');
    } else {
      for (const d of node.children) if (PASS_DIRECTIVES.includes(d.name)) addRoute(d, 'DEFAULT', 'default');
    }

    const visitLocation = (loc, parentPath) => {
      const mod = ['=', '~', '~*', '^~'].includes(loc.args[0]) ? loc.args[0] : '';
      const p = mod ? loc.args[1] : loc.args[0];
      const label = `${mod ? `${mod} ` : ''}${p || ''}`.trim();
      const info = { path: p, modifier: mod, line: loc.line, file: loc.file, kind: 'other', target: null, parent: parentPath };
      const dirs = loc.children || [];
      const passes = [];
      walkDirectives(loc, (d) => { if (PASS_DIRECTIVES.includes(d.name)) passes.push(d); });
      if (passes.length) {
        info.kind = passes[0].name === 'proxy_pass' ? 'proxy' : passes[0].name.replace('_pass', '');
        const rewrites = [];
        walkDirectives(loc, (d) => { if (d.name === 'rewrite') rewrites.push(d.args.join(' ')); });
        passes.forEach((d) => addRoute(d, `location ${label}`, 'conditional', passes[0] === d ? info : null, { path: p, modifier: mod, rewrites }));
      } else if (dirs.some((d) => d.name === 'return')) { info.kind = 'return'; info.detail = dirs.find((d) => d.name === 'return').args.join(' '); }
      else if (dirs.some((d) => d.name === 'root' || d.name === 'alias' || d.name === 'try_files')) { info.kind = 'static'; info.detail = (dirs.find((d) => d.name === 'root' || d.name === 'alias') || { args: [] }).args[0]; }
      else if (dirs.some((d) => d.name === 'stub_status')) info.kind = 'stub_status';
      sec.locations.push(info);
      for (const c of dirs) if (c.name === 'location') visitLocation(c, label);
    };
    for (const l of kids(node, 'location')) visitLocation(l, null);
    for (const ifb of kids(node, 'if')) walkDirectives(ifb, (d) => { if (PASS_DIRECTIVES.includes(d.name)) addRoute(d, `if ${ifb.args.join(' ')}`, 'conditional'); });
    sections.push(sec);
  }
  sections.push(...implicit.values());
  return sections;
}

// --------------------------------------------------------------- redaction
const SECRET_NAME = /(authorization|token|secret|passw|api[-_]?key|apikey|credential)/i;
function redactLine(line) {
  const m = line.match(/^(\s*(?:set\s+\$\S+|proxy_set_header\s+\S+|add_header\s+\S+|fastcgi_param\s+\S+|auth_request_set\s+\$\S+)\s+)("[^"]*"|'[^']*'|[^;\s]+)(.*)$/);
  if (m && SECRET_NAME.test(m[1]) && !/^\$[\w]+$/.test(m[2])) return `${m[1]}"***"${m[3]}`;
  if (/^\s*(?:ssl_password_file|auth_basic_user_file)\b/.test(line)) return line; // paths only
  return line.replace(/(:\/\/[^:/\s]+:)([^@\s]+)(@)/g, '$1***$3');
}
const redactNginx = (raw) => (typeof raw === 'string' ? raw.split(/\r?\n/).map(redactLine).join('\n') : '');

// ------------------------------------------------------------------ public
function loadNginxConfig(mainPath, rootDir) {
  const loader = new Loader(mainPath, rootDir);
  const { ast, files, notes } = loader.load();
  const sections = buildModel(ast);
  return {
    sections, notes,
    files: files.map((f) => ({ name: f.name, raw: redactNginx(f.raw), mtimeMs: f.mtimeMs, abs: f.abs })),
    ast,
  };
}

/**
 * Analyse an uploaded set of files [{name, content}] (e.g. nginx.conf + conf.d/*.conf), resolving
 * include directives against the set. Returns { sections, notes, files, mainFile }.
 */
function astFromFiles(input) {
  const list = (input || []).filter((f) => f && typeof f.name === 'string' && typeof f.content === 'string').slice(0, MAX_FILES);
  if (!list.length) throw new Error('No files provided');
  const norm = list.map((f) => ({ name: f.name.replace(/\\/g, '/').replace(/^\/+/, '').replace(/^(\.\/)+/, ''), content: f.content.slice(0, MAX_FILE_BYTES) }));
  // Drop a shared top-level folder (folder uploads arrive as "nginx/conf.d/app.conf").
  const tops = new Set(norm.map((f) => f.name.split('/')[0]));
  if (norm.every((f) => f.name.includes('/')) && tops.size === 1) norm.forEach((f) => { f.name = f.name.split('/').slice(1).join('/'); });
  const vfs = new Map(norm.map((f) => [`/${path.posix.normalize(f.name)}`, f.content]));
  const looksMain = (c) => /\b(events|http|stream)\s*\{/.test(c);
  const included = new Set();
  norm.forEach((f) => { for (const m of f.content.matchAll(/^\s*include\s+([^;]+);/gm)) included.add(path.posix.basename(m[1].trim())); });
  const main = norm.find((f) => path.posix.basename(f.name) === 'nginx.conf')
    || norm.find((f) => looksMain(f.content) && !included.has(path.posix.basename(f.name)))
    || norm.find((f) => looksMain(f.content)) || norm[0];
  const loader = new Loader(`/${path.posix.normalize(main.name)}`, '/', vfs);
  const { ast, files, notes } = loader.load();
  return { ast, files, notes, main, norm };
}

function parseNginxFiles(input) {
  const { ast, files, notes, main, norm } = astFromFiles(input);
  // A file with only server{}/upstream{} (no http{} wrapper) is a conf.d fragment: parse it as if inside http.
  const sections = buildModel(ast);
  if (!ast.some((n) => n.name === 'http' || n.name === 'stream')) {
    notes.push({ file: main.name, msg: 'No http{} / stream{} block found — analysed as a fragment. Upstreams defined in other files are reported as undefined; upload the whole config folder for a complete picture.' });
  }
  const loaded = new Set(files.map((f) => f.name));
  const extra = norm.filter((f) => !loaded.has(path.posix.normalize(f.name)));
  return {
    sections, notes, mainFile: main.name,
    files: [...files.map((f) => ({ name: f.name, raw: redactNginx(f.raw), mtimeMs: 0 })), ...extra.map((f) => ({ name: `${f.name}`, raw: redactNginx(f.content), mtimeMs: 0, unused: true }))],
  };
}

/** Parse a single pasted config (no includes resolved). */
function parseNginxText(text) {
  const loader = new Loader('/nginx.conf', '/');
  const ast = loader.parseTokens(tokenize(text), '/nginx.conf', 0, []);
  return { sections: buildModel(ast), notes: [], files: [{ name: 'nginx.conf', raw: redactNginx(text), mtimeMs: 0 }], ast };
}

module.exports = { loadNginxConfig, parseNginxText, parseNginxFiles, astFromFiles, tokenize, redactNginx, parseListen };

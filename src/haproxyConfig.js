'use strict';
/**
 * HAProxy configuration parser.
 *
 * Produces a structural model (sections, binds, ACLs, routes, servers, ...) with
 * source line numbers so that audit findings can point at the exact line.
 * Commented-out routing/server directives are retained and flagged `commented`
 * so the UI can show "disabled" topology.
 */

const SECTION_KEYWORDS = [
  'global', 'defaults', 'frontend', 'backend', 'listen', 'userlist', 'peers',
  'resolvers', 'mailers', 'cache', 'program', 'http-errors', 'ring',
];
const SECTION_RE = new RegExp(`^(${SECTION_KEYWORDS.join('|')})(?:\\s+(\\S.*))?$`);

// Server keywords that consume the next token as their value.
const SERVER_VALUE_KEYS = new Set([
  'weight', 'maxconn', 'minconn', 'maxqueue', 'port', 'addr', 'inter', 'fastinter',
  'downinter', 'rise', 'fall', 'cookie', 'slowstart', 'track', 'source', 'sni',
  'ca-file', 'crt', 'verify', 'verifyhost', 'resolvers', 'init-addr', 'agent-port',
  'agent-inter', 'agent-addr', 'agent-send', 'on-marked-down', 'on-marked-up',
  'on-error', 'observe', 'error-limit', 'id', 'redir', 'proto', 'alpn', 'ssl-min-ver',
  'ssl-max-ver', 'ciphers', 'check-sni', 'pool-max-conn', 'pool-purge-delay',
  'namespace', 'sigalgs', 'curves', 'ws', 'tcp-ut', 'max-reuse', 'set-proxy-v2-tlv-fmt',
  'check-proto', 'rise', 'hash-key', 'log-bufsize',
]);

const COMMENTABLE = new Set([
  'bind', 'acl', 'use_backend', 'default_backend', 'server', 'server-template',
]);

function tokenize(line) {
  const out = [];
  let cur = '';
  let quote = null;
  let has = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\' && i + 1 < line.length) { cur += line[++i]; continue; }
      if (ch === quote) { quote = null; continue; }
      cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch; has = true;
    } else if (/\s/.test(ch)) {
      if (cur.length || has) { out.push(cur); cur = ''; has = false; }
    } else {
      cur += ch;
    }
  }
  if (cur.length || has) out.push(cur);
  return out;
}

/** Strip a trailing `# comment` (a `#` preceded by whitespace, outside quotes). */
function stripInlineComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i).trimEnd();
  }
  return line;
}

function parseServerOptions(tokens) {
  const opts = {};
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (SERVER_VALUE_KEYS.has(t) && i + 1 < tokens.length) opts[t] = tokens[++i];
    else opts[t] = true;
  }
  return opts;
}

function parseBind(tokens) {
  // bind [addr]:port[,addr:port...] [options]
  const addrs = (tokens[1] || '').split(',').filter(Boolean);
  const rest = tokens.slice(2);
  const opts = parseServerOptions(rest);
  return {
    def: tokens.slice(1).join(' '),
    addresses: addrs,
    ssl: Boolean(opts.ssl),
    crt: opts.crt || null,
    options: opts,
  };
}

function looksLikeAddress(s) {
  return typeof s === 'string' && /^[\w.\-[\]:@*/]+$/.test(s) && /[.:\d*/@]/.test(s);
}

/** Extract ACL names referenced by an `if`/`unless` condition. */
function conditionAcls(condition) {
  if (!condition) return [];
  const noAnon = condition.replace(/\{[^}]*\}/g, ' ');
  return noAnon
    .split(/\s+|\|\|/)
    .map((t) => t.replace(/^!/, ''))
    .filter((t) => t && !['if', 'unless', 'or', 'and', '||', '&&'].includes(t) && /^[\w.\-:]+$/.test(t));
}


const TERM_OPS = { is: 'is', beg: 'begins with', end: 'ends with', sub: 'contains', dir: 'has directory', dom: 'has domain', reg: 'matches', len: 'length' };
const SHORT = { is: (v) => v, beg: (v) => `${v}*`, end: (v) => `*${v}`, sub: (v) => `*${v}*`, dir: (v) => `*/${v}/*`, dom: (v) => `*.${v}`, reg: (v) => `~${v}`, len: (v) => `len ${v}` };

/** Turn one ACL expression ("path_beg /api", "hdr(host) -i a.example.com") into {field, op, values, short}. */
function describeAcl(expr) {
  const t = String(expr || '').trim().split(/\s+/).filter(Boolean);
  if (!t.length) return null;
  const crit = t[0].toLowerCase();
  const values = []; let ci = false; let mflag = null;
  for (let i = 1; i < t.length; i++) {
    if (t[i] === '-i') ci = true;
    else if (t[i] === '-m') { mflag = (t[i + 1] || '').toLowerCase(); i++; } // explicit match operator
    else if (t[i] === '-f' || t[i] === '-u' || t[i] === '-n') i++;
    else if (!/^-[a-z]$/.test(t[i])) values.push(t[i]);
  }
  const m = crit.match(/^(path|url|url_param|hdr|req\.hdr|hdr_cnt|req\.hdr_cnt|ssl_fc_sni|req\.ssl_sni|method|src|dst_port|dst|base)(?:_(beg|end|sub|dir|dom|reg|len|ip|cnt))?(?:\(([^)]*)\))?$/);
  let field = crit; let op = 'is'; let kind = 'is';
  if (m) {
    const [, base, suf, arg] = m; kind = suf && TERM_OPS[suf] ? suf : (mflag && TERM_OPS[mflag] ? mflag : 'is'); op = TERM_OPS[kind];
    if (base === 'path') field = 'Path'; else if (base === 'url') field = 'URL'; else if (base === 'base') field = 'Host+URL';
    else if (base === 'url_param') field = `Query param ${arg || ''}`.trim();
    else if (base === 'hdr' || base === 'req.hdr') field = /^host$/i.test(arg || '') ? 'Host' : `Header ${arg || ''}`.trim();
    else if (/sni/.test(base)) field = 'TLS SNI'; else if (base === 'method') field = 'Method'; else if (base === 'src') field = 'Client IP';
    else field = base;
  }
  const short = values.map((v) => (field === 'Host' || field === 'TLS SNI' || kind !== 'is' ? SHORT[kind](v) : v)).join(', ');
  return { field, op, values, caseInsensitive: ci, text: `${field} ${op} ${values.join(' or ')}`.trim(), short: field === 'Path' || field === 'URL' || field === 'Host' || field === 'TLS SNI' ? short : `${field} ${short}`.trim() };
}

/** Resolve an `if`/`unless` condition against the section's ACL definitions into human-readable URL/host matchers. */
function resolveCondition(cond, acls) {
  if (!cond) return { match: '', short: '', matchers: [], paths: [], hosts: [] };
  const byName = new Map(); for (const a of acls) if (!a.commented && !byName.has(a.name)) byName.set(a.name, a.expression);
  const neg = /^\s*unless\b/.test(cond);
  const re = /(!?)\{([^}]*)\}|(\|\||&&)|(\S+)/g; let m;
  const body = cond.replace(/^\s*(if|unless)\s+/, '');
  const parts = []; // {text, short, negated, op}
  let join = 'AND'; let first = true;
  while ((m = re.exec(body))) {
    if (m[3] || (m[4] && /^(or|and)$/i.test(m[4]))) { join = /\|\||or/i.test(m[3] || m[4]) ? 'OR' : 'AND'; continue; }
    let d; let negated = false; let name = null;
    if (m[2] !== undefined) { d = describeAcl(m[2]); negated = m[1] === '!'; } else {
      name = m[4].replace(/^!/, ''); negated = m[4].startsWith('!');
      const e = byName.get(name); d = e ? describeAcl(e) : { field: 'ACL', op: 'is', values: [name], text: `ACL ${name} (undefined)`, short: name };
    }
    if (!d) continue;
    parts.push({ ...d, acl: name, negated, join: first ? null : join }); first = false; join = 'AND';
  }
  const wrap = (p, key) => `${p.join ? ` ${p.join === 'OR' ? '|' : '+'} ` : ''}${p.negated ? '!' : ''}${p[key]}`;
  const texts = parts.map((p) => `${p.join ? ` ${p.join} ` : ''}${p.negated ? 'NOT ' : ''}${p.text}`).join('');
  return {
    match: (neg ? 'NOT (' : '') + texts + (neg ? ')' : ''),
    short: (neg ? '!' : '') + parts.map((p) => wrap(p, 'short')).join(''),
    matchers: parts.map(({ field, op, values, acl, negated, join }) => ({ field, op, values, acl, negated, join })),
    paths: parts.filter((p) => ['Path', 'URL'].includes(p.field) && !p.negated).flatMap((p) => p.values.map((v) => (p.op === 'is' ? v : `${p.op === 'begins with' ? '' : '…'}${v}${p.op === 'begins with' ? '…' : ''}`))),
    hosts: parts.filter((p) => ['Host', 'TLS SNI'].includes(p.field) && !p.negated).flatMap((p) => p.values),
  };
}

function makeSection(type, name, line) {
  return {
    type, name, line, endLine: line, mode: null, balance: null, cookie: null, timeouts: {},
    binds: [], acls: [], routes: [], servers: [], defaultServer: null, users: [], directives: [], effective: {},
  };
}

function parseConfig(raw) {
  const text = typeof raw === 'string' ? raw : '';
  const lines = text.split(/\r?\n/);
  const sections = [];
  let current = null;
  let lastDefaults = null;

  const closeSection = (lineNo) => { if (current) current.endLine = lineNo; };

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNo = idx + 1;
    const trimmed = lines[idx].trim();
    if (!trimmed) continue;

    const isComment = trimmed.startsWith('#');
    let body = isComment ? trimmed.replace(/^#+\s*/, '') : stripInlineComment(trimmed);
    if (!body) continue;

    if (!isComment) {
      const sec = body.match(SECTION_RE);
      if (sec) {
        closeSection(lineNo - 1);
        current = makeSection(sec[1], (sec[2] || sec[1]).trim(), lineNo);
        if (current.type === 'defaults') lastDefaults = current;
        else if (['frontend', 'backend', 'listen'].includes(current.type)) current.defaults = lastDefaults ? lastDefaults.name : null;
        sections.push(current);
        continue;
      }
    }

    // A commented-out section header ("#frontend old") starts a disabled block: its (also commented)
    // contents must not be attributed to the previous real section. Prose like "# backend notes" has a space.
    if (isComment) {
      const dis = trimmed.match(/^#+(frontend|backend|listen)\s+(\S+)\s*$/);
      if (dis) { closeSection(lineNo - 1); current = makeSection(dis[1], dis[2], lineNo); continue; }
    }

    if (!current) continue;
    const tokens = tokenize(body);
    if (!tokens.length) continue;
    const kw = tokens[0];

    if (isComment) {
      // Only treat the comment as disabled config if it plausibly is a directive.
      if (!COMMENTABLE.has(kw)) continue;
      if (kw === 'server' && !(tokens.length >= 3 && looksLikeAddress(tokens[2]))) continue;
      if (kw === 'server-template' && tokens.length < 4) continue;
      if (kw === 'bind' && !(tokens.length >= 2 && looksLikeAddress(tokens[1].split(',')[0]))) continue;
      if (kw === 'acl' && tokens.length < 3) continue;
      if (kw === 'use_backend' && !(tokens.length === 2 || ['if', 'unless'].includes(tokens[2]))) continue;
      if (kw === 'default_backend' && tokens.length !== 2) continue;
    }
    const commented = isComment;

    if (!commented) current.directives.push({ keyword: kw, args: tokens.slice(1), line: lineNo, raw: body });

    switch (kw) {
      case 'bind':
        current.binds.push({ ...parseBind(tokens), commented, line: lineNo });
        break;
      case 'acl':
        current.acls.push({ name: tokens[1], expression: tokens.slice(2).join(' '), commented, line: lineNo });
        break;
      case 'use_backend': {
        const cond = tokens.slice(2).join(' ');
        current.routes.push({
          target: tokens[1],
          dynamic: /%\[|%\{/.test(tokens[1]),
          condition: cond || 'direct',
          rawCondition: cond,
          aclRefs: conditionAcls(cond),
          type: 'conditional',
          commented,
          line: lineNo,
        });
        break;
      }
      case 'default_backend':
        current.routes.push({
          target: tokens[1], dynamic: /%\[|%\{/.test(tokens[1]), condition: 'DEFAULT', rawCondition: '',
          aclRefs: [], type: 'default', commented, line: lineNo,
        });
        break;
      case 'server': {
        const opts = parseServerOptions(tokens.slice(3));
        current.servers.push({
          name: tokens[1], address: tokens[2] || '', options: tokens.slice(3).join(' '), opts,
          check: Boolean(opts.check), backup: Boolean(opts.backup), disabled: Boolean(opts.disabled),
          weight: opts.weight != null ? Number(opts.weight) : null,
          commented, line: lineNo,
        });
        break;
      }
      case 'server-template':
        current.servers.push({
          name: tokens[2], address: tokens[3] || '', options: tokens.slice(4).join(' '),
          opts: parseServerOptions(tokens.slice(4)), template: tokens[1],
          check: tokens.includes('check'), backup: false, disabled: false, weight: null, commented, line: lineNo,
        });
        break;
      case 'default-server':
        current.defaultServer = parseServerOptions(tokens.slice(1));
        break;
      case 'balance': current.balance = tokens.slice(1).join(' '); break;
      case 'mode': current.mode = tokens[1]; break;
      case 'cookie': current.cookie = tokens.slice(1).join(' '); break;
      case 'timeout':
        if (tokens.length >= 3) current.timeouts[tokens[1]] = tokens[2];
        break;
      case 'user':
        if (current.type === 'userlist') {
          const pwIdx = tokens.findIndex((t) => t === 'password' || t === 'insecure-password');
          // Never keep the secret itself in the model (it is serialised to API clients).
          const pwValue = pwIdx >= 0 ? tokens[pwIdx + 1] : null;
          current.users.push({
            name: tokens[1],
            passwordKind: pwIdx >= 0 ? tokens[pwIdx] : null,
            passwordHashed: Boolean(pwValue && /^\$[0-9a-z]+\$/i.test(pwValue)),
            line: lineNo,
          });
        }
        break;
      default: break;
    }
  }
  closeSection(lines.length);

  // Resolve each routing rule's ACLs into readable URL / host matchers.
  const defAcls = sections.filter((x) => x.type === 'defaults').flatMap((x) => x.acls);
  for (const s of sections) for (const rt of s.routes) Object.assign(rt, resolveCondition(rt.rawCondition, [...s.acls, ...defAcls]));

  // Resolve effective settings via the defaults section that precedes each proxy.
  let activeDefaults = null;
  for (const s of sections) {
    if (s.type === 'defaults') { activeDefaults = s; continue; }
    if (!['frontend', 'backend', 'listen'].includes(s.type)) continue;
    const d = activeDefaults;
    s.effective = {
      mode: s.mode || (d && d.mode) || 'http',
      balance: s.balance || (d && d.balance) || null,
      timeouts: { ...(d ? d.timeouts : {}), ...s.timeouts },
      defaultServer: { ...((d && d.defaultServer) || {}), ...(s.defaultServer || {}) },
    };
    s.mode = s.effective.mode;
  }
  return sections;
}

/** Roles a section plays in the topology. `listen` is both a frontend and a backend. */
const isFrontendLike = (s) => s.type === 'frontend' || s.type === 'listen';
const isBackendLike = (s) => s.type === 'backend' || s.type === 'listen';

// --- Secret redaction ------------------------------------------------------

function redactConfig(raw) {
  if (typeof raw !== 'string') return '';
  return raw.split(/\r?\n/).map((line) => {
    let out = line;
    // stats auth user:password
    out = out.replace(/^(\s*#*\s*stats\s+auth\s+[^:\s]+:)(\S+)/i, '$1***');
    // userlist: password / insecure-password VALUE
    out = out.replace(/(\b(?:insecure-)?password\s+)(\S+)/i, '$1***');
    // Basic auth embedded in URLs
    out = out.replace(/(:\/\/[^:/\s]+:)([^@\s]+)(@)/g, '$1***$3');
    return out;
  }).join('\n');
}

module.exports = {
  parseConfig, redactConfig, tokenize, stripInlineComment, conditionAcls, describeAcl, resolveCondition,
  isFrontendLike, isBackendLike, SECTION_KEYWORDS,
};

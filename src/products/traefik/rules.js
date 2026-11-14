'use strict';
/**
 * Traefik router rules: parser, checker, DNF expansion (one AND-route per OR branch) and an evaluator.
 *
 * Grammar (both syntaxes, docs: routing/routers "Rule"):  expr := and ('||' and)* ;  and := unary ('&&' unary)* ;
 * unary := '!' unary | '(' expr ')' | Matcher '(' [value (',' value)*] ')' ;  value := `backtick` | "double quoted".
 * Single quotes are not accepted (Go string literals).
 *
 * Syntax differences (migration/v2-to-v3-details "Router Rule Matchers"):
 *   v2: Host/HostRegexp/Path/PathPrefix/Method/Query/ClientIP take a list of values (OR), Headers/HeadersRegexp take
 *       (key, value), HostHeader exists, regex values use gorilla/mux templates "{name:regex}" inside Host/Path/PathPrefix.
 *   v3: every matcher takes one value, Header/HeaderRegexp/QueryRegexp take (key, value), Query takes (key[, value]),
 *       PathRegexp/QueryRegexp are new, HostRegexp/PathRegexp use Go regexp syntax, PathPrefix is literal, no HostHeader.
 */

class RuleError extends Error { constructor(msg, pos) { super(msg); this.pos = pos; } }

// ------------------------------------------------------------------------------------------------ tokenizer / parser
function tokenize(s) {
  const out = []; let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (s.startsWith('&&', i) || s.startsWith('||', i)) { out.push({ t: s.slice(i, i + 2), pos: i }); i += 2; continue; }
    if ('()!,'.includes(c)) { out.push({ t: c, pos: i }); i++; continue; }
    if (c === '`') { const e = s.indexOf('`', i + 1); if (e < 0) throw new RuleError('unterminated `backtick` value', i); out.push({ t: 'str', v: s.slice(i + 1, e), pos: i }); i = e + 1; continue; }
    if (c === '"') {
      let j = i + 1; let v = '';
      while (j < s.length && s[j] !== '"') { if (s[j] === '\\' && j + 1 < s.length) { const n = s[j + 1]; v += n === 'n' ? '\n' : n === 't' ? '\t' : n; j += 2; continue; } v += s[j++]; }
      if (j >= s.length) throw new RuleError('unterminated "quoted" value', i);
      out.push({ t: 'str', v, pos: i, dq: true }); i = j + 1; continue;
    }
    if (c === "'") throw new RuleError("single quotes are not accepted in rules: use `backticks`", i);
    const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(s.slice(i));
    if (m) { out.push({ t: 'id', v: m[0], pos: i }); i += m[0].length; continue; }
    throw new RuleError(`unexpected character "${c}"`, i);
  }
  return out;
}

/** Parse a rule into { type: 'or'|'and'|'not'|'m', ... }. Throws RuleError. */
function parseRule(rule) {
  const src = String(rule == null ? '' : rule);
  if (!src.trim()) throw new RuleError('empty rule', 0);
  const toks = tokenize(src); let k = 0;
  const peek = () => toks[k]; const take = () => toks[k++];
  const expect = (t) => { const x = take(); if (!x || x.t !== t) throw new RuleError(`expected "${t}"${x ? ` at "${src.slice(x.pos, x.pos + 12)}"` : ' at the end of the rule'}`, x ? x.pos : src.length); return x; };
  const orE = () => { const items = [andE()]; while (peek() && peek().t === '||') { take(); items.push(andE()); } return items.length === 1 ? items[0] : { type: 'or', items }; };
  const andE = () => { const items = [unary()]; while (peek() && peek().t === '&&') { take(); items.push(unary()); } return items.length === 1 ? items[0] : { type: 'and', items }; };
  const unary = () => {
    const x = peek();
    if (!x) throw new RuleError('rule ends too early', src.length);
    if (x.t === '!') { take(); return { type: 'not', item: unary() }; }
    if (x.t === '(') { take(); const e = orE(); expect(')'); return e; }
    if (x.t === 'id') {
      take(); expect('(');
      const args = [];
      if (peek() && peek().t !== ')') {
        for (;;) {
          const a = take();
          if (!a || a.t !== 'str') throw new RuleError(`matcher ${x.v}: values must be in \`backticks\` or "double quotes"`, a ? a.pos : src.length);
          args.push(a.v);
          if (peek() && peek().t === ',') { take(); continue; }
          break;
        }
      }
      expect(')');
      return { type: 'm', name: x.v, args, pos: x.pos };
    }
    throw new RuleError(`unexpected "${x.t === 'str' ? x.v : x.t}"`, x.pos);
  };
  const e = orE();
  if (k < toks.length) throw new RuleError(`unexpected "${src.slice(toks[k].pos, toks[k].pos + 12)}" (missing && or ||?)`, toks[k].pos);
  return e;
}

/** All matcher nodes of a tree. */
function matchersOf(node, out = []) {
  if (!node) return out;
  if (node.type === 'm') out.push(node);
  else if (node.type === 'not') matchersOf(node.item, out);
  else node.items.forEach((x) => matchersOf(x, out));
  return out;
}

/** Disjunctive normal form: [[{m, neg}]] (OR of ANDs). Capped to keep pathological rules cheap. */
function toDnf(node, neg = false, cap = 64) {
  if (node.type === 'm') return [[{ m: node, neg }]];
  if (node.type === 'not') return toDnf(node.item, !neg, cap);
  const isOr = (node.type === 'or') !== neg; // De Morgan
  const parts = node.items.map((x) => toDnf(x, neg, cap));
  if (isOr) return parts.flat().slice(0, cap);
  let acc = [[]];
  for (const p of parts) { const next = []; for (const a of acc) for (const b of p) { next.push([...a, ...b]); if (next.length >= cap) break; } acc = next; }
  return acc.slice(0, cap);
}

// ------------------------------------------------------------------------------------------------ model mapping
const V2_TEMPLATE = /\{[^}]*\}/; // gorilla/mux "{name:regex}" template used by the v2 syntax
const FIELD = {
  Host: 'Host', HostHeader: 'Host', HostRegexp: 'Host', Path: 'Path', PathPrefix: 'Path', PathRegexp: 'Path', Method: 'Method',
  Header: 'Header', Headers: 'Header', HeaderRegexp: 'Header', HeadersRegexp: 'Header', Query: 'Query', QueryRegexp: 'Query',
  ClientIP: 'ClientIP', HostSNI: 'SNI', HostSNIRegexp: 'SNI', ALPN: 'ALPN',
};
/** One matcher node -> contract matcher(s) { field, op, values, negated, name? }. */
function describeMatcher(m, neg, syntax) {
  const field = FIELD[m.name] || m.name;
  const regex = /Regexp$/.test(m.name);
  const a = m.args;
  if (/^Headers?(Regexp)?$/.test(m.name) || m.name === 'HeadersRegexp' || (m.name === 'QueryRegexp')) {
    return [{ field, op: regex ? 'matches' : 'is', name: a[0], values: a.slice(1), negated: neg }];
  }
  if (m.name === 'Query') {
    if (syntax === 'v2') { // Query(`a=b`, `c=d`): any of the pairs
      const pairs = a.map((x) => { const i = x.indexOf('='); return i < 0 ? [x, ''] : [x.slice(0, i), x.slice(i + 1)]; });
      const names = [...new Set(pairs.map((p) => p[0]))];
      return names.map((n) => ({ field, op: 'is', name: n, values: pairs.filter((p) => p[0] === n).map((p) => p[1]), negated: neg }));
    }
    return [{ field, op: a.length > 1 ? 'is' : 'contains', name: a[0], values: a.length > 1 ? [a[1]] : [], negated: neg }];
  }
  let op = 'is';
  if (regex) op = 'matches';
  else if (m.name === 'PathPrefix') op = syntax === 'v2' && a.some((x) => V2_TEMPLATE.test(x)) ? 'matches' : 'begins with';
  else if ((m.name === 'Path' || m.name === 'Host' || m.name === 'HostHeader') && syntax === 'v2' && a.some((x) => V2_TEMPLATE.test(x))) op = 'matches';
  if ((m.name === 'HostSNI' || m.name === 'Host') && a.length === 1 && a[0] === '*') return []; // HostSNI(`*`) / Host(`*`): any
  const values = m.name === 'Method' ? a.map((x) => x.toUpperCase()) : a;
  return [{ field, op, values, negated: neg }];
}

const OP_TEXT = { is: 'is', 'begins with': 'begins with', matches: 'matches', contains: 'is present' };
function matcherText(x) {
  const not = x.negated ? 'not ' : '';
  if (x.field === 'Header' || x.field === 'Query') return x.op === 'contains' ? `${x.field} ${x.name} is ${not}present` : `${x.field} ${x.name} ${not}${OP_TEXT[x.op]} ${x.values.join(' or ')}`;
  return `${x.field} ${not}${OP_TEXT[x.op] || x.op} ${x.values.join(' or ')}`;
}
function matcherShort(x) {
  const v = x.values.join(',');
  const s = x.field === 'Host' || x.field === 'SNI' ? (x.op === 'is' ? v : `~${v}`)
    : x.field === 'Path' ? (x.op === 'is' ? v : x.op === 'begins with' ? `${v}*` : `~${v}`)
      : x.field === 'Header' || x.field === 'Query' ? `${x.name}${x.op === 'contains' ? '' : x.op === 'matches' ? `~${v}` : `=${v}`}` : `${x.field} ${v}`;
  return `${x.negated ? '!' : ''}${s}`;
}

/**
 * Expand a rule into AND-only branches for the route list. Each branch: { matchers, hosts, paths, match, short, condition }.
 * Returns { branches, error } (error = RuleError message when the rule cannot be parsed).
 */
function branches(rule, syntax = 'v3') {
  let tree;
  try { tree = parseRule(rule); } catch (e) { return { branches: [{ matchers: [], hosts: [], paths: [], match: `(unparsable rule: ${e.message})`, short: '?', unparsable: true }], error: e.message }; }
  const out = [];
  for (const conj of toDnf(tree)) {
    const ms = conj.flatMap(({ m, neg }) => describeMatcher(m, neg, syntax));
    const hosts = ms.filter((x) => (x.field === 'Host' || x.field === 'SNI') && !x.negated && x.op === 'is').flatMap((x) => x.values);
    const paths = ms.filter((x) => x.field === 'Path' && !x.negated).flatMap((x) => x.values.map((v) => (x.op === 'is' ? v : x.op === 'begins with' ? `${v}…` : `…${v}…`)));
    const condition = conj.map(({ m, neg }) => `${neg ? '!' : ''}${m.name}(${m.args.map((a) => `\`${a}\``).join(', ')})`).join(' && ');
    out.push({ matchers: ms, hosts, paths, condition, match: ms.length ? ms.map(matcherText).join(' and ') : 'any request', short: ms.length ? ms.map(matcherShort).join(' ') : '*' });
  }
  return { branches: out, error: null, tree };
}

// ------------------------------------------------------------------------------------------------ checks
/**
 * Check a rule against the matchers documented for a syntax/version (from the KB). Returns problems:
 * [{ severity, msg, matcher }]. `kbMatchers` = kb.matchers.http|tcp, `minorOk(entry)` tells if an entry exists in the target.
 */
function checkRule(rule, { syntax = 'v3', kbMatchers, available, proto = 'http' } = {}) {
  const out = [];
  let tree;
  try { tree = parseRule(rule); } catch (e) { return [{ severity: 'error', msg: `rule syntax error: ${e.message}` }]; }
  const table = kbMatchers ? kbMatchers[syntax] || {} : {};
  const other = kbMatchers ? kbMatchers[syntax === 'v3' ? 'v2' : 'v3'] || {} : {};
  for (const m of matchersOf(tree)) {
    const e = table[m.name];
    if (!e) {
      const ci = Object.keys(table).find((n) => n.toLowerCase() === m.name.toLowerCase());
      if (ci) out.push({ severity: 'error', matcher: m.name, msg: `matcher names are case-sensitive: write ${ci}(...)` });
      else if (other[m.name]) out.push({ severity: 'error', matcher: m.name, code: 'other-syntax', msg: `${m.name}() is a ${syntax === 'v3' ? 'v2' : 'v3'}-syntax matcher; with ruleSyntax ${syntax} use ${renameFor(m.name, syntax) || 'the documented equivalent'}` });
      else out.push({ severity: 'error', matcher: m.name, msg: `unknown ${proto.toUpperCase()} matcher ${m.name}()${proto === 'http' && /^(HostSNI|HostSNIRegexp|ALPN)$/.test(m.name) ? ' (it is a TCP router matcher)' : ''}` });
      continue;
    }
    if (available && !available(e)) { out.push({ severity: 'error', matcher: m.name, code: 'version', msg: `${m.name}() is not available in this version (since ${e.s}${e.u ? `, removed in ${e.u}` : ''})`, since: e.s, until: e.u }); continue; }
    if (m.args.length < e.min) out.push({ severity: 'error', matcher: m.name, msg: `${m.name}() needs ${e.min === e.max ? e.min : `at least ${e.min}`} value${e.min > 1 ? 's' : ''}, got ${m.args.length}` });
    else if (e.max != null && m.args.length > e.max) out.push({ severity: 'error', matcher: m.name, code: 'arity', msg: `${m.name}() takes ${e.max === 1 ? 'a single value' : `${e.max} values`} with ruleSyntax ${syntax}; combine matchers with || instead (e.g. ${m.name}(\`${m.args[0]}\`) || ${m.name}(\`${m.args[1]}\`))` });
    if (syntax === 'v3' && /^(HostRegexp|PathRegexp|HeaderRegexp|QueryRegexp|HostSNIRegexp)$/.test(m.name)) {
      const re = m.args[m.args.length - 1] || '';
      if (/\{[A-Za-z_]\w*(:[^}]*)?\}/.test(re) && !/\\\{/.test(re)) out.push({ severity: 'warning', matcher: m.name, msg: `${m.name}(\`${re}\`) looks like the v2 "{name:regex}" template; v3 uses plain Go regular expressions (e.g. ^[a-z]+\\.example\\.com$)` });
      try { new RegExp(re.replace(/\(\?[imsU]+\)/g, '').replace(/\\z/g, '$').replace(/\[\[:([a-z]+):\]\]/g, '[a-z]')); } catch (err) { out.push({ severity: 'error', matcher: m.name, msg: `invalid regular expression in ${m.name}(): ${err.message.replace(/^Invalid regular expression: /, '')}` }); }
    }
    if (syntax === 'v3' && /^(Path|PathPrefix)$/.test(m.name) && m.args.some((a) => V2_TEMPLATE.test(a))) out.push({ severity: 'warning', matcher: m.name, msg: `${m.name}() is literal in the v3 syntax; "{...}" templates only worked with v2 (use PathRegexp)` });
    if (/^(Path|PathPrefix)$/.test(m.name) && m.args.some((a) => a && !a.startsWith('/'))) out.push({ severity: 'error', matcher: m.name, msg: `${m.name}() values must start with "/"` });
    if (m.name === 'Host' && m.args.some((a) => /[:/]/.test(a) && !V2_TEMPLATE.test(a))) out.push({ severity: 'warning', matcher: m.name, msg: `Host() takes a bare host name (no scheme, port or path): "${m.args.find((a) => /[:/]/.test(a))}"` });
  }
  return out;
}
const RENAME_V3 = { Headers: 'Header', HeadersRegexp: 'HeaderRegexp', HostHeader: 'Host' };
const RENAME_V2 = { Header: 'Headers', HeaderRegexp: 'HeadersRegexp', PathRegexp: 'Path with a {name:regex} template', QueryRegexp: 'Query' };
function renameFor(name, syntax) { return syntax === 'v3' ? RENAME_V3[name] : RENAME_V2[name]; }

/**
 * Rewrite a v2-syntax rule into the v3 syntax when that is mechanical: Headers->Header, HeadersRegexp->HeaderRegexp,
 * HostHeader->Host, and multi-value matchers into ORs. Returns null when a template "{...}" or Query needs a human.
 */
function migrateRule(rule) {
  let tree; try { tree = parseRule(rule); } catch { return null; }
  let manual = false;
  const q = (v) => `\`${v}\``;
  const emit = (n, top) => {
    if (n.type === 'not') return `!${emit(n.item, false)}`;
    if (n.type === 'and' || n.type === 'or') { const s = n.items.map((x) => emit(x, false)).join(n.type === 'and' ? ' && ' : ' || '); return top || n.type === 'and' ? s : `(${s})`; }
    const name = RENAME_V3[n.name] || n.name;
    if (n.args.some((a) => V2_TEMPLATE.test(a)) && /^(Host|HostHeader|HostRegexp|Path|PathPrefix|HostSNIRegexp)$/.test(n.name)) manual = true;
    if (n.name === 'Query' || n.name === 'HostRegexp' || n.name === 'HostSNIRegexp') manual = true;
    if (/^(Headers|HeadersRegexp)$/.test(n.name)) return `${name}(${n.args.map(q).join(', ')})`;
    if (n.args.length > 1) return `(${n.args.map((a) => `${name}(${q(a)})`).join(' || ')})`;
    return `${name}(${n.args.map(q).join(', ')})`;
  };
  let out = emit(tree, true);
  if (manual) return null;
  if (/^\(.*\)$/.test(out) && tree.type === 'm') out = out.slice(1, -1);
  return out;
}

// ------------------------------------------------------------------------------------------------ evaluation
/** Go-ish regexp -> JS RegExp (best effort). */
function goRe(src, flags = '') {
  let s = src; let f = flags;
  const m = /^\(\?([imsU]+)\)/.exec(s);
  if (m) { if (m[1].includes('i')) f += 'i'; if (m[1].includes('s')) f += 's'; s = s.slice(m[0].length); }
  try { return new RegExp(s.replace(/\\z/g, '$'), f); } catch { return null; }
}
/** v2 gorilla/mux template "{sub:[a-z]+}.example.com" -> RegExp. */
function templateRe(t, prefix) {
  let out = ''; let i = 0;
  while (i < t.length) {
    if (t[i] === '{') { let depth = 1; let j = i + 1; while (j < t.length && depth) { if (t[j] === '{') depth++; else if (t[j] === '}') depth--; j++; } const inner = t.slice(i + 1, j - 1); const c = inner.indexOf(':'); out += `(${c < 0 ? '[^/.]+' : inner.slice(c + 1)})`; i = j; continue; }
    out += t[i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); i++;
  }
  try { return new RegExp(`^${out}${prefix ? '' : '$'}`, 'i'); } catch { return null; }
}
function hostMatches(pattern, host) {
  const h = String(host || '').toLowerCase().replace(/:\d+$/, '');
  const p = String(pattern).toLowerCase();
  if (p === '*') return true;
  if (p.startsWith('*.')) return h.endsWith(p.slice(1)) && h.length > p.length - 1;
  return h === p;
}
/**
 * Evaluate a parsed rule against a request { host, path, method, headers: {lc name: value}, query: {k: [v]}, clientIp, sni }.
 * Returns true / false, or null when it depends on something the request does not say.
 */
function evaluate(tree, req, syntax = 'v3') {
  const ev = (n) => {
    if (n.type === 'not') { const x = ev(n.item); return x === null ? null : !x; }
    if (n.type === 'and') { let unknown = false; for (const it of n.items) { const x = ev(it); if (x === false) return false; if (x === null) unknown = true; } return unknown ? null : true; }
    if (n.type === 'or') { let unknown = false; for (const it of n.items) { const x = ev(it); if (x === true) return true; if (x === null) unknown = true; } return unknown ? null : false; }
    const a = n.args; const path = req.path == null ? null : String(req.path).split('?')[0];
    const any = (fn) => a.some(fn);
    switch (n.name) {
      case 'Host': case 'HostHeader': if (req.host == null) return null; return syntax === 'v2' && any((x) => V2_TEMPLATE.test(x)) ? any((x) => { const r = templateRe(x); return r ? r.test(String(req.host).replace(/:\d+$/, '')) : false; }) : any((x) => hostMatches(x, req.host));
      case 'HostRegexp': if (req.host == null) return null; return any((x) => { const r = syntax === 'v2' ? templateRe(x) : goRe(x); return r ? r.test(String(req.host).replace(/:\d+$/, '')) : false; });
      case 'Path': if (path == null) return null; return any((x) => (syntax === 'v2' && V2_TEMPLATE.test(x) ? Boolean(templateRe(x) && templateRe(x).test(path)) : path === x));
      case 'PathPrefix': if (path == null) return null; return any((x) => (syntax === 'v2' && V2_TEMPLATE.test(x) ? Boolean(templateRe(x, true) && templateRe(x, true).test(path)) : path.startsWith(x)));
      case 'PathRegexp': { if (path == null) return null; const r = goRe(a[0]); return r ? r.test(path) : false; }
      case 'Method': if (req.method == null) return null; return any((x) => x.toUpperCase() === String(req.method).toUpperCase());
      case 'Header': case 'Headers': case 'HeaderRegexp': case 'HeadersRegexp': {
        if (!req.headers) return null; const v = req.headers[String(a[0]).toLowerCase()]; if (v === undefined) return false;
        if (/Regexp$/.test(n.name)) { const r = goRe(a[1] || ''); return r ? r.test(v) : false; }
        return v === a[1];
      }
      case 'Query': case 'QueryRegexp': {
        if (!req.query) return null;
        const pairs = syntax === 'v2' ? a.map((x) => { const i = x.indexOf('='); return i < 0 ? [x, ''] : [x.slice(0, i), x.slice(i + 1)]; }) : [[a[0], a[1]]];
        return pairs.some(([k, v]) => { const vals = req.query[k]; if (!vals) return false; if (v === undefined) return true; if (n.name === 'QueryRegexp') { const r = goRe(v); return r ? vals.some((x) => r.test(x)) : false; } return vals.includes(v); });
      }
      case 'ClientIP': return req.clientIp == null ? null : any((x) => ipMatch(x, req.clientIp));
      case 'HostSNI': if (a.length === 1 && a[0] === '*') return true; return req.sni == null ? null : any((x) => hostMatches(x, req.sni));
      case 'HostSNIRegexp': { if (req.sni == null) return null; return any((x) => { const r = syntax === 'v2' ? templateRe(x) : goRe(x); return r ? r.test(req.sni) : false; }); }
      default: return null;
    }
  };
  return ev(tree);
}
function ipMatch(cidr, ip) {
  const [net, bits] = String(cidr).split('/');
  const toN = (x) => { const p = String(x).split('.').map(Number); return p.length === 4 && p.every((n) => n >= 0 && n < 256) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null; };
  const a = toN(net); const b = toN(ip);
  if (a === null || b === null) return String(net).toLowerCase() === String(ip).toLowerCase();
  const n = bits === undefined ? 32 : Number(bits); const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

/** Default priority of a router (routing/routers "Priority"): the length of the rule string. */
const defaultPriority = (rule) => String(rule || '').length;

module.exports = { parseRule, tokenize, toDnf, matchersOf, branches, describeMatcher, checkRule, migrateRule, evaluate, defaultPriority, hostMatches, RuleError, V2_TEMPLATE };

'use strict';
/**
 * Version-aware validation of a HAProxy configuration against the knowledge base built from the official manuals
 * (src/kb/haproxy.json, see tools/kb/haproxy.js).
 *
 * It has its own lexer (line continuations, quotes, `${ENV}`, `.if/.else/.endif` preprocessor lines) so that it
 * validates every keyword the file contains, not only the ones the topology model understands.
 *
 * Findings: { id, severity, category, title, detail, fix, section, line, since?, until?, docs? }
 *   ids: compat-unknown-*, compat-too-new, compat-removed, compat-deprecated, compat-wrong-section, syntax-*
 */
const kb = require('../kb/haproxy.json');
const V = require('./version');
const { suggest } = require('./suggest');
const { REPLACEMENT, ADDRESS_SINCE } = require('./curated');
const { recommendHaproxy } = require('./recommendHaproxy');

const VERSIONS = kb.versions;
const SECTION_TYPES = ['global', 'defaults', 'frontend', 'backend', 'listen', 'userlist', 'peers', 'resolvers', 'mailers', 'program', 'http-errors', 'ring', 'log-forward', 'cache', 'fcgi-app', 'crt-store', 'acme', 'traces', 'log-profile', 'ssl-engine'];
const PROXY_TYPES = new Set(['defaults', 'frontend', 'backend', 'listen']);
const LETTER = { defaults: 'd', frontend: 'f', listen: 'l', backend: 'b' };
const FAMILY = new Set(['option', 'timeout', 'tcp-request', 'tcp-response', 'http-check', 'tcp-check', 'stick', 'email-alert', 'declare', 'http-error', 'log', 'compression', 'capture', 'balance', 'hash-type', 'monitor', 'external-check', 'normalize-uri', 'expect-proxy', 'expect-netscaler-cip', 'http-send-name-header', 'wait-for-body', 'switch-mode', 'persist', 'rate-limit', 'redirect', 'stats', 'stick-table', 'load-server-state-from-file']);
// families whose second word must itself be a documented keyword (option httplog, timeout client, ...)
const STRICT_SUB = new Set(['option', 'timeout', 'http-check', 'tcp-check', 'stick', 'email-alert', 'declare']);
const RULE_FAMILIES = new Set(['http-request', 'http-response', 'http-after-response', 'tcp-request', 'tcp-response']);

const nextVersion = (v) => VERSIONS[VERSIONS.indexOf(v) + 1] || null;
const keyDocs = (branch, anchor) => `https://docs.haproxy.org/${branch}/configuration.html#${encodeURIComponent(anchor)}`;

// ---------------------------------------------------------------------------------------------- lexer
/** Split one logical line into words, honouring quotes and escapes. Comments start at an unquoted `#` at a word start. */
function words(line) {
  const out = []; let cur = ''; let inW = false; let q = null; let hasQuote = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '\\' && i + 1 < line.length) { cur += line[++i]; continue; }
      if (c === q) { q = null; continue; }
      cur += c; continue;
    }
    if (c === '\\' && i + 1 < line.length) { cur += line[++i]; inW = true; continue; }
    if (c === '"' || c === "'") { q = c; inW = true; hasQuote = true; continue; }
    if (c === '#' && !inW) break;
    if (/\s/.test(c)) { if (inW) { out.push({ v: cur, quoted: hasQuote }); cur = ''; inW = false; hasQuote = false; } continue; }
    cur += c; inW = true;
  }
  if (inW) out.push({ v: cur, quoted: hasQuote });
  return out;
}

/** Logical lines with continuation (`\` at end of line) merged. */
function logicalLines(text) {
  const raw = String(text || '').split(/\r?\n/);
  const out = [];
  for (let i = 0; i < raw.length; i++) {
    let line = raw[i]; const start = i + 1;
    while (/\\\s*$/.test(line) && i + 1 < raw.length && !/^\s*#/.test(line)) { line = line.replace(/\\\s*$/, ' ') + raw[++i]; }
    out.push({ line: start, text: line });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------- preprocessor
/** Evaluate a `.if` condition. true/false when decidable for the target version, null when it depends on the build. */
function evalCond(expr, target) {
  const e = expr.trim();
  const or = splitTop(e, '||'); if (or.length > 1) { const r = or.map((x) => evalCond(x, target)); return r.includes(true) ? true : r.includes(null) ? null : false; }
  const and = splitTop(e, '&&'); if (and.length > 1) { const r = and.map((x) => evalCond(x, target)); return r.includes(false) ? false : r.includes(null) ? null : true; }
  if (e.startsWith('!')) { const r = evalCond(e.slice(1), target); return r === null ? null : !r; }
  if (e.startsWith('(') && e.endsWith(')')) return evalCond(e.slice(1, -1), target);
  let m = e.match(/^version_atleast\(\s*([\d.]+)\s*\)$/); if (m) return V.gte(target, m[1]);
  m = e.match(/^version_before\(\s*([\d.]+)\s*\)$/); if (m) return V.lt(target, m[1]);
  m = e.match(/^(?:version_atleast|version_before)\b/); if (m) return null;
  if (/^(true|1)$/i.test(e)) return true;
  if (/^(false|0)$/i.test(e)) return false;
  return null;
}
function splitTop(s, op) {
  const out = []; let depth = 0; let last = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '(') depth++; else if (s[i] === ')') depth--;
    else if (depth === 0 && s.startsWith(op, i)) { out.push(s.slice(last, i)); last = i + op.length; i += op.length - 1; }
  }
  out.push(s.slice(last)); return out;
}

// ---------------------------------------------------------------------------------------------- main
function analyzeHaproxy(raw, { version } = {}) {
  const requested = version || null;
  let branch = V.haproxyBranch(requested, VERSIONS);
  let note = null;
  if (requested && !branch) note = `Could not read "${requested}" as a version; validating against the latest documented release (${VERSIONS[VERSIONS.length - 1]}).`;
  if (!branch) branch = VERSIONS[VERSIONS.length - 1];
  else if (V.lt(requested, VERSIONS[0])) note = `Versions older than ${VERSIONS[0]} are not documented in the knowledge base; validating as ${VERSIONS[0]}.`;
  else if (V.parse(requested) && V.gte(requested, branch) && VERSIONS.indexOf(branch) === VERSIONS.length - 1 && V.cmp(requested, VERSIONS[VERSIONS.length - 1]) > 0 && V.parse(requested)[1] !== V.parse(branch)[1]) note = `${requested} is newer than the newest documented release (${branch}); validating as ${branch}.`;
  const target = branch;

  const findings = [];
  const add = (f) => findings.push({ category: 'compat', detail: '', fix: '', ...f });
  const sections = []; // model for the recommendation pass
  let cur = null;
  const cond = []; // preprocessor stack: { active: true|false|null, parent, taken }

  const skipping = () => cond.some((c) => c.active === false);
  const guarded = () => cond.some((c) => c.active === null);

  function scan() {
  for (const ll of logicalLines(raw)) {
    const trimmed = ll.text.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // ---- preprocessor
    if (trimmed.startsWith('.')) {
      const m = trimmed.match(/^\.(if|elif|else|endif|diag|warning|alert|notice)\b\s*(.*)$/);
      if (!m) { add({ id: 'syntax-unknown-directive', severity: 'error', category: 'syntax', line: ll.line, section: cur ? cur.name : 'global', title: `Unknown preprocessor directive "${trimmed.split(/\s/)[0]}"`, detail: 'Lines starting with "." are preprocessor directives (.if, .elif, .else, .endif, .diag, .warning, .alert, .notice).', fix: 'Remove the line or use a supported preprocessor directive.' }); continue; }
      const kw = m[1];
      if (kw === 'if') { const r = evalCond(m[2], target); cond.push({ active: r, line: ll.line, taken: r === true, unknown: r === null }); }
      else if (kw === 'elif') {
        const top = cond[cond.length - 1];
        if (!top) { add({ id: 'syntax-preprocessor', severity: 'error', category: 'syntax', line: ll.line, title: '.elif without a matching .if', fix: 'Add the missing .if or remove this line.' }); continue; }
        const r = evalCond(m[2], target);
        top.active = top.taken ? false : r; if (r === true) top.taken = true; if (r === null) top.unknown = true;
      } else if (kw === 'else') {
        const top = cond[cond.length - 1];
        if (!top) { add({ id: 'syntax-preprocessor', severity: 'error', category: 'syntax', line: ll.line, title: '.else without a matching .if', fix: 'Add the missing .if or remove this line.' }); continue; }
        top.active = top.unknown ? null : !top.taken; top.taken = true;
      } else if (kw === 'endif') {
        if (!cond.length) add({ id: 'syntax-preprocessor', severity: 'error', category: 'syntax', line: ll.line, title: '.endif without a matching .if', fix: 'Remove it or add the matching .if.' });
        else cond.pop();
      }
      continue;
    }
    if (skipping()) continue;

    const toks = words(ll.text);
    if (!toks.length) continue;
    const t = toks.map((x) => x.v);
    const head = t[0];

    // ---- section header
    if (SECTION_TYPES.includes(head) && (head === 'global' || head === 'defaults' || t.length >= 1)) {
      const sinceKw = kb.sections[head] ? Object.values(kb.sections[head]).reduce((a, e) => (!a || V.lt(e.s, a) ? e.s : a), null) : null;
      cur = { type: head, name: t[1] || (head === 'global' ? 'global' : head), line: ll.line, items: [] };
      sections.push(cur);
      if (sinceKw && sinceKw !== VERSIONS[0] && V.lt(target, sinceKw) && !guarded()) {
        add({ id: 'compat-too-new', severity: 'error', title: `Section "${head}" requires HAProxy ${sinceKw}+`, detail: `Its keywords first appear in the ${sinceKw} manual; you are validating against ${target}.`, fix: `Upgrade to ${sinceKw} or newer, or remove the section.`, section: cur.name, line: ll.line, since: sinceKw });
      }
      if (['frontend', 'backend', 'listen'].includes(head) && !t[1]) add({ id: 'syntax-missing-name', severity: 'error', category: 'syntax', title: `"${head}" section without a name`, detail: 'HAProxy requires a name for frontend, backend and listen sections.', fix: `Write "${head} <name>".`, section: head, line: ll.line });
      continue;
    }
    if (!cur) {
      add({ id: 'syntax-outside-section', severity: 'error', category: 'syntax', line: ll.line, section: 'global', title: `"${head}" appears before any section`, detail: 'Every keyword must be inside a section (global, defaults, frontend, backend, listen, ...).', fix: 'Move it below the right section header.' });
      continue;
    }

    const item = { kw: head, args: t.slice(1), tokens: toks, line: ll.line, raw: ll.text, guarded: guarded() };
    cur.items.push(item);
    checkItem(cur, item);
  }
  for (const c of cond) add({ id: 'syntax-preprocessor', severity: 'error', category: 'syntax', line: c.line, title: '.if without a matching .endif', fix: 'Close the conditional block with .endif.' });
  }

  // -------------------------------------------------------------------------------------------- per-keyword checks
  function lifecycle(entry, label, where, item, anchor, extra = {}) {
    if (!entry || item.guarded) return;
    const base = { section: where.name, line: item.line, docs: anchor ? keyDocs(target, anchor) : undefined };
    const repl = REPLACEMENT.haproxy[label];
    if (entry.s && entry.s !== VERSIONS[0] && !(extra.baselineAtMost && V.cmp(entry.s, extra.baselineAtMost) <= 0) && V.lt(target, entry.s)) {
      add({ ...base, id: 'compat-too-new', severity: 'error', title: `"${label}" needs HAProxy ${entry.s}+`, detail: `Introduced in ${entry.s}; your target is ${target}, so HAProxy ${target} will reject this line.`, fix: repl && repl.older ? repl.older : `Upgrade to ${entry.s}+ or remove it.`, since: entry.s });
    }
    if (entry.r && VERSIONS.indexOf(entry.r) >= 0 && V.lt(entry.r, target)) {
      const gone = nextVersion(entry.r);
      add({ ...base, id: 'compat-removed', severity: 'error', title: `"${label}" was removed in HAProxy ${gone}`, detail: `It is no longer accepted since ${gone} and your target is ${target}. HAProxy refuses to start with it.`, fix: repl ? repl.fix : 'Remove it or migrate to the documented replacement.', until: entry.r });
    }
    if (entry.d && V.gte(target, entry.d) && !(entry.r && V.lt(entry.r, target))) {
      add({ ...base, id: 'compat-deprecated', severity: 'warning', title: `"${label}" is deprecated`, detail: `Flagged deprecated in the ${entry.d} manual and still accepted by ${target}, but it may be removed in a future release.`, fix: repl ? repl.fix : 'Move to the keyword that the manual recommends instead.', since: entry.d });
    }
  }

  function unknown(kind, name, pool, where, item, extra = {}) {
    const near = suggest(name, pool);
    const anyOther = extra.elsewhere;
    add({
      id: `compat-unknown-${kind}`, severity: extra.severity || 'error', section: where.name, line: item.line,
      title: `Unknown ${kind === 'keyword' ? 'keyword' : kind} "${name}"${extra.inside ? ` in ${extra.inside}` : ''}`,
      detail: `Not found in the HAProxy ${target} manual${anyOther ? `, but it exists in ${anyOther}` : ''}. HAProxy ${extra.severity === 'warning' ? 'may reject' : 'rejects'} unknown ${kind === 'keyword' ? 'keywords' : kind}s at startup.`,
      fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Check the spelling against the manual for this version, or remove the line.',
    });
  }

  const maskAt = (entry) => {
    if (!entry.cc) return entry.c;
    let m = entry.cc[0][1];
    for (const [v, mask] of entry.cc) if (V.gte(target, v)) m = mask;
    return m;
  };

  function checkItem(sec, item) {
    const { args } = item;
    let kw = item.kw;
    const type = sec.type;
    // ------------------------------------------------ global
    if (type === 'global') {
      if (kw === 'no' && args[0]) kw = args[0];
      if (kw === 'default') kw = args[0] || kw;
      const e = kb.global[kw];
      if (!e) {
        const elsewhere = Object.keys(kb.sections).filter((s) => kb.sections[s][kw]).join(', ') || (kb.proxy[kw] ? 'proxy sections (frontend/backend/listen/defaults)' : null);
        return unknown('keyword', kw, Object.keys(kb.global), sec, item, { elsewhere, inside: '"global"' });
      }
      lifecycle(e, kw, sec, item, kw);
      checkExpressions(sec, item);
      return undefined;
    }
    // ------------------------------------------------ other section kinds
    if (!PROXY_TYPES.has(type)) {
      const pool = kb.sections[type];
      if (pool && Object.keys(pool).length) {
        const key = (kw === 'no' || kw === 'default') && args[0] ? args[0] : kw;
        const e = pool[key] || pool[`${key} ${args[0]}`] || (type === 'peers' && (key === 'peer' || key === 'bind' || key === 'server' || key === 'table') ? {} : null) || (type === 'ring' && kb.proxy[key] ? {} : null) || (type === 'userlist' && (key === 'group' || key === 'user') ? {} : null) || (type === 'resolvers' && key === 'nameserver' ? {} : null) || (type === 'program' && kb.proxy[key] ? {} : null);
        if (!e && !kb.global[key] && !kb.proxy[key]) unknown('keyword', key, Object.keys(pool), sec, item, { inside: `section "${type}"`, severity: 'warning' });
        else if (e && e.s) lifecycle({ s: e.s }, key, sec, item, key); // minor sections: availability only (their docs were restructured over time)
      }
      checkExpressions(sec, item);
      return undefined;
    }

    // ------------------------------------------------ proxy sections
    let neg = null;
    if ((kw === 'no' || kw === 'default') && args.length) { neg = kw; kw = args[0]; item = { ...item, kw, args: args.slice(1), neg }; }
    const a = item.args;
    let key = kw; let entry = kb.proxy[kw]; let used = 0;
    if (a[0] && kb.proxy[`${kw} ${a[0]}`]) { key = `${kw} ${a[0]}`; entry = kb.proxy[key]; used = 1; }
    if (RULE_FAMILIES.has(kw)) {
      // http-request <action> / tcp-request connection <action> ...
      let idx = 0; let fam = kw;
      if ((kw === 'tcp-request' || kw === 'tcp-response') && a[0]) { fam = `${kw} ${a[0]}`; idx = 1; }
      const famEntry = kb.proxy[fam] || kb.proxy[kw];
      if (famEntry) {
        const m = maskAt(famEntry);
        if (m && !m.includes(LETTER[type])) wrongSection(sec, item, fam, m);
        lifecycle(famEntry, fam, sec, item, fam);
      } else if (kw === 'tcp-request' || kw === 'tcp-response') {
        return unknown('keyword', fam, Object.keys(kb.proxy).filter((k) => k.startsWith(`${kw} `)), sec, item);
      }
      const actionTok = a[0] === 'inspect-delay' ? null : a[idx];
      if (actionTok && !/^[{}]|^(if|unless)$/.test(actionTok)) {
        const act = actionTok.replace(/\(.*$/, '').replace(/^lua\..*/, 'lua.x');
        const known = Object.keys(kb.actions);
        if (act !== 'lua.x' && !kb.actions[act] && !/^track-sc\d+$/.test(act) && !/^sc-(inc-gpc|set-gpt|add-gpc)\d*$/.test(act) && !kb.proxy[`${fam} ${act}`]) {
          unknown('action', act, known, sec, item, { inside: `"${fam}"` });
        } else if (kb.actions[act]) {
          // the manuals only started giving every action its own entry in 1.9 (http-*) / 2.5 (tcp-*): older ones are baseline
          lifecycle(kb.actions[act], `${fam} ${act}`, sec, item, null, { baselineAtMost: /^tcp-/.test(fam) ? '2.5' : '1.9' });
        }
      }
      checkExpressions(sec, item);
      return checkCondition(sec, item);
    }

    if (STRICT_SUB.has(kw) && a[0] && !kb.proxy[`${kw} ${a[0]}`]) {
      const subs = Object.keys(kb.proxy).filter((k) => k.startsWith(`${kw} `));
      if (subs.length) return unknown('keyword', `${kw} ${a[0]}`, subs, sec, item, { inside: `${type} "${sec.name}"` });
    }
    if (!entry && kw.includes('.')) entry = null;
    if (!entry && FAMILY.has(kw)) entry = kb.proxy[kw]; // e.g. "compression algo gzip" -> "compression"
    if (!entry) {
      const pool = Object.keys(kb.proxy).filter((k) => !k.includes(' ') || (a.length && k.startsWith(`${kw} `)));
      const subs = Object.keys(kb.proxy).filter((k) => k.startsWith(`${kw} `));
      if (subs.length && a[0]) return unknown('keyword', `${kw} ${a[0]}`, subs, sec, item, { inside: `"${type} ${sec.name}"` });
      // legacy keyword the manual no longer lists but that the manual says were removed? check the other-section pools
      const inGlobal = kb.global[kw] ? 'the "global" section' : null;
      return unknown('keyword', kw, Object.keys(kb.proxy).filter((k) => !k.includes(' ')), sec, item, { elsewhere: inGlobal, inside: `${type} "${sec.name}"` });
    }
    const m = maskAt(entry);
    if (m && !m.includes(LETTER[type])) wrongSection(sec, item, key, m);
    lifecycle(entry, neg && key.startsWith('option') ? key : key, sec, item, key.split(' ')[0] === 'option' ? key : key);

    if (kw === 'bind') checkBind(sec, item);
    else if (kw === 'server' || kw === 'default-server' || kw === 'server-template') checkServer(sec, item, kw);
    checkExpressions(sec, item);
    if (kw === 'acl') checkAcl(sec, item);
    checkCondition(sec, item);
    return undefined;
  }

  function wrongSection(sec, item, key, mask) {
    const names = { d: 'defaults', f: 'frontend', l: 'listen', b: 'backend' };
    const ok = mask.split('').map((c) => names[c]).join(', ');
    add({ id: 'compat-wrong-section', severity: 'warning', title: `"${key}" is not valid in a ${sec.type} section`, detail: `HAProxy ${target} only accepts it in: ${ok}. In a ${sec.type} section it is ignored with a warning (or rejected, depending on the keyword).`, fix: `Move it to a ${mask.split('').map((c) => names[c]).join(' / ')} section.`, section: sec.name, line: item.line, docs: keyDocs(target, key.split(' ')[0]) });
  }

  /** Walk bind/server option lists using the documented argument counts. */
  function walkOptions(sec, item, startIdx, table, argcPrefix, label) {
    const t = item.tokens.map((x) => x.v);
    for (let i = startIdx; i < t.length; i++) {
      const tok = t[i];
      if (/^(if|unless)$/.test(tok)) break;
      if (tok === ',' || tok === '') continue;
      const name = tok.replace(/\(.*$/, '');
      const e = table[name];
      if (!e) {
        // a stray value of an option we do not know the arity of? only complain for word-like tokens
        if (/^[a-z][a-z0-9-]+$/i.test(name) && !/^\d/.test(name)) {
          const nearHint = Object.keys(table).concat(Object.keys(kb[argcPrefix === 'b' ? 'server' : 'bind'] || {}).filter((x) => table === kb.bind ? kb.server[x] : kb.bind[x]).slice(0, 0));
          const other = (argcPrefix === 'b' ? kb.server : kb.bind)[name] ? ` (it is a ${argcPrefix === 'b' ? 'server' : 'bind'} option)` : '';
          unknown(`${label} option`, name, nearHint, sec, item, { elsewhere: other ? `the ${argcPrefix === 'b' ? 'server' : 'bind'} options` : null });
        }
        continue;
      }
      lifecycle(e, `${label} option "${name}"`, sec, item, name);
      const n = kb.argc[`${argcPrefix}:${name}`];
      i += typeof n === 'number' ? n : 0;
    }
  }

  function checkBind(sec, item) {
    const t = item.tokens.map((x) => x.v);
    const addrTok = t[1] || '';
    const pre = addrTok.match(/^([a-z0-9+]+)@/i);
    if (pre && ADDRESS_SINCE[pre[1].toLowerCase()]) {
      const need = ADDRESS_SINCE[pre[1].toLowerCase()];
      if (V.lt(target, need) && !item.guarded) add({ id: 'compat-too-new', severity: 'error', title: `Address family "${pre[1]}@" needs HAProxy ${need}+`, detail: `Your target is ${target}.`, fix: `Use a plain address, or upgrade to ${need}+.`, section: sec.name, line: item.line, since: need });
    }
    // bind may list several addresses separated by commas; options start after the address token
    walkOptions(sec, item, 2, kb.bind, 'b', 'bind');
  }

  function checkServer(sec, item, kw) {
    const t = item.tokens.map((x) => x.v);
    const start = kw === 'server' ? 3 : kw === 'default-server' ? 1 : 4;
    walkOptions(sec, item, start, kb.server, 's', 'server');
  }

  // --------------------------------------------------------- sample fetches / converters
  const fetchPool = Object.keys(kb.fetches);
  const convPool = Object.keys(kb.converters);
  const splitComma = (s) => { const out = []; let d = 0; let last = 0; for (let i = 0; i < s.length; i++) { if (s[i] === '(') d++; else if (s[i] === ')') d--; else if (s[i] === ',' && d === 0) { out.push(s.slice(last, i)); last = i + 1; } } out.push(s.slice(last)); return out; };

  function checkExpr(sec, item, expr) {
    const parts = splitComma(expr).map((x) => x.trim()).filter(Boolean);
    parts.forEach((p, i) => {
      const name = p.replace(/\(.*$/s, '').replace(/^-/, '');
      if (!name || /^[\d"'$%]/.test(name)) return;
      if (/^(lua\.|var$|str$|int$|bool$|ipv4$|ipv6$)/.test(name) || name.startsWith('lua.') || /^(51d|da|wurfl)[.-]/.test(name)) return; // vendor / scripted extensions
      const table = i === 0 ? kb.fetches : kb.converters;
      const e = table[name];
      if (!e) {
        if (i === 0 && kb.converters[name]) return; // a converter applied right after a literal; lenient
        const near = suggest(name, i === 0 ? fetchPool : convPool);
        add({ id: `compat-unknown-${i === 0 ? 'fetch' : 'converter'}`, severity: 'error', title: `Unknown ${i === 0 ? 'sample fetch' : 'converter'} "${name}"`, detail: `Not found in the HAProxy ${target} manual.`, fix: near.length ? `Did you mean ${near.map((x) => `"${x}"`).join(', ')}?` : 'Check the spelling or the version that introduced it.', section: sec.name, line: item.line });
      } else lifecycle(e, `${i === 0 ? 'fetch' : 'converter'} "${name}"`, sec, item, name);
    });
  }

  /** `%[fetch(args),conv]` expressions embedded in any argument (log-format, set-header values, redirect ...). */
  function checkExpressions(sec, item) {
    for (const tok of item.tokens) {
      for (const m of tok.v.matchAll(/%\[((?:[^\]\\]|\\.)*)\]/g)) checkExpr(sec, item, m[1]);
    }
  }

  function checkAcl(sec, item) {
    const t = item.tokens.map((x) => x.v);
    const crit = t[2];
    if (!crit || crit.startsWith('-')) return;
    checkExpr(sec, item, crit);
  }

  /** Inline anonymous ACLs: `if { path_beg /api } or { hdr(host) -i x }` */
  function checkCondition(sec, item) {
    const t = item.tokens.map((x) => x.v);
    const at = t.findIndex((x) => x === 'if' || x === 'unless');
    if (at < 0) return;
    for (let i = at + 1; i < t.length; i++) {
      if (t[i] === '{' && t[i + 1]) checkExpr(sec, item, t[i + 1]);
    }
  }

  scan();
  findings.sort((a, b) => (a.line || 0) - (b.line || 0));
  const result = { findings, model: { sections }, target: { requested, branch: target, note }, kb: { generated: kb.generated, source: kb.source } };
  recommendHaproxy({ sections, target, add, kb, V });
  return result;
}

module.exports = { analyzeHaproxy, words, logicalLines, evalCond };

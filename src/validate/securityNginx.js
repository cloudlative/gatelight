'use strict';
/**
 * Request-handling security checks for an NGINX configuration (ids prefixed `sec-nginx-`, category "security").
 * They look at how request data (URI, arguments, headers, regex captures) flows into proxy_pass, headers, redirects and
 * Origin/Referer tests, and suggest a fix that fits the target version.
 *
 *   sec-nginx-ssrf              proxy_pass host or scheme built from request data
 *   sec-nginx-host-header       Host sent to the upstream taken from the client (spoofing, cache and reset-link poisoning)
 *   sec-nginx-http-splitting    $uri / $document_uri or a loose regex capture inside a redirect, header or proxied URL (CR/LF injection)
 *   sec-nginx-origin-check      `if ($http_origin|$http_referer ~ ...)` whose regex can be bypassed
 *   sec-nginx-referers-none     valid_referers that accepts a missing Referer, or a weak ~regex entry
 *   sec-nginx-multiline-header  a header value written over several lines
 *
 * The rules are conservative: variables set by `map` / `geo` are treated as a allow-list and never reported.
 */

const REQUEST_VAR = /^(arg_\w*|http_\w+|cookie_\w*|args|query_string|request_uri|uri|document_uri|request|host|request_filename|path_info)$/;
const SPLIT_VAR = /^(uri|document_uri)$/;
const PATH_ONLY = /^(uri|request_uri|document_uri)$/; // always start with "/": they can extend a path but not a host name
const HEADER_SINKS = new Set(['add_header', 'add_trailer', 'proxy_set_header', 'grpc_set_header', 'more_set_headers', 'more_set_input_headers', 'more_clear_headers']);
// a capture group that can match a newline: negated classes, \W \D \s, or an explicit newline
const LOOSE_GROUP = /\[\^|\\[WDs]|\\[nr]/;

const varsIn = (s) => { const out = []; const re = /\$\{?(\w+)\}?/g; let m; while ((m = re.exec(String(s)))) out.push(m[1]); return out; };

/** The capture groups of a location / if regex, in order, with their source text. */
function groupsOf(regex) {
  const groups = []; const stack = [];
  for (let i = 0; i < regex.length; i++) {
    const c = regex[i];
    if (c === '\\') { i++; continue; }
    if (c === '[') { while (i < regex.length && regex[i] !== ']') { if (regex[i] === '\\') i++; i++; } continue; }
    if (c === '(') {
      let name = null; let capturing = true;
      const m = /^\(\?(?:P?<(\w+)>|'(\w+)')/.exec(regex.slice(i));
      if (m) name = m[1] || m[2]; else if (regex[i + 1] === '?') capturing = false;
      stack.push({ start: i, capturing, name, index: capturing ? groups.length + 1 : 0 });
      if (capturing) groups.push({ name, index: groups.length + 1, src: '' });
    } else if (c === ')') {
      const g = stack.pop();
      if (g && g.capturing) { const body = regex.slice(g.start + 1, i).replace(/^\?(?:P?<\w+>|'\w+')/, ''); groups[g.index - 1].src = body; }
    }
  }
  return groups;
}

function securityNginx({ ast, add, V, target }) {
  const sec = (f) => add({ category: 'security', severity: 'warning', ...f });
  const alwaysOk = !V || !target || V.gte(target, '1.7.5'); // "add_header ... always" exists from 1.7.5
  const all = [];
  (function flat(nodes, chain) {
    for (const n of nodes) { all.push({ node: n, chain }); if (n.children) flat(n.children, [...chain, n]); }
  })(ast, []);
  const label = (chain) => { const b = chain.filter((c) => ['server', 'location', 'upstream'].includes(c.name)).pop(); return b ? `${b.name}${b.args && b.args[0] ? ` ${b.args.slice(0, 2).join(' ')}` : ''}` : 'main'; };
  const where = (x) => ({ file: x.node.file, line: x.node.line, section: label(x.chain) });

  // variables defined by map/geo are an allow-list: never user data
  const safeVars = new Set();
  for (const x of all) if ((x.node.name === 'map' || x.node.name === 'geo' || x.node.name === 'split_clients') && x.node.args.length) { const v = x.node.args[x.node.args.length - 1]; if (/^\$/.test(v)) safeVars.add(v.slice(1)); }

  /** Capture groups visible at a node: from its enclosing location / if blocks. */
  const capturesAt = (chain) => {
    const caps = new Map(); // name or index -> { src, loose }
    for (const b of chain) {
      let regex = null;
      if (b.name === 'location' && /^~\*?$/.test(b.args[0] || '')) regex = b.args[1];
      else if (b.name === 'if') { const t = b.args.join(' ').replace(/^\(\s*/, '').replace(/\s*\)$/, ''); const m = /^\$\S+\s+(?:!~|~)\*?\s+(.+)$/.exec(t); if (m) regex = m[1].replace(/^(['"])(.*)\1$/, '$2'); }
      if (!regex) continue;
      groupsOf(regex).forEach((g) => { const info = { src: g.src, loose: LOOSE_GROUP.test(g.src) }; caps.set(String(g.index), info); if (g.name) caps.set(g.name, info); });
    }
    return caps;
  };
  /** Variables assigned with `set` in the enclosing blocks (nearest wins): name -> expression. */
  const setsAt = (chain, node) => {
    const m = new Map();
    for (const b of chain) for (const c of b.children || []) if (c.name === 'set' && c.args.length >= 2 && /^\$/.test(c.args[0]) && c !== node) m.set(c.args[0].slice(1), c.args.slice(1).join(' '));
    return m;
  };
  /** Is this variable user-controlled? Returns { kind: 'request' | 'capture', name, loose } or null. */
  const taint = (name, caps, sets, depth = 0, forHost = false) => {
    if (safeVars.has(name)) return null;
    if (forHost && PATH_ONLY.test(name)) return null;
    if (REQUEST_VAR.test(name)) return { kind: 'request', name };
    if (caps.has(name)) return { kind: 'capture', name, loose: caps.get(name).loose };
    if (sets.has(name) && depth < 4) {
      for (const v of varsIn(sets.get(name))) { const t = taint(v, caps, sets, depth + 1, forHost); if (t) return t; }
    }
    return null;
  };
  const taints = (expr, caps, sets, forHost = false) => varsIn(expr).map((v) => taint(v, caps, sets, 0, forHost)).filter(Boolean);

  const proxyPasses = all.filter((x) => x.node.name === 'proxy_pass');
  // ---- 1. SSRF: the scheme or host of proxy_pass comes from the request ----------------------------------------------
  for (const x of proxyPasses) {
    const arg = x.node.args[0] || ''; if (!/\$/.test(arg)) continue;
    const caps = capturesAt(x.chain); const sets = setsAt(x.chain, x.node);
    const m = /^([^/]*?):\/\/([^/]*)/.exec(arg);
    const head = m ? `${m[1]}://${m[2]}` : (arg.split('/')[0]);
    if (x.chain.some((b) => b.name === 'location' && (b.children || []).some((c) => c.name === 'internal'))) continue; // only reachable through internal redirects
    const hostTaint = taints(head, caps, sets, true);
    if (!hostTaint.length) continue;
    const whole = /^\$\{?\w+\}?$/.test(arg) || (m && (/^\$\{?\w+\}?$/.test(m[1]) || /^\$\{?\w+\}?(:\d+)?$/.test(m[2])));
    const names = [...new Set(hostTaint.map((t) => `$${t.name}`))].slice(0, 3).join(', ');
    sec({
      id: 'sec-nginx-ssrf', severity: whole ? 'error' : 'warning', ...where(x),
      title: `proxy_pass builds the ${m ? (/\$/.test(m[1]) ? 'scheme' : 'host') : 'target'} from request data (${names})`,
      detail: `Whoever sends the request chooses where NGINX connects: internal services, cloud metadata (169.254.169.254), localhost admin ports. That is server-side request forgery. ${whole ? 'The whole target is request-controlled.' : 'Even a partial host such as "some$var" lets an attacker steer the name (for example "some.evil.com" or "@evil.com").'}`,
      fix: 'Proxy to fixed upstreams. If the target has to vary, translate a validated key to a known upstream with a map:  map $arg_site $backend { default ""; a app_a; b app_b; }  then  proxy_pass http://$backend;  (an empty result is a 502, not an open proxy). Never put $arg_*, $http_*, $uri or regex captures in the scheme or host.',
    });
  }

  // ---- 2. Host header taken from the client ----------------------------------------------------------------------------
  for (const x of all.filter((y) => y.node.name === 'proxy_set_header' && /^host$/i.test(y.node.args[0] || ''))) {
    const val = x.node.args[1] || ''; const caps = capturesAt(x.chain); const sets = setsAt(x.chain, x.node);
    const t = taints(val, caps, sets).filter((k) => k.name !== 'host');
    if (!t.length) continue;
    const onlyHttpHost = t.every((k) => k.name === 'http_host');
    sec({
      id: 'sec-nginx-host-header', severity: onlyHttpHost ? 'info' : 'warning', ...where(x),
      title: onlyHttpHost ? 'Host is passed to the upstream exactly as the client sent it ($http_host)' : `Host sent to the upstream comes from request data (${[...new Set(t.map((k) => `$${k.name}`))].join(', ')})`,
      detail: onlyHttpHost
        ? '$http_host is the raw header, including any port or odd value the client chose. A backend that builds links or password-reset URLs from Host can be poisoned (host header injection), and shared caches can be poisoned too. $host is normalised and always matches a server_name or the default server.'
        : 'The client decides which virtual host the backend serves and what absolute URLs it generates. That allows cache poisoning, password-reset poisoning and access to other virtual hosts on the backend.',
      fix: onlyHttpHost ? 'Use `proxy_set_header Host $host;` (add `proxy_set_header X-Forwarded-Host $http_host;` if the backend needs the original value with its port).' : 'Send a fixed or normalised value: `proxy_set_header Host $host;` or the literal name of the backend virtual host.',
    });
  }

  // ---- 3. CR/LF injection (HTTP response splitting) -------------------------------------------------------------------------
  const splitting = (x, expr, kind) => {
    const caps = capturesAt(x.chain); const sets = setsAt(x.chain, x.node);
    const bad = [];
    for (const v of varsIn(expr)) {
      if (safeVars.has(v)) continue;
      if (SPLIT_VAR.test(v)) bad.push({ name: v, why: 'is URL-decoded, so %0d%0a becomes a real line break' });
      else { const t = taint(v, caps, sets); if (t && t.kind === 'capture' && t.loose) bad.push({ name: v, why: 'captures with a pattern that can match a line break' }); }
    }
    if (!bad.length) return;
    sec({
      id: 'sec-nginx-http-splitting', ...where(x),
      title: `${kind} contains ${[...new Set(bad.map((b) => `$${b.name}`))].slice(0, 3).join(', ')}, which can carry CR/LF`,
      detail: `${bad[0].name.match(/^\d+$|^[a-z]/) && !SPLIT_VAR.test(bad[0].name) ? `$${bad[0].name} ${bad[0].why}` : `$${bad[0].name} ${bad[0].why}`}. An attacker can inject extra response headers or a second response (HTTP response splitting, open redirects, cache poisoning).`,
      fix: SPLIT_VAR.test(bad[0].name) ? 'Use `$request_uri` (the raw, still-encoded URI including the query) instead of `$uri` / `$document_uri` in redirects and headers, for example `return 301 https://$host$request_uri;`.' : 'Restrict the capture so it cannot match whitespace: use `([^/\\s]+)` or `([\\w.-]+)` instead of `([^/]+)` or `(\\W*)`.',
    });
  };
  for (const x of all) {
    const n = x.node;
    if (n.name === 'return' && n.args.length >= 2 && /^30[1237]$/.test(n.args[0])) splitting(x, n.args.slice(1).join(' '), `return ${n.args[0]}`);
    else if (n.name === 'rewrite' && n.args[1] && /^(https?:\/\/|\$)/.test(n.args[1])) splitting(x, n.args[1], 'rewrite replacement');
    else if (HEADER_SINKS.has(n.name) && n.name !== 'more_clear_headers' && n.args.length >= 2 && !(n.name === 'proxy_set_header' && /^host$/i.test(n.args[0]))) splitting(x, n.args.slice(1).join(' '), `${n.name} ${n.args[0]}`);
    else if (n.name === 'proxy_pass' && /\$/.test(n.args[0] || '')) { const rest = n.args[0].replace(/^[^/]*?:\/\//, ''); if (/\$/.test(rest)) splitting(x, rest, 'proxy_pass URL'); }
  }

  // ---- 4. Origin / Referer regex checks that can be bypassed ----------------------------------------------------------
  const originProblems = (regex, header) => {
    const probs = []; const isOrigin = header === 'http_origin';
    let r = regex;
    if (!/^\(?\^/.test(r)) probs.push('it is not anchored with ^, so "https://evil.com/?x=https://allowed.example/" also matches');
    if (!/(\\?\/|\$|\$\)|\(\??:?\\?\/\|\$\))['"]?$/.test(r)) probs.push('it does not end the host (with / or $), so "https://allowed.example.evil.com" matches');
    { let depth = 0; let cur = ''; const alts = []; for (let i = 0; i < r.length; i++) { const c = r[i]; if (c === '\\') { cur += c + (r[++i] || ''); continue; } if (c === '(') depth++; if (c === ')') depth--; if (c === '|' && depth === 0) { alts.push(cur); cur = ''; } else cur += c; } alts.push(cur); if (alts.length > 1 && alts.slice(1).some((a2) => !/^\(?\^/.test(a2))) probs.push('an alternative after | is not anchored, so it matches anywhere in the value'); }
    const bare = r.replace(/\\./g, '');
    if (/[A-Za-z0-9-]\.[A-Za-z]{2,}/.test(bare)) probs.push('a dot in the host is not escaped (\\.), so it matches any character');
    if (/(\.\*|\.\+|\[\^\/\]\*|\[\^\/\]\+)[A-Za-z0-9-]/.test(r)) probs.push('a wildcard sits right before the domain, so "evilallowed.example" matches (put "\\." before the domain)');
    return probs;
  };
  const betterRegex = (regex, header) => {
    const m = /https?:(?:\\?\/){2}(?:\([^)]*\)\??)?((?:[A-Za-z0-9-]+(?:\\?\.)?)+[A-Za-z0-9-])/.exec(regex);
    const dom = m ? m[1].replace(/\\\./g, '.').replace(/\./g, '\\.') : 'example\\.com';
    return header === 'http_origin' ? `^https?://([a-z0-9-]+\\.)?${dom}$` : `^https?://([a-z0-9-]+\\.)?${dom}(/|$)`;
  };
  for (const x of all.filter((y) => y.node.name === 'if')) {
    const t = x.node.args.join(' ').replace(/^\(\s*/, '').replace(/\s*\)$/, '');
    const m = /^\$(http_origin|http_referer)\s+(!?~\*?)\s+([\s\S]+)$/.exec(t); if (!m) continue;
    const regex = m[3].replace(/^(['"])([\s\S]*)\1$/, '$2');
    const probs = originProblems(regex, m[1]); if (!probs.length) continue;
    const hdr = m[1] === 'http_origin' ? 'Origin' : 'Referer';
    sec({
      id: 'sec-nginx-origin-check', ...where(x),
      title: `${hdr} check can be bypassed: ${probs[0].replace(/^it /, '').replace(/^a /, 'a ')}`,
      detail: `The regex \`${regex.length > 90 ? `${regex.slice(0, 87)}…` : regex}\` is meant to allow only your own site, but ${probs.join('; and ')}. Origin and Referer are chosen by the client's page, so a lookalike domain passes the test.`,
      fix: m[1] === 'http_origin'
        ? `Do not use \`if\`. Allow-list exact origins with a map and echo the match back:  map $http_origin $cors_origin { default ""; "https://app.example.com" $http_origin; }  add_header Access-Control-Allow-Origin $cors_origin${alwaysOk ? ' always' : ''};  If you keep a regex, use  ${betterRegex(regex, m[1])}`
        : `Anchor and end the host:  ${betterRegex(regex, m[1])}  (or use valid_referers with server_names and exact hosts).`,
    });
  }
  for (const x of all.filter((y) => y.node.name === 'valid_referers')) {
    const a = x.node.args;
    if (a.includes('none')) {
      sec({ id: 'sec-nginx-referers-none', severity: 'info', ...where(x), title: 'valid_referers accepts requests with no Referer ("none")', detail: 'Anything that omits the Referer header (curl, scripts, privacy settings, a page opened from a https->http link) passes the check, so it does not stop hotlinking or CSRF-style abuse by itself. It is fine only when direct visits must work.', fix: 'Remove `none` if the resource must never be fetched without a Referer; keep it only for content that is allowed to be linked directly, and do not use this check as an access control.' });
    }
    for (const e of a.filter((y) => /^~/.test(y))) {
      const re = e.slice(1); const bare = re.replace(/\\./g, '');
      const probs = [];
      if (!/^\^/.test(re) && !/^\.\*\\?\./.test(re) && !/^\(\^|^\(\.\*?\\\./.test(re)) probs.push('not anchored with ^');
      if (/[A-Za-z0-9-]\.[A-Za-z]{2,}/.test(bare)) probs.push('a dot is not escaped');
      if (!/(\\?\/|\$|\))['"]?$/.test(re)) probs.push('it does not end the host');
      if (probs.length) sec({ id: 'sec-nginx-referers-none', ...where(x), title: `valid_referers regex "${e}" is too loose (${probs.join(', ')})`, detail: 'valid_referers matches this regex against the Referer without the scheme, so a lookalike host such as allowed.example.evil.com or evil.com/allowed.example can pass.', fix: 'Prefer plain names (`server_names`, `example.com`, `*.example.com`). If a regex is needed: `~^example\\.com(/|$)` or `~^([a-z0-9-]+\\.)?example\\.com(/|$)`.' });
    }
  }

  // ---- 5. header values written over several lines ---------------------------------------------------------------------
  for (const x of all.filter((y) => HEADER_SINKS.has(y.node.name))) {
    const a = x.node.args; const isMore = /^more_/.test(x.node.name);
    if (!a.some((v, i) => /\n/.test(v) && (!isMore || (/^[^\s:]+:/.test(v) && !/^-[ts]$/.test(a[i - 1] || ''))))) continue;
    sec({
      id: 'sec-nginx-multiline-header', ...where(x),
      title: `${x.node.name} ${a[0] && !/\n/.test(a[0]) ? a[0] : 'value'} is written over several lines`,
      detail: 'The line breaks and the indentation are part of the header value that is sent. Obsolete line folding is rejected or mangled by many clients and proxies, and for Content-Security-Policy it can invalidate the policy.',
      fix: `Put the value on one line (join the parts with a single space)${alwaysOk && x.node.name === 'add_header' ? ', and add `always` so it is also sent on error responses' : ''}.`,
    });
  }
}

module.exports = { securityNginx, groupsOf };

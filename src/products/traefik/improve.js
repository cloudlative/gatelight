'use strict';
/**
 * Config Doctor for Traefik: rules that rewrite the YAML / TOML files (comment-preserving, line-based edits) or give
 * advice where a rewrite is risky. Version-aware (target from the KB); running it again on its own output proposes
 * no new automatic change.
 */
const K = require('./kb');
const M = require('./model');
const E = require('./edit');
const rules = require('./rules');
const YAML = require('./yaml');

const { getCI, pick, realKey, isObj, arr, truthy } = M;
const SEC_MW = 'security-headers';
const COMPRESS_MW = 'compress';

function improve({ files, version } = {}) {
  const list = M.normalizeFiles(files || []);
  const tv = K.resolveVersion(version);
  const minor = tv.minor; const major = tv.major;
  const gte = (m) => K.MINORS.indexOf(minor) >= K.MINORS.indexOf(m);
  const docs = (topic, anchor) => K.docsUrl(topic, major, anchor);
  const cfg = M.load(list);
  const { sections } = M.buildModel(cfg, { syntax: major === '2' ? 'v2' : undefined });
  const g = sections[0].traefik;
  const changes = []; let seq = 0;
  const st = cfg.static; const sd = st ? st.data : null;
  const parsedByName = new Map(cfg.parsed.map((p) => [p.name, p]));
  const dynFiles = cfg.parsed.filter((p) => p.kind === 'dynamic');
  const items = (k) => [...(cfg.items[k] || new Map()).values()];
  const fileItems = (k) => items(k).filter((it) => it.provider === 'file');

  /** A change; ops edit files by path when render() runs them. */
  const add = (c) => changes.push({ key: `${c.rule}:${++seq}`, auto: true, on: true, severity: 'medium', ...c, ops: c.ops || [] });
  const advice = (c) => add({ ...c, auto: false, on: false, ops: [] });
  const op = (kind, file, text, before, run) => ({ kind, file, text, before, run });
  const setOp = (file, segs, value, before) => op(before === undefined ? 'add' : 'mod', file, `${segs.join('.')}: ${E.yamlValue(value)}`, before === undefined ? undefined : `${segs.join('.')}: ${before}`, (t) => E.set(file, t, segs, value));
  const renameOp = (file, segs, to) => op('mod', file, `${[...segs.slice(0, -1), to].join('.')}`, segs.join('.'), (t) => E.renameKey(file, t, segs, to));
  const delOp = (file, segs) => op('del', file, undefined, segs.join('.'), (t) => E.del(file, t, segs));
  const appendOp = (file, segs, item) => op('add', file, `${segs.join('.')} += ${item}`, undefined, (t) => E.append(file, t, segs, item));
  const fromFlags = st && st.fromFlags;
  const staticEditable = st && !fromFlags;
  const stKey = (...keys) => { const out = []; let o = sd; for (const k of keys) { const rk = realKey(o, k) || k; out.push(rk); o = getCI(o, k); } return out; };

  // ---- entryPoints: HTTP -> HTTPS redirection --------------------------------------------------------------------
  if (sd && gte('2.2')) {
    const eps = getCI(sd, 'entryPoints') || {};
    const port = (ep) => M.parseAddress(getCI(ep || {}, 'address')).port;
    const httpsEp = Object.entries(eps).find(([n, ep]) => port(ep) === '443' || /^(websecure|https)$/i.test(n));
    for (const [n, ep] of Object.entries(eps)) {
      if (!(port(ep) === '80' || /^(web|http)$/i.test(n)) || !httpsEp || pick(ep || {}, 'http', 'redirections')) continue;
      const line = YAML.lineOf(st.lines, stKey('entryPoints', n)) || 1;
      const base = [...stKey('entryPoints', n), 'http', 'redirections', 'entryPoint'];
      const c = { rule: 'tfk-https-redirect', category: 'security', severity: 'medium', title: `Redirect entryPoint "${n}" to HTTPS`, section: `entryPoints.${n}`, line, file: st.file, docs: docs('entrypoints', 'redirection'),
        why: `Plain-HTTP requests on "${n}" are served (or answered 404) instead of being sent to "${httpsEp[0]}". An entryPoint redirection applies to every router of the entryPoint at once; ACME HTTP challenges keep working (they are answered before the redirection).` };
      // routers that serve this entryPoint on purpose (anything but a redirect to https) would become unreachable
      const fe = sections.find((x) => x.type === 'frontend' && x.name === n);
      const content = fe ? fe.routes.filter((r) => r.proto === 'http' && !r.internal && !(r.transforms || []).some((t) => t.action === 'redirect' && /^https/.test(String(t.args[t.args.length - 1] || '')))) : [];
      if (content.length) advice({ ...c, why: `${c.why} Not rewritten automatically: router${content.length > 1 ? 's' : ''} ${[...new Set(content.map((r) => r.router))].slice(0, 4).join(', ')} serve${content.length > 1 ? '' : 's'} this entryPoint on purpose and would only be reachable over HTTPS afterwards.` });
      else if (staticEditable) add({ ...c, ops: [setOp(st.file, [...base, 'to'], httpsEp[0]), setOp(st.file, [...base, 'scheme'], 'https')] });
      else advice({ ...c, why: `${c.why} Add --entryPoints.${n}.http.redirections.entryPoint.to=${httpsEp[0]} and --entryPoints.${n}.http.redirections.entryPoint.scheme=https to the command line.` });
    }
  }

  // ---- api.insecure ---------------------------------------------------------------------------------------------------
  const api = sd ? getCI(sd, 'api') : undefined;
  if (isObj(api) && truthy(getCI(api, 'insecure'))) {
    const c = { rule: 'tfk-api-insecure', category: 'security', severity: 'high', title: 'Stop serving the API / dashboard without authentication', section: 'api', line: g.apiLine || 1, file: st.file, docs: docs('api'),
      why: '`api.insecure: true` publishes the API and dashboard on the "traefik" entryPoint (:8080) without any authentication. After this change publish `api@internal` through a router with a basicAuth / forwardAuth middleware (see the dashboard example in the docs).' };
    if (staticEditable) add({ ...c, ops: [setOp(st.file, stKey('api', 'insecure'), false, 'true')] }); else advice(c);
  }

  // ---- providers.docker.exposedByDefault -------------------------------------------------------------------------------
  const docker = sd ? pick(sd, 'providers', 'docker') : undefined;
  if (docker !== undefined && (getCI(docker || {}, 'exposedByDefault') === undefined || truthy(getCI(docker || {}, 'exposedByDefault'))) && !getCI(docker || {}, 'constraints')) {
    const c = { rule: 'tfk-exposed-by-default', category: 'security', severity: 'medium', on: false, title: 'Only publish containers that opt in (exposedByDefault: false)', section: 'providers.docker', line: g.docker && g.docker.line, file: st.file, docs: docs('docker'),
      why: 'With the default `exposedByDefault: true` every container on the host gets a router. Turn it off and add `traefik.enable=true` to the containers you publish - containers without that label disappear from Traefik, which is why this change is not switched on by default.' };
    if (staticEditable && isObj(docker)) add({ ...c, ops: [setOp(st.file, [...stKey('providers', 'docker'), 'exposedByDefault'], false, getCI(docker, 'exposedByDefault') === undefined ? undefined : 'true')] });
    else advice(c);
  }

  // ---- logs -----------------------------------------------------------------------------------------------------------
  if (staticEditable && getCI(sd, 'accessLog') === undefined) add({ rule: 'tfk-access-log', category: 'observability', severity: 'low', title: 'Write an access log (JSON)', section: 'accessLog', line: 1, file: st.file, docs: docs('accessLogs'),
    why: 'Without accessLog there is no record of requests, status codes, routers and backend timings (GateLight Traffic Stats reads it). JSON keeps every field; add filePath to write to a file instead of stdout.', ops: [setOp(st.file, ['accessLog', 'format'], 'json')] });
  const level = sd ? pick(sd, 'log', 'level') : undefined;
  if (staticEditable && level && /^(debug|trace)$/i.test(String(level))) add({ rule: 'tfk-log-level', category: 'observability', severity: 'low', title: 'Log at INFO in production', section: 'log', line: g.logLine || 1, file: st.file, docs: docs('logs'), why: `log.level ${level} is very verbose, costs CPU and can include request details.`, ops: [setOp(st.file, stKey('log', 'level'), 'INFO', String(level))] });

  // ---- TLS options -------------------------------------------------------------------------------------------------------
  const tlsRouters = items('http.routers').filter((it) => getCI(it.def, 'tls') !== undefined && getCI(it.def, 'tls') !== false);
  const tlsInUse = tlsRouters.length || Object.values((sd && getCI(sd, 'entryPoints')) || {}).some((ep) => pick(ep || {}, 'http', 'tls'));
  const tlsFile = (cfg.tls.options.size ? [...cfg.tls.options.values()][0].file : null) || (dynFiles[0] && dynFiles[0].name) || null;
  for (const o of cfg.tls.options.values()) {
    const mv = getCI(o.def, 'minVersion');
    if (/^VersionTLS1[01]$/.test(String(mv || ''))) add({ rule: 'tfk-tls-min', category: 'security', severity: 'high', title: `TLS options "${o.name}": require TLS 1.2 or newer`, section: `tls.options.${o.name}`, line: o.lineOf(['minVersion']) || o.line, file: o.file, docs: docs('tls'), why: 'TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail compliance scans; every supported browser speaks TLS 1.2.', ops: [setOp(o.file, ['tls', 'options', o.name, realKey(o.def, 'minVersion')], 'VersionTLS12', mv)] });
  }
  if (tlsInUse && parsedByName.get(tlsFile)) {
    const def = cfg.tls.options.get('default');
    if (!def) add({ rule: 'tfk-tls-default', category: 'security', severity: 'medium', title: 'Pin the default TLS policy (TLS 1.2+)', section: 'tls.options.default', line: 1, file: tlsFile, docs: docs('tls'), why: 'Without a `default` TLS option the minimum version depends on the Traefik / Go release. Setting minVersion VersionTLS12 documents and fixes the policy for every router that does not pick other options.', ops: [setOp(tlsFile, ['tls', 'options', 'default', 'minVersion'], 'VersionTLS12')] });
    else if (getCI(def.def, 'minVersion') === undefined) add({ rule: 'tfk-tls-default', category: 'security', severity: 'medium', title: 'Set minVersion on the default TLS options', section: 'tls.options.default', line: def.line, file: def.file, docs: docs('tls'), why: 'The default TLS options have no minVersion, so the minimum depends on the Traefik / Go release.', ops: [setOp(def.file, ['tls', 'options', 'default', 'minVersion'], 'VersionTLS12')] });
    const d2 = cfg.tls.options.get('default');
    if (!d2 || !truthy(getCI(d2.def, 'sniStrict'))) add({ rule: 'tfk-sni-strict', category: 'security', severity: 'low', on: false, title: 'Reject TLS clients without a matching SNI (sniStrict)', section: 'tls.options.default', line: d2 ? d2.line : 1, file: d2 ? d2.file : tlsFile, docs: docs('tls', 'strict-sni-checking'), why: 'With sniStrict Traefik refuses handshakes whose server name matches no certificate instead of answering with the default certificate - scanners learn less. Very old clients without SNI are refused, so this is off by default.', ops: [setOp(d2 ? d2.file : tlsFile, ['tls', 'options', 'default', 'sniStrict'], true)] });
  } else if (tlsInUse && !cfg.tls.options.size) advice({ rule: 'tfk-tls-default', category: 'security', severity: 'medium', title: 'Pin the default TLS policy (TLS 1.2+)', section: 'tls.options.default', line: 1, file: (st && st.file) || null, docs: docs('tls'), why: 'Add `tls.options.default.minVersion: VersionTLS12` to a dynamic configuration file (TLS options cannot be set in the static configuration).' });

  // ---- services: health checks ----------------------------------------------------------------------------------------
  for (const it of fileItems('http.services')) {
    const lb = getCI(it.def, 'loadBalancer');
    if (!isObj(lb) || arr(getCI(lb, 'servers')).length < 2 || getCI(lb, 'healthCheck') !== undefined) continue;
    const base = ['http', 'services', it.name, realKey(it.def, 'loadBalancer'), 'healthCheck'];
    add({ rule: 'tfk-healthcheck', category: 'reliability', severity: 'medium', title: `Health-check the servers of "${it.name}"`, section: `http.services.${it.name}`, line: it.line, file: it.file, docs: docs('services', 'health-check'),
      why: `"${it.name}" balances ${arr(getCI(lb, 'servers')).length} servers without active health checks, so a dead server keeps receiving its share of requests. Adjust the path to an endpoint that answers 2xx/3xx when the application is healthy.`,
      ops: [setOp(it.file, [...base, 'path'], '/'), setOp(it.file, [...base, 'interval'], '10s'), setOp(it.file, [...base, 'timeout'], '3s')] });
  }

  // ---- insecureSkipVerify: advice (needs the CA) ---------------------------------------------------------------------
  for (const t of g.serversTransports || []) if (t.insecureSkipVerify) advice({ rule: 'tfk-skip-verify', category: 'security', severity: 'medium', title: `Verify backend certificates (${t.static ? 'serversTransport' : t.name})`, section: t.static ? 'serversTransport' : `http.serversTransports.${t.name}`, line: t.line, file: t.file, docs: docs('serversTransport'), why: 'insecureSkipVerify accepts any certificate from the backend. Trust the backend CA with `rootCAs` (and serverName if the certificate name differs), then remove insecureSkipVerify.' });

  // ---- security headers + compression on the HTTPS entryPoint ---------------------------------------------------------
  const mwTypesOn = (refs) => refs.map((r) => M.qualify(r, 'file')).map((q) => (cfg.items['http.middlewares'] || new Map()).get(`${q.name}@${q.provider}`)).filter(Boolean)
    .flatMap((it) => { const type = Object.keys(it.def)[0] || ''; return type.toLowerCase() === 'chain' ? mwTypesOn(arr(pick(it.def, 'chain', 'middlewares'))) : [{ type: type.toLowerCase(), o: it.def[type] || {} }]; });
  if (sd && staticEditable && dynFiles.length) {
    const eps = getCI(sd, 'entryPoints') || {};
    const tlsEp = Object.entries(eps).find(([n, ep]) => pick(ep || {}, 'http', 'tls') || M.parseAddress(getCI(ep || {}, 'address')).port === '443' || /^(websecure|https)$/i.test(n));
    if (tlsEp) {
      const [epName, ep] = tlsEp;
      const epMw = arr(pick(ep || {}, 'http', 'middlewares'));
      const routersOn = items('http.routers').filter((it) => arr(getCI(it.def, 'entryPoints')).includes(epName) || !arr(getCI(it.def, 'entryPoints')).length);
      const covered = (pred) => mwTypesOn(epMw).some(pred) || (routersOn.length && routersOn.every((r) => mwTypesOn(arr(getCI(r.def, 'middlewares')).map((x) => (String(x).includes('@') ? x : `${x}@${r.provider}`))).some(pred)));
      const mwFile = (fileItems('http.middlewares')[0] || {}).file || dynFiles[0].name;
      const mwExists = (n) => (cfg.items['http.middlewares'] || new Map()).has(`${n}@file`);
      const epSegs = [...stKey('entryPoints', epName), 'http', 'middlewares'];
      const hsts = (x) => x.type === 'headers' && getCI(x.o, 'stsSeconds');
      if (!covered(hsts)) {
        const name = mwExists(SEC_MW) ? `${SEC_MW}-gl` : SEC_MW;
        const base = ['http', 'middlewares', name, 'headers'];
        add({ rule: 'tfk-security-headers', category: 'security', severity: 'medium', title: `Send HSTS and security headers on "${epName}"`, section: `entryPoints.${epName}`, line: 1, file: mwFile, docs: K.middlewareDocs('headers', major),
          why: 'Strict-Transport-Security makes browsers use HTTPS only; nosniff stops MIME sniffing; a referrer policy keeps URLs (and tokens in them) from leaking. Attached to the entryPoint so every router on it gets them.',
          ops: [setOp(mwFile, [...base, 'stsSeconds'], 31536000), setOp(mwFile, [...base, 'stsIncludeSubdomains'], true), setOp(mwFile, [...base, 'contentTypeNosniff'], true), setOp(mwFile, [...base, 'referrerPolicy'], 'strict-origin-when-cross-origin'), appendOp(st.file, epSegs, `${name}@file`)] });
      }
      if (!covered((x) => x.type === 'compress')) {
        const name = mwExists(COMPRESS_MW) ? `${COMPRESS_MW}-gl` : COMPRESS_MW;
        add({ rule: 'tfk-compress', category: 'performance', severity: 'low', title: `Compress responses on "${epName}"`, section: `entryPoints.${epName}`, line: 1, file: mwFile, docs: K.middlewareDocs('compress', major),
          why: 'The compress middleware gzips (and in newer releases brotli/zstd-encodes) text responses when the client accepts it, typically saving 70-90 % on HTML, CSS, JS and JSON.',
          ops: [setOp(mwFile, ['http', 'middlewares', name, 'compress'], {}), appendOp(st.file, epSegs, `${name}@file`)] });
      }
    }
  }

  // ---- v2 -> v3 (and 2.11) migrations -----------------------------------------------------------------------------------
  if (gte('2.11')) {
    for (const it of [...items('http.middlewares'), ...items('tcp.middlewares')]) {
      const k = realKey(it.def, 'ipWhiteList'); if (!k) continue;
      const proto = it.kind.split('.')[0];
      if (it.provider === 'file') add({ rule: 'tfk-ipallowlist', category: 'compatibility', severity: major === '3' ? 'medium' : 'low', title: `Rename ipWhiteList to ipAllowList ("${it.name}")`, section: `${proto}.middlewares.${it.name}`, line: it.line, file: it.file, docs: K.docsUrl('migrationV3', '3'), why: 'ipWhiteList is deprecated since v2.11 and renamed ipAllowList in v3 (same options).', ops: [renameOp(it.file, [proto, 'middlewares', it.name, k], 'ipAllowList')] });
      else if (it.provider === 'docker') add({ rule: 'tfk-ipallowlist', category: 'compatibility', severity: 'low', title: `Rename the ipwhitelist labels to ipallowlist ("${it.name}")`, section: `${proto}.middlewares.${it.name}`, line: it.line, file: it.file, docs: K.docsUrl('migrationV3', '3'), why: 'ipWhiteList is deprecated since v2.11 and renamed ipAllowList in v3.', ops: [op('mod', it.file, 'ipallowlist', 'ipwhitelist', (t) => t.split('\n').map((l) => (/traefik\.(http|tcp)\.middlewares\.[^.=:]+\.ipwhitelist\./i.test(l) ? l.replace(/(\.middlewares\.[^.=:]+\.)ipwhitelist\./i, '$1ipallowlist.') : l)).join('\n'))] });
    }
  }
  if (major === '3') {
    if (sd && getCI(sd, 'pilot') !== undefined && staticEditable) add({ rule: 'tfk-v3-pilot', category: 'compatibility', severity: 'high', title: 'Remove the pilot section (Traefik v3 refuses to start with it)', section: 'pilot', line: YAML.lineOf(st.lines, stKey('pilot')) || 1, file: st.file, docs: K.docsUrl('migrationV3', '3'), why: 'Traefik Pilot was shut down in 2022; v3 rejects the configuration.', ops: [delOp(st.file, stKey('pilot'))] });
    for (const p of ['marathon', 'rancher']) if (sd && pick(sd, 'providers', p) !== undefined) advice({ rule: 'tfk-v3-provider', category: 'compatibility', severity: 'high', title: `providers.${p} was removed in v3`, section: `providers.${p}`, line: 1, file: st.file, docs: K.docsUrl('migrationV3', '3'), why: 'v3 does not start with this provider configured. Move the services to another provider (docker, file, kubernetes, ...) and remove the section.' });
    if (sd && pick(sd, 'providers', 'docker', 'swarmMode') !== undefined) advice({ rule: 'tfk-v3-swarm', category: 'compatibility', severity: 'high', title: 'providers.docker.swarmMode moved to providers.swarm in v3', section: 'providers.docker', line: 1, file: st.file, docs: K.docsUrl('migrationV3', '3'), why: 'Move the Swarm settings to a `providers.swarm` section.' });
    const defaultSyntax = String((sd && pick(sd, 'core', 'defaultRuleSyntax')) || 'v3');
    for (const it of [...items('http.routers'), ...items('tcp.routers')]) {
      const rule = getCI(it.def, 'rule'); if (!rule) continue;
      const syntax = String(getCI(it.def, 'ruleSyntax') || defaultSyntax);
      const tree = (() => { try { return rules.parseRule(String(rule)); } catch { return null; } })();
      if (!tree) continue;
      const v2Only = rules.matchersOf(tree).some((m) => /^(Headers|HeadersRegexp|HostHeader)$/.test(m.name) || (m.args.length > 1 && !/^(Headers|HeadersRegexp|Header|HeaderRegexp|Query|QueryRegexp)$/.test(m.name)));
      const needs = syntax === 'v2' || v2Only;
      if (!needs) continue;
      const v3 = rules.migrateRule(String(rule));
      const proto = it.kind.split('.')[0];
      const c = { rule: 'tfk-v3-rule', category: 'compatibility', severity: v2Only && syntax !== 'v2' ? 'high' : 'low', title: `Router "${it.name}": use the v3 rule syntax`, section: `${proto}.routers.${it.name}`, line: it.lineOf(['rule']) || it.line, file: it.file, docs: K.docsUrl('migrationV3', '3'),
        why: v2Only && syntax !== 'v2' ? 'This rule uses v2 matchers but is parsed with the v3 syntax (the default in v3), so the router is rejected.' : 'The router is parsed with the deprecated v2 syntax (ruleSyntax / core.defaultRuleSyntax v2), which goes away in the next major release.' };
      if (v3 && it.provider === 'file' && !/\n/.test(String(rule))) {
        const ops = [setOp(it.file, [proto, 'routers', it.name, realKey(it.def, 'rule')], v3, String(rule))];
        if (getCI(it.def, 'ruleSyntax') !== undefined) ops.push(delOp(it.file, [proto, 'routers', it.name, realKey(it.def, 'ruleSyntax')]));
        add({ ...c, why: `${c.why} Rewritten mechanically: Headers->Header, HostHeader->Host, one value per matcher joined with ||.`, ops });
      } else if (v3 && it.provider === 'docker') {
        add({ ...c, why: `${c.why} Rewritten mechanically in the label.`, ops: [op('mod', it.file, `rule=${v3}`, `rule=${rule}`, (t) => { if (!t.includes(String(rule))) throw new E.EditError('rule text not found'); return t.replace(String(rule), v3); })] });
      } else advice({ ...c, why: `${c.why} It uses a "{name:regex}" template, HostRegexp or Query, which need a manual rewrite (Go regexps, Query(\`key\`, \`value\`)).` });
    }
    for (const it of items('http.middlewares')) {
      const h = getCI(it.def, 'headers');
      const old = isObj(h) ? ['sslRedirect', 'sslTemporaryRedirect', 'sslHost', 'sslForceHost', 'featurePolicy'].filter((k) => getCI(h, k) !== undefined) : [];
      if (old.length) advice({ rule: 'tfk-v3-headers', category: 'compatibility', severity: 'medium', title: `Headers middleware "${it.name}" uses ${old.join(', ')}`, section: `http.middlewares.${it.name}`, line: it.line, file: it.file, docs: K.docsUrl('migrationV3', '3'), why: 'These options are deprecated and listed as removed in the v2 to v3 migration guide: use an entryPoint redirection or the redirectScheme middleware instead of sslRedirect, and permissionsPolicy instead of featurePolicy.' });
    }
  }

  const catRank = { security: 0, reliability: 1, compatibility: 2, performance: 3, observability: 4, hygiene: 5 };
  changes.sort((a, b) => catRank[a.category] - catRank[b.category]);
  return {
    product: 'traefik', target: tv.version, versionKnown: Boolean(version), changes,
    normalized: list.map((f) => ({ name: f.name, content: f.content })),
    render(enabled) {
      const out = new Map(list.map((f) => [f.name, f.content]));
      for (const c of changes) {
        if (!c.auto || !enabled(c)) continue;
        // a change is applied whole or not at all
        const snapshot = new Map(out);
        try {
          for (const o of c.ops) { const before = out.get(o.file); if (before === undefined) throw new E.EditError(`file ${o.file} not found`); out.set(o.file, o.run(before)); }
        } catch (e) { for (const [k, v] of snapshot) out.set(k, v); c.failed = e.message; }
      }
      return list.map((f) => ({ name: f.name, content: out.get(f.name) }));
    },
  };
}

module.exports = { improve };

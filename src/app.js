'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const { Registry } = require('./poller');
const { HistoryStore } = require('./history');
const { Notifier } = require('./alerts');
const { parseConfig, redactConfig } = require('./haproxyConfig');
const { parseNginxText, parseNginxFiles } = require('./nginxConfig');
const { auditNginx } = require('./nginxAudit');
const { detectType } = require('./detect');
const { parseStatsCsv, statusClass } = require('./statsParser');
const { auditConfig, summarize } = require('./audit');
const { validateConfig, versions: kbVersions } = require('./validate');
const { detect: detectVersion } = require('./validate/version');
const { renderMetrics } = require('./metrics');
const { securityHeaders, rateLimit } = require('./security');
const { createAuth } = require('./login');
const { sessionMiddleware } = require('./session');
const { InstanceStore, validateInput, cleanFiles } = require('./store');
const { normalizeInstance, slug } = require('./settings');
const { DRIVERS } = require('./drivers');
const log = require('./logger');

const PUBLIC = path.join(__dirname, '..', 'public');
const VIS_DIR = path.dirname(require.resolve('vis-network/standalone/umd/vis-network.min.js'));

function createApp(settings) {
  const app = express();
  app.disable('x-powered-by');
  if (settings.trustProxy) app.set('trust proxy', true);

  const notifier = new Notifier(settings.alerts.webhookUrl ? settings.alerts : {});
  const history = settings.history.enabled ? HistoryStore.open(settings.history.file || path.join(settings.ui.dir, 'history.db'), settings.history, log) : null;
  const registry = new Registry(settings, notifier, history);

  app.use(securityHeaders);
  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));
  const loginAuth = createAuth(settings.auth, log, settings.ui.dir);
  app.use(loginAuth.router);
  app.use(loginAuth.middleware);
  app.use('/api', sessionMiddleware, rateLimit({ max: 600 }), (_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  // --- Static assets (explicit allowlist: nothing outside /public is served) ---
  app.use('/vendor/vis-network.min.js', (_req, res) => res.sendFile(path.join(VIS_DIR, 'vis-network.min.js')));
  // The UI files change on every release and must always match each other, so the browser revalidates them (cheap 304s via ETag)
  // instead of reusing a mix of old and new files for a few minutes after an upgrade. Images and fonts may be cached.
  app.use(express.static(PUBLIC, {
    index: 'index.html', maxAge: '1h',
    setHeaders: (res, file) => { if (/\.(html|js|css)$/.test(file)) res.setHeader('Cache-Control', 'no-cache'); },
  }));

  app.get('/readyz', (_req, res) => {
    const ready = registry.list().filter((i) => !i.managed || settings.ui.shared).every((i) => i.ok !== null);
    res.status(ready ? 200 : 503).json({ ready });
  });

  app.get('/metrics', (_req, res) => {
    const open = [...registry.pollers].filter(([, p]) => !p.instance.managed || settings.ui.shared);
    res.type('text/plain; version=0.0.4').send(renderMetrics({ pollers: new Map(open) }));
  });

  // --- API ---------------------------------------------------------------
  const api = express.Router();
  api.get('/meta', (req, res) => res.json({
    authUser: req.authUser || null,
    authExp: req.authExp || null,
    sessionHours: settings.auth.sessionHours,
    version: require('../package.json').version,
    authEnabled: settings.auth.enabled,
    alertsEnabled: notifier.enabled,
    demo: settings.demo,
    historyPoints: settings.historyPoints,
    features: settings.features,
    canManage: settings.ui.enabled,
    hostsRestricted: settings.ui.allowedHosts.length > 0,
    types: [...new Set(settings.instances.map((i) => i.type))],
  }));

  api.get('/instances', (req, res) => {
    if (ui.enabled && !ui.shared) { // connections saved before ownership existed go to the first browser that asks
      let claimed = false;
      for (const p of registry.pollers.values()) if (p.instance.managed && !p.instance.owner) { p.instance.owner = req.owner; claimed = true; }
      if (claimed) { persist(); log.info('assigned legacy UI connections to the first browser that opened GateLight'); }
    }
    const list = registry.list().filter((i) => canSee(registry.get(i.id).instance, req));
    list.forEach((i) => touch(registry.get(i.id)));
    res.json({ instances: list });
  });

  // --- Instances managed from the UI (opt-in: ALLOW_UI_INSTANCES=true) ---------------------------
  const ui = settings.ui;
  const store = new InstanceStore(ui.dir);
  // Connections added in the UI belong to the browser (cookie) that added them, unless UI_INSTANCES_SHARED=true.
  const canSee = (inst, req) => !inst.managed || ui.shared || inst.owner === req.owner;
  const touch = (p) => { p.lastSeen = Date.now(); };
  for (const p of registry.pollers.values()) touch(p);
  // Drop connections nobody has opened for a while (their stored credentials go with them).
  const sweep = setInterval(() => {
    const cutoff = Date.now() - ui.ttlDays * 86400000; let dropped = 0;
    for (const [id, p] of registry.pollers) if (p.instance.managed && (p.lastSeen || 0) < cutoff) { registry.remove(id); dropped++; }
    if (dropped) { persist(); log.info('removed idle UI connections', { count: dropped, ttlDays: ui.ttlDays }); }
  }, 3600000);
  sweep.unref();
  const validateCtx = { features: settings.features, allowedHosts: ui.allowedHosts };
  const storedKeys = ['owner', 'type', 'name', 'statsUrl', 'plusApiUrl', 'socket', 'username', 'password', 'insecureTls', 'configFiles', 'tags'];
  const toDef = (inst) => ({ id: inst.id, ...Object.fromEntries(storedKeys.filter((k) => inst[k] != null && inst[k] !== false && inst[k] !== '').map((k) => [k, inst[k]])), ...(inst.type === 'nginx' ? { probe: Boolean(inst.probe) } : {}) });
  const persist = () => store.save([...registry.pollers.values()].filter((p) => p.instance.managed).map((p) => toDef(p.instance)));
  const manage = [
    (_req, res, next) => (ui.enabled ? next() : res.status(403).json({ error: 'Adding instances from the UI is disabled. Start GateLight with ALLOW_UI_INSTANCES=true.' })),
    (req, res, next) => (req.is('application/json') ? next() : res.status(415).json({ error: 'Content-Type must be application/json' })),
    express.json({ limit: '3mb' }),
  ];
  // Names are unique among the instances a browser can see, so the dashboard never lists two with the same label.
  const nameTaken = (name, req, exceptId) => [...registry.pollers.values()].some((p) => p.instance.id !== exceptId && canSee(p.instance, req) && p.instance.name.trim().toLowerCase() === name.trim().toLowerCase());
  const build = (def, id) => normalizeInstance({ ...def, id, managed: true }, 0, null, settings.defaults, new Set());
  const safeDef = (inst) => ({
    id: inst.id, type: inst.type, name: inst.name, statsUrl: inst.statsUrl, plusApiUrl: inst.plusApiUrl, socket: inst.socket,
    username: inst.username, hasPassword: Boolean(inst.password), insecureTls: inst.insecureTls,
    configFiles: (inst.configFiles || []).map((f) => f.name), probe: inst.probe, configOnly: !DRIVERS[inst.type].hasSource(inst),
  });

  // Try a connection without saving anything.
  api.post('/instances/test', rateLimit({ max: 20 }), ...manage, async (req, res) => {
    try {
      const found = req.body && req.body.id ? registry.get(String(req.body.id)) : null;
      const existing = found && canSee(found.instance, req) ? found.instance : null;
      const def = validateInput(req.body, validateCtx, existing && existing.managed ? existing : null);
      const inst = build(def, 'connection-test');
      inst.timeoutMs = Math.min(inst.timeoutMs, 8000);
      const { rows, info } = await DRIVERS[inst.type].collect(inst, { sections: [] }, {});
      const count = (k) => rows.filter((r) => r.kind === k).length;
      return res.json({ ok: true, version: (info && info.version) || null, frontends: count('frontend'), backends: count('backend'), servers: count('server') });
    } catch (e) {
      return res.json({ ok: false, error: e.message });
    }
  });

  api.post('/instances', rateLimit({ max: 20 }), ...manage, (req, res) => {
    try {
      const def = validateInput(req.body, validateCtx, null);
      if (nameTaken(def.name, req)) return res.status(409).json({ error: `An instance named "${def.name}" already exists. Pick a different name.` });
      let id = slug(def.name);
      while (registry.get(id)) id += '-x';
      const inst = build({ ...def, owner: req.owner }, id);
      touch(registry.add(inst));
      persist();
      return res.status(201).json({ id });
    } catch (e) { return res.status(400).json({ error: e.message }); }
  });

  api.get('/instances/:id/definition', (req, res) => {
    const p = registry.get(req.params.id);
    if (!p || !p.instance.managed || !canSee(p.instance, req)) return res.status(404).json({ error: 'Not a UI-managed instance' });
    return res.json(safeDef(p.instance));
  });

  api.put('/instances/:id', rateLimit({ max: 20 }), ...manage, (req, res) => {
    const p = registry.get(req.params.id);
    if (!p || !p.instance.managed || !canSee(p.instance, req)) return res.status(404).json({ error: 'Not a UI-managed instance' });
    try {
      const def = validateInput(req.body, validateCtx, p.instance);
      if (nameTaken(def.name, req, p.instance.id)) return res.status(409).json({ error: `An instance named "${def.name}" already exists. Pick a different name.` });
      touch(registry.add(build({ ...def, owner: p.instance.owner || req.owner }, p.instance.id)));
      persist();
      return res.json({ id: p.instance.id });
    } catch (e) { return res.status(400).json({ error: e.message }); }
  });

  // Replace just the config of an existing connection (people edit configs often). Everything else, including live
  // credentials and traffic history of entities that still exist, is kept; entities that vanished are flushed by the next poll.
  api.put('/instances/:id/config', rateLimit({ max: 30 }), ...manage, async (req, res) => {
    const p = registry.get(req.params.id);
    if (!p || !p.instance.managed || !canSee(p.instance, req)) return res.status(404).json({ error: 'Not a UI-managed instance' });
    try {
      const b = req.body || {};
      let files = cleanFiles(b.configFiles);
      if (!files.length && typeof b.configText === 'string' && b.configText.trim()) files = cleanFiles([{ name: p.instance.type === 'nginx' ? 'nginx.conf' : 'haproxy.cfg', content: b.configText }]);
      if (!files.length) return res.status(400).json({ error: 'Provide the new config as files or pasted text' });
      const guess = detectType(files.map((f) => f.content).join('\n'));
      if (['haproxy', 'nginx'].includes(guess) && guess !== p.instance.type) return res.status(422).json({ error: `This looks like an ${guess === 'nginx' ? 'NGINX' : 'HAProxy'} config, but "${p.instance.name}" is ${p.instance.type === 'nginx' ? 'NGINX' : 'HAProxy'}. Upload it as a new instance instead.` });
      const next = DRIVERS[p.instance.type].loadConfig({ ...p.instance, configFiles: files }, null);
      if (next.error) return res.status(422).json({ error: next.error });
      const keys = (secs) => new Set((secs || []).flatMap((x) => [`${x.type} ${x.name}`, ...(x.servers || []).map((v) => `server ${x.name}/${v.name}`)]));
      const before = keys(p.configCache && p.configCache.sections); const after = keys(next.sections);
      p.instance.configFiles = files;
      await p.poll();
      persist(); touch(p);
      return res.json({
        ok: true, files: files.length,
        added: [...after].filter((k) => !before.has(k)), removed: [...before].filter((k) => !after.has(k)),
      });
    } catch (e) { return res.status(400).json({ error: e.message }); }
  });

  api.delete('/instances/:id', rateLimit({ max: 20 }), (req, res) => {
    if (!ui.enabled) return res.status(403).json({ error: 'Adding instances from the UI is disabled.' });
    const p = registry.get(req.params.id);
    if (!p || !p.instance.managed || !canSee(p.instance, req)) return res.status(404).json({ error: 'Not a UI-managed instance' });
    registry.remove(req.params.id);
    persist();
    return res.json({ ok: true });
  });

  const withInstance = (req, res, next) => {
    const p = registry.get(req.params.id);
    if (!p || !canSee(p.instance, req)) return res.status(404).json({ error: `Unknown instance "${req.params.id}"` });
    touch(p);
    req.poller = p;
    return next();
  };

  api.get('/instances/:id/snapshot', withInstance, (req, res) => {
    const snap = req.poller.snapshot;
    if (!snap) return res.status(503).json({ error: 'First poll has not completed yet' });
    return res.json(snap);
  });

  api.get('/instances/:id/events', withInstance, (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    res.json({ events: req.poller.events.slice(0, limit) });
  });

  api.get('/instances/:id/history-all', withInstance, (req, res) => {
    const kinds = String(req.query.kinds || 'frontend,backend,server').split(',').filter((k) => ['frontend', 'backend', 'server'].includes(k));
    const rangeMin = Math.min(Number(req.query.range) || 0, 60 * 24 * 14);
    const from = Number(req.query.from); const to = Number(req.query.to);
    const win = Number.isFinite(from) && Number.isFinite(to) && to - from >= 5000 && to - from <= 15 * 86400e3 ? { from, to } : null;
    const maxPts = Math.max(60, Math.min(Number(req.query.max) || 360, 720));
    res.json(req.poller.getAllHistory(kinds, Number(req.query.points) || undefined, rangeMin > 0 ? rangeMin * 60000 : 0, win, maxPts));
  });

  api.get('/instances/:id/history', withInstance, (req, res) => {
    const key = String(req.query.key || '');
    res.json({ key, points: req.poller.getHistory(key, Number(req.query.points) || undefined) });
  });

  api.post('/instances/:id/refresh', rateLimit({ max: 30 }), withInstance, async (req, res) => {
    await req.poller.poll();
    res.json({ ok: true, snapshotTs: req.poller.snapshot && req.poller.snapshot.ts });
  });

  // Offline analysis of uploaded/pasted configuration (no network fetches).
  //   body: { type?: 'auto'|'haproxy'|'nginx', config?: string, files?: [{name, content}], stats?: string }
  api.post('/analyze', express.json({ limit: '8mb' }), rateLimit({ max: 60 }), (req, res) => {
    const body = req.body || {};
    const files = Array.isArray(body.files) ? body.files.filter((f) => f && typeof f.content === 'string' && typeof f.name === 'string').slice(0, 300) : [];
    const text = typeof body.config === 'string' ? body.config : '';
    if (!files.length && !text.trim()) return res.status(400).json({ error: 'Provide "config" (string) or "files" ([{name, content}])' });

    // Separate an optional stats CSV from the config files.
    let stats = typeof body.stats === 'string' ? body.stats : '';
    const cfgFiles = files.filter((f) => { if (/\.csv$/i.test(f.name)) { stats = stats || f.content; return false; } return true; });
    const sample = cfgFiles.length ? cfgFiles.map((f) => f.content).join('\n') : text;
    let type = String(body.type || 'auto');
    if (type === 'auto') type = detectType(sample);
    if (!['haproxy', 'nginx'].includes(type)) return res.status(400).json({ error: `Unknown type "${type}"` });
    if (!settings.features[type]) return res.status(400).json({ error: `${type} support is disabled on this server (ENABLE_${type.toUpperCase()}=false)` });

    let sections; let findings; let outFiles; let rows = []; let notes = [];
    try {
      if (type === 'nginx') {
        const parsed = cfgFiles.length ? parseNginxFiles(cfgFiles) : parseNginxText(text);
        sections = parsed.sections; outFiles = parsed.files.map(({ name, raw }) => ({ name, raw })); notes = parsed.notes || [];
        findings = auditNginx(sections, { notes });
      } else {
        const f = cfgFiles.find((x) => /haproxy/i.test(x.name)) || cfgFiles[0];
        const raw = f ? f.content : text;
        sections = parseConfig(raw);
        outFiles = [{ name: f ? f.name.split('/').pop() : 'haproxy.cfg', raw: redactConfig(raw) }];
        rows = stats ? parseStatsCsv(stats).map((r) => ({ ...r, state: statusClass(r.status) })) : [];
        findings = auditConfig(sections, { runtime: { rows } }).map((x) => ({ ...x, file: outFiles[0].name }));
        if (cfgFiles.length > 1) notes.push({ file: outFiles[0].name, msg: `Multiple files uploaded; only ${outFiles[0].name} was analysed (HAProxy configs are single-file).` });
      }
    } catch (e) {
      return res.status(422).json({ error: `Could not parse configuration: ${e.message}` });
    }
    return res.json({
      type, notes,
      config: { files: outFiles, sections: sections.map(({ directives, ...rest }) => rest) },
      rows, findings, findingsSummary: summarize(findings),
    });
  });

  // Version-aware validation against the official HAProxy / NGINX documentation (knowledge bases in src/kb).
  //   POST body: { type?: 'auto'|'haproxy'|'nginx', version?: '2.8' | '1.24.0' | 'HAProxy version 2.8.5', config?: string, files?: [{name, content}], build?: 'nginx -V output' }
  api.get('/validate/versions', (_req, res) => res.json(kbVersions()));

  api.post('/validate', express.json({ limit: '8mb' }), rateLimit({ max: 60 }), (req, res) => {
    const body = req.body || {};
    const files = Array.isArray(body.files) ? body.files.filter((f) => f && typeof f.content === 'string' && typeof f.name === 'string').slice(0, 300) : [];
    const text = typeof body.config === 'string' ? body.config : '';
    if (!files.length && !text.trim()) return res.status(400).json({ error: 'Provide "config" (string) or "files" ([{name, content}])' });
    const cfgFiles = files.filter((f) => !/\.csv$/i.test(f.name));
    let type = String(body.type || 'auto');
    if (type === 'auto') type = detectType(cfgFiles.length ? cfgFiles.map((f) => f.content).join('\n') : text);
    if (!['haproxy', 'nginx'].includes(type)) return res.status(400).json({ error: `Unknown type "${type}"` });
    try {
      const out = validateConfig({ product: type, version: typeof body.version === 'string' ? body.version : null, config: text, files: cfgFiles, build: typeof body.build === 'string' ? body.build : undefined });
      return res.json(out);
    } catch (e) { return res.status(422).json({ error: `Could not validate configuration: ${e.message}` }); }
  });

  api.get('/instances/:id/validate', withInstance, rateLimit({ max: 30 }), (req, res) => {
    const p = req.poller; const type = p.instance.type;
    const cache = p.configCache;
    if (!cache || !cache.files || !cache.files.length) return res.status(404).json({ error: 'This instance has no configuration loaded to validate.' });
    const info = (p.snapshot && p.snapshot.info) || {};
    const detected = detectVersion(info.version);
    const version = typeof req.query.version === 'string' && req.query.version.trim() ? req.query.version.trim() : detected;
    try {
      const files = cache.files.map((f) => ({ name: f.name, content: f.raw }));
      const out = validateConfig({ product: type, version, config: type === 'haproxy' ? files[0].content : undefined, files: type === 'nginx' ? files : undefined, build: typeof req.query.build === 'string' ? req.query.build : undefined });
      return res.json({ ...out, detectedVersion: detected, runningVersionText: info.version || null });
    } catch (e) { return res.status(422).json({ error: `Could not validate configuration: ${e.message}` }); }
  });

  // Bundled, sanitised examples so people can try the tool without their own config.
  api.get('/examples/:type', (req, res) => {
    const t = req.params.type;
    if (!['haproxy', 'nginx'].includes(t)) return res.status(404).json({ error: 'Unknown example' });
    const root = path.join(__dirname, '..', 'examples', t);
    const out = [];
    const walk = (dir, prefix) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) walk(path.join(dir, e.name), `${prefix}${e.name}/`);
        else if (e.isFile()) out.push({ name: `${prefix}${e.name}`, content: fs.readFileSync(path.join(dir, e.name), 'utf8') });
      }
    };
    walk(root, '');
    return res.json({ type: t, files: out });
  });

  api.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  app.use('/api', api);

  // SPA fallback
  app.get('*', (req, res) => {
    if (path.basename(req.path).includes('.')) return res.status(404).send('Not found');
    if (fs.existsSync(path.join(PUBLIC, 'index.html'))) res.sendFile(path.join(PUBLIC, 'index.html'));
    else res.status(404).send('UI not found');
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
    log.error('unhandled error', { error: err.stack });
    return res.status(500).json({ error: 'Internal server error' });
  });

  return { app, registry };
}

module.exports = { createApp };

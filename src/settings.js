'use strict';
const fs = require('fs');
const path = require('path');

const { InstanceStore } = require('./store');
const { ruleDefaults } = require('./thresholds');

const ROOT = path.join(__dirname, '..');
const DEMO_CONFIGS = {
  haproxy: path.join(ROOT, 'examples', 'haproxy', 'haproxy.cfg'),
  nginx: path.join(ROOT, 'examples', 'nginx', 'nginx.conf'),
};
const TYPES = ['haproxy', 'nginx', 'apache', 'caddy', 'traefik'];
const LABEL = { haproxy: 'HAProxy', nginx: 'NGINX', apache: 'Apache', caddy: 'Caddy', traefik: 'Traefik' };
/** The bundled example of a newer product, if its module is installed (examples/<type>/). */
function exampleOf(type) {
  if (DEMO_CONFIGS[type]) return DEMO_CONFIGS[type];
  try { const m = require('./products').get(type); return m && m.example && fs.existsSync(m.example) ? m.example : null; } catch { return null; }
}

const bool = (v, d = false) => (v === undefined || v === null || v === '' ? d : /^(1|true|yes|on)$/i.test(String(v)));
const int = (v, d, min = 0) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= min ? n : d;
};
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'instance';

/** Replace ${VAR} references so secrets can stay out of instances.json. */
function interpolate(value, env) {
  if (typeof value !== 'string' || !env) return value; // env=null: literal values (UI-managed instances never expand ${VAR})
  return value.replace(/\$\{([A-Z0-9_]+)\}/gi, (_, k) => env[k] ?? '');
}

function readInstancesFile(env) {
  const file = env.INSTANCES_FILE
    || [path.join(ROOT, 'config', 'instances.json'), path.join(ROOT, 'instances.json')].find((p) => fs.existsSync(p));
  if (!file) return { file: null, raw: [], features: {} };
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {
    throw new Error(`Cannot read INSTANCES_FILE ${file}: ${e.message}`);
  }
  const raw = Array.isArray(parsed) ? parsed : parsed.instances;
  if (!Array.isArray(raw)) throw new Error(`${file} must contain an array (or {"instances": [...]})`);
  return { file, raw, features: Array.isArray(parsed) ? {} : (parsed.features || {}) };
}

function legacyEnvInstances(env) {
  const out = [];
  if (env.HAPROXY_STATS_URL || env.HAPROXY_SOCKET) {
    out.push({
      type: 'haproxy', name: env.HAPROXY_NAME || 'haproxy',
      statsUrl: env.HAPROXY_STATS_URL, socket: env.HAPROXY_SOCKET,
      username: env.HAPROXY_STATS_USER, password: env.HAPROXY_STATS_PASS,
      configPath: env.HAPROXY_CONFIG_PATH, configUrls: env.HAPROXY_CONFIG_URL ? [env.HAPROXY_CONFIG_URL] : undefined, insecureTls: bool(env.HAPROXY_INSECURE_TLS),
    });
  }
  if (env.NGINX_STATUS_URL || env.NGINX_PLUS_API_URL || env.NGINX_CONFIG_PATH || env.NGINX_CONFIG_URL) {
    out.push({
      type: 'nginx', name: env.NGINX_NAME || 'nginx',
      statsUrl: env.NGINX_STATUS_URL, plusApiUrl: env.NGINX_PLUS_API_URL,
      username: env.NGINX_STATUS_USER, password: env.NGINX_STATUS_PASS,
      configPath: env.NGINX_CONFIG_PATH, configUrls: env.NGINX_CONFIG_URL ? [env.NGINX_CONFIG_URL] : undefined, insecureTls: bool(env.NGINX_INSECURE_TLS),
      probe: bool(env.NGINX_PROBE, true), includeRoot: env.NGINX_INCLUDE_ROOT,
    });
  }
  // Apache (mod_status + balancer-manager), Caddy (admin API), Traefik (API): one instance each, from env.
  if (env.APACHE_STATUS_URL || env.APACHE_BALANCER_URL || env.APACHE_CONFIG_PATH || env.APACHE_CONFIG_URL) {
    out.push({ type: 'apache', name: env.APACHE_NAME || 'apache', statsUrl: env.APACHE_STATUS_URL, balancerUrl: env.APACHE_BALANCER_URL, username: env.APACHE_STATUS_USER, password: env.APACHE_STATUS_PASS,
      configPath: env.APACHE_CONFIG_PATH, configUrls: env.APACHE_CONFIG_URL ? [env.APACHE_CONFIG_URL] : undefined, insecureTls: bool(env.APACHE_INSECURE_TLS) });
  }
  if (env.CADDY_ADMIN_URL || env.CADDY_CONFIG_PATH || env.CADDY_CONFIG_URL) {
    out.push({ type: 'caddy', name: env.CADDY_NAME || 'caddy', statsUrl: env.CADDY_ADMIN_URL, configPath: env.CADDY_CONFIG_PATH, configUrls: env.CADDY_CONFIG_URL ? [env.CADDY_CONFIG_URL] : undefined, insecureTls: bool(env.CADDY_INSECURE_TLS) });
  }
  if (env.TRAEFIK_API_URL || env.TRAEFIK_CONFIG_PATH || env.TRAEFIK_CONFIG_URL) {
    out.push({ type: 'traefik', name: env.TRAEFIK_NAME || 'traefik', statsUrl: env.TRAEFIK_API_URL, username: env.TRAEFIK_API_USER, password: env.TRAEFIK_API_PASS,
      configPath: env.TRAEFIK_CONFIG_PATH, configUrls: env.TRAEFIK_CONFIG_URL ? [env.TRAEFIK_CONFIG_URL] : undefined, insecureTls: bool(env.TRAEFIK_INSECURE_TLS) });
  }
  return out;
}

function normalizeInstance(r, i, env, defaults, seen) {
  const type = String(r.type || 'haproxy').toLowerCase();
  if (!TYPES.includes(type)) throw new Error(`Instance "${r.name || i}": unknown type "${r.type}" (expected one of ${TYPES.join(', ')})`);
  const name = interpolate(r.name || `${type}-${i + 1}`, env);
  let id = slug(r.id || name);
  while (seen.has(id)) id += '-x';
  seen.add(id);
  const statsUrl = interpolate(r.statsUrl, env) || null;
  const plusApiUrl = interpolate(r.plusApiUrl, env) || null;
  return {
    id, name, type, enabled: r.enabled !== false,
    statsUrl, plusApiUrl,
    balancerUrl: interpolate(r.balancerUrl, env) || null, // Apache balancer-manager page
    metricsUrl: interpolate(r.metricsUrl, env) || null,   // Prometheus endpoint (Caddy / Traefik), when not under statsUrl
    socket: interpolate(r.socket, env) || null,
    username: interpolate(r.username, env) || null,
    password: interpolate(r.password, env) || null,
    insecureTls: Boolean(r.insecureTls),
    configPath: interpolate(r.configPath, env) || null,
    configUrls: [...(Array.isArray(r.configUrls) ? r.configUrls : []), ...(r.configUrl ? [r.configUrl] : [])].map((u) => interpolate(String(u), env)).filter((u) => /^https?:\/\//i.test(u)).slice(0, 50),
    configRefreshMs: int(r.configRefreshSec ? r.configRefreshSec * 1000 : null, 300000, 10000),
    configFiles: Array.isArray(r.configFiles) && r.configFiles.length ? r.configFiles : (typeof r.configText === 'string' && r.configText ? [{ name: { nginx: 'nginx.conf', apache: 'httpd.conf', caddy: 'Caddyfile', traefik: 'traefik.yml' }[type] || 'haproxy.cfg', content: r.configText }] : null), // uploaded in the UI
    managed: Boolean(r.managed), owner: r.owner || null,
    includeRoot: interpolate(r.includeRoot, env) || null,
    // NGINX only: actively TCP-probe upstream servers. Defaults on for explicitly configured NGINX instances.
    probe: type === 'nginx' ? (r.probe === undefined ? true : Boolean(r.probe)) : false,
    probeTimeoutMs: int(r.probeTimeoutMs, 1500, 100),
    pollIntervalMs: int(r.pollIntervalMs, defaults.pollIntervalMs, 1000),
    timeoutMs: int(r.timeoutMs, defaults.timeoutMs, 500),
    tags: Array.isArray(r.tags) ? r.tags.map(String) : [],
    // Per-instance threshold overrides, e.g. {"errorPct": 2, "latencyMs": 500} (see src/thresholds.js)
    alertRules: r.alertRules && typeof r.alertRules === 'object' && !Array.isArray(r.alertRules) ? r.alertRules : null,
    demo: false,
  };
}

function loadSettings(env = process.env) {
  const file = readInstancesFile(env);
  const defaults = {
    pollIntervalMs: int(env.POLL_INTERVAL || env.HAPROXY_POLL_INTERVAL, 5000, 1000),
    timeoutMs: int(env.UPSTREAM_TIMEOUT_MS || env.HAPROXY_TIMEOUT_MS, 7000, 500),
  };

  // Feature switches: env wins over instances.json; everything defaults to enabled.
  const features = {
    haproxy: bool(env.ENABLE_HAPROXY, file.features.haproxy !== false),
    nginx: bool(env.ENABLE_NGINX, file.features.nginx !== false),
    apache: bool(env.ENABLE_APACHE, file.features.apache !== false),
    caddy: bool(env.ENABLE_CADDY, file.features.caddy !== false),
    traefik: bool(env.ENABLE_TRAEFIK, file.features.traefik !== false),
  };

  const seen = new Set();
  const rawList = file.raw.length ? file.raw : legacyEnvInstances(env);
  const all = rawList.map((r, i) => normalizeInstance(r, i, env, defaults, seen));

  // Instances added from the UI (opt-in): stored in DATA_DIR, never interpolated, always shown when their technology is on.
  const ui = {
    enabled: bool(env.ALLOW_UI_INSTANCES),
    dir: env.DATA_DIR || path.join(ROOT, 'data'),
    configDir: path.join(ROOT, 'config'),
    shared: bool(env.UI_INSTANCES_SHARED), // true: every visitor sees every UI-added connection (team mode, put auth in front)
    ttlDays: int(env.UI_INSTANCE_TTL_DAYS, 7, 1),
    allowedHosts: String(env.UI_ALLOWED_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean),
  };
  if (ui.enabled) {
    const stored = new InstanceStore(ui.dir).load();
    stored.forEach((r, i) => all.push(normalizeInstance({ ...r, managed: true }, i, null, defaults, seen)));
  }
  const instances = all.filter((i) => i.enabled && features[i.type]);
  const skipped = all.filter((i) => !instances.includes(i)).map((i) => ({ id: i.id, type: i.type, reason: i.enabled ? 'feature disabled' : 'instance disabled' }));

  const demo = bool(env.DEMO_MODE);
  const autoOf = (type) => ({
    id: demo ? `demo-${type}` : `${type}-config`,
    name: demo ? `Demo ${LABEL[type]} (synthetic traffic)` : `${LABEL[type]} (config only)`,
    type, enabled: true, statsUrl: null, plusApiUrl: null, socket: null, username: null, password: null, insecureTls: false,
    probe: false, probeTimeoutMs: 1500, includeRoot: null, pollIntervalMs: 2000, timeoutMs: 5000, tags: demo ? ['demo'] : [], demo,
  });
  for (const type of TYPES) {
    if (!features[type]) continue;
    if (demo) {
      // Demo always uses the bundled, sanitised examples — never a real config.
      const ex = exampleOf(type);
      if (ex) instances.push({ ...autoOf(type), configPath: ex, includeRoot: require('path').dirname(ex) });
    }
  }

  return {
    port: int(env.PORT, 3000, 1),
    host: env.HOST || '0.0.0.0',
    trustProxy: bool(env.TRUST_PROXY),
    logLevel: env.LOG_LEVEL || 'info',
    auth: {
      user: env.AUTH_USER || null, pass: env.AUTH_PASS || null, passHash: env.AUTH_PASS_HASH || null, token: env.AUTH_TOKEN || null,
      secret: env.AUTH_SECRET || null, sessionHours: int(env.AUTH_SESSION_HOURS, 12, 1),
      enabled: Boolean((env.AUTH_USER && (env.AUTH_PASS || env.AUTH_PASS_HASH)) || env.AUTH_TOKEN),
    },
    historyPoints: int(env.HISTORY_POINTS, 360, 10),
    // Persistent history (SQLite in DATA_DIR). HISTORY_DB=off keeps it in memory only.
    history: { enabled: String(env.HISTORY_DB || '').toLowerCase() !== 'off', file: env.HISTORY_DB && String(env.HISTORY_DB).toLowerCase() !== 'off' ? env.HISTORY_DB : null,
      rawMs: int(env.HISTORY_RAW_HOURS, 6, 1) * 3600e3, keepMs: int(env.HISTORY_KEEP_DAYS, 14, 1) * 86400e3 },
    eventLimit: int(env.EVENT_LIMIT, 500, 10),
    // Traffic log upload: one file, at most LOG_MAX_MB (default 50, hard ceiling 500). Parsed as a stream, only aggregates are kept.
    logs: { maxBytes: Math.min(int(env.LOG_MAX_MB, 50, 1), 500) * 1048576 },
    alerts: { webhookUrl: env.ALERT_WEBHOOK_URL || null, minFailures: int(env.ALERT_MIN_FAILURES, 2, 1), insecureTls: bool(env.ALERT_INSECURE_TLS), rules: ruleDefaults(env) },
    // How many configuration versions are kept per instance (Running Config → History).
    configHistory: { keep: int(env.CONFIG_HISTORY_KEEP, 50, 2) },
    demo, features, skipped, instances, instancesFile: file.file, ui, defaults,
  };
}

module.exports = { loadSettings, normalizeInstance, slug, TYPES, LABEL };

'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Secrets at rest: saved passwords, user names and uploaded config files (which can contain credentials) are
 * encrypted with AES-256-GCM. The key is GATELIGHT_SECRET_KEY when set (keep it outside the data volume, so a copy
 * of the volume or a backup alone does not reveal the credentials), otherwise a random key generated once in the
 * data directory (.store-key, mode 0600), which still keeps them out of plain-text exports and backups of the file.
 */
const SEALED = ['password', 'username', 'configFiles'];
const PREFIX = 'enc:v1:';
class SecretBox {
  constructor(dir, envKey = process.env.GATELIGHT_SECRET_KEY) { this.dir = dir; this.envKey = envKey || null; this.key = null; }

  get source() { return this.envKey ? 'GATELIGHT_SECRET_KEY' : path.join(this.dir, '.store-key'); }

  _key(create) {
    if (this.key) return this.key;
    if (this.envKey) { this.key = crypto.scryptSync(this.envKey, 'gatelight-store-v1', 32); return this.key; }
    const file = path.join(this.dir, '.store-key');
    try { this.key = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64'); } catch (e) {
      if (e.code !== 'ENOENT' || !create) return null;
      fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      const k = crypto.randomBytes(32);
      fs.writeFileSync(file, k.toString('base64'), { mode: 0o600, flag: 'wx' });
      this.key = k;
    }
    if (this.key.length !== 32) throw new Error(`${file} is not a valid key (32 bytes, base64)`);
    return this.key;
  }

  seal(value) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this._key(true), iv);
    const ct = Buffer.concat([c.update(JSON.stringify(value), 'utf8'), c.final()]);
    return `${PREFIX}${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
  }

  open(text) {
    const [iv, tag, ct] = text.slice(PREFIX.length).split(':');
    const key = this._key(false);
    if (!key) throw new Error(`Saved connections are encrypted, but the key is missing (${this.source}). Restore it, or set GATELIGHT_SECRET_KEY to the key used before.`);
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
      d.setAuthTag(Buffer.from(tag, 'base64'));
      return JSON.parse(Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8'));
    } catch { throw new Error(`Saved connections were encrypted with a different key than ${this.source}. Set GATELIGHT_SECRET_KEY to the key used before, or remove ui-instances.json to start over.`); }
  }
}
const isSealed = (v) => typeof v === 'string' && v.startsWith(PREFIX);

/**
 * Persists instances added from the UI (ALLOW_UI_INSTANCES=true) as JSON in DATA_DIR (file mode 0600), with the
 * secret fields encrypted (see SecretBox). Files written by older versions in plain text are still read; `legacy`
 * tells the caller to save them again, which encrypts them.
 */
class InstanceStore {
  constructor(dir, box = new SecretBox(dir)) { this.dir = dir; this.file = path.join(dir, 'ui-instances.json'); this.box = box; this.legacy = false; }

  load() {
    let j;
    try { j = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch (e) {
      if (e.code === 'ENOENT') return [];
      throw new Error(`Cannot read ${this.file}: ${e.message}`);
    }
    const list = Array.isArray(j.instances) ? j.instances : [];
    this.legacy = false;
    return list.map((inst) => {
      const out = { ...inst };
      for (const k of SEALED) {
        if (out[k] == null) continue;
        if (isSealed(out[k])) out[k] = this.box.open(out[k]);
        else this.legacy = true; // written before encryption existed
      }
      return out;
    });
  }

  save(list) {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const sealed = list.map((inst) => {
      const out = { ...inst };
      for (const k of SEALED) if (out[k] != null && out[k] !== '') out[k] = this.box.seal(out[k]);
      return out;
    });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ format: 2, instances: sealed }, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    this.legacy = false;
  }
}

const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const hostOf = (u) => u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
const hostAllowed = (host, list) => !list.length || list.some((a) => (a.startsWith('*.') ? host.endsWith(a.slice(1)) : host === a));

function checkUrl(label, value, allowedHosts) {
  let u;
  try { u = new URL(value); } catch { throw new Error(`${label} is not a valid URL (expected http://host:port/path)`); }
  if (!/^https?:$/.test(u.protocol)) throw new Error(`${label} must start with http:// or https://`);
  if (u.username || u.password) throw new Error(`${label} must not contain credentials: use the username and password fields`);
  if (!hostAllowed(hostOf(u), allowedHosts)) throw new Error(`Host "${hostOf(u)}" is not in this server's UI_ALLOWED_HOSTS`);
  return u.toString();
}

const CFG_LIMITS = { files: 300, fileBytes: 1024 * 1024, totalBytes: 4 * 1024 * 1024 };
/** Config uploaded in the UI: a list of {name, content}. Names are relative labels only; nothing is ever read from or written to disk by name. */
function cleanFiles(input) {
  if (!Array.isArray(input)) return [];
  const out = []; let total = 0;
  for (const f of input.slice(0, CFG_LIMITS.files)) {
    if (!f || typeof f.content !== 'string' || typeof f.name !== 'string' || !f.content.trim()) continue;
    if (f.content.includes('\u0000')) throw new Error(`${f.name} looks binary, not a text config`);
    if (f.content.length > CFG_LIMITS.fileBytes) throw new Error(`${f.name} is larger than 1 MB`);
    total += f.content.length;
    if (total > CFG_LIMITS.totalBytes) throw new Error('Config files are larger than 4 MB in total');
    const name = f.name.replace(/\\/g, '/').split('/').filter((x) => x && x !== '.' && x !== '..').join('/').slice(0, 200);
    if (name) out.push({ name, content: f.content });
  }
  return out;
}

const TYPES = ['haproxy', 'nginx', 'apache', 'caddy', 'traefik'];
const DEFAULT_FILE = { haproxy: 'haproxy.cfg', nginx: 'nginx.conf', apache: 'httpd.conf', caddy: 'Caddyfile', traefik: 'traefik.yml' };
const URL_LABEL = { haproxy: 'Stats URL', nginx: 'Status URL', apache: 'server-status URL', caddy: 'Admin API URL', traefik: 'API URL' };
const NEED_SOURCE = {
  haproxy: 'Enter the stats URL (e.g. http://host:8404/stats) or a Runtime API host:port, or upload a config or a traffic log to look at it without a live connection',
  nginx: 'Enter the stub_status URL or the NGINX Plus API URL, or upload a config to review it without a live connection',
  apache: 'Enter the server-status URL (mod_status, e.g. http://host/server-status) and/or the balancer-manager URL, or upload a config or a traffic log to look at it without a live connection',
  caddy: 'Enter the Caddy admin API URL (e.g. http://127.0.0.1:2019), or upload a Caddyfile / JSON config or a traffic log to look at it without a live connection',
  traefik: 'Enter the Traefik API URL (e.g. http://host:8080), or upload the static and dynamic config or a traffic log to look at it without a live connection',
};

/**
 * Validate and normalise a create/update body into a stored-instance definition.
 * `existing` supplies the current password when an update leaves it blank.
 */
function validateInput(body, ctx, existing) {
  const b = body && typeof body === 'object' ? body : {};
  const type = str(b.type, 10).toLowerCase();
  if (!TYPES.includes(type)) throw new Error(`Type must be one of ${TYPES.join(', ')}`);
  if (ctx.features && ctx.features[type] === false) throw new Error(`${type} support is disabled on this server`);
  const name = str(b.name, 60);
  if (!name) throw new Error('Give the instance a name');

  const def = { type, name, insecureTls: Boolean(b.insecureTls), tags: [] };
  const statsUrl = str(b.statsUrl, 2048);
  const plusApiUrl = type === 'nginx' ? str(b.plusApiUrl, 2048) : '';
  const socket = type === 'haproxy' ? str(b.socket, 255) : '';
  if (statsUrl) def.statsUrl = checkUrl(URL_LABEL[type], statsUrl, ctx.allowedHosts);
  const balancerUrl = type === 'apache' ? str(b.balancerUrl, 2048) : '';
  if (balancerUrl) def.balancerUrl = checkUrl('Balancer manager URL', balancerUrl, ctx.allowedHosts);
  const metricsUrl = ['caddy', 'traefik'].includes(type) ? str(b.metricsUrl, 2048) : '';
  if (metricsUrl) def.metricsUrl = checkUrl('Metrics URL', metricsUrl, ctx.allowedHosts);
  if (plusApiUrl) def.plusApiUrl = checkUrl('NGINX Plus API URL', plusApiUrl, ctx.allowedHosts);
  if (socket) {
    const m = socket.replace(/^tcp:\/\//, '').match(/^([^:/\s]+):(\d{1,5})$/);
    if (!m || +m[2] < 1 || +m[2] > 65535) throw new Error('Runtime API must be host:port (unix sockets are not allowed from the UI)');
    if (!hostAllowed(m[1].toLowerCase(), ctx.allowedHosts)) throw new Error(`Host "${m[1]}" is not in this server's UI_ALLOWED_HOSTS`);
    def.socket = `${m[1]}:${m[2]}`;
  }
  // Config published by the server itself: fetched with GET, so "refresh" can pull new changes any time.
  const rawUrls = Array.isArray(b.configUrls) ? b.configUrls : typeof b.configUrls === 'string' ? b.configUrls.split(/\r?\n/) : [];
  const cfgUrls = rawUrls.map((u) => str(u, 2048)).filter(Boolean).slice(0, 50).map((u) => checkUrl('Config URL', u, ctx.allowedHosts));
  if (cfgUrls.length) def.configUrls = [...new Set(cfgUrls)];
  // A HAProxy log is uploaded right after the instance is created; it can be the instance's only content.
  if (b.logOnly === true) def.logOnly = true;
  if (type === 'nginx' && b.probe !== undefined) def.probe = Boolean(b.probe);
  // Config uploaded in the browser (replaces the old "put a file in config/" method). Stored with the instance.
  let files = cleanFiles(b.configFiles);
  if (!files.length && typeof b.configText === 'string' && b.configText.trim()) files = cleanFiles([{ name: DEFAULT_FILE[type], content: b.configText }]);
  if (!files.length && b.keepConfig && existing && existing.configFiles && existing.configFiles.length) files = existing.configFiles;
  if (files.length) def.configFiles = files;
  if (type === 'nginx' && b.probe === undefined && !def.statsUrl && !def.plusApiUrl) def.probe = false; // config-only: never probe hosts named in an uploaded file
  if (!def.statsUrl && !def.plusApiUrl && !def.socket && !def.balancerUrl && !(type === 'nginx' && def.probe) && !def.configFiles && !def.configUrls && !def.logOnly) {
    throw new Error(NEED_SOURCE[type]);
  }

  const username = str(b.username, 256);
  if (username) def.username = username;
  const pw = typeof b.password === 'string' ? b.password.slice(0, 512) : '';
  // A blank password on edit keeps the stored one, but only while the target and user are unchanged:
  // otherwise an editor could redirect the saved credential to a host of their choosing.
  const target = (d) => [d.statsUrl && new URL(d.statsUrl).host, d.plusApiUrl && new URL(d.plusApiUrl).host, d.balancerUrl && new URL(d.balancerUrl).host, d.metricsUrl && new URL(d.metricsUrl).host, d.socket].join('|');
  if (pw) def.password = pw;
  else if (existing && existing.password && username === (existing.username || '') && target(def) === target(existing)) def.password = existing.password;

  return def;
}

module.exports = { InstanceStore, SecretBox, validateInput, checkUrl, cleanFiles };

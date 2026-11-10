'use strict';
const fs = require('fs');
const path = require('path');

/**
 * Persists instances added from the UI (ALLOW_UI_INSTANCES=true) as JSON in DATA_DIR.
 * The file is written 0600 because it holds the stats credentials the operator typed in.
 */
class InstanceStore {
  constructor(dir) { this.dir = dir; this.file = path.join(dir, 'ui-instances.json'); }

  load() {
    try {
      const j = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return Array.isArray(j.instances) ? j.instances : [];
    } catch (e) {
      if (e.code === 'ENOENT') return [];
      throw new Error(`Cannot read ${this.file}: ${e.message}`);
    }
  }

  save(list) {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ instances: list }, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
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

/**
 * Validate and normalise a create/update body into a stored-instance definition.
 * `existing` supplies the current password when an update leaves it blank.
 */
function validateInput(body, ctx, existing) {
  const b = body && typeof body === 'object' ? body : {};
  const type = str(b.type, 10).toLowerCase();
  if (!['haproxy', 'nginx'].includes(type)) throw new Error('Type must be haproxy or nginx');
  if (ctx.features && ctx.features[type] === false) throw new Error(`${type} support is disabled on this server`);
  const name = str(b.name, 60);
  if (!name) throw new Error('Give the instance a name');

  const def = { type, name, insecureTls: Boolean(b.insecureTls), tags: [] };
  const statsUrl = str(b.statsUrl, 2048);
  const plusApiUrl = type === 'nginx' ? str(b.plusApiUrl, 2048) : '';
  const socket = type === 'haproxy' ? str(b.socket, 255) : '';
  if (statsUrl) def.statsUrl = checkUrl(type === 'haproxy' ? 'Stats URL' : 'Status URL', statsUrl, ctx.allowedHosts);
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
  if (type === 'haproxy' && b.logOnly === true) def.logOnly = true;
  if (type === 'nginx' && b.probe !== undefined) def.probe = Boolean(b.probe);
  // Config uploaded in the browser (replaces the old "put a file in config/" method). Stored with the instance.
  let files = cleanFiles(b.configFiles);
  if (!files.length && typeof b.configText === 'string' && b.configText.trim()) files = cleanFiles([{ name: type === 'nginx' ? 'nginx.conf' : 'haproxy.cfg', content: b.configText }]);
  if (!files.length && b.keepConfig && existing && existing.configFiles && existing.configFiles.length) files = existing.configFiles;
  if (files.length) def.configFiles = files;
  if (type === 'nginx' && b.probe === undefined && !def.statsUrl && !def.plusApiUrl) def.probe = false; // config-only: never probe hosts named in an uploaded file
  if (!def.statsUrl && !def.plusApiUrl && !def.socket && !(type === 'nginx' && def.probe) && !def.configFiles && !def.configUrls && !def.logOnly) {
    throw new Error(type === 'haproxy' ? 'Enter the stats URL (e.g. http://host:8404/stats) or a Runtime API host:port, or upload a config or a traffic log to look at it without a live connection' : 'Enter the stub_status URL or the NGINX Plus API URL, or upload a config to review it without a live connection');
  }

  const username = str(b.username, 256);
  if (username) def.username = username;
  const pw = typeof b.password === 'string' ? b.password.slice(0, 512) : '';
  // A blank password on edit keeps the stored one, but only while the target and user are unchanged:
  // otherwise an editor could redirect the saved credential to a host of their choosing.
  const target = (d) => [d.statsUrl && new URL(d.statsUrl).host, d.plusApiUrl && new URL(d.plusApiUrl).host, d.socket].join('|');
  if (pw) def.password = pw;
  else if (existing && existing.password && username === (existing.username || '') && target(def) === target(existing)) def.password = existing.password;

  return def;
}

module.exports = { InstanceStore, validateInput, checkUrl, cleanFiles };

'use strict';
const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

const MAX_BODY = 32 * 1024 * 1024;
const READ_ONLY_METHODS = new Set(['GET', 'HEAD']);
// The only HAProxy Runtime API commands GateLight may send. Everything else (set, enable, disable, add, del, shutdown,
// clear, commit, prepare, ...), several commands in one line, or any control character is refused.
const RUNTIME_ALLOWED = new Set(['show stat', 'show info']);

/**
 * Minimal HTTP(S) request helper with timeout, body-size cap and optional
 * basic auth / TLS verification bypass. Redirects are NOT followed (an
 * operator-configured endpoint should answer directly).
 */
function httpRequest(urlStr, { method = 'GET', username, password, timeout = 7000, insecureTls = false, body, headers = {}, notification = false } = {}) {
  return new Promise((resolve, reject) => {
    // GateLight never changes a load balancer: only reads are possible. The one exception is the alert webhook
    // (a chat / incident receiver, not a proxy), which the alert sender marks explicitly.
    if (!notification && !READ_ONLY_METHODS.has(String(method).toUpperCase())) return reject(new Error(`Refused: GateLight is read-only and does not send ${method} requests to servers`));
    if (!notification && body) return reject(new Error('Refused: GateLight is read-only and does not send request bodies to servers'));
    let u;
    try { u = new URL(urlStr); } catch { return reject(new Error(`Invalid URL: ${urlStr}`)); }
    if (!/^https?:$/.test(u.protocol)) return reject(new Error(`Unsupported protocol ${u.protocol}`));
    const lib = u.protocol === 'https:' ? https : http;
    const h = { 'User-Agent': 'gatelight', Accept: '*/*', ...headers };
    if (username) h.Authorization = `Basic ${Buffer.from(`${username}:${password || ''}`).toString('base64')}`;
    if (body) h['Content-Length'] = Buffer.byteLength(body);
    const req = lib.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || undefined,
      path: u.pathname + u.search, method, headers: h, timeout,
      rejectUnauthorized: !insecureTls,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) { req.destroy(new Error('Response exceeded size limit')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error(`Timed out after ${timeout}ms`)));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** Send one command to the HAProxy Runtime API (TCP `host:port` or unix socket path). */
function runtimeCommand(target, command, timeout = 7000) {
  return new Promise((resolve, reject) => {
    if (!RUNTIME_ALLOWED.has(command)) return reject(new Error(`Refused: GateLight is read-only; Runtime API command "${String(command).slice(0, 40)}" is not allowed (only ${[...RUNTIME_ALLOWED].join(', ')})`));
    const opts = target.startsWith('/') || target.startsWith('unix:')
      ? { path: target.replace(/^unix:/, '') }
      : (() => { const [host, port] = target.replace(/^tcp:\/\//, '').split(':'); return { host, port: Number(port) }; })();
    const sock = net.createConnection(opts);
    const chunks = [];
    let size = 0;
    sock.setTimeout(timeout, () => sock.destroy(new Error(`Runtime API timed out after ${timeout}ms`)));
    sock.on('connect', () => sock.write(`${command}\n`));
    sock.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) return sock.destroy(new Error('Runtime API response exceeded size limit'));
      chunks.push(c);
    });
    sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    sock.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
    sock.on('error', reject);
  });
}


/** URL without its query string (tokens often live there): safe for messages and logs. */
const urlLabel = (u) => { try { const x = new URL(u); return `${x.origin}${x.pathname}`; } catch { return 'the config URL'; } };
const CFG_URL_LIMITS = { urls: 50, fileBytes: 1024 * 1024, totalBytes: 4 * 1024 * 1024 };

/**
 * Read-only: fetch the configuration files of a server from the URL(s) it publishes them at (GET only).
 * Credentials of the stats endpoint are only sent to the same host. Names keep the folder structure below the
 * common directory, so NGINX `include conf.d/*.conf` still resolves.
 */
async function fetchConfigFiles(inst) {
  const urls = (inst.configUrls || []).slice(0, CFG_URL_LIMITS.urls);
  const sameHost = (u) => [inst.statsUrl, inst.plusApiUrl].filter(Boolean).some((x) => { try { return new URL(x).host === new URL(u).host; } catch { return false; } });
  const got = []; let total = 0;
  for (const url of urls) {
    let res;
    try {
      res = await httpRequest(url, { username: sameHost(url) ? inst.username : undefined, password: sameHost(url) ? inst.password : undefined, timeout: inst.timeoutMs, insecureTls: inst.insecureTls });
    } catch (e) { throw new Error(`Cannot fetch ${urlLabel(url)}: ${e.message}`); }
    if (res.status !== 200) throw new Error(`${urlLabel(url)} returned HTTP ${res.status}`);
    if (res.body.includes('\u0000')) throw new Error(`${urlLabel(url)} is not a text file`);
    if (res.body.length > CFG_URL_LIMITS.fileBytes) throw new Error(`${urlLabel(url)} is larger than 1 MB`);
    total += res.body.length;
    if (total > CFG_URL_LIMITS.totalBytes) throw new Error('Config files are larger than 4 MB in total');
    got.push({ segs: new URL(url).pathname.split('/').filter(Boolean).map((x) => { try { return decodeURIComponent(x); } catch { return x; } }), content: res.body });
  }
  // strip the directory every file shares
  let common = got.length ? got[0].segs.slice(0, -1) : [];
  for (const g of got) { let i = 0; while (i < common.length && i < g.segs.length - 1 && common[i] === g.segs[i]) i++; common = common.slice(0, i); }
  return got.map((g) => ({ name: g.segs.slice(common.length).join('/') || 'config', content: g.content }));
}

const htmlInfoCache = new WeakMap();
const HTML_INFO_TTL_MS = 60000;

const DURATION_RE = /(?:(\d+)d)?\s*(?:(\d+)h)?\s*(?:(\d+)m)?\s*(?:(\d+)s)?/;
const durationSec = (txt) => { const m = String(txt).match(DURATION_RE); return m ? (+m[1] || 0) * 86400 + (+m[2] || 0) * 3600 + (+m[3] || 0) * 60 + (+m[4] || 0) : null; };

/** Extract process facts from the HAProxy stats HTML page, formatted like `show info` for parseInfo(). */
function htmlToInfo(html) {
  const v = html.match(/HAProxy version ([^,<\s]+)/i);
  const pid = html.match(/pid\s*=\s*(?:<[^>]*>|\s)*(\d+)/i);
  const up = html.match(/uptime\s*=\s*(?:<[^>]*>|\s)*([0-9dhms ]+?)(?:;|<|\n)/i);
  const idle = html.match(/idle\s*=\s*(\d+)\s*%/i);
  const mc = html.match(/maxconn\s*=\s*(?:<[^>]*>|\s)*(\d+)/i);
  const cc = html.match(/current conns\s*=\s*(\d+)/i);
  const nbproc = html.match(/nbproc\s*=\s*(\d+)/i); const nbthread = html.match(/nbthread\s*=\s*(\d+)/i);
  const memmax = html.match(/memmax\s*=\s*([A-Za-z0-9.]+)/i); const ulim = html.match(/ulimit-n\s*=\s*(\d+)/i);
  const maxsock = html.match(/maxsock\s*=\s*(\d+)/i); const maxpipes = html.match(/maxpipes\s*=\s*(\d+)/i);
  const pipes = html.match(/current pipes\s*=\s*(\d+)\s*\/\s*(\d+)/i); const crate = html.match(/conn rate\s*=\s*(\d+)\s*\/\s*sec/i);
  const tasks = html.match(/running tasks:?\s*(\d+)\s*\/\s*(\d+)/i);
  const lines = [];
  if (v) lines.push(`Version: ${v[1]}`);
  if (pid) lines.push(`Pid: ${pid[1]}`);
  if (up) { lines.push(`Uptime: ${up[1].trim()}`); const s = durationSec(up[1]); if (s != null) lines.push(`Uptime_sec: ${s}`); }
  if (idle) lines.push(`Idle_pct: ${idle[1]}`);
  if (mc) lines.push(`Maxconn: ${mc[1]}`);
  if (cc) lines.push(`CurrConns: ${cc[1]}`);
  if (nbproc) lines.push(`Nbproc: ${nbproc[1]}`);
  if (nbthread) lines.push(`Nbthread: ${nbthread[1]}`);
  if (memmax) lines.push(`Memmax: ${memmax[1]}`);
  if (ulim) lines.push(`Ulimit-n: ${ulim[1]}`);
  if (maxsock) lines.push(`Maxsock: ${maxsock[1]}`);
  if (maxpipes) lines.push(`Maxpipes: ${maxpipes[1]}`);
  if (pipes) lines.push(`CurrPipes: ${pipes[1]}`);
  if (crate) lines.push(`ConnRate: ${crate[1]}`);
  if (tasks) { lines.push(`Run_queue: ${tasks[1]}`); lines.push(`Tasks: ${tasks[2]}`); }
  return lines.join('\n');
}

/** Process info is only on the HTML page for the HTTP source; fetch it at most once a minute. */
async function fetchHtmlInfo(instance) {
  const hit = htmlInfoCache.get(instance);
  if (hit && Date.now() - hit.at < HTML_INFO_TTL_MS) return hit.info;
  let info = '';
  try {
    const url = instance.statsUrl.replace(/;csv.*$/, '');
    const res = await httpRequest(url, { username: instance.username, password: instance.password, timeout: instance.timeoutMs, insecureTls: instance.insecureTls });
    if (res.status === 200) info = htmlToInfo(res.body);
  } catch { /* optional enrichment only */ }
  htmlInfoCache.set(instance, { at: Date.now(), info });
  return info;
}

/** Fetch raw `show stat` CSV (and `show info` when available) for an instance. */
async function fetchStats(instance) {
  if (instance.socket) {
    const [stat, info] = await Promise.all([
      runtimeCommand(instance.socket, 'show stat', instance.timeoutMs),
      runtimeCommand(instance.socket, 'show info', instance.timeoutMs).catch(() => ''),
    ]);
    return { csv: stat, info };
  }
  let url = instance.statsUrl;
  if (!/;csv(;|$)/.test(url)) url = url.replace(/\/+$/, '') + '/;csv';
  const res = await httpRequest(url, {
    username: instance.username, password: instance.password,
    timeout: instance.timeoutMs, insecureTls: instance.insecureTls,
  });
  if (res.status === 401 || res.status === 403) throw new Error(`HAProxy stats rejected credentials (HTTP ${res.status})`);
  if (res.status !== 200) throw new Error(`HAProxy stats returned HTTP ${res.status}`);
  if (!/^#?\s*pxname/.test(res.body)) throw new Error('Endpoint did not return HAProxy CSV stats (is the URL the stats page, e.g. /stats?)');
  return { csv: res.body, info: await fetchHtmlInfo(instance) };
}

module.exports = { fetchConfigFiles, urlLabel, httpRequest, runtimeCommand, fetchStats, htmlToInfo, READ_ONLY_METHODS, RUNTIME_ALLOWED };

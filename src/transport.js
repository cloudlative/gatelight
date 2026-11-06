'use strict';
const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

const MAX_BODY = 32 * 1024 * 1024;

/**
 * Minimal HTTP(S) request helper with timeout, body-size cap and optional
 * basic auth / TLS verification bypass. Redirects are NOT followed (an
 * operator-configured endpoint should answer directly).
 */
function httpRequest(urlStr, { method = 'GET', username, password, timeout = 7000, insecureTls = false, body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
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
  const lines = [];
  if (v) lines.push(`Version: ${v[1]}`);
  if (pid) lines.push(`Pid: ${pid[1]}`);
  if (up) { lines.push(`Uptime: ${up[1].trim()}`); const s = durationSec(up[1]); if (s != null) lines.push(`Uptime_sec: ${s}`); }
  if (idle) lines.push(`Idle_pct: ${idle[1]}`);
  if (mc) lines.push(`Maxconn: ${mc[1]}`);
  if (cc) lines.push(`CurrConns: ${cc[1]}`);
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

module.exports = { httpRequest, runtimeCommand, fetchStats, htmlToInfo };

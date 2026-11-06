'use strict';
const http = require('http');
const { loadSettings } = require('../src/settings');
const { createApp } = require('../src/app');

/** Start the real app on an ephemeral port. */
async function startApp(env = {}) {
  const settings = loadSettings({ HISTORY_DB: 'off', ...env });
  const { app, registry } = createApp(settings);
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { settings, registry, base, close: () => new Promise((r) => { registry.stop(); server.close(r); }) };
}

/** Tiny programmable HTTP server (stats endpoint / webhook receiver). */
async function startStub(handler) {
  const hits = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => { hits.push({ method: req.method, url: req.url, headers: req.headers, body }); handler(req, res, body); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, hits, close: () => new Promise((r) => server.close(r)) };
}

const get = async (base, path, headers) => {
  const res = await fetch(base + path, { headers });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json, headers: res.headers };
};
const post = async (base, path, body, headers) => {
  const res = await fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text };
};

module.exports = { startApp, startStub, get, post };

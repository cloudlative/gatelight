'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const { safeEqual } = require('./security');

const COOKIE = 'gl_auth';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
// Reachable without a session: the sign-in page and the few static files it needs. Nothing else.
const OPEN_PATHS = new Set(['/healthz', '/login', '/login.js', '/logo.svg', '/app.css', '/auth/login', '/auth/session', '/brands/cyferio.svg', '/brands/invisibly.svg', '/brands/braintally.svg']);

const b64 = (b) => Buffer.from(b).toString('base64url');

/** `gatelight hash-password` output: scrypt$<salt hex>$<hash hex>. Lets operators keep a hash, not the password, in .env. */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${crypto.scryptSync(String(pw), salt, 32).toString('hex')}`;
}
function verifyHash(pw, stored) {
  const [alg, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const got = crypto.scryptSync(String(pw), Buffer.from(salt, 'hex'), 32);
  const want = Buffer.from(hash, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

/**
 * Password sign-in for the web UI: a branded login page and a signed, HttpOnly session cookie.
 * Scripts/Prometheus can still use Authorization: Bearer / Basic. Failed logins are throttled per IP.
 */
/** Session-signing secret: AUTH_SECRET, else one generated once and kept in the data volume so restarts/redeploys do not sign everyone out. */
function loadSecret(auth, dataDir, log) {
  if (auth.secret) return Buffer.from(auth.secret);
  if (dataDir) {
    const file = path.join(dataDir, '.auth-secret');
    try { const v = fs.readFileSync(file, 'utf8').trim(); if (v.length >= 32) return Buffer.from(v); } catch { /* create below */ }
    try {
      fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      const v = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(file, v, { mode: 0o600 });
      return Buffer.from(v);
    } catch (e) { log.warn('Could not persist the session secret; people will be signed out on every restart. Set AUTH_SECRET or make the data directory writable.', { error: e.message }); }
  }
  return crypto.randomBytes(32);
}

function createAuth(auth, log, dataDir) {
  const secret = auth.enabled ? loadSecret(auth, dataDir, log) : crypto.randomBytes(32);
  const ttlMs = auth.sessionHours * 3600 * 1000;
  const sign = (payload) => crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  const issue = (user) => { const p = b64(JSON.stringify({ u: user, exp: Date.now() + ttlMs })); return `${p}.${sign(p)}`; };
  const read = (req) => {
    const m = String(req.headers.cookie || '').match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
    if (!m) return null;
    const [p, sig] = m[1].split('.');
    if (!p || !sig || !safeEqual(sig, sign(p))) return null;
    try { const j = JSON.parse(Buffer.from(p, 'base64url').toString()); return j.exp > Date.now() ? j : null; } catch { return null; }
  };
  const cookie = (req, value, maxAge) => {
    const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
  };
  const checkPassword = (user, pw) => {
    const userOk = safeEqual(String(user), auth.user || '');
    const pwOk = auth.passHash ? verifyHash(pw, auth.passHash) : safeEqual(String(pw), auth.pass || '');
    return userOk && pwOk; // both are always evaluated: no hint about which one was wrong
  };

  // brute-force throttle: 5 failures per IP lock sign-in for 15 minutes
  const fails = new Map();
  const MAX_FAILS = 5; const LOCK_MS = 15 * 60 * 1000;
  setInterval(() => { const now = Date.now(); for (const [k, v] of fails) if (v.until < now && now - v.last > LOCK_MS) fails.delete(k); }, 60000).unref();

  const router = express.Router();
  router.get('/login', (_req, res) => { res.setHeader('Cache-Control', 'no-store'); res.sendFile(path.join(PUBLIC_DIR, 'login.html')); });
  router.get('/login.js', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'login.js')));
  router.get('/auth/session', (req, res) => { const s = read(req); res.setHeader('Cache-Control', 'no-store'); res.json({ enabled: auth.enabled, authenticated: Boolean(s), user: s ? s.u : null }); });
  router.post('/auth/login', express.json({ limit: '4kb' }), async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!auth.user || !(auth.pass || auth.passHash)) return res.status(400).json({ error: 'Password sign-in is not configured on this server.' });
    if (!req.is('application/json')) return res.status(415).json({ error: 'Content-Type must be application/json' });
    const origin = req.headers.origin;
    if (origin) {
      try { if (new URL(origin).host !== req.headers.host) return res.status(403).json({ error: 'Cross-origin sign-in refused' }); } catch { return res.status(403).json({ error: 'Bad origin' }); }
    }
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const rec = fails.get(ip) || { n: 0, until: 0, last: 0 };
    if (rec.until > Date.now()) {
      res.setHeader('Retry-After', Math.ceil((rec.until - Date.now()) / 1000));
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil((rec.until - Date.now()) / 60000)} minute(s).` });
    }
    const { username, password } = req.body || {};
    if (typeof username === 'string' && typeof password === 'string' && password.length <= 512 && checkPassword(username.trim(), password)) {
      fails.delete(ip);
      res.setHeader('Set-Cookie', cookie(req, issue(auth.user), Math.floor(ttlMs / 1000)));
      log.info('sign-in', { user: auth.user });
      return res.json({ ok: true });
    }
    rec.n += 1; rec.last = Date.now();
    if (rec.n >= MAX_FAILS) { rec.until = Date.now() + LOCK_MS; rec.n = 0; }
    fails.set(ip, rec);
    log.warn('failed sign-in', { ip });
    await new Promise((r) => setTimeout(r, 400)); // slows online guessing
    return res.status(401).json({ error: 'Wrong username or password.' });
  });
  router.post('/auth/logout', (req, res) => { res.setHeader('Set-Cookie', cookie(req, '', 0)); res.json({ ok: true }); });

  /** Session cookie, Bearer token or Basic (scripts) lets a request through; browsers are sent to the sign-in page. */
  const middleware = (req, res, next) => {
    if (!auth.enabled || OPEN_PATHS.has(req.path)) return next();
    const s = read(req);
    if (s) { req.authUser = s.u; req.authExp = s.exp; return next(); }
    const h = req.headers.authorization || '';
    if (auth.token && h.startsWith('Bearer ') && safeEqual(h.slice(7), auth.token)) return next();
    if (auth.user && (auth.pass || auth.passHash) && h.startsWith('Basic ')) {
      const d = Buffer.from(h.slice(6), 'base64').toString('utf8'); const i = d.indexOf(':');
      if (i > 0 && checkPassword(d.slice(0, i), d.slice(i + 1))) return next();
    }
    if (req.method === 'GET' && !req.path.startsWith('/api') && String(req.headers.accept || '').includes('text/html')) return res.redirect(302, '/login');
    return res.status(401).json({ error: 'Authentication required' });
  };
  return { router, middleware };
}

module.exports = { createAuth, hashPassword, verifyHash };

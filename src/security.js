'use strict';
const crypto = require('crypto');

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function securityHeaders(_req, res, next) {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; "
    + "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
}

/** HTTP Basic (browser prompt) and/or Bearer token (API, Prometheus). /healthz is always open. */
function authMiddleware(auth) {
  return (req, res, next) => {
    if (!auth.enabled || req.path === '/healthz') return next();
    const h = req.headers.authorization || '';
    if (auth.token && h.startsWith('Bearer ') && safeEqual(h.slice(7), auth.token)) return next();
    if (auth.user && auth.pass && h.startsWith('Basic ')) {
      const decoded = Buffer.from(h.slice(6), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      if (i > 0 && safeEqual(decoded.slice(0, i), auth.user) && safeEqual(decoded.slice(i + 1), auth.pass)) return next();
    }
    res.setHeader('WWW-Authenticate', 'Basic realm="GateLight", charset="UTF-8"');
    return res.status(401).json({ error: 'Authentication required' });
  };
}

/** Small fixed-window per-IP limiter (no dependency; per process). */
function rateLimit({ windowMs = 60000, max = 300 } = {}) {
  const hits = new Map();
  const timer = setInterval(() => hits.clear(), windowMs);
  timer.unref();
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const n = (hits.get(ip) || 0) + 1;
    hits.set(ip, n);
    if (n > max) {
      res.setHeader('Retry-After', Math.ceil(windowMs / 1000));
      return res.status(429).json({ error: 'Too many requests' });
    }
    return next();
  };
}

module.exports = { securityHeaders, authMiddleware, rateLimit, safeEqual };

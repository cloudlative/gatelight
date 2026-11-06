'use strict';
const crypto = require('crypto');

const COOKIE = 'gl_sid';
const LEGACY_COOKIE = 'nx_sid'; // pre-rename name: honoured once so existing browsers keep their connections
const SID_RE = /^[a-f0-9]{64}$/;

/**
 * Anonymous per-browser identity. The cookie is a random secret; only its SHA-256 is stored with the
 * connections that browser creates, so connections are private to the browser that added them.
 */
function sessionMiddleware(req, res, next) {
  const read = (name) => { const m = String(req.headers.cookie || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`)); return m && SID_RE.test(m[1]) ? m[1] : null; };
  const current = read(COOKIE);
  let sid = current || read(LEGACY_COOKIE);
  if (!current) {
    sid = sid || crypto.randomBytes(32).toString('hex');
    const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${30 * 86400}${secure ? '; Secure' : ''}`);
  }
  req.owner = crypto.createHash('sha256').update(sid).digest('hex');
  next();
}

module.exports = { sessionMiddleware };

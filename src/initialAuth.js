'use strict';
/**
 * Zero-config sign-in for the "curl the compose file and run it" setup.
 * With AUTH_AUTOGEN=true, AUTH_USER set and no password configured, a random password is generated once, kept in the
 * data volume (file mode 0600) and printed in the logs on first run. Setting AUTH_PASS / AUTH_PASS_HASH later takes over.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function ensureInitialPassword(settings, env = process.env) {
  const a = settings.auth;
  if (String(env.AUTH_AUTOGEN).toLowerCase() !== 'true' || !a.user || a.pass || a.passHash || a.token) return { generated: false, active: false };
  const dir = settings.ui.dir; const file = path.join(dir, '.initial-password');
  let pw = null; let generated = false;
  try { pw = fs.readFileSync(file, 'utf8').trim() || null; } catch { /* first run */ }
  if (!pw) {
    pw = crypto.randomBytes(15).toString('base64url'); generated = true;
    try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); fs.writeFileSync(file, `${pw}\n`, { mode: 0o600 }); } catch { /* not persistable: the password lasts until restart */ }
  }
  a.pass = pw; a.enabled = true;
  return { generated, active: true, file, user: a.user, password: pw };
}

module.exports = { ensureInitialPassword };

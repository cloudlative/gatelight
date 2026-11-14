'use strict';
/**
 * Guess which product a configuration is for. Apache, Caddy and Traefik modules score their own syntax
 * (src/products/<type> detect()); when none is confident, the long-standing NGINX/HAProxy rule decides:
 * NGINX uses braces to open blocks; HAProxy never does.
 */
function detectType(raw) {
  const text = String(raw || '');
  try {
    const products = require('./products');
    const t = products.detect(text, 0.5);
    if (t && t !== 'haproxy' && t !== 'nginx') return t;
  } catch { /* registry unavailable: classic rule below */ }
  return /^\s*(events|http|stream|server|upstream|location)(\s[^\n#;{}]*)?\{\s*(#.*)?$/m.test(text) ? 'nginx' : 'haproxy';
}
module.exports = { detectType };

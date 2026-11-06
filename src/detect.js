'use strict';
/** Guess whether a config is NGINX or HAProxy. NGINX uses braces to open blocks; HAProxy never does. */
function detectType(raw) {
  return /^\s*(events|http|stream|server|upstream|location)(\s[^\n#;{}]*)?\{\s*(#.*)?$/m.test(raw) ? 'nginx' : 'haproxy';
}
module.exports = { detectType };

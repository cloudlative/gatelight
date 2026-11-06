'use strict';
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
let threshold = LEVELS.info;
function setLevel(l) { threshold = LEVELS[l] || LEVELS.info; }
function log(level, msg, extra) {
  if (LEVELS[level] < threshold) return;
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra });
  (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n');
}
module.exports = {
  setLevel,
  debug: (m, e) => log('debug', m, e), info: (m, e) => log('info', m, e),
  warn: (m, e) => log('warn', m, e), error: (m, e) => log('error', m, e),
};

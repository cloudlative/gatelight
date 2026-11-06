'use strict';
const { loadSettings } = require('./src/settings');
const { createApp } = require('./src/app');
const log = require('./src/logger');
const { ensureInitialPassword } = require('./src/initialAuth');

let settings;
try { settings = loadSettings(); } catch (e) {
  console.error(`Configuration error: ${e.message}`);
  process.exit(1);
}
log.setLevel(settings.logLevel);
const firstRun = ensureInitialPassword(settings);

const { app, registry } = createApp(settings);
registry.start();

const server = app.listen(settings.port, settings.host, () => {
  log.info('GateLight started', {
    url: `http://${settings.host}:${settings.port}`,
    instances: settings.instances.map((i) => i.id),
    auth: settings.auth.enabled, alerts: Boolean(settings.alerts.webhookUrl),
  });
  if (firstRun.active && firstRun.generated) {
    log.info(`FIRST RUN: sign in as "${firstRun.user}" with the password  ${firstRun.password}  (kept in the data volume; set AUTH_PASS to choose your own)`);
  } else if (firstRun.active) {
    log.info(`Signed-in user "${firstRun.user}": the generated password is in ${firstRun.file} (docker compose exec gatelight cat /app/data/.initial-password)`);
  }
  if (!settings.auth.enabled) {
    log.warn('Sign-in is DISABLED: anyone who can reach this port can use GateLight. Set AUTH_USER and AUTH_PASS (or AUTH_PASS_HASH) before exposing it beyond this machine.');
  } else if (settings.auth.pass && settings.auth.pass.length < 12) {
    log.warn('AUTH_PASS is shorter than 12 characters. Use a long random password (or AUTH_PASS_HASH).');
  }
  if (settings.instances.length === 0) {
    log.warn('No instances configured. Set HAPROXY_STATS_URL, INSTANCES_FILE, or DEMO_MODE=true.');
  }
});

function shutdown(signal) {
  log.info(`${signal} received, shutting down`);
  registry.stop();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (e) => log.error('unhandledRejection', { error: String(e && e.stack || e) }));

'use strict';
const { httpRequest } = require('./transport');
const log = require('./logger');

const ICON = { critical: ':red_circle:', warning: ':warning:', recovery: ':white_check_mark:', info: ':information_source:' };

/**
 * Fire-and-forget webhook notifier. Payload is Slack/Mattermost/Teams-"text"
 * compatible and also carries structured fields for generic receivers.
 */
class Notifier {
  constructor({ webhookUrl, insecureTls }) {
    this.url = webhookUrl;
    this.insecureTls = insecureTls;
  }

  get enabled() { return Boolean(this.url); }

  async notify(event) {
    if (!this.enabled) return;
    if (event.level === 'info') return;
    const body = JSON.stringify({
      text: `${ICON[event.level] || ''} [${event.instanceName}] ${event.message}`,
      source: 'gatelight', ...event,
    });
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await httpRequest(this.url, {
          method: 'POST', body, headers: { 'Content-Type': 'application/json' },
          timeout: 5000, insecureTls: this.insecureTls,
        });
        if (res.status < 300) return;
        throw new Error(`HTTP ${res.status}`);
      } catch (e) {
        if (attempt === 3) { log.warn('alert webhook failed', { error: e.message }); return; }
        await new Promise((r) => setTimeout(r, attempt * 1000));
      }
    }
  }
}

module.exports = { Notifier };

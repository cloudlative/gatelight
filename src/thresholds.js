'use strict';
/**
 * Threshold alert rules, evaluated after every successful poll.
 *
 * Each rule watches one condition (error ratio, latency, saturation, a server that stays down). A condition must hold
 * for `forSeconds` before it fires, so one bad sample does not page anyone; it then emits one `threshold` event
 * (sent to the webhook like any other warning) and a `recovery` event when it clears. While it holds it is listed
 * as "firing" in the snapshot, so the Overview and the API can show what is wrong right now.
 *
 * Every rule can be switched off with 0. Defaults come from ALERT_* env vars and can be overridden per instance
 * with `"alertRules": { ... }` in instances.json.
 */

const RULES = {
  errorPct: { label: '5xx error ratio', unit: '%', env: 'ALERT_5XX_PCT', def: 5 },
  latencyMs: { label: 'Average server response time', unit: 'ms', env: 'ALERT_LATENCY_MS', def: 1000 },
  saturationPct: { label: 'Sessions near the limit', unit: '%', env: 'ALERT_SATURATION_PCT', def: 90 },
  queue: { label: 'Requests waiting in a queue', unit: '', env: 'ALERT_QUEUE', def: 10 },
  downMinutes: { label: 'Server down for too long', unit: 'min', env: 'ALERT_DOWN_MINUTES', def: 5 },
};
const MIN_RATE = 1; // req/s below which the error ratio is too noisy to judge

const num = (v, d) => {
  if (v === undefined || v === null || v === '') return d;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : d;
};

/** Global defaults from the environment. */
function ruleDefaults(env = process.env) {
  const out = { forSeconds: num(env.ALERT_FOR_SECONDS, 60) };
  for (const [k, r] of Object.entries(RULES)) out[k] = num(env[r.env], r.def);
  return out;
}

/** Defaults merged with an instance's own `alertRules` (unknown keys and bad values are ignored). */
function resolveRules(defaults, overrides) {
  const out = { ...defaults };
  if (overrides && typeof overrides === 'object') {
    for (const k of [...Object.keys(RULES), 'forSeconds']) if (k in overrides) out[k] = num(overrides[k], out[k]);
  }
  return out;
}

const pct = (v) => `${(Math.round(v * 10) / 10).toLocaleString('en-US')}%`;
const label = (r) => (r.kind === 'server' ? `server ${r.proxy}/${r.name}` : `${r.kind} ${r.proxy}`);

/** The conditions that hold right now, as {key, rule, message, value, threshold, since?}. Pure: easy to test. */
function conditions(rows, summary, rules, now = Date.now()) {
  const out = [];
  if (rules.errorPct > 0) {
    let req = 0; let err = 0;
    for (const r of rows) if (r.kind === 'backend') { req += r.ratePerSec || 0; err += r.err5xxPerSec || 0; }
    if (req >= MIN_RATE) {
      const ratio = (err / req) * 100;
      if (ratio >= rules.errorPct) out.push({ key: 'errorPct', rule: 'errorPct', value: ratio, threshold: rules.errorPct, message: `5xx errors are ${pct(ratio)} of requests (threshold ${pct(rules.errorPct)})` });
    }
  }
  if (rules.latencyMs > 0 && summary && summary.rtimeAvg >= rules.latencyMs) {
    out.push({ key: 'latencyMs', rule: 'latencyMs', value: summary.rtimeAvg, threshold: rules.latencyMs, message: `Average server response time is ${Math.round(summary.rtimeAvg)} ms (threshold ${rules.latencyMs} ms)` });
  }
  for (const r of rows) {
    if (!['frontend', 'backend', 'server'].includes(r.kind)) continue;
    const id = `${r.proxy}/${r.name}`;
    if (rules.saturationPct > 0 && r.slim > 0 && r.scur != null) {
      const p = (r.scur / r.slim) * 100;
      if (p >= rules.saturationPct) out.push({ key: `saturationPct:${id}`, rule: 'saturationPct', proxy: r.proxy, name: r.name, value: p, threshold: rules.saturationPct, message: `${label(r)} is at ${pct(p)} of its session limit (${r.scur}/${r.slim})` });
    }
    if (rules.queue > 0 && r.kind !== 'frontend' && r.qcur >= rules.queue) {
      out.push({ key: `queue:${id}`, rule: 'queue', proxy: r.proxy, name: r.name, value: r.qcur, threshold: rules.queue, message: `${label(r)} has ${r.qcur} requests waiting in its queue (threshold ${rules.queue})` });
    }
    if (rules.downMinutes > 0 && r.kind === 'server' && r.state === 'down') {
      // HAProxy reports how long the state has lasted (lastchg, seconds); otherwise we count from when we first saw it.
      const since = Number.isFinite(r.lastchg) && r.lastchg >= 0 ? now - r.lastchg * 1000 : null;
      out.push({ key: `downMinutes:${id}`, rule: 'downMinutes', proxy: r.proxy, name: r.name, threshold: rules.downMinutes, since, forMs: rules.downMinutes * 60000, message: `${label(r)} has been down for more than ${rules.downMinutes} min` });
    }
  }
  return out;
}

/** Keeps per-instance rule state between polls and turns conditions into events. */
class ThresholdEvaluator {
  constructor(rules) {
    this.rules = rules;
    this.state = new Map(); // key -> {since, firing, firedAt, cond}
  }

  /**
   * @param emit (event) => void  called with level 'warning' when a rule fires and 'recovery' when it clears
   * @returns the list of firing alerts
   */
  evaluate(rows, summary, emit, now = Date.now()) {
    const seen = new Set();
    for (const c of conditions(rows, summary, this.rules, now)) {
      seen.add(c.key);
      let s = this.state.get(c.key);
      if (!s) { s = { since: c.since != null ? Math.min(c.since, now) : now, firing: false }; this.state.set(c.key, s); }
      s.cond = c;
      const holdMs = c.forMs != null ? c.forMs : this.rules.forSeconds * 1000;
      if (!s.firing && now - s.since >= holdMs) {
        s.firing = true; s.firedAt = now;
        emit({ level: 'warning', type: 'threshold', rule: c.rule, proxy: c.proxy, name: c.name, value: c.value, threshold: c.threshold, message: `Alert: ${c.message}` });
      }
    }
    for (const [key, s] of this.state) {
      if (seen.has(key)) continue;
      this.state.delete(key);
      if (s.firing) {
        const mins = Math.max(1, Math.round((now - s.firedAt) / 60000));
        emit({ level: 'recovery', type: 'threshold', rule: s.cond.rule, proxy: s.cond.proxy, name: s.cond.name, message: `Resolved after ${mins} min: ${RULES[s.cond.rule].label.toLowerCase()}${s.cond.proxy ? ` (${s.cond.proxy}${s.cond.name && s.cond.name !== s.cond.proxy ? `/${s.cond.name}` : ''})` : ''} is back under the threshold` });
      }
    }
    return this.firing();
  }

  /** Firing alerts plus the ones still waiting out `forSeconds` (pending), newest condition first. */
  firing() {
    const out = [];
    for (const [key, s] of this.state) {
      const c = s.cond;
      out.push({ key, rule: c.rule, label: RULES[c.rule].label, status: s.firing ? 'firing' : 'pending', since: s.since, firedAt: s.firedAt || null, proxy: c.proxy || null, name: c.name || null, value: c.value ?? null, threshold: c.threshold, message: c.message });
    }
    return out.sort((a, b) => (a.status === b.status ? b.since - a.since : a.status === 'firing' ? -1 : 1));
  }

  /** Forget everything (e.g. when the endpoint becomes unreachable: we cannot tell whether a condition still holds). */
  reset() { this.state.clear(); }
}

module.exports = { RULES, ruleDefaults, resolveRules, conditions, ThresholdEvaluator };

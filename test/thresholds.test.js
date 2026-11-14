'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { ThresholdEvaluator, ruleDefaults, resolveRules, conditions } = require('../src/thresholds');

const rules = (o = {}) => resolveRules(ruleDefaults({}), { forSeconds: 30, ...o });
const be = (o) => ({ kind: 'backend', proxy: 'api', name: 'BACKEND', state: 'up', ...o });
const sv = (o) => ({ kind: 'server', proxy: 'api', name: 's1', state: 'up', ...o });

test('defaults come from ALERT_* and can be overridden per instance, 0 disables a rule', () => {
  const d = ruleDefaults({ ALERT_5XX_PCT: '2', ALERT_LATENCY_MS: 'nonsense', ALERT_FOR_SECONDS: '0' });
  assert.equal(d.errorPct, 2); assert.equal(d.latencyMs, 1000); assert.equal(d.forSeconds, 0);
  const r = resolveRules(d, { latencyMs: 250, errorPct: 0, bogus: 1 });
  assert.equal(r.latencyMs, 250); assert.equal(r.errorPct, 0); assert.equal(r.bogus, undefined);
  assert.deepEqual(conditions([be({ ratePerSec: 100, err5xxPerSec: 50 })], { rtimeAvg: 0 }, r), []);
});

test('error ratio needs enough traffic and is measured across backends', () => {
  const r = rules();
  assert.equal(conditions([be({ ratePerSec: 0.5, err5xxPerSec: 0.5 })], {}, r).length, 0, 'too little traffic to judge');
  const c = conditions([be({ ratePerSec: 90, err5xxPerSec: 1 }), be({ proxy: 'web', ratePerSec: 10, err5xxPerSec: 9 })], {}, r);
  assert.equal(c.length, 1); assert.equal(c[0].rule, 'errorPct'); assert.equal(Math.round(c[0].value), 10);
});

test('saturation, queue and latency conditions', () => {
  const c = conditions([sv({ scur: 95, slim: 100 }), be({ qcur: 12 }), { kind: 'frontend', proxy: 'fe', name: 'FRONTEND', qcur: 99 }], { rtimeAvg: 1500 }, rules());
  assert.deepEqual(c.map((x) => x.rule).sort(), ['latencyMs', 'queue', 'saturationPct']);
  assert.ok(c.find((x) => x.rule === 'saturationPct').key.endsWith('api/s1'));
});

test('a condition fires only after forSeconds, once, and recovers once', () => {
  const ev = new ThresholdEvaluator(rules());
  const events = []; const emit = (e) => events.push(e);
  const bad = [be({ ratePerSec: 100, err5xxPerSec: 20 })]; const good = [be({ ratePerSec: 100, err5xxPerSec: 0 })];
  let t = 1_000_000;
  assert.equal(ev.evaluate(bad, {}, emit, t)[0].status, 'pending');
  assert.equal(events.length, 0);
  t += 31_000; assert.equal(ev.evaluate(bad, {}, emit, t)[0].status, 'firing');
  t += 5_000; ev.evaluate(bad, {}, emit, t);
  assert.equal(events.length, 1); assert.equal(events[0].level, 'warning'); assert.equal(events[0].type, 'threshold');
  t += 120_000; assert.deepEqual(ev.evaluate(good, {}, emit, t), []);
  assert.equal(events.length, 2); assert.equal(events[1].level, 'recovery'); assert.match(events[1].message, /Resolved after 2 min/);
});

test('a blip shorter than forSeconds never fires', () => {
  const ev = new ThresholdEvaluator(rules());
  const events = [];
  ev.evaluate([be({ ratePerSec: 100, err5xxPerSec: 20 })], {}, (e) => events.push(e), 0);
  ev.evaluate([be({ ratePerSec: 100, err5xxPerSec: 0 })], {}, (e) => events.push(e), 10_000);
  assert.equal(events.length, 0);
});

test('server down too long uses HAProxy lastchg when present', () => {
  const ev = new ThresholdEvaluator(rules({ downMinutes: 5 }));
  const events = [];
  ev.evaluate([sv({ state: 'down', lastchg: 30 })], {}, (e) => events.push(e), 10_000_000);
  assert.equal(events.length, 0, 'down for 30 s: not yet');
  const ev2 = new ThresholdEvaluator(rules({ downMinutes: 5 }));
  ev2.evaluate([sv({ state: 'down', lastchg: 600 })], {}, (e) => events.push(e), 10_000_000);
  assert.equal(events.length, 1); assert.match(events[0].message, /api\/s1 has been down for more than 5 min/);
});

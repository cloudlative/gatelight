#!/usr/bin/env node
'use strict';
/**
 * `npm test`: runs the suite with node --test and refuses a run that executed fewer tests than the last known count
 * (test/.test-count). A runner that stops early and still says "pass" (it happened with --test-force-exit) fails
 * here instead of hiding tests. When you add tests, run `npm test -- --update-count` to raise the baseline.
 */
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const BASELINE = path.join(__dirname, '..', 'test', '.test-count');
const update = process.argv.includes('--update-count');
const args = ['--test', '--test-timeout=60000', '--test-reporter=spec', '--test-reporter-destination=stdout', '--test-reporter=tap', `--test-reporter-destination=${path.join(require('os').tmpdir(), `gatelight-tap-${process.pid}.txt`)}`];

const child = spawn(process.execPath, args, { stdio: 'inherit', cwd: path.join(__dirname, '..') });
child.on('exit', (code) => {
  const tapFile = args[args.length - 1].split('=')[1];
  let tap = '';
  try { tap = fs.readFileSync(tapFile, 'utf8'); fs.unlinkSync(tapFile); } catch { /* no report */ }
  const n = (k) => { const m = tap.match(new RegExp(`^# ${k} (\\d+)$`, 'm')); return m ? Number(m[1]) : null; };
  const tests = n('tests'); const cancelled = n('cancelled') || 0;
  const expected = fs.existsSync(BASELINE) ? Number(fs.readFileSync(BASELINE, 'utf8').trim()) : 0;
  if (code !== 0) process.exit(code || 1);
  if (tests == null) { console.error('\nCould not read the number of tests that ran.'); process.exit(1); }
  if (cancelled) { console.error(`\n${cancelled} test(s) were cancelled.`); process.exit(1); }
  if (update) { fs.writeFileSync(BASELINE, `${tests}\n`); console.log(`\nTest count baseline set to ${tests}.`); process.exit(0); }
  if (tests < expected) {
    console.error(`\nOnly ${tests} tests ran, but ${expected} are expected (test/.test-count). Tests were skipped or removed.\nIf tests were removed on purpose, run: npm test -- --update-count`);
    process.exit(1);
  }
  if (tests > expected) console.log(`\n${tests} tests ran (baseline ${expected}). Run \`npm test -- --update-count\` to record the new count.`);
  process.exit(0);
});

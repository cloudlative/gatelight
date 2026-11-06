#!/usr/bin/env node
'use strict';
/**
 * gatelight hash-password   (password on stdin; prints a value for AUTH_PASS_HASH)
 * gatelight audit <config> [--type haproxy|nginx] [--format text|json|github] [--fail-on error|warning|never]
 * Intended for CI pipelines: exits non-zero when findings at/above --fail-on exist.
 */
const fs = require('fs');
const { parseConfig } = require('./haproxyConfig');
const { loadNginxConfig } = require('./nginxConfig');
const { auditNginx } = require('./nginxAudit');
const { detectType } = require('./detect');
const { auditConfig, summarize, SEVERITY_ORDER } = require('./audit');

function main(argv) {
  const [cmd, file, ...rest] = argv;
  if (cmd === 'hash-password') {
    // Prefer stdin so the password never lands in shell history.
    const pw = file || fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');
    if (!pw) { console.error("Usage: printf '%s' 'your password' | gatelight hash-password   (then set AUTH_PASS_HASH to the output)"); return 2; }
    console.log(require('./login').hashPassword(pw));
    return 0;
  }
  if (cmd !== 'audit' || !file || file.startsWith('-')) {
    console.error('Usage: gatelight audit <config> [--type haproxy|nginx] [--format text|json|github] [--fail-on error|warning|never]');
    return 2;
  }
  const opt = (name, def) => { const i = rest.indexOf(`--${name}`); return i >= 0 && rest[i + 1] ? rest[i + 1] : def; };
  const format = opt('format', 'text');
  const failOn = opt('fail-on', 'error');
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { console.error(`Cannot read ${file}: ${e.message}`); return 2; }

  // Type: explicit flag, else guess (nginx files contain "server {" / "upstream" blocks and no HAProxy sections).
  const type = opt('type', detectType(raw));
  let findings;
  if (type === 'nginx') {
    const r = loadNginxConfig(file);
    findings = auditNginx(r.sections, { notes: r.notes });
  } else {
    findings = auditConfig(parseConfig(raw));
  }
  const summary = summarize(findings);

  if (format === 'json') {
    console.log(JSON.stringify({ file, summary, findings }, null, 2));
  } else if (format === 'github') {
    for (const f of findings) {
      const level = f.severity === 'info' ? 'notice' : f.severity;
      console.log(`::${level} file=${f.file || file},line=${f.line || 1},title=${f.id}::${f.title}`);
    }
  } else {
    for (const f of findings) console.log(`${f.file || file}:${f.line || 0}  ${f.severity.toUpperCase().padEnd(7)} ${f.id.padEnd(28)} ${f.title}`);
    console.log(`\n${summary.error} error(s), ${summary.warning} warning(s), ${summary.info} info`);
  }
  if (failOn === 'never') return 0;
  const threshold = SEVERITY_ORDER[failOn] ?? 0;
  return findings.some((f) => SEVERITY_ORDER[f.severity] <= threshold) ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));

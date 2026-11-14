'use strict';
const esc = (v) => String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
const labels = (o) => `{${Object.entries(o).map(([k, v]) => `${k}="${esc(v)}"`).join(',')}}`;

/** Prometheus text exposition of GateLight-derived state (health, audit, drift). */
function renderMetrics(registry) {
  const out = [];
  const meta = (name, type, help) => { out.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`); };
  const snaps = [...registry.pollers.values()].map((p) => p.snapshot).filter(Boolean);

  meta('gatelight_instance_up', 'gauge', '1 if the last poll of the HAProxy stats endpoint succeeded.');
  for (const s of snaps) out.push(`gatelight_instance_up${labels({ instance: s.instance.id })} ${s.ok ? 1 : 0}`);

  meta('gatelight_instance_last_poll_timestamp_seconds', 'gauge', 'Unix time of the last poll attempt.');
  for (const s of snaps) out.push(`gatelight_instance_last_poll_timestamp_seconds${labels({ instance: s.instance.id })} ${(s.ts / 1000).toFixed(3)}`);

  meta('gatelight_server_up', 'gauge', '1 if the server is UP (or OPEN), 0 otherwise.');
  meta('gatelight_server_current_sessions', 'gauge', 'Current sessions.');
  meta('gatelight_server_sessions_total', 'counter', 'Total sessions.');
  meta('gatelight_server_bytes_in_total', 'counter', 'Bytes in.');
  meta('gatelight_server_bytes_out_total', 'counter', 'Bytes out.');
  meta('gatelight_server_http_responses_total', 'counter', 'HTTP responses by class.');
  for (const s of snaps) {
    for (const r of s.rows) {
      if (!['server', 'backend', 'frontend'].includes(r.kind)) continue;
      const l = { instance: s.instance.id, type: s.instance.type, proxy: r.proxy, name: r.name, kind: r.kind };
      out.push(`gatelight_server_up${labels(l)} ${r.state === 'up' || r.state === 'degraded' ? 1 : 0}`);
      if (r.scur != null) out.push(`gatelight_server_current_sessions${labels(l)} ${r.scur}`);
      if (r.stot != null) out.push(`gatelight_server_sessions_total${labels(l)} ${r.stot}`);
      if (r.bin != null) out.push(`gatelight_server_bytes_in_total${labels(l)} ${r.bin}`);
      if (r.bout != null) out.push(`gatelight_server_bytes_out_total${labels(l)} ${r.bout}`);
      for (const c of ['2xx', '3xx', '4xx', '5xx']) {
        const v = r[`hrsp_${c}`];
        if (v != null) out.push(`gatelight_server_http_responses_total${labels({ ...l, code: c })} ${v}`);
      }
    }
  }

  meta('gatelight_config_findings', 'gauge', 'Configuration audit findings by severity.');
  for (const s of snaps) {
    for (const sev of ['error', 'warning', 'info']) {
      out.push(`gatelight_config_findings${labels({ instance: s.instance.id, severity: sev })} ${s.findingsSummary[sev]}`);
    }
  }
  meta('gatelight_config_drift_findings', 'gauge', 'Differences between the config file and the running process.');
  for (const s of snaps) out.push(`gatelight_config_drift_findings${labels({ instance: s.instance.id })} ${s.findings.filter((f) => f.category === 'drift').length}`);

  meta('gatelight_alerts_firing', 'gauge', 'Threshold alerts currently firing, by rule.');
  for (const s of snaps) {
    const by = {};
    for (const a of s.alerts || []) if (a.status === 'firing') by[a.rule] = (by[a.rule] || 0) + 1;
    for (const rule of ['errorPct', 'latencyMs', 'saturationPct', 'queue', 'downMinutes']) out.push(`gatelight_alerts_firing${labels({ instance: s.instance.id, rule })} ${by[rule] || 0}`);
  }

  return `${out.join('\n')}\n`;
}

module.exports = { renderMetrics };

# Changelog

## 3.0.0 — first open-source release
- **One-file setup**: `curl` the compose file, `docker compose up -d`. Multi-arch image on GHCR, first-run sign-in password generated and printed in the logs.
- **Graphs** page (zoom, pan, shared crosshair, clickable legends, donut charts for HTTP errors), **LB Infra** page (what is behind the load balancer and whether it is alive), charts on Services and Config audit, details pages instead of a side panel, profile page.
- **History in SQLite**: chart samples and events survive restarts; ranges up to 7 days.
- **NGINX support** alongside HAProxy (config parser with `include` resolution, 17 audit rules, `stub_status`, NGINX Plus API, TCP probing); either technology can be disabled.
- **Upload & preview**: drop a config file or a whole folder to get the relationship map, audit and searchable config — no live server needed.
- Server-side polling with history, rate derivation, state-change events, webhook alerts, Prometheus `/metrics`, multi-instance fleet view.
- 39 audit rules incl. config drift; `gatelight audit` CLI with GitHub annotations.
- Security hardening: auth, secret redaction, strict CSP, no SSRF surface, sandboxed includes, hardened container.
- Redesigned UI: light/dark themes, command palette, keyboard shortcuts, focus-highlighting, PNG export, self-hosted assets (air-gap friendly).
- Replaces the 2.x prototype (see git history).

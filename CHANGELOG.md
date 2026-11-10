# Changelog

## Unreleased

### Added
- **Validate** page and engine: version-aware validation of HAProxy (1.7–3.4) and NGINX configurations against the official documentation, with version-dependent recommendations. Knowledge bases are generated from the manuals (`npm run kb:build`).
- **Traffic flow** page: listener port → backend port map (TLS terminate / re-encrypt / passthrough, HAProxy omitted-port and `+N` rules, check-only `port`), URI map with rewrite chains and examples, a diagram, a "Try a request" tracer, and routing findings (shadowed rules, check-port mismatch, TLS/port mismatch, self-loop, NGINX trailing-slash and `rewrite … break`). Port and URI details also appear in Topology tooltips and the rule inspector.
- **L7 / L4 in the topology**: every frontend and pool is labelled L7 (HTTP) or L4 (TCP); L4 nodes have a dashed outline, a layer filter and a tooltip explaining what that layer can and cannot see (no paths, headers or rewrites at L4). Also in the tree, URL map, rule inspector and Traffic flow page. The HAProxy example now includes a TCP (MQTT) frontend.
- Traffic flow **Domains** tab: domain → listener port → rule → pool → server address and port, per host name (wildcard, default, catch-all, redirect-only, dynamic), with live status, a per-domain Trace button and domain findings (duplicate `server_name` on a port, HTTP-only names).
- Traffic flow marks every relationship as active / idle / down / never used / configured (from runtime stats), with moving dashes for live traffic and a Status column in the Port map.
- API: `GET /api/instances/:id/flow`, `POST /api/instances/:id/flow/trace`, `POST /api/flow`.
- API: `POST /api/validate`, `GET /api/instances/:id/validate`, `GET /api/validate/versions`.

- **Refresh from server**: fetch the configuration again on demand (button on the Config page) from the server's config URL(s) or file, read-only (`GET` only), with a summary of what changed. New `configUrls` / `*_CONFIG_URL` setting and a Config URL(s) field in the connection form. API: `POST /api/instances/:id/config/refresh`.

### Security
- Read-only toward load balancers is now enforced in code: only `GET`/`HEAD` (no body) to servers, only `show stat` / `show info` on the HAProxy Runtime API, tests prevent any other write path.

### Changed
- The app header no longer shows the tagline (it stays on the sign-in page and the website).

## 3.0.0 — first open-source release
- **One-file setup**: `curl` the compose file, `docker compose up -d`. Multi-arch image on GHCR, first-run sign-in password generated and printed in the logs.
- **Graphs** page (zoom, pan, shared crosshair, clickable legends, donut charts for HTTP errors), **Infrastructure** page (what is behind the load balancer and whether it is alive), charts on Services and Config audit, details pages instead of a side panel, profile page.
- **History in SQLite**: chart samples and events survive restarts; ranges up to 7 days.
- **NGINX support** alongside HAProxy (config parser with `include` resolution, 17 audit rules, `stub_status`, NGINX Plus API, TCP probing); either technology can be disabled.
- **Upload & preview**: drop a config file or a whole folder to get the relationship map, audit and searchable config — no live server needed.
- Server-side polling with history, rate derivation, state-change events, webhook alerts, Prometheus `/metrics`, multi-instance fleet view.
- 39 audit rules incl. config drift; `gatelight audit` CLI with GitHub annotations.
- Security hardening: auth, secret redaction, strict CSP, no SSRF surface, sandboxed includes, hardened container.
- Redesigned UI: light/dark themes, command palette, keyboard shortcuts, focus-highlighting, PNG export, self-hosted assets (air-gap friendly).
- Replaces the 2.x prototype (see git history).

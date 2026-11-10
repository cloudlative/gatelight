# Changelog

## Unreleased

### Added
- **Validate** page and engine: version-aware validation of HAProxy (1.7–3.4) and NGINX configurations against the official documentation, with version-dependent recommendations. Knowledge bases are generated from the manuals (`npm run kb:build`).
- **Traffic flow** page: listener port → backend port map (TLS terminate / re-encrypt / passthrough, HAProxy omitted-port and `+N` rules, check-only `port`), URI map with rewrite chains and examples, a diagram, a "Try a request" tracer, and routing findings (shadowed rules, check-port mismatch, TLS/port mismatch, self-loop, NGINX trailing-slash and `rewrite … break`). Port and URI details also appear in Topology tooltips and the rule inspector.
- **L7 / L4 in the topology**: every frontend and pool is labelled L7 (HTTP) or L4 (TCP); L4 nodes have a dashed outline, a layer filter and a tooltip explaining what that layer can and cannot see (no paths, headers or rewrites at L4). Also in the tree, URL map, rule inspector and Traffic flow page. The HAProxy example now includes a TCP (MQTT) frontend.
- Traffic flow **Domains** tab: domain → listener port → rule → pool → server address and port, per host name (wildcard, default, catch-all, redirect-only, dynamic), with live status, a per-domain Trace button and domain findings (duplicate `server_name` on a port, HTTP-only names).
- Traffic flow diagram: click a listener, rule or pool to see only its relationships (a listener keeps just its own port), with a "Show all" button; click empty space to clear.
- Traffic flow **status filter** (Alive / Not alive / Unused) on every tab; in Domains it also filters the servers inside each card.
- Traffic flow marks every relationship as active / idle / down / never used / configured (from runtime stats), with moving dashes for live traffic and a Status column in the Port map.
- API: `GET /api/instances/:id/flow`, `POST /api/instances/:id/flow/trace`, `POST /api/flow`.
- **Traffic statistics** page: upload an HAProxy log (plain or `.gz`, one file at a time, 50 MB by default, `LOG_MAX_MB`) from Add instance or the page itself, and get requests, TCP sessions, response-time percentiles, error rate, throughput, concurrency, status/method/protocol breakdowns, backends, servers, frontends, latency histogram, termination states, top URLs (ids grouped), slowest requests, top clients, sites, error samples, server events, SSL/connection errors and a data-quality card, with time (drag to zoom), frontend, backend, server, status and protocol filters. The log is streamed and only aggregates are stored (`DATA_DIR/logs`, mode 0600); malformed lines are skipped and counted; oversized, empty, binary, corrupt and non-HAProxy files get clear errors, and splitting commands are shown next to the upload. The parser is separate from the dashboard so NGINX logs can be added later. A "traffic log only" connection works without a stats endpoint. API: `PUT/GET/DELETE /api/instances/:id/logs`.
- **Traffic statistics: several log files, shown combined.** Select many files at once, or add them one by one later: each is processed on its own (one per request, up to 20 per instance) and the dashboard shows the total. The same file cannot be added twice, a file can be removed with its ×, and "Delete all" clears everything. API: `PUT /api/instances/:id/logs` now adds (use `?mode=replace` to start over), `DELETE …/logs?part=<id>` removes one file. Unique clients is an estimate when files are combined.
- **Topology: collapse and expand.** Shift-click a frontend or backend (or use the Collapse / Expand button in the selection bar) to fold what hangs below it; "Collapse all" and "Expand all" in the toolbar fold or unfold everything, and folded nodes show how much is hidden. Arrows now also point from each pool to its members, so every link shows the direction of traffic (client → frontend → backend → server), with a note in the legend.
- **Config Forge** page (Configuration → Config Forge): paste, upload or pick an instance's config and get a 0-100 score, a list of explained and switchable changes, a rewritten best-practice configuration (changed lines highlighted), a diff, copy/download and the test/reload commands. Version-aware, NGINX-inheritance-aware, comments preserved, and idempotent (the result proposes nothing new). Covers TLS, security headers, redirects, timeouts, health checks, logging, forwarded headers, upstream keep-alive, HTTP/2, catch-all servers, exposed status pages and legacy syntax for both HAProxy and NGINX. API: `POST /api/improve`, `POST /api/instances/:id/improve`.
- **Pages merged**: *Config audit*, *Validate* and *Config Forge* are now one page, **Config Forge**. One list of findings from the structural audit, the version validator and the rewrite rules, with each concern reported once (the other checks are noted on it), severity and category filters, JSON export, line links to the Config page, an auto-loaded instance config, the detected version, and `nginx -V` build info. The audit CLI, `/api/validate`, `/api/analyze`, Prometheus metrics, alerts and drift detection are unchanged; old `#…/audit` and `#…/validate` links open Config Forge.
- **Pages merged (2)**: *Infrastructure* is now the **Network** layout in Topology (same hierarchy, grouping and aliveness filters; old links open it). The URL-map drawer in Topology is replaced by a button to **Traffic flow → URI map**, and the Traffic flow *Diagram* tab is gone (the Topology graph shows the same relationships, with ports and URIs in its tooltips and click-to-focus).
- **Pages merged (3)**: *Graphs* and *Traffic statistics* are now one nav entry, **Traffic**, with a **Live metrics / From a log file** switch at the top of each. Instances without a stats endpoint (log-only) open the log view directly. Old links keep working.
- API: `POST /api/validate`, `GET /api/instances/:id/validate`, `GET /api/validate/versions`.

- **Refresh from server**: fetch the configuration again on demand (button on the Config page) from the server's config URL(s) or file, read-only (`GET` only), with a summary of what changed. New `configUrls` / `*_CONFIG_URL` setting and a Config URL(s) field in the connection form. API: `POST /api/instances/:id/config/refresh`.

### Security
- Read-only toward load balancers is now enforced in code: only `GET`/`HEAD` (no body) to servers, only `show stat` / `show info` on the HAProxy Runtime API, tests prevent any other write path.

### Changed
- Filters now reset when you navigate: leaving a page (or switching instance) clears that page's search, status, layer, severity and focus filters, so coming back never shows a half-filtered list. Links that open a page with a preset filter (for example an Overview card) still apply it.
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

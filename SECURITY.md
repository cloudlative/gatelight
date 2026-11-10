# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately via GitHub's *Security → Report a vulnerability*
(private advisory) on this repository, with steps to reproduce. We aim to acknowledge within 3 working days
and to ship a fix or mitigation within 30 days for confirmed issues. You will be credited unless you prefer otherwise.

## Scope and design assumptions

GateLight reads configuration files and statistics from your load balancers. Items we treat as vulnerabilities:

- Disclosure of credentials or secrets (stats passwords, `stats auth`, userlist passwords, auth headers) through the UI, API, logs or metrics
- Server-side request forgery, path traversal / reading files outside the configured config root (including via `include`), or remote code execution
- Authentication bypass when `AUTH_*` is configured; XSS despite the CSP; stored/reflected injection through config or stats content

Operational guidance (see README → Security model): enable authentication, serve over TLS, give GateLight a read-only
stats user, mount configuration read-only, and do not expose it to the public internet.

## Supported versions

The latest release receives security fixes.

## Read-only by design

GateLight never changes a load balancer. HTTP requests to servers are limited to `GET`/`HEAD` without a body, the HAProxy Runtime API accepts only `show stat` and `show info`, and configuration files are only read. These limits are enforced in `src/transport.js` and checked by `test/readonly.test.js`. The alert webhook is the only outbound write and goes to the URL you configure. If you find a path that can modify a server, please report it as a vulnerability.

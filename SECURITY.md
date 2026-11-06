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

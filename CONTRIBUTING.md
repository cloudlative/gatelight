# Contributing

Thanks for helping! This project is intentionally small: Node (no build step), Express, vanilla JS UI.

## Setup

```bash
npm ci
npm test                 # must stay green
DEMO_MODE=true npm start # http://localhost:3000 with synthetic traffic on the bundled examples
```

## Ground rules

- **Never commit real configs, hostnames, IPs or credentials** — not even in tests or screenshots. Use `examples/` (sanitised) and RFC 5737 / `10.x` addresses. `config/` and `.env` are git-ignored on purpose.
- Add a test for every bug fix and every new rule. Real-world snippets are the best fixtures (sanitise them first).
- Keep dependencies minimal; new runtime dependencies need a strong reason.
- UI: no inline scripts/handlers (strict CSP); every dynamic string goes through `esc()`.

## Adding an audit rule

1. HAProxy → `src/audit.js`, NGINX → `src/nginxAudit.js`. Push a finding with `id`, `severity` (`error|warning|info`), `category`
   (`correctness|reliability|security|hygiene|drift`), `title`, `detail`, `fix`, `section`, `line` (NGINX also `file`).
2. Register a short plural description in that file's `RULE_TITLES` (used to group repeated findings in the UI).
3. Add a test in `test/haproxy.test.js` / `test/nginx.test.js` covering a hit **and** a near-miss that must not be flagged.
4. Prefer fewer, accurate rules over noisy ones: a finding should be something an operator would act on.

## Adding a technology

Implement a driver in `src/drivers.js` (`loadConfig`, `collect`, `audit`, `labels`) that maps its config to the shared model
(frontend → routes → backend → servers) and its stats to the normalised row format. The UI, poller, history, events, alerts and
metrics then work unchanged.

## Pull requests

Small, focused PRs with a clear description. CI runs the tests on Node 18/20/22 and smoke-builds the Docker image.
By contributing you agree your work is licensed under the MIT license.

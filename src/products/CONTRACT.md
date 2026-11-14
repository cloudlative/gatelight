# Product module contract

Every proxy technology GateLight understands is one module in `src/products/<type>/index.js`, registered in
`src/products/index.js`. Shared code (pages, API, poller, Config Doctor, Request Routing, Traffic Stats, Config
Builder) only talks to this interface. HAProxy and NGINX are adapters over their existing modules; Apache, Caddy
and Traefik implement it directly.

All functions are synchronous and pure unless marked async. Nothing here may write to a proxy: live collection is
read-only (`GET`/`HEAD` only, through `src/transport.js` `httpRequest` / `fetchStats`).

```js
module.exports = {
  type: 'apache',                       // 'haproxy' | 'nginx' | 'apache' | 'caddy' | 'traefik'
  name: 'Apache HTTP Server',           // long name for headings
  short: 'Apache',                      // short name for chips and messages
  labels: { frontend: 'VirtualHost', backend: 'Balancer', server: 'Member' }, // what the shared model's nouns are called
  defaultFile: 'httpd.conf',            // file name used when a config is pasted
  example: '/abs/path/examples/apache/httpd.conf',  // bundled, sanitised example (used by demo mode and /api/examples/:type)
  fileFormats: ['httpd.conf', '*.conf'],            // hint for the UI

  detect(text) -> number,               // 0..1: how strongly a text looks like this product's configuration
                                        // (only the strongest product wins; keep NGINX/HAProxy/YAML/TOML false positives low)

  parseFiles(files) -> { sections, files, notes },
      // files: [{ name, content }] (relative names; includes resolved between them, never from disk)
      // sections: the SHARED MODEL below; files: [{ name, raw }] with secrets REDACTED; notes: [{ file, msg }]
  loadPath(mainPath, rootDir) -> { sections, files, notes },   // same, reading from disk; includes must stay inside rootDir
  redact(text) -> string,               // mask passwords, tokens, keys, basic-auth hashes, URLs with user:pass@

  audit(sections, { notes, rows }) -> findings,     // structural rules (see Finding)

  versions() -> { list: ['2.4.63', ...newest first], latest, generated, source },   // from the knowledge base
  validate({ files, version }) -> { target: { requested, version, note }, kb: { generated, source, latest }, findings },
      // version-aware, against the knowledge base in src/kb/<type>.json built from the OFFICIAL docs at release tags

  improve({ files, version }) -> { target, changes, render(enabled) -> files }
      // Config Doctor. change: { rule, category, severity: 'high'|'medium'|'low'|'info', title, why, section, line,
      //   auto: boolean (has a rewrite), on: boolean (enabled by default), ops: [{ kind: 'add'|'mod'|'del', text, before }] }
      // render(c => bool) returns [{ name, content }] with the enabled auto changes applied. Running improve() again on
      // the output must propose no new auto changes (idempotent).

  flow: {                                // Request Routing; see "Routes" below. The generic engine in src/flow.js does the rest.
    defaultPort(scheme) -> number,
  },

  live: {                                // optional: runtime stats
    hasSource(inst) -> boolean,
    sources(inst) -> ['admin-api', ...],
    async collect(inst, cache, ctx) -> { rows, info },   // rows in the HAProxy stats row shape (see Rows)
  },

  logs: {                                // optional: Traffic Stats from access logs
    createAggregator() -> { push(line) -> boolean, finish(meta) -> result, ... }   // use src/logs/haproxy.js createAggregator() core
    sniff(lines) -> { ratio },           // 0..1 share of lines this parser understands
  },

  build(spec) -> { files: [{ name, content }], notes: [string], unsupported: [string] },  // Config Builder, see src/build/spec.js
};
```

## Shared model (sections)

```js
{ type: 'global', name: 'global', line, file, directives: [...] }
{ type: 'frontend', name, line, endLine, file, mode: 'http'|'tcp',
  binds: [{ address: '*:443', addresses: ['*:443'], port: '443', ssl: true, options: {}, line, file, commented: false }],
  serverNames: ['shop.example.com', '*.example.com'],      // host names this frontend answers (empty = any)
  routes: [Route], acls: [], servers: [], users: [], timeouts: {}, effective: { mode, timeouts: {}, defaultServer: {} },
  directives: [{ keyword, args, line, file, raw, within: ['<Location /api>'] }],   // flat, for audit / line links
  locations: [{ path, modifier, line, file, kind: 'proxy'|'static'|'return'|'other', target, detail }],   // optional URL map extras
}
{ type: 'backend', name, line, file, mode, balance: 'roundrobin'|..., implicit: false,
  servers: [{ name, address: 'host:port', scheme: 'http'|'https'|'h2c'|..., check: bool, backup: bool, disabled: bool,
              weight: number|null, opts: {}, options: '', line, file, commented: false }],
  healthCheck: { path, interval } | null, sticky: bool, routes: [], binds: [], acls: [], users: [], timeouts: {}, effective: {...}, directives: [...] }
```

### Route (one per routing rule, IN EVALUATION ORDER for that product)

```js
{ target: 'api_pool',                  // backend section name (an implicit backend is created for a bare URL target)
  type: 'conditional'|'default',
  condition: 'Host(`a.com`) && PathPrefix(`/api`)',   // as written in the config
  rawCondition, match: 'Host is a.com and path begins with /api', short: 'a.com/api/*',
  matchers: [{ field: 'Host'|'Path'|'Method'|'Header'|'Query'|'SNI'|'ClientIP', op: 'is'|'begins with'|'ends with'|'matches'|'contains',
               values: ['/api'], negated: false, name?: 'X-Header' }],   // all must match (AND); use separate routes for OR
  hosts: ['a.com'], paths: ['/api/…'], priority: number|null,
  transforms: [{ action: 'strip-prefix'|'add-prefix'|'replace-path'|'replace-path-regex'|'set-path'|'set-header'|'redirect'|'return'|'deny',
                 args: [...], line, text: 'StripPrefix /api' }],     // applied in order before the request reaches the pool
  passUrl: 'http://api_pool/v2',       // if the product proxies to a URL with its own path
  terminal: false,                     // true when the route answers itself (redirect/return/static) and has no pool
  line, file, commented: false, dynamic: false, external: false }
```

## Finding

```js
{ id: 'apache-proxy-no-timeout', severity: 'error'|'warning'|'info', category: 'security'|'reliability'|'performance'|
  'observability'|'compatibility'|'hygiene'|'syntax'|'compat'|'recommendation'|'drift',
  section, file, line, title, detail, fix, docs?: 'https://…official page#anchor', since?: '2.4.30', until?: '...' }
```

## Rows (live stats)

Same shape as `src/statsParser.js` rows: `{ proxy, name, kind: 'frontend'|'backend'|'server', status: 'UP'|'DOWN'|'OPEN'|'MAINT'|'NO CHECK',
scur, stot, req_tot, hrsp_2xx..hrsp_5xx, bin, bout, rtime, qcur, slim, check_status, last_chk, lastchg, addr }`, numbers or null.
`proxy` / `name` must match the section / server names from the parsed config so the topology can join them.

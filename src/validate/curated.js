'use strict';
/**
 * Hand-curated knowledge that the manuals do not state in machine-readable form:
 * what to use instead of a removed/deprecated keyword, and when special address forms appeared.
 * The *facts* about availability (since / removed / deprecated) always come from src/kb/*.json.
 */
const legacyReq = (what, repl) => ({ fix: `Replace it with ${repl}. The old req*/rsp* rules were removed in 2.1.`, older: `Use ${repl}.` });
const REPLACEMENT = {
  haproxy: {
    nbproc: { fix: 'Use `nbthread` (threads share stick-tables, health checks and stats) and, from 2.7, `thread-groups` on large machines.' },
    'bind-process': { fix: 'Remove it; threads replace processes. Pin threads with `cpu-map` if needed.' },
    grace: { fix: 'Use `hard-stop-after` to bound how long old processes live after a reload.' },
    block: { fix: 'Use `http-request deny if <condition>` (or `tcp-request content reject`).' },
    reqadd: { fix: 'Use `http-request add-header <name> <fmt>`.' }, reqiadd: { fix: 'Use `http-request add-header <name> <fmt>`.' },
    reqdel: { fix: 'Use `http-request del-header <name>`.' }, reqidel: { fix: 'Use `http-request del-header <name>`.' },
    reqrep: legacyReq('reqrep', '`http-request replace-header|replace-path|replace-uri`'), reqirep: legacyReq('reqirep', '`http-request replace-header|replace-path`'),
    reqallow: { fix: 'Use `http-request allow if <condition>`.' }, reqiallow: { fix: 'Use `http-request allow if <condition>`.' },
    reqdeny: { fix: 'Use `http-request deny if <condition>`.' }, reqideny: { fix: 'Use `http-request deny if <condition>`.' },
    reqpass: { fix: 'Remove it, or use `http-request allow`.' }, reqipass: { fix: 'Remove it, or use `http-request allow`.' },
    reqtarpit: { fix: 'Use `http-request tarpit if <condition>`.' }, reqitarpit: { fix: 'Use `http-request tarpit if <condition>`.' },
    rspadd: { fix: 'Use `http-response add-header <name> <fmt>`.' }, rspdel: { fix: 'Use `http-response del-header <name>`.' }, rspidel: { fix: 'Use `http-response del-header <name>`.' },
    rsprep: legacyReq('rsprep', '`http-response replace-header`'), rspirep: legacyReq('rspirep', '`http-response replace-header`'),
    rspdeny: { fix: 'Use `http-response deny if <condition>`.' }, rspideny: { fix: 'Use `http-response deny if <condition>`.' },
    clitimeout: { fix: 'Use `timeout client`.' }, srvtimeout: { fix: 'Use `timeout server`.' }, contimeout: { fix: 'Use `timeout connect`.' },
    'timeout clitimeout': { fix: 'Use `timeout client`.' }, 'timeout srvtimeout': { fix: 'Use `timeout server`.' }, 'timeout contimeout': { fix: 'Use `timeout connect`.' },
    redispatch: { fix: 'Use `option redispatch` (with `retries`).' }, redisp: { fix: 'Use `option redispatch`.' },
    appsession: { fix: 'Use `stick-table` + `stick on` / `stick store-response`, or insert a cookie with `cookie <name> insert`.' },
    'option forceclose': { fix: 'Use `option http-server-close` (or the default keep-alive behaviour).' },
    'option http-tunnel': { fix: 'Use `option http-server-close`; HTTP tunnel mode no longer exists.' },
    'option http_proxy': { fix: 'Forward proxy mode was removed; use a dedicated proxy or `http-request set-dst` based routing.' },
    'option http-use-htx': { fix: 'Remove it; HTX is always on from 2.0.' },
    'monitor-net': { fix: 'Use `monitor-uri` or an ACL on `src` with `http-request return`.' },
    'option transparent': { fix: 'Use `source <addr> usesrc clientip` on the server/backend.' }, transparent: { fix: 'Use `source <addr> usesrc clientip`.' },
    dispatch: { fix: 'Declare a regular `server` line instead.' },
    'ssl-engine': { fix: 'Use OpenSSL providers (`ssl-provider`, `ssl-provider-path`) with OpenSSL 3.' },
  },
};

// address prefix forms accepted by `bind` / `server`
const ADDRESS_SINCE = { quic4: '2.6', quic6: '2.6', abns: '1.8', sockpair: '1.8', fd: '1.7', unix: '1.7', ip4: '1.7', ip6: '1.7', udp4: '2.6', udp6: '2.6' };

// NGINX things the docs record only in prose
const NGINX_PARAM_SINCE = {
  listen: { http2: '1.9.5', quic: '1.25.0', ssl: '0.7.14', reuseport: '1.9.1', proxy_protocol: '1.5.12', so_keepalive: '1.1.11', fastopen: '1.21.0', multipath: '1.29.7' },
  ssl_protocols: { TLSv1_3: '1.13.0' },
};

module.exports = { REPLACEMENT, ADDRESS_SINCE, NGINX_PARAM_SINCE };

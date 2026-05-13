# AGENTS.md

This file gives coding agents and contributors a fast map of the repository and the guardrails to follow when changing it.

## What this repository is

`sentirum-lb` is a Rust HTTP load balancer inspired by Fabio. It uses Pingora for proxying, Consul for dynamic route discovery, and `arc-swap` for lock-free route table reads.

## Core architecture

- `src/main.rs`
  - loads optional config and CLI overrides
  - wires Pingora server settings
  - starts proxy listener, optional TLS listeners (primary + additional), admin API, and Consul watchers
  - each file-based TLS listener gets its own `FileCertWatcherService` background service for hot-reload

- `src/proxy/handler.rs`
  - hot-path request handling
  - reads runtime config via `arc_swap::ArcSwap` on every request (strategy, matcher, timeouts, CB, rate-limit all live-switchable)
  - route lookup
  - upstream peer construction
  - SSRF checks
  - protocol-aware HTTP/2 / gRPC / gRPC-Web / WebSocket handling
  - path rewriting
  - request/response logging and metrics

- `src/route/`
  - `parser.rs`: Fabio-style route command parsing
  - `definition.rs`: route command model
  - `target.rs`: upstream target model, SSRF helpers, circuit breaker, and DNS cache
  - `table.rs`: immutable route table snapshots and matchers
  - `registry.rs`: merge static, KV, and service-discovery routes safely; `append_static()` for live route addition
  - `picker.rs`: balancing strategies (round-robin, random, least-connections)

- `src/proxy/tls/`
  - `config.rs`: TLS mode resolution, client auth config
  - `selector.rs`: SNI-based cert selection; `ServerCertificateSource::Static` wraps `Arc<ArcSwap<LoadedCertificate>>` for hot-reload
  - `watcher.rs`: `FileCertWatcherService` polls cert+key file mtime every 30s, reloads on change
  - `helpers.rs`: PEM parsing, certificate name extraction, ASN1 time conversion
  - `ocsp.rs`: OCSP stapling infrastructure

- `src/consul/`
  - `client.rs`: Consul HTTP client and blocking query URLs
  - `watcher.rs`: KV and health/catalog watchers

- `src/admin/api.rs`
  - operational inspection endpoints
  - `PUT /admin/config` — runtime hot-reload of proxy settings (strategy, matcher, timeouts, CB, health check, rate limit, logging)
  - `POST /admin/routes` — live route addition via Fabio-style commands
  - `DELETE /admin/routes/static` — clear static routes
  - `POST /admin/config/reset` — reset to startup config
  - `/admin` redirect to `/admin/` (trailing slash)
  - SSE URL percent-decode for session token auth
- `src/metrics/prometheus.rs`
  - in-process counters/gauges/histogram buckets

## Working agreements

- Keep changes surgical and behavior-safe
- Reuse existing helpers before adding new abstractions
- Do not remove SSRF protections unless explicitly requested
- Prefer atomic route-table rebuild/swap patterns over mutating hot-path shared state
- Keep request-path allocations minimal in proxy code
- When changing watcher behavior, preserve separation between:
  - static file routes
  - Consul KV routes
  - Consul service routes
- Circuit breaker is per-target: each `Target` has its own `health_tracker` with independent state
- DNS cache is a global singleton: `global_dns_cache()` returns a shared `DnsCache` instance
- Service filtering (whitelist/blacklist) applies to service discovery but not KV routes

## Configuration expectations

These config values are live and should stay wired unless intentionally redesigned:

- `server.admin_token`
- `server.workers`
- `consul.poll_interval`
- `consul.service_whitelist`
- `consul.service_blacklist`
- `proxy.strategy`
- `proxy.matcher`
- `proxy.request_id_header`
- `proxy.no_route_status`
- `proxy.connect_timeout`
- `proxy.read_timeout`
- `proxy.write_timeout`
- `proxy.idle_timeout`
- `proxy.enable_h2c`
- `proxy.upstream_h2_max_streams`
- `proxy.upstream_h2_ping_interval`
- `proxy.pool_size`
- `proxy.max_connections`
- `proxy.circuit_breaker_enabled`
- `proxy.circuit_breaker_error_threshold`
- `proxy.circuit_breaker_window_size`
- `proxy.circuit_breaker_recovery_timeout`
- `proxy.circuit_breaker_half_open_max`
- `proxy.dns_cache_ttl`
- `proxy.dns_negative_cache_ttl`
- `tls.cert_path`
- `tls.key_path`
- `tls.listen`
- `tls_listeners` — array of additional TLS listener configs; each supports its own cert, listen address, client auth (mTLS), and cert hot-reload
- `proxy.health_check_interval`
- `proxy.health_check_timeout`
- `proxy.health_check_fall`
- `proxy.health_check_rise`
- `proxy.health_check_path`
- `proxy.health_check_tls_skip_verify`
- `proxy.rate_limit_per_target`
- `proxy.rate_limit_burst`
- `consul.graceful_shutdown`

If you introduce a new config field, wire it into runtime behavior and cover it with tests when practical.

## Circuit breaker behavior details

- **Minimum sample threshold**: Circuit opens when `error_rate >= error_threshold%` AND `window_len >= min_samples`. `min_samples = max(window_size / 4, 5)`. This ensures the circuit can open even before the window is full if error rate is high enough (e.g., 100% failure on first 25 requests with threshold=50 and window=100)
- **Half-open probe timeout**: If a half-open probe's callback is lost (DNS failure, connection drop without logging), the `half_open_in_flight` flag is auto-reset after `recovery_timeout` seconds. This prevents permanent HalfOpen stuck state
- **Check ordering**: Rate limit → Circuit breaker check → Connection slot acquire. CB is checked before acquiring connection slots to avoid unnecessary acquire/release cycles
- **Matcher hot path**: `MatcherKind` enum (not string) is used on the hot path for branch-prediction-friendly dispatch

- No-match responses use `proxy.no_route_status`
- Circuit breaker: when `proxy.circuit_breaker_enabled` is true, failing upstream targets are temporarily bypassed with 503; when a picked target has an open circuit breaker, the proxy attempts to find a healthy fallback on the same route before returning 503
- Circuit breaker states: Closed → Open (on error threshold) → HalfOpen (after recovery_timeout) → Closed (on probe success)
- DNS cache: `proxy.dns_cache_ttl` controls positive cache TTL (default 30s); `proxy.dns_negative_cache_ttl` controls negative cache TTL (default 10s)
- `iprefix` is case-insensitive prefix matching
- `glob` uses the `glob` crate pattern support
- `strip` happens before `prepend`
- Query strings must survive rewrites
- `host=` route option overrides upstream Host header and TLS SNI
- `grpc` / `grpcs` targets must stay on HTTP/2-capable upstream paths
- gRPC-Web requests are bridged to native gRPC upstreams in the proxy layer
- WebSocket support relies on Pingora’s upgrade path; keep upgrade semantics intact
- `strip` / `prepend` remain available, but gRPC rewrites must preserve a valid `/Service/Method` path
- With the current Pingora rustls upstream connector, `tlsskipverify=true` is not fully reliable for self-signed `grpcs` / `wss` upstreams; prefer trusted/internal CA certificates and do not document self-signed bypass as production-safe
- `max_connections` is enforced per upstream target
- `0` for `max_connections` means unlimited

## Consul notes

- Blocking queries must use `index` and `wait` query params, not `X-Consul-Index` request headers
- Empty KV snapshots should clear only KV routes
- Empty service snapshots should clear only service-discovery routes
- Do not collapse all empty updates into a generic shared event
- Keep Fabio-compatible tag semantics:
  - `urlprefix-/api` => catch-all path route
  - `urlprefix-example.com/api` => host-specific path route
  - service name is not injected into the route host
- Consul-discovered targets are trusted to use RFC1918/private addresses by default; loopback/link-local/localhost-style targets must still remain blocked unless explicitly bypassed

## Testing expectations

Before finishing changes, run:

```bash
cargo test --quiet
```

Add or update unit tests when you touch:

- route parsing
- matcher behavior
- rewrite behavior
- metrics accounting
- Consul URL construction
- protocol detection / HTTP/2 wiring / gRPC trailer behavior

Add or update ignored integration tests when you touch:

- gRPC / gRPCS routing
- gRPC-Web bridging
- WebSocket / WSS proxying
- h2c enablement

## Documentation expectations

If you change user-facing behavior, also update:

- `README.md` for runtime usage/config
- `AGENTS.md` for contributor/agent guidance when the change affects architecture or workflow

## Known non-goals / placeholders

- Raw TCP proxy mode supports plain TCP, TCP+SNI routing, dynamic listeners, and PROXY protocol v1; production-tested with NATS protocol (INFO, PING/PONG, CONNECT/SUB/PUB/UNSUB, queue groups, 50KB payloads, 20 concurrent connections)

## Implemented features (recently added)

- **Active health checking**: HTTP/TCP probes via `src/proxy/health.rs`; config: `proxy.health_check_interval`, `proxy.health_check_timeout`, `proxy.health_check_rise`, `proxy.health_check_fall`, `proxy.health_check_path`; `is_probe_healthy()` integrated into proxy hot path via `lookup_target()`; probe health status works alongside circuit breaker; all HC params are runtime-switchable via `PUT /admin/config`
- **Token Bucket rate limiting (per-target)**: `parking_lot::Mutex<BucketState>` based via `src/proxy/ratelimit.rs`; config: `proxy.rate_limit_per_target` (0=disabled), `proxy.rate_limit_burst`; per-target override via opts `ratelimit=X burst=Y`; returns 429 when exceeded; runtime-switchable via `PUT /admin/config`
- **Multi-TLS listener**: `[[tls_listeners]]` in config for additional TLS endpoints (e.g., mTLS on a separate port); each listener has independent cert, client auth, and hot-reload; primary `[tls]` section is always listener 0
- **File-based TLS cert hot-reload**: `FileCertWatcherService` in `src/proxy/tls/watcher.rs` polls cert+key file mtime every 30s and atomically swaps via `ArcSwap<LoadedCertificate>`; new TLS handshakes immediately use refreshed cert; manual reload via `POST /admin/certs/reload`
- **Dynamic route management**: `POST /admin/routes` for live Fabio-style route addition; `DELETE /admin/routes/static` to clear static routes; routes appear in dashboard immediately
- **OCSP stapling infrastructure**: `src/proxy/ocsp.rs`; fetcher, cache, and config wiring implemented; actual TLS handshake stapling depends on Pingora exposing `SSL_set_ocsp_resp` callback

## Runtime hot-reloadable settings (via `PUT /admin/config`)

These settings can be changed at runtime without restart:
- `proxy.strategy` (round-robin, random, least-connections)
- `proxy.matcher` (prefix, iprefix, glob, exact)
- `proxy.request_id_header`
- `proxy.no_route_status`
- `proxy.*_timeout` (connect, read, write, idle)
- `proxy.max_connections`
- `proxy.dns_cache_ttl`, `proxy.dns_negative_cache_ttl`
- `proxy.circuit_breaker_*` (enabled, error_threshold, window_size, recovery_timeout, half_open_max)
- `proxy.upstream_h2_max_streams`, `proxy.upstream_h2_ping_interval`
- `proxy.health_check_*` (interval, timeout, fall, rise, path, tls_skip_verify)
- `proxy.rate_limit_per_target`, `proxy.rate_limit_burst`
- `logging.level`, `logging.format`

Not hot-reloadable (require restart): `pool_size`, `enable_h2c`, `trusted_proxies`

## Commit hygiene

- Keep commits focused
- Do not commit `target/` or IDE folders
- Be careful with accidental filesystem artifact paths in commits
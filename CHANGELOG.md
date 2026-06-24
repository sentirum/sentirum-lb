# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Hardening pass from a full-codebase audit: correctness, availability, and security fixes plus hot-path performance work. No config schema breakage; new validation rejects values that previously degraded silently.

### Security

- **Admin token no longer accepted in the query string.** `?token=` auth (used by SSE/dashboard streams) now accepts only ephemeral session tokens; the long-lived `server.admin_token` must travel in a header (`Authorization: Bearer` / `X-Admin-Token`) so it cannot leak into access logs or browser history.
- **Required mTLS fails closed when the client-CA store is empty** instead of silently disabling client-certificate verification.
- **Primary TLS listener failure is now fatal.** A primary cert/settings load failure exits the process (matching the existing client-CA behavior) rather than silently coming up plaintext-only with the HTTPS port absent.

### Fixed

- **Route-weight DoS (Critical).** A non-finite or very large route `weight` (from a static file, Consul tag, or `POST /admin/routes`) expanded the weighted-target list without bound, OOM-ing or wedging the process on the lock-held route rebuild. Weights are now validated finite and per-target slot expansion is capped.
- **`glob` matcher black-holed literal routes.** Under `matcher = "glob"`, every literal-path route — including the `/` catch-all — was unreachable (`no_route`). A literal path now matches itself under glob mode; the catch-all is preserved.
- **`exact` matcher implemented.** It was documented/hot-reloadable but silently fell back to prefix matching, broadening routes (e.g. `/admin` also served `/admin-backup`). `exact` now matches the full path.
- **Unknown `proxy.matcher` / `proxy.strategy` are rejected** at config load and via `PUT /admin/config`, instead of silently degrading to prefix / round-robin. The strategy hot path no longer logs a per-request warning.
- **Rate limit is now truly hot-reloadable.** Changing or disabling `proxy.rate_limit_per_target` at runtime now affects already-warm targets; per-target buckets reconcile to the live global config (a per-route `ratelimit=` override still sticks).
- **Negative DNS cache now suppresses re-resolution.** NXDOMAIN hosts fast-fail for `dns_negative_cache_ttl` instead of re-resolving on every request.
- **TLS cert/key hot-reload no longer publishes a mismatched pair** observed mid-rotation: the private key is verified against the leaf certificate, and a mismatch keeps the current certificate and retries on the next poll.
- **Circuit-breaker opens on error *rate*, not absolute count.** The open threshold is computed over the current window length, so the `min_samples` early-open gate works during warm-up — a fully-failing upstream trips at the documented sample count instead of ~2× later, and the regression recurs no longer after each recovery.
- **Half-open probe slot is released** when a request is rejected by the rate limiter or connection-slot limit after the probe was reserved, preventing recovery from stalling for `recovery_timeout`.
- **Active health-check TCP probe has a connect timeout**, so a SYN-black-holing target no longer pins a probe-concurrency slot for the OS connect timeout.
- **Consul service-watcher retry path is no longer dead code.** After a transient catalog-lookup failure the stashed snapshot is actually retried on the next tick (previously the index guard discarded it, so new service state could be delayed indefinitely).
- **Consul blocking-query HTTP timeout** now exceeds Consul's `wait + wait/16` jitter, eliminating spurious watcher errors/backoff on an idle cluster with the default 5m wait. The parsed index is clamped to ≥1 to avoid a non-blocking busy-loop if `X-Consul-Index` is ever absent.
- **Dynamic TCP listener that fails to bind is rebound** on the next reconcile instead of being left permanently dead.
- **Config validation gaps closed**: `health_check_rise`/`health_check_fall` must be ≥ 1 (no single-sample flapping), `no_route_status` must be a valid HTTP status, and `request_id_header` must be a valid header name (an invalid name previously failed every request).
- **`X-Forwarded-For` preserves the full client chain** (all header values) instead of keeping only the first.
- **`Host` header IPv6 parsing is consistent** — `[::1]` and `[::1]:8080` both normalize to `::1`.
- **PROXY protocol v1 emits `TCP4`** for IPv4-mapped IPv6 client addresses on dual-stack listeners instead of a malformed `TCP6 ::ffff:a.b.c.d` line.
- **Token-bucket scaling** uses saturating multiplication, and the PEM scanner skips an unterminated block instead of dropping all blocks after it.

### Performance

- **Target route options are pre-parsed into typed fields** (`strip`, `prepend`, `host`, `tlsskipverify`, `readtimeout`, `pxyproto`, header constraints), removing ~5 per-request HashMap lookups plus per-request duration/header parsing from the proxy hot path.
- **Header-constrained routes** filter the small target list instead of cloning the up-to-1000-slot weighted list (and re-parsing header constraints) on every request.
- **DNS cache lookups** take a single read lock on the common live-entry path (write lock only on actual expiry).
- **bcrypt verification and admin certificate file reads** run on the blocking pool instead of stalling the single-threaded async admin worker.
- **Raw TCP proxy** drops the `arc_swap` config guard before the long-lived `copy_bidirectional` (avoiding debt-slot exhaustion that pushed the HTTP hot-path `load()` onto the slow clone path), bounds pre-routing handshakes with a global semaphore (slowloris defense), and applies an idle timeout to reap half-open connections.

### Changed

- **Concurrent `PUT`/`POST /admin/config` are serialized** so updates compose (no lost updates) and the config, trusted-proxy, and circuit-breaker swaps apply as one atomic group.
- The route matcher is now a single shared helper (`Table::route_matches`) used by both the collect and find paths, so matcher semantics cannot drift between them.

## [1.5.0] - 2026-06-06

### Added

- **TCP keepalive on pooled connections (Issue #22)** — both upstream (LB → backend) and downstream (edge/CDN → LB) pooled connections now carry TCP keepalive probes, so silently-dead connections are detected and evicted before a request is written into them. Previously a dead pooled connection would black-hole a non-idempotent (POST/PUT/PATCH) request until `read_timeout`, surfacing as 100s+ stalls and Cloudflare 524s.
  - `proxy.upstream_tcp_keepalive` — pooled LB→backend keepalive, format `"idle,interval,count"` (default `"15s,5s,3"`; empty disables)
  - `proxy.downstream_tcp_keepalive` — accepted CDN→LB keepalive, applied to the plaintext listener and **every** TLS listener (default `"15s,5s,3"`; empty disables)
  - `proxy.upstream_user_timeout` — `TCP_USER_TIMEOUT` (Linux only); bounds unacknowledged upstream writes so a black-holed write fails in ~30s instead of waiting on `read_timeout` (default `"30s"`; empty/0 = system default)
- **Streaming-aware read timeout (Issue #22)** — `proxy.stream_read_timeout` (default `"3600s"`) applies to long-lived streams (WebSocket upgrades, SSE via `Accept: text/event-stream`), while non-streaming requests use the shorter `proxy.read_timeout`. This lets the LB fail fast on dead non-streaming upstreams while keeping streams alive.
- **Per-route `readtimeout=` target option** — Fabio-style escape hatch that overrides the read timeout for a specific target (e.g. `readtimeout=120s`); takes precedence over both `read_timeout` and `stream_read_timeout`. Covers long-polling and non-standard SSE backends that have no deterministic request-side signal.

### Changed

- **Parsed TCP keepalive is cached** in `ParsedProxyTimeouts` (lazily computed, `OnceLock`-backed) so the `"idle,interval,count"` string is parsed once per config rather than on every request; config swaps (ArcSwap) recompute automatically.
- **All dependencies upgraded to latest stable** — pingora 0.8.0→0.8.1, thiserror 1→2, base64 0.21→0.22, rand 0.8→0.10, dashmap 5→6, reqwest 0.12→0.13, bcrypt 0.15→0.19, tonic/tonic-build/prost 0.12/0.13→0.14 (+ `tonic-prost`), criterion 0.5→0.8, rcgen 0.13→0.14, tokio-tungstenite 0.24→0.29. No public API or config breakage; verified against the full unit + e2e suite (gRPC/gRPC-Web/WebSocket/mTLS/TCP). `rand` session-token generation remains CSPRNG-backed (ChaCha12 ThreadRng).

### Notes

- `read_timeout` is now the **non-streaming** default. Deployments that previously set a long `read_timeout` (e.g. `3600s`) for WebSocket/SSE compatibility should lower it (e.g. `60s`) and rely on `stream_read_timeout` for long-lived streams — see the updated `docs/sentirum-lb.nomad.hcl`.

## [1.3.2] - 2026-05-15

### Fixed

- **Hot-path clone elimination (PERF-HOT-1)** — `lookup_target()` no longer clones the full target list on every request. Non-header-constrained routes borrow directly from the ArcSwap snapshot via a `Borrowed`/`Owned` enum, eliminating N×Arc clones and 2 Vec allocations per request
- **Login rate limit TOCTOU** — replaced `retain()`→`get()`→`entry()` flow with atomic `DashMap::entry()` + `and_modify`/`or_insert` to prevent concurrent logins exceeding the rate limit
- **Query-token auth false 401s** — changed `try_read()` to `read().await` in SSE/dashboard auth path to prevent false 401 responses during login/logout write-lock contention
- **Metrics stream state coupling** — replaced `OnceLock` global static with per-state `RwLock<Option<watch::Sender>>` + lazy init + auto-stop when all receivers disconnect; fixes wrong-state-publish in test and multi-instance scenarios
- **Consul watcher index reset** — explicit detection and logging when Consul server restart causes index reset (`new_index < last_index`); prevents tight query loops on both service and KV watchers
- **Config update atomicity** — moved `dns_cache.set_ttl()` before `config.store()` in both update and reset handlers to eliminate micro-window of inconsistent DNS + proxy settings

### Changed

- **`matching_routes()` stack allocation** — `Vec` → `SmallVec<[&Arc<Route>; 4]>` for zero-heap-allocation on typical match counts ≤ 4
- **`all_targets` clone elimination** — `HashSet<String>` → `HashSet<&str>` during route table finalization
- **`escape_prometheus_label` DRY** — canonical implementation made `pub` in `prometheus.rs`; duplicate in `metrics_handler` replaced with delegate call
- **Clippy compliance** — resolved `map_or`→`is_none_or`, `match`→`?`, `filter().next()`→`find()`, `filter().cloned().next()`→`find().cloned()`

## [1.3.0] - 2026-05-13

### Added

- **Directory restructuring** — split god-object files into single-responsibility modules:
  - `route/target.rs` (2,112 → 811 lines, -62%): extracted `circuit_breaker.rs`, `dns_cache.rs`, `health_tracker.rs`, `target_stats.rs`
  - `admin/api.rs` (2,521 → 759 lines, -70%): extracted `auth.rs`, `config_handler.rs`, `metrics_handler.rs`, `certs_handler.rs`, `routes_handler.rs`
- **Runtime hot-reloadable health check settings** — `proxy.health_check_interval`, `proxy.health_check_timeout`, `proxy.health_check_fall`, `proxy.health_check_rise`, `proxy.health_check_path`, `proxy.health_check_tls_skip_verify` now switchable via `PUT /admin/config` without restart
- **Header-based routing (Approach A)** — target-level header filtering via `opts "header=X-Api-Key:required"` in route commands; backward-compatible with existing routes
- **`drain_timeout` wiring** — `server.drain_timeout` config maps to Pingora `grace_period_seconds` for graceful shutdown
- **Active health checking** — HTTP/TCP probes via `src/proxy/health.rs`; integrates with circuit breaker and per-target health tracking
- **Token Bucket rate limiting (per-target)** — `parking_lot::Mutex<BucketState>` based; config: `proxy.rate_limit_per_target`, `proxy.rate_limit_burst`; per-target override via `opts "ratelimit=X burst=Y"`; returns 429 when exceeded
- **Multi-TLS listener** — `[[tls_listeners]]` in config for additional TLS endpoints (e.g., mTLS on separate port); each listener has independent cert, client auth, and hot-reload
- **File-based TLS cert hot-reload** — `FileCertWatcherService` polls cert+key file mtime every 30s and atomically swaps via `ArcSwap`; manual reload via `POST /admin/certs/reload`
- **Dynamic route management** — `POST /admin/routes` for live Fabio-style route addition; `DELETE /admin/routes/static` to clear static routes
- **OCSP stapling infrastructure** — fetcher, cache, and config wiring; actual handshake stapling deferred to Pingora upstream support

### Changed

- **Pingora 0.5 → 0.8 upgrade** — only breaking change was `upstream_response_body_filter` return type
- **Config internals** — `Config` clone replaced with `Arc` for zero-copy runtime swaps; `ParsedProxyTimeouts` cached via `OnceLock`
- **Monotonic unified epoch** — single `MONO_EPOCH: OnceLock<Instant>` shared across circuit breaker, rate limiter, and DNS cache modules
- **Admin auth lock contention eliminated** — session eviction moved to dedicated background task (every 60s) instead of per-request write lock
- **Root directory cleanup** — removed 14 agent/junk files, updated `.gitignore` with agent artifact patterns

### Fixed

- **DnsCache TOCTOU** — replaced `remove()` + re-insert with `remove_if()` for atomic conditional update
- **Circuit breaker stale count** — re-read error count after lock acquisition to prevent stale window computation
- **Rate limiter connection slot leak** — added `retain()` cleanup for abandoned slots on target re-registration
- **26+ clippy warnings** — all resolved, zero warnings in CI
- **Path traversal validation** — admin API endpoints validate paths against directory traversal
- **Timestamp consistency** — `timestamp_ms` replaced with `elapsed_ms` for monotonic time sources across all modules

### Testing

- **250 tests, 0 failures, 0 clippy warnings**
- **Live load testing** — 93K+ requests across HTTP (3,445 req/s), HTTPS (248 req/s), gRPC, circuit breaker, and mixed protocols
- **29/29 live protocol tests** — gRPC unary/streaming, gRPC-Web, WebSocket, TCP/NATS

## [1.2.0] - 2026-05-09

### Added

- **CB-aware target fallback** — when the picker selects a circuit-breaker-open target,
  the proxy now scans remaining targets for a healthy alternative before returning 503.
  Previously a single CB-open target would immediately fail the request even when healthy
  targets were available on the same route.
- **`/admin` redirect** — `GET /admin` (no trailing slash) now redirects to `/admin/`
  with `308 Permanent Redirect`, fixing the JSON auth error that appeared when typing
  the admin URL without a trailing slash.
- **TCP/NATS Docker test infrastructure** — test environment now includes a NATS
  container (`nats:2.10-alpine` with JetStream) and a TCP route through the load balancer
  for end-to-end NATS protocol testing.
- **Comprehensive edge test suite** — `docker/test/edge-test.sh` with 11 sections
  (Auth, Routes, Admin API, SSE, TCP/NATS, Load, Security, Consistency, Errors,
  Round-trip, SSE Stability) covering 58+ test cases.

### Fixed

- **Dashboard JS syntax error** — `refreshStatic()` closing brace was missing, causing
  all subsequent JS functions (including `doLogin`) to be swallowed by the parser.
  The login screen showed `doLogin is not defined` in the browser console.
- **Prometheus histogram parsing** — `refreshMetrics()` now correctly parses Prometheus
  exposition format with labeled metrics (`{le="0.001"}`, `{code="2xx"}`). Previously
  the parser stripped labels and used wrong key names, causing latency and status code
  charts to show zero data.
- **Latency distribution chart** — histogram buckets are now converted from cumulative
  to per-bucket deltas for accurate bar chart rendering. Bar color changed from
  invisible `#27272a` to accent `#818cf8`.
- **Targets table flickering** — replaced full `innerHTML` rebuild with in-place DOM
  updates when the target list structure hasn't changed. Cells are updated individually
  without destroying and recreating the entire table, eliminating layout shift on every
  SSE tick.
- **SSE URL decode for session tokens** — session tokens containing `/` and `=` (e.g.,
  `h/Vv6exl...uzg=`) were URL-encoded by the browser but compared raw against the
  session store, causing 401 on SSE and log stream endpoints. Added inline percent-decode.
- **Dashboard trend indicators** — in-place target updates now include trend arrows
  (▲/▼) for request rate, error %, latency, and connections using delta tracking.
- **CSS transitions** — stat-card values and table cells now have smooth 300-400ms
  color transitions instead of abrupt changes.

### Changed

- **TCP proxy production status** — TCP modes (`tcp`, `tcp+sni`, `https+tcp+sni`,
  `tcp-dynamic`) are now production-tested with NATS protocol validation including
  INFO, PING/PONG, CONNECT/SUB/PUB/UNSUB, queue groups, 50KB payloads, 20 concurrent
  connections, binary garbage, and slow streams. Updated documentation accordingly.

### Testing

- **91/93 protocol edge-case tests passing** — comprehensive test coverage for NATS TCP
  (25/25), gRPC/RPC (29/29), WebSocket/H2 (24/24), WebSocket deep (13/15 — 2 fails
  due to upstream http-echo not supporting WS server).
- **Edge test shell compatibility** — replaced `curl -sf` with `curl -s`, removed
  `curl -o /dev/null` (Pingora keep-alive hang), replaced `timeout` (unavailable on macOS)
  with `curl --max-time` and `nc -w`.

## [1.2.1] - 2026-05-09

### Fixed

- **Security: Admin auth lock contention** — hot-path auth middleware no longer acquires write lock on every request; eviction handled by background task
- **Weight-aware least-connections picker** — respects configured weights by selecting target with lowest effective load (`active_connections / weight`)

## [1.1.2] - 2026-05-08


### Security

- **TCP proxy SSRF protection** — raw TCP proxy mode now enforces SSRF checks before opening
   upstream connections, blocking private/reserved IP targets unless `ssrfskipverify=true`.
   Previously SSRF was only enforced for HTTP/gRPC paths, leaving TCP passthrough unprotected.
   Added unit tests covering loopback, RFC1918, and ConsulService-source SSRF semantics.
- **DNS cache multi-A-record SSRF gap closed** — resolved addresses beyond the first were
   cached without SSRF validation, allowing a blocked IP to hide in the tail of a DNS
   response. All resolved addresses are now individually filtered before caching.

### Reliability

- **Admin auth lock contention eliminated** — hot-path auth middleware no longer acquires
   a write lock or runs O(n) session eviction on every request. Eviction is now handled
   by a dedicated background task running every 60 seconds, keeping the auth path as a
   fast read-only HashMap lookup.
- **Consul warning health status support** — new `consul.include_warning` config option
   (default: false). When enabled, services with Consul health status "warning" are
   included in route discovery alongside "passing". Previously only fully passing services
   were routed, causing traffic loss for degraded-but-functional instances.


### Performance

- **least-connections picker memory ordering** — `Relaxed` load replaced with `Acquire`
   ordering to form a proper AcqRel memory barrier with `try_acquire_connection_slot`'s
   `Release` store. This prevents torn reads on concurrent connection counts without
   the cost of full `SeqCst` serialization across all pick operations.
- **Round-robin picker ordering relaxed** — counter `fetch_add` changed from `SeqCst` to
   `Relaxed`. The counter only produces an index; no other memory location needs
   synchronization, making the full fence unnecessary overhead per pick.
- **Weight-aware least-connections picker** — `LeastConnectionsPicker` now respects
   configured weights by selecting the target with the lowest effective load
   (`active_connections / weight`). A target with weight 0.7 can hold proportionally
   more connections than one with weight 0.3 before being deprioritized. Targets with
   weight 0 are excluded (canary drain). Falls back to simple min-connections when
   no weights are configured (Fabio-compatible).


### Operations

- **Session cleanup visibility** — background cleanup logs evicted count and remaining
   session map size for operational monitoring.
- **Weight overflow warning** — `compute_weights` now logs a warning when fixed weights
   sum exceeds 1.0, alerting operators that dynamic targets will receive no traffic.
- **Circuit breaker state as Prometheus gauge** — new `sentirum_lb_target_circuit_breaker_state`
   metric per target (0=closed, 1=half-open, 2=open).
- **Circuit breaker transition history** — `CircuitBreaker` now records the last 20 state
   transitions with timestamps, exposed via `/admin/targets` for dashboard visualization.
- **Log search filtering** — `/admin/logs` endpoint accepts `?search=` query parameter for
   case-insensitive substring filtering on log messages.
- **Topology endpoint enriched** — `/admin/topology` now returns host→route→target hierarchy
   with weight, stats, and CB state per target instead of flat node/edge lists.
- **Target detail in API** — `/admin/targets` now includes `weight`, `fixed_weight`, `source`,
   and `circuit_breaker_history` fields per target.

### Dashboard (Admin UI)

- **Real-time SSE metrics** — replaced 3s polling with `EventSource` consuming the existing
   `/admin/metrics/stream` endpoint. Overview stats update every second with delta-based
   request/sec and error rate calculations.
- **Per-target sparklines** — inline SVG sparkline graphs showing request rate trend (last 60s)
   directly in the targets table.
- **Circuit breaker timeline** — visual state transition bar per target showing recent
   Closed/Open/HalfOpen history. Full transition table in target detail expansion.
- **Canvas force-directed topology** — interactive topology graph with pan/zoom/scroll,
   host-grouped layout, edge thickness proportional to connection count, node color by CB state.
- **Log filtering** — level filter buttons (ERROR/WARN/INFO/DEBUG/TRACE), text search with
   case-insensitive substring matching, search term highlighting.
- **Target detail expansion** — click any target row to expand full details: properties, stats,
   request/error trend sparklines (60s), weight breakdown, CB transition history table.
- **Weight visualization** — inline weight bar per target showing traffic distribution percentage.
- **Config diff viewer** — runtime config display highlights non-default values, masks sensitive
   fields (tokens, passwords).
- **TLS certificate page** — new Certs page showing loaded certificates with expiry countdown,
   color-coded warnings (<30 days yellow, <7 days red).
- **JSON export** — export routes and configuration as JSON files for troubleshooting.
- **Certs nav entry** — added certificate management to sidebar navigation.


## [1.1.1] - 2026-05-08

### Fixed

- **Security: Dashboard hardcoded auth token** — login now uses the server-issued session token instead of a hardcoded fallback
- **Security: SSE stream authentication** — EventSource endpoints now accept `?token=` query parameter since the API does not support custom headers
- **Security: XSS in dashboard** — all dynamic content rendered via innerHTML is now HTML-escaped
- **Security: Login rate limiting** — max 5 login attempts per username per 60-second window to prevent brute-force attacks
- **Security: Login input length limit** — usernames and passwords longer than 256 characters are rejected before bcrypt verification
- **Security: SSRF IP range coverage** — added blocking for multicast, CGNAT (100.64.0.0/10), documentation (RFC 5737), and benchmark (198.18.0.0/15) IP ranges
- **Security: SSRF cache re-validation** — DNS cache hits are now re-checked against current SSRF rules before use
- **Security: DNS cache unbounded growth** — added 10,000 entry limit with eviction on insert
- **Prometheus targets-metrics output** — fixed invalid text exposition format caused by whitespace indentation
- **Admin dashboard error handling** — shows error banner and disconnects live indicator when backend is unreachable
- **Admin dashboard WCAG contrast** — fixed secondary text colors to meet 4.5:1 contrast ratio against dark backgrounds
- **Admin dashboard responsive design** — added media queries for viewports under 768px
- **Admin dashboard language** — standardized all UI strings to English
- **Consul client error handling** — JSON deserialization failures now produce `ParseError` instead of generic `RequestError`

## [1.1.0] - 2026-05-08

### Added

- **gRPC / gRPC-Web / WebSocket proxy support** — full protocol-aware routing with gRPC-Web-to-native bridging, WebSocket upgrade passthrough, and per-target ALPN negotiation
- **TCP proxy with dynamic routing** — SNI-based multiplexing (`https+tcp+sni` mode), PROXY protocol v1 header support, per-target connection limits
- **TLS module restructured** — split into `config`, `helpers`, and `selector` submodules; dynamic certificate loading from Consul KV; strict SNI mode
- **mTLS client certificate forwarding** — `X-Client-Cert-*` headers derived from verified peer certificates with identity caching (LRU, 4096 entries)
- **Trusted proxy + Cloudflare-aware header handling** — `X-Forwarded-For` chain preservation, `CF-Connecting-IP` passthrough, configurable CIDR-based trusted proxy ranges
- **Consul service discovery enhancements** — Fabio-compatible health check aggregation (node maintenance, service maintenance, all-checks-must-pass), concurrent catalog lookups
- **E2E test suite** — mTLS, protocol (gRPC/WebSocket), and TCP integration tests

### Changed

- **Proxy handler refactored into focused submodules** — `rewrite`, `forwarded`, `protocol`, `client_cert` for maintainability
- Dependencies updated (Pingora 0.5, Rustls, Tokio, Axum)

### Fixed

- **Security: `X-Client-Cert-*` header spoofing** — headers are now unconditionally stripped before conditionally inserting authoritative values, preventing downstream identity injection on non-mTLS connections
- **Security: `constant_time_eq` timing leak** — admin token length no longer leaks through iteration count; fixed 256-iteration loop
- **Logic: DNS cache stored incomplete address list** — single-address DNS responses were never cached; resolved address is now included in the cached list
- **Logic: DNS cache TTL config silently ignored** — `dns_cache_ttl` / `dns_negative_cache_ttl` config values are now correctly applied to the global cache at startup via `AtomicU64` fields
- **Logic: Circuit breaker stuck in half-open** — consumed probe slots are now resolved with `record_error()` when connection slot acquisition fails, preventing permanent half-open deadlock
- **Logic: Consul service watcher spin-loop** — fixed condition to skip on unchanged index regardless of check contents, consistent with KV watcher behavior
- Production blocker fixes — config panic, duration parser, Consul timeout, TLS port, feature flags, mutex recovery, backoff, loopback checks

## [1.0.3] - 2026-04-XX

### Fixed

- Minor reliability fixes

## [1.0.2] - 2026-04-XX

### Fixed

- Bug fixes and stability improvements

## [1.0.1] - 2026-04-XX

### Fixed

- Initial production fixes

## [1.0.0] - 2026-04-XX

### Added

- Initial release — HTTP load balancer with Pingora proxy, Consul KV and service discovery, Fabio-style route tags, TLS support, admin API, Prometheus metrics

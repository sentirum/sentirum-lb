# Sentirum LB — System Review Guide

Architecture, protocol, UI/UX, security, and operational readiness review checklist for Sentirum LB.

---

## 1. Architecture Review

### 1.1 Data Flow & Component Topology

- [ ] **Request lifecycle is end-to-end traceable**: Client → Pingora listener → `early_request_filter` (protocol detection) → `request_filter` (health check / WebSocket intercept) → `upstream_peer` (route lookup + circuit breaker + connection limit + SSRF + DNS resolution) → `upstream_request_filter` (request ID, Forwarded headers, client cert headers, path rewrite, Host override) → upstream proxy → `response_filter` (status capture, X-Served-By) → `upstream_response_body_filter` (byte accounting) → `logging` (access log + Prometheus metrics + circuit breaker result recording + connection release).
- [ ] **Route table swap is atomic**: `ManagedRouteTable` uses `arc_swap::ArcSwap` for lock-free reads. Writes (rebuild) go through `Mutex<RouteRegistry>` → rebuild `Table` → `arc_swap.store()`. Verify no partial snapshots are ever visible on the hot path.
- [ ] **Three source partitioning is clean**: Static file routes, Consul KV routes, and Consul service-discovery routes are merged by `RouteRegistry` into a single `Table`. Empty KV snapshots clear only KV routes; empty service snapshots clear only service routes. No cross-contamination.
- [ ] **Background service separation**: `ConsulBackgroundService`, `ConsulTlsBackgroundService`, `ConsulClientCaBackgroundService`, `AdminBackgroundService`, `TcpBackgroundService` run as independent Pingora `BackgroundService` tasks. Evaluate whether failure isolation is adequate — does a Consul watch failure starve TLS cert rotation?

### 1.2 Concurrency Model

- [ ] **Hot-path lock-free**: Proxy handler reads route table via `ArcSwap` — no mutex on the data path. Confirm no accidental `Mutex` / `RwLock` acquisitions in `upstream_peer` or `upstream_request_filter`.
- [ ] **Per-target atomic counters**: `max_connections` enforcement via `AtomicU64` (acquire/release). `TargetStatsRegistry` uses `Weak<AtomicU64>` for auto-cleanup when targets are evicted from route table.
- [ ] **Circuit breaker thread safety**: `CircuitBreaker` wraps `Mutex<CircuitInner>`. Evaluate contention — is `Mutex` appropriate given that circuit breaker is checked per-request? Consider whether `try_lock` with fallback is safer than blocking.
- [ ] **DNS cache**: `DnsCache` uses `RwLock<HashMap>`. Positive lookups are read-heavy. Verify write contention from TTL expiration cleanup doesn't block reads.
- [ ] **Admin session store**: `DashMap<String, SessionEntry>` for session tokens. Lazy eviction on insert and lookup. Verify `SESSION_MAX_CAPACITY` eviction doesn't cause unbounded iteration under load.

### 1.3 Resource Management

- [ ] **Connection pooling**: Pingora's built-in connection pool with configurable `pool_size`. Verify pool sizing matches expected concurrent upstream connections.
- [ ] **TCP proxy connection guard**: `TcpConnectionGuard` (RAII) decrements active connection count on drop. Confirm no leaks when connections are aborted mid-stream.
- [ ] **Memory boundedness**: DNS cache is unbounded in entry count (entries expire by TTL). Log ring buffer is capped at 1000 entries. Admin session map is capped at 10,000 with TTL eviction. Verify no unbounded growth path exists under sustained load.
- [ ] **Allocation discipline on hot path**: `upstream_peer` does one `Arc<Target>` clone into context (intentional — avoids double lookup). `rewrite_upstream_uri` may allocate a new `Uri`. Verify no hidden allocation spikes (e.g., per-request `format!` in hot path).

---

## 2. Protocol Review

### 2.1 HTTP/1.1 & HTTP/2

- [ ] **H2C (HTTP/2 cleartext) support**: Controlled by `proxy.enable_h2c`. When enabled, upstream connections to HTTP backends upgrade to HTTP/2. Verify `upstream_h2_max_streams` and `upstream_h2_ping_interval` are correctly applied.
- [ ] **Protocol detection accuracy**: `is_grpc_request` checks `Content-Type: application/grpc`. `is_grpc_web_request` checks `application/grpc-web`. `is_websocket_upgrade` checks `Upgrade: websocket`. Verify no false positives/negatives on ambiguous headers.
- [ ] **gRPC-Web bridge**: Pingora's `GrpcWebBridge` module is initialized in `init_downstream_modules`. Verify trailer translation (gRPC-Web response → native gRPC trailers) works correctly for error status codes.

### 2.2 gRPC / gRPCS

- [ ] **gRPC upstream protocol**: `grpc://` targets use HTTP/2 without TLS; `grpcs://` targets use HTTP/2 with TLS. Verify `requires_http2()` correctly forces H2 on the upstream connection.
- [ ] **Path preservation for gRPC**: Strip/prepend rewrite rules must preserve valid `/Service/Method` path format. Verify rewrite logic skips gRPC requests or validates the result.
- [ ] **Trailer propagation**: Pingora's `upstream_response_body_filter` handles gRPC trailers. Verify `Grpc-Status` and `Grpc-Message` trailers survive the proxy path.

### 2.3 WebSocket / WSS

- [ ] **Upgrade passthrough**: WebSocket upgrade requests are detected in `early_request_filter` and the proxy passes them through without modification. Verify Pingora's upgrade path is configured correctly (no response buffering).
- [ ] **WSS upstream**: `wss://` targets use TLS. Verify SNI and Host header are set correctly for WSS connections.

### 2.4 TCP Proxy

- [ ] **TCP modes**: Plain TCP, TCP+SNI, and HTTPS+TCP+SNI. Verify mode resolution (`resolve_tcp_mode`) correctly picks the mode based on config.
- [ ] **SNI-based routing**: `read_server_name` parses TLS ClientHello to extract SNI. Verify edge cases: truncated ClientHello, no SNI extension, malformed handshake.
- [ ] **PROXY protocol v1**: `write_proxy_header` writes PROXY protocol header to upstream. Verify downstream IP extraction and header format compliance.
- [ ] **Dynamic listeners**: `reconcile_dynamic_listeners` manages TCP listeners based on route table changes. Verify listener cleanup when routes are removed (no orphaned sockets).

### 2.5 TLS

- [ ] **Certificate loading**: File-based (`tls.cert_path` / `tls.key_path`) or dynamic Consul KV (`/fabio/cert` prefix). Verify cert rotation is seamless — new cert is fully loaded before old one is released.
- [ ] **SNI-based cert selection**: `CertSnapshot` matches on exact and wildcard names. Verify wildcard matching behavior (e.g., `*.example.com` matches `sub.example.com` but not `deep.sub.example.com`).
- [ ] **mTLS / Client CA**: `DynamicClientCaStore` loads client CA certificates from Consul KV. Verify client certificate verification is enforced when client CAs are configured.
- [ ] **TLS skip verify**: `tlsskipverify=true` route option. Per AGENTS.md, this is not fully reliable for self-signed certs with rustls. Verify this is documented clearly and not treated as production-safe.

---

## 3. Route Engine Review

### 3.1 Route Matching

- [ ] **Matcher strategies**: `prefix` (default), `iprefix` (case-insensitive prefix), `glob` (pattern matching). Verify `iprefix` normalizes both host and path consistently.
- [ ] **Host-specific vs catch-all**: `urlprefix-/api` → catch-all path route. `urlprefix-example.com/api` → host+path route. Verify host extraction from route source handles port suffixes correctly (e.g., `example.com:8080/api`).
- [ ] **Specificity ordering**: Routes are sorted by path in reverse order (most specific first). Verify this produces correct matches when overlapping routes exist (e.g., `/api/v2` vs `/api`).
- [ ] **TCP route matching**: TCP routes are identified by `tcp://` scheme on targets. Verify TCP routes don't interfere with HTTP routing.

### 3.2 Route Sources

- [ ] **Static file routes**: Loaded at startup from `--static-routes` file. Verify changes require restart (no hot-reload expected).
- [ ] **Consul KV routes**: `KVWatcher` uses blocking queries with `index`/`wait` params. Verify empty KV snapshot clears only KV-sourced routes.
- [ ] **Consul service routes**: `ServiceMonitor` watches health checks with `passing` filter. Verify service filtering (whitelist/blacklist) is applied only to service routes, not KV routes.
- [ ] **Fabio tag compatibility**: `urlprefix-` tag parsing preserves Fabio semantics. Verify `strip`, `prepend`, `weight`, `host=` options are parsed correctly.

### 3.3 Load Balancing

- [ ] **Round-robin**: `RoundRobinPicker` uses `AtomicU64` counter. Verify wrapping behavior at `u64::MAX`.
- [ ] **Random**: `RandomPicker` uses thread-local `SmallRng`. Verify statistical distribution is adequate.
- [ ] **Least-connections**: `LeastConnectionsPicker` reads per-target `AtomicU64` active connection counts. Verify race condition between reading and picking (two concurrent pickers may choose the same target).

---

## 4. Admin UI / Dashboard Review

### 4.1 Authentication & Session Management

- [ ] **Login flow**: Username + password → bcrypt verify → session token → `localStorage`. Verify token is not the raw config `admin_token` (check lines 607-608 — hardcoded `'admin123'` is suspicious).
- [ ] **Session storage**: `DashMap<String, SessionEntry>` with 24h TTL and 10K max capacity. Verify constant-time comparison is used for token validation (see `constant_time_eq`).
- [ ] **Token exposure**: Token is stored in `localStorage` (accessible via XSS). Verify dashboard has no XSS vectors (user inputs are not rendered as HTML without escaping).
- [ ] **Auth middleware**: `admin_auth_middleware` checks `Authorization: Bearer <token>` header. Verify all endpoints except `/admin/login` and `/admin/` (dashboard HTML) are protected.

### 4.2 UI/UX Quality

- [ ] **Page structure**: Overview, Topology, Targets, DNS Cache, Consul, Routes, Logs, Config — 8 pages. Verify navigation is intuitive and consistent.
- [ ] **Real-time updates**: `setInterval(refreshAll, 3000)` polls all endpoints every 3 seconds. Evaluate whether this is too aggressive — consider SSE for metrics (already exists for logs) and reduce polling.
- [ ] **Chart rendering**: Chart.js for latency histogram and status code doughnut. Verify chart updates don't cause memory leaks (old chart data references).
- [ ] **Responsive design**: CSS uses `grid-template-columns: 200px 1fr` with fixed sidebar. Verify usability on smaller viewports (< 768px).
- [ ] **Dark theme consistency**: Background `#0f0f0f`, cards `#141414`, borders `#1a1a1a`. Verify all text meets WCAG contrast ratios against dark backgrounds.
- [ ] **Error states**: API calls use `.catch(() => fallback)`. Verify user gets feedback when backend is unreachable (not just silent fallback to empty data).
- [ ] **Loading states**: CSS `.loading` class with animated dots. Verify it's actually applied during data fetches (currently unused in the refresh flow).
- [ ] **Localization**: Login button text is Turkish ("Giriş Yap", "Çıkış"). Verify consistent language choice — either all Turkish or all English.

### 4.3 API Surface

- [ ] **Endpoints**: `/admin/` (dashboard), `/admin/health`, `/admin/routes`, `/admin/metrics`, `/admin/config`, `/admin/certs`, `/admin/logs`, `/admin/logs/stream`, `/admin/login`, `/admin/logout`, `/admin/me`, `/admin/metrics/stream`, `/admin/dns-cache`, `/admin/consul-status`, `/admin/topology`, `/admin/targets`, `/admin/targets/metrics`. Verify all endpoints are documented and access-controlled.
- [ ] **SSE streams**: `/admin/metrics/stream` and `/admin/logs/stream`. Verify connection cleanup when client disconnects.
- [ ] **Prometheus exposition**: `/admin/metrics` returns Prometheus text format. Verify label escaping (`escape_prometheus_label` handles `\`, `"`, `\n`).

---

## 5. Security Review

### 5.1 SSRF Protection

- [ ] **Private IP blocking**: `is_ip_private` blocks RFC1918, loopback, link-local, and IPv6 unique-local addresses for route targets. Verify DNS resolution result is checked (not just the hostname string).
- [ ] **Consul-discovered targets**: Excluded from SSRF checks by default (trusted internal addresses). Verify this assumption holds in multi-tenant environments.
- [ ] **DNS rebinding**: Between route registration and request handling, a DNS entry could change to point to a private IP. Verify DNS cache doesn't create a window for rebinding attacks.

### 5.2 Input Validation

- [ ] **Route command parsing**: `parse_route_commands` tokenizes with quote handling. Verify no injection vectors through malicious opts or tag values.
- [ ] **Admin API input**: Login endpoint accepts JSON with username/password. Verify input length limits and bcrypt cost prevents CPU DoS.
- [ ] **Consul response parsing**: `CatalogService`, `HealthCheck` deserialized from Consul JSON. Verify deserialization failures don't panic — check error handling in watcher loops.

### 5.3 Cryptographic Operations

- [ ] **Bcrypt**: Used for admin user passwords with `DEFAULT_COST` (12). Verify this is adequate for the threat model.
- [ ] **Session tokens**: Generated with `rand::random::<[u8; 32]>()` → hex encoded. Verify RNG is `ThreadRng` (Cryptographically secure on modern platforms).
- [ ] **TLS**: Uses Pingora's rustls integration. Verify TLS 1.3 is preferred and TLS 1.0/1.1 are disabled.

---

## 6. Observability & Operations Review

### 6.1 Metrics

- [ ] **Coverage**: Request counter, latency histogram, error counter, active connections gauge, per-target stats (requests, errors, latency, bytes), protocol breakdown (HTTP, gRPC, gRPC-Web, WebSocket), DNS cache stats, circuit breaker states, certificate expiry, process metrics. Verify no critical metric is missing.
- [ ] **Histogram buckets**: Latency buckets at 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s. Verify bucket boundaries are appropriate for the expected latency profile.
- [ ] **Label cardinality**: Prometheus labels include target URL, service name, status code. Verify no unbounded label values (e.g., per-path labels would cause cardinality explosion).

### 6.2 Logging

- [ ] **Structured logging**: `tracing` crate with JSON format. Verify all hot-path logs use structured fields (not string interpolation).
- [ ] **Access log**: Logged in `logging` callback with method, host, path, status, latency, upstream target, protocol flags. Verify no sensitive data leakage (headers, cookies, request bodies).
- [ ] **Log ring buffer**: 1000 entries with broadcast channel for SSE subscribers. Verify backpressure handling when broadcast channel is full.

### 6.3 Graceful Shutdown

- [ ] **Consul graceful shutdown**: `consul.graceful_shutdown` config option. Verify in-flight requests complete before the process exits.
- [ ] **Connection drain**: Verify Pingora's shutdown sequence drains active connections without abrupt termination.

---

## 7. Configuration Review

### 7.1 Config Completeness

- [ ] **All documented fields are wired**: Compare `AGENTS.md` config list against `Config` struct in `src/config.rs`. Verify every field is read and applied in runtime behavior.
- [ ] **Default values**: Every optional field has a sensible default. Verify defaults are safe for production (e.g., `no_route_status: 404`, `circuit_breaker_enabled: true`).
- [ ] **Config validation**: `Config::validate()` checks for conflicts. Verify all validation paths are covered and errors are actionable.

### 7.2 Config Hot-Reload

- [ ] **Route hot-reload**: Routes update via Consul watchers without restart. Verify config values like timeouts and strategy require restart (expected) vs routes (dynamic).

---

## 8. Test Coverage Review

### 8.1 Unit Tests

- [ ] **Route parsing**: `parser.rs` has comprehensive tests for all route command formats. Verify edge cases: malformed tokens, empty opts, unicode paths.
- [ ] **Route matching**: `table.rs` tests prefix, iprefix, glob matchers. Verify overlapping routes, empty host, path normalization.
- [ ] **Circuit breaker**: `target.rs` tests state transitions (Closed → Open → HalfOpen → Closed). Verify error threshold, window size, recovery timeout, half-open max probes.
- [ ] **SSRF protection**: Tests for RFC1918, loopback, link-local, IPv6 unique-local. Verify all blocked ranges are tested.

### 8.2 Integration Tests

- [ ] **gRPC/H2C**: `protocol_e2e.rs` tests gRPC, gRPCS, gRPC-Web, WebSocket over H2C. Verify ignored tests are run in CI with appropriate flags.
- [ ] **TCP proxy**: `tcp_e2e.rs` tests plain TCP, TCP+SNI, PROXY protocol. Verify SNI extraction edge cases.
- [ ] **mTLS**: `mtls_e2e.rs` tests mutual TLS with client certificate verification. Verify cert rotation during active connections.

---

## 9. Documentation Review

- [ ] **README.md**: Runtime usage, configuration reference, deployment instructions. Verify all CLI flags are documented.
- [ ] **AGENTS.md**: Architecture map, working agreements, testing expectations. Verify accuracy against current codebase.
- [ ] **CHANGELOG.md**: Verify change log is up to date with current version.
- [ ] **Migration docs**: `docs/fabio-to-sentirum-lb-migration-table.md` and `docs/fabio-migration-action-plan.md`. Verify compatibility claims are accurate.

---

## 10. Known Gaps & Technical Debt

Track these explicitly:

| Area | Gap | Risk | Recommendation |
|---|---|---|---|
| Admin auth | Hardcoded token fallback in dashboard JS (line 607) | Token bypass | Use actual server-issued token |
| Admin UI | Mixed Turkish/English strings | UX confusion | Standardize to one language |
| Admin UI | 3s polling all endpoints | Server load under many dashboards | Migrate to SSE for all pages |
| TCP proxy | Multi-plexed HTTPS+TCP+SNI not production-ready | Documented as non-goal | Track in roadmap |
| TLS skip verify | Not reliable with rustls for self-signed certs | Misleading config option | Warn in config validation |
| DNS cache | No max entry limit | Memory under DNS churn | Add upper bound on entry count |
| SSE auth | `EventSource` API doesn't support custom headers | Log stream auth bypass | Use `fetch` + `ReadableStream` or token in query param |

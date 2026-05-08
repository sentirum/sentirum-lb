# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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




## [1.1.1] - 2025-05-08

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

## [1.1.0] - 2025-05-08

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

## [1.0.3] - 2025-04-XX

### Fixed

- Minor reliability fixes

## [1.0.2] - 2025-04-XX

### Fixed

- Bug fixes and stability improvements

## [1.0.1] - 2025-04-XX

### Fixed

- Initial production fixes

## [1.0.0] - 2025-04-XX

### Added

- Initial release — HTTP load balancer with Pingora proxy, Consul KV and service discovery, Fabio-style route tags, TLS support, admin API, Prometheus metrics

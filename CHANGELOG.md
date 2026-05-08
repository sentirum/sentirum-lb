# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

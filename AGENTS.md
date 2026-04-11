# AGENTS.md

This file gives coding agents and contributors a fast map of the repository and the guardrails to follow when changing it.

## What this repository is

`sentirum-lb` is a Rust HTTP load balancer inspired by Fabio. It uses Pingora for proxying, Consul for dynamic route discovery, and `arc-swap` for lock-free route table reads.

## Core architecture

- `src/main.rs`
  - loads optional config and CLI overrides
  - wires Pingora server settings
  - starts proxy listener, optional TLS listener, admin API, and Consul watchers

- `src/proxy/handler.rs`
  - hot-path request handling
  - route lookup
  - upstream peer construction
  - SSRF checks
  - protocol-aware HTTP/2 / gRPC / gRPC-Web / WebSocket handling
  - path rewriting
  - request/response logging and metrics

- `src/route/`
  - `parser.rs`: Fabio-style route command parsing
  - `definition.rs`: route command model
  - `target.rs`: upstream target model and SSRF helpers
  - `table.rs`: immutable route table snapshots and matchers
  - `registry.rs`: merge static, KV, and service-discovery routes safely
  - `picker.rs`: balancing strategies

- `src/consul/`
  - `client.rs`: Consul HTTP client and blocking query URLs
  - `watcher.rs`: KV and health/catalog watchers

- `src/admin/api.rs`
  - operational inspection endpoints

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

## Configuration expectations

These config values are live and should stay wired unless intentionally redesigned:

- `server.admin_token`
- `server.workers`
- `consul.poll_interval`
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
- `tls.cert_path`
- `tls.key_path`
- `tls.listen`

If you introduce a new config field, wire it into runtime behavior and cover it with tests when practical.

## Route and proxy semantics

- No-match responses use `proxy.no_route_status`
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

- Raw TCP proxy mode is not finished yet
- Avoid documenting TCP proxy support as production-ready unless it is actually implemented

## Commit hygiene

- Keep commits focused
- Do not commit `target/` or IDE folders
- Be careful with accidental filesystem artifact paths in commits

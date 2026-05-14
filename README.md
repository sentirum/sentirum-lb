# Sentirum LB

High-performance Rust load balancer inspired by [Fabio](https://github.com/fabiolb/fabio), built on top of Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

`sentirum-lb` watches Consul and/or a static routes file, builds an in-memory route table, and proxies HTTP traffic to matching upstreams with low-lock hot-path lookups.

Default runtime behavior is **Consul-first**: you can start without a config file and rely on built-in defaults plus CLI overrides. All operational settings are hot-reloadable at runtime via the admin API — no restart required for strategy changes, timeout tuning, circuit breaker adjustments, health check configuration, or rate limit updates.

## Features

- Fabio-style route definitions with live addition via admin API
- Consul KV route watching
- Consul service discovery via `urlprefix-` tags
- Atomic route table swaps with `arc-swap`
- Multiple balancing strategies: `round-robin`, `random`, `least-connections`
- Matchers: `prefix`, `iprefix`, `glob`
- Optional TLS termination for downstream traffic
- **Multi-TLS listener** support — additional TLS endpoints via `[[tls_listeners]]` with independent certs, client auth, and hot-reload
- **Circuit breaker** for upstream failure protection (per-target, closed/open/half-open states) with automatic healthy-target fallback
- **Active health checking** — HTTP/TCP probes with configurable intervals, integrated with circuit breaker
- **Token bucket rate limiting** (per-target) with configurable rate and burst
- **Header-based routing** — target-level header filtering via route options
- **Service filtering** via whitelist/blacklist for Consul service discovery
- **DNS caching** with TTL-based positive caching and negative caching
- Fabio-style raw TCP proxy modes: `tcp`, `tcp+sni`, `https+tcp+sni`, and `tcp-dynamic`
- Downstream h2c support for cleartext gRPC clients
- Upstream protocol-aware proxying for HTTP, HTTPS, gRPC, gRPCS, WS, and WSS
- gRPC-Web bridge support
- Path rewrite support with `strip` and `prepend`
- **File-based TLS cert hot-reload** — polls cert+key mtime every 30s, atomic swap without restart
- Admin API with embedded dashboard, Prometheus metrics, and SSE streams
- Basic SSRF protection for upstream targets
- Configurable upstream keepalive pool size, HTTP/2 stream concurrency, and per-upstream concurrency limit
- Graceful shutdown with configurable drain timeout

## Project layout

```
src/
├── main.rs              # Process bootstrap, config loading, Pingora server setup
├── config.rs            # Configuration model and defaults
├── lib.rs               # Crate root
├── proxy/
│   ├── handler.rs       # Hot-path request handling, upstream selection
│   ├── handler/
│   │   ├── client_cert.rs  # mTLS client certificate forwarding
│   │   ├── forwarded.rs    # X-Forwarded-* / CF-Connecting-IP handling
│   │   ├── protocol.rs     # gRPC, gRPC-Web, WebSocket detection
│   │   └── rewrite.rs      # Path strip/prepend rewriting
│   ├── health.rs        # Active health checking (HTTP/TCP probes)
│   ├── ratelimit.rs     # Token bucket rate limiter
│   ├── tcp.rs           # Raw TCP proxy (tcp, tcp+sni, tcp-dynamic)
│   ├── tls.rs           # TLS listener bootstrap
│   └── tls/
│       ├── config.rs    # TLS mode resolution, client auth
│       ├── helpers.rs   # PEM parsing, certificate extraction
│       ├── ocsp.rs      # OCSP stapling infrastructure
│       ├── selector.rs  # SNI-based certificate selection
│       └── watcher.rs   # FileCertWatcherService (30s mtime poll)
├── route/
│   ├── circuit_breaker.rs  # CircuitBreaker, CircuitState, monotonic epoch
│   ├── definition.rs    # Route command model
│   ├── dns_cache.rs     # DnsCache, DnsCacheStats, global singleton
│   ├── health_tracker.rs   # TargetHealthTracker (probe health + CB)
│   ├── parser.rs        # Fabio-style route command parser
│   ├── picker.rs        # Balancing strategies (RR, random, least-conn)
│   ├── registry.rs      # Route source merging (static, KV, service discovery)
│   ├── table.rs         # Immutable route table snapshots and lookup
│   ├── target.rs        # Target struct, SSRF, DNS resolution, re-exports
│   └── target_stats.rs  # TargetStatsRegistry, per-target stats
├── admin/
│   ├── api.rs           # Router, shared types, health, logs, run_admin_server
│   ├── auth.rs          # Login/logout, sessions, middleware, rate-limiting
│   ├── certs_handler.rs # TLS cert inspection and hot-reload
│   ├── config_handler.rs   # Config GET/PUT/reset, DNS cache endpoint
│   ├── dashboard.html   # Embedded admin dashboard SPA
│   ├── logs.rs          # Log capture and buffering
│   ├── metrics_handler.rs  # Metrics, SSE stream, targets, topology
│   └── routes_handler.rs   # Routes GET/POST/DELETE
├── consul/
│   ├── client.rs        # Consul HTTP client, blocking query URLs
│   └── watcher.rs       # KV and health/catalog watchers
└── metrics/
    └── prometheus.rs    # Prometheus counters, gauges, histograms
```

## Quick start

### Prerequisites

- Rust 1.94+ (pinned in `rust-toolchain.toml`)
- `protoc` (vendored via `protoc-bin-vendored` — no separate install needed)

### Build

```bash
cargo build --release
```

### Run with static routes

```bash
cargo run -- --routes routes.txt
```

### Run with CLI overrides

```bash
cargo run -- --listen :9999 --consul 127.0.0.1:8500 --log-level info
```

## Configuration

Example `config.toml`:

```toml
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = "change-me"
workers = 0
drain_timeout = "30s"

# Admin users for dashboard login
[[server.admin_users]]
username = "admin"
password = "admin-password-hash"

[consul]
address = "127.0.0.1:8500"
scheme = "http"
token = ""
kv_prefix = "/sentirum-lb/routes"
tag_prefix = "urlprefix-"
poll_interval = "3s"
service_discovery = false
kv_watching = false

[proxy]
strategy = "round-robin"
matcher = "prefix"
request_id_header = "X-Request-ID"
no_route_status = 404
connect_timeout = "5s"
read_timeout = "30s"
write_timeout = "30s"
idle_timeout = "120s"
enable_h2c = false
upstream_h2_max_streams = 128
upstream_h2_ping_interval = ""
pool_size = 128
max_connections = 10000

# Circuit breaker
circuit_breaker_enabled = true
circuit_breaker_error_threshold = 50
circuit_breaker_window_size = 100
circuit_breaker_recovery_timeout = 30
circuit_breaker_half_open_max = 3

# Health checking
health_check_interval = "10s"
health_check_timeout = "5s"
health_check_fall = 3
health_check_rise = 2
health_check_path = "/health"
health_check_tls_skip_verify = false

# Rate limiting (per-target)
rate_limit_per_target = 0     # 0 = disabled; set e.g. 100 for 100 req/s
rate_limit_burst = 0

# DNS cache
dns_cache_ttl = 30
dns_negative_cache_ttl = 10

[logging]
level = "info"
format = "text"

[tls]
source = ""
cert_path = ""
key_path = ""
listen = ""
consul_cert_prefix = "/fabio/cert"
strict_sni = false
require_initial_snapshot = false
client_auth = ""
client_ca_source = ""
client_ca_path = ""
client_ca_consul_prefix = ""
client_ca_upgrade_cn = ""

# Additional TLS listeners (e.g., mTLS on a separate port)
# [[tls_listeners]]
# listen = ":8443"
# cert_path = "/etc/sentirum-lb/mtls-cert.pem"
# key_path = "/etc/sentirum-lb/mtls-key.pem"
# client_auth = "required"
# client_ca_path = "/etc/sentirum-lb/client-ca.pem"

[tcp]
mode = ""
listen = ""
refresh = "5s"
```

### TLS sources

Sentirum LB supports two downstream TLS modes:

- `source = "file"` — PEM files from disk via `cert_path` + `key_path`, with automatic hot-reload every 30s
- `source = "consul_kv"` — Fabio-compatible Consul KV bundles under `tls.consul_cert_prefix`

In `consul_kv` mode the load balancer watches keys like:

- `/fabio/cert/example.com.pem`
- `/fabio/cert/api.example.com.pem`

Each KV value may be a single bundled PEM containing:

- leaf certificate
- intermediate chain
- private key

Certificates are selected dynamically per SNI and reloaded without listener restarts.
Existing connections stay alive; only new TLS handshakes use the updated certificate snapshot.
Each Consul cert entry is capped at 1 MiB to avoid pathological memory spikes.
If `require_initial_snapshot = true`, startup fails unless the first Consul TLS load yields at least one valid certificate.

File mode also supports hot-reload: `FileCertWatcherService` polls cert+key file mtime every 30s and atomically swaps via `ArcSwap`. Manual reload is available via `POST /admin/certs/reload`.

Example (Consul KV):

```toml
[tls]
source = "consul_kv"
listen = ":443"
consul_cert_prefix = "/fabio/cert"
strict_sni = false
require_initial_snapshot = true
```

Example (file):

```toml
[tls]
source = "file"
listen = ":443"
cert_path = "/etc/sentirum-lb/cert.pem"
key_path = "/etc/sentirum-lb/key.pem"
```

### Multi-TLS listeners

Additional TLS endpoints can be configured via `[[tls_listeners]]`:

```toml
[[tls_listeners]]
listen = ":8443"
cert_path = "/etc/sentirum-lb/mtls-cert.pem"
key_path = "/etc/sentirum-lb/mtls-key.pem"
client_auth = "required"
client_ca_path = "/etc/sentirum-lb/client-ca.pem"
```

Each additional listener has independent certificates, client auth settings, and file-based hot-reload.

### mTLS / client certificate auth

Downstream client certificate auth is listener-wide, matching Fabio's model more closely than a per-route switch.
Current implementation supports:

- `client_auth = "optional"` — request and verify client certs when presented
- `client_auth = "required"` — require a valid client cert for the TLS handshake
- `client_ca_source = "consul_kv"` — dynamically load trusted client CA PEM bundles from Consul KV
- `client_ca_source = "file"` — load trusted client CA PEMs from a file or directory on disk
- `client_ca_upgrade_cn` — Fabio-compatible CA-upgrade behavior for awkward self-signed/non-CA client-auth cert chains (for matching CNs)

When mTLS is enabled, successful requests propagate verified client identity upstream with headers such as:

- `X-Client-Cert-Verified`
- `X-Client-Cert-Serial`
- `X-Client-Cert-Organization`
- `X-Client-Cert-Common-Name`
- `X-Client-Cert-Organizational-Unit`
- `X-Client-Cert-Subject`
- `X-Client-Cert-SHA256`

Consul-backed example:

```toml
[tls]
source = "consul_kv"
listen = ":443"
consul_cert_prefix = "/fabio/cert"
strict_sni = false
require_initial_snapshot = true
client_auth = "required"
client_ca_source = "consul_kv"
client_ca_consul_prefix = "/fabio/client-ca"
```

Deployment examples:

- Nomad job template: `docs/sentirum-lb.nomad.hcl`
- Migration guide: `docs/fabio-migration-action-plan.md`
- Migration table: `docs/fabio-to-sentirum-lb-migration-table.md`
- Canary checklist: `docs/sentirum-lb-canary-checklist.md`
- Smoke/canary runbook: `docs/sentirum-lb-smoke-and-canary-runbook.md`

### TCP modes

Fabio-style raw TCP support is configured under `[tcp]`:

- `mode = "tcp"` — fixed raw TCP listener from `tcp.listen`
- `mode = "tcp+sni"` — fixed SNI-aware TCP passthrough listener from `tcp.listen`
- `mode = "https+tcp+sni"` — public HTTPS listener first checks SNI against `proto=tcp` routes, otherwise falls through to normal HTTPS termination
- `mode = "tcp-dynamic"` — discovers `:port` / `host:port` TCP routes from the route table and starts/stops listeners dynamically, Fabio-style

Examples:

```toml
[tcp]
mode = "tcp"
listen = ":4222"
```

```toml
[tcp]
mode = "tcp+sni"
listen = ":443"
```

```toml
[tcp]
mode = "https+tcp+sni"
```

```toml
[tcp]
mode = "tcp-dynamic"
refresh = "5s"
```

Service-discovery TCP tags remain Fabio-compatible:

```text
urlprefix-:4222 proto=tcp
urlprefix-nats.example.com proto=tcp
urlprefix-nats.example.com:4222 proto=tcp
```

Runtime semantics:

- plain `tcp`: lookup by listener local address, then fallback to `:port`
- `tcp+sni`: lookup by SNI host only
- `https+tcp+sni`: if SNI maps to a `proto=tcp` target, passthrough; otherwise fall through to HTTPS termination
- `tcp-dynamic`: listener ports are derived from the live route table and reconciled periodically

### Important knobs

#### Server
- `server.workers`: Pingora service thread count. `0` keeps Pingora defaults.
- `server.drain_timeout`: graceful shutdown drain period (default: `30s`). Maps to Pingora's `grace_period_seconds`.
- `server.admin_users`: list of `[[server.admin_users]]` with `username` and `password` for dashboard login.

#### Proxy
- `proxy.strategy`: balancing strategy — `round-robin`, `random`, or `least-connections`.
- `proxy.matcher`: route matching — `prefix`, `iprefix`, or `glob`.
- `proxy.pool_size`: upstream keepalive pool size.
- `proxy.max_connections`: max active requests per upstream target. `0` means unlimited.
- `proxy.enable_h2c`: accept cleartext HTTP/2 on the plaintext listener for gRPC clients.
- `proxy.upstream_h2_max_streams`: max concurrent streams per upstream H2 connection.
- `proxy.upstream_h2_ping_interval`: optional upstream H2 ping interval for long-lived gRPC streams.
- `proxy.no_route_status`: status returned when no route matches.
- `proxy.request_id_header`: header name for request ID generation (default: `X-Request-ID`).

#### Circuit breaker
- `proxy.circuit_breaker_enabled`: enable circuit breaker for upstream failure protection (default: `true`).
- `proxy.circuit_breaker_error_threshold`: error threshold percentage (0–100) for circuit opening (default: `50`).
- `proxy.circuit_breaker_window_size`: number of requests to track in the sliding window (default: `100`).
- `proxy.circuit_breaker_recovery_timeout`: seconds to stay open before probing recovery (default: `30`).
- `proxy.circuit_breaker_half_open_max`: max probe requests in half-open state (default: `3`).

#### Health checking
- `proxy.health_check_interval`: interval between health check probes (default: `10s`).
- `proxy.health_check_timeout`: timeout per health check probe (default: `5s`).
- `proxy.health_check_fall`: consecutive failures before marking unhealthy (default: `3`).
- `proxy.health_check_rise`: consecutive successes before marking healthy (default: `2`).
- `proxy.health_check_path`: HTTP path for health check probes (default: `/health`).
- `proxy.health_check_tls_skip_verify`: skip TLS verification for HTTPS health checks (default: `false`).

#### Rate limiting
- `proxy.rate_limit_per_target`: requests per second per upstream target (default: `0` = disabled).
- `proxy.rate_limit_burst`: burst allowance for token bucket (default: `0`).
- Per-target override via route options: `opts "ratelimit=100 burst=20"`.

#### DNS
- `proxy.dns_cache_ttl`: DNS cache TTL in seconds (default: `30`, `0` = disabled).
- `proxy.dns_negative_cache_ttl`: DNS negative cache TTL in seconds (default: `10`).

#### Consul
- `consul.poll_interval`: blocking query wait duration for Consul watchers.
- `consul.service_whitelist`: only discover routes for these service names (empty = all).
- `consul.service_blacklist`: never discover routes for these service names.

#### TLS
- `tls.source`: select `file` or `consul_kv` for downstream TLS.
- `tls.consul_cert_prefix`: Fabio-compatible certificate KV prefix, e.g. `/fabio/cert`.
- `tls.strict_sni`: if true, fail TLS handshakes without an exact/wildcard SNI match.
- `tls.require_initial_snapshot`: if true in `consul_kv` mode, refuse startup until the initial cert snapshot is valid.
- `tls.client_auth`: downstream client cert mode: `optional` or `required`.
- `tls.client_ca_source`: trusted client CA source: `file` or `consul_kv`.
- `tls.client_ca_path`: file or directory containing trusted client CA PEMs.
- `tls.client_ca_consul_prefix`: Consul KV prefix containing trusted client CA PEM bundles.
- `tls.client_ca_upgrade_cn`: Fabio-style CA upgrade compatibility knob.

#### TCP
- `tcp.mode`: choose `tcp`, `tcp+sni`, `https+tcp+sni`, or `tcp-dynamic`.
- `tcp.listen`: fixed listen address for `tcp` / `tcp+sni`.
- `tcp.refresh`: reconciliation interval for `tcp-dynamic`.

## Route format

The parser accepts Fabio-style commands:

```text
route add <service> <src> <dst>
route add <service> <src> <dst> weight <w>
route add <service> <src> <dst> tags "v1,canary"
route add <service> <src> <dst> opts "strip=/api prepend=/v2 tlsskipverify=true"
route del <service>
route del <service> <src>
route del <service> tags "v1"
route del tags "v1"
route weight <service> <src> weight <w>
route weight <src> weight <w> tags "v1"
```

Example:

```text
route add webapp myhost.com/ http://127.0.0.1:8080/
route add webapp myhost.com/ http://127.0.0.1:8081/
route add api myhost.com/api/ http://127.0.0.1:9090/ weight 0.7
route add static static.example.com/static/ http://127.0.0.1:3000/ opts "strip=/static"
```

### Supported route options

- `strip=/prefix`: remove a path prefix before proxying
- `prepend=/prefix`: prepend a path prefix before proxying
- `tlsskipverify=true`: request upstream certificate verification bypass (note: Pingora rustls upstream connectors currently do not fully honor this for self-signed upstream TLS; prefer trusted/internal CA certificates for `grpcs` / `wss` upstreams)
- `ssrfskipverify=true`: bypass SSRF checks for a target
- `host=example.internal`: override upstream Host header and TLS SNI
- `proto=https|grpc|grpcs|ws|wss|tcp`: override the upstream transport/protocol semantics for service-discovery targets
- `header=X-Name:value`: require request header `X-Name` to match `value` for this target (multiple headers allowed, comma-separated). Targets without matching headers are skipped during selection.
- `ratelimit=X burst=Y`: override per-target rate limit (X req/s, burst Y)

### Protocol notes

- `http` / `https`: standard HTTP proxying
- `grpc` / `grpcs`: upstream HTTP/2 proxying for native gRPC
- `ws` / `wss`: WebSocket proxying over HTTP/1.1 upgrade
- gRPC-Web requests are bridged to native gRPC upstreams automatically
- gRPC rewrites are guarded: only safe path rewrites that preserve a valid `/Service/Method`-style path are applied

Examples:

```text
route add grpc / grpc://10.0.0.10:50051/
route add grpcs localhost/ grpcs://10.0.0.11:8443/ opts "tlsskipverify=true"
route add ws /socket ws://10.0.0.20:8080/socket
route add wss localhost/realtime wss://10.0.0.21:9443/realtime opts "tlsskipverify=true"
route add canary api.example.com/ http://10.0.0.2:8080/ opts "header=x-version:v2"
```

## Consul integration

Sentirum LB can build routes from:

- Consul KV under `consul.kv_prefix`
- Consul health/catalog data using tags starting with `consul.tag_prefix`

Service discovery expects Fabio-like tags, for example:

```text
urlprefix-/api
urlprefix-example.com/api
urlprefix-/ proto=https strip=/api prepend=/v1
urlprefix-/ proto=grpc
urlprefix-example.com/realtime proto=wss
```

Fabio-compatible semantics:

- `urlprefix-/api` => catch-all path route
- `urlprefix-example.com/api` => host-specific path route
- `urlprefix-example.com/` => host-specific catch-all route

## HTTP and admin endpoints

### Proxy listener

- Configured by `server.listen`
- Built-in health response on `/health` and `/healthz`

### Admin API

- `GET /admin/health` — health check
- `GET /admin/routes` — route table inspection
- `POST /admin/routes` — live route addition (Fabio-style commands)
- `DELETE /admin/routes/static` — clear static routes
- `GET /admin/metrics` — Prometheus text metrics
- `GET /admin/config` — runtime config (JSON)
- `PUT /admin/config` — hot-reload proxy settings (no restart)
- `POST /admin/config/reset` — reset to startup config
- `GET /admin/certs` — TLS certificate status
- `POST /admin/certs/reload` — manual certificate reload
- `GET /admin/logs` — recent log entries (JSON, `?limit=N&level=LEVEL&search=QUERY`)
- `GET /admin/logs/stream` — live log stream (SSE, auth via `?token=`)
- `GET /admin/metrics/stream` — live metrics stream (SSE, auth via `?token=`)
- `GET /admin/targets` — per-target health, circuit breaker status, and stats
- `GET /admin/targets-metrics` — per-target Prometheus metrics
- `GET /admin/dns-cache` — DNS cache stats and entries
- `GET /admin/consul-status` — Consul watcher state per subsystem
- `GET /admin/topology` — route topology graph data
- `GET /admin/me` — current session info
- `POST /admin/login` — authenticate and receive session token
- `POST /admin/logout` — invalidate session
- `GET /admin/` — embedded dashboard SPA

Default admin bind address: `127.0.0.1:9998`

If `server.admin_token` is set, requests must include either:

- `Authorization: Bearer <token>`
- `X-Admin-Token: <token>`

For non-loopback admin binds, `server.admin_token` is required.

### Runtime hot-reloadable settings

These settings can be changed via `PUT /admin/config` without restart:

- `proxy.strategy`, `proxy.matcher`
- `proxy.request_id_header`, `proxy.no_route_status`
- `proxy.connect_timeout`, `proxy.read_timeout`, `proxy.write_timeout`, `proxy.idle_timeout`
- `proxy.max_connections`
- `proxy.circuit_breaker_*` (enabled, error_threshold, window_size, recovery_timeout, half_open_max)
- `proxy.health_check_*` (interval, timeout, fall, rise, path, tls_skip_verify)
- `proxy.rate_limit_per_target`, `proxy.rate_limit_burst`
- `proxy.dns_cache_ttl`, `proxy.dns_negative_cache_ttl`
- `proxy.upstream_h2_max_streams`, `proxy.upstream_h2_ping_interval`
- `logging.level`, `logging.format`

Settings requiring restart: `pool_size`, `enable_h2c`, `trusted_proxies`, `server.*`, `consul.*`, `tls.*`.

## Metrics

Prometheus metrics are exposed via:

```text
GET /admin/metrics
```

In addition to request metrics, the endpoint exports Linux `/proc`-based process gauges for:

- resident memory bytes
- virtual memory bytes
- open file descriptors

Tracked metrics include:

- total requests
- error requests
- gRPC request count
- gRPC-Web request count
- WebSocket request count
- active connections
- route and target counts
- status code buckets
- request latency histogram buckets
- per-target circuit breaker state gauge (0=closed, 1=half-open, 2=open)

## Security notes

- Loopback, link-local, unspecified, and localhost-style upstreams are blocked by default
- Consul-discovered targets are allowed to use RFC1918/private addresses by default to support Nomad/Consul internal networking
- Hostnames like `localhost` and `.local` are blocked
- You can bypass SSRF checks per target with `ssrfskipverify=true` if your environment requires it
- Upstream TLS verification bypass can be requested per target with `tlsskipverify=true`, but with the current Pingora rustls connector you should still prefer trusted/internal CA certificates for `grpcs` / `wss` upstreams because self-signed bypass is not fully reliable yet
- Admin login rate limiting: max 5 attempts per username per 60-second window
- Session tokens with configurable TTL and automatic background cleanup

## Development

```bash
# Run tests
cargo test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Build release binary
cargo build --release
```

## Current scope

### Implemented and production-tested

- HTTP / HTTPS proxying
- gRPC / gRPCS proxying (unary, server streaming, client streaming, bidi streaming)
- gRPC-Web bridging
- WebSocket / WSS proxying
- TLS termination (file and Consul KV sources, hot-reload)
- Multi-TLS listener
- Downstream h2c support
- Consul KV + service discovery
- Admin API with embedded dashboard
- Prometheus metrics with SSE streams
- Circuit breaker with per-target state tracking
- Active health checking (HTTP/TCP probes)
- Per-target token bucket rate limiting
- Header-based routing (target-level filtering)
- Raw TCP proxy modes (`tcp`, `tcp+sni`, `https+tcp+sni`, `tcp-dynamic`) — validated with NATS protocol (INFO, PING/PONG, CONNECT/SUB/PUB/UNSUB, queue groups, 50KB payloads, 20+ concurrent connections)
- Graceful shutdown with drain timeout
- Runtime config hot-reload
- Live route addition and deletion
- mTLS / client certificate auth with identity forwarding
- DNS caching with positive and negative TTL
- Weighted load balancing (round-robin, random, least-connections)

### Notes

- OCSP stapling infrastructure is in place; actual handshake stapling depends on Pingora exposing the `SSL_set_ocsp_resp` callback
- `tlsskipverify=true` for upstream TLS is not fully reliable with Pingora's rustls connector; prefer trusted/internal CA certificates

## License

MIT

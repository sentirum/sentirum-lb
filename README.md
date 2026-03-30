# Sentirum LB

High-performance Rust load balancer inspired by [Fabio](https://github.com/fabiolb/fabio), built on top of Cloudflare's Pingora.

`sentirum-lb` watches Consul and/or a static routes file, builds an in-memory route table, and proxies HTTP traffic to matching upstreams with low-lock hot-path lookups.

Default runtime behavior is now **Consul-first**: you can start without a config file and rely on built-in defaults plus CLI overrides.

## Features

- Fabio-style route definitions
- Consul KV route watching
- Consul service discovery via `urlprefix-` tags
- Atomic route table swaps with `arc-swap`
- Multiple balancing strategies: `round-robin`, `random`, `least-connections`
- Matchers: `prefix`, `iprefix`, `glob`
- Optional TLS termination for downstream traffic
- Path rewrite support with `strip` and `prepend`
- Admin API and Prometheus metrics
- Basic SSRF protection for upstream targets
- Configurable upstream keepalive pool size and per-upstream concurrency limit

## Project layout

- `src/main.rs`: process bootstrap, config loading, Pingora server setup
- `src/proxy/`: request handling and upstream selection
- `src/route/`: route parsing, target modeling, route table management
- `src/consul/`: Consul client and watcher logic
- `src/admin/`: admin HTTP API
- `src/metrics/`: Prometheus exposition

## Quick start

### Build

```bash
cargo build --release
```

### Run with static routes

```bash
cargo run -- --routes test_routes.txt
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
pool_size = 128
max_connections = 10000

[logging]
level = "info"
format = "text"

[tls]
cert_path = ""
key_path = ""
listen = ""
```

### Important knobs

- `server.workers`: Pingora service thread count. `0` keeps Pingora defaults.
- `proxy.pool_size`: upstream keepalive pool size.
- `proxy.max_connections`: max active requests per upstream target. `0` means unlimited.
- `consul.poll_interval`: blocking query wait duration for Consul watchers.
- `proxy.no_route_status`: status returned when no route matches.

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
- `tlsskipverify=true`: disable upstream certificate verification
- `ssrfskipverify=true`: bypass SSRF checks for a target
- `host=example.internal`: reserved for host override-style usage
- `proto=https`: mark a service-discovery target as HTTPS

## Consul integration

Sentirum LB can build routes from:

- Consul KV under `consul.kv_prefix`
- Consul health/catalog data using tags starting with `consul.tag_prefix`

Service discovery expects Fabio-like tags, for example:

```text
urlprefix-/api
urlprefix-example.com/api
urlprefix-/ proto=https strip=/api prepend=/v1
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

- `GET /admin/health`
- `GET /admin/routes`
- `GET /admin/metrics`
- `GET /admin/config`

Default admin bind address: `127.0.0.1:9998`

If `server.admin_token` is set, requests must include either:

- `Authorization: Bearer <token>`
- `X-Admin-Token: <token>`

For non-loopback admin binds, `server.admin_token` is required.

## Metrics

Prometheus metrics are exposed via:

```text
GET /admin/metrics
```

Tracked metrics include:

- total requests
- error requests
- active connections
- route and target counts
- status code buckets
- request latency histogram buckets

## Security notes

- Loopback, link-local, unspecified, and localhost-style upstreams are blocked by default
- Consul-discovered targets are allowed to use RFC1918/private addresses by default to support Nomad/Consul internal networking
- Hostnames like `localhost` and `.local` are blocked
- You can bypass SSRF checks per target with `ssrfskipverify=true` if your environment requires it
- Upstream TLS verification can be disabled per target with `tlsskipverify=true`

## Development

Run tests:

```bash
cargo test
```

Format and inspect the tree:

```bash
cargo fmt
cargo test
```

## Current scope

Implemented today:

- HTTP proxying
- TLS termination
- Consul KV + service discovery
- Admin API
- Metrics

Not fully implemented yet:

- Raw TCP proxy mode (`src/proxy/tcp.rs` is still a placeholder)

## License

MIT

# Fabio → Sentirum LB Migration Table

## Scope

This table covers the **current migration target**:
- replace Fabio for **HTTP/HTTPS host/path ingress**
- preserve current **Cloudflare + Consul service-tag routing** behavior
- support both **mounted PEM files** and **Consul KV** for TLS certificates

Out of scope for phase 1:
- full Fabio property compatibility
- Fabio UI parity

Important notes:
- **Raw TCP modes** (`tcp`, `tcp+sni`, `https+tcp+sni`, `tcp-dynamic`) are **production-tested** with NATS protocol validation (INFO, PING/PONG, CONNECT/SUB/PUB/UNSUB, queue groups, 50KB payloads, 20+ concurrent connections)
- **Both TLS sources** (`file` and `consul_kv`) are fully supported with live hot-reload
- **Circuit breaker**, **active health checking**, and **per-target rate limiting** are available but have no Fabio equivalent

---

## Executive summary

| Area | Fabio today | Sentirum LB today | Migration status | Action |
|---|---|---|---|---|
| HTTP ingress | Supported | Supported | ✅ OK | Migrate |
| HTTPS ingress | Supported | Supported | ✅ OK | Migrate |
| Host/path routing | `urlprefix-` tags | `urlprefix-` tags | ✅ OK | Migrate |
| Consul service discovery | Yes | Yes | ✅ OK | Migrate |
| Consul KV routes | Yes (`/fabio/config`) in theory, but empty now | Yes (native KV route prefix) | ✅ Mostly irrelevant | Optional mapping |
| Consul KV certificates | Yes | Yes (`source = "consul_kv"`) | ✅ OK | Direct migration |
| File-based certificates | Yes | Yes (`source = "file"` with hot-reload) | ✅ OK | Migrate with PEM mount |
| Cloudflare real IP | Yes | Yes, via trusted proxies | ⚠️ Needs verification | Canary test |
| WebSocket | Yes | Yes | ⚠️ Needs validation | Canary test |
| gRPC/gRPC-Web | Fabio unclear / maybe limited | Supported | ⚠️ Needs validation if used | Canary test |
| Raw TCP / SNI | Fabio supports | Production-tested (tcp, tcp+sni, https+tcp+sni, tcp-dynamic) | ✅ Supported | Available if needed |
| Circuit breaker | No | Per-target, closed/open/half-open with fallback | ✅ Bonus | Enable if desired |
| Health checking | No | HTTP/TCP probes with configurable intervals | ✅ Bonus | Enable if desired |
| Rate limiting | No | Token bucket per-target, 429 on exceed | ✅ Bonus | Enable if desired |
| Fabio UI | Yes | No — replaced with admin API + embedded dashboard + Prometheus | ⚠️ Gap | Replace with admin API + metrics |

---

## Property / behavior mapping

| Fabio property / behavior | Current Fabio usage | Sentirum LB equivalent | Status | Notes |
|---|---|---|---|---|
| `proxy.addr = :80;proto=http,:443;proto=https;cs=consul` | Yes | `server.listen`, `tls.listen` | Supported | Sentirum LB separates HTTP and TLS listener config |
| `proxy.cs = cs=consul;type=consul;cert=http://consul.../v1/kv/fabio/cert` | Yes | `tls.source = "consul_kv"`, `tls.consul_cert_prefix` | Supported | Direct Fabio-compatible migration path |
| `registry.consul.addr = consul.service.consul:8500` | Yes | `consul.address`, `consul.scheme` | Supported | Direct mapping |
| `registry.consul.register.enabled = true` | Yes | None | Not needed | Nomad service stanza handles registration |
| `registry.consul.register.name = fabio` | Yes | None | Not needed | Sentirum LB does not need Fabio-style self-registration |
| `registry.consul.kvpath = /fabio/config` | Configured, but KV empty | `consul.kv_prefix` | Supported | Only relevant if you want route KV |
| `registry.consul.tagprefix = urlprefix-` | Yes | `consul.tag_prefix` | Supported | Direct mapping |
| `ui.addr` | Yes | `/admin/*` + embedded dashboard | Different | Replace with admin API + Prometheus/Grafana |
| `log.level` | Yes | `logging.level` / runtime logging | Supported | Hot-reloadable via `PUT /admin/config` |
| `log.routes.format = delta` | Yes | No direct equivalent | Low priority | Optional observability enhancement |
| `log.access.*` | Yes | Request logging exists | Partial | Validate desired log format |
| `metrics.target = stdout` | Yes | `/admin/metrics` Prometheus endpoint | Different | Prefer Prometheus scrape |
| `metrics.prefix = fabio` | Yes | Native Prometheus metric names | Different | Dashboard/alert migration needed |
| `proxy.readtimeout = 3600s` | Yes | `proxy.read_timeout` | Supported | Map value |
| `proxy.writetimeout = 3600s` | Yes | `proxy.write_timeout` | Supported | Map value |
| `proxy.dialtimeout = 30s` | Yes | `proxy.connect_timeout` | Supported | Map value |
| `proxy.responseheadertimeout = 300s` | Yes | No exact dedicated knob | Partial | Check current timeout surface |
| `proxy.keepalivetimeout = 90s` | Yes | `proxy.idle_timeout` | Approximate | Validate semantics |
| `proxy.maxconn = 10000` | Yes | `proxy.max_connections` | Supported | Per-upstream target enforcement |
| `proxy.strategy = rr` | Yes | `proxy.strategy` | Supported | Also supports `random`, `least-connections` |
| `proxy.matcher = prefix` | Yes | `proxy.matcher` | Supported | Also supports `iprefix`, `glob`, `exact` |
| `proxy.noroutestatus = 404` | Yes | `proxy.no_route_status` | Supported | Configurable |
| `proxy.header.clientip = X-Forwarded-For` | Yes | Forwarded-header handling | Supported | Trusted proxy policy based |
| `proxy.header.clientip.header = CF-Connecting-IP` | Yes | `CF-Connecting-IP` trusted from `trusted_proxies` | Supported | Configure Cloudflare CIDRs |
| `proxy.header.tls = X-Forwarded-Proto` | Yes | Native forwarded header behavior | Supported | Verify exact output in canary |
| `proxy.ws = true` | Yes | WebSocket support exists | Supported | Must validate in canary |
| `proxy.localip = ${attr.unique.network.ip-address}` | Yes | No direct equivalent needed | Usually not needed | Check if source-IP pinning matters |
| `proxy.shutdownwait = 30s` | Yes | `server.drain_timeout` → Pingora `grace_period_seconds` | Supported | Graceful shutdown wiring |

---

## Route source mapping

| Current Fabio route source | Observed state | Sentirum LB migration | Decision |
|---|---|---|---|
| Consul service tags with `urlprefix-` | Active | Keep as-is | Primary path |
| `/fabio/config` KV routes | Configured in Fabio but currently empty | Map to `consul.kv_prefix` if needed later | Not required for phase 1 |
| KV cert store under `/fabio/cert/*` | Active | `tls.source = "consul_kv"` | Direct migration |

---

## TLS / certificate migration

### Current Fabio model
- Fabio reads cert bundles from Consul KV under `/fabio/cert/*`
- bundle appears to include:
  - leaf cert
  - chain
  - private key

### Sentirum LB supported models

#### Option A: Consul KV (direct migration, recommended)
```toml
[tls]
source = "consul_kv"
listen = ":443"
consul_cert_prefix = "/fabio/cert"
```
- watches keys under `tls.consul_cert_prefix` (e.g. `/fabio/cert`)
- supports combined PEM bundles (leaf + chain + key)
- dynamic SNI-based certificate selection
- live reload without listener restart
- zero operational change from Fabio

#### Option B: File-based with hot-reload
```toml
[tls]
source = "file"
cert_path = "/etc/sentirum-lb/cert.pem"
key_path = "/etc/sentirum-lb/key.pem"
listen = ":443"
```
- `FileCertWatcherService` polls cert+key file mtime every 30s
- atomic swap via `ArcSwap<LoadedCertificate>`
- manual reload via `POST /admin/certs/reload`
- certs rendered by Nomad template, Vault agent, or external sync

### Decision
**Both modes are fully supported.** Consul KV is the path of least change from Fabio.

---

## Cloudflare / real IP mapping

| Behavior | Fabio today | Sentirum LB target | Required action |
|---|---|---|---|
| trust `CF-Connecting-IP` | Yes | Yes | configure `proxy.trusted_proxies` with Cloudflare CIDRs |
| set forwarded proto correctly | Yes | Yes | validate under HTTPS canary |
| reject spoofed client IP headers from untrusted sources | Implicit Fabio behavior | Explicit trusted proxy model | validate in canary |

### Canary checks
- request from Cloudflare path shows real client IP upstream
- direct/untrusted request cannot spoof `CF-Connecting-IP`
- `X-Forwarded-Proto=https` parity is preserved

---

## Observability / operations mapping

| Fabio capability | Current usage | Sentirum LB replacement |
|---|---|---|
| Fabio UI | Internal UI on `:9997` | `/admin/*` embedded dashboard + Prometheus/Grafana |
| stdout metrics | Yes | Prometheus scrape at `/admin/metrics` |
| route visibility | UI/routes | `/admin/routes` JSON + dashboard |
| health checks | TCP on 80/443/UI | `/health`, `/healthz`, `/admin/health` |
| config visibility | Fabio UI | `GET /admin/config` (JSON) |
| live config update | Fabio UI / restart | `PUT /admin/config` (hot-reload, no restart) |
| live route addition | KV edit only | `POST /admin/routes` (Fabio-style commands) |
| cert status | Fabio UI | `GET /admin/certs` (JSON + dashboard) |
| target health | Basic | `/admin/targets` (per-target CB state, health, stats) |

---

## Canary checklist

| Test | Required for phase 1 | Notes |
|---|---|---|
| HTTP host routing | Yes | must pass |
| HTTPS host routing | Yes | must pass |
| path prefix routing | Yes | must pass |
| Cloudflare real IP | Yes | must pass |
| WebSocket | Yes if used | likely must pass |
| gRPC/gRPC-Web | If used | validate separately |
| KV route updates | Only if enabled | optional for phase 1 |
| cert rotation procedure | Yes | operationally proven |
| raw TCP / SNI | If used | now production-tested |

---

## TCP / NATS routing

### Status: Production-tested

All raw TCP modes are implemented and validated:

| Mode | Description | Status |
|---|---|---|
| `tcp` | Fixed raw TCP listener | Production-tested with NATS |
| `tcp+sni` | SNI-aware TCP passthrough | Production-tested with NATS |
| `https+tcp+sni` | HTTPS listener with TCP fallback | Production-tested with NATS |
| `tcp-dynamic` | Dynamic listeners from route table | Implemented |

Validated with NATS protocol:
- INFO, PING/PONG, CONNECT/SUB/PUB/UNSUB
- Queue groups
- 50KB payloads
- 20+ concurrent connections
- Binary garbage rejection
- Slow stream handling

---

## Final migration decision

### Safe to migrate now if
- current production use is limited to HTTP/HTTPS/WS/gRPC family (fully supported)
- certificates use Consul KV or mounted PEM files (both supported)
- Cloudflare real-IP behavior is verified
- canary passes on low-risk domains

### Not safe yet if
- you depend on Fabio UI as primary operational surface (replace with admin API + dashboard)
- `/fabio/config` contains critical behavior with no native mapping
- Cloudflare header trust chain is not verified

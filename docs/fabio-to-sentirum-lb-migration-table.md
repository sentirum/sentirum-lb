# Fabio → sent irum-lb Migration Table

## Scope

This table covers the **current migration target**:
- replace Fabio for **HTTP/HTTPS host/path ingress**
- preserve current **Cloudflare + Consul service-tag routing** behavior
- use **mounted PEM files** for TLS in sent irum-lb

Out of scope for phase 1:
- full Fabio property compatibility
- Fabio UI parity
- raw TCP / `proto=tcp` / `tcp+sni` parity

Important note:
- **Raw TCP is not used today**, so it is **not a blocker for phase 1**
- but it **will become a future blocker** if you want to route **NATS** through the same LB later

---

## Executive summary

| Area | Fabio today | sent irum-lb today | Migration status | Action |
|---|---|---|---|---|
| HTTP ingress | Supported | Supported | OK | Migrate |
| HTTPS ingress | Supported | Supported | OK with TLS delivery change | Migrate with PEM mount |
| Host/path routing | `urlprefix-` tags | `urlprefix-` tags | OK | Migrate |
| Consul service discovery | Yes | Yes | OK | Migrate |
| Consul KV routes | Yes (`/fabio/config`) in theory, but empty now | Yes (native KV route prefix) | Mostly irrelevant today | Optional mapping only |
| Consul KV certificates | Yes | No | Gap | Replace with file sync/mount |
| Cloudflare real IP | Yes | Yes, via trusted proxies | Needs verification | Canary test |
| WebSocket | Yes | Yes | Needs validation | Canary test |
| gRPC/gRPC-Web | Fabio unclear / maybe limited by usage | Supported | Needs validation if used | Canary test |
| Fabio UI | Yes | No | Gap | Replace with admin API + metrics |
| Raw TCP / SNI | Fabio supports | sent irum-lb not production-ready | Gap | Phase 2 / future work |

---

## Property / behavior mapping

| Fabio property / behavior | Current Fabio usage | sent irum-lb equivalent | Status | Notes |
|---|---|---|---|---|
| `proxy.addr = :80;proto=http,:443;proto=https;cs=consul` | Yes | `server.listen`, `tls.listen` | Partial | sent irum-lb separates HTTP and TLS listener config |
| `proxy.cs = cs=consul;type=consul;cert=http://consul.../v1/kv/fabio/cert` | Yes | None native | Missing | Must migrate to mounted PEM files or add new cert watcher feature |
| `registry.consul.addr = consul.service.consul:8500` | Yes | `consul.address`, `consul.scheme` | Supported | Direct mapping |
| `registry.consul.register.enabled = true` | Yes | None | Not needed / separate concern | Nomad service stanza can handle registration |
| `registry.consul.register.name = fabio` | Yes | None | Not needed | sent irum-lb does not need Fabio-style self-registration for routing |
| `registry.consul.kvpath = /fabio/config` | Configured, but KV empty | `consul.kv_prefix` | Partial | Only relevant if you actually want route KV in sent irum-lb |
| `registry.consul.tagprefix = urlprefix-` | Yes | `consul.tag_prefix` | Supported | Direct mapping |
| `ui.addr` | Yes | None | Missing | Replace with `/admin/*` + Prometheus/Grafana |
| `log.level` | Yes | `server.log_level` / runtime logging | Supported-ish | Use native logging style |
| `log.routes.format = delta` | Yes | No direct equivalent | Missing / low priority | Optional observability enhancement |
| `log.access.*` | Yes | Request logging exists | Partial | Validate desired log format |
| `metrics.target = stdout` | Yes | `/admin/metrics` Prometheus endpoint | Different model | Prefer Prometheus scrape |
| `metrics.prefix = fabio` | Yes | Native Prometheus metric names | Different model | Dashboard/alert migration needed |
| `proxy.readtimeout = 3600s` | Yes | `proxy.read_timeout` | Supported | Map value |
| `proxy.writetimeout = 3600s` | Yes | `proxy.write_timeout` | Supported | Map value |
| `proxy.dialtimeout = 30s` | Yes | `proxy.connect_timeout` | Supported | Map value |
| `proxy.responseheadertimeout = 300s` | Yes | No exact dedicated knob seen | Partial | Check current timeout surface |
| `proxy.keepalivetimeout = 90s` | Yes | `proxy.idle_timeout` | Approximate | Validate semantics |
| `proxy.maxconn = 10000` | Yes | `proxy.max_connections` | Partial | sent irum-lb enforces per-upstream target, not same global semantic |
| `proxy.strategy = rr` | Yes | `proxy.strategy` | Supported | Map to existing picker strategy |
| `proxy.matcher = prefix` | Yes | `proxy.matcher` | Supported | Direct mapping |
| `proxy.noroutestatus = 404` | Yes | `proxy.no_route_status` | Supported | Direct mapping |
| `proxy.header.clientip = X-Forwarded-For` | Yes | Forwarded-header handling in proxy | Partial | sent irum-lb appends/forwards based on trusted proxy policy |
| `proxy.header.clientip.header = CF-Connecting-IP` | Yes | `CF-Connecting-IP` trusted only from `trusted_proxies` | Supported | Must configure Cloudflare CIDRs |
| `proxy.header.tls = X-Forwarded-Proto` | Yes | native forwarded header behavior | Supported | Verify exact output in canary |
| `proxy.header.tls.value = https` | Yes | inferred from TLS/trusted proxy path | Supported-ish | Verify parity |
| `proxy.ws = true` | Yes | WebSocket support exists | Supported | Must validate in canary |
| `proxy.localip = ${attr.unique.network.ip-address}` | Yes | No direct equivalent needed | Usually not needed | Check if source-IP pinning matters operationally |
| `proxy.shutdownwait = 30s` | Yes | graceful shutdown behavior via service/runtime | Partial | Worth validating during rolling restart |

---

## Route source mapping

| Current Fabio route source | Observed state | sent irum-lb migration | Decision |
|---|---|---|---|
| Consul service tags with `urlprefix-` | Active | Keep as-is | Primary path |
| `/fabio/config` KV routes | Configured in Fabio but currently empty | Optional: map to `consul.kv_prefix` if needed later | Not required for phase 1 |
| KV cert store under `/fabio/cert/*` | Active | Replace with PEM file delivery | Required |

---

## TLS / certificate migration

### Current Fabio model
- Fabio reads cert bundles from Consul KV under `/fabio/cert/*`
- bundle appears to include:
  - leaf cert
  - chain
  - private key

### sent irum-lb current model
- expects file paths:
  - `tls.cert_path`
  - `tls.key_path`
- no native Consul-backed cert ingestion today

### Recommended migration model
| Current | Target |
|---|---|
| Consul KV cert bundles | Render/sync PEM files onto node/allocation |
| Fabio loads from KV | sent irum-lb loads from mounted files |
| dynamic KV-based rotation | rolling restart on cert update |

### Recommended delivery options
1. Nomad template rendering
2. Vault/sidecar sync to files
3. external sync job writing PEM files

### Decision
**For phase 1, do not build Consul-backed live cert reload unless required.**

---

## Cloudflare / real IP mapping

| Behavior | Fabio today | sent irum-lb target | Required action |
|---|---|---|---|
| trust `CF-Connecting-IP` | Yes | Yes | configure `proxy.trusted_proxies` with Cloudflare CIDRs / trusted edge chain |
| set forwarded proto correctly | Yes | Yes | validate under HTTPS canary |
| reject spoofed client IP headers from untrusted sources | Implicit Fabio behavior | Explicit trusted proxy model | validate in canary |

### Canary checks
- request from Cloudflare path shows real client IP upstream
- direct/untrusted request cannot spoof `CF-Connecting-IP`
- `X-Forwarded-Proto=https` parity is preserved

---

## Observability / operations mapping

| Fabio capability | Current usage | sent irum-lb replacement |
|---|---|---|
| Fabio UI | Internal UI on `:9997` | `/admin/routes`, `/admin/config`, `/admin/metrics` + Grafana |
| stdout metrics | Yes | Prometheus scrape |
| route visibility | UI/routes | admin API |
| health checks | TCP on 80/443/UI | `/health`, `/healthz`, `/admin/health` |

### Operational change
Team will lose Fabio dashboard, so dashboards and alerts must move to:
- Prometheus
- Grafana
- sent irum-lb admin endpoints

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
| raw TCP / SNI | No for phase 1 | future phase |

---

## Future phase: NATS / TCP routing

If you later want to proxy NATS through this LB, current sent irum-lb is **not enough yet**.

### Why
- route parsing may recognize `proto=tcp`
- but runtime raw TCP serving is still placeholder-level
- Fabio-style `tcp+sni` parity is not ready

### What that means
| Use case | Phase 1 | Future |
|---|---|---|
| replace Fabio for web ingress | Yes | now |
| replace Fabio for NATS/TCP ingress | No | requires raw TCP implementation |

### Recommendation
Treat **TCP/NATS support as a separate phase** with separate acceptance criteria.

---

## Final migration decision

### Safe to migrate now if
- current production use is limited to HTTP/HTTPS/WS/gRPC family
- certificates are moved from Consul KV delivery to mounted PEM delivery
- Cloudflare real-IP behavior is verified
- canary passes on low-risk domains

### Not safe yet if
- you need Fabio KV cert behavior without operational changes
- you need TCP/SNI/NATS routing in same migration wave
- you depend on Fabio UI as primary operational surface

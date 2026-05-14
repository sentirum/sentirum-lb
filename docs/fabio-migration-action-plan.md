# Fabio → Sentirum LB Action Plan

## Recommendation

**Default path: low-risk replacement.**

Goal:
- replace current Fabio usage for **HTTP/HTTPS host/path ingress**
- optionally target raw TCP/SNI parity — all modes are now production-tested
- **do not** build full Fabio config compatibility unless inventory proves it is required
- prefer **mounted PEM or Consul KV** for certificate delivery — both fully supported

Reason:
- repo already supports service-tag and route-KV driven HTTP-family ingress
- TLS source supports both **file** (`cert_path` + `key_path`) and **Consul KV** (`consul_kv` source with live reload)
- raw TCP modes (`tcp`, `tcp+sni`, `https+tcp+sni`, `tcp-dynamic`) are production-tested with NATS
- full Fabio parity is expensive and risky

---

## P0 — Stop guessing, lock inventory

### Objective
Confirm what production Fabio actually uses.

### Tasks
1. Inventory active route sources
   - list Consul service tags using `urlprefix-`
   - list KV prefixes consumed by Fabio
   - verify whether `/fabio/config` contains only routes or also operational config/certs
2. Inventory protocol usage
   - classify traffic as: `http`, `https`, `ws`, `wss`, `grpc`, `grpcs`, `tcp`
   - flag any `proto=tcp` or TCP+SNI style usage — now supported and production-tested
3. Inventory certificate source
   - confirm whether certs come from mounted files, Consul KV, Vault template, or another sync path
4. Inventory Cloudflare assumptions
   - identify current real-IP header path
   - capture current trusted proxy ranges / ingress chain

### Deliverable
Compatibility matrix:
- **supported now**
- **needs migration/config change**
- **blocker / not supported**

### Exit criteria
No unknowns left around:
- cert source
- `/fabio/config` usage
- TCP usage
- Cloudflare header path

---

## P1 — Make native Sentirum LB deployment operable

### Objective
Close must-have gaps without widening scope.

### Code changes

#### 1) TLS source visibility and fail-fast
Files:
- `src/config.rs`
- `src/main.rs`
- `src/proxy/tls.rs`

Changes:
- make TLS mode explicit in logs/config diagnostics
- fail fast or emit hard-error logs when TLS listener is expected but cert/key is missing/invalid
- print active TLS source strategy at startup
- improve PEM validation messages

Acceptance:
- operator can tell in logs why TLS listener did or did not start
- no silent half-working HTTPS state

#### 2) Runtime visibility for trusted proxies
Files:
- `src/admin/api.rs`
- `config.toml`

Changes:
- expose `proxy.trusted_proxies` in `/admin/config`
- expose TLS source/status in `/admin/config`
- add sample config for Cloudflare CIDRs

Acceptance:
- canary can verify runtime config via admin API

#### 3) Docs for real migration boundary
Files:
- `README.md`
- `docs/fabio-migration-action-plan.md`

Changes:
- document clearly:
  - supported today: service tags + route KV + HTTP-family protocols + TCP modes
  - not parity today: Fabio UI, generic Fabio property ingestion
  - recommended cert model: Consul KV (direct migration) or mounted PEM + rolling restart
  - Cloudflare real-IP behavior depends on `trusted_proxies`

Acceptance:
- no false expectation of full Fabio compatibility

---

## P2 — Decide TLS strategy

### Recommended options (both fully supported)

#### Option A: Consul KV source (path of least change)
- `tls.source = "consul_kv"` watches keys under `tls.consul_cert_prefix`
- Fabio-compatible cert bundles (leaf + chain + key in one PEM)
- Live reload without restart
- SNI-based certificate selection
- Zero operational change from current Fabio setup

#### Option B: Mounted PEM files + rolling restart
- `tls.source = "file"` via `cert_path` + `key_path`
- certs rendered/synced by Nomad template, Vault agent, sidecar, or external secret sync
- checksum/version change triggers rolling restart
- Sentirum LB keeps simple file-based TLS

Why Option A is default:
- smallest operational change from Fabio
- cert bundles stay in the same Consul KV path
- live cert rotation without restart
- both options support hot-reload (file mode via `FileCertWatcherService` polling mtime)

---

## P3 — Canary rollout plan

### Topology
- run Fabio and Sentirum LB side-by-side
- same Consul route sources
- separate listener/bind or separate hostname subset
- move 1–2 low-risk domains first

### Verify in canary
1. Health
   - `/health`
   - `/healthz`
   - `/admin/health`
2. Routing
   - host routing
   - path prefix routing
   - KV route updates
   - service tag updates
3. Cloudflare / real IP
   - `CF-Connecting-IP`
   - `X-Forwarded-Proto`
   - `X-Forwarded-Host`
   - ensure only trusted proxies can influence these
4. TLS
   - correct cert served per SNI
   - rotation procedure works operationally
   - cert hot-reload without restart
5. Protocols in use
   - WebSocket if any
   - gRPC / gRPC-Web if any
   - Raw TCP if any (production-tested with NATS)
6. Observability
   - `/admin/routes`
   - `/admin/metrics`
   - Prometheus scrape
   - alerting/dashboard coverage replacing Fabio UI habit

### Success criteria
- route parity on pilot domains
- correct client IP/header behavior behind Cloudflare
- no TLS regressions
- route propagation latency acceptable
- no unexplained error-rate increase

### Rollback
- keep Fabio path intact during canary
- rollback must be only traffic flip / routing revert
- no data migration dependence

---

## P4 — Replace criteria

### Replace allowed when
- all active prod traffic is HTTP-family or TCP (both supported)
- no required Fabio-only config remains unmapped
- cert delivery strategy is proven and documented
- Cloudflare real-IP behavior validated
- canary passes for pilot domains

### No-go when
- cert rotation model is still unclear
- `/fabio/config` contains critical behavior with no native mapping
- Cloudflare header trust chain is not verified

---

## Concrete work breakdown

### Track A — Ops inventory
Owner: ops/platform
- export active Consul tag usage
- export Fabio KV usage
- identify current cert source
- identify Cloudflare CIDR/trust chain

### Track B — Code hardening
Owner: app/repo
- expose trusted proxies + TLS status in admin config
- improve TLS startup diagnostics
- improve config samples and docs

### Track C — Canary ops
Owner: ops + app
- provision side-by-side deployment
- wire metrics/dashboard/alerts
- run pilot domains
- record propagation/error/header results

---

## Minimal first implementation set

If we want fastest path to usable replacement, do only this first:
1. P0 inventory
2. admin/config visibility for `trusted_proxies` + TLS status
3. TLS startup validation/logging
4. README/config migration notes
5. side-by-side canary

This gets us to a safe decision point.

---

## Immediate next 5 actions

1. Confirm whether prod certs are **mounted files** or **Consul/Vault-backed dynamic material**.
2. Confirm whether any active route uses `proto=tcp` — now fully supported.
3. Inspect `/fabio/config` usage and classify each key as route / cert / other config.
4. Implement admin/runtime visibility + TLS diagnostics in this repo.
5. Stand up one canary deployment and test 1–2 low-risk hostnames.

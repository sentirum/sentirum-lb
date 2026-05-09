# Fabio → sent irum-lb Action Plan

## Recommendation

**Default path: low-risk replacement.**

Goal:
- replace current Fabio usage for **HTTP/HTTPS host/path ingress**
- **do not** target raw TCP/SNI parity in first wave
- **do not** build full Fabio config compatibility unless inventory proves it is required
- prefer **mounted PEM + rolling restart** over Consul-backed live cert reload

Reason:
- repo already supports service-tag and route-KV driven HTTP-family ingress
- biggest gap is **TLS source/rotation model**, not core routing
- raw TCP is not production-ready
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
   - flag any `proto=tcp` or TCP+SNI style usage as blocker
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

## P1 — Make native sent irum-lb deployment operable

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
  - supported today: service tags + route KV + HTTP-family protocols
  - not parity today: Fabio UI, raw TCP, generic Fabio property ingestion
  - recommended cert model: mounted PEM + rolling restart
  - Cloudflare real-IP behavior depends on `trusted_proxies`

Acceptance:
- no false expectation of full Fabio compatibility

---

## P2 — Decide TLS strategy

### Recommended option
**Use mounted PEM files + rolling restart.**

Operational model:
- certs rendered/synced by Nomad template, Vault agent, sidecar, or external secret sync
- checksum/version change triggers rolling restart
- sent irum-lb keeps simple file-based TLS

Why this is default:
- smallest code change
- lowest runtime risk
- aligns with current implementation

### Only if inventory requires it
Build **separate** Consul-backed cert/config watch.

Files if needed:
- `src/config.rs`
- `src/consul/client.rs`
- `src/consul/watcher.rs`
- `src/main.rs`
- maybe `src/proxy/tls.rs`

Rules if implemented:
- keep route watch and cert/config watch separate
- do not overload route KV parser with Fabio general config
- define clear precedence between file config and KV config
- add tests for empty/invalid/stale cert states

### No-go for this branch unless truly required
Do **not** build live cert reload just because Fabio had it. Only do it if P0 proves it is a real production dependency.

---

## P3 — Canary rollout plan

### Topology
- run Fabio and sent irum-lb side-by-side
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
   - correct cert served
   - rotation procedure works operationally
5. Protocols in use
   - WebSocket if any
   - gRPC / gRPC-Web if any
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
- all active prod traffic is HTTP-family
- no required Fabio-only config remains unmapped
- cert delivery strategy is proven and documented
- Cloudflare real-IP behavior validated
- canary passes for pilot domains

### No-go when
- any production route requires raw TCP/SNI parity
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

This gets us to a safe decision point **without** prematurely building Consul-backed cert reload.

---

## Immediate next 5 actions

1. Confirm whether prod certs are **mounted files** or **Consul/Vault-backed dynamic material**.
2. Confirm whether any active route uses `proto=tcp`.
3. Inspect `/fabio/config` usage and classify each key as route / cert / other config.
4. Implement admin/runtime visibility + TLS diagnostics in this repo.
5. Stand up one canary deployment and test 1–2 low-risk hostnames.

# sent irum-lb Smoke Test + Canary Runbook

## 0. Goal
Validate that `sentirum-lb` can replace Fabio for HTTP/HTTPS ingress with:
- runtime route updates
- runtime TLS cert updates from Consul KV
- no LB restart for route/cert changes
- no active connection drops during cert changes

---

## 1. Pre-flight checks

### Build / test
```bash
cd /Users/alper/dev/sentirum/sentirum-lb
cargo test --quiet
cargo build --release --locked
```

### Nomad / Consul access
```bash
export NOMAD_ADDR=http://10.101.1.21:4646
export CONSUL_HTTP_ADDR=http://10.101.1.11:8500

nomad server members
nomad node status
consul members
```

### Current cert inventory
```bash
consul kv export /fabio | jq -r '.[].key' | sort
```

### Current route signal inventory
```bash
consul catalog services
consul catalog nodes
```

---

## 2. Validate the Nomad job

```bash
nomad job validate /Users/alper/dev/devops/sentirum-nomad/nomad/jobs/services/sentirum-lb.nomad
nomad job plan /Users/alper/dev/devops/sentirum-nomad/nomad/jobs/services/sentirum-lb.nomad
```

Before deploy, confirm:
- registry image path is correct
- admin token variable exists
- consul token variable exists if needed
- trusted proxy CIDRs are filled

---

## 3. Recommended canary topology

Do **not** bind Fabio and `sentirum-lb` to `:80/:443` on the same node simultaneously.

Use one of these:
1. separate ingress nodes
2. separate public IP
3. temporary alt ports in a canary-only job variant

Recommended first canary:
- dedicate 1 ingress node to `sentirum-lb`
- route only 1–2 low-risk domains there
- keep Fabio unchanged on the rest

---

## 4. Deploy and observe

### Deploy
```bash
nomad job run /Users/alper/dev/devops/sentirum-nomad/nomad/jobs/services/sentirum-lb.nomad
nomad job status sentirum-lb
```

### Find allocation
```bash
nomad job allocs sentirum-lb
```

### Logs
```bash
nomad alloc logs <alloc-id>
nomad alloc logs -stderr <alloc-id>
```

Expected logs:
- HTTP listener started
- HTTPS listener started
- initial Consul TLS snapshot loaded
- Consul watcher started
- TLS cert watcher started

---

## 5. Admin API checks

### Health
```bash
curl -s http://127.0.0.1:9998/admin/health
```

### Config
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/config | jq
```

Look for:
- `tls.source == "consul_kv"`
- `tls.consul_cert_prefix == "/fabio/cert"`
- `tls.require_initial_snapshot == true`

### Cert runtime state
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/certs | jq
```

### Memory / FD baseline
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/metrics | rg 'sentirum_lb_process_(resident_memory_bytes|virtual_memory_bytes|open_fds|metrics_available)'
```

Look for:
- `loaded_certificates`
- `default_certificate`
- `last_consul_index`
- `last_error == null`

### Routes
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/routes | jq
```

---

## 6. HTTP route smoke test

Choose one real canary hostname already represented by `urlprefix-...` tags.

### Plain HTTP
```bash
curl -sv -H 'Host: <canary-host>' http://<canary-node-ip>/health
```

### HTTPS with SNI
```bash
curl -skv --resolve <canary-host>:443:<canary-node-ip> https://<canary-host>/health
```

Expected:
- correct upstream response
- no route mismatch
- no TLS warning other than trust-chain if using private CA locally

---

## 7. Certificate selection test

### Check served certificate
```bash
openssl s_client -connect <canary-node-ip>:443 -servername <canary-host> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName
```

Expected:
- CN/SAN covers the requested hostname

### Wildcard behavior
If a wildcard cert exists:
```bash
openssl s_client -connect <canary-node-ip>:443 -servername foo.betapi.win </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName
```

Expected:
- wildcard cert selected

---

## 8. Runtime cert reload test

Pick a test-only hostname/cert entry.

### Step A — baseline
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/certs | jq
openssl s_client -connect <canary-node-ip>:443 -servername <test-host> </dev/null 2>/dev/null | openssl x509 -noout -serial -subject
```

### Step B — update KV entry
Update:
- `/fabio/cert/<test-host>.pem`

### Step C — verify runtime pickup
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/certs | jq
openssl s_client -connect <canary-node-ip>:443 -servername <test-host> </dev/null 2>/dev/null | openssl x509 -noout -serial -subject
```

Expected:
- `last_consul_index` advances
- cert serial changes for **new** handshakes
- no process restart
- no allocation replacement

### Confirm no restart happened
```bash
nomad alloc status <alloc-id>
nomad alloc logs <alloc-id> | tail -100
```

Expected:
- same allocation still running
- no fresh process start sequence

---

## 9. Existing connection survival test

Use a long-lived WebSocket/SSE/gRPC stream if available.

### Flow
1. open a long-lived connection through `sentirum-lb`
2. change a test certificate in `/fabio/cert/*`
3. keep the connection open
4. open a **new** connection and verify new cert is served

Expected:
- existing connection stays alive
- new connection uses new cert

This is the key zero-drop behavior.

---

## 10. Route update test without restart

Register or edit a test service tag:
- `urlprefix-<host>/...`

Then:
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/routes | jq
curl -skv --resolve <host>:443:<canary-node-ip> https://<host>/
```

Expected:
- route appears at runtime
- new requests follow new route
- no restart

---

## 11. Broken cert safety test

Create a temporary bad PEM for a test-only hostname under `/fabio/cert/*`.

Then check:
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/certs | jq
```

Expected:
- `last_error` is populated
- previous valid snapshot remains active
- unrelated hostnames still work

This validates last-known-good protection.

---

## 12. Cloudflare / trusted proxy validation

After filling `proxy.trusted_proxies`:

### Real IP
Have upstream log these headers:
- `CF-Connecting-IP`
- `X-Forwarded-For`
- `X-Forwarded-Proto`

Then verify from real traffic that:
- real client IP is preserved from trusted Cloudflare hops
- proto is `https`

### Spoof resistance
Send a direct request from an untrusted source with fake headers and confirm they are not trusted.

---

## 13. Metrics validation

```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:9998/admin/metrics | head -80
```

Check:
- endpoint responds
- Prometheus scrape works
- build dashboard panels before large cutover

---

## 14. Rollback

Rollback is traffic-level, not state-level.

Steps:
1. stop sending canary traffic to `sentirum-lb`
2. send traffic back to Fabio
3. keep KV and service tags unchanged
4. inspect logs before next attempt

No route/cert migration rollback is needed because:
- service tags are still Fabio-compatible
- certs still live under `/fabio/cert/*`

---

## 15. Exit criteria for wider rollout

Promote only if all pass:
- admin API healthy
- `/admin/certs` shows stable snapshot state
- real host/path parity confirmed
- correct cert served per SNI
- cert update picked up without restart
- existing connections survive cert rotation
- route updates work without restart
- Cloudflare IP/header handling verified
- rollback path proven

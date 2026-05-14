# Sentirum LB Smoke Test + Canary Runbook

## 0. Goal
Validate that Sentirum LB can replace Fabio for HTTP/HTTPS ingress with:
- runtime route updates
- runtime TLS cert updates from Consul KV or file source
- optional downstream mTLS / client-cert auth
- no LB restart for route/cert/config changes
- no active connection drops during cert changes

---

## 1. Pre-flight checks

### Build / test
```bash
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
nomad job validate <path-to-nomad-job>
nomad job plan <path-to-nomad-job>
```

Before deploy, confirm:
- registry image path is correct
- admin token variable exists
- consul token variable exists if needed
- trusted proxy CIDRs are filled
- TLS source is configured (`consul_kv` or `file`)

---

## 3. Recommended canary topology

Do **not** bind Fabio and Sentirum LB to `:80/:443` on the same node simultaneously.

Use one of these:
1. separate ingress nodes
2. separate public IP
3. temporary alt ports in a canary-only job variant

Recommended first canary:
- dedicate 1 ingress node to Sentirum LB
- route only 1–2 low-risk domains there
- keep Fabio unchanged on the rest

Port note:
- production job typically uses `:80 / :443 / :9998`
- current canary job uses `:8080 / :8443 / :19998`
- replace `<http-port>`, `<https-port>`, and `<admin-port>` below accordingly

---

## 4. Deploy and observe

### Deploy
```bash
nomad job run <path-to-nomad-job>
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
- HTTPS listener started (if TLS configured)
- initial Consul TLS snapshot loaded (if `consul_kv` source)
- Consul watcher started
- TLS cert watcher started (if `file` source)

---

## 5. Admin API checks

### Health
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/health
```

### Config
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/config | jq
```

Look for:
- `tls.source` matches intended mode (`consul_kv` or `file`)
- `tls.consul_cert_prefix` (if `consul_kv`) or `tls.cert_path`/`tls.key_path` (if `file`)
- `tls.require_initial_snapshot == true` (if `consul_kv`)
- if enabled: `tls.client_auth`, `tls.client_ca_source`, `tls.client_ca_consul_prefix` / `tls.client_ca_path`

### Cert runtime state
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/certs | jq
```

### Memory / FD baseline
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/metrics | rg 'sentirum_lb_process_(resident_memory_bytes|virtual_memory_bytes|open_fds)'
```

Look for:
- `loaded_certificates`
- `default_certificate`
- `last_consul_index` (if `consul_kv` source)
- `last_error == null`
- if enabled: `client_auth.loaded_entries` is non-empty and `client_auth.last_error == null`

### Routes
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/routes | jq
```

---

## 6. HTTP route smoke test

Choose one real canary hostname already represented by `urlprefix-...` tags.

### Plain HTTP
```bash
curl -sv -H 'Host: <canary-host>' http://<canary-node-ip>:<http-port>/health
```

### HTTPS with SNI
```bash
curl -skv --resolve <canary-host>:<https-port>:<canary-node-ip> https://<canary-host>:<https-port>/health
```

Expected:
- correct upstream response
- no route mismatch
- no TLS warning other than trust-chain if using private CA locally

---

## 7. Certificate selection test

### Check served certificate
```bash
openssl s_client -connect <canary-node-ip>:<https-port> -servername <canary-host> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName
```

Expected:
- CN/SAN covers the requested hostname

### Wildcard behavior
If a wildcard cert exists:
```bash
openssl s_client -connect <canary-node-ip>:<https-port> -servername foo.example.com </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName
```

Expected:
- wildcard cert selected

---

## 8. Runtime cert reload test

Pick a test-only hostname/cert entry.

### Step A — baseline
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/certs | jq
openssl s_client -connect <canary-node-ip>:<https-port> -servername <test-host> </dev/null 2>/dev/null | openssl x509 -noout -serial -subject
```

### Step B — update cert
- **Consul KV mode**: update `/fabio/cert/<test-host>.pem`
- **File mode**: update the cert/key files on disk, then either wait 30s for auto-reload or trigger `POST /admin/certs/reload`

### Step C — verify runtime pickup
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/certs | jq
openssl s_client -connect <canary-node-ip>:<https-port> -servername <test-host> </dev/null 2>/dev/null | openssl x509 -noout -serial -subject
```

Expected:
- `last_consul_index` advances (Consul KV mode) or cert mtime changes (file mode)
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
1. open a long-lived connection through Sentirum LB
2. change a test certificate
3. keep the connection open
4. open a **new** connection and verify new cert is served

Expected:
- existing connection stays alive
- new connection uses new cert

This is the key zero-drop behavior.

---

## 10. mTLS smoke test

Run this only when downstream client-cert auth is enabled.

### Confirm runtime config
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/config | jq '.tls'
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/certs | jq '.client_auth'
```

### Required-mode negative test
```bash
curl -skv --resolve <mtls-host>:<https-port>:<canary-node-ip> https://<mtls-host>:<https-port>/health
```

Expected with `client_auth = "required"`:
- handshake fails without a client cert

### Positive test with client cert
```bash
curl -skv \
  --resolve <mtls-host>:<https-port>:<canary-node-ip> \
  --cert client-cert.pem \
  --key client-key.pem \
  --cacert downstream-server-ca.pem \
  https://<mtls-host>/whoami
```

Expected:
- handshake succeeds
- upstream/app receives:
  - `X-Client-Cert-Verified: true`
  - `X-Client-Cert-Serial`
  - `X-Client-Cert-Organization`
  - `X-Client-Cert-Common-Name`
  - `X-Client-Cert-Organizational-Unit`
  - `X-Client-Cert-Subject`
  - `X-Client-Cert-SHA256`

### Fabio-style CA-upgrade edge case
If you rely on self-signed/non-CA client-auth roots similar to Fabio's `ApiGateway` compatibility path:
- configure `tls.client_ca_upgrade_cn = "ApiGateway"`
- verify the same client cert fails without it
- verify the same client cert succeeds with it

---

## 11. Route update test without restart

Register or edit a test service tag:
- `urlprefix-<host>/...`

Then:
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/routes | jq
curl -skv --resolve <host>:<https-port>:<canary-node-ip> https://<host>:<https-port>/
```

Expected:
- route appears at runtime
- new requests follow new route
- no restart

---

## 12. Runtime config hot-reload test

### Change a setting
```bash
curl -s -X PUT -H "X-Admin-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"proxy":{"strategy":"random"}}' \
  http://127.0.0.1:<admin-port>/admin/config | jq
```

### Verify
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/config | jq '.proxy.strategy'
```

Expected:
- setting changes immediately
- no restart
- no traffic disruption

---

## 13. Broken cert safety test

Create a temporary bad PEM for a test-only hostname.

Then check:
```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/certs | jq
```

Expected:
- `last_error` is populated
- previous valid snapshot remains active
- unrelated hostnames still work

This validates last-known-good protection.

---

## 14. Cloudflare / trusted proxy validation

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

## 15. Metrics validation

```bash
curl -s -H "X-Admin-Token: <token>" http://127.0.0.1:<admin-port>/admin/metrics | head -80
```

Check:
- endpoint responds
- Prometheus scrape works
- build dashboard panels before large cutover

---

## 16. Rollback

Rollback is traffic-level, not state-level.

Steps:
1. stop sending canary traffic to Sentirum LB
2. send traffic back to Fabio
3. keep KV and service tags unchanged
4. inspect logs before next attempt

No route/cert migration rollback is needed because:
- service tags are still Fabio-compatible
- certs still live under `/fabio/cert/*` (or file paths are independent)

---

## 17. Graceful Reload / Nomad Lifecycle

### Procedure for Zero-Downtime Reload

When deploying a new version of Sentirum LB via Nomad:

1. **Pre-maintenance**: Before stopping the old instance, enable Consul node maintenance mode:
   ```bash
   consul maint -enable -reason "Upgrading sentirum-lb to vX.Y.Z"
   ```

2. **Deploy new version**: Nomad will start the new instance. The new instance will:
   - Start listening on the configured ports
   - Begin Consul watchers to discover routes
   - Accept new connections immediately

3. **Wait for routes**: The new instance will discover routes from Consul and become operational within the poll interval (default: 3s with blocking queries).

4. **Verify operation**: Check `/admin/health` and `/admin/routes` on the new instance.

5. **Post-maintenance**: Disable Consul node maintenance after confirming the new instance is healthy:
   ```bash
   consul maint -disable
   ```

### Configuration Options

Key configuration for graceful operation:

```toml
[consul]
service_discovery = true
kv_watching = true
poll_interval = "3s"  # Balance between responsiveness and Consul load
service_whitelist = ["webapp", "api"]  # Only route traffic for specific services

[server]
drain_timeout = "30s"  # Grace period for in-flight requests during shutdown
```

### Consul Node Maintenance

When a Sentirum LB node is in Consul node maintenance mode:
- Health checks are marked critical
- Consul's `passing_services` logic will exclude that node's services
- Other Sentirum LB instances will automatically route around the node
- No new traffic is sent to the node during maintenance

---

## 18. Exit criteria for wider rollout

Promote only if all pass:
- admin API healthy
- `/admin/certs` shows stable snapshot state
- real host/path parity confirmed
- correct cert served per SNI
- cert update picked up without restart
- existing connections survive cert rotation
- route updates work without restart
- runtime config changes work without restart
- Cloudflare IP/header handling verified
- rollback path proven

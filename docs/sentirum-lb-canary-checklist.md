# Sentirum LB Canary Checklist

## Goal
Replace Fabio for HTTP/HTTPS ingress without dropping active users.

## Preconditions
- `sentirum-lb` image built from current repo
- Nomad job uses `tls.source = "consul_kv"`
- Consul KV certs exist under `/fabio/cert/*`
- service tags continue to use `urlprefix-...`
- `proxy.trusted_proxies` is filled correctly for Cloudflare / trusted hops
- if mTLS is enabled:
  - `tls.client_auth` is set as intended (`optional` or `required`)
  - trusted client CA bundles exist in `tls.client_ca_path` or `tls.client_ca_consul_prefix`
  - `tls.client_ca_upgrade_cn` is set if Fabio-style CA-upgrade compatibility is needed

## Runtime guarantees to verify
- route updates are applied without process restart
- cert updates are applied without process restart
- existing WebSocket / long-lived streams are not dropped
- only new TLS handshakes pick up new cert snapshots

## Step 1 — Side-by-side deploy
- keep Fabio running
- deploy `sentirum-lb` on separate edge nodes or separate public IP / DNS target
- verify:
  - `GET /health`
  - `GET /healthz`
  - `GET /admin/health` (include `X-Admin-Token` when admin auth is enabled)
  - `GET /admin/config`
  - `GET /admin/certs`
  - `GET /admin/metrics`

## Step 2 — Route parity
For 1–2 low-risk domains:
- verify host routing
- verify path routing
- verify `strip` / `prepend`
- verify no-route status behavior
- verify route change propagation from Consul service tags

## Step 3 — TLS parity
- hit each pilot hostname with SNI set correctly
- verify the served cert CN/SAN is correct
- verify wildcard coverage works where expected
- add a new cert KV key under `/fabio/cert/*`
- verify `/admin/certs` reflects the new snapshot
- verify new TLS handshakes use the new cert
- verify existing long-lived connections are still alive
- if mTLS is enabled:
  - verify `/admin/certs.client_auth` shows expected CA source and loaded entries
  - verify request without client cert fails when `client_auth = "required"`
  - verify request with valid client cert succeeds
  - verify upstream receives `X-Client-Cert-*` identity headers
  - if using non-CA/self-signed Fabio-compatible client CA, verify `client_ca_upgrade_cn` path works as expected

## Step 4 — Cloudflare / real IP
- confirm upstream sees real client IP from `CF-Connecting-IP`
- confirm direct untrusted requests cannot spoof forwarded headers
- confirm `X-Forwarded-Proto=https` behavior is correct

## Step 5 — Protocols
- WebSocket upgrade works
- gRPC / gRPCS works if used
- gRPC-Web works if used

## Step 6 — Failure safety
- push one intentionally broken cert bundle to a test hostname
- confirm:
  - old valid snapshot stays active
  - `/admin/certs` shows `last_error`
  - unrelated hostnames continue to work
- restore valid cert and confirm new snapshot applies

## Step 7 — Cutover
- move a small production domain set first
- watch:
  - 4xx/5xx rates
  - TLS handshake failures
  - route misses
  - websocket disconnects
- if stable, expand domain set gradually

## Rollback
- switch traffic back to Fabio
- no state migration required
- Consul service tags and cert KV remain unchanged

## Success criteria
- no LB restart required for route changes
- no LB restart required for cert changes
- no user-visible disconnect spike during cert rotation
- `/admin/certs` shows healthy runtime snapshots
- pilot domains behave the same or better than Fabio

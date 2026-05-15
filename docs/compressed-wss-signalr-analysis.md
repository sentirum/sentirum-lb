# Compressed WSS (permessage-deflate) Handshake Failure Analysis

## Issue

SignalR/Kestrel with `permessage-deflate` WebSocket compression enabled causes WSS
handshake to hang indefinitely behind sentirum-lb. The browser shows the 101 response
as "pending" with 0 bytes received. After ~70-90 seconds, SignalR falls back to SSE transport.

## Root Cause (Empirical Evidence)

**Cloudflare strict 101 response parsing + `X-Served-By` header injection.**

### Evidence

Production cutover test (sentirum-lb → Fabio):

| Proxy | Compressed WSS | Observations |
|-------|---------------|--------------|
| Fabio | ✅ Works | Browser DevTools: 101 + `Sec-WebSocket-Extensions: permessage-deflate` returned |
| sentirum-lb (Pingora) | ❌ Hangs | Browser DevTools: 101 pending, 0 bytes |

The only behavioral difference: sentirum-lb adds `X-Served-By: sentirum-lb` to **all**
responses including 101 Switching Protocols. Fabio adds no extra headers.

### Mechanism

1. Browser sends WSS upgrade request with `Sec-WebSocket-Extensions: permessage-deflate`
2. sentirum-lb proxies to upstream, upstream returns 101 Switching Protocols
3. `response_filter` injects `X-Served-By: sentirum-lb` into the 101 response
4. Cloudflare's strict 101 parser rejects/misreads the response due to the non-standard
   header (RFC 6455 §4.2.2 "additional fields" interpreted narrowly)
5. Cloudflare does not forward the 101 to the browser
6. Browser shows pending → SignalR timeout → SSE fallback

### Why `tls.http2 = false` is relevant

Production has `tls.http2 = false` since v1.4.1. This means Pingora's HTTP/2 → HTTP/1.1
conversion path in `proxy_h1.rs` is **never triggered**. The initial theory that H2→H1
conversion drops the `Upgrade` header is **not the actual cause** in this case — it was
based on static code analysis without empirical validation.

## Fix

Remove `X-Served-By` header injection from all response paths:

- `handler.rs` — `response_filter` (proxy responses)
- `handler.rs` — health check (200 responses)
- `access.rs` — error responses
- `protocol.rs` — gRPC error responses

### Rationale for complete removal (vs. 101-only skip)

- `X-Served-By` provides near-zero operational value: `X-Request-ID`, structured logging,
  and Prometheus metrics already cover request tracing
- Every response pays an allocation/write cost for a header nobody consumes
- Fabio (the predecessor) does not inject any response headers — behavioral parity
- Eliminates the entire class of strict-intermediary edge cases, not just Cloudflare

## Non-goals (Speculative — Not Included)

These were considered but **not validated by empirical testing**:

1. **H2→H1 Upgrade header injection**: With `tls.http2 = false`, the H2→H1 path is dead
   code. If HTTP/2 downstream is re-enabled in the future **and** Pingora adds RFC 8441
   (Extended CONNECT) support, this may become relevant — address it then.

2. **WebSocket-specific timeout override**: The actual issue was header injection, not
   timeouts. Existing `idle_timeout` is already configurable and sufficient for SignalR's
   `keepAliveInterval` (default 15s).

## References

- RFC 6455 §4.2.2 — WebSocket handshake server response requirements
- RFC 7692 — WebSocket Per-Message Deflate compression extension
- Fabio source: minimal header modification on proxy responses

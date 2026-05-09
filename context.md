# context.md — sentirum-lb TLS-from-Consul-KV migration territory

Goal context: replace Fabio with sentirum-lb in a Nomad+Consul+Cloudflare ingress, sourcing TLS certificates dynamically from Consul KV under the existing `/fabio/cert/<domain>.pem` layout, with live reload, per-SNI selection, and zero per-domain manual file management.

This document maps the territory only. It does not propose a solution.

---

## 0) Cargo dependencies (verbatim, `Cargo.toml`)

`Cargo.toml:11-12`
```toml
pingora = { version = "0.5", features = ["proxy", "lb", "rustls"] }
pingora-http = "0.5"
```

`Cargo.toml:55`
```toml
rustls = { version = "0.23", features = ["ring"] }
```

Resolved (`Cargo.lock`):
- `pingora` 0.5.0
- `pingora-core` 0.5.0
- `pingora-proxy` 0.5.0
- `pingora-rustls` 0.5.0
- `rustls` 0.23.37

Feature flag selected: `rustls` (NOT openssl/boringssl). This choice has direct consequences in section 1.

Crypto provider initialised at process start (`src/main.rs:153`):
```rust
let _ = rustls::crypto::ring::default_provider().install_default();
```

---

## 1) TLS termination model

### 1.1 Where it is built

The TLS listener is created entirely inside `main()` and hands a fully-baked `TlsSettings` value to the proxy service.

`src/main.rs:280-323`
```rust
// Add TLS listener if configured
let tls_cert_config: Option<sentirum_lb::proxy::tls::TlsCertConfig> = (&config.tls).into();
if let Some(tls) = &tls_cert_config {
    match tls.validate() {
        Ok(()) => {
            // Use explicit TLS listen address, or derive from HTTP port +1
            let tls_listen = if config.tls.listen.is_empty() {
                let http_port: u16 = config
                    .server
                    .listen
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(9999);
                format!(":{}", http_port + 1)
            } else {
                config.tls.listen.clone()
            };

            match pingora::listeners::tls::TlsSettings::intermediate(
                &tls.cert_path,
                &tls.key_path,
            ) {
                Ok(mut settings) => {
                    settings.enable_h2();
                    lb_service.add_tls_with_settings(&tls_listen, None, settings);
                    tracing::info!(addr = %tls_listen, h2_enabled = true, "Proxy listening (HTTPS/TLS)");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to configure TLS listener");
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "TLS configuration invalid, skipping HTTPS listener");
        }
    }
}
```

`src/proxy/tls.rs:12-18` (current cert config model):
```rust
pub struct TlsCertConfig {
    /// Path to the TLS certificate (PEM format)
    pub cert_path: String,
    /// Path to the TLS private key (PEM format)
    pub key_path: String,
}
```

`src/config.rs:194-202`:
```rust
pub struct TlsConfig {
    /// Path to TLS certificate (PEM)
    pub cert_path: String,
    /// Path to TLS private key (PEM)
    pub key_path: String,
    /// TLS listen address (e.g. ":9443"). Empty = auto-derive from HTTP port +1
    #[serde(default)]
    pub listen: String,
}
```

### 1.2 What Pingora 0.5.0 actually supports under the `rustls` feature

`/tmp/pingora-src/pingora-core/src/listeners/tls/rustls/mod.rs` (full file inspected). Verbatim relevant parts:

```rust
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_path: String,
    key_path: String,
}

pub struct Acceptor {
    pub acceptor: RusTlsAcceptor,
    callbacks: Option<TlsAcceptCallbacks>,
}
```

```rust
pub fn build(self) -> Acceptor {
    let Ok(Some((certs, key))) = load_certs_and_key_files(&self.cert_path, &self.key_path)
    else {
        panic!(
            "Failed to load provided certificates \"{}\" or key \"{}\".",
            self.cert_path, self.key_path
        )
    };

    let mut config =
        ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            ...
    Acceptor {
        acceptor: RusTlsAcceptor::from(Arc::new(config)),
        callbacks: None,
    }
}
```

```rust
pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self> { ... }

pub fn with_callbacks() -> Result<Self> {
    Error::e_explain(
        InternalError,
        "Certificate callbacks are not supported with feature \"rustls\".",
    )
}
```

And in `pingora-core/src/protocols/tls/rustls/server.rs:64-83`:
```rust
pub async fn handshake_with_callback<S: IO>(
    acceptor: &Acceptor,
    io: S,
    _callbacks: &TlsAcceptCallbacks,
) -> Result<TlsStream<S>> {
    ...
    if !done {
        warn!("Callacks are not supported with feature \"rustls\".");
        ...
    }
    ...
}
```

Hard facts derived:

1. With `feature = "rustls"`, the only public path to a TLS endpoint is `TlsSettings::intermediate(cert_path, key_path)` → `Service::add_tls_with_settings(...)`.
2. `with_callbacks()` is explicitly stubbed to return an error in rustls mode.
3. The `Acceptor` wraps `tokio_rustls::TlsAcceptor::from(Arc::new(rustls::ServerConfig))`. Once built, the `ServerConfig` is in an `Arc` and is not exposed through any public mutator.
4. There is **no public API in pingora-core 0.5.0** to:
   - inject a pre-built `rustls::ServerConfig`
   - inject an `Arc<dyn rustls::server::ResolvesServerCert>`
   - swap the cert resolver at runtime
5. `pingora::listeners::tls::Acceptor` and `TransportStack` are non-`pub`/`pub(crate)`; the listener stack is constructed only via `TransportStackBuilder` inside pingora-core. See `pingora-core/src/listeners/mod.rs:55-79` (`TransportStackBuilder.build`) and `mod.rs:84-104` (`TransportStack`/`UninitializedStream`).

What the BoringSSL/OpenSSL path supports (for completeness, since `pingora-rustls` selection currently blocks this in our build):

`/tmp/pingora-src/pingora-core/src/listeners/tls/boringssl_openssl/mod.rs:91-100`:
```rust
pub fn with_callbacks(callbacks: TlsAcceptCallbacks) -> Result<Self> {
    let accept_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).or_err(...)?;
    Ok(TlsSettings { accept_builder, callbacks: Some(callbacks) })
}
```

`pingora-core/src/listeners/mod.rs:42-52`:
```rust
#[async_trait]
pub trait TlsAccept {
    async fn certificate_callback(&self, _ssl: &mut TlsRef) -> () {
        // does nothing by default
    }
}
pub type TlsAcceptCallbacks = Box<dyn TlsAccept + Send + Sync>;
```

And in `pingora-core/src/protocols/tls/boringssl_openssl/server.rs:49-62` the callback is awaited inside the handshake before the cert is selected, with the `SslRef` mutable so an implementation can call `ssl_use_certificate` / `ssl_use_private_key` per-SNI. That is the mechanism Fabio-style dynamic, per-handshake cert selection would use — but it is unreachable from the current rustls feature configuration.

### 1.3 What `pingora-rustls` 0.5.0 re-exports

`/tmp/pingora-src/pingora-rustls/src/lib.rs:28-35`:
```rust
pub use rustls::{version, ClientConfig, RootCertStore, ServerConfig, Stream};
pub use rustls_native_certs::load_native_certs;
use rustls_pemfile::Item;
pub use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;
pub use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};
```

So `rustls::ServerConfig`, `rustls::server::ResolvesServerCertUsingSni` (and any custom `ResolvesServerCert`), and `tokio_rustls::TlsAcceptor` are all reachable as Rust-API surface; what's missing is a pingora-core entry point that takes them.

Upstream evidence of where this is going (web): pingora issue #594 ("Server TLS Certificate bundle + SNI based resolver") proposes `TlsSettings::intermediate_bundle(Vec<BundleCert>)` which internally builds `rustls::server::ResolvesServerCertUsingSni`; not merged at time of writing.

### 1.4 Pingora server lifecycle relevant to TLS

`src/main.rs:265-339` builds one `Server`, adds one `lb_service` (with HTTP listener via `add_tcp` and optionally HTTPS via `add_tls_with_settings`), then `server.add_service(lb_service)` and `server.run_forever()`. There is no in-process listener replacement after `run_forever`.

Pingora itself supports a graceful upgrade path:

`pingora-core/src/server/mod.rs:86-112` — `SIGQUIT`: graceful upgrade; `SIGTERM`: graceful terminate; `SIGINT`: fast shutdown.

`server/mod.rs:189-220` — on `GracefulUpgrade`, listening FDs are sent over `upgrade_sock` to the new process; the old process drains for `CLOSE_TIMEOUT` then gracefully shuts down. So the supported "reload" model is process-replacement with FD passing, not in-process cert swap.

---

## 2) Consul integration

### 2.1 Client model

`src/consul/client.rs:13-32` (`ConsulConfig`) carries:
- `address`, `scheme`, `token`
- `kv_prefix` (currently a single, route-oriented prefix)
- `tag_prefix`
- `allow_stale`, `require_consistent`
- `query_wait` (blocking wait duration)

`src/consul/client.rs:172-180` builds the underlying `reqwest::Client`:
```rust
let http_timeout = query_wait + Duration::from_secs(10);

let client = Client::builder()
    .timeout(http_timeout)
    .connect_timeout(Duration::from_secs(10))
    .build()
    ...
```
i.e. blocking wait + 10s slack — this is reused as the global HTTP timeout for all Consul calls.

### 2.2 KV blocking watch

`src/consul/client.rs:90-119` (`kv_watch_url`):
```rust
fn kv_watch_url(&self, path: &str, index: u64) -> Result<Url, ConsulError> {
    let mut url = Url::parse(&format!(
        "{}/v1/kv/{}",
        self.base_url,
        path.trim_start_matches('/')
    ))
    ...
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("recurse", "true");
        if self.config.allow_stale {
            query.append_pair("stale", "true");
        }
        if self.config.require_consistent {
            query.append_pair("consistent", "true");
        }
        if index > 0 {
            query.append_pair("index", &index.to_string());
            query.append_pair("wait", &self.config.query_wait);
        }
    }
    Ok(url)
}
```

`src/consul/client.rs:191-263` (`watch_kv`):
- sends a single GET to `/v1/kv/<prefix>?recurse=true[&index=...&wait=...]`
- reads `X-Consul-Index` header for the next blocking index
- decodes `Value` (base64) and concatenates entries with `# --- <key>` separators (Fabio-style for routes):
```rust
for kv in kv_pairs {
    let raw_value = kv.Value.unwrap_or_default();
    ...
    let decoded = match STANDARD.decode(raw_value.trim()) { ... };
    let decoded_text = match String::from_utf8(decoded) { ... };
    ...
    parts.push(format!("# --- {}\n{}", kv.Key, trimmed));
}
```
Returns `(Option<String>, u64)` where the string is the merged blob.

`src/consul/client.rs:319-339` (`list_keys`) returns just the keys under a prefix (`?keys=true`), useful for enumerating cert keys per domain.

There is also a per-key (non-recursive) read pattern available — the URL builder supports any path, but the current implementation always sets `recurse=true` in `kv_watch_url`. There is **no** dedicated single-key read helper.

### 2.3 KV watcher loop

`src/consul/watcher.rs:289-321` (`KVWatcher::watch`):
```rust
pub async fn watch(&self, updates: mpsc::Sender<RouteUpdate>) {
    let mut last_index: u64 = 0;
    let kv_path = self.config.kv_prefix.clone();
    let mut backoff_secs: u64 = 1;

    loop {
        match self.client.watch_kv(&kv_path, last_index).await {
            Ok((value, new_index)) => {
                backoff_secs = 1;
                if new_index != last_index {
                    last_index = new_index;
                    let update = RouteUpdate::Manual(value.unwrap_or_default());
                    if updates.send(update).await.is_err() {
                        tracing::warn!("KV watcher: channel closed, stopping");
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(backoff_secs, error = %e, "Consul KV error; retrying");
                let _ = updates.send(RouteUpdate::Error(e.to_string())).await;
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }
}
```
Properties:
- single prefix only
- uses blocking-query `index` correctly (passes back the response's `X-Consul-Index`)
- exponential backoff on errors, capped at 60s
- emits a single `RouteUpdate::Manual(String)` event with the merged blob
- only one prefix is watched → adding a second independent prefix (e.g. `/fabio/cert`) means a new watcher instance, not a parameter on this one

### 2.4 Update enum and combined watcher

`src/consul/watcher.rs:9-18`:
```rust
pub enum RouteUpdate {
    Services(Vec<RouteDef>),
    Manual(String),
    Error(String),
}
```
Today this enum is the only signal channel from Consul to the rest of the process. Cert updates have no representation in it.

`src/consul/watcher.rs:333-380` (`ConsulWatcher::run`) spawns one `ServiceMonitor::watch` task and one `KVWatcher::watch` task into `tokio::spawn`, gated by `service_discovery_enabled` / `kv_watching_enabled` flags. There is no third slot for cert watching.

### 2.5 Reusability for cert KV

What's directly reusable for `/fabio/cert/*` ingestion:
- `ConsulClient::list_keys(prefix)` — enumerate `fabio/cert/*.pem` (returns Vec<String>).
- `ConsulClient::watch_kv(path, index)` — recursive blocking watch with `X-Consul-Index` and base64 decode.
- The blocking-query backoff pattern in `KVWatcher::watch`.
- The HTTP client and ACL token plumbing.

What isn't: the current `watch_kv` decodes UTF-8 and concatenates with `# --- <key>` separators (good for route command files; OK but not ideal for binary PEM bundles since PEM is ASCII anyway, but the per-key identification is lost in the merged blob form). For cert ingestion you want **per-key** values keyed by domain, not a merged blob.

---

## 3) Route table lifecycle and the ArcSwap pattern

### 3.1 Hot-path snapshot via `arc_swap`

`src/route/table.rs:460-486`:
```rust
pub struct RouteTable {
    inner: ArcSwap<Table>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self { inner: ArcSwap::from(Arc::new(Table::new())) }
    }

    pub fn get(&self) -> Arc<Table> {
        self.inner.load_full()
    }

    pub fn swap(&self, table: Table) {
        let route_count = table.route_count();
        let target_count = table.target_count();
        self.inner.store(Arc::new(table));
        ...
    }
}
```

This is the project's canonical "build new snapshot, atomic swap, drain old via Arc refcount" pattern.

### 3.2 Multi-source merge with a `Mutex`-serialised writer

`src/route/registry.rs:55-138` (`ManagedRouteTable`):
- holds:
  - `inner: RouteTable` (the swap target)
  - `registry: ArcSwap<RouteRegistry>` (per-source state)
  - `update_lock: Mutex<()>` (serialises writers; readers don't take it)
- exposes `load_static`, `update_kv`, `update_services`
- each updater clones the current registry, mutates one source slice, then `rebuild_and_swap`:
```rust
fn rebuild_and_swap(&self, registry: &RouteRegistry) {
    let all_defs = registry.get_all();
    let table = Table::from_definitions(&all_defs);
    let route_count = table.route_count();
    let target_count = table.target_count();
    self.registry.store(Arc::new(registry.clone()));
    self.inner.swap(table);
    ...
}
```

Tests in `registry.rs:175-209` ("preserves_static_routes_when_kv_updates_arrive", "preserves_kv_routes_when_service_updates_arrive") confirm the design intent: each source can update independently without clobbering others.

### 3.3 Applicability to a CertStore

A cert store mirroring this shape would carry:
- a hot-path snapshot (`ArcSwap<CertStoreSnapshot>`) that maps SNI → cert+key (and an optional default)
- a writer that serialises updates with a small mutex
- updaters that ingest a Consul KV snapshot (set of `(domain, pem_bundle)`) and rebuild

There is no reason this pattern wouldn't work for certs in isolation — the missing piece is the consumer: pingora-core/rustls does not expose a public hook that reads from such a store at TLS-handshake time (see section 1.2).

---

## 4) Listener lifecycle

### 4.1 How the TLS listener is constructed

`src/main.rs:267-323` summary:
1. Build `ManagedRouteTable`, possibly load static routes.
2. Build `pingora::server::Server` and call `server.bootstrap()`.
3. Build `SentirumProxy` handler and `pingora::proxy::http_proxy_service(&server.configuration, proxy_handler)`.
4. Configure h2c on the plaintext app via `app.server_options`.
5. `lb_service.add_tcp(&config.server.listen)` → HTTP listener.
6. If TLS configured: `TlsSettings::intermediate(cert, key)` → `settings.enable_h2()` → `lb_service.add_tls_with_settings(&tls_listen, None, settings)`.
7. `server.add_service(lb_service)`, then `server.add_service(consul_service)`, `server.add_service(admin_service)`.
8. `server.run_forever()`.

`pingora-core/src/services/listening.rs:78-110` — once `add_tcp`/`add_tls_with_settings` is called, a `TransportStackBuilder` is appended to `Listeners`. `TransportStackBuilder::build` (`listeners/mod.rs:60-79`) is invoked once per listener at service start; the resulting `TransportStack` holds an `Option<Arc<Acceptor>>` cloned per-connection. There is no `replace_acceptor` API.

`pingora-core/src/services/listening.rs` comment says verbatim:
> the follow add* function has no effect if the server is already started.

So adding listeners after `run_forever` is not supported.

### 4.2 Rotating cert without dropping HTTP

Without a fork:
- The HTTPS listener cannot be rebuilt in place (no public API).
- The HTTP listener is independent of the HTTPS listener (separate `add_tcp` and `add_tls_with_settings`), so an HTTPS-listener-only restart would not touch the HTTP path; but you cannot do a "just HTTPS" restart inside the same process either.
- Process-level `SIGQUIT` graceful upgrade rebuilds both listeners but inherits FDs, so listening sockets aren't dropped from the network's perspective. New connections after the swap use the new cert.

With a fork: pingora-core can be modified to (a) accept a `rustls::ServerConfig` directly, or (b) accept an `Arc<dyn rustls::server::ResolvesServerCert>`, both feeding `Acceptor::acceptor`. The resolver is the cleanest match because it is consulted per-handshake against the ClientHello SNI, and `Arc<dyn ResolvesServerCert>` already supports concurrent reads with internal interior mutability (e.g. an `ArcSwap<CertStoreSnapshot>`).

### 4.3 Service ordering vs. cert availability

`src/main.rs:325-344` — the Consul background service is registered after the proxy service, but Pingora services run concurrently from `run_forever`. Today, the TLS listener is only constructed once at startup, so a missing/empty `tls.cert_path` at process boot disables TLS entirely (`src/proxy/tls.rs:50-58` returns `None`). The Consul cert source has no chance to feed the listener if it starts later. This is structural, not a bug: there's no current path to "lazy-build" the listener.

---

## 5) Admin / observability surfaces relevant to TLS

`src/admin/api.rs:35-49` builds the router:
```rust
let protected = Router::new()
    .route("/admin/health", get(health_handler))
    .route("/admin/routes", get(routes_handler))
    .route("/admin/metrics", get(metrics_handler))
    .route("/admin/config", get(config_handler));
```

`src/admin/api.rs:113-141` (`config_handler`) emits server/consul/proxy fields. Verbatim:
```rust
async fn config_handler(State(state): State<AdminState>) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "server": { "listen": ..., "admin_listen": ..., "workers": ... },
        "consul": { "address": ..., "scheme": ..., "kv_prefix": ..., "tag_prefix": ... },
        "proxy":  { "strategy": ..., "matcher": ..., ..., "max_connections": ... },
    }))
}
```
No `tls.*` block, no `trusted_proxies`, no cert source diagnostics.

Auth guard (`api.rs:144-170`): admin token is required if set; otherwise non-loopback bind is refused. Token check accepts `Authorization: Bearer <token>` or `X-Admin-Token: <token>` (api.rs:175-205).

Metrics (`src/metrics/prometheus.rs:18-67`) cover requests, status, latency buckets, route/target counts. No TLS-specific gauges (cert count, last reload, parse errors) exist.

There is no `/admin/certs` endpoint and no `last_cert_reload_at` style gauge.

---

## 6) Specific gaps to fill

These are the discovered gaps relative to the goal. They are listed to scope the next planning step; this section deliberately does not propose a chosen approach.

### 6.1 Cert source gap (rustls feature ceiling)
- pingora-core 0.5.0 with `rustls` feature exposes only `TlsSettings::intermediate(cert_path, key_path)`. No `ResolvesServerCert` injection, no `ServerConfig` injection, no per-handshake callback.
- `with_callbacks()` is a hard error in rustls mode (`pingora-core/src/listeners/tls/rustls/mod.rs:99-106`).
- No public way to mutate `Acceptor::acceptor` after build.
- Implication: a "natively dynamic" rustls TLS path requires either (a) an upstream/forked pingora-core change, (b) a switch of the `pingora` feature flag from `rustls` to one of `openssl_derived`/`boringssl` (which already supports `TlsAccept::certificate_callback`), or (c) external orchestration via files+`SIGQUIT` graceful upgrade.

### 6.2 SNI multi-cert selection gap
- Today's cert config (`TlsCertConfig`) is a single `(cert_path, key_path)` pair. There is no domain → cert map.
- `proxy/handler.rs:777-780` already deals with **upstream** SNI per request, but the **downstream** SNI (for picking which cert to present) is decided inside pingora-core's hidden `Acceptor` and is not surfaced to the application layer.

### 6.3 Hot-reload signal gap
- No code path emits a "certificates changed" event. `RouteUpdate` (`consul/watcher.rs:9-18`) carries only `Services | Manual | Error`.
- The current `KVWatcher` is hard-bound to `config.kv_prefix` and `RouteUpdate::Manual`. A second watcher (cert prefix) is not modeled.
- No `CertStore` analogue of `ManagedRouteTable` exists.

### 6.4 KV layout gap (Fabio compatibility)
- Existing live KV layout (confirmed earlier this session): keys under `fabio/cert/<domain>.pem`, each value is a single base64-encoded **bundle PEM** containing leaf cert + chain + EC PRIVATE KEY.
- `pingora_rustls::load_certs_and_key_files` (`/tmp/pingora-src/pingora-rustls/src/lib.rs:99-128`) takes **two file paths** and splits items by `Item::X509Certificate` vs `Item::Pkcs1Key | Pkcs8Key | Sec1Key`. It cannot consume an in-memory bundle.
- For dynamic ingestion you need an in-memory equivalent: read the PEM bundle from KV, pass it through `rustls_pemfile::read_all`, partition into certs + keys, and feed `with_single_cert` (or a custom `CertifiedKey`) — this is exactly what `pingora-rustls` does internally but the helper is path-only.

### 6.5 Fail-safe gap
- `TlsSettings::build` (`pingora-core/src/listeners/tls/rustls/mod.rs:51-56`) **panics** on bad cert/key files at startup. Therefore today, a corrupt cert file at boot kills the process.
- Live-reload semantics on a bad KV write are undefined; there is no validate-before-swap layer because there is no swap layer.
- Validate-before-swap is naturally expressible with the same Mutex+ArcSwap pattern from `ManagedRouteTable`, but only if a swappable cert store exists.

### 6.6 Listener wiring gap
- TLS listener is only added at startup; HTTP listener is on the same `lb_service`. There is no separation that would let HTTPS rebuild without HTTP also rebuilding.
- Pingora's supported "reload" is process-level graceful upgrade via SIGQUIT, which keeps the listening sockets alive across process boundaries but does not provide an in-process refresh.

### 6.7 Observability gap
- `/admin/config` does not surface `tls.*` fields or `proxy.trusted_proxies`.
- No `/admin/certs` (number of certs, domains, hashes, last reload, parse errors).
- Metrics have no cert-related counters/gauges.

### 6.8 Configuration model gap
- `TlsConfig` only models `cert_path | key_path | listen`. There is no `source = file | consul_kv` discriminator, no `kv_prefix`, no reload-policy field.
- `ConsulConfig` has a single `kv_prefix` (`src/config.rs:47-48`) used for routes; cert prefix would need to be a separate field, not a re-use.

---

## File index used in this analysis

Local repo:
- `Cargo.toml`
- `Cargo.lock` (versions only)
- `src/main.rs` (esp. lines 95-200, 265-345)
- `src/config.rs` (esp. lines 35-72, 113-145, 194-202)
- `src/proxy/tls.rs` (whole file)
- `src/proxy/handler.rs` (lines 200-260, 690-790, 791-855)
- `src/proxy/tcp.rs` (whole file)
- `src/consul/client.rs` (esp. lines 13-82, 90-265, 267-340)
- `src/consul/watcher.rs` (esp. lines 9-18, 222-290, 289-380)
- `src/route/table.rs` (esp. lines 460-495)
- `src/route/registry.rs` (whole file)
- `src/route/target.rs` (lines 1-110)
- `src/admin/api.rs` (esp. lines 35-49, 113-170)
- `src/metrics/prometheus.rs` (lines 1-80)

Pingora 0.5.0 source (cloned `/tmp/pingora-src`, tag `0.5.0`):
- `pingora-core/src/listeners/mod.rs`
- `pingora-core/src/listeners/tls/mod.rs`
- `pingora-core/src/listeners/tls/rustls/mod.rs`
- `pingora-core/src/listeners/tls/boringssl_openssl/mod.rs`
- `pingora-core/src/protocols/tls/rustls/server.rs`
- `pingora-core/src/services/listening.rs`
- `pingora-core/src/server/mod.rs`
- `pingora-rustls/src/lib.rs`

External evidence (web):
- pingora issue #594 — proposed `intermediate_bundle` + `ResolvesServerCertUsingSni` (not merged at time of writing).
- pingora-core 0.5.0 example `pingora/examples/server.rs` — `with_callbacks(dynamic_cert)` only under non-rustls features.

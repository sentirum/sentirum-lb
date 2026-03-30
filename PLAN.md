# Sentirum LB — Rust-Based Consul-Integrated Load Balancer

## Context

Fabio LB (Go, ~22K LOC, eBay) stagnant durumda. Consul KV ile native entegre, hafif ve yüksek performanslı bir Rust alternatifi yazmak isteniyor. Fabio'dan esinlenilecek ama gereksiz komplekslik (BGP, gRPC proxy, admin UI vb.) dahil edilmeyecek.

### Neden Rust?
- Zero-cost abstractions, no GC pauses
- Bellek güvenliği (memory safety)
- Cloudflare Pingora ile kanıtlanmış performans (40M+ req/sec)
- Düşük binary boyutu (<10MB), düşük RAM (<20MB idle)
- Rust ekosisteminde Consul-entegre LB yok — boş niş

## Approach

Fabio'nun çekirdek mimarisinden esinlenerek, **Pingora framework'ü üzerine** inşa edilecek. Hyper+Tokio ile sıfırdan yazmak yerine Pingora'nın olgun HTTP proxy altyapısını kullanıp, üzerine Consul entegrasyonu ve dinamik routing katmanı eklenecek.

### Mimari Akış (Fabio'dan esinlenme)

```
┌─────────────────────────────────────────────────────┐
│                   Sentirum LB                       │
│                                                     │
│  ┌──────────────┐    ┌──────────────────────────┐  │
│  │ Consul Watch │───>│    Route Table (RwLock)   │  │
│  │              │    │  HashMap<Host, Routes>    │  │
│  │ • KV watch   │    │  ├─ Route { path, targets}│  │
│  │ • Health API │    │  └─ Target { url, weight} │  │
│  │ • Catalog API│    └──────────┬───────────────┘  │
│  └──────────────┘               │                   │
│                                  ▼                   │
│  ┌──────────────────────────────────────────────┐   │
│  │           Pingora Proxy Service               │   │
│  │  Request → Lookup(Host+Path) → Proxy → Resp  │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Fabio ile Kıyaslama

| Özellik | Fabio (Go) | Sentirum LB (Rust) |
|---|---|---|
| Dil | Go | Rust |
| Framework | net/http + httputil.ReverseProxy | Pingora (Cloudflare) |
| Consul KV Watch | Blocking queries (long-poll) | Blocking queries (reqwest) |
| Consul Health | Health API watch | Health API watch |
| Route Table | atomic.Value + sync | RwLock + Arc (lock-free reads) |
| Route Format | `route add svc src dst` | Aynı format (backward compat) |
| Service Tags | `urlprefix-/` prefix | `urlprefix-/` prefix (aynı) |
| LB Algoritmaları | rnd, rr | Round-robin, weighted, random, least-connections |
| Matchers | prefix, glob, iprefix | prefix, glob |
| TLS |自成Cert manager | rustls / native-tls |
| Boyut | ~30MB binary | <10MB binary hedef |
| Bağımlılıklar | 50+ Go modülü | Minimal Rust crate'ler |

## Crates & Dependencies

```toml
[dependencies]
# Proxy framework
pingora = "0.5"
pingora-proxy = "0.5"
pingora-load-balancing = "0.5"
pingora-core = "0.5"

# Async runtime
tokio = { version = "1", features = ["full"] }

# HTTP client (Consul API)
reqwest = { version = "0.12", features = ["rustls-tls", "json"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# CLI & Config
clap = { version = "4", features = ["derive"] }
toml = "0.8"

# Glob matching
glob = "0.3"

# Metrics (Phase 4)
prometheus = "0.13"
```

## Project Structure

```
sentirum-lb/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── config.toml                  # Default config
├── src/
│   ├── main.rs                  # Entry point, CLI, server startup
│   ├── config.rs                # Configuration parsing (TOML)
│   ├── consul/
│   │   ├── mod.rs               # Consul module
│   │   ├── client.rs            # Consul HTTP client (KV, Health, Catalog)
│   │   ├── watcher.rs           # Blocking query watcher (KV + Health)
│   │   └── discovery.rs         # Service discovery from Consul Catalog
│   ├── route/
│   │   ├── mod.rs               # Route module
│   │   ├── table.rs             # Thread-safe routing table (RwLock<Arc<Table>>)
│   │   ├── definition.rs        # Route definition (service, src, dst, weight)
│   │   ├── target.rs            # Target (URL, weight, tags, opts)
│   │   ├── parser.rs            # Route command parser (Fabio-compatible)
│   │   ├── matcher.rs           # Path matchers (prefix, glob)
│   │   └── picker.rs            # Target selection (rr, weighted, rnd, least-conn)
│   ├── proxy/
│   │   ├── mod.rs               # Proxy module
│   │   ├── handler.rs           # Pingora ProxyHttp trait impl
│   │   ├── http.rs              # HTTP proxy logic
│   │   └── tls.rs               # TLS termination (Phase 3)
│   ├── metrics/
│   │   ├── mod.rs               # Metrics module
│   │   └── prometheus.rs        # Prometheus metrics (Phase 4)
│   └── admin/
│       ├── mod.rs               # Admin module
│       └── api.rs               # Admin API + routes view (Phase 4)
```

## Implementation Steps

### Phase 1: Temel Proxy + Statik Routing (1 hafta)

- [ ] **1.1** Proje iskeletini oluştur — `cargo init`, Cargo.toml, modül yapısı
- [ ] **1.2** `config.rs` — TOML tabanlı konfigürasyon (listen addr, consul addr, tag prefix, picker strategy)
- [ ] **1.3** `route/definition.rs` — Route/Target struct'ları (Fabio'nun RouteDef/Target'ından esinlenme)
- [ ] **1.4** `route/parser.rs` — `route add <svc> <src> <dst>` komut parser'ı (Fabio-compatible)
- [ ] **1.5** `route/table.rs` — Thread-safe routing table: `RwLock<Arc<Table>>` where `Table = HashMap<String, Routes>`
  - Fabio referansı: `route/table.go` — `atomic.Value` ile lock-free read
  - Rust'ta: `arc_swap::ArcSwap<Table>` ile lock-free swap (daha iyi)
- [ ] **1.6** `route/matcher.rs` — Prefix ve glob matcher'lar
- [ ] **1.7** `route/picker.rs` — Round-robin ve weighted-random picker
- [ ] **1.8** `proxy/handler.rs` — Pingora `ProxyHttp` trait implementation
  - `upstream_peer()` — Route table'dan target lookup, picker ile seçim
  - `upstream_request_filter()` — Header manipulation
- [ ] **1.9** `main.rs` — CLI (clap), config yükleme, statik route dosyası okuma, Pingora server başlatma
- [ ] **1.10** Test: curl ile statik routing doğrulama

### Phase 2: Consul Entegrasyonu (1 hafta)

- [ ] **2.1** `consul/client.rs` — Consul HTTP client
  - KV: `GET /v1/kv/{prefix}` (blocking query with `?index=` & `?wait=`)
  - Health: `GET /v1/health/state/any` (blocking query)
  - Catalog: `GET /v1/catalog/service/{name}`
  - Referans: Fabio `registry/consul/kv.go` + `service.go`
- [ ] **2.2** `consul/watcher.rs` — Blocking query watcher
  - KV watcher: KV prefix'ini izle, değişiklik olunca route parser'a gönder
  - Health watcher: Health state'i izle, passing service'leri belirle
  - Fabio referansı: `watchKV()` ve `ServiceMonitor.Watch()`
- [ ] **2.3** `consul/discovery.rs` — Service discovery
  - Consul Catalog'tan service'leri çek
  - `urlprefix-` tag'lerinden route'ları oluştur
  - Health check durumuna göre filtrele
  - Fabio referansı: `routecmd.build()` + `passingServices()`
- [ ] **2.4** Route table'ı Consul watcher'dan dinamik güncelle
  - `ArcSwap<Table>` ile atomic swap
  - Eski route'ları temizle, yeni route'ları yükle
- [ ] **2.5** Config: Consul adres, KV prefix, tag prefix, poll interval ayarları
- [ ] **2.6** Integration test: Consul container + test servisleri + routing doğrulama

### Phase 3: TLS + Production Hardening (1 hafta)

- [ ] **3.1** `proxy/tls.rs` — TLS termination (rustls)
  - SNI-based certificate selection
  - Auto-reload certificates on change
- [ ] **3.2** Graceful shutdown — SIGTERM handling, drain connections
- [ ] **3.3** Connection pooling — Hyper/Pingora connection pool tuning
- [ ] **3.4** Timeouts — Connect, read, write, idle timeout konfigürasyonu
- [ ] **3.5** Access logging — structured JSON logging (tracing)
- [ ] **3.6** Error handling — Proper 502, 503, 504 responses
- [ ] **3.7** Health check endpoint — `/health` endpoint for Sentirum LB itself

### Phase 4: Observability + Admin (istediği kadar)

- [ ] **4.1** `metrics/prometheus.rs` — Request latency histogram, request counter, active connections gauge
- [ ] **4.2** `admin/api.rs` — Minimal admin API
  - `GET /admin/routes` — Aktif routing tablosunu göster
  - `GET /admin/stats` — Basit istatistikler
- [ ] **4.3** Least-connections picker ekle
- [ ] **4.4** WebSocket proxy desteği
- [ ] **4.5** TCP proxy (Phase 5'e kadar ertelenebilir)

## Configuration Format

```toml
# sentirum-lb config.toml

[server]
listen = ":9999"          # Proxy listen address
admin_listen = ":9998"    # Admin API listen address
workers = 0               # 0 = auto (num_cpus)

[consul]
address = "127.0.0.1:8500"
scheme = "http"
token = ""                # ACL token (optional)
kv_prefix = "/fabio"      # KV prefix for route commands
tag_prefix = "urlprefix-" # Service tag prefix
poll_interval = "3s"      # Health poll interval (0 = blocking query)

[proxy]
strategy = "round-robin"  # round-robin | weighted-random | least-connections
matcher = "prefix"        # prefix | glob
request_id_header = "X-Request-ID"
no_route_status = 404
connect_timeout = "5s"
read_timeout = "30s"
write_timeout = "30s"
idle_timeout = "120s"

[logging]
level = "info"            # trace | debug | info | warn | error
format = "json"           # json | text

[tls]
cert_path = ""
key_path = ""
```

## Key Design Decisions

1. **Pingora over raw Hyper**: Pingora connection pooling, graceful upgrade, HTTP/2 desteği hazır geliyor. Hyper ile sıfırdan yazmaktan çok daha az efor.

2. **Fabio-compatible route format**: `route add svc src dst` formatı korunacak. Mevcut Consul KV'deki Fabio route'ları direkt çalışacak.

3. **`urlprefix-` tag convention**: Fabio'nun tag konvensiyonu aynı kalacak (`urlprefix-/myservice`). Geçiş Fabio'dan Sentirum LB'ye sorunsuz olacak.

4. **ArcSwap<Table>**: Fabio `atomic.Value` kullanıyor. Rust'ta `arc_swap` crate'i ile aynı lock-free swap pattern'i elde ediyoruz. Read'ler tamamen lock-free.

5. **Blocking queries**: Consul'un blocking query mekanizmasını doğrudan kullanacağız (long-polling). WebSocket/SSE yerine, Fabio'nun da kullandığı aynı yaklaşım.

6. **Phase-based delivery**: Her phase çalışan bir deliverable üretir. Phase 1 sonunda statik routing çalışır, Phase 2 sonunda Consul dinamik routing çalışır.

## Verification

### Phase 1 Test
```bash
# Statik route dosyası ile test
echo 'route add myservice myhost.com/ http://127.0.0.1:8080/' > routes.txt
cargo run -- -c config.toml -r routes.txt
curl -H "Host: myhost.com" http://127.0.0.1:9999/
```

### Phase 2 Test
```bash
# Consul + servis başlat
docker run -d --name consul -p 8500:8500 hashicorp/consul agent -dev
# Servis kaydet
curl -X PUT http://localhost:8500/v1/kv/fabio/routes -d 'route add myservice myhost.com/ http://127.0.0.1:8080/'
# Test
curl -H "Host: myhost.com" http://127.0.0.1:9999/
```

### Benchmark
```bash
wrk -t4 -c100 -d30s http://127.0.0.1:9999/
# Hedef: Fabio'dan en az %20 daha iyi throughput ve tail latency
```

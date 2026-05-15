# 🔍 Sentirum LB — Tam Kapsamlı Deep Code Review Raporu

**Tarih:** 2025-05-15  
**Kapsam:** ~17.800 satır Rust kodu, 45+ dosya  
**İnceleyen:** MiMo (Xiaomi MiMo Team)

---

## 🔴 P0 — Kritik Bug'lar & Race Condition'lar

### 1. TCP Proxy — `rr_counter` Type Tutarsızlığı

**Dosya:** `src/proxy/tcp.rs` satır 497, 513  
**Tür:** API tutarlılığı

`rr_counter` `Arc<AtomicU64>` olarak değiştirildi ama TCP proxy hâlâ `&route.rr_counter` kullanıyor. Rust auto-deref sayesinde compile ediyor ama tutarlılık açısından `route.rr_counter.as_ref()` kullanılmalı:

```rust
// Mevcut (tcp.rs:497):
&route.rr_counter,
// Olması gereken:
route.rr_counter.as_ref(),
```

**Risk:** Düşük — çalışıyor ama inconsistent API kullanımı.  
**Öneri:** Tüm `pick_target_by_strategy` çağrılarında `route.rr_counter.as_ref()` kullanmak.

---

### 2. Prometheus Metrics — Histogram Bucket Race Condition

**Dosya:** `src/metrics/prometheus.rs` — `record_request()`  
**Tür:** Data tutarsızlığı

Her bucket ayrı bir `AtomicU64`. Prometheus histogram formatında bucket'lar **kümülatif** olmalı. `render()` anında snapshot aldığında, iki thread farklı bucket'lara yazdığında **tutarlı olmayan toplamlar** görünebilir:

```rust
// Thread A: latency_bucket_1ms += 1
// Thread B: latency_bucket_5ms += 1
// render() arada çağrılırsa: _count = 2 ama _bucket{le="+Inf"} = 1
```

**Etki:** Prometheus scrape'lerinde nadiren anlık tutarsızlık. Grafana aggregation'da anomali görünebilir.  
**Öneri:** `record_request`'ta tüm bucket'ları tek bir `parking_lot::Mutex` ile atomic yapmak, veya mevcut pragmatik yaklaşımı korumak (pratikte yeterli).

---

### 3. DNS Cache — Poisoned Lock Recovery Yetersiz

**Dosya:** `src/route/dns_cache.rs` — `DnsCache`  
**Tür:** Veri bütünlüğü

```rust
let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
```

Poisoned lock'tan kurtuluyor ama **hatalı veriyle devam ediyor**. Bir thread panic etmişse cache'in içeriği yarı-tutarsız olabilir.

**Risk:** Düşük — poisoning nadiren olur ve cache TTL ile kendini düzeltir.  
**Öneri:** Poisoned lock durumunda cache'i temizleyip yeniden başlatmak.

---

### 4. Admin Auth — Login Rate Limit TOCTOU

**Dosya:** `src/admin/auth.rs` — `login_handler`  
**Tür:** Rate limit bypass

`login_attempts` bir `DashMap`. `retain` + `get` + `entry` arasında TOCTOU var:

```
Thread A: retain → entry var, count=4
Thread B: retain → entry var, count=4
Thread A: get → count=4 < 5 → geçer
Thread B: get → count=4 < 5 → geçer
Her ikisi de password check yapar → count=6 (limit 5 olmasına rağmen)
```

**Etki:** Rate limit 5 yerine 6-7 denemeye izin verebilir. Düşük güvenlik riski.  
**Öneri:** `entry` API'sini `get` yerine doğrudan kullanarak atomic increment yapmak:

```rust
let mut entry = state.login_attempts.entry(req.username.clone()).or_insert((0, now));
let (count, window_start) = entry.value_mut();
if now.duration_since(*window_start).as_secs() < LOGIN_WINDOW_SECS && *count >= LOGIN_MAX_ATTEMPTS {
    return rate_limited_response;
}
*count += 1;
```

---

### 5. Admin Auth — Session Cache Race (try_read)

**Dosya:** `src/admin/auth.rs` — `admin_auth_middleware`  
**Tür:** Geçici auth hatası

Query token auth'da `try_read()` kullanılıyor. Write lock tutuluyorsa (login/logout), session doğrulaması **başarısız** sayılıyor:

```rust
if let Ok(sessions) = state.sessions.try_read() {
    sessions.get(&token).is_some()
} else {
    false  // ← login/logout sırasında tüm SSE stream'ler 401 alır
}
```

**Etki:** Kullanıcı deneyimi sorunu — login sırasında dashboard geçici olarak 401 dönebilir.  
**Öneri:** `try_read()` yerine `read().await` kullanmak (async context'te güvenli).

---

### 6. Topology Flow — Mutex Poisoning Panik Riski

**Dosya:** `src/admin/topology_flow.rs`  
**Tür:** Panic propagation

```rust
let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
```

Poisoned lock'tan kurtuluyor ✅ ama bu durumda **hatalı veri** ile devam ediyor. Flow metrics hesaplaması yanlış olabilir.

**Risk:** Düşük — nadiren olur.  
**Öneri:** Poisoned lock durumunda default snapshot döndürmek.

---

## 🟠 P1 — Orta Ciddiyette Sorunlar

### 7. Consul Watcher — Blocking Query Index Reset Loop

**Dosya:** `src/consul/watcher.rs`  
**Tür:** CPU spike

Consul sunucusu restart ettiğinde eski index geçersiz olur ve Consul hemen döner. Watcher index = 0'a reset ediyor ama **backoff uygulamıyor**. Sürekli Consul restart durumunda tight loop'a girebilir.

**Etki:** Consul restart sırasında CPU spike.  
**Öneri:** Index reset'inde kısa bir backoff (1-2 saniye) eklemek:

```rust
if new_index < *index {
    tracing::warn!("Consul index reset; applying backoff");
    tokio::time::sleep(Duration::from_secs(2)).await;
}
```

---

### 8. Dynamic TCP Listener — Stale Cleanup Eksik

**Dosya:** `src/proxy/tcp.rs` — `reconcile_dynamic_listeners`  
**Tür:** Bağlantı kesilmesi

Stale listener shutdown **fire-and-forget**. JoinHandle drop edildiğinde task **abort** edilir ama mevcut TCP bağlantıları **graceful** kapatılmaz.

**Etki:** Route değişikliğinde mevcut TCP bağlantıları aniden kesilebilir (NATS, Redis, vb.).  
**Öneri:** Stale listener'ları bir background task'ta graceful shutdown ile temizlemek:

```rust
tokio::spawn(async move {
    let _ = tokio::time::timeout(Duration::from_secs(30), handle.task).await;
});
```

---

### 9. Health Check — Probe vs CB Senkronizasyon Eksik

**Dosya:** `src/proxy/health.rs` + `src/route/health_tracker.rs`  
**Tür:** Kafa karıştırıcı durum

Active health check probe'ları `set_probe_health()` çağırıyor ama circuit breaker state'i etkilenmiyor. Bir target hem probe unhealthy hem CB closed olabilir.

**Etki:** `lookup_target` doğru ele alıyor (probe check önce) ama logging ve dashboard'da kafa karıştırıcı.  
**Öneri:** Probe unhealthy olduğunda CB'yi de Open yapmak (veya en azından log'da belirtmek).

---

### 10. Metrics Handler — Global Static Task Leak

**Dosya:** `src/admin/metrics_handler.rs`  
**Tür:** Resource leak

```rust
static METRICS_TX: std::sync::OnceLock<tokio::sync::watch::Sender<Arc<String>>> =
    std::sync::OnceLock::new();
```

İlk `/admin/metrics/stream` çağrısında spawn edilen background task **asla sonlanmıyor**. Admin API kapatılsa bile task yaşamaya devam eder (tokio runtime kapanana kadar).

**Etki:** Test'lerde memory leak. Production'da düşük risk (runtime kapanınca temizlenir).  
**Öneri:** Task'ı bir `AbortHandle` ile yönetmek ve admin API shutdown'da abort etmek.

---

### 11. Ring Buffer — Edge Case: CAP = 1

**Dosya:** `src/admin/logs.rs` — `LogBuffer::push`  
**Tür:** Edge case bug

Buffer capacity 1 olduğunda:
```rust
let next_pos = (pos + 1) % RING_BUFFER_CAPACITY; // (0 + 1) % 1 = 0
```

Sürekli aynı index'e yazar — doğru çalışır. Ama `write_pos` hep 0 kalır ve `recent()` hep en son entry'i döndürür. ✅

Aslında bu bir bug değil, ama `RING_BUFFER_CAPACITY` const'ı compile-time'da validate etmek iyi olur:

```rust
const _: () = assert!(RING_BUFFER_CAPACITY > 0, "ring buffer capacity must be > 0");
```

---

### 12. Config Validation — `circuit_breaker_recovery_timeout = 0` Geçersiz

**Dosya:** `src/config/validation.rs`  
**Tür:** Config validation eksik

Validation `circuit_breaker_recovery_timeout == 0` için hata döndürüyor ama test config'lerinde (`test_support.rs`) bu değer 0 olarak ayarlanıyor. Bu, test'lerin validation bypass etmesi gerektiği anlamına geliyor.

**Etki:** Production'da sorun yok ama test config'leri validation'dan geçemiyor.  
**Öneri:** Test config'lerinde geçerli değerler kullanmak (örn: `recovery_timeout: 1`).

---

## 🟡 P2 — Performans Sorunları

### 13. Topology Handler — Her Request'te Full Route Table Scan

**Dosya:** `src/admin/metrics_handler.rs` — `topology_handler`  
**Tür:** CPU kullanımı

Her `/admin/topology` isteğinde:
1. `table.hosts()` → tüm host'ları listele
2. Her host için `table.get_routes(host)` → route'ları al
3. Her route için tüm target'ları iterate et
4. Her target için atomik counter'ları oku
5. `TopologyFlowMetrics::combine()` hesapla

10K target'ta bu **her istekte ~10K atomik load + JSON serialization** demek.

**Etki:** Dashboard'da yüksek QPS'de CPU kullanımı.  
**Öneri:** Topology snapshot'ını 1-2 saniyede bir pre-compute etmek (zaten `TopologyFlowCache` var ama handler hâlâ her seferinde yeniden hesaplıyor).

---

### 14. Prometheus Render — Büyük String Allocation

**Dosya:** `src/metrics/prometheus.rs` — `render_uncached()`  
**Tür:** Bellek kullanımı

`format!()` ile tüm metrics text'i tek bir String'de toplanıyor. 10K target'ta bu **çok büyük** bir String olabilir (her target ~5 satır × 10K = 50K satır).

**Etki:** Her Prometheus scrape'inde büyük memory allocation + deallocation.  
**Öneri:** Streaming output kullanmak (`Write` trait ile) veya chunk'lar halinde render etmek. Mevcut 3 saniyelik cache bu sorunu hafifletiyor.

---

### 15. `all_targets()` Cache — Rebuild'de String Clone

**Dosya:** `src/route/table.rs` — `finalize()`  
**Tür:** Allocation overhead

```rust
if seen.insert(target.url.clone()) {
    targets.push(Arc::clone(target));
}
```

Her target için URL String clone. 10K target'ta ~10K String allocation.

**Öneri:** `seen` set'ini `HashSet<&str>` yaparak clone'u önlemek:

```rust
let mut seen = HashSet::new();
let mut targets = Vec::new();
for target in self.routes.values().flat_map(|r| r.iter()).flat_map(|route| &route.targets) {
    if seen.insert(target.url.as_str()) {
        targets.push(Arc::clone(target));
    }
}
```

---

### 16. `matching_routes` — Her Çağrıda Vec Allocation

**Dosya:** `src/route/table.rs` — `matching_routes()`  
**Tür:** Hot path allocation

Her `lookup_target` çağrısında yeni bir `Vec<&Arc<Route>>` oluşturuluyor.

**Öneri:** Stack-allocated buffer (`SmallVec<[&Arc<Route>; 4]>`) veya iterator-returning yapmak.

---

### 17. Consul Watcher — Full Snapshot Rebuild

**Dosya:** `src/consul/watcher.rs`  
**Tür:** CPU kullanımı

Her Consul service değişikliğinde **tüm** service snapshot yeniden işleniyor. 1000 service'te bu her seferinde 1000 tag parse + route extraction demek.

**Etki:** Consul update sıklığıyla doğru orantılı.  
**Not:** Consul blocking query full snapshot döndüğü için incremental update zor. Mevcut yaklaşım pratikte yeterli.

---

### 18. Access Log — Her Request'te Multiple String Allocation

**Dosya:** `src/proxy/handler/access.rs`  
**Tür:** Hot path allocation

```rust
let status_label = format_status_class(response_status);
let upstream_ip = target_url.rsplit_once('/').map(...).to_string();
```

Her request'te 2+ String allocation.

**Öneri:** `status_label` için static string table kullanmak, `upstream_ip` için `Cow<str>`.

---

## 🔵 P3 — Anti-Pattern'ler & Kod Kalitesi

### 19. `unwrap_or_else(|e| e.into_inner())` Tekrarı

**Dosya:** Tüm proje genelinde ~15 yerde  
**Tür:** DRY ihlali

Bu pattern Mutex poisoning recovery için kullanılıyor. Macro veya yardımcı fonksiyon daha temiz olur:

```rust
macro_rules! recover_lock {
    ($lock:expr) => {
        $lock.unwrap_or_else(|e| {
            tracing::warn!("Lock poisoned; recovering");
            e.into_inner()
        })
    };
}
```

---

### 20. `escape_prometheus_label` Duplikasyonu

**Dosya:** `src/metrics/prometheus.rs` ve `src/admin/metrics_handler.rs`  
**Tür:** DRY ihlali

Aynı fonksiyon iki farklı modülde tanımlı. Tek bir yere taşınmalı:

```rust
// src/metrics/prometheus.rs'de tanımlı, admin/metrics_handler.rs'de de kopyalanmış
pub fn escape_prometheus_label(s: &str) -> String { ... }
```

**Öneri:** `metrics` modülünden export edip admin handler'da kullanmak.

---

### 21. `status_message` Yanlış HTTP Mesajı

**Dosya:** `src/proxy/handler.rs` — `status_message()`  
**Tür:** Yanlış davranış

```rust
fn status_message(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        // ...
        _ => "Service Unavailable",  // ← 429 "Too Many Requests" için yanlış
    }
}
```

429 status code'u "Service Unavailable" yerine "Too Many Requests" olmalı.

**Öneri:** Eksik status code'ları eklemek:

```rust
429 => "Too Many Requests",
504 => "Gateway Timeout",
502 => "Bad Gateway",
```

---

### 22. Manual Percent-Decoding

**Dosya:** `src/admin/auth.rs`  
**Tür:** Güvenlik

Query parameter'dan token okurken manual percent-decoding yapılıyor:

```rust
if b == b'%' {
    let hi = bytes.next().unwrap_or(b'0');  // ← % + EOF → \0
    let lo = bytes.next().unwrap_or(b'0');
}
```

`%` sonrası iki byte eksikse `unwrap_or(b'0')` ile devam ediyor — bu, `%` + EOF durumunda `\0` karakteri ekler.

**Öneri:** `urlencoding::decode()` veya `percent_encoding` crate'i kullanmak.

---

### 23. PEM Parsing Regex Overhead

**Dosya:** `src/proxy/tls/helpers.rs`  
**Tür:** Performans

```rust
static PEM_BEGIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN ([A-Z0-9 ]+)-----").expect("valid PEM regex"));
```

Her PEM parse işleminde regex çalıştırılıyor. Yüksek sertifika sayısında yavaşlayabilir.

**Öneri:** Basit string search (`find("-----BEGIN")`) daha hızlı olabilir. Ama regex daha güvenli.

---

### 24. Consul Client — HTTP Timeout Çok Uzun

**Dosya:** `src/consul/client.rs`  
**Tür:** Kaynak kullanımı

```rust
let http_timeout = query_wait + Duration::from_secs(10);
// Varsayılan: 5 dakika + 10 saniye = 5:10 HTTP timeout
```

Blocking query'lerin doğası gereği bu normal ama connection pool'da uzun süreli bağlantılar birikebilir.

**Risk:** Düşük — Consul blocking query'leri zaten uzun sürer.

---

### 25. Watcher Graceful Shutdown Timeout Sabit

**Dosya:** `src/consul/watcher.rs`  
**Tür:** Konfigürasyon eksikliği

Watcher shutdown'ında `tokio::time::timeout(Duration::from_secs(5), ...)` kullanılıyor. Bu değer config'den gelmiyor.

**Öneri:** `server.drain_timeout` config değerini kullanmak.

---

### 26. `Cow<str>` Kullanımı Az

**Dosya:** `src/route/table.rs`  
**Tür:** Performans

Route table'da host key normalization her seferinde `to_ascii_lowercase()` ile yeni String oluşturuyor. `Cow` ile bu önlenebilir (eğer zaten lowercase ise borrow).

---

### 27. `HashMap` vs `FxHashMap`

**Dosya:** `src/route/table.rs`  
**Tür:** Performans

Route table'da `HashMap<String, Vec<Arc<Route>>>` kullanılıyor. Rust'ın default `HashMap`'i SipHash kullanıyor (DDoS-safe ama yavaş). `rustc-hash`'in `FxHashMap`'i hot path'te daha hızlı olabilir.

**Öneri:** `rustc-hash` dependency ekleyip route table'da `FxHashMap` kullanmak.

---

### 28. `Vec::with_capacity` Kullanımı Eksik

**Dosya:** Çeşitli dosyalar  
**Tür:** Performans

Birçok yerde `Vec::new()` kullanılıyor ama capacity biliniyor. Örneğin:

```rust
// table.rs - matching_routes
let mut results = Vec::new(); // → Vec::with_capacity(route_count)
// prometheus.rs - render_uncached
let mut output = String::new(); // → String::with_capacity(estimated_size)
```

---

### 29. `format!()` Yerine `write!()`

**Dosya:** `src/admin/metrics_handler.rs`  
**Tür:** Performans

Hot path'te `format!()` her seferinde yeni String oluşturuyor. `write!()` ile mevcut buffer'a yazmak daha verimli:

```rust
// Mevcut:
output.push_str(&format!("sentirum_lb_target_requests_total{{...}} {requests}\n"));
// Daha iyi:
use std::fmt::Write;
write!(output, "sentirum_lb_target_requests_total{{...}} {requests}\n").unwrap();
```

---

## 🟢 P4 — Test Coverage Gaps

### 30. Eksik Testler

| Test | Durum | Açıklama |
|------|-------|----------|
| TCP proxy integration | ❌ Yok | Sadece unit test var |
| TLS cert hot-reload async | ❌ Yok | File watcher async davranışı test edilmemiş |
| Dynamic TCP listener reconciliation | ❌ Yok | Port ekleme/çıkarma senaryoları |
| Rate limit per-target override | ❌ Yok | `ratelimit=X burst=Y` opts |
| gRPC-Web bridging | ⚠️ Ignored | Integration test ignored |
| WebSocket upgrade | ⚠️ Ignored | Integration test ignored |
| Header matching fallback | ❌ Yok | Yeni eklenen `matching_routes` davranışı |
| CB TOCTOU inline fallback | ❌ Yok | Yeni eklenen fallback davranışı |
| Login rate limit edge cases | ❌ Yok | Concurrent login, window expiry |
| Session eviction overflow | ❌ Yok | `SESSION_MAX_CAPACITY` aşıldığında |

---

## 📊 Özet Tablo

| # | Sorun | Seviye | Dosya | Etki | Çözüm Zorluğu |
|---|-------|--------|-------|------|----------------|
| 1 | TCP rr_counter tutarsızlığı | P0 | tcp.rs | API tutarlılığı | Kolay |
| 2 | Histogram bucket race | P0 | prometheus.rs | Nadiren tutarsız metrics | Orta |
| 3 | DNS cache poisoned lock | P0 | dns_cache.rs | Düşük risk | Kolay |
| 4 | Login rate limit TOCTOU | P0 | auth.rs | Rate limit bypass | Kolay |
| 5 | Session try_read race | P0 | auth.rs | Geçici 401 | Kolay |
| 6 | Topology flow mutex | P0 | topology_flow.rs | Düşük risk | Kolay |
| 7 | Consul watcher tight loop | P1 | watcher.rs | CPU spike | Kolay |
| 8 | Dynamic TCP stale cleanup | P1 | tcp.rs | Bağlantı kesilmesi | Orta |
| 9 | Health probe vs CB sync | P1 | health.rs | Kafa karıştırıcı log | Orta |
| 10 | Metrics handler task leak | P1 | metrics_handler.rs | Test memory leak | Kolay |
| 11 | Ring buffer CAP=1 | P1 | logs.rs | Edge case | Kolay |
| 12 | CB recovery_timeout=0 | P1 | validation.rs | Test config | Kolay |
| 13 | Topology full scan | P2 | metrics_handler.rs | CPU kullanımı | Orta |
| 14 | Prometheus render alloc | P2 | prometheus.rs | Bellek kullanımı | Orta |
| 15 | all_targets String clone | P2 | table.rs | Rebuild overhead | Kolay |
| 16 | matching_routes Vec alloc | P2 | table.rs | Hot path allocation | Kolay |
| 17 | Consul full snapshot | P2 | watcher.rs | CPU kullanımı | Zor |
| 18 | Access log alloc | P2 | access.rs | Hot path allocation | Kolay |
| 19 | unwrap_or_else tekrarı | P3 | genel | DRY ihlali | Kolay |
| 20 | escape_prometheus dup | P3 | metrics/ | DRY ihlali | Kolay |
| 21 | status_message 429 | P3 | handler.rs | Yanlış HTTP mesaj | Kolay |
| 22 | Manual percent-decode | P3 | auth.rs | Güvenlik | Kolay |
| 23 | PEM regex overhead | P3 | helpers.rs | Performans | Kolay |
| 24 | HTTP timeout uzun | P3 | client.rs | Kaynak kullanımı | Kolay |
| 25 | Shutdown timeout sabit | P3 | watcher.rs | Konfigürasyon | Kolay |
| 26 | Cow kullanımı az | P3 | table.rs | Performans | Kolay |
| 27 | HashMap vs FxHashMap | P3 | table.rs | Performans | Kolay |
| 28 | with_capacity eksik | P3 | çeşitli | Performans | Kolay |
| 29 | format! vs write! | P3 | metrics_handler.rs | Performans | Kolay |
| 30 | Test coverage gaps | P3 | çeşitli | Bakım riski | Orta |

---

## 🏆 İyi Tasarım Kararları

1. **`ArcSwap` ile lock-free route table okuma** — Hot path'te sıfır lock contention
2. **Circuit breaker atomic state encoding** — Tek u8'de state + probe counter
3. **Monotonic time** — NTP'den etkilenmeyen `Instant`-tabanlı zamanlama
4. **SSRF koruması multi-layer** — Host check, DNS resolution check, cache hit check
5. **Token bucket rate limiting** — Mutex ile refill+consume atomik
6. **Stats/health tracker Arc paylaşımı** — Route rebuild'lerde state kaybı yok
7. **Weak reference registry** — Target'lar route table'dan çıktığında memory leak yok
8. **DNS negative caching** — NXDOMAIN sonuçları da cache'leniyor
9. **Graceful shutdown** — Tüm watcher'lar ve TCP listener'lar shutdown signal ile sonlanıyor
10. **Comprehensive metrics** — 40+ Prometheus metric, topology flow, per-target stats
11. **Hot-reloadable config** — Runtime'da strategy, matcher, timeouts, CB, rate limit değiştirilebilir
12. **Fabio-compatible route format** — Mevcut Fabio kullanıcıları için kolay geçiş

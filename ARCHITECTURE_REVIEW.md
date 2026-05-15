# 🏗️ Sentirum LB — Kapsamlı Mimari Analiz Raporu

**Tarih:** 2025-05-15
**Kapsam:** ~17.800 satır Rust, tüm modüller
**Metod:** Kaynak kodun satır satır okunması, data flow analizi, race condition analizi, performans profilleme

---

## 1. Mimari Genel Değerlendirme

Sentirum LB, Fabio'dan ilham alan bir HTTP/TCP load balancer. Pingora framework'ü üzerine inşa edilmiş. Genel mimari **sağlam ve iyi düşünülmüş**. Temel tasarım kararları (ArcSwap ile lock-free okuma, immutable route table snapshot'ları, per-target circuit breaker, DNS cache singleton) profesyonel seviyede.

**Mimari Puan: 8/10**

Güçlü yönler:
- ArcSwap ile hot-path'te sıfır-lock route table okuma
- Pingora'nın ProxyHttp trait'ini doğru kullanma
- SSRF koruması katmanlı ve tutarlı
- TLS hot-reload mekanizması temiz
- Config hot-reload validation'lı

---

## 2. 🔴 Kritik Bulgular ve Doğrulanan Sorunlar

### ✅ ARCH-1: Connection Slot Lifecycle — Doğrulanmış, Sorun Yok

**Dosya:** `src/proxy/handler/upstream.rs:235`, `src/proxy/handler/access.rs:66`

`try_acquire_connection_slot()` upstream_peer'de çağrılıyor, `release_connection_slot()` logging callback'inde. Pingora `logging()`'i her request için garanti ediyor → **leak yok**.

`ctx.picked_target = Some(target)` sıralaması doğru (acquire sonrası). Early return eklenirse dikkat edilmeli.

---

### 🟡 ARCH-2: DNS Cache — Re-resolve Single Pass (Not a Bug)

**Dosya:** `src/route/target.rs:318-405`
**Severity:** DÜŞÜK (belgeleme notu)

DNS cache hit'de ilk IP SSRF check'den geçemezse:
1. Cache.remove() → re-resolve
2. Fresh DNS lookup → SSRF check tekrar uygulanır
3. Eğer yine private IP dönüyorsa → PermissionDenied (hata dönüyor, sonsuz döngü yok)
4. Eğer public IP dönerse → normal akış devam eder

**Sonuç:** Sonsuz döngü riski **yok**. Cache remove + re-resolve en fazla 1 kez gerçekleşir. Kod doğru çalışıyor.

---

### 🟠 ARCH-3: Circuit Breaker Two-Phase Check — Tasarım Trade-off (Bug Değil)

**Dosya:** `src/proxy/handler/upstream.rs:88, 177-181`
**Severity:** DÜŞÜK (documented trade-off)

```rust
// lookup_target içinde (ilk check):
if !cb_enabled || target.health_tracker.circuit_breaker().can_accept_request() {
    return Some(target);
}

// select_upstream_peer içinde (ikinci check):
if config.proxy.circuit_breaker_enabled
    && !target.health_tracker.circuit_breaker().allow_request()
{
    // inline fallback logic...
}
```

Kod kendisi bu durumu zaten biliyor ve yorumlamış:
```rust
// upstream.rs:180-181
// This handles the TOCTOU race where can_accept_request() returned true
// during lookup_target but allow_request() fails here.
```

**Düzeltme:** Bu bir bug değil, **kasıtlı tasarım trade-off'ü**. HalfOpen probe slot yarışında iki concurrent request aynı target'ı alabilir. İkinci check ile garanti altına alınıyor.

Fallback maliyeti de abartılmamalı — `matching_routes()` full table scan yapmıyor, sadece ilgili host/catch-all bucket'ları tarıyor.

---

### 🟡 PERF-HOT-1: Hot-Path Vec/Arc Clone — `lookup_target()` Genel Sorun

**Dosya:** `src/proxy/handler/upstream.rs:31-62`
**Severity:** ORTA (Performans — en değerli iyileştirme adayı)

```rust
// Header constraint varsa:
let matching: Vec<Arc<Target>> = route.targets.iter()
    .filter(|t| t.matches_headers(headers))
    .cloned()  // Arc clone
    .collect();

// Header constraint yoksa:
(route.targets.clone(), route.w_targets.clone())  // Vec clone + tüm Arc'lar
```

**Asıl sorun:** Header matching sadece özel case. **Her lookup'ta** `else` branch çalışıyor:
- `route.targets.clone()` → Vec allocation + N× Arc::clone
- `route.w_targets.clone()` → Vec allocation + M× Arc::clone

Bu **her request** için geçerli. 100 target = 200 Arc clone + 2 Vec alloc.

**Öneri:** `pick_target_by_strategy` fonksiyonunu `&[Arc<Target>]` referansı ile çağırmak yeterli — clone gereksiz. `w_targets` zaten interleave edilmiş, pick yapılırken filter edilmiyor.

**Teşhis düzeltmesi:** İlk review'de bunu "header matching clone" olarak scope'lamıştım. Reviewer haklı olarak asıl sorunun daha geniş olduğunu belirtti: header yokluğunda da clone yapılıyor.

---

## 3. 🟠 Orta Severity Sorunlar

### 🟠 ARCH-5: Weighted Target Interleaving — Float Precision Kaybı

**Dosya:** `src/route/table.rs:180-250`

Weight interleaving algoritması `f64` ile çalışıyor:

```rust
let stride = n as f64 / runs[best_group].1 as f64;
positions[best_group] += stride;
```

Büyük weight farklarında (örneğin 1:999) float accumulation error ile interleaving bozulabilir. 1000 slot ile bu genellikle sorun değil, ama weight'ler 0.001 gibi küçük değerlerde precision kaybı yaşanır.

**Sonuç:** Pratikte sorun değil (Fabio da benzer yaklaşım kullanıyor), ama test coverage eksik.

---

### 🟠 ARCH-6: DNS Negative Cache — Stale NXDOMAIN

**Dosya:** `src/route/dns_cache.rs`

Negative cache TTL ile NXDOMAIN sonuçları cache'leniyor. Ama Consul service discovery'de:
1. Service kaydolur → DNS lookup → NXDOMAIN → negative cache
2. Service unhealthy → Consul health check fail → DNS hâlâ NXDOMAIN
3. Service healthy → DNS cache TTL bitene kadar hâlâ negative cache'den geliyor

**default TTL 10s** — bu kısa ama service restart sonrası 10 saniyelik delay yaşanabilir.

---

### 🟠 ARCH-7: Consul Watcher — Index Reset Handling

**Dosya:** `src/consul/watcher.rs:405+`

Consul restart sonrası index sıfırlanabilir. Mevcut kod `new_index`'i güncelliyor ama explicit `new_index < last_index` kontrolü yok. Bu durumda:
- Consul restart → `index=1` döner
- Watcher `index=1` ile tekrar sorar
- Consul `index=1` → hemen response (blocking olmadan)
- Watcher tekrar sorar → tekrar hemen response → short loop

Bu döngü Consul yeni index'e ulaşıncaya kadar devam eder. CPU spike riski düşük ama mevcut.

---

### ~~ARCH-8: Rate Limiter is_configured()~~ — REDDEDİLDİ

**İlk iddia:** `is_configured()` her request'te `Mutex::lock()` yapıyor

**Gerçek:** `src/proxy/ratelimit.rs:135-136`
```rust
pub fn is_configured(&self) -> bool {
    self.rate.load(Ordering::Acquire) != UNCONFIGURED
}
```

`is_configured()` **Mutex kullanmıyor**, `AtomicU64::load` yapıyor. Mutex sadece `try_acquire()` içinde — bu tasarım gereği (refill + consume atomikliği için). İlk review yanlış dosya yolu (`src/route/ratelimit.rs` yerine `src/proxy/ratelimit.rs`) ve yanlış implementasyon okuması yapmış. **Bu madde tamamen yanlış.**

---

### 🟠 ARCH-9: TCP SNI Parsing — Malformed Client Hello

**Dosya:** `src/proxy/tcp.rs:680+`

`read_server_name` fonksiyonu raw bytes üzerinde manuel parsing yapıyor. Bu doğru ama:
- Extension length validation strict (`extensions_length != data.len()` → `None`)
- Bazı TLS client'lar (özellikle eski Go implementasyonları) extension length uyumsuzluğu gönderebilir
- Bu durumda SNI route bulunamaz → connection silently drop

**Sonuç:** Üretimde nadiren karşılaşılır, ama SNI parsing'de lenient olmak (trailing data ignore) daha sağlam olur.

---

### 🟠 ARCH-10: Admin API — Config Update Atomicity

**Dosya:** `src/admin/config_handler.rs:290-320`

Config update sıralaması:
1. `current = state.config.load()` — mevcut config oku
2. `new_proxy = current.proxy.clone()` — clone
3. Field'ları güncelle
4. `temp_config = Config { ... }` — yeni config oluştur
5. `state.config.store(Arc::new(temp_config))` — atomik swap
6. `dns_cache.set_ttl(...)` — DNS cache TTL güncelle
7. `route_table.reconfigure_circuit_breaker(...)` — CB güncelle

Adım 5-7 arası **atomik değil**. Config store olduktan sonra, DNS TTL ve CB reconfigure ayrı adımlar. Bu window'da yeni config ile eski CB config birlikte çalışabilir.

**Sonuç:** Window çok kısa (µs), pratikte sorun değil. Ama DNS TTL set failure durumunda config inconsistency kalır.

---

### 🟠 ARCH-11: Access Log — Error Classification ✅ Doğru Çalışıyor

**Dosya:** `src/proxy/handler/access.rs:23-28`

```rust
pub(super) fn should_record_target_error(status: u16, error: Option<&pingora::Error>) -> bool {
    status >= 500
        || matches!(error, Some(err) if err.etype() == &ErrorType::ConnectTimedout)
        || matches!(error, Some(err) if err.etype() == &ErrorType::ConnectRefused)
        || matches!(error, Some(err) if err.etype() == &ErrorType::ConnectNoRoute)
}
```

**Düzeltme:** İlk incelememde 429/403'ün CB error sayılacağını düşündüm ama `status >= 500` filtresi zaten bunu önlüyor. 4xx'ler CB'ye error olarak kaydedilmiyor. ✅ Doğru tasarım.

**Kalan concern:** Upstream'in kendi 503'leri (overload, maintenance) CB'ye error kaydedilir. Bu istenen davranış olabilir ama "upstream intentionally 503" senaryosunda CB gereksiz açılabilir. Bu bilinçli bir trade-off.

---

### 🟠 ARCH-12: TLS Certificate Reload — Transient Failure Window

**Dosya:** `src/proxy/tls/watcher.rs:120-140`

```rust
Err(error) => {
    tracing::warn!(...);
    // Don't update last_meta so we'll retry on next poll
}
```

Cert reload failure durumunda eski cert kullanılmaya devam ediyor. Ama cert expired olduysa ve reload fail ederse:
- Eski expired cert ile handshake'ler devam eder
- Client'lar cert validation error alır

**Sonuç:** Doğru davranış (fail-open), ama alerting mekanizması yok. Expired cert + reload failure → silent degradation.

---

## 4. 🟡 Performans Sorunları

### 🟡 PERF-1: Config Load Per-Request

**Dosya:** `src/proxy/handler/upstream.rs:144`

```rust
let config = self.config.load();  // ArcSwap::load() — atomic load
```

Her request'te `ArcSwap::load()` çağrılıyor. Bu atomic bir işlem ama her request'te reference count artırılıp azalılıyor. ArcSwap'in `guard` API'si ile RefCount increment olmadan okuma mümkün, ama mevcut yaklaşım `Arc<Config>` clone yapıyor.

**Sonuç:** µs-level overhead, yüksek QPS'de hissedilir ama kritik değil.

---

### 🟡 PERF-2: Route Table Clone on Rebuild

**Dosya:** `src/route/table.rs` — `TableBuilder::build()`

Her route table rebuild'de tüm `Arc<Route>` clone'ları yapılıyor. 10K route = 10K Arc clone. Rebuild Consul update başına bir kez oluyor, bu yüzden hot path değil.

**Sonuç:** Kabul edilebilir.

---

### 🟡 PERF-3: Topology Flow Cache — Mutex Under Load

**Dosya:** `src/admin/topology_flow.rs:213`

```rust
let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
```

Admin dashboard her topology request'inde Mutex lock alıyor. Dashboard refresh interval ~1s ile bu sorun değil. Ama aynı anda 10 dashboard client bağlanırsa contention yaşanabilir.

**Sonuç:** Admin endpoint, kritik değil.

---

### 🟡 PERF-4: Weighted Target Array — Memory Overhead

**Dosya:** `src/route/table.rs:160-200`

1000 slot'lu weighted target array, her slot bir `Arc<Target>`. 10 route × 100 target × 1000 slot = 1M Arc clone. Bu rebuild sırasında yaşanıyor ve memory'de tutuluyor.

**Sonuç:** Alternatif (weighted random pick) daha memory-efficient ama round-robin garantisi vermez. Mevcut yaklaşım Fabio-uyumlu ve kabul edilebilir.

---

### 🟡 PERF-5: Prometheus Metrics — String Allocation on Every Request

**Dosya:** `src/metrics/prometheus.rs`

`record_request()` her request'te çağrılıyor, atomic increment yapıyor — bu verimli. Ama `render()` metodu scrape sırasında tüm label'lar için String allocation yapıyor. 10K target × 5 metric = 50K String allocation.

3 saniyelik render cache var, bu yüzden sadece Prometheus scrape sırasında yaşanıyor (~15s interval).

**Sonuç:** Kabul edilebilir, ama streaming output ile iyileştirilebilir.

---

## 5. 🔵 Mimari İyileştirme Önerileri

### 🔵 REC-1: Request Context'te Route Snapshot Tutma

Mevcut akış:
1. `upstream_peer()` → `lookup_target()` → route table oku → target pick
2. `fail_to_proxy()` → tekrar route table oku → inline fallback

**Öneri:** `ProxyCtx`'de picked route snapshot tutarak fallback'te tekrar table okuması önlenebilir.

---

### 🔵 REC-2: DNS Cache Batch Eviction

Mevcut DNS cache lookup sırasında inline eviction yapıyor. Yüksek DNS churn'de bu hot path'ı yavaşlatabilir. Background eviction task ile ayrılabilir.

---

### 🔵 REC-3: Health Check Parallel Probing

Mevcut health check sıralı probing yapıyor (tüm target'ları tek tek). `futures::stream::iter(...).for_each_concurrent(limit, ...)` ile paralel probing mümkün.

---

### 🔵 REC-4: Circuit Breaker Open → Probe Health Sync

AGENTS.md'de probe health ve CB'nin ayrı olduğu belirtiliyor (kasıtlı tasarım). Ama operatör perspective'den "probe unhealthy + CB closed" durumu kafa karıştırıcı. Admin dashboard'da her iki durumu birlikte göstermek UX'i iyileştirir.

---

### 🔵 REC-5: Graceful Shutdown — In-Flight Request Tracking

Mevcut shutdown akışı Pingora'nın shutdown signal'i ile çalışıyor. Ama TCP proxy bağlantıları için in-flight tracking yok. Dynamic TCP listener shutdown sırasında bağlantılar aniden kesilebilir (5 saniye grace period var ama zorunlu değil).

---

## 6. 🔧 Küçük Kod Kalitesi Notları

### Küçük-1: `Route.source` Serialization

`RouteSource` enum'u `serde(skip)` ile serileştirmeden çıkarılmış. Admin API'den route source bilgisi görünmüyor — debugging için faydalı olur.

### Küçük-2: `TargetStats` Atomic Ordering

`TargetStats` içindeki tüm atomic'ler `Ordering::Relaxed` kullanıyor. Bu tek-threaded counter için doğru ama cross-thread visibility garantisi yok. Prometheus scrape sırasında farklı thread'ten okunan değerler tutarsız olabilir. Bu bilinçli bir trade-off (lock-free metrics).

### Küçük-3: `SentirumProxy.trusted_proxies` Runtime Update Desteği Yok

`trusted_proxies` field'ı constructor'da parse ediliyor ve hiç güncellenmiyor. `PUT /admin/config` ile `trusted_proxies` değiştirilemiyor (doğru bir kısıtlama). Ama startup sonrası değişiklik için restart gerekiyor — bu bilinen bir kısıtlama ve AGENTS.md'de belirtilmiş.

---

## 7. 📊 Özet Tablo

| Kategori | Bulgu Sayısı | En Yüksek Severity |
|----------|-------------|--------------------|
| 🟡 Performans | 5 | PERF-HOT-1 (hot-path clone — en değerli bulgu) |
| 🟠 Orta Sorunlar | 7 | ARCH-7 (Consul), ARCH-10 (config atomicity) |
| ~~Reddedildi~~ | 1 | ARCH-8 (yanlış okuma) |
| 🔵 İyileştirme Önerisi | 5 | REC-1 (route snapshot), REC-3 (parallel probing) |
| 🔧 Kod Kalitesi | 3 | Küçük-1 (route source visibility) |

### Hemen Yapılması Gerekenler

1. **PERF-HOT-1**: Hot-path clone eliminasyonu — `lookup_target()` içinde `route.targets.clone()` + `route.w_targets.clone()` kaldırılabilir. `pick_target_by_strategy` fonksiyonu `&[Arc<Target>]` referansı ile zaten çalışabiliyor
2. **ARCH-7**: Consul watcher index reset handling — robustness iyileştirmesi
3. **ARCH-10**: Config update non-atomic window — document et veya DNS TTL set'i config.store öncesine taşı

### Bilinen Trade-off'ler (Değiştirilmemesi Gerekenler)

- CB two-phase check (ARCH-3) — documented tasarım kararı, TOCTOU bilinçli
- Probe health vs Circuit breaker ayrımı — kasıtlı tasarım kararı
- Weighted target array memory overhead — Fabio uyumluluğu için
- DNS negative cache — short TTL ile kabul edilebilir

### Reddedilen Bulgular

- **ARCH-8** Rate limiter `is_configured()` Mutex claim — kod AtomicU64 kullanıyor, Mutex değil

---

## 8. Güvenlik Değerlendirmesi

### ✅ İyi Yapılmış
- SSRF koruması katmanlı: hostname → resolved IP → cache hit
- Admin token constant-time comparison
- Session eviction (max capacity + TTL)
- Login rate limiting (TOCTOU düzeltildi)
- Trusted proxy XFF chain validation
- TLS client auth (mTLS) desteği
- `ssrfskipverify` explicit opt-in

### ⚠️ Dikkat Gerekenler
- DNS cache SSRF bypass riski (BUG-2)
- Admin API TLS olmadan HTTP üzerinde çalışabilir — production'da TLS veya localhost-only binding gerekli
- Session token `String` — timing attack riski yok (token generate sonrası comparison UUID formatında)

---

**Son Söz:** Mimari genel olarak **profesyonel seviyede** ve production-ready. Tespit edilen sorunların çoğu edge case ve iyileştirme kategorisinde. Gerçek bug sayısı az ve etki alanları sınırlı. AGENTS.md'deki tasarım kararları tutarlı bir şekilde uygulanmış.

---

## 9. Reviewer Geri Bildirimi ve Düzeltmeler

Bu rapor üçüncü bir incelemeci tarafından değerlendirildi. Sonuçlar:

### Kabul Edilen Bulgular
- **PERF-HOT-1** (eski BUG-4): Hot-path clone — geçerli performans iyileştirme adayı, ama kapsam genişletildi (sadece header matching değil, genel clone sorunu)
- **ARCH-7**: Consul index reset — low-priority hardening
- **ARCH-10**: Config update non-atomic window — teknik not, düşük risk

### Yumuşatılan Bulgular
- **BUG-3 → ARCH-3**: CB TOCTOU — bug değil, documented tasarım trade-off. Kod zaten yorumla belgelenmiş. Fallback "full table scan" yapmıyor.

### Reddedilen Bulgular
- **ARCH-8**: Rate limiter `is_configured()` Mutex claim — **tamamen yanlış**. Kod `AtomicU64::load` kullanıyor, Mutex değil. Yanlış dosya yolu da verilmişti.

### Review Güvenilirlik Notu

Bu rapor iyi bir discussion input olarak kullanılabilir ama doğrudan "action list" olarak alınmamalı. Özellikle:
- Dosya yolları ve implementasyon detayları ikinci kez doğrulanmalı
- Severity kalibrasyonu bazen şişirilmiş
- Bazı trade-off'lar "bug" olarak etiketlenmiş

**Düzeltilmiş puan: 6.5/10** (ilk puan 8/10 idi)

# Copilot Review Fix Plan

## Context

PR #1 için Copilot review yorumları içinde gerçekten davranış, güvenlik veya doğruluk etkisi olan maddeler var. Ama hepsi aynı ağırlıkta değil:

**Doğrudan fixlenmesi gerekenler**
- `Target.source` de-dup anahtarına dahil edilmediği için SSRF kararları source’a göre yanlış birleşebilir (`src/route/table.rs`)
- `route del ... tags ...` uygulaması `src`/`path` kısıtlarını yok sayarak beklenenden geniş silme yapabiliyor (`src/route/table.rs`)
- `X-Forwarded-Proto` şu an request URI scheme’inden türetiliyor; origin-form isteklerde bu çoğunlukla boş olduğu için TLS dinleyicisinde bile `http` yazılabilir (`src/proxy/handler.rs`)
- `--config` verilince dosya okunamazsa panic oluyor; kullanıcı dostu hata + exit daha doğru (`src/main.rs`)
- Prometheus histogram bucket sınırları ile bucket kayıt mantığı birebir uyuşmuyor; boundary semantiği düzeltilmeli (`src/metrics/prometheus.rs`)
- Prometheus sum testi exact string karşılaştırdığı için kırılgan (`src/metrics/prometheus.rs`)
- IPv6 SSRF tarafında link-local / unique-local kapsamı net değil (`src/route/target.rs`)

**Bu patch’e dahil edilecek ek iyileştirmeler**
- `mark_sources()` gereksiz clone yapıyor (`src/route/registry.rs`)
- `passing_service_ids()` O(n²) tarama yapıyor (`src/consul/watcher.rs`)
- forwarded header insert hataları sessizce yutuluyor (`src/proxy/handler.rs`)

Kullanıcı kararı: valid production fixlere ek olarak bu performans/polish yorumları da aynı patch’e dahil edilecek.

## Approach

Önerilen yaklaşım:

1. **Correctness ve security önce**: source-aware target de-dup, scoped tag-delete, doğru forwarded proto üretimi, config error handling, IPv6 SSRF kapsamı.
2. **Metrics doğruluğu**: Prometheus bucket boundary semantiğini gerçek `le=` sınırları ile hizala; testleri kırılgan string equality’den çıkar.
3. **Performance + robustness cleanup**: aynı patch içinde `mark_sources()` clone azaltma, `passing_service_ids()` tarama maliyeti düşürme ve forwarded header insertion hata yönetimini de tamamla.

## Files to modify

Yüksek olasılıkla değişecek dosyalar:

- `src/route/table.rs`
- `src/route/target.rs`
- `src/proxy/handler.rs`
- `src/main.rs`
- `src/metrics/prometheus.rs`

Bu patch kapsamında da değişmesi beklenen ek dosyalar:

- `src/route/registry.rs`
- `src/consul/watcher.rs`

## Reuse

Mevcut kod içinde tekrar kullanılacak alanlar:

- `Route::add_target`, `Route::remove_targets`, `Table::apply_del` — target de-dup ve delete scope davranışı burada düzeltilecek (`src/route/table.rs`)
- `Target::{is_host_safe, source_allows_private_upstreams}`, `is_ip_rfc1918`, `is_ip_always_blocked` — IPv6/local-address politikası burada netleştirilecek (`src/route/target.rs`)
- `SentirumProxy::upstream_request_filter` ve `append_forwarded_headers` — forwarded header üretimi ve hata yönetimi burada iyileştirilecek (`src/proxy/handler.rs`)
- `main()` config load akışı — panic yerine kontrollü kullanıcı hatası döndürmek için mevcut akış yeniden düzenlenecek (`src/main.rs`)
- `Metrics::record_request`, `Metrics::render`, mevcut testler — histogram boundary ve assertion düzeltmeleri için temel (`src/metrics/prometheus.rs`)
- `mark_sources()` — route source işaretlemeyi in-place / ownership-preserving hale getirmek için mevcut helper yeniden şekillendirilecek (`src/route/registry.rs`)
- `ServiceMonitor::passing_service_ids()` — node/service maintenance durumlarını önceden gruplayarak tekil service değerlendirmesini daha düşük maliyetli hale getirmek için mevcut fonksiyon yeniden düzenlenecek (`src/consul/watcher.rs`)

## Steps

- [x] `Route::add_target` de-dup anahtarını `source` farkını koruyacak şekilde düzelt; SSRF davranışının source’a göre deterministik kaldığını testle doğrula.
- [x] `Table::apply_del` içinde `tags` ile birlikte `src` verildiğinde host/path kısıtlarını koruyacak scoped delete davranışını netleştir ve test ekle.
- [x] `append_forwarded_headers` için proto kaynağını düzelt: mevcut downstream header varsa koru, aksi halde session/TLS bilgisinden türet; insertion hatalarını sessizce yutmamak için log veya error propagation ekle.
- [x] `main()` config load akışını user-friendly hata ile çıkacak şekilde düzenle; panic kaldır.
- [x] IPv6 SSRF politikasını netleştir ve uygula: `fc00::/7` unique-local adresleri IPv4 private ile aynı source-aware kurala tabi tut; link-local adresleri block et.
- [x] `Metrics::record_request` bucket mantığını `latency_us` tabanlı ve `le=` boundary semantiği ile uyumlu hale getir.
- [x] `Metrics` testlerini brittle exact string equality’den çıkar; parse + tolerance veya line-level numeric assert kullan.
- [x] `mark_sources()` helper’ını ownership-preserving / in-place işaretleme ile optimize et.
- [x] `passing_service_ids()` için node-level ve maintenance durumlarını önceden hesaplayıp O(n²) taramayı azalt.

## Verification

- `cargo test --quiet`
- route table unit testleri:
  - farklı source ama aynı `(service,url,weight)` kombinasyonları için ayrı target davranışı
  - `route del <svc> <src> tags "..."` veya eşdeğeri scoped delete senaryosu
- proxy/header testleri:
  - `X-Forwarded-Proto` TLS/plaintext senaryoları
  - invalid forwarded header insertion durumunda seçilen davranış
- SSRF testleri:
  - IPv6 loopback/link-local/unique-local davranışı
  - unique-local adreslerde Consul source vs Static source farkı
- metrics testleri:
  - tam boundary değerleri (`1000us`, `5000us`, vb.) doğru bucket’a gidiyor mu
  - `_sum` assert’i tolerant/numeric mi

## Open questions

Kararlar alındı ve plan buna göre şekillendirildi:

1. **IPv6 unique-local (`fc00::/7`) adresler**
   - IPv4 private ile aynı davranacak: Consul-discovered ise trusted, diğer kaynaklarda blocked.

2. **Düşük öncelikli performans/polish yorumları**
   - Bu patch’e dahil edilecek: `mark_sources()` clone azaltma ve `passing_service_ids()` optimizasyonu uygulanacak.

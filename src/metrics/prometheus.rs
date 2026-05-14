//! Prometheus metrics for Sentirum LB.
//!
//! Tracks request latency histogram, request counter, active connections gauge,
//! and route-level metrics for observability.

use std::sync::RwLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Global metrics instance
static METRICS: std::sync::OnceLock<Metrics> = std::sync::OnceLock::new();

/// Get the global metrics instance
pub fn global() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateExpiryMetric {
    pub entry: String,
    pub cn: String,
    pub not_after_unix: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct ProcessMetricsSnapshot {
    available: bool,
    resident_memory_bytes: u64,
    virtual_memory_bytes: u64,
    open_fds: u64,
}

#[cfg(target_os = "linux")]
fn parse_proc_status_value_bytes(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim();
        let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        Some(kb * 1024)
    })
}

/// Cached process metrics with a 5-second TTL to avoid /proc walks on every scrape.
struct CachedProcessMetrics {
    at: std::time::Instant,
    snapshot: ProcessMetricsSnapshot,
}

static PROCESS_METRICS_CACHE: std::sync::OnceLock<std::sync::RwLock<Option<CachedProcessMetrics>>> =
    std::sync::OnceLock::new();

fn collect_process_metrics_cached() -> ProcessMetricsSnapshot {
    let cache = PROCESS_METRICS_CACHE
        .get_or_init(|| std::sync::RwLock::new(None));
    {
        let guard = cache.read().unwrap();
        if let Some(cached) = &*guard
            && cached.at.elapsed() < std::time::Duration::from_secs(5) {
                return cached.snapshot; // ProcessMetricsSnapshot is just plain data
            }
    }
    let snapshot = collect_process_metrics_uncached();
    *cache.write().unwrap() = Some(CachedProcessMetrics {
        at: std::time::Instant::now(),
        snapshot,
    });
    snapshot
}

/// Cached render output with a 3-second TTL.
#[derive(Debug)]
struct CachedRender {
    at: std::time::Instant,
    output: String,
}

const RENDER_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3);

/// Escape a string for safe use as a Prometheus label value.
/// Per the exposition format spec, backslashes, double quotes, and newlines must be escaped.
fn escape_prometheus_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn collect_process_metrics_uncached() -> ProcessMetricsSnapshot {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok();
        let open_fds = std::fs::read_dir("/proc/self/fd")
            .ok()
            .map(|entries| entries.filter_map(Result::ok).count() as u64)
            .unwrap_or(0);

        if let Some(status) = status {
            return ProcessMetricsSnapshot {
                available: true,
                resident_memory_bytes: parse_proc_status_value_bytes(&status, "VmRSS:")
                    .unwrap_or(0),
                virtual_memory_bytes: parse_proc_status_value_bytes(&status, "VmSize:")
                    .unwrap_or(0),
                open_fds,
            };
        }
    }

    ProcessMetricsSnapshot::default()
}

/// Core metrics for the load balancer
#[derive(Debug)]
pub struct Metrics {
    // --- Counters ---
    /// Total requests processed
    pub requests_total: AtomicU64,
    /// Total requests that resulted in an error
    pub requests_error_total: AtomicU64,
    /// Total bytes received from upstream
    pub bytes_received_total: AtomicU64,
    /// Total gRPC requests processed
    pub grpc_requests_total: AtomicU64,
    /// Total gRPC-Web requests processed
    pub grpc_web_requests_total: AtomicU64,
    /// Total WebSocket requests processed
    pub websocket_requests_total: AtomicU64,
    /// Total successful TLS cert reloads
    pub cert_reload_total: AtomicU64,
    /// Total failed TLS cert reloads
    pub cert_reload_errors_total: AtomicU64,
    /// TLS reload skips due to oversize entries
    pub cert_reload_skipped_oversize_total: AtomicU64,
    /// TLS reload skips due to invalid entries
    pub cert_reload_skipped_invalid_total: AtomicU64,
    /// TLS reload skips due to empty snapshots
    pub cert_reload_skipped_empty_total: AtomicU64,
    /// Static route reloads
    pub route_reload_total_static: AtomicU64,
    /// KV route reloads
    pub route_reload_total_kv: AtomicU64,
    /// Service route reloads
    pub route_reload_total_service: AtomicU64,
    /// Consul watcher errors
    pub consul_watcher_errors_total_services: AtomicU64,
    pub consul_watcher_errors_total_kv: AtomicU64,
    pub consul_watcher_errors_total_tls: AtomicU64,
    pub consul_watcher_errors_total_client_ca: AtomicU64,
    /// Circuit breaker opens
    pub circuit_breaker_open_total: AtomicU64,
    /// Circuit breaker reopens (from half-open)
    pub circuit_breaker_reopen_total: AtomicU64,
    /// Circuit breaker closes (recovery)
    pub circuit_breaker_close_total: AtomicU64,
    /// Circuit breaker fast-fail responses (503 when open)
    pub circuit_breaker_fastfail_total: AtomicU64,
    /// DNS cache hits
    pub dns_cache_hits_total: AtomicU64,
    /// DNS cache misses
    pub dns_cache_misses_total: AtomicU64,
    /// DNS cache negatives (NXDOMAIN)
    pub dns_cache_negatives_total: AtomicU64,
    /// Rate limit rejections
    pub rate_limit_rejected_total: AtomicU64,
    /// Health check probes total
    pub health_check_probes_total: AtomicU64,
    /// Health check probe failures
    pub health_check_probe_failures_total: AtomicU64,

    // --- Gauges ---
    /// Currently active connections
    pub active_connections: AtomicI64,
    /// Number of routes in the routing table
    pub route_count: AtomicI64,
    /// Number of target backends
    pub target_count: AtomicI64,
    /// Current watcher backoff seconds
    pub consul_watcher_backoff_seconds_services: AtomicU64,
    pub consul_watcher_backoff_seconds_kv: AtomicU64,
    pub consul_watcher_backoff_seconds_tls: AtomicU64,
    pub consul_watcher_backoff_seconds_client_ca: AtomicU64,
    /// Last seen Consul index per watcher
    pub consul_watcher_last_index_services: AtomicU64,
    pub consul_watcher_last_index_kv: AtomicU64,
    pub consul_watcher_last_index_tls: AtomicU64,
    pub consul_watcher_last_index_client_ca: AtomicU64,
    /// Oldest loaded certificate expiry timestamp
    pub cert_min_expiry_unix_seconds: AtomicU64,
    /// Per-certificate expiry details
    pub cert_expiry_entries: RwLock<Vec<CertificateExpiryMetric>>,
    /// Cached render output with a 3-second TTL to avoid redundant String
    /// allocation on every /admin/metrics scrape. Instance-level so that
    /// each Metrics (including test instances) gets its own cache.
    render_cache: RwLock<Option<CachedRender>>,

    // --- Histograms (simplified as buckets) ---
    /// Request latency tracking (microseconds)
    /// Buckets: <1ms, <5ms, <10ms, <25ms, <50ms, <100ms, <250ms, <500ms, <1s, <5s, >5s
    pub latency_bucket_1ms: AtomicU64,
    pub latency_bucket_5ms: AtomicU64,
    pub latency_bucket_10ms: AtomicU64,
    pub latency_bucket_25ms: AtomicU64,
    pub latency_bucket_50ms: AtomicU64,
    pub latency_bucket_100ms: AtomicU64,
    pub latency_bucket_250ms: AtomicU64,
    pub latency_bucket_500ms: AtomicU64,
    pub latency_bucket_1s: AtomicU64,
    pub latency_bucket_5s: AtomicU64,
    pub latency_bucket_inf: AtomicU64,
    /// Sum of request latencies in microseconds
    pub latency_sum_us: AtomicU64,

    // --- Status code counters ---
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_error_total: AtomicU64::new(0),
            bytes_received_total: AtomicU64::new(0),
            grpc_requests_total: AtomicU64::new(0),
            grpc_web_requests_total: AtomicU64::new(0),
            websocket_requests_total: AtomicU64::new(0),
            cert_reload_total: AtomicU64::new(0),
            cert_reload_errors_total: AtomicU64::new(0),
            cert_reload_skipped_oversize_total: AtomicU64::new(0),
            cert_reload_skipped_invalid_total: AtomicU64::new(0),
            cert_reload_skipped_empty_total: AtomicU64::new(0),
            route_reload_total_static: AtomicU64::new(0),
            route_reload_total_kv: AtomicU64::new(0),
            route_reload_total_service: AtomicU64::new(0),
            consul_watcher_errors_total_services: AtomicU64::new(0),
            consul_watcher_errors_total_kv: AtomicU64::new(0),
            consul_watcher_errors_total_tls: AtomicU64::new(0),
            consul_watcher_errors_total_client_ca: AtomicU64::new(0),
            circuit_breaker_open_total: AtomicU64::new(0),
            circuit_breaker_reopen_total: AtomicU64::new(0),
            circuit_breaker_close_total: AtomicU64::new(0),
            circuit_breaker_fastfail_total: AtomicU64::new(0),
            dns_cache_hits_total: AtomicU64::new(0),
            dns_cache_misses_total: AtomicU64::new(0),
            dns_cache_negatives_total: AtomicU64::new(0),
            rate_limit_rejected_total: AtomicU64::new(0),
            health_check_probes_total: AtomicU64::new(0),
            health_check_probe_failures_total: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            route_count: AtomicI64::new(0),
            target_count: AtomicI64::new(0),
            consul_watcher_backoff_seconds_services: AtomicU64::new(0),
            consul_watcher_backoff_seconds_kv: AtomicU64::new(0),
            consul_watcher_backoff_seconds_tls: AtomicU64::new(0),
            consul_watcher_backoff_seconds_client_ca: AtomicU64::new(0),
            consul_watcher_last_index_services: AtomicU64::new(0),
            consul_watcher_last_index_kv: AtomicU64::new(0),
            consul_watcher_last_index_tls: AtomicU64::new(0),
            consul_watcher_last_index_client_ca: AtomicU64::new(0),
            cert_min_expiry_unix_seconds: AtomicU64::new(0),
            cert_expiry_entries: RwLock::new(Vec::new()),
            render_cache: RwLock::new(None),
            latency_bucket_1ms: AtomicU64::new(0),
            latency_bucket_5ms: AtomicU64::new(0),
            latency_bucket_10ms: AtomicU64::new(0),
            latency_bucket_25ms: AtomicU64::new(0),
            latency_bucket_50ms: AtomicU64::new(0),
            latency_bucket_100ms: AtomicU64::new(0),
            latency_bucket_250ms: AtomicU64::new(0),
            latency_bucket_500ms: AtomicU64::new(0),
            latency_bucket_1s: AtomicU64::new(0),
            latency_bucket_5s: AtomicU64::new(0),
            latency_bucket_inf: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
        }
    }

    /// Record a completed request
    pub fn record_request(&self, status: u16, latency_us: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);

        // Record latency bucket using microsecond boundaries that match the
        // exported `le=` labels exactly.
        if latency_us <= 1_000 {
            self.latency_bucket_1ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 5_000 {
            self.latency_bucket_5ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 10_000 {
            self.latency_bucket_10ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 25_000 {
            self.latency_bucket_25ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 50_000 {
            self.latency_bucket_50ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 100_000 {
            self.latency_bucket_100ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 250_000 {
            self.latency_bucket_250ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 500_000 {
            self.latency_bucket_500ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 1_000_000 {
            self.latency_bucket_1s.fetch_add(1, Ordering::Relaxed);
        } else if latency_us <= 5_000_000 {
            self.latency_bucket_5s.fetch_add(1, Ordering::Relaxed);
        } else {
            self.latency_bucket_inf.fetch_add(1, Ordering::Relaxed);
        }

        // Record status code
        match status {
            200..=299 => {
                self.status_2xx.fetch_add(1, Ordering::Relaxed);
            }
            300..=399 => {
                self.status_3xx.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.status_4xx.fetch_add(1, Ordering::Relaxed);
                self.requests_error_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.status_5xx.fetch_add(1, Ordering::Relaxed);
                self.requests_error_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_protocol_request(&self, grpc: bool, grpc_web: bool, websocket: bool) {
        if grpc {
            self.grpc_requests_total.fetch_add(1, Ordering::Relaxed);
        }
        if grpc_web {
            self.grpc_web_requests_total.fetch_add(1, Ordering::Relaxed);
        }
        if websocket {
            self.websocket_requests_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_cert_reload_success(&self) {
        self.cert_reload_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cert_reload_error(&self) {
        self.cert_reload_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cert_reload_skipped(&self, reason: &str) {
        match reason {
            "oversize" => {
                self.cert_reload_skipped_oversize_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            "empty" => {
                self.cert_reload_skipped_empty_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.cert_reload_skipped_invalid_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_route_reload(&self, source: &str) {
        match source {
            "static" => {
                self.route_reload_total_static
                    .fetch_add(1, Ordering::Relaxed);
            }
            "kv" => {
                self.route_reload_total_kv.fetch_add(1, Ordering::Relaxed);
            }
            "service" => {
                self.route_reload_total_service
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn set_consul_watcher_backoff_seconds(&self, watcher: &str, seconds: u64) {
        match watcher {
            "services" => {
                self.consul_watcher_backoff_seconds_services
                    .store(seconds, Ordering::Relaxed);
            }
            "kv" => {
                self.consul_watcher_backoff_seconds_kv
                    .store(seconds, Ordering::Relaxed);
            }
            "tls" => {
                self.consul_watcher_backoff_seconds_tls
                    .store(seconds, Ordering::Relaxed);
            }
            "client_ca" => {
                self.consul_watcher_backoff_seconds_client_ca
                    .store(seconds, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn set_consul_watcher_last_index(&self, watcher: &str, index: u64) {
        match watcher {
            "services" => {
                self.consul_watcher_last_index_services
                    .store(index, Ordering::Relaxed);
            }
            "kv" => {
                self.consul_watcher_last_index_kv
                    .store(index, Ordering::Relaxed);
            }
            "tls" => {
                self.consul_watcher_last_index_tls
                    .store(index, Ordering::Relaxed);
            }
            "client_ca" => {
                self.consul_watcher_last_index_client_ca
                    .store(index, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_consul_watcher_error(&self, watcher: &str) {
        match watcher {
            "services" => {
                self.consul_watcher_errors_total_services
                    .fetch_add(1, Ordering::Relaxed);
            }
            "kv" => {
                self.consul_watcher_errors_total_kv
                    .fetch_add(1, Ordering::Relaxed);
            }
            "tls" => {
                self.consul_watcher_errors_total_tls
                    .fetch_add(1, Ordering::Relaxed);
            }
            "client_ca" => {
                self.consul_watcher_errors_total_client_ca
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn set_cert_expiry_entries(&self, entries: Vec<CertificateExpiryMetric>) {
        let min_expiry = entries
            .iter()
            .map(|entry| entry.not_after_unix)
            .min()
            .unwrap_or(0);
        self.cert_min_expiry_unix_seconds
            .store(min_expiry, Ordering::Relaxed);
        *self
            .cert_expiry_entries
            .write()
            .expect("cert expiry entries poisoned") = entries;
    }

    /// Increment active connections
    pub fn connect(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections
    pub fn disconnect(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record bytes transferred
    pub fn record_bytes(&self, upstream_response_bytes: usize) {
        self.bytes_received_total
            .fetch_add(upstream_response_bytes as u64, Ordering::Relaxed);
    }

    /// Generate Prometheus text exposition format.
    /// Uses a 3-second render cache to avoid rebuilding the string on every scrape.
    pub fn render(&self) -> String {
        {
            let guard = self.render_cache.read().unwrap();
            if let Some(cached) = &*guard
                && cached.at.elapsed() < RENDER_CACHE_TTL {
                    return cached.output.clone();
                }
        }
        let output = self.render_uncached();
        *self.render_cache.write().unwrap() = Some(CachedRender {
            at: std::time::Instant::now(),
            output: output.clone(),
        });
        output
    }

    /// Build the full Prometheus text exposition from scratch.
    fn render_uncached(&self) -> String {
        let requests_total = self.requests_total.load(Ordering::Relaxed);
        let requests_error_total = self.requests_error_total.load(Ordering::Relaxed);
        let active_connections = self.active_connections.load(Ordering::Relaxed);
        let route_count = self.route_count.load(Ordering::Relaxed);
        let target_count = self.target_count.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received_total.load(Ordering::Relaxed);
        let grpc_requests_total = self.grpc_requests_total.load(Ordering::Relaxed);
        let grpc_web_requests_total = self.grpc_web_requests_total.load(Ordering::Relaxed);
        let websocket_requests_total = self.websocket_requests_total.load(Ordering::Relaxed);
        let cert_reload_total = self.cert_reload_total.load(Ordering::Relaxed);
        let cert_reload_errors_total = self.cert_reload_errors_total.load(Ordering::Relaxed);
        let cert_reload_skipped_oversize_total = self
            .cert_reload_skipped_oversize_total
            .load(Ordering::Relaxed);
        let cert_reload_skipped_invalid_total = self
            .cert_reload_skipped_invalid_total
            .load(Ordering::Relaxed);
        let cert_reload_skipped_empty_total =
            self.cert_reload_skipped_empty_total.load(Ordering::Relaxed);
        let route_reload_total_static = self.route_reload_total_static.load(Ordering::Relaxed);
        let route_reload_total_kv = self.route_reload_total_kv.load(Ordering::Relaxed);
        let route_reload_total_service = self.route_reload_total_service.load(Ordering::Relaxed);
        let circuit_breaker_open_total = self.circuit_breaker_open_total.load(Ordering::Relaxed);
        let circuit_breaker_reopen_total =
            self.circuit_breaker_reopen_total.load(Ordering::Relaxed);
        let circuit_breaker_close_total = self.circuit_breaker_close_total.load(Ordering::Relaxed);
        let circuit_breaker_fastfail_total =
            self.circuit_breaker_fastfail_total.load(Ordering::Relaxed);
        let watcher_backoff_services = self
            .consul_watcher_backoff_seconds_services
            .load(Ordering::Relaxed);
        let watcher_backoff_kv = self
            .consul_watcher_backoff_seconds_kv
            .load(Ordering::Relaxed);
        let watcher_backoff_tls = self
            .consul_watcher_backoff_seconds_tls
            .load(Ordering::Relaxed);
        let watcher_backoff_client_ca = self
            .consul_watcher_backoff_seconds_client_ca
            .load(Ordering::Relaxed);
        let watcher_last_index_services = self
            .consul_watcher_last_index_services
            .load(Ordering::Relaxed);
        let watcher_last_index_kv = self.consul_watcher_last_index_kv.load(Ordering::Relaxed);
        let watcher_last_index_tls = self.consul_watcher_last_index_tls.load(Ordering::Relaxed);
        let watcher_last_index_client_ca = self
            .consul_watcher_last_index_client_ca
            .load(Ordering::Relaxed);
        let watcher_errors_services = self
            .consul_watcher_errors_total_services
            .load(Ordering::Relaxed);
        let watcher_errors_kv = self.consul_watcher_errors_total_kv.load(Ordering::Relaxed);
        let watcher_errors_tls = self.consul_watcher_errors_total_tls.load(Ordering::Relaxed);
        let watcher_errors_client_ca = self
            .consul_watcher_errors_total_client_ca
            .load(Ordering::Relaxed);
        let cert_min_expiry_unix_seconds =
            self.cert_min_expiry_unix_seconds.load(Ordering::Relaxed);
        let cert_expiry_metrics = self
            .cert_expiry_entries
            .read()
            .expect("cert expiry entries poisoned")
            .iter()
            .map(|entry| {
                let entry_name = escape_prometheus_label(&entry.entry);
                let cn = escape_prometheus_label(&entry.cn);
                format!(
                    "sentirum_lb_cert_expiry_unix_seconds{{entry=\"{entry_name}\",cn=\"{cn}\"}} {}\n",
                    entry.not_after_unix
                )
            })
            .collect::<String>();
        let status_2xx = self.status_2xx.load(Ordering::Relaxed);
        let status_3xx = self.status_3xx.load(Ordering::Relaxed);
        let status_4xx = self.status_4xx.load(Ordering::Relaxed);
        let status_5xx = self.status_5xx.load(Ordering::Relaxed);
        let rate_limit_rejected_total = self.rate_limit_rejected_total.load(Ordering::Relaxed);
        let health_check_probes_total = self.health_check_probes_total.load(Ordering::Relaxed);
        let health_check_probe_failures_total = self.health_check_probe_failures_total.load(Ordering::Relaxed);
        let process = collect_process_metrics_cached();
        let process_metrics_available = if process.available { 1 } else { 0 };

        let b_1ms = self.latency_bucket_1ms.load(Ordering::Relaxed);
        let b_5ms = b_1ms + self.latency_bucket_5ms.load(Ordering::Relaxed);
        let b_10ms = b_5ms + self.latency_bucket_10ms.load(Ordering::Relaxed);
        let b_25ms = b_10ms + self.latency_bucket_25ms.load(Ordering::Relaxed);
        let b_50ms = b_25ms + self.latency_bucket_50ms.load(Ordering::Relaxed);
        let b_100ms = b_50ms + self.latency_bucket_100ms.load(Ordering::Relaxed);
        let b_250ms = b_100ms + self.latency_bucket_250ms.load(Ordering::Relaxed);
        let b_500ms = b_250ms + self.latency_bucket_500ms.load(Ordering::Relaxed);
        let b_1s = b_500ms + self.latency_bucket_1s.load(Ordering::Relaxed);
        let b_5s = b_1s + self.latency_bucket_5s.load(Ordering::Relaxed);
        let b_inf = b_5s + self.latency_bucket_inf.load(Ordering::Relaxed);
        let sum_seconds = self.latency_sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;

        format!(
            r#"# HELP sentirum_lb_requests_total Total number of requests processed
# TYPE sentirum_lb_requests_total counter
sentirum_lb_requests_total {requests_total}

# HELP sentirum_lb_requests_error_total Total number of request errors
# TYPE sentirum_lb_requests_error_total counter
sentirum_lb_requests_error_total {requests_error_total}

# HELP sentirum_lb_active_connections Currently active connections
# TYPE sentirum_lb_active_connections gauge
sentirum_lb_active_connections {active_connections}

# HELP sentirum_lb_route_count Number of routes in the routing table
# TYPE sentirum_lb_route_count gauge
sentirum_lb_route_count {route_count}

# HELP sentirum_lb_target_count Number of target backends
# TYPE sentirum_lb_target_count gauge
sentirum_lb_target_count {target_count}

# HELP sentirum_lb_bytes_received_total Total response bytes received from upstream
# TYPE sentirum_lb_bytes_received_total counter
sentirum_lb_bytes_received_total {bytes_received}

# HELP sentirum_lb_grpc_requests_total Total gRPC requests processed
# TYPE sentirum_lb_grpc_requests_total counter
sentirum_lb_grpc_requests_total {grpc_requests_total}

# HELP sentirum_lb_grpc_web_requests_total Total gRPC-Web requests processed
# TYPE sentirum_lb_grpc_web_requests_total counter
sentirum_lb_grpc_web_requests_total {grpc_web_requests_total}

# HELP sentirum_lb_websocket_requests_total Total WebSocket requests processed
# TYPE sentirum_lb_websocket_requests_total counter
sentirum_lb_websocket_requests_total {websocket_requests_total}

# HELP sentirum_lb_cert_reload_total Total successful TLS certificate reloads
# TYPE sentirum_lb_cert_reload_total counter
sentirum_lb_cert_reload_total {cert_reload_total}

# HELP sentirum_lb_cert_reload_errors_total Total failed TLS certificate reloads
# TYPE sentirum_lb_cert_reload_errors_total counter
sentirum_lb_cert_reload_errors_total {cert_reload_errors_total}

# HELP sentirum_lb_cert_reload_skipped_total TLS certificate reload skips by reason
# TYPE sentirum_lb_cert_reload_skipped_total counter
sentirum_lb_cert_reload_skipped_total{{reason="oversize"}} {cert_reload_skipped_oversize_total}
sentirum_lb_cert_reload_skipped_total{{reason="invalid"}} {cert_reload_skipped_invalid_total}
sentirum_lb_cert_reload_skipped_total{{reason="empty"}} {cert_reload_skipped_empty_total}

# HELP sentirum_lb_route_reload_total Route table rebuilds by source
# TYPE sentirum_lb_route_reload_total counter
sentirum_lb_route_reload_total{{source="static"}} {route_reload_total_static}
sentirum_lb_route_reload_total{{source="kv"}} {route_reload_total_kv}
sentirum_lb_route_reload_total{{source="service"}} {route_reload_total_service}

# HELP sentirum_lb_circuit_breaker_transitions_total Circuit breaker state transitions by kind
# TYPE sentirum_lb_circuit_breaker_transitions_total counter
sentirum_lb_circuit_breaker_transitions_total{{transition="open"}} {circuit_breaker_open_total}
sentirum_lb_circuit_breaker_transitions_total{{transition="reopen"}} {circuit_breaker_reopen_total}
sentirum_lb_circuit_breaker_transitions_total{{transition="close"}} {circuit_breaker_close_total}

# HELP sentirum_lb_circuit_breaker_fastfail_total Circuit breaker fast-fail responses
# TYPE sentirum_lb_circuit_breaker_fastfail_total counter
sentirum_lb_circuit_breaker_fastfail_total {circuit_breaker_fastfail_total}

# HELP sentirum_lb_consul_watcher_backoff_seconds Current Consul watcher backoff in seconds
# TYPE sentirum_lb_consul_watcher_backoff_seconds gauge
sentirum_lb_consul_watcher_backoff_seconds{{watcher="services"}} {watcher_backoff_services}
sentirum_lb_consul_watcher_backoff_seconds{{watcher="kv"}} {watcher_backoff_kv}
sentirum_lb_consul_watcher_backoff_seconds{{watcher="tls"}} {watcher_backoff_tls}
sentirum_lb_consul_watcher_backoff_seconds{{watcher="client_ca"}} {watcher_backoff_client_ca}

# HELP sentirum_lb_consul_watcher_last_index Last observed Consul index per watcher
# TYPE sentirum_lb_consul_watcher_last_index gauge
sentirum_lb_consul_watcher_last_index{{watcher="services"}} {watcher_last_index_services}
sentirum_lb_consul_watcher_last_index{{watcher="kv"}} {watcher_last_index_kv}
sentirum_lb_consul_watcher_last_index{{watcher="tls"}} {watcher_last_index_tls}
sentirum_lb_consul_watcher_last_index{{watcher="client_ca"}} {watcher_last_index_client_ca}

# HELP sentirum_lb_consul_watcher_errors_total Consul watcher errors by watcher
# TYPE sentirum_lb_consul_watcher_errors_total counter
sentirum_lb_consul_watcher_errors_total{{watcher="services"}} {watcher_errors_services}
sentirum_lb_consul_watcher_errors_total{{watcher="kv"}} {watcher_errors_kv}
sentirum_lb_consul_watcher_errors_total{{watcher="tls"}} {watcher_errors_tls}
sentirum_lb_consul_watcher_errors_total{{watcher="client_ca"}} {watcher_errors_client_ca}

# HELP sentirum_lb_cert_min_expiry_unix_seconds Oldest loaded certificate expiry timestamp
# TYPE sentirum_lb_cert_min_expiry_unix_seconds gauge
sentirum_lb_cert_min_expiry_unix_seconds {cert_min_expiry_unix_seconds}

# HELP sentirum_lb_cert_expiry_unix_seconds Per-certificate expiry timestamp
# TYPE sentirum_lb_cert_expiry_unix_seconds gauge
{cert_expiry_metrics}
# HELP sentirum_lb_process_metrics_available Process-level memory and FD metrics availability (Linux /proc based)
# TYPE sentirum_lb_process_metrics_available gauge
sentirum_lb_process_metrics_available {process_metrics_available}

# HELP sentirum_lb_process_resident_memory_bytes Resident memory size in bytes
# TYPE sentirum_lb_process_resident_memory_bytes gauge
sentirum_lb_process_resident_memory_bytes {resident_memory_bytes}

# HELP sentirum_lb_process_virtual_memory_bytes Virtual memory size in bytes
# TYPE sentirum_lb_process_virtual_memory_bytes gauge
sentirum_lb_process_virtual_memory_bytes {virtual_memory_bytes}

# HELP sentirum_lb_process_open_fds Number of open file descriptors
# TYPE sentirum_lb_process_open_fds gauge
sentirum_lb_process_open_fds {open_fds}

# HELP sentirum_lb_response_status_total Response status codes
# TYPE sentirum_lb_response_status_total counter
sentirum_lb_response_status_total{{code="2xx"}} {status_2xx}
sentirum_lb_response_status_total{{code="3xx"}} {status_3xx}
sentirum_lb_response_status_total{{code="4xx"}} {status_4xx}
sentirum_lb_response_status_total{{code="5xx"}} {status_5xx}

# HELP sentirum_lb_rate_limit_rejected_total Total requests rejected by per-target rate limiter
# TYPE sentirum_lb_rate_limit_rejected_total counter
sentirum_lb_rate_limit_rejected_total {rate_limit_rejected_total}

# HELP sentirum_lb_health_check_probes_total Total active health check probes
# TYPE sentirum_lb_health_check_probes_total counter
sentirum_lb_health_check_probes_total {health_check_probes_total}

# HELP sentirum_lb_health_check_probe_failures_total Total failed health check probes
# TYPE sentirum_lb_health_check_probe_failures_total counter
sentirum_lb_health_check_probe_failures_total {health_check_probe_failures_total}

# HELP sentirum_lb_request_duration_seconds Request latency histogram
# TYPE sentirum_lb_request_duration_seconds histogram
sentirum_lb_request_duration_seconds_bucket{{le="0.001"}} {b_1ms}
sentirum_lb_request_duration_seconds_bucket{{le="0.005"}} {b_5ms}
sentirum_lb_request_duration_seconds_bucket{{le="0.01"}} {b_10ms}
sentirum_lb_request_duration_seconds_bucket{{le="0.025"}} {b_25ms}
sentirum_lb_request_duration_seconds_bucket{{le="0.05"}} {b_50ms}
sentirum_lb_request_duration_seconds_bucket{{le="0.1"}} {b_100ms}
sentirum_lb_request_duration_seconds_bucket{{le="0.25"}} {b_250ms}
sentirum_lb_request_duration_seconds_bucket{{le="0.5"}} {b_500ms}
sentirum_lb_request_duration_seconds_bucket{{le="1"}} {b_1s}
sentirum_lb_request_duration_seconds_bucket{{le="5"}} {b_5s}
sentirum_lb_request_duration_seconds_bucket{{le="+Inf"}} {b_inf}
sentirum_lb_request_duration_seconds_sum {sum}
sentirum_lb_request_duration_seconds_count {count}
"#,
            sum = sum_seconds,
            count = requests_total,
            grpc_requests_total = grpc_requests_total,
            grpc_web_requests_total = grpc_web_requests_total,
            websocket_requests_total = websocket_requests_total,
            cert_reload_total = cert_reload_total,
            cert_reload_errors_total = cert_reload_errors_total,
            cert_reload_skipped_oversize_total = cert_reload_skipped_oversize_total,
            cert_reload_skipped_invalid_total = cert_reload_skipped_invalid_total,
            cert_reload_skipped_empty_total = cert_reload_skipped_empty_total,
            route_reload_total_static = route_reload_total_static,
            route_reload_total_kv = route_reload_total_kv,
            route_reload_total_service = route_reload_total_service,
            circuit_breaker_open_total = circuit_breaker_open_total,
            circuit_breaker_reopen_total = circuit_breaker_reopen_total,
            circuit_breaker_close_total = circuit_breaker_close_total,
            circuit_breaker_fastfail_total = circuit_breaker_fastfail_total,
            watcher_backoff_services = watcher_backoff_services,
            watcher_backoff_kv = watcher_backoff_kv,
            watcher_backoff_tls = watcher_backoff_tls,
            watcher_backoff_client_ca = watcher_backoff_client_ca,
            watcher_last_index_services = watcher_last_index_services,
            watcher_last_index_kv = watcher_last_index_kv,
            watcher_last_index_tls = watcher_last_index_tls,
            watcher_last_index_client_ca = watcher_last_index_client_ca,
            watcher_errors_services = watcher_errors_services,
            watcher_errors_kv = watcher_errors_kv,
            watcher_errors_tls = watcher_errors_tls,
            watcher_errors_client_ca = watcher_errors_client_ca,
            cert_min_expiry_unix_seconds = cert_min_expiry_unix_seconds,
            cert_expiry_metrics = cert_expiry_metrics,
            process_metrics_available = process_metrics_available,
            resident_memory_bytes = process.resident_memory_bytes,
            virtual_memory_bytes = process.virtual_memory_bytes,
            open_fds = process.open_fds,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_record_request() {
        let metrics = Metrics::new();
        metrics.record_request(200, 500); // 500us = 0.5ms
        assert_eq!(metrics.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_1ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.status_2xx.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_metrics_status_codes() {
        let metrics = Metrics::new();
        metrics.record_request(200, 100);
        metrics.record_request(301, 100);
        metrics.record_request(404, 100);
        metrics.record_request(502, 100);
        assert_eq!(metrics.status_2xx.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.status_3xx.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.status_4xx.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.status_5xx.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.requests_error_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_metrics_active_connections() {
        let metrics = Metrics::new();
        metrics.connect();
        metrics.connect();
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 2);
        metrics.disconnect();
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_render_prometheus() {
        let metrics = Metrics::new();
        metrics.record_protocol_request(true, true, true);
        metrics.record_request(200, 5000);
        metrics.record_cert_reload_success();
        metrics.record_cert_reload_error();
        metrics.record_cert_reload_skipped("oversize");
        metrics.record_cert_reload_skipped("invalid");
        metrics.record_cert_reload_skipped("empty");
        metrics.record_route_reload("service");
        metrics.set_consul_watcher_backoff_seconds("tls", 8);
        metrics.set_consul_watcher_last_index("tls", 42);
        metrics.record_consul_watcher_error("tls");
        metrics.set_cert_expiry_entries(vec![CertificateExpiryMetric {
            entry: "example.com.pem".to_string(),
            cn: "example.com".to_string(),
            not_after_unix: 1_700_000_000,
        }]);
        let output = metrics.render();
        assert!(output.contains("sentirum_lb_requests_total 1"));
        assert!(output.contains("sentirum_lb_request_duration_seconds_bucket"));
        let sum_line = output
            .lines()
            .find(|line| line.starts_with("sentirum_lb_request_duration_seconds_sum"))
            .expect("missing duration sum line");
        let sum: f64 = sum_line
            .split_whitespace()
            .nth(1)
            .expect("missing duration sum value")
            .parse()
            .expect("sum should parse as f64");
        assert!(
            (sum - 0.005_f64).abs() < 1e-9,
            "unexpected duration sum: {sum}"
        );
        assert!(output.contains("sentirum_lb_response_status_total"));
        assert!(output.contains("sentirum_lb_grpc_requests_total 1"));
        assert!(output.contains("sentirum_lb_grpc_web_requests_total 1"));
        assert!(output.contains("sentirum_lb_websocket_requests_total 1"));
        assert!(output.contains("sentirum_lb_process_resident_memory_bytes"));
        assert!(output.contains("sentirum_lb_process_open_fds"));
        assert!(output.contains("sentirum_lb_cert_reload_total 1"));
        assert!(output.contains("sentirum_lb_cert_reload_errors_total 1"));
        assert!(output.contains("sentirum_lb_cert_reload_skipped_total{reason=\"oversize\"} 1"));
        assert!(output.contains("sentirum_lb_route_reload_total{source=\"service\"} 1"));
        assert!(output.contains("sentirum_lb_consul_watcher_backoff_seconds{watcher=\"tls\"} 8"));
        assert!(output.contains("sentirum_lb_consul_watcher_last_index{watcher=\"tls\"} 42"));
        assert!(output.contains("sentirum_lb_consul_watcher_errors_total{watcher=\"tls\"} 1"));
        assert!(output.contains("sentirum_lb_cert_min_expiry_unix_seconds 1700000000"));
        assert!(output.contains("sentirum_lb_cert_expiry_unix_seconds{entry=\"example.com.pem\",cn=\"example.com\"} 1700000000"));
    }

    #[test]
    fn test_record_protocol_request_counters() {
        let metrics = Metrics::new();
        metrics.record_protocol_request(true, false, true);
        metrics.record_protocol_request(false, true, false);
        assert_eq!(metrics.grpc_requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.grpc_web_requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.websocket_requests_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_cert_expiry_entries_updates_min_expiry() {
        let metrics = Metrics::new();
        metrics.set_cert_expiry_entries(vec![
            CertificateExpiryMetric {
                entry: "b.pem".to_string(),
                cn: "b.example.com".to_string(),
                not_after_unix: 200,
            },
            CertificateExpiryMetric {
                entry: "a.pem".to_string(),
                cn: "a.example.com".to_string(),
                not_after_unix: 100,
            },
        ]);

        assert_eq!(
            metrics.cert_min_expiry_unix_seconds.load(Ordering::Relaxed),
            100
        );
        assert_eq!(
            metrics
                .cert_expiry_entries
                .read()
                .expect("cert expiry entries poisoned")
                .len(),
            2
        );
    }

    #[test]
    fn test_latency_buckets() {
        let metrics = Metrics::new();
        metrics.record_request(200, 500); // <=1ms
        metrics.record_request(200, 1_000); // boundary <=1ms
        metrics.record_request(200, 3_000); // <=5ms
        metrics.record_request(200, 8_000); // <=10ms
        metrics.record_request(200, 20_000); // <=25ms
        metrics.record_request(200, 80_000); // <=100ms
        metrics.record_request(200, 2_000_000); // <=5s

        assert_eq!(metrics.latency_bucket_1ms.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.latency_bucket_5ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_10ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_25ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_100ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_5s.load(Ordering::Relaxed), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_proc_status_value_bytes() {
        let status = "Name:\tsentirum-lb\nVmSize:\t  2048 kB\nVmRSS:\t  1024 kB\n";
        assert_eq!(
            parse_proc_status_value_bytes(status, "VmRSS:"),
            Some(1_048_576)
        );
        assert_eq!(
            parse_proc_status_value_bytes(status, "VmSize:"),
            Some(2_097_152)
        );
        assert_eq!(parse_proc_status_value_bytes(status, "VmData:"), None);
    }
}

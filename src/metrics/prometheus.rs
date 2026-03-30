//! Prometheus metrics for Sentirum LB.
//!
//! Tracks request latency histogram, request counter, active connections gauge,
//! and route-level metrics for observability.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
 // keep for future use with per-route metrics
use std::time::Instant;

/// Global metrics instance
static METRICS: std::sync::OnceLock<Metrics> = std::sync::OnceLock::new();

/// Get the global metrics instance
pub fn global() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

/// Core metrics for the load balancer
#[derive(Debug)]
pub struct Metrics {
    // --- Counters ---
    /// Total requests processed
    pub requests_total: AtomicU64,
    /// Total requests that resulted in an error
    pub requests_error_total: AtomicU64,
    /// Total bytes sent to downstream
    pub bytes_sent_total: AtomicU64,
    /// Total bytes received from upstream
    pub bytes_received_total: AtomicU64,

    // --- Gauges ---
    /// Currently active connections
    pub active_connections: AtomicI64,
    /// Number of routes in the routing table
    pub route_count: AtomicI64,
    /// Number of target backends
    pub target_count: AtomicI64,

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
            bytes_sent_total: AtomicU64::new(0),
            bytes_received_total: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            route_count: AtomicI64::new(0),
            target_count: AtomicI64::new(0),
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

        // Record latency bucket
        let latency_ms = latency_us / 1000;
        if latency_ms < 1 {
            self.latency_bucket_1ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 5 {
            self.latency_bucket_5ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 10 {
            self.latency_bucket_10ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 25 {
            self.latency_bucket_25ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 50 {
            self.latency_bucket_50ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 100 {
            self.latency_bucket_100ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 250 {
            self.latency_bucket_250ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 500 {
            self.latency_bucket_500ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 1000 {
            self.latency_bucket_1s.fetch_add(1, Ordering::Relaxed);
        } else if latency_ms < 5000 {
            self.latency_bucket_5s.fetch_add(1, Ordering::Relaxed);
        } else {
            self.latency_bucket_inf.fetch_add(1, Ordering::Relaxed);
        }

        // Record status code
        match status {
            200..=299 => { self.status_2xx.fetch_add(1, Ordering::Relaxed); }
            300..=399 => { self.status_3xx.fetch_add(1, Ordering::Relaxed); }
            400..=499 => {
                self.status_4xx.fetch_add(1, Ordering::Relaxed);
                self.requests_error_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => { self.status_5xx.fetch_add(1, Ordering::Relaxed); self.requests_error_total.fetch_add(1, Ordering::Relaxed); }
        }
    }

    /// Increment active connections
    pub fn connect(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections
    pub fn disconnect(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Generate Prometheus text exposition format
    pub fn render(&self) -> String {
        let requests_total = self.requests_total.load(Ordering::Relaxed);
        let requests_error_total = self.requests_error_total.load(Ordering::Relaxed);
        let active_connections = self.active_connections.load(Ordering::Relaxed);
        let route_count = self.route_count.load(Ordering::Relaxed);
        let target_count = self.target_count.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent_total.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received_total.load(Ordering::Relaxed);
        let status_2xx = self.status_2xx.load(Ordering::Relaxed);
        let status_3xx = self.status_3xx.load(Ordering::Relaxed);
        let status_4xx = self.status_4xx.load(Ordering::Relaxed);
        let status_5xx = self.status_5xx.load(Ordering::Relaxed);

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

# HELP sentirum_lb_bytes_sent_total Total bytes sent to downstream
# TYPE sentirum_lb_bytes_sent_total counter
sentirum_lb_bytes_sent_total {bytes_sent}

# HELP sentirum_lb_bytes_received_total Total bytes received from upstream
# TYPE sentirum_lb_bytes_received_total counter
sentirum_lb_bytes_received_total {bytes_received}

# HELP sentirum_lb_response_status_total Response status codes
# TYPE sentirum_lb_response_status_total counter
sentirum_lb_response_status_total{{code="2xx"}} {status_2xx}
sentirum_lb_response_status_total{{code="3xx"}} {status_3xx}
sentirum_lb_response_status_total{{code="4xx"}} {status_4xx}
sentirum_lb_response_status_total{{code="5xx"}} {status_5xx}

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
        )
    }
}

/// RAII guard that tracks request timing
pub struct RequestTimer {
    start: Instant,
}

impl Default for RequestTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestTimer {
    pub fn new() -> Self {
        let metrics = global();
        metrics.connect();
        Self { start: Instant::now() }
    }

    /// Complete the request and record metrics
    pub fn complete(self, status: u16) {
        let elapsed = self.start.elapsed().as_micros() as u64;
        let metrics = global();
        metrics.record_request(status, elapsed);
        metrics.disconnect();
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
        metrics.record_request(200, 5000);
        let output = metrics.render();
        assert!(output.contains("sentirum_lb_requests_total 1"));
        assert!(output.contains("sentirum_lb_request_duration_seconds_bucket"));
        assert!(output.contains("sentirum_lb_request_duration_seconds_sum 0.005"));
        assert!(output.contains("sentirum_lb_response_status_total"));
    }

    #[test]
    fn test_latency_buckets() {
        let metrics = Metrics::new();
        metrics.record_request(200, 500);    // <1ms
        metrics.record_request(200, 3000);   // 1-5ms
        metrics.record_request(200, 8000);   // 5-10ms
        metrics.record_request(200, 20000);  // 10-25ms
        metrics.record_request(200, 80000);  // 50-100ms
        metrics.record_request(200, 2000000); // 1-5s

        assert_eq!(metrics.latency_bucket_1ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_5ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_10ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_25ms.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_bucket_100ms.load(Ordering::Relaxed), 1);  // 80ms < 100ms
        assert_eq!(metrics.latency_bucket_5s.load(Ordering::Relaxed), 1);    // 2000ms < 5000ms
    }
}

use crate::route::definition::RouteSource;
use pingora::protocols::tls::ALPN;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UpstreamProtocol {
    #[default]
    Http,
    Https,
    Grpc,
    Grpcs,
    Ws,
    Wss,
    Tcp,
}

impl UpstreamProtocol {
    fn from_scheme_or_proto(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "grpc" => Some(Self::Grpc),
            "grpcs" => Some(Self::Grpcs),
            "ws" => Some(Self::Ws),
            "wss" => Some(Self::Wss),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }

    pub fn uses_tls(self) -> bool {
        matches!(self, Self::Https | Self::Grpcs | Self::Wss)
    }

    pub fn requires_http2(self) -> bool {
        matches!(self, Self::Grpc | Self::Grpcs)
    }

    pub fn is_websocket(self) -> bool {
        matches!(self, Self::Ws | Self::Wss)
    }

    pub fn default_port(self) -> Option<u16> {
        match self {
            Self::Http | Self::Ws => Some(80),
            Self::Https | Self::Wss => Some(443),
            Self::Grpc => Some(80),
            Self::Grpcs => Some(443),
            Self::Tcp => None,
        }
    }

    pub fn preferred_alpn(self) -> ALPN {
        if self.requires_http2() {
            ALPN::H2
        } else if self.is_websocket() {
            ALPN::H1
        } else {
            ALPN::H2H1
        }
    }
}

/// Circuit breaker state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CircuitState {
    /// Normal operation — requests flow through
    Closed,
    /// Circuit is open — requests fail fast with 503
    Open,
    /// Probing recovery — limited requests allowed
    HalfOpen,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self::Closed
    }
}

/// Immutable circuit breaker configuration
#[derive(Debug, Clone, Serialize)]
pub struct CircuitBreakerConfig {
    /// Error threshold percentage (e.g., 50 = 50%)
    pub error_threshold: u8,
    /// Number of requests to track in the sliding window
    pub window_size: usize,
    /// Seconds to stay open before probing recovery
    pub recovery_timeout_secs: u64,
    /// Max probe requests in half-open state
    pub half_open_max_requests: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            error_threshold: 50,
            window_size: 100,
            recovery_timeout_secs: 30,
            half_open_max_requests: 3,
        }
    }
}

/// Circuit breaker for per-target failure protection.

    /// Uses a sliding window of N requests to track error rate.
    /// When error_threshold % of requests in the window fail, the circuit opens.
    /// After recovery_timeout, the circuit enters half-open and allows N probe requests.
    /// All probes succeed → circuit closes. Any probe fails → circuit reopens.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Current circuit state (Arc-shared so clones preserve history across route rebuilds)
    state: Arc<parking_lot::Mutex<CircuitInner>>,
    /// Configuration (shared, read-only after init)
    config: CircuitBreakerConfig,
}

#[derive(Debug)]
struct CircuitInner {
    state: CircuitState,
    /// Sliding window: success (false) / error (true) per request
    window: std::collections::VecDeque<bool>,
    /// Time when circuit last transitioned to Open
    opened_at_ms: u64,
    /// Number of probe requests sent in half-open state
    half_open_requests: usize,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default config
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom config
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(parking_lot::Mutex::new(CircuitInner {
                state: CircuitState::Closed,
                window: std::collections::VecDeque::with_capacity(config.window_size),
                opened_at_ms: 0,
                half_open_requests: 0,
            })),
            config,
        }
    }

    /// Returns true if the circuit allows a request to proceed.
    /// If false, the caller should return 503 immediately.
    pub fn allow_request(&self) -> bool {
        let mut inner = self.state.lock();
        let now_ms = Self::now_ms();

        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let elapsed = now_ms.saturating_sub(inner.opened_at_ms);
                let recovery_ms = self.config.recovery_timeout_secs as u64 * 1000;
                if elapsed >= recovery_ms {
                    inner.state = CircuitState::HalfOpen;
                    inner.half_open_requests = 0;
                    tracing::info!(
                        recovery_timeout = self.config.recovery_timeout_secs,
                        "Circuit breaker transitioning to half-open"
                    );
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                inner.half_open_requests += 1;
                inner.half_open_requests <= self.config.half_open_max_requests
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let mut inner = self.state.lock();
        match inner.state {
            CircuitState::Closed => {
                Self::push_window(&mut inner, false, self.config.window_size);
            }
            CircuitState::HalfOpen => {
                // All probe requests succeeded → close the circuit
                inner.state = CircuitState::Closed;
                inner.window.clear();
                tracing::info!("Circuit breaker closed after successful recovery probes");
            }
            CircuitState::Open => {
                // Success while open shouldn't happen (requests are blocked),
                // but handle gracefully in case of race.
            }
        }
    }

    /// Record a failed request (5xx, timeout, connection error)
    pub fn record_error(&self) {
        let mut inner = self.state.lock();
        match inner.state {
            CircuitState::Closed => {
                Self::push_window(&mut inner, true, self.config.window_size);
                let error_count = inner.window.iter().filter(|&&e| e).count();
                let threshold = self.config.window_size * self.config.error_threshold as usize / 100;
                if error_count >= threshold && inner.window.len() >= self.config.window_size {
                    inner.state = CircuitState::Open;
                    inner.opened_at_ms = Self::now_ms();
                    tracing::warn!(
                        error_rate = format!("{:.1}%", 100.0 * error_count as f64 / self.config.window_size as f64),
                        error_count,
                        window_size = self.config.window_size,
                        threshold = threshold,
                        "Circuit breaker OPENED"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Any error in half-open → reopen immediately
                inner.state = CircuitState::Open;
                inner.opened_at_ms = Self::now_ms();
                tracing::warn!("Circuit breaker REOPENED — probe failed");
            }
            CircuitState::Open => {
                // Already open, refresh the timer on errors
                inner.opened_at_ms = Self::now_ms();
            }
        }
    }

    /// Get current circuit state (for metrics/admin)
    pub fn current_state(&self) -> CircuitState {
        self.state.lock().state
    }

    fn push_window(inner: &mut CircuitInner, is_error: bool, window_size: usize) {
        if inner.window.len() >= window_size {
            inner.window.pop_front();
        }
        inner.window.push_back(is_error);
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Clone preserves the shared state via Arc so that route-table rebuilds
/// do not reset circuit-breaker history.
impl Clone for CircuitBreaker {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            config: self.config.clone(),
        }
    }
}

 impl Default for CircuitBreaker {
     fn default() -> Self {
         Self::new()
     }
 }

/// Per-target health tracker (circuit breaker wrapper)
#[derive(Debug, Clone)]
pub struct TargetHealthTracker {
    circuit_breaker: CircuitBreaker,
}

impl TargetHealthTracker {
    pub fn new() -> Self {
        Self {
            circuit_breaker: CircuitBreaker::new(),
        }
    }

    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            circuit_breaker: CircuitBreaker::with_config(config),
        }
    }

    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }
}

impl Default for TargetHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DNS Cache (shared global instance)
// ============================================================================

/// Global DNS cache instance
static DNS_CACHE: std::sync::OnceLock<DnsCache> = std::sync::OnceLock::new();

/// Get the global DNS cache
pub fn global_dns_cache() -> &'static DnsCache {
    DNS_CACHE.get_or_init(DnsCache::new)
}

/// DNS cache entry with TTL and expiration
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// Resolved IP addresses
    addrs: Vec<SocketAddr>,
    /// Expiration timestamp (milliseconds since epoch)
    expires_at_ms: u64,
    /// Whether this was a negative lookup (NXDOMAIN)
    negative: bool,
}

/// Thread-safe DNS cache with TTL-based expiration
#[derive(Debug)]
pub struct DnsCache {
    inner: dashmap::DashMap<String, DnsCacheEntry>,
    /// Default TTL in seconds
    default_ttl_secs: u64,
    /// Negative cache TTL in seconds
    negative_ttl_secs: u64,
    /// Metrics reference
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    negatives: std::sync::atomic::AtomicU64,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: dashmap::DashMap::new(),
            default_ttl_secs: 30,
            negative_ttl_secs: 10,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            negatives: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn with_ttl(default_ttl_secs: u64, negative_ttl_secs: u64) -> Self {
        Self {
            inner: dashmap::DashMap::new(),
            default_ttl_secs,
            negative_ttl_secs,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            negatives: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set the TTL values
    pub fn set_ttl(&self, default_secs: u64, negative_secs: u64) {
        // Note: We can't modify OnceLock contents, but we can use a new instance
        // For simplicity, we'll use the configured values at creation time
    }

    /// Lookup a cached DNS entry
    pub fn lookup(&self, host: &str) -> Option<Vec<SocketAddr>> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Check expiry in a separate scope so the read guard is dropped before
        // the mutable remove() call — holding both on the same DashMap shard deadlocks.
        let expired = self
            .inner
            .get(host)
            .map_or(false, |e| now_ms >= e.expires_at_ms);
        if expired {
            self.inner.remove(host);
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }

        let entry = self.inner.get(host)?;

        if entry.negative {
            self.negatives.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }

        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(entry.addrs.clone())
    }

    /// Store a positive DNS lookup result
    pub fn store(&self, host: String, addrs: Vec<SocketAddr>) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = DnsCacheEntry {
            addrs,
            expires_at_ms: now_ms + (self.default_ttl_secs as u64 * 1000),
            negative: false,
        };

        self.inner.insert(host, entry);
    }

    /// Store a negative DNS lookup result (NXDOMAIN)
    pub fn store_negative(&self, host: String) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = DnsCacheEntry {
            addrs: Vec::new(),
            expires_at_ms: now_ms + (self.negative_ttl_secs as u64 * 1000),
            negative: true,
        };

        self.inner.insert(host, entry);
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> DnsCacheStats {
        DnsCacheStats {
            entries: self.inner.len() as u64,
            hits: self.hits.load(std::sync::atomic::Ordering::Relaxed),
            misses: self.misses.load(std::sync::atomic::Ordering::Relaxed),
            negatives: self.negatives.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS cache statistics
#[derive(Debug, Clone, Default)]
pub struct DnsCacheStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub negatives: u64,
}

impl std::fmt::Display for DnsCacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "entries={} hits={} misses={} negatives={}",
            self.entries, self.hits, self.misses, self.negatives
        )
    }
}


#[derive(Debug, Default)]
pub struct TargetStatsRegistry {
    active_connections: Mutex<HashMap<String, Weak<AtomicU64>>>,
}

impl TargetStatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active_connections_for(&self, key: &str) -> Arc<AtomicU64> {
        let mut entries = self.active_connections.lock().unwrap_or_else(|e| {
            tracing::warn!("Target stats registry lock was poisoned; recovering");
            e.into_inner()
        });

        if let Some(counter) = entries.get(key).and_then(Weak::upgrade) {
            return counter;
        }

        let counter = Arc::new(AtomicU64::new(0));
        entries.insert(key.to_string(), Arc::downgrade(&counter));
        counter
    }
}

/// A target backend for a route.
#[derive(Debug, Serialize, Deserialize)]
pub struct Target {
    /// Service name (e.g. "myservice")
    pub service: String,
    /// Target URL string (e.g. "http://10.0.0.1:8080/")
    pub url: String,
    /// Fixed weight for traffic distribution (0 = dynamic)
    #[serde(default)]
    pub fixed_weight: f64,
    /// Actual computed weight (percentage)
    #[serde(default)]
    pub weight: f64,
    /// Tags from Consul service
    #[serde(default)]
    pub tags: Vec<String>,
    /// Route options
    #[serde(default)]
    pub opts: HashMap<String, String>,
    /// Origin of the target definition
    #[serde(default)]
    pub source: RouteSource,

    // --- Pre-parsed fields (not serialized, computed from url) ---
    /// Pre-parsed host from URL
    #[serde(skip)]
    pub parsed_host: Option<String>,
    /// Pre-parsed port from URL
    #[serde(skip)]
    pub parsed_port: Option<u16>,
    /// Whether upstream uses TLS
    #[serde(skip)]
    pub parsed_tls: bool,
    /// Parsed upstream transport protocol
    #[serde(skip)]
    pub parsed_protocol: UpstreamProtocol,
    /// Active connection count for least-connections picker
    #[serde(skip)]
    pub active_connections: Arc<AtomicU64>,
    /// Circuit breaker for upstream failure protection
    #[serde(skip)]
    pub health_tracker: TargetHealthTracker,
}

impl Clone for Target {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            url: self.url.clone(),
            fixed_weight: self.fixed_weight,
            weight: self.weight,
            tags: self.tags.clone(),
            opts: self.opts.clone(),
            source: self.source.clone(),
            parsed_host: self.parsed_host.clone(),
            parsed_port: self.parsed_port,
            parsed_tls: self.parsed_tls,
            parsed_protocol: self.parsed_protocol,
            active_connections: Arc::clone(&self.active_connections),
            health_tracker: self.health_tracker.clone(),
        }
    }
}

impl Default for Target {
    fn default() -> Self {
        Self {
            service: String::new(),
            url: String::new(),
            fixed_weight: 0.0,
            weight: 0.0,
            tags: Vec::new(),
            opts: HashMap::new(),
            source: RouteSource::Static,
            parsed_host: None,
            parsed_port: None,
            parsed_tls: false,
            parsed_protocol: UpstreamProtocol::Http,
            active_connections: Arc::new(AtomicU64::new(0)),
            health_tracker: TargetHealthTracker::new(),
        }
    }
}

impl Target {
    /// Create a new target with URL auto-parsed.
    pub fn new(service: String, url: String) -> Self {
        let mut target = Self {
            service,
            url,
            ..Default::default()
        };
        target.pre_parse();
        target
    }

    pub fn with_active_connections(
        service: String,
        url: String,
        active_connections: Arc<AtomicU64>,
    ) -> Self {
        let mut target = Self {
            service,
            url,
            active_connections,
            ..Default::default()
        };
        target.pre_parse();
        target
    }

    /// Pre-parse the URL once to avoid per-request parsing.
    /// Also validates against SSRF risks (private/loopback IPs).
    pub fn pre_parse(&mut self) {
        if let Ok(parsed) = url::Url::parse(&self.url) {
            self.parsed_host = parsed.host_str().map(|h| h.to_string());
            self.parsed_protocol = self
                .opts
                .get("proto")
                .and_then(|proto| UpstreamProtocol::from_scheme_or_proto(proto))
                .or_else(|| UpstreamProtocol::from_scheme_or_proto(parsed.scheme()))
                .unwrap_or(UpstreamProtocol::Http);
            self.parsed_port = parsed
                .port()
                .or_else(|| self.parsed_protocol.default_port())
                .or_else(|| parsed.port_or_known_default());
            self.parsed_tls = self.parsed_protocol.uses_tls();
        }
    }

    /// Check if the upstream host is safe for proxying.
    /// Consul-origin routes may use RFC1918/private IPs by default, but loopback,
    /// link-local, unspecified, and localhost-style hosts remain blocked unless
    /// explicitly bypassed.
    pub fn is_host_safe(&self) -> bool {
        let host = match self.parsed_host.as_deref() {
            Some(h) => h.trim_matches(&['[', ']'][..]),
            None => return false,
        };

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_ip_always_blocked(&ip) {
                return false;
            }
            if is_ip_rfc1918(&ip) {
                return self.source_allows_private_upstreams();
            }
            return true;
        }

        let lower = host.to_lowercase();
        if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
            return false;
        }

        true
    }

    /// Whether SSRF protection is explicitly bypassed for this target.
    pub fn ssrf_skip_verify(&self) -> bool {
        self.opts
            .get("ssrfskipverify")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    pub fn source_allows_private_upstreams(&self) -> bool {
        matches!(
            self.source,
            RouteSource::ConsulKv | RouteSource::ConsulService
        )
    }

    pub fn try_acquire_connection_slot(&self, max_connections: u64) -> bool {
        if max_connections == 0 {
            self.active_connections.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        let mut current = self.active_connections.load(Ordering::Relaxed);
        loop {
            if current >= max_connections {
                return false;
            }
            match self.active_connections.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn release_connection_slot(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub async fn resolve_upstream_addr(&self) -> Result<SocketAddr, std::io::Error> {
        if !self.is_host_safe() && !self.ssrf_skip_verify() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "blocked private/reserved upstream target {}",
                    self.upstream_host()
                ),
            ));
        }

        let host = self.upstream_host();
        let port = self.upstream_port();
        let cache_key = format!("{host}:{port}");

        // Try DNS cache first
        let cache = global_dns_cache();
        if let Some(addrs) = cache.lookup(&cache_key) {
            if let Some(addr) = addrs.first() {
                tracing::trace!(host, port, "DNS cache hit");
                return Ok(*addr);
            }
        }

        let addr_str = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };

        // DNS lookup
        let mut addrs = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs,
            Err(e) => {
                // Store negative result
                cache.store_negative(cache_key.clone());
                tracing::warn!(host, port, error = %e, "DNS lookup failed, storing negative result");
                return Err(e);
            }
        };

        let resolved = addrs.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no upstream IP addresses found for {host}:{port}"),
            )
        })?;

        if !self.ssrf_skip_verify()
            && (is_ip_always_blocked(&resolved.ip())
                || (!self.source_allows_private_upstreams() && is_ip_rfc1918(&resolved.ip())))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "blocked upstream target during resolution {} -> {}",
                    host,
                    resolved.ip()
                ),
            ));
        }

        // Cache successful result
        let addr_list: Vec<SocketAddr> = addrs.collect();
        if !addr_list.is_empty() {
            cache.store(cache_key, addr_list);
        }

        Ok(resolved)
    }

    /// Get the upstream host (pre-parsed, no allocation)
    pub fn upstream_host(&self) -> &str {
        self.parsed_host
            .as_deref()
            .map(|h| h.trim_matches(&['[', ']'][..]))
            .unwrap_or("127.0.0.1")
    }

    /// Get the upstream port (pre-parsed)
    pub fn upstream_port(&self) -> u16 {
        self.parsed_port
            .or_else(|| self.parsed_protocol.default_port())
            .unwrap_or(80)
    }

    /// Whether upstream uses TLS
    pub fn upstream_tls(&self) -> bool {
        self.parsed_tls
    }

    pub fn upstream_protocol(&self) -> UpstreamProtocol {
        self.parsed_protocol
    }

    pub fn requires_http2(&self) -> bool {
        self.parsed_protocol.requires_http2()
    }

    pub fn preferred_alpn(&self) -> ALPN {
        self.parsed_protocol.preferred_alpn()
    }

    pub fn is_websocket(&self) -> bool {
        self.parsed_protocol.is_websocket()
    }

    /// Get the strip path option.
    pub fn strip_path(&self) -> Option<&str> {
        self.opts.get("strip").map(|s| s.as_str())
    }

    /// Get the prepend path option.
    pub fn prepend_path(&self) -> Option<&str> {
        self.opts.get("prepend").map(|s| s.as_str())
    }

    /// Whether to skip TLS verification for upstream.
    pub fn tls_skip_verify(&self) -> bool {
        self.opts
            .get("tlsskipverify")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    /// Whether this is a TCP proxy target.
    pub fn is_tcp(&self) -> bool {
        self.parsed_protocol == UpstreamProtocol::Tcp
    }

    /// Whether to prepend a PROXY protocol v1 header on upstream TCP connects.
    pub fn proxy_proto(&self) -> bool {
        self.opts
            .get("pxyproto")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    /// Whether this is an HTTPS upstream target.
    pub fn is_https(&self) -> bool {
        self.parsed_protocol == UpstreamProtocol::Https
    }

    pub fn is_grpc(&self) -> bool {
        matches!(
            self.parsed_protocol,
            UpstreamProtocol::Grpc | UpstreamProtocol::Grpcs
        )
    }

    /// Get the host header override.
    pub fn host_override(&self) -> Option<&str> {
        self.opts.get("host").map(|s| s.as_str())
    }

    pub fn upstream_authority(&self) -> String {
        if let Some(host) = self.host_override() {
            return host.to_string();
        }

        let host = self.upstream_host();
        let port = self.upstream_port();
        match self.parsed_protocol.default_port() {
            Some(default_port) if default_port == port => host.to_string(),
            _ => format!("{host}:{port}"),
        }
    }
}

/// Check if an IP address is private/reserved and should be blocked for SSRF protection.
pub fn is_ip_private(ip: &std::net::IpAddr) -> bool {
    is_ip_always_blocked(ip) || is_ip_rfc1918(ip)
}

pub fn is_ip_rfc1918(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => is_ipv6_unique_local(v6),
    }
}

pub fn is_ip_always_blocked(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local()
        }
    }
}

fn is_ipv6_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_blocks_private_ips() {
        let t = Target::new("svc".into(), "http://10.0.0.1:8080/".into());
        assert!(!t.is_host_safe()); // RFC1918

        let t = Target::new("svc".into(), "http://192.168.1.1:8080/".into());
        assert!(!t.is_host_safe()); // RFC1918

        let t = Target::new("svc".into(), "http://172.16.0.1:8080/".into());
        assert!(!t.is_host_safe()); // RFC1918

        let t = Target::new("svc".into(), "http://127.0.0.1:8080/".into());
        assert!(!t.is_host_safe()); // Loopback

        let t = Target::new("svc".into(), "http://169.254.169.254:80/".into());
        assert!(!t.is_host_safe()); // Cloud metadata
    }

    #[test]
    fn test_ssrf_allows_public_ips() {
        let t = Target::new("svc".into(), "http://8.8.8.8:80/".into());
        assert!(t.is_host_safe());

        let t = Target::new("svc".into(), "http://1.2.3.4:80/".into());
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_ssrf_blocks_localhost_hostname() {
        let t = Target::new("svc".into(), "http://localhost:8080/".into());
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_ssrf_allows_normal_hostnames() {
        let t = Target::new("svc".into(), "http://api.example.com/".into());
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_consul_sources_allow_private_rfc1918_hosts() {
        let mut t = Target::new("svc".into(), "http://10.0.0.1:8080/".into());
        t.source = RouteSource::ConsulService;
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_consul_sources_still_block_loopback_hosts() {
        let mut t = Target::new("svc".into(), "http://127.0.0.1:8080/".into());
        t.source = RouteSource::ConsulService;
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_static_sources_block_ipv6_unique_local_hosts() {
        let t = Target::new("svc".into(), "http://[fd00::1]:8080/".into());
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_consul_sources_allow_ipv6_unique_local_hosts() {
        let mut t = Target::new("svc".into(), "http://[fd00::1]:8080/".into());
        t.source = RouteSource::ConsulService;
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_ipv6_link_local_hosts_are_blocked() {
        let t = Target::new("svc".into(), "http://[fe80::1]:8080/".into());
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_ssrf_skip_verify_opt() {
        let mut t = Target::new("svc".into(), "http://10.0.0.1:8080/".into());
        t.opts
            .insert("ssrfskipverify".to_string(), "true".to_string());
        assert!(t.ssrf_skip_verify());
    }

    #[test]
    fn test_proxy_proto_opt() {
        let mut t = Target::new("svc".into(), "tcp://10.0.0.1:4222".into());
        assert!(!t.proxy_proto());
        t.opts.insert("pxyproto".to_string(), "true".to_string());
        assert!(t.proxy_proto());
    }

    #[test]
    fn test_grpcs_targets_use_tls_and_require_http2() {
        let t = Target::new("svc".into(), "grpcs://api.example.com/".into());
        assert!(t.upstream_tls());
        assert!(t.requires_http2());
        assert!(t.is_grpc());
        assert_eq!(t.upstream_port(), 443);
    }

    #[test]
    fn test_wss_targets_use_tls_without_requiring_http2() {
        let t = Target::new("svc".into(), "wss://api.example.com/socket".into());
        assert!(t.upstream_tls());
        assert!(t.is_websocket());
        assert!(!t.requires_http2());
        assert_eq!(t.upstream_port(), 443);
    }

    #[test]
    fn test_proto_option_overrides_url_scheme_for_grpc() {
        let mut t = Target::new("svc".into(), "http://api.example.com/service".into());
        t.opts.insert("proto".into(), "grpc".into());
        t.pre_parse();
        assert_eq!(t.upstream_protocol(), UpstreamProtocol::Grpc);
        assert!(t.requires_http2());
        assert!(!t.upstream_tls());
    }

    #[test]
    fn test_websocket_targets_force_h1_alpn() {
        let t = Target::new("svc".into(), "wss://api.example.com/socket".into());
        assert_eq!(t.preferred_alpn().get_max_http_version(), 1);
        assert_eq!(t.preferred_alpn().get_min_http_version(), 1);
    }

    // === Circuit Breaker Tests ===

    #[test]
    fn test_circuit_breaker_default_state_is_closed() {
        let cb = CircuitBreaker::new();
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_circuit_breaker_opens_after_error_threshold() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 30,
            half_open_max_requests: 3,
        };
        let cb = CircuitBreaker::with_config(config);

        // First 5 requests succeed
        for _ in 0..5 {
            cb.record_success();
        }
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert!(cb.allow_request());

        // Next 5 requests fail (50% error rate)
        for _ in 0..5 {
            cb.record_error();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_circuit_breaker_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0, // Immediate transition
            half_open_max_requests: 3,
        };
        let cb = CircuitBreaker::with_config(config);

        // Open the circuit
        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);

        // With 0s timeout, next allow_request transitions to half-open
        assert!(cb.allow_request());
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_breaker_closes_after_successful_probes() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 3,
        };
        let cb = CircuitBreaker::with_config(config);

        // Open the circuit
        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);

        // Transition to half-open
        assert!(cb.allow_request());
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        // Successful probes close the circuit
        cb.record_success();
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_reopens_on_error_in_half_open() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 3,
        };
        let cb = CircuitBreaker::with_config(config);

        // Open the circuit
        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);

        // Transition to half-open
        assert!(cb.allow_request());
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        // Any error reopens the circuit
        cb.record_error();
        assert_eq!(cb.current_state(), CircuitState::Open);
    }
}

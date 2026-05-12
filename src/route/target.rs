use crate::route::definition::RouteSource;
use pingora::protocols::tls::ALPN;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use parking_lot::Mutex as ParkingMutex;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum CircuitState {
    /// Normal operation — requests flow through
    #[default]
    Closed,
    /// Circuit is open — requests fail fast with 503
    Open,
    /// Probing recovery — limited requests allowed
    HalfOpen,
}

/// Record of a circuit breaker state transition
#[derive(Debug, Clone, Serialize)]
pub struct CircuitTransition {
    pub from: CircuitState,
    pub to: CircuitState,
    pub timestamp_ms: u64,
}


/// Immutable circuit breaker configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
///
/// Atomic circuit breaker for high-concurrency hot paths.
/// Uses atomic operations instead of Mutex for the fast path (allow_request).
/// Only uses Mutex for window modifications (record_success/error).
///
/// State encoding in a single u8:
///   bits 0-1: CircuitState (Closed=0, Open=1, HalfOpen=2)
///   bits 2-7: probe counter (only valid in HalfOpen)

#[derive(Debug)]
pub struct CircuitBreaker {
    /// Atomic state byte: bits 0-1 = state, bits 2-7 = probe_counter
    state_atomic: AtomicU8,
    /// Recovery timeout in seconds
    recovery_timeout_secs: AtomicU64,
    /// Error threshold percentage
    error_threshold: u8,
    /// Window size
    window_size: usize,
    /// Max probe requests in half-open state
    half_open_max_requests: usize,
    /// Sliding window: Arc shared so clones preserve history across route rebuilds
    window: Arc<ParkingMutex<VecDeque<bool>>>,
    /// Time when circuit last transitioned to Open (milliseconds)
    opened_at_ms: AtomicU64,
    /// Whether a half-open probe is currently in flight.
    half_open_in_flight: AtomicBool,
    /// Lock for window modifications only (fine-grained, not on hot path)
    window_lock: std::sync::Mutex<()>,
    /// History of recent state transitions (ring buffer, max 20)
    history: Arc<ParkingMutex<Vec<CircuitTransition>>>,
}

const STATE_MASK: u8 = 0x03;
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;


impl CircuitBreaker {
    /// Create a new circuit breaker with default config
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom config.
    /// Clamps `half_open_max_requests` to 63 because the probe counter
    /// is packed into bits 2-7 of the atomic state byte (6 bits).
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            state_atomic: AtomicU8::new(STATE_CLOSED),
            recovery_timeout_secs: AtomicU64::new(config.recovery_timeout_secs),
            error_threshold: config.error_threshold,
            window_size: config.window_size,
            half_open_max_requests: config.half_open_max_requests.min(63),
            window: Arc::new(ParkingMutex::new(VecDeque::with_capacity(config.window_size))),
            opened_at_ms: AtomicU64::new(0),
            half_open_in_flight: AtomicBool::new(false),
            window_lock: std::sync::Mutex::new(()),
            history: Arc::new(ParkingMutex::new(Vec::with_capacity(20))),
        }
    }

    /// Returns true if the circuit could accept a request.
    /// This does not reserve a half-open probe slot.
    #[inline]
    pub fn can_accept_request(&self) -> bool {
        let state = self.state_atomic.load(Ordering::Acquire);
        match state & STATE_MASK {
            STATE_CLOSED => true,
            STATE_OPEN => self.recovery_elapsed(),
            STATE_HALF_OPEN => {
                let probe_count = ((state >> 2) & 0x3F) as usize;
                probe_count < self.half_open_max_requests
                    && !self.half_open_in_flight.load(Ordering::Acquire)
            }
            _ => false,
        }
    }

    /// Returns true if the circuit allows a request to proceed.
    /// In half-open state this reserves the next probe slot.
    #[inline]
    pub fn allow_request(&self) -> bool {
        loop {
            let state = self.state_atomic.load(Ordering::Acquire);
            match state & STATE_MASK {
                STATE_CLOSED => return true,
                STATE_OPEN => {
                    if !self.recovery_elapsed() {
                        return false;
                    }
                    if !self.try_transition_to_half_open() {
                        return false;
                    }
                }
                STATE_HALF_OPEN => {
                    let probe_count = ((state >> 2) & 0x3F) as usize;
                    if probe_count >= self.half_open_max_requests {
                        return false;
                    }
                    return self
                        .half_open_in_flight
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok();
                }
                _ => return false,
            }
        }
    }

    #[inline]
    fn recovery_elapsed(&self) -> bool {
        let recovery_timeout = self.recovery_timeout_secs.load(Ordering::Relaxed);
        let opened_at = self.opened_at_ms.load(Ordering::Relaxed);
        let elapsed = now_ms().saturating_sub(opened_at);
        elapsed >= recovery_timeout * 1000
    }

    /// Atomic transition to HalfOpen state
    #[inline(always)]
    fn try_transition_to_half_open(&self) -> bool {
        let current = self.state_atomic.load(Ordering::Acquire);
        let current_state = current & STATE_MASK;

        if current_state == STATE_HALF_OPEN {
            return true;
        }
        if current_state == STATE_CLOSED {
            return true;
        }

        match self
            .state_atomic
            .compare_exchange(current, STATE_HALF_OPEN, Ordering::AcqRel, Ordering::Relaxed)
        {
            Ok(_) => {
                self.half_open_in_flight.store(false, Ordering::Release);
                self.record_transition(CircuitState::Open, CircuitState::HalfOpen);
                tracing::info!(
                    recovery_timeout = self.recovery_timeout_secs.load(Ordering::Relaxed),
                    "Circuit breaker transitioning to half-open"
                );
                true
            }
            Err(actual) => (actual & STATE_MASK) != STATE_OPEN,
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let state = self.state_atomic.load(Ordering::Acquire);
        match state & STATE_MASK {
            STATE_CLOSED => {
                let _guard = self.window_lock.lock();
                let mut window = self.window.lock();
                if window.len() >= self.window_size { window.pop_front(); }
                window.push_back(false);
            }
            STATE_HALF_OPEN => {
                self.half_open_in_flight.store(false, Ordering::Release);
                let probe_count = ((state >> 2) & 0x3F) as usize;
                if probe_count + 1 >= self.half_open_max_requests {
                    self.transition_to_closed();
                    tracing::info!("Circuit breaker closed after successful recovery probes");
                } else {
                    let _ = self.state_atomic.compare_exchange(
                        state,
                        STATE_HALF_OPEN | (((probe_count + 1) as u8) << 2),
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
            }
            _ => {}
        }
    }

    /// Record a failed request (5xx, timeout, connection error)
    pub fn record_error(&self) {
        let state = self.state_atomic.load(Ordering::Acquire);
        match state & STATE_MASK {
            STATE_CLOSED => {
                {
                    let mut window = self.window.lock();
                    if window.len() >= self.window_size { window.pop_front(); }
                    window.push_back(true);
                }
                let window = self.window.lock();
                let error_count = window.iter().filter(|&&e| e).count();
                let threshold = self.window_size * self.error_threshold as usize / 100;
                if error_count >= threshold && window.len() >= self.window_size {
                    drop(window);
                    self.transition_to_open();
                    tracing::warn!(
                        error_rate = format!("{:.1}%", 100.0 * error_count as f64 / self.window_size as f64),
                        error_count, window_size = self.window_size, threshold = threshold,
                        "Circuit breaker OPENED"
                    );
                }
            }
            STATE_HALF_OPEN => {
                self.half_open_in_flight.store(false, Ordering::Release);
                self.transition_to_open();
                tracing::warn!("Circuit breaker REOPENED — probe failed");
            }
            STATE_OPEN => {
                self.opened_at_ms.store(now_ms(), Ordering::Relaxed);
            }
            _ => {}
        }
    }

    #[inline(always)]
    fn transition_to_open(&self) {
        self.opened_at_ms.store(now_ms(), Ordering::Relaxed);
        self.half_open_in_flight.store(false, Ordering::Release);
        let mut attempts = 0u32;
        loop {
            let current = self.state_atomic.load(Ordering::Acquire);
            let from = match current & STATE_MASK {
                STATE_CLOSED => CircuitState::Closed,
                STATE_HALF_OPEN => CircuitState::HalfOpen,
                STATE_OPEN => CircuitState::Open,
                _ => CircuitState::Closed,
            };
            match self
                .state_atomic
                .compare_exchange(current, STATE_OPEN, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    self.record_open_transition(from);
                    break;
                }
                Err(actual) if actual & STATE_MASK == STATE_OPEN => break,
                Err(_) => {
                    attempts += 1;
                    if attempts >= 64 {
                        tracing::warn!(
                            attempts,
                            "transition_to_open: CAS contention after 64 attempts, forcing open"
                        );
                        self.state_atomic.store(STATE_OPEN, Ordering::Release);
                        self.record_open_transition(from);
                        break;
                    }
                    std::hint::spin_loop();
                }
            }
        }
    }

    #[inline(always)]
    fn transition_to_closed(&self) {
        let current = self.state_atomic.load(Ordering::Relaxed);
        self.half_open_in_flight.store(false, Ordering::Release);
        if self
            .state_atomic
            .compare_exchange(current, STATE_CLOSED, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            crate::metrics::prometheus::global()
                .circuit_breaker_close_total
                .fetch_add(1, Ordering::Relaxed);
        }
        let mut window = self.window.lock();
        window.clear();
    }

    #[inline]
    fn record_open_transition(&self, from: CircuitState) {
        if from == CircuitState::Open {
            return;
        }
        self.record_transition(from, CircuitState::Open);
        let metrics = crate::metrics::prometheus::global();
        match from {
            CircuitState::HalfOpen => {
                metrics
                    .circuit_breaker_reopen_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            CircuitState::Closed => {
                metrics
                    .circuit_breaker_open_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            CircuitState::Open => {}
        }
    }

    #[inline]
    pub fn current_state(&self) -> CircuitState {
        match self.state_atomic.load(Ordering::Acquire) & STATE_MASK {
            STATE_CLOSED => CircuitState::Closed,
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    #[inline]
    fn record_transition(&self, from: CircuitState, to: CircuitState) {
        let mut history = self.history.lock();
        if history.len() >= 20 { history.remove(0); }
        history.push(CircuitTransition { from, to, timestamp_ms: now_ms() });
    }

    pub fn transition_history(&self) -> Vec<CircuitTransition> {
        self.history.lock().clone()
    }
}

#[inline]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Clone preserves the shared state via Arc so that route-table rebuilds
/// do not reset circuit-breaker history.
impl Clone for CircuitBreaker {
    fn clone(&self) -> Self {
        Self {
            state_atomic: AtomicU8::new(self.state_atomic.load(Ordering::Relaxed)),
            recovery_timeout_secs: AtomicU64::new(self.recovery_timeout_secs.load(Ordering::Relaxed)),
            error_threshold: self.error_threshold,
            window_size: self.window_size,
            half_open_max_requests: self.half_open_max_requests,
            window: Arc::clone(&self.window),
            opened_at_ms: AtomicU64::new(self.opened_at_ms.load(Ordering::Relaxed)),
            half_open_in_flight: AtomicBool::new(
                self.half_open_in_flight.load(Ordering::Relaxed),
            ),
            window_lock: std::sync::Mutex::new(()),
            history: Arc::clone(&self.history),
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
    default_ttl_secs: AtomicU64,
    /// Negative cache TTL in seconds
    negative_ttl_secs: AtomicU64,
    /// Local counters (fast, no indirection)
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    negatives: std::sync::atomic::AtomicU64,
    /// Cached reference to global Prometheus metrics (avoids OnceLock lookup per hit)
    prom: &'static crate::metrics::prometheus::Metrics,
}

/// Maximum number of entries in the DNS cache before eviction kicks in.
const DNS_CACHE_MAX_ENTRIES: usize = 10_000;

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: dashmap::DashMap::new(),
            default_ttl_secs: AtomicU64::new(30),
            negative_ttl_secs: AtomicU64::new(10),
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            negatives: std::sync::atomic::AtomicU64::new(0),
            prom: crate::metrics::prometheus::global(),
        }
    }

    pub fn with_ttl(default_ttl_secs: u64, negative_ttl_secs: u64) -> Self {
        Self {
            inner: dashmap::DashMap::new(),
            default_ttl_secs: AtomicU64::new(default_ttl_secs),
            negative_ttl_secs: AtomicU64::new(negative_ttl_secs),
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            negatives: std::sync::atomic::AtomicU64::new(0),
            prom: crate::metrics::prometheus::global(),
        }
    }

    /// Set the TTL values (thread-safe, can be called after OnceLock init)
    pub fn set_ttl(&self, default_secs: u64, negative_secs: u64) {
        let previous_default = self.default_ttl_secs.swap(default_secs, Ordering::Relaxed);
        let previous_negative = self.negative_ttl_secs.swap(negative_secs, Ordering::Relaxed);
        if previous_default != default_secs || previous_negative != negative_secs {
            self.clear();
        }
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
            .is_some_and(|e| now_ms >= e.expires_at_ms);
        if expired {
            self.inner.remove(host);
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.prom.dns_cache_misses_total.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let Some(entry) = self.inner.get(host) else {
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.prom.dns_cache_misses_total.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        if entry.negative {
            self.negatives.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.prom.dns_cache_negatives_total.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.prom.dns_cache_hits_total.fetch_add(1, Ordering::Relaxed);
        Some(entry.addrs.clone())
    }

    /// Store a positive DNS lookup result
    pub fn store(&self, host: String, addrs: Vec<SocketAddr>) {
        let ttl_secs = self.default_ttl_secs.load(Ordering::Relaxed);
        if ttl_secs == 0 {
            return;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = DnsCacheEntry {
            addrs,
            expires_at_ms: now_ms + (ttl_secs * 1000),
            negative: false,
        };

        self.inner.insert(host, entry);
        self.evict_if_over_capacity(now_ms);
    }

    /// Store a negative DNS lookup result (NXDOMAIN)
    pub fn store_negative(&self, host: String) {
        let ttl_secs = self.negative_ttl_secs.load(Ordering::Relaxed);
        if ttl_secs == 0 {
            return;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = DnsCacheEntry {
            addrs: Vec::new(),
            expires_at_ms: now_ms + (ttl_secs * 1000),
            negative: true,
        };

        self.inner.insert(host, entry);
        self.evict_if_over_capacity(now_ms);
    }

    /// Evict entries when the cache exceeds DNS_CACHE_MAX_ENTRIES.
    /// First removes expired entries (lazy TTL cleanup). If still over capacity,
    /// removes the oldest entries by expiration time.
    fn evict_if_over_capacity(&self, now_ms: u64) {
        if self.inner.len() <= DNS_CACHE_MAX_ENTRIES {
            return;
        }

        // Phase 1: Remove expired entries
        let expired_keys: Vec<String> = self
            .inner
            .iter()
            .filter(|e| now_ms >= e.expires_at_ms)
            .map(|e| e.key().clone())
            .collect();
        for key in expired_keys {
            self.inner.remove(&key);
        }

        if self.inner.len() <= DNS_CACHE_MAX_ENTRIES {
            return;
        }

        // Phase 2: Remove oldest entries by expires_at_ms until under capacity
        let mut entries: Vec<(String, u64)> = self
            .inner
            .iter()
            .map(|e| (e.key().clone(), e.expires_at_ms))
            .collect();
        entries.sort_by_key(|(_, exp)| *exp);

        let to_remove = self.inner.len() - DNS_CACHE_MAX_ENTRIES;
        for (key, _) in entries.into_iter().take(to_remove) {
            self.inner.remove(&key);
        }
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


    /// Get all cached entries with expiration info (for admin API).
    pub fn entries(&self) -> Vec<DnsCacheEntryView> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        self.inner.iter()
            .map(|entry| {
                let ttl_remaining_ms = entry.expires_at_ms.saturating_sub(now_ms);
                DnsCacheEntryView {
                    host: entry.key().clone(),
                    addrs: entry.addrs.iter().map(|a| a.to_string()).collect(),
                    ttl_remaining_secs: ttl_remaining_ms as i64 / 1000,
                    is_negative: entry.negative,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsCacheEntryView {
    pub host: String,
    pub addrs: Vec<String>,
    pub ttl_remaining_secs: i64,
    pub is_negative: bool,
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
    stats: Mutex<HashMap<String, Weak<TargetStats>>>,
    health_trackers: Mutex<HashMap<String, Weak<TargetHealthTracker>>>,
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

    pub fn stats_for(&self, key: &str) -> Arc<TargetStats> {
        let mut entries = self.stats.lock().unwrap_or_else(|e| {
            tracing::warn!("Target stats registry lock was poisoned; recovering");
            e.into_inner()
        });

        if let Some(stats) = entries.get(key).and_then(Weak::upgrade) {
            return stats;
        }

        let stats = Arc::new(TargetStats::default());
        entries.insert(key.to_string(), Arc::downgrade(&stats));
        stats
    }

    pub fn health_tracker_for(
        &self,
        key: &str,
        cb_config: Option<&CircuitBreakerConfig>,
    ) -> Arc<TargetHealthTracker> {
        let mut entries = self.health_trackers.lock().unwrap_or_else(|e| {
            tracing::warn!("Target health registry lock was poisoned; recovering");
            e.into_inner()
        });

        if let Some(tracker) = entries.get(key).and_then(Weak::upgrade) {
            return tracker;
        }

        let tracker = Arc::new(
            cb_config
                .cloned()
                .map(TargetHealthTracker::with_config)
                .unwrap_or_default(),
        );
        entries.insert(key.to_string(), Arc::downgrade(&tracker));
        tracker
    }

    pub fn clear_health_trackers(&self) {
        let mut entries = self.health_trackers.lock().unwrap_or_else(|e| {
            tracing::warn!("Target health registry lock was poisoned; recovering");
            e.into_inner()
        });
        entries.clear();
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
    pub health_tracker: Arc<TargetHealthTracker>,
    #[serde(skip)]
    pub stats: Arc<TargetStats>,
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
            health_tracker: Arc::clone(&self.health_tracker),
            stats: Arc::clone(&self.stats),
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
            health_tracker: Arc::new(TargetHealthTracker::new()),
            stats: Arc::new(TargetStats::default()),
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
        if let Some(addrs) = cache.lookup(&cache_key)
            && let Some(addr) = addrs.first()
        {
            tracing::trace!(host, port, "DNS cache hit");
            if !self.ssrf_skip_verify()
                && (is_ip_always_blocked(&addr.ip())
                    || (!self.source_allows_private_upstreams() && is_ip_rfc1918(&addr.ip())))
            {
                // Stale cached address fails SSRF check — evict and re-resolve
                cache.inner.remove(&cache_key);
                tracing::warn!(host, port, addr = %addr, "DNS cache hit failed SSRF check, re-resolving");
            } else {
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


        // Cache ALL addresses, filtering out any that fail SSRF checks.
        // This prevents a blocked IP from hiding in the multi-A-record tail
        // and being served on a subsequent cache hit.
        let mut addr_list = vec![resolved];
        for addr in addrs {
            if !self.ssrf_skip_verify()
                && (is_ip_always_blocked(&addr.ip())
                    || (!self.source_allows_private_upstreams() && is_ip_rfc1918(&addr.ip())))
            {
                tracing::debug!(
                    host,
                    addr = %addr,
                    "Filtered blocked IP from DNS multi-record response"
                );
                continue;
            }
            addr_list.push(addr);
        }
        cache.store(cache_key, addr_list);

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
            if v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_unspecified() || v4.is_multicast() {
                return true;
            }
            let octets = v4.octets();
            // CGNAT / Shared address space (100.64.0.0/10, RFC 6598)
            let is_cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 0x40;
            // Documentation / benchmark ranges (RFC 5737 / RFC 2544)
            let is_documentation = (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)); // RFC 2544 benchmarking (198.18.0.0/15)
            is_cgnat || is_documentation
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local() || v6.is_multicast()
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

        // First two successes: circuit stays half-open
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen, "Should stay half-open after 1 success");
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen, "Should stay half-open after 2 successes");

        // Third success: circuit closes
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed, "Should close after 3 successes");
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

    #[test]
    fn test_circuit_breaker_closes_on_first_success_when_max_is_one() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 1,
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

        // With max=1, first success closes
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open_reserves_single_probe_when_max_is_one() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::with_config(config);

        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }

        assert!(cb.allow_request(), "first half-open probe should be allowed");
        assert!(
            !cb.allow_request(),
            "second half-open probe should be rejected until the first completes"
        );

        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    // === SSRF IP range tests ===

    #[test]
    fn test_ssrf_blocks_multicast_ipv4() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(239, 255, 255, 255));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_multicast_ipv6() {
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_cgnat() {
        // 100.64.0.0/10 range (RFC 6598)
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 127, 255, 255));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_allows_100_not_in_cgnat() {
        // 100.0.0.1 is NOT in CGNAT range (100.64.0.0/10)
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 0, 0, 1));
        assert!(!is_ip_always_blocked(&ip));
        // 100.128.0.1 is also NOT in CGNAT range
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 128, 0, 1));
        assert!(!is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_documentation_ranges() {
        // RFC 5737 documentation ranges
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_benchmark_range() {
        // RFC 2544 benchmarking (198.18.0.0/15)
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_benchmark_range_upper() {
        // 198.19.x.x is also in RFC 2544 benchmarking range
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 19, 255, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_dns_cache_eviction_enforced() {
        let cache = DnsCache::with_ttl(300, 10);
        // Fill beyond DNS_CACHE_MAX_ENTRIES
        for i in 0..(DNS_CACHE_MAX_ENTRIES + 50) {
            let hi = (i / 256) % 256;
            let lo = i % 256;
            let addr: SocketAddr = format!("10.0.{hi}.{lo}:80").parse().unwrap();
            cache.store(format!("host-{i}"), vec![addr]);
        }
        assert!(
            cache.inner.len() <= DNS_CACHE_MAX_ENTRIES,
            "cache should be capped at DNS_CACHE_MAX_ENTRIES, got {}",
            cache.inner.len()
        );
    }

    #[test]
    fn test_dns_cache_absent_key_counts_as_miss() {
        let cache = DnsCache::with_ttl(30, 10);
        assert!(cache.lookup("missing.example").is_none());
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn test_dns_cache_ttl_zero_bypasses_positive_store() {
        let cache = DnsCache::with_ttl(0, 10);
        let addr: SocketAddr = "203.0.113.10:80".parse().unwrap();
        cache.store("no-cache.example:80".to_string(), vec![addr]);
        assert!(cache.lookup("no-cache.example:80").is_none());
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn test_dns_cache_ttl_change_clears_existing_entries() {
        let cache = DnsCache::with_ttl(30, 10);
        let addr: SocketAddr = "203.0.113.11:80".parse().unwrap();
        cache.store("ttl-change.example:80".to_string(), vec![addr]);
        assert_eq!(cache.stats().entries, 1);

        cache.set_ttl(60, 10);
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn test_circuit_breaker_half_open_max_clamped_to_63() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 100, // exceeds 6-bit capacity
        };
        let cb = CircuitBreaker::with_config(config);
        // Internal field should be clamped to 63
        assert_eq!(cb.half_open_max_requests, 63);
    }

    #[test]
    fn test_circuit_breaker_half_open_probe_count_does_not_overflow_encoding() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 63, // max safe value
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

        // Record success, probe count goes to 1
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        // Verify state encoding is still valid (no overflow)
        let state_byte = cb.state_atomic.load(Ordering::Acquire);
        let probe_count = ((state_byte >> 2) & 0x3F) as usize;
        assert_eq!(probe_count, 1);
    }
}

// Per-target statistics for admin dashboard and Prometheus labels.
#[derive(Debug, Default)]
pub struct TargetStats {
    pub requests_total: AtomicU64,
    pub errors_total: AtomicU64,
    pub latency_sum_us: AtomicU64,
    pub bytes_total: AtomicU64,
    pub last_access: AtomicU64, // Unix timestamp
}

impl TargetStats {
    pub fn record_request(&self, latency_us: u64, bytes: usize, is_error: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if is_error {
            self.errors_total.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        self.bytes_total.fetch_add(bytes as u64, Ordering::Relaxed);
        self.last_access.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed
        );
    }
    
    pub fn error_rate(&self) -> f64 {
        let total = self.requests_total.load(Ordering::Relaxed);
        if total == 0 { return 0.0; }
        let errors = self.errors_total.load(Ordering::Relaxed);
        (errors as f64 / total as f64) * 100.0
    }
    
    pub fn avg_latency_us(&self) -> u64 {
        let total = self.requests_total.load(Ordering::Relaxed);
        if total == 0 { return 0; }
        let sum = self.latency_sum_us.load(Ordering::Relaxed);
        sum / total
    }
}

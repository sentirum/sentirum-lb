//! Circuit breaker for per-target failure protection.
//!
//! Uses a sliding window of N requests to track error rate.
//! When `error_threshold`% of requests in the window fail, the circuit opens.
//! After `recovery_timeout`, the circuit enters half-open and allows N probe requests.
//! All probes succeed → circuit closes. Any probe fails → circuit reopens.
//!
//! Atomic circuit breaker for high-concurrency hot paths.
//! Uses atomic operations instead of Mutex for the fast path (`allow_request`).
//! Only uses Mutex for window modifications (`record_success`/`record_error`).
//!
//! State encoding in a single u8:
//!   bits 0-1: CircuitState (Closed=0, Open=1, HalfOpen=2)
//!   bits 2-7: probe counter (only valid in HalfOpen)

use parking_lot::Mutex as ParkingMutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

/// Circuit breaker state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    /// Monotonic milliseconds since process start (not unix epoch).
    /// Use this only for relative ordering; convert to wall-clock in the admin API.
    pub elapsed_ms: u64,
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

#[derive(Debug)]
pub struct CircuitBreaker {
    /// Atomic state byte: bits 0-1 = state, bits 2-7 = probe_counter
    pub(crate) state_atomic: AtomicU8,
    /// Recovery timeout in seconds
    recovery_timeout_secs: AtomicU64,
    /// Error threshold percentage
    error_threshold: u8,
    /// Window size
    window_size: usize,
    /// Max probe requests in half-open state
    pub(crate) half_open_max_requests: usize,
    /// Sliding window: Arc shared so clones preserve history across route rebuilds
    window: Arc<ParkingMutex<VecDeque<bool>>>,
    /// Number of `true` (error) entries currently in `window`.
    /// Maintained atomically alongside push/pop so `record_error` can check
    /// the threshold in O(1) instead of scanning the whole window.
    error_count: AtomicU64,
    /// Time when circuit last transitioned to Open (milliseconds)
    opened_at_ms: AtomicU64,
    /// Whether a half-open probe is currently in flight.
    half_open_in_flight: AtomicBool,
    /// Timestamp (ms) when the half-open probe was dispatched.
    /// Used to detect stuck probes and auto-reset them after a timeout.
    half_open_probe_sent_at_ms: AtomicU64,
    /// History of recent state transitions (ring buffer, max 20)
    history: Arc<ParkingMutex<Vec<CircuitTransition>>>,
}

pub(crate) const STATE_MASK: u8 = 0x03;
pub(crate) const STATE_CLOSED: u8 = 0;
pub(crate) const STATE_OPEN: u8 = 1;
pub(crate) const STATE_HALF_OPEN: u8 = 2;

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
            window_size: config.window_size.max(1),
            half_open_max_requests: config.half_open_max_requests.clamp(1, 63),
            window: Arc::new(ParkingMutex::new(VecDeque::with_capacity(
                config.window_size.max(1),
            ))),
            error_count: AtomicU64::new(0),
            opened_at_ms: AtomicU64::new(0),
            half_open_in_flight: AtomicBool::new(false),
            half_open_probe_sent_at_ms: AtomicU64::new(0),
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
                    // Auto-reset stuck probe: if half_open_in_flight has been true
                    // for longer than recovery_timeout, the upstream callback was
                    // likely lost (DNS failure, connection drop without logging).
                    // Reset the flag so a new probe can be dispatched.
                    //
                    // Minimum 100ms guard prevents race conditions where another
                    // thread sees the flag set in the same millisecond and resets it.
                    if self.half_open_in_flight.load(Ordering::Acquire) {
                        let probe_sent = self.half_open_probe_sent_at_ms.load(Ordering::Relaxed);
                        let recovery_ms = self.recovery_timeout_secs.load(Ordering::Relaxed) * 1000;
                        let reset_threshold_ms = (recovery_ms).max(100);
                        let elapsed = monotonic_elapsed_ms().saturating_sub(probe_sent);
                        if probe_sent > 0 && elapsed >= reset_threshold_ms {
                            tracing::warn!(
                                probe_sent_ago_ms =
                                    monotonic_elapsed_ms().saturating_sub(probe_sent),
                                recovery_ms,
                                "Half-open probe appears stuck; auto-resetting"
                            );
                            self.half_open_in_flight.store(false, Ordering::Release);
                        }
                    }
                    if self
                        .half_open_in_flight
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        self.half_open_probe_sent_at_ms
                            .store(monotonic_elapsed_ms(), Ordering::Relaxed);
                        return true;
                    }
                    return false;
                }
                _ => return false,
            }
        }
    }

    #[inline]
    fn recovery_elapsed(&self) -> bool {
        let recovery_timeout = self.recovery_timeout_secs.load(Ordering::Relaxed);
        let opened_at = self.opened_at_ms.load(Ordering::Relaxed);
        let elapsed = monotonic_elapsed_ms().saturating_sub(opened_at);
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

        match self.state_atomic.compare_exchange(
            current,
            STATE_HALF_OPEN,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
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
                let mut window = self.window.lock();
                if window.len() >= self.window_size
                    && let Some(was_error) = window.pop_front()
                    && was_error
                {
                    self.error_count.fetch_sub(1, Ordering::Relaxed);
                }
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
                let (window_len, errors) = {
                    let mut window = self.window.lock();
                    self.error_count.fetch_add(1, Ordering::Relaxed);
                    if window.len() >= self.window_size
                        && let Some(was_error) = window.pop_front()
                        && was_error
                    {
                        self.error_count.fetch_sub(1, Ordering::Relaxed);
                    }
                    window.push_back(true);
                    // Read error_count inside the lock to prevent a concurrent
                    // pop_front + fetch_sub from making our count stale (Issue #17 #1).
                    let len = window.len();
                    let errs = self.error_count.load(Ordering::Relaxed);
                    (len, errs)
                };
                // O(1) threshold check using the maintained error counter.
                // Open the circuit when BOTH conditions are met:
                //   1. Error rate >= error_threshold%
                //   2. At least min_samples requests observed
                // min_samples = max(window_size / 4, 5) to avoid triggering on
                // tiny samples while still protecting against 100% failure rates.
                let threshold = self.window_size * self.error_threshold as usize / 100;
                let min_samples = (self.window_size / 4).max(5).min(self.window_size);
                if errors >= threshold as u64 && window_len >= min_samples {
                    self.transition_to_open();
                    tracing::warn!(
                        error_rate =
                            format!("{:.1}%", 100.0 * errors as f64 / self.window_size as f64),
                        error_count = errors,
                        window_size = self.window_size,
                        threshold = threshold,
                        "Circuit breaker OPENED"
                    );
                }
            }
            STATE_HALF_OPEN => {
                self.half_open_in_flight.store(false, Ordering::Release);
                self.transition_to_open();
                tracing::warn!("Circuit breaker REOPENED — probe failed");
            }
            // STATE_OPEN: Do NOT reset opened_at_ms here.
            // Previously this bumped opened_at_ms on every call, preventing
            // recovery_elapsed() from ever returning true and permanently
            // locking the circuit in Open state (Issue #17 #2).
            STATE_OPEN => {
                // No-op: opened_at_ms is set once in transition_to_open()
                // and must not be overwritten while the circuit remains Open.
            }
            _ => {}
        }
    }

    #[inline(always)]
    fn transition_to_open(&self) {
        self.opened_at_ms
            .store(monotonic_elapsed_ms(), Ordering::Relaxed);
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
            match self.state_atomic.compare_exchange(
                current,
                STATE_OPEN,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
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
        self.error_count.store(0, Ordering::Relaxed);
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
                // Also increment open_total so it reflects all transitions to Open
                // (Issue #17 #16 — previously only Closed→Open was counted).
                metrics
                    .circuit_breaker_open_total
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
        if history.len() >= 20 {
            history.remove(0);
        }
        history.push(CircuitTransition {
            from,
            to,
            elapsed_ms: monotonic_elapsed_ms(),
        });
    }

    pub fn transition_history(&self) -> Vec<CircuitTransition> {
        self.history.lock().clone()
    }
}

// ============================================================================
// Monotonic time (shared epoch)
// ============================================================================

/// Shared monotonic epoch — all monotonic timestamps derive from this single
/// `Instant` so that relative comparisons between ms/s/ns are always consistent.
static MONO_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

#[inline]
pub(crate) fn mono_start() -> &'static Instant {
    MONO_EPOCH.get_or_init(Instant::now)
}

/// Monotonic millisecond timestamp based on `Instant::now()`.
/// Uses a process-start epoch so that NTP clock adjustments never
/// affect circuit-breaker or DNS-cache timing.
#[inline]
pub fn monotonic_elapsed_ms() -> u64 {
    mono_start().elapsed().as_millis() as u64
}

/// Monotonic second timestamp (for last_access tracking).
#[inline]
pub fn monotonic_secs() -> u64 {
    mono_start().elapsed().as_secs()
}

/// Clone preserves the shared state via Arc so that route-table rebuilds
/// do not reset circuit-breaker history.
impl Clone for CircuitBreaker {
    fn clone(&self) -> Self {
        Self {
            state_atomic: AtomicU8::new(self.state_atomic.load(Ordering::Relaxed)),
            recovery_timeout_secs: AtomicU64::new(
                self.recovery_timeout_secs.load(Ordering::Relaxed),
            ),
            error_threshold: self.error_threshold,
            window_size: self.window_size,
            half_open_max_requests: self.half_open_max_requests,
            window: Arc::clone(&self.window),
            error_count: AtomicU64::new(self.error_count.load(Ordering::Relaxed)),
            opened_at_ms: AtomicU64::new(self.opened_at_ms.load(Ordering::Relaxed)),
            half_open_in_flight: AtomicBool::new(self.half_open_in_flight.load(Ordering::Relaxed)),
            half_open_probe_sent_at_ms: AtomicU64::new(
                self.half_open_probe_sent_at_ms.load(Ordering::Relaxed),
            ),
            history: Arc::clone(&self.history),
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

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

        for _ in 0..5 {
            cb.record_success();
        }
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert!(cb.allow_request());

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
            recovery_timeout_secs: 0,
            half_open_max_requests: 3,
        };
        let cb = CircuitBreaker::with_config(config);

        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);

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

        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert!(cb.allow_request());

        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
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

        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert!(cb.allow_request());

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

        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert!(cb.allow_request());

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

        assert!(
            cb.allow_request(),
            "first half-open probe should be allowed"
        );
        assert!(
            !cb.allow_request(),
            "second half-open probe should be rejected until the first completes"
        );

        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open_max_clamped_to_63() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 100,
        };
        let cb = CircuitBreaker::with_config(config);
        assert_eq!(cb.half_open_max_requests, 63);
    }

    #[test]
    fn test_circuit_breaker_half_open_probe_count_does_not_overflow_encoding() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 63,
        };
        let cb = CircuitBreaker::with_config(config);

        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert!(cb.allow_request());

        cb.record_success();
        let state_byte = cb.state_atomic.load(Ordering::Acquire);
        let probe_count = ((state_byte >> 2) & 0x3F) as usize;
        assert_eq!(probe_count, 1);
    }

    #[test]
    fn test_circuit_breaker_allows_only_one_concurrent_half_open_probe() {
        let cb = Arc::new(CircuitBreaker::with_config(CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 3,
        }));
        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);

        let threads = 12;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let cb = Arc::clone(&cb);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    cb.allow_request()
                })
            })
            .collect();

        let allowed = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread should join"))
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(allowed, 1, "only one probe should be in flight at once");
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        assert!(cb.half_open_in_flight.load(Ordering::Acquire));
    }

    #[test]
    fn test_circuit_breaker_auto_resets_stuck_half_open_probe() {
        let cb = CircuitBreaker::with_config(CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0,
            half_open_max_requests: 2,
        });
        cb.state_atomic.store(STATE_HALF_OPEN, Ordering::Release);
        cb.half_open_in_flight.store(true, Ordering::Release);
        cb.half_open_probe_sent_at_ms.store(1, Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(2));

        assert!(
            cb.allow_request(),
            "stuck probe should be reset and retried"
        );
        assert!(cb.half_open_in_flight.load(Ordering::Acquire));
    }

    #[test]
    fn test_circuit_breaker_concurrent_half_open_errors_reopen_cleanly() {
        let cb = Arc::new(CircuitBreaker::with_config(CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 1,
            half_open_max_requests: 2,
        }));
        cb.state_atomic.store(STATE_HALF_OPEN, Ordering::Release);

        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cb = Arc::clone(&cb);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    cb.record_error();
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("thread should join");
        }

        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(!cb.half_open_in_flight.load(Ordering::Acquire));
        assert!(
            cb.transition_history()
                .iter()
                .any(|t| t.from == CircuitState::HalfOpen && t.to == CircuitState::Open)
        );
    }

    /// Regression test for Issue #17 #2:
    /// Previously, record_error in Open state would keep bumping opened_at_ms,
    /// preventing recovery_elapsed() from ever returning true and permanently
    /// locking the circuit breaker in Open state.
    #[test]
    fn test_circuit_breaker_open_state_does_not_bump_opened_at() {
        let config = CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 10,
            recovery_timeout_secs: 0, // immediate recovery for test
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::with_config(config);

        // Fill window to trigger Open
        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_error();
        }
        assert_eq!(cb.current_state(), CircuitState::Open);

        let opened_at = cb.opened_at_ms.load(Ordering::Relaxed);

        // Simulate additional errors arriving while Open
        for _ in 0..10 {
            cb.record_error();
        }

        // opened_at_ms must NOT have been bumped
        let opened_at_after = cb.opened_at_ms.load(Ordering::Relaxed);
        assert_eq!(
            opened_at, opened_at_after,
            "opened_at_ms should not change while circuit remains Open"
        );

        // With recovery_timeout_secs=0, the circuit should still be able to
        // transition to HalfOpen (recovery_elapsed() returns true immediately).
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(cb.recovery_elapsed(), "recovery should be possible after errors in Open state");
    }
}

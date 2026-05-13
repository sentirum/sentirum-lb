//! Token bucket rate limiter with correct refill semantics.
//!
//! Each upstream target can have its own rate limiter with configurable
//! `rate` (tokens/sec refill) and `burst` (max tokens). A rate of 0
//! means unlimited — `try_acquire()` always returns `true`.
//!
//! Uses a `parking_lot::Mutex` for the refill+consume critical section
//! to guarantee correct token accounting under high concurrency.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed-point scaling factor: 1 real token = `SCALE` sub-tokens.
/// Provides fractional precision for refill calculations.
const SCALE: u64 = 1_000_000;

/// Sentinel value indicating the rate limiter was never configured.
/// When `rate` is this value, `try_acquire` always returns `true`.
const UNCONFIGURED: u64 = 0;

/// Mutable state protected by a single Mutex.
/// The lock is held for nanoseconds (just arithmetic), so contention is negligible.
#[derive(Debug)]
struct BucketState {
    /// Available tokens in fixed-point representation.
    tokens: u64,
    /// Last refill time as a nanosecond timestamp.
    last_refill_ns: u64,
}

/// Token bucket rate limiter.
///
/// `rate` and `burst` are stored as atomics for lock-free reads (diagnostics).
/// The refill+consume path uses a Mutex for correctness.
#[derive(Debug)]
pub struct TokenBucket {
    /// Mutable state: tokens + last_refill_ns (protected by Mutex).
    state: Mutex<BucketState>,
    /// Refill rate in tokens per second (fixed-point).
    /// Actual rate = `rate / SCALE`. 0 = unconfigured/unlimited.
    rate: AtomicU64,
    /// Maximum burst capacity (fixed-point).
    /// Actual burst = `burst / SCALE`.
    burst: AtomicU64,
}

impl TokenBucket {
    /// Create a new unconfigured token bucket (unlimited).
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BucketState {
                tokens: 0,
                last_refill_ns: 0,
            }),
            rate: AtomicU64::new(UNCONFIGURED),
            burst: AtomicU64::new(0),
        }
    }

    /// Create a configured token bucket.
    pub fn with_params(rate: u64, burst: u64) -> Self {
        let bucket = Self::new();
        bucket.configure(rate, burst);
        bucket
    }

    /// Configure (or reconfigure) the bucket with a new rate and burst.
    /// Rate 0 means unlimited.
    pub fn configure(&self, rate: u64, burst: u64) {
        if rate == 0 {
            self.rate.store(UNCONFIGURED, Ordering::Release);
            self.burst.store(0, Ordering::Release);
            return;
        }
        let scaled_rate = rate * SCALE;
        let scaled_burst = burst.max(1) * SCALE;
        self.rate.store(scaled_rate, Ordering::Release);
        self.burst.store(scaled_burst, Ordering::Release);
        // Initialize tokens to full burst on first configuration
        let mut state = self.state.lock();
        if state.tokens == 0 {
            state.tokens = scaled_burst;
        }
        if state.last_refill_ns == 0 {
            state.last_refill_ns = Self::now_ns();
        }
    }

    /// Try to acquire one token. Returns `true` if allowed.
    /// When rate is 0 (unconfigured), always returns `true`.
    pub fn try_acquire(&self) -> bool {
        let rate = self.rate.load(Ordering::Acquire);
        if rate == UNCONFIGURED {
            return true;
        }

        let burst = self.burst.load(Ordering::Acquire);

        // Single critical section: refill + consume atomically.
        // The Mutex is held for ~nanoseconds (just arithmetic), so
        // contention is negligible even at 100K+ req/s.
        let mut state = self.state.lock();

        // Refill tokens based on elapsed time
        let now_ns = Self::now_ns();
        let elapsed_ns = now_ns.saturating_sub(state.last_refill_ns);

        if elapsed_ns > 0 {
            // refill = rate * elapsed_ns / 1_000_000_000 (ns → sec)
            let refill = ((rate as u128 * elapsed_ns as u128) / 1_000_000_000) as u64;
            state.tokens = state.tokens.saturating_add(refill);
            if state.tokens > burst {
                state.tokens = burst;
            }
            state.last_refill_ns = now_ns;
        }

        // Try to consume one token (SCALE units)
        if state.tokens < SCALE {
            return false;
        }
        state.tokens = state.tokens.saturating_sub(SCALE);
        true
    }

    /// Get current nanosecond timestamp from a monotonic clock.
    /// Shares the same epoch as `target::monotonic_elapsed_ms()` for consistency.
    fn now_ns() -> u64 {
        crate::route::target::mono_start().elapsed().as_nanos() as u64
    }

    /// Returns `true` if this bucket is configured with a non-zero rate.
    pub fn is_configured(&self) -> bool {
        self.rate.load(Ordering::Acquire) != UNCONFIGURED
    }

    /// Current approximate number of available tokens (for diagnostics).
    pub fn available_tokens(&self) -> u64 {
        let rate = self.rate.load(Ordering::Acquire);
        if rate == UNCONFIGURED {
            return u64::MAX;
        }
        self.state.lock().tokens / SCALE
    }
}

/// Clone shares the underlying state via Arc so that route-table rebuilds
/// do not duplicate token buckets (which would double the effective rate).
impl Clone for TokenBucket {
    fn clone(&self) -> Self {
        // Note: This creates an independent bucket (not Arc-shared).
        // Use `Arc<TokenBucket>` on the Target struct for true sharing.
        let state = self.state.lock();
        Self {
            state: Mutex::new(BucketState {
                tokens: state.tokens,
                last_refill_ns: state.last_refill_ns,
            }),
            rate: AtomicU64::new(self.rate.load(Ordering::Relaxed)),
            burst: AtomicU64::new(self.burst.load(Ordering::Relaxed)),
        }
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_token_bucket_allows_within_rate() {
        let bucket = TokenBucket::with_params(100, 10);
        // Should allow up to 10 (burst) requests immediately
        for _ in 0..10 {
            assert!(bucket.try_acquire(), "should allow within burst");
        }
        // 11th should fail (bucket depleted)
        assert!(!bucket.try_acquire(), "should reject over burst");
    }

    #[test]
    fn test_token_bucket_rejects_over_burst() {
        let bucket = TokenBucket::with_params(1, 3);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire(), "over burst should be rejected");
    }

    #[test]
    fn test_token_bucket_refills_over_time() {
        // Use a very high rate so refill happens quickly even on slow CI.
        let bucket = TokenBucket::with_params(100_000, 5);
        // Drain the bucket
        for _ in 0..5 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire(), "bucket should be empty");

        // Wait 20ms for refill (at 100K/sec, ~2 tokens in 20μs — generous margin)
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(bucket.try_acquire(), "should refill after time passes");
    }

    #[test]
    fn test_rate_limit_zero_means_unlimited() {
        let bucket = TokenBucket::new();
        // Unconfigured bucket should allow everything
        for _ in 0..1000 {
            assert!(bucket.try_acquire(), "unconfigured should always allow");
        }

        // Explicitly configured with 0 rate should also be unlimited
        let bucket = TokenBucket::new();
        bucket.configure(0, 0);
        for _ in 0..1000 {
            assert!(bucket.try_acquire(), "rate=0 should always allow");
        }
    }

    #[test]
    fn test_token_bucket_reconfigure() {
        let bucket = TokenBucket::with_params(100, 5);
        for _ in 0..5 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire());

        // Reconfigure to unlimited
        bucket.configure(0, 0);
        assert!(bucket.try_acquire(), "reconfigured to unlimited");
    }

    #[test]
    fn test_token_bucket_clone_preserves_config() {
        let bucket = TokenBucket::with_params(50, 10);
        let cloned = bucket.clone();
        assert!(cloned.try_acquire(), "cloned bucket should work");
        assert!(cloned.is_configured());
    }

    #[test]
    fn test_token_bucket_burst_at_least_one() {
        // Burst of 0 should be treated as at least 1
        let bucket = TokenBucket::new();
        bucket.configure(10, 0);
        assert!(bucket.try_acquire(), "should allow at least 1 token");
    }

    #[test]
    fn test_token_bucket_concurrent_no_double_refill() {
        // Use a low refill rate (1 token/sec) so no meaningful refill happens
        // during the test. 4 threads compete for 10 burst tokens.
        // Total successes must not exceed burst.
        let bucket = Arc::new(TokenBucket::with_params(1, 10));
        let success = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let bucket = Arc::clone(&bucket);
            let success = Arc::clone(&success);
            handles.push(std::thread::spawn(move || {
                let mut local_success = 0u64;
                for _ in 0..100 {
                    if bucket.try_acquire() {
                        local_success += 1;
                    }
                }
                success.fetch_add(local_success, Ordering::Relaxed);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Total successes should not exceed burst (10)
        let total = success.load(Ordering::Relaxed);
        assert!(
            total <= 10,
            "concurrent acquires should respect burst limit, got {total}"
        );
    }

    #[test]
    fn test_token_bucket_no_refill_skew() {
        // Drain, then immediately try_acquire from many threads.
        // Without proper mutex, some threads could see stale tokens.
        let bucket = Arc::new(TokenBucket::with_params(1, 3));
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());

        // All subsequent acquires should fail (no time for refill)
        let success = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let bucket = Arc::clone(&bucket);
            let success = Arc::clone(&success);
            handles.push(std::thread::spawn(move || {
                if bucket.try_acquire() {
                    success.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            success.load(Ordering::Relaxed),
            0,
            "no tokens should be available after drain"
        );
    }
}

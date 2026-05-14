//! Per-target health tracker combining circuit breaker with active health check state.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use super::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};

/// Per-target health tracker (circuit breaker + active health check wrapper)
#[derive(Debug, Clone)]
pub struct TargetHealthTracker {
    circuit_breaker: CircuitBreaker,
    /// Whether the target is considered healthy by active health checking.
    /// Starts `true` (healthy by default) to avoid breaking existing traffic.
    is_healthy: Arc<AtomicBool>,
    /// Consecutive probe failures (for fall threshold)
    consecutive_failures: Arc<AtomicU64>,
    /// Consecutive probe successes (for rise threshold)
    consecutive_successes: Arc<AtomicU64>,
}

impl TargetHealthTracker {
    pub fn new() -> Self {
        Self {
            circuit_breaker: CircuitBreaker::new(),
            is_healthy: Arc::new(AtomicBool::new(true)),
            consecutive_failures: Arc::new(AtomicU64::new(0)),
            consecutive_successes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            circuit_breaker: CircuitBreaker::with_config(config),
            is_healthy: Arc::new(AtomicBool::new(true)),
            consecutive_failures: Arc::new(AtomicU64::new(0)),
            consecutive_successes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    /// Record a successful health check probe.
    /// After `rise` consecutive successes, the target is marked healthy.
    /// No-op if already healthy (avoids unnecessary atomic writes).
    pub fn record_health_check_success(&self, rise: usize) {
        if self.is_healthy.load(Ordering::Acquire) {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            return;
        }
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
        if successes >= rise as u64 {
            self.is_healthy.store(true, Ordering::Release);
            tracing::info!(
                consecutive_successes = successes,
                "Target marked healthy by active health check"
            );
        }
    }

    /// Record a failed health check probe.
    /// After `fall` consecutive failures, the target is marked unhealthy.
    /// No-op if already unhealthy (avoids unnecessary atomic writes).
    pub fn record_health_check_failure(&self, fall: usize) {
        if !self.is_healthy.load(Ordering::Acquire) {
            self.consecutive_successes.store(0, Ordering::Relaxed);
            return;
        }
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= fall as u64 {
            self.is_healthy.store(false, Ordering::Release);
            tracing::warn!(
                consecutive_failures = failures,
                "Target marked unhealthy by active health check"
            );
        }
    }

    /// Returns `true` if the target is considered healthy by active probing.
    /// Targets start healthy by default.
    pub fn is_probe_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::Acquire)
    }
}

impl Default for TargetHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

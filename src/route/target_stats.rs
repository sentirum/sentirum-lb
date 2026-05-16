//! Per-target statistics registry and metrics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::circuit_breaker::monotonic_secs;
use super::health_tracker::TargetHealthTracker;
use super::target::CircuitBreakerConfig;

use crate::proxy::ratelimit::TokenBucket;

/// Prune dead Weak entries from a HashMap when it exceeds a threshold.
fn prune_dead<T>(map: &mut HashMap<String, Weak<T>>) {
    map.retain(|_, weak| weak.strong_count() > 0);
}

const REGISTRY_PRUNE_THRESHOLD: usize = 512;

#[derive(Debug, Default)]
pub struct TargetStatsRegistry {
    active_connections: Mutex<HashMap<String, Weak<AtomicU64>>>,
    stats: Mutex<HashMap<String, Weak<TargetStats>>>,
    edge_stats: Mutex<HashMap<String, Weak<TargetStats>>>,
    health_trackers: Mutex<HashMap<String, Weak<TargetHealthTracker>>>,
    rate_limiters: Mutex<HashMap<String, Weak<TokenBucket>>>,
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

        if entries.len() > REGISTRY_PRUNE_THRESHOLD {
            prune_dead(&mut entries);
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

        if entries.len() > REGISTRY_PRUNE_THRESHOLD {
            prune_dead(&mut entries);
        }

        let stats = Arc::new(TargetStats::default());
        entries.insert(key.to_string(), Arc::downgrade(&stats));
        stats
    }

    pub fn edge_stats_for(&self, key: &str) -> Arc<TargetStats> {
        let mut entries = self.edge_stats.lock().unwrap_or_else(|e| {
            tracing::warn!("Target edge stats registry lock was poisoned; recovering");
            e.into_inner()
        });

        if let Some(stats) = entries.get(key).and_then(Weak::upgrade) {
            return stats;
        }

        if entries.len() > REGISTRY_PRUNE_THRESHOLD {
            prune_dead(&mut entries);
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

        if entries.len() > REGISTRY_PRUNE_THRESHOLD {
            prune_dead(&mut entries);
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

    pub fn rate_limiter_for(&self, key: &str) -> Arc<TokenBucket> {
        let mut entries = self.rate_limiters.lock().unwrap_or_else(|e| {
            tracing::warn!("Target rate limiter registry lock was poisoned; recovering");
            e.into_inner()
        });

        if let Some(limiter) = entries.get(key).and_then(Weak::upgrade) {
            return limiter;
        }

        if entries.len() > REGISTRY_PRUNE_THRESHOLD {
            prune_dead(&mut entries);
        }

        let limiter = Arc::new(TokenBucket::new());
        entries.insert(key.to_string(), Arc::downgrade(&limiter));
        limiter
    }

    pub fn clear_health_trackers(&self) {
        let mut entries = self.health_trackers.lock().unwrap_or_else(|e| {
            tracing::warn!("Target health registry lock was poisoned; recovering");
            e.into_inner()
        });
        entries.clear();
    }
}

/// Per-target statistics for admin dashboard and Prometheus labels.
#[derive(Debug, Default)]
pub struct TargetStats {
    pub requests_total: AtomicU64,
    pub errors_total: AtomicU64,
    pub latency_sum_us: AtomicU64,
    pub bytes_total: AtomicU64,
    /// Monotonic seconds since process start
    pub last_access: AtomicU64,
}

impl TargetStats {
    pub fn record_request(&self, latency_us: u64, bytes: usize, is_error: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if is_error {
            self.errors_total.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        self.bytes_total.fetch_add(bytes as u64, Ordering::Relaxed);
        self.last_access.store(monotonic_secs(), Ordering::Relaxed);
    }

    pub fn error_rate(&self) -> f64 {
        let total = self.requests_total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let errors = self.errors_total.load(Ordering::Relaxed);
        (errors as f64 / total as f64) * 100.0
    }

    pub fn avg_latency_us(&self) -> u64 {
        let total = self.requests_total.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        let sum = self.latency_sum_us.load(Ordering::Relaxed);
        sum / total
    }
}

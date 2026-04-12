use crate::route::target::Target;
use rand::Rng;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Target selection strategy
pub trait Picker: Send + Sync {
    /// Pick a target from the list of targets.
    /// `w_targets` is the pre-computed weighted target list (Arc references for zero-copy pick).
    /// `targets` is the original target list.
    fn pick(
        &self,
        targets: &[Arc<Target>],
        w_targets: &[Arc<Target>],
        counter: &std::sync::atomic::AtomicU64,
    ) -> Option<Arc<Target>>;
}

/// Round-robin picker — cycles through targets in order
pub struct RoundRobinPicker;

impl Picker for RoundRobinPicker {
    fn pick(
        &self,
        _targets: &[Arc<Target>],
        w_targets: &[Arc<Target>],
        counter: &std::sync::atomic::AtomicU64,
    ) -> Option<Arc<Target>> {
        if w_targets.is_empty() {
            return None;
        }
        let idx = counter.fetch_add(1, Ordering::Relaxed) as usize % w_targets.len();
        // Zero-copy: just return the Arc reference
        Some(Arc::clone(&w_targets[idx]))
    }
}

/// Random picker — selects a random target from weighted list
/// Uses thread-local SmallRng for fast, high-quality randomness (thread-safe)
pub struct RandomPicker {
    // Thread-local RNG - each thread gets its own RNG automatically
}

impl RandomPicker {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RandomPicker {
    fn default() -> Self {
        Self::new()
    }
}

impl Picker for RandomPicker {
    fn pick(
        &self,
        _targets: &[Arc<Target>],
        w_targets: &[Arc<Target>],
        _counter: &std::sync::atomic::AtomicU64,
    ) -> Option<Arc<Target>> {
        if w_targets.is_empty() {
            return None;
        }
        // Thread-local RNG - no sharing issues, very fast
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..w_targets.len());
        Some(Arc::clone(&w_targets[idx]))
    }
}

/// Least-connections picker — selects target with fewest active connections.
/// Uses atomic counters per-target to track active connections.
pub struct LeastConnectionsPicker;

impl Picker for LeastConnectionsPicker {
    fn pick(
        &self,
        targets: &[Arc<Target>],
        _w_targets: &[Arc<Target>],
        _counter: &std::sync::atomic::AtomicU64,
    ) -> Option<Arc<Target>> {
        if targets.is_empty() {
            return None;
        }

        // Find target with minimum active connections
        // Each Target has an `active_connections` AtomicU64 (default 0)
        targets
            .iter()
            .min_by_key(|t| t.active_connections.load(Ordering::Relaxed))
            .map(Arc::clone)
    }
}

/// Create a picker based on the strategy name
pub fn create_picker(strategy: &str) -> Box<dyn Picker> {
    match strategy {
        "round-robin" | "rr" | "" => Box::new(RoundRobinPicker),
        "random" | "rnd" => Box::new(RandomPicker::new()),
        "least-connections" | "lc" => Box::new(LeastConnectionsPicker),
        _ => {
            tracing::warn!("Unknown picker '{}', defaulting to round-robin", strategy);
            Box::new(RoundRobinPicker)
        }
    }
}

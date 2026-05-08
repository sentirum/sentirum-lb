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
        targets: &[Arc<Target>],
        w_targets: &[Arc<Target>],
        counter: &std::sync::atomic::AtomicU64,
    ) -> Option<Arc<Target>> {
        if w_targets.is_empty() || targets.is_empty() {
            return None;
        }
        // Use SeqCst to ensure the increment is visible to all threads before
        // any thread reads the updated counter value for indexing.
        let counter_val = counter.fetch_add(1, Ordering::SeqCst);
        let idx = counter_val as usize % w_targets.len();

        // DEBUG: Log the pick decision
        tracing::debug!(
            targets_len = targets.len(),
            w_targets_len = w_targets.len(),
            counter_val = counter_val,
            idx = idx,
            picked_url = %w_targets[idx].url,
            "RoundRobinPicker: selecting target"
        );

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn make_targets(count: usize) -> Vec<Arc<Target>> {
        (0..count)
            .map(|i| Arc::new(Target::new(format!("svc-{}", i), format!("http://10.0.0.{}:8080/", i+1))))
            .collect()
    }

    #[test]
    fn round_robin_two_targets() {
        let targets = make_targets(2);
        let w_targets = targets.clone();
        let counter = AtomicU64::new(0);
        let picker = RoundRobinPicker;

        // Simulate 100 picks and verify distribution
        let mut counts = std::collections::HashMap::new();
        for _ in 0..100 {
            let picked = picker.pick(&targets, &w_targets, &counter).unwrap();
            *counts.entry(picked.url.clone()).or_insert(0) += 1;
        }

        // With 2 targets and 100 requests, should be ~50/50 (allow some variance)
        let values: Vec<_> = counts.values().cloned().collect();
        assert_eq!(values.len(), 2, "Should use both targets");
        for v in &values {
            assert!(*v >= 40 && *v <= 60, "Each target should get ~50% traffic, got {}", v);
        }
    }

    #[test]
    fn round_robin_with_weighted_targets() {
        use crate::route::table::Route;

        // Simulate production: 2 targets with equal weights → 1000 w_targets slots
        let mut route = Route::new("host.com".to_string(), "/".to_string());
        route.add_target(Target::new("svc-a".into(), "http://10.0.0.1:80/".into()));
        route.add_target(Target::new("svc-b".into(), "http://10.0.0.2:80/".into()));
        route.compute_weights();

        assert_eq!(route.targets.len(), 2);
        assert_eq!(route.w_targets.len(), 1000);

        let counter = AtomicU64::new(0);
        let picker = RoundRobinPicker;

        let mut counts = std::collections::HashMap::new();
        // Run through the full w_targets range to verify equal distribution
        for _ in 0..1000 {
            let picked = picker.pick(&route.targets, &route.w_targets, &counter).unwrap();
            *counts.entry(picked.url.clone()).or_insert(0) += 1;
        }

        // Both targets must receive traffic (50% each exactly, since w_targets is
        // grouped by target: first 500 slots = svc-a, next 500 = svc-b)
        assert_eq!(counts.len(), 2, "Round-robin must distribute across both targets, got: {:?}", counts);
        let svc_a = counts.get("http://10.0.0.1:80/").unwrap();
        let svc_b = counts.get("http://10.0.0.2:80/").unwrap();
        assert_eq!(*svc_a, 500, "svc-a should get 500 picks");
        assert_eq!(*svc_b, 500, "svc-b should get 500 picks");
    }

    #[test]
    fn round_robin_with_unequal_weights() {
        use crate::route::table::Route;

        let mut route = Route::new("host.com".to_string(), "/".to_string());
        let mut t1 = Target::new("heavy".into(), "http://10.0.0.1:80/".into());
        t1.fixed_weight = 0.9;
        let mut t2 = Target::new("light".into(), "http://10.0.0.2:80/".into());
        t2.fixed_weight = 0.1;
        route.add_target(t1);
        route.add_target(t2);
        route.compute_weights();

        let counter = AtomicU64::new(0);
        let picker = RoundRobinPicker;

        let mut counts = std::collections::HashMap::new();
        // Run through the full w_targets range
        for _ in 0..1000 {
            let picked = picker.pick(&route.targets, &route.w_targets, &counter).unwrap();
            *counts.entry(picked.url.clone()).or_insert(0) += 1;
        }

        // heavy: 900 slots, light: 100 slots → 90/10 split
        assert_eq!(counts.len(), 2, "Both targets must get traffic: {:?}", counts);
        let heavy = counts.get("http://10.0.0.1:80/").unwrap();
        let light = counts.get("http://10.0.0.2:80/").unwrap();
        assert_eq!(*heavy, 900, "heavy target should get 900 picks");
        assert_eq!(*light, 100, "light target should get 100 picks");
    }

    #[test]
    fn round_robin_three_targets() {
        let targets = make_targets(3);
        let w_targets = targets.clone();
        let counter = AtomicU64::new(0);
        let picker = RoundRobinPicker;

        let mut counts = std::collections::HashMap::new();
        for _ in 0..300 {
            let picked = picker.pick(&targets, &w_targets, &counter).unwrap();
            *counts.entry(picked.url.clone()).or_insert(0) += 1;
        }

        assert_eq!(counts.len(), 3, "Should use all three targets");
    }
}
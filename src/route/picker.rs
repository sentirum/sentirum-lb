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
        // Relaxed is sufficient: fetch_add guarantees a unique value per thread
        // without requiring a global memory fence. The counter only produces an
        // index — no other memory location needs to be synchronized with this read.
        let counter_val = counter.fetch_add(1, Ordering::Relaxed);
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




/// Least-connections picker — selects target with the lowest effective load,
/// where effective load = active_connections / weight.
///
/// This respects configured weights: a target with weight 0.7 can hold
/// proportionally more connections than one with weight 0.3 before being
/// deprioritized. Targets with weight == 0 are excluded from selection
/// (they receive no traffic). When all targets have weight 0, falls back
/// to simple min-by-connection-count.
///
/// Memory ordering: Acquire on load pairs with Release in
/// `Target::try_acquire_connection_slot`, forming a proper inter-thread
/// ordering boundary without requiring full SeqCst serialization.

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

        // Acquire ordering: pairs with Release in try_acquire_connection_slot.
        let has_weight = targets.iter().any(|t| t.weight > 0.0);

        if has_weight {
            // Weight-aware: pick the target with the lowest connections/weight ratio.
            // Use OrderedFloat for deterministic comparison of f64 in min_by_key.
            targets
                .iter()
                .filter(|t| t.weight > 0.0)
                .min_by_key(|t| {
                    let conns = t.active_connections.load(Ordering::Acquire) as f64;
                    // Scale by 1e6 to preserve sub-integer precision in integer comparison.
                    // weight ranges [0.001, 1.0], conns ranges [0, u64::MAX].
                    // conns / weight gives effective load — lower is preferred.
                    (conns / t.weight * 1e6) as u64
                })
                .map(Arc::clone)
        } else {
            // No weights configured — simple min-connections (Fabio-compatible).
            targets
                .iter()
                .min_by_key(|t| t.active_connections.load(Ordering::Acquire))
                .map(Arc::clone)
        }
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

    #[test]
    fn least_connections_prefers_fewer_connections() {
        let t1 = Target::new("svc-1".into(), "http://10.0.0.1:80/".into());
        let t2 = Target::new("svc-2".into(), "http://10.0.0.2:80/".into());
        let targets: Vec<Arc<Target>> = vec![Arc::new(t1), Arc::new(t2)];

        // Set different connection counts
        targets[0].active_connections.store(5, Ordering::Release);
        targets[1].active_connections.store(2, Ordering::Release);

        let picker = LeastConnectionsPicker;
        let counter = AtomicU64::new(0);
        let picked = picker.pick(&targets, &[], &counter).unwrap();
        assert_eq!(picked.url, "http://10.0.0.2:80/");
    }

    #[test]
    fn least_connections_weight_aware_respects_ratio() {
        use crate::route::table::Route;

        // Two targets: heavy (weight=0.7) and light (weight=0.3)
        // With 7 conns on heavy and 3 conns on light:
        //   heavy effective load = 7/0.7 = 10.0
        //   light effective load = 3/0.3 = 10.0
        // Both equal → pick first (heavy by iteration order)
        //
        // With 8 conns on heavy and 3 conns on light:
        //   heavy effective load = 8/0.7 ≈ 11.4
        //   light effective load = 3/0.3 = 10.0
        // Pick light (lower effective load)
        let mut route = Route::new("host.com".to_string(), "/".to_string());
        let mut heavy = Target::new("heavy".into(), "http://10.0.0.1:80/".into());
        heavy.fixed_weight = 0.7;
        let mut light = Target::new("light".into(), "http://10.0.0.2:80/".into());
        light.fixed_weight = 0.3;
        route.add_target(heavy);
        route.add_target(light);
        route.compute_weights();

        // Simulate: heavy has 8 connections, light has 3
        route.targets[0].active_connections.store(8, Ordering::Release);
        route.targets[1].active_connections.store(3, Ordering::Release);

        let picker = LeastConnectionsPicker;
        let counter = AtomicU64::new(0);
        let picked = picker.pick(&route.targets, &route.w_targets, &counter).unwrap();
        // light has lower effective load (10.0 vs 11.4)
        assert_eq!(picked.url, "http://10.0.0.2:80/", "Should pick light (lower effective load)");

        // Now equalize: heavy 7, light 3
        route.targets[0].active_connections.store(7, Ordering::Release);
        let picked2 = picker.pick(&route.targets, &route.w_targets, &counter).unwrap();
        // Both have effective load = 10.0, pick first (heavy)
        assert_eq!(picked2.url, "http://10.0.0.1:80/", "Should pick heavy (equal load, first wins)");

        // Verify heavy can hold more: heavy 6, light 3
        route.targets[0].active_connections.store(6, Ordering::Release);
        let picked3 = picker.pick(&route.targets, &route.w_targets, &counter).unwrap();
        // heavy: 6/0.7 ≈ 8.57, light: 3/0.3 = 10.0 → pick heavy
        assert_eq!(picked3.url, "http://10.0.0.1:80/", "Heavy should still be preferred at proportional load");
    }

    #[test]
    fn least_connections_weight_zero_target_excluded() {
        use crate::route::table::Route;

        // 3 targets: one with weight 0 (draining), two with equal weight
        let mut route = Route::new("host.com".to_string(), "/".to_string());
        let mut draining = Target::new("drain".into(), "http://10.0.0.1:80/".into());
        draining.fixed_weight = 0.0;
        let mut active1 = Target::new("active1".into(), "http://10.0.0.2:80/".into());
        active1.fixed_weight = 0.5;
        let mut active2 = Target::new("active2".into(), "http://10.0.0.3:80/".into());
        active2.fixed_weight = 0.5;
        route.add_target(draining);
        route.add_target(active1);
        route.add_target(active2);
        route.compute_weights();

        // All have 0 connections
        let picker = LeastConnectionsPicker;
        let counter = AtomicU64::new(0);

        for _ in 0..100 {
            let picked = picker.pick(&route.targets, &route.w_targets, &counter).unwrap();
            assert_ne!(picked.url, "http://10.0.0.1:80/", "Draining target should never be picked");
        }
    }

    #[test]
    fn least_connections_no_weights_falls_back_to_simple() {
        // All weights 0 → simple min-connections (Fabio-compatible)
        let t1 = Target::new("svc-1".into(), "http://10.0.0.1:80/".into());
        let t2 = Target::new("svc-2".into(), "http://10.0.0.2:80/".into());
        let targets: Vec<Arc<Target>> = vec![Arc::new(t1), Arc::new(t2)];
        // weights default to 0.0

        targets[0].active_connections.store(10, Ordering::Release);
        targets[1].active_connections.store(3, Ordering::Release);

        let picker = LeastConnectionsPicker;
        let counter = AtomicU64::new(0);
        let picked = picker.pick(&targets, &[], &counter).unwrap();
        assert_eq!(picked.url, "http://10.0.0.2:80/");
    }
}
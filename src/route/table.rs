use crate::route::definition::{RouteCmd, RouteDef};
use crate::route::target::Target;
use arc_swap::ArcSwap;
use glob::Pattern;
use std::collections::HashMap;
use std::sync::Arc;

/// A route maps a host + path prefix to one or more target backends.
#[derive(Debug)]
pub struct Route {
    /// Host pattern (e.g. "myhost.com")
    pub host: String,
    /// Path prefix (e.g. "/api/")
    pub path: String,
    /// Compiled glob pattern (if matcher is "glob")
    pub glob: Option<Pattern>,
    /// Target backends for this route
    pub targets: Vec<Arc<Target>>,
    /// Weighted targets (pre-distributed for fast selection, Arc refs for zero-copy pick)
    pub w_targets: Vec<Arc<Target>>,
    /// Counter for round-robin selection
    pub rr_counter: std::sync::atomic::AtomicU64,
}

impl Clone for Route {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            path: self.path.clone(),
            glob: self.glob.clone(),
            targets: self.targets.clone(), // Vec<Arc<Target>> clones cheaply
            w_targets: self.w_targets.clone(),
            rr_counter: std::sync::atomic::AtomicU64::new(
                self.rr_counter.load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

impl Route {
    pub fn new(host: String, path: String) -> Self {
        let glob = if path.contains('*') || path.contains('?') || path.contains('[') {
            Pattern::new(&path).ok()
        } else {
            None
        };

        Self {
            host,
            path,
            glob,
            targets: Vec::new(),
            w_targets: Vec::new(),
            rr_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Add a target to this route.
    pub fn add_target(&mut self, target: Target) {
        // De-dup check (compare against Arc targets)
        let exists = self.targets.iter().any(|t| {
            t.service == target.service && t.url == target.url && t.fixed_weight == target.fixed_weight
        });
        if !exists {
            self.targets.push(Arc::new(target));
        }
    }

    /// Remove targets matching the given service and optionally URL.
    pub fn remove_targets(&mut self, service: &str, url: Option<&str>) {
        self.targets.retain(|t| {
            if t.service != service {
                return true;
            }
            if let Some(url) = url {
                t.url != url
            } else {
                false
            }
        });
    }

    /// Compute weighted targets for fast selection.
    /// Must be called after adding/removing targets.
    pub fn compute_weights(&mut self) {
        if self.targets.is_empty() {
            self.w_targets.clear();
            return;
        }

        let has_fixed = self.targets.iter().any(|t| t.fixed_weight > 0.0);

        if has_fixed {
            // Distribute targets according to fixed weights
            let total_fixed: f64 = self
                .targets
                .iter()
                .map(|t| if t.fixed_weight > 0.0 { t.fixed_weight } else { 0.0 })
                .sum();

            let dynamic_count = self
                .targets
                .iter()
                .filter(|t| t.fixed_weight <= 0.0)
                .count() as f64;

            // Remaining weight for dynamic targets
            let remaining = (1.0 - total_fixed).max(0.0);
            let dynamic_weight = if dynamic_count > 0.0 {
                remaining / dynamic_count
            } else {
                0.0
            };

            // Use Arc::make_mut to get mutable references
            for i in 0..self.targets.len() {
                let t = Arc::make_mut(&mut self.targets[i]);
                t.weight = if t.fixed_weight > 0.0 {
                    t.fixed_weight
                } else {
                    dynamic_weight
                };
            }
        } else {
            // Equal distribution
            let weight = 1.0 / self.targets.len() as f64;
            for i in 0..self.targets.len() {
                let t = Arc::make_mut(&mut self.targets[i]);
                t.weight = weight;
            }
        }

        // Build weighted targets list (1000 slots for good granularity)
        // Fabio uses 10000 slots; 1000 provides 0.1% precision with low memory
        self.w_targets.clear();
        let slots = 1000;
        for t in &self.targets {
            let count = (t.weight * slots as f64).round() as usize;
            // Fabio-compatible: if weight > 0 but count is 0, give at least 1 slot
            // But if weight == 0, give 0 slots (target receives no traffic)
            if count == 0 && t.weight > 0.0 {
                self.w_targets.push(Arc::clone(t));
            } else {
                for _ in 0..count {
                    self.w_targets.push(Arc::clone(t));
                }
            }
        }

        // If w_targets is empty due to all weights being 0, fallback to equal distribution
        if self.w_targets.is_empty() && !self.targets.is_empty() {
            // Fabio: "if nFixed == 0" case — equal distribution
            let weight = 1.0 / self.targets.len() as f64;
            let count = (weight * slots as f64).round() as usize;
            for t in &self.targets {
                // Each target gets at least 1 slot in equal distribution
                let actual = count.max(1);
                for _ in 0..actual {
                    self.w_targets.push(Arc::clone(t));
                }
            }
        }
    }

    /// Get the number of targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

/// The routing table: maps host -> list of routes.
/// Routes are sorted by path in reverse order (most specific first).
#[derive(Debug, Clone, Default)]
pub struct Table {
    /// host -> sorted routes
    routes: HashMap<String, Vec<Arc<Route>>>,
}

impl Table {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Lookup a route by host and path.
    /// Returns the matching route (with targets) for the given matcher strategy.
    pub fn lookup_route(&self, host: &str, path: &str, matcher: &str) -> Option<&Arc<Route>> {
        // Try exact host match first
        if let Some(routes) = self.routes.get(host)
            && let Some(route) = Self::find_matching_route(routes, path, matcher) {
                return Some(route);
            }

        // Try empty host (catch-all)
        if let Some(routes) = self.routes.get("")
            && let Some(route) = Self::find_matching_route(routes, path, matcher) {
                return Some(route);
            }

        None
    }

    fn find_matching_route<'a>(
        routes: &'a [Arc<Route>],
        path: &str,
        matcher: &str,
    ) -> Option<&'a Arc<Route>> {
        for route in routes {
            let matches = match matcher {
                "prefix" | "" => path.starts_with(&route.path) || route.path == "/",
                "iprefix" => starts_with_ignore_ascii_case(path, &route.path) || route.path == "/",
                "glob" => route
                    .glob
                    .as_ref()
                    .map(|g| g.matches(path))
                    .unwrap_or(false),
                _ => path.starts_with(&route.path),
            };

            if matches && !route.targets.is_empty() {
                return Some(route);
            }
        }
        None
    }

    /// Apply a route definition to the table.
    pub fn apply(&mut self, def: &RouteDef) {
        match def.cmd {
            RouteCmd::Add => self.apply_add(def),
            RouteCmd::Del => self.apply_del(def),
            RouteCmd::Weight => self.apply_weight(def),
        }
    }

    fn apply_add(&mut self, def: &RouteDef) {
        let host = def.src_host().to_string();
        let path = if def.src_path().is_empty() {
            "/".to_string()
        } else {
            format!("/{}", def.src_path())
        };

        let mut target = Target {
            service: def.service.clone(),
            url: def.dst.clone(),
            fixed_weight: def.weight,
            weight: 0.0,
            tags: def.tags.clone(),
            opts: def.opts.clone(),
            parsed_host: None,
            parsed_port: None,
            parsed_tls: false,
            active_connections: std::sync::atomic::AtomicU64::new(0),
        };
        target.pre_parse();

        let host_routes = self.routes.entry(host.clone()).or_default();

        // Find existing route or create new one
        if let Some(existing) = host_routes.iter_mut().find(|r| r.path == path) {
            // Need to get mutable access through Arc — clone and replace
            let mut route = (**existing).clone();
            route.add_target(target);
            route.compute_weights();
            *existing = Arc::new(route);
        } else {
            let mut route = Route::new(host, path);
            route.add_target(target);
            route.compute_weights();
            host_routes.push(Arc::new(route));
            // Sort by path in reverse order (most specific first)
            host_routes.sort_by(|a, b| b.path.cmp(&a.path));
        }
    }

    fn apply_del(&mut self, def: &RouteDef) {
        let host = def.src_host().to_string();

        if let Some(host_routes) = self.routes.get_mut(&host) {
            let path = if def.src_path().is_empty() {
                None
            } else {
                Some(format!("/{}", def.src_path()))
            };

            for route in host_routes.iter_mut() {
                if path.as_ref().is_none_or(|p| route.path == *p) {
                    let url = if def.dst.is_empty() {
                        None
                    } else {
                        Some(def.dst.as_str())
                    };
                    let mut r = (**route).clone();
                    r.remove_targets(&def.service, url);
                    r.compute_weights();
                    *route = Arc::new(r);
                }
            }

            // Remove routes with no targets
            host_routes.retain(|r| !r.targets.is_empty());
        }

        // Remove empty hosts
        if self.routes.get(&host).is_some_and(|r| r.is_empty()) {
            self.routes.remove(&host);
        }
    }

    fn apply_weight(&mut self, def: &RouteDef) {
        let host = def.src_host().to_string();

        if let Some(host_routes) = self.routes.get_mut(&host) {
            let path = if def.src_path().is_empty() {
                "/".to_string()
            } else {
                format!("/{}", def.src_path())
            };

            for route in host_routes.iter_mut() {
                if route.path == path {
                    // Clone route for modification
                    let mut r = (**route).clone();
                    // Use Arc::make_mut to modify targets
                    for i in 0..r.targets.len() {
                        let target = Arc::make_mut(&mut r.targets[i]);
                        if def.tags.is_empty() || def.tags.iter().all(|t| target.tags.contains(t)) {
                            target.fixed_weight = def.weight;
                        }
                    }
                    r.compute_weights();
                    *route = Arc::new(r);
                }
            }
        }
    }

    /// Build a new table from a list of route definitions.
    pub fn from_definitions(defs: &[RouteDef]) -> Self {
        let mut table = Table::new();
        for def in defs {
            table.apply(def);
        }
        table
    }

    /// Get the number of routes in the table.
    pub fn route_count(&self) -> usize {
        self.routes.values().map(|r| r.len()).sum()
    }

    /// Get the total number of targets across all routes.
    pub fn target_count(&self) -> usize {
        self.routes
            .values()
            .flat_map(|r| r.iter())
            .map(|r| r.target_count())
            .sum()
    }

    /// Get all hosts in the table.
    pub fn hosts(&self) -> Vec<&str> {
        self.routes.keys().map(|s| s.as_str()).collect()
    }

    /// Get routes for a specific host.
    pub fn get_routes(&self, host: &str) -> Option<&Vec<Arc<Route>>> {
        self.routes.get(host)
    }

    /// Get the full internal map (for admin API).
    pub fn all_routes(&self) -> &HashMap<String, Vec<Arc<Route>>> {
        &self.routes
    }
}

/// Thread-safe routing table using ArcSwap for lock-free reads.
pub struct RouteTable {
    inner: ArcSwap<Table>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from(Arc::new(Table::new())),
        }
    }

    /// Get a snapshot of the current routing table.
    /// This is lock-free and very fast.
    pub fn get(&self) -> Arc<Table> {
        self.inner.load_full()
    }

    /// Swap the entire routing table atomically.
    pub fn swap(&self, table: Table) {
        let route_count = table.route_count();
        let target_count = table.target_count();
        self.inner.store(Arc::new(table));
        let metrics = crate::metrics::prometheus::global();
        metrics
            .route_count
            .store(route_count as i64, std::sync::atomic::Ordering::Relaxed);
        metrics
            .target_count
            .store(target_count as i64, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            route_count,
            target_count,
            "Routing table updated"
        );
    }

    /// Apply definitions and swap the table.
    pub fn apply_and_swap(&self, defs: &[RouteDef]) {
        let table = Table::from_definitions(defs);
        self.swap(table);
    }
}

fn starts_with_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(needle))
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(service: &str, url: &str, fixed_weight: f64, weight: f64) -> Target {
        let mut t = Target {
            service: service.to_string(),
            url: url.to_string(),
            fixed_weight,
            weight,
            active_connections: std::sync::atomic::AtomicU64::new(0),
            ..Default::default()
        };
        t.pre_parse();
        t
    }

    #[test]
    fn test_weight_zero_gets_no_slots() {
        let mut route = Route::new("host.com".to_string(), "/".to_string());
        route.add_target(make_target("svc1", "http://1.0.0.1:80", 0.0, 0.0));
        route.add_target(make_target("svc2", "http://1.0.0.2:80", 1.0, 1.0));
        route.compute_weights();

        // weight=0 target should get 0 slots, weight=1.0 should get 1000 slots
        assert_eq!(route.w_targets.len(), 1000);
        // First target (weight=0) should NOT appear
        assert!(route.w_targets.iter().all(|t| t.service == "svc2"));
    }

    #[test]
    fn test_all_weights_zero_equal_distribution() {
        let mut route = Route::new("host.com".to_string(), "/".to_string());
        route.add_target(make_target("svc1", "http://1.0.0.1:80", 0.0, 0.0));
        route.add_target(make_target("svc2", "http://1.0.0.2:80", 0.0, 0.0));
        route.compute_weights();

        // Both should get equal distribution (500 slots each = 1000 total)
        assert_eq!(route.w_targets.len(), 1000);
        let svc1_count = route.w_targets.iter().filter(|t| t.service == "svc1").count();
        let svc2_count = route.w_targets.iter().filter(|t| t.service == "svc2").count();
        assert_eq!(svc1_count, 500);
        assert_eq!(svc2_count, 500);
    }

    #[test]
    fn test_iprefix_matcher_is_case_insensitive() {
        let defs = vec![RouteDef {
            cmd: RouteCmd::Add,
            service: "svc".to_string(),
            src: "example.com/API/".to_string(),
            dst: "http://127.0.0.1:8080/".to_string(),
            weight: 0.0,
            tags: vec![],
            opts: HashMap::new(),
        }];

        let table = Table::from_definitions(&defs);
        assert!(table.lookup_route("example.com", "/api/users", "iprefix").is_some());
        assert!(table.lookup_route("example.com", "/API/users", "iprefix").is_some());
    }
}

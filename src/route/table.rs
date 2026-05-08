use crate::route::definition::{RouteCmd, RouteDef};
use crate::route::target::{Target, TargetStatsRegistry};
use arc_swap::ArcSwap;
use glob::Pattern;
use std::collections::{BTreeSet, HashMap};
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
            t.service == target.service
                && t.url == target.url
                && t.fixed_weight == target.fixed_weight
                && t.source == target.source
        });
        if !exists {
            self.targets.push(Arc::new(target));
        }
    }

    /// Remove targets matching the given service, tags, and optionally URL.
    pub fn remove_targets(&mut self, service: &str, tags: &[String], url: Option<&str>) {
        self.targets.retain(|t| {
            if !service.is_empty() && t.service != service {
                return true;
            }
            if !tags.is_empty() && !tags.iter().all(|tag| t.tags.contains(tag)) {
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
                .map(|t| {
                    if t.fixed_weight > 0.0 {
                        t.fixed_weight
                    } else {
                        0.0
                    }
                })
                .sum();


            let dynamic_count = self
                .targets
                .iter()
                .filter(|t| t.fixed_weight <= 0.0)
                .count() as f64;

            if total_fixed > 1.0 {
                tracing::warn!(
                    total_fixed,
                    "Fixed weights sum exceeds 1.0; dynamic targets will receive no traffic. \
                     Reduce fixed weights or remove weight specifications."
                );
            } else if total_fixed == 1.0 && dynamic_count > 0.0 {
                tracing::debug!(
                    dynamic_count,
                    "Fixed weights sum to exactly 1.0; {} dynamic targets will receive no traffic",
                    dynamic_count as usize
                );
            }

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
#[derive(Debug, Clone)]
pub struct Table {
    /// host -> sorted routes
    routes: HashMap<String, Vec<Arc<Route>>>,
    stats_registry: Option<Arc<TargetStatsRegistry>>,
    /// Circuit breaker config for new targets
    cb_config: Option<crate::route::target::CircuitBreakerConfig>,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            stats_registry: None,
            cb_config: None,
        }
    }

    pub fn with_stats_registry(stats_registry: Arc<TargetStatsRegistry>) -> Self {
        Self {
            routes: HashMap::new(),
            stats_registry: Some(stats_registry),
            cb_config: None,
        }
    }

    pub fn with_cb_config(mut self, cb_config: crate::route::target::CircuitBreakerConfig) -> Self {
        self.cb_config = Some(cb_config);
        self
    }

    /// Lookup a route by host and path.
    /// Returns the matching route (with targets) for the given matcher strategy.
    /// Host is normalized to lowercase to match Fabio semantics (routes are stored lowercased).
    pub fn lookup_route(&self, host: &str, path: &str, matcher: &str) -> Option<&Arc<Route>> {
        // Normalize host to lowercase for case-insensitive matching.
        // HTTP Host headers may be mixed-case (e.g. "Example.com"), but
        // routes from service discovery and KV are stored lowercased.
        let host_lower = host.to_ascii_lowercase();

        // Try exact host match first
        if let Some(routes) = self.routes.get(&host_lower)
            && let Some(route) = Self::find_matching_route(routes, path, matcher)
        {
            return Some(route);
        }

        // Try empty host (catch-all)
        if let Some(routes) = self.routes.get("")
            && let Some(route) = Self::find_matching_route(routes, path, matcher)
        {
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
            source: def.source.clone(),
            parsed_host: None,
            parsed_port: None,
            parsed_tls: false,
            parsed_protocol: crate::route::target::UpstreamProtocol::Http,
            active_connections: self.active_connections_for(&def.dst),
            health_tracker: self.cb_config.as_ref()
                .map(|cb| crate::route::target::TargetHealthTracker::with_config(cb.clone()))
                .unwrap_or_default(),
            stats: Arc::new(crate::route::target::TargetStats::default()),
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
            // Sort by most specific (longest) path first, then lexicographic
            // descending as a tiebreaker — mirrors Fabio's "longest prefix wins"
            // semantics. Pure lexicographic order would wrongly rank `/z` above
            // `/api/v2/users` because 'z' > 'a'.
            host_routes.sort_by(|a, b| {
                b.path
                    .len()
                    .cmp(&a.path.len())
                    .then_with(|| b.path.cmp(&a.path))
            });
        }
    }

    fn apply_del(&mut self, def: &RouteDef) {
        let url = if def.dst.is_empty() {
            None
        } else {
            Some(def.dst.as_str())
        };

        if !def.tags.is_empty() {
            let host = def.src_host().to_string();
            let path = if def.src_path().is_empty() {
                None
            } else {
                Some(format!("/{}", def.src_path()))
            };

            if !host.is_empty() || path.is_some() {
                if let Some(host_routes) = self.routes.get_mut(&host) {
                    for route in host_routes.iter_mut() {
                        if path.as_ref().is_none_or(|p| route.path == *p) {
                            let mut r = (**route).clone();
                            r.remove_targets(&def.service, &def.tags, url);
                            r.compute_weights();
                            *route = Arc::new(r);
                        }
                    }
                    host_routes.retain(|r| !r.targets.is_empty());
                }
                if self.routes.get(&host).is_some_and(|r| r.is_empty()) {
                    self.routes.remove(&host);
                }
            } else {
                for host_routes in self.routes.values_mut() {
                    for route in host_routes.iter_mut() {
                        let mut r = (**route).clone();
                        r.remove_targets(&def.service, &def.tags, url);
                        r.compute_weights();
                        *route = Arc::new(r);
                    }
                    host_routes.retain(|r| !r.targets.is_empty());
                }
                self.routes.retain(|_, routes| !routes.is_empty());
            }
            return;
        }

        let host = def.src_host().to_string();
        if let Some(host_routes) = self.routes.get_mut(&host) {
            let path = if def.src_path().is_empty() {
                None
            } else {
                Some(format!("/{}", def.src_path()))
            };

            for route in host_routes.iter_mut() {
                if path.as_ref().is_none_or(|p| route.path == *p) {
                    let mut r = (**route).clone();
                    r.remove_targets(&def.service, &def.tags, url);
                    r.compute_weights();
                    *route = Arc::new(r);
                }
            }

            host_routes.retain(|r| !r.targets.is_empty());
        }

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
                    let mut r = (**route).clone();
                    let match_count = r
                        .targets
                        .iter()
                        .filter(|target| {
                            (def.service.is_empty() || target.service == def.service)
                                && (def.tags.is_empty()
                                    || def.tags.iter().all(|t| target.tags.contains(t)))
                        })
                        .count();

                    if match_count == 0 {
                        continue;
                    }

                    let fixed_weight = if match_count > 0 {
                        def.weight / match_count as f64
                    } else {
                        def.weight
                    };

                    for i in 0..r.targets.len() {
                        let target = Arc::make_mut(&mut r.targets[i]);
                        if (def.service.is_empty() || target.service == def.service)
                            && (def.tags.is_empty()
                                || def.tags.iter().all(|t| target.tags.contains(t)))
                        {
                            target.fixed_weight = fixed_weight;
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

    pub fn from_definitions_with_stats(
        defs: &[RouteDef],
        stats_registry: Arc<TargetStatsRegistry>,
        cb_config: Option<crate::route::target::CircuitBreakerConfig>,
    ) -> Self {
        let mut table = Table {
            routes: HashMap::new(),
            stats_registry: Some(stats_registry),
            cb_config,
        };
        for def in defs {
            table.apply(def);
        }
        table
    }

    fn active_connections_for(&self, key: &str) -> Arc<std::sync::atomic::AtomicU64> {
        self.stats_registry
            .as_ref()
            .map(|registry| registry.active_connections_for(key))
            .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicU64::new(0)))
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

    pub fn lookup_tcp_route(&self, listen_port: u16) -> Option<&Arc<Route>> {
        let catch_all = format!(":{listen_port}");
        if let Some(routes) = self.routes.get(&catch_all)
            && let Some(route) = routes.iter().find(|route| route_is_tcp(route))
        {
            return Some(route);
        }

        let suffix = format!(":{listen_port}");
        let mut matched: Option<&Arc<Route>> = None;
        for (host, routes) in &self.routes {
            if !host.ends_with(&suffix) {
                continue;
            }
            for route in routes {
                if !route_is_tcp(route) {
                    continue;
                }
                if matched.is_some() {
                    tracing::warn!(
                        listen_port,
                        "Multiple TCP routes found for port; using first match"
                    );
                    break;
                }
                matched = Some(route);
            }
        }

        matched
    }

    pub fn lookup_tcp_route_for_local_addr(&self, local_addr: &str) -> Option<&Arc<Route>> {
        if let Some(routes) = self.routes.get(local_addr)
            && let Some(route) = routes.iter().find(|route| route_is_tcp(route))
        {
            return Some(route);
        }

        parse_listener_port(local_addr).and_then(|port| self.lookup_tcp_route(port))
    }

    pub fn lookup_tcp_sni_route(&self, host: &str) -> Option<&Arc<Route>> {
        self.routes
            .get(&host.to_ascii_lowercase())?
            .iter()
            .find(|route| route.path == "/" && route_is_tcp(route))
    }

    pub fn tcp_listener_ports(&self) -> Vec<u16> {
        let mut ports = BTreeSet::new();
        for (host, routes) in &self.routes {
            if !routes.iter().all(route_is_tcp) {
                continue;
            }

            if let Some(port) = parse_listener_port(host) {
                ports.insert(port);
            }
        }
        ports.into_iter().collect()
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
    stats_registry: Arc<TargetStatsRegistry>,
    cb_config: Option<crate::route::target::CircuitBreakerConfig>,
}

impl RouteTable {
    pub fn new() -> Self {
        let stats_registry = Arc::new(TargetStatsRegistry::new());
        Self {
            inner: ArcSwap::from(Arc::new(Table::with_stats_registry(stats_registry.clone()))),
            stats_registry,
            cb_config: None,
        }
    }

    pub fn with_cb_config(mut self, cb_config: crate::route::target::CircuitBreakerConfig) -> Self {
        self.cb_config = Some(cb_config);
        self
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
        tracing::info!(route_count, target_count, "Routing table updated");
    }

    /// Apply definitions and swap the table.
    pub fn apply_and_swap(&self, defs: &[RouteDef]) {
        let table = Table::from_definitions_with_stats(
            defs,
            self.stats_registry.clone(),
            self.cb_config.clone(),
        );
        self.swap(table);
    }

    pub fn stats_registry(&self) -> Arc<TargetStatsRegistry> {
        self.stats_registry.clone()
    }

    pub fn cb_config(&self) -> Option<crate::route::target::CircuitBreakerConfig> {
        self.cb_config.clone()
    }
}

fn route_is_tcp(route: &Arc<Route>) -> bool {
    !route.targets.is_empty() && route.targets.iter().all(|target| target.is_tcp())
}

fn parse_listener_port(host: &str) -> Option<u16> {
    host.rsplit(':').next()?.parse().ok()
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
            active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
        let svc1_count = route
            .w_targets
            .iter()
            .filter(|t| t.service == "svc1")
            .count();
        let svc2_count = route
            .w_targets
            .iter()
            .filter(|t| t.service == "svc2")
            .count();
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
            source: crate::route::definition::RouteSource::Static,
        }];

        let table = Table::from_definitions(&defs);
        assert!(
            table
                .lookup_route("example.com", "/api/users", "iprefix")
                .is_some()
        );
        assert!(
            table
                .lookup_route("example.com", "/API/users", "iprefix")
                .is_some()
        );
    }

    #[test]
    fn test_delete_routes_by_tags_without_service() {
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-a".to_string(),
                src: "example.com/".to_string(),
                dst: "http://a/".to_string(),
                weight: 0.0,
                tags: vec!["v1".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-b".to_string(),
                src: "example.com/".to_string(),
                dst: "http://b/".to_string(),
                weight: 0.0,
                tags: vec!["v2".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Del,
                service: String::new(),
                src: String::new(),
                dst: String::new(),
                weight: 0.0,
                tags: vec!["v1".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
        ];

        let table = Table::from_definitions(&defs);
        let route = table.lookup_route("example.com", "/", "prefix").unwrap();
        assert_eq!(route.targets.len(), 1);
        assert_eq!(route.targets[0].service, "svc-b");
    }

    #[test]
    fn test_dedup_keeps_targets_separate_when_sources_differ() {
        let mut route = Route::new("example.com".to_string(), "/".to_string());
        let mut static_target = make_target("svc", "http://10.0.0.1:80", 0.0, 0.0);
        static_target.source = crate::route::definition::RouteSource::Static;
        let mut consul_target = make_target("svc", "http://10.0.0.1:80", 0.0, 0.0);
        consul_target.source = crate::route::definition::RouteSource::ConsulService;

        route.add_target(static_target);
        route.add_target(consul_target);

        assert_eq!(route.targets.len(), 2);
    }

    #[test]
    fn test_delete_routes_by_tags_with_src_is_scoped() {
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-a".to_string(),
                src: "example.com/api".to_string(),
                dst: "http://a/".to_string(),
                weight: 0.0,
                tags: vec!["blue".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-b".to_string(),
                src: "example.com/other".to_string(),
                dst: "http://b/".to_string(),
                weight: 0.0,
                tags: vec!["blue".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Del,
                service: String::new(),
                src: "example.com/api".to_string(),
                dst: String::new(),
                weight: 0.0,
                tags: vec!["blue".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
        ];

        let table = Table::from_definitions(&defs);
        assert!(
            table
                .lookup_route("example.com", "/api", "prefix")
                .is_none()
        );
        assert!(
            table
                .lookup_route("example.com", "/other", "prefix")
                .is_some()
        );
    }

    #[test]
    fn test_weight_is_distributed_across_matching_targets() {
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-a".to_string(),
                src: "example.com/".to_string(),
                dst: "http://a/".to_string(),
                weight: 0.0,
                tags: vec!["blue".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-b".to_string(),
                src: "example.com/".to_string(),
                dst: "http://b/".to_string(),
                weight: 0.0,
                tags: vec!["blue".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Weight,
                service: String::new(),
                src: "example.com/".to_string(),
                dst: String::new(),
                weight: 0.6,
                tags: vec!["blue".to_string()],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
        ];

        let table = Table::from_definitions(&defs);
        let route = table.lookup_route("example.com", "/", "prefix").unwrap();
        assert_eq!(route.targets.len(), 2);
        assert!((route.targets[0].fixed_weight - 0.3).abs() < f64::EPSILON);
        assert!((route.targets[1].fixed_weight - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_route_sort_longest_prefix_wins() {
        // Regression: lexicographic sort would rank `/z` before `/api/v2/users`
        // because 'z' > 'a'. Length-first sort must put the longest path first.
        use crate::route::definition::{RouteCmd, RouteSource};
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-z".to_string(),
                src: "example.com/z".to_string(),
                dst: "http://z-upstream:8080".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-api".to_string(),
                src: "example.com/api/v2/users".to_string(),
                dst: "http://api-upstream:8080".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-api-short".to_string(),
                src: "example.com/api".to_string(),
                dst: "http://api-short-upstream:8080".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
        ];

        let table = Table::from_definitions(&defs);

        // `/api/v2/users` must match before `/api` (longer prefix wins)
        let route = table
            .lookup_route("example.com", "/api/v2/users", "prefix")
            .unwrap();
        assert_eq!(
            route.targets[0].service, "svc-api",
            "/api/v2/users should match svc-api, not svc-api-short"
        );

        // `/api/other` must fall back to `/api`
        let route = table
            .lookup_route("example.com", "/api/other", "prefix")
            .unwrap();
        assert_eq!(
            route.targets[0].service, "svc-api-short",
            "/api/other should match svc-api-short"
        );

        // `/z` must still match its own route
        let route = table.lookup_route("example.com", "/z", "prefix").unwrap();
        assert_eq!(route.targets[0].service, "svc-z", "/z should match svc-z");
    }
}

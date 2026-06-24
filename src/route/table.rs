use crate::route::definition::{RouteCmd, RouteDef};
use crate::route::target::{Target, TargetStatsRegistry};
use arc_swap::ArcSwap;
use glob::Pattern;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// Compiled matcher strategy — avoids string comparisons on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherKind {
    Prefix,
    CaseInsensitivePrefix,
    Glob,
    Exact,
}

impl MatcherKind {
    /// Parse from config string. Falls back to Prefix for unknown values.
    #[inline]
    pub fn from_config(s: &str) -> Self {
        match s {
            "prefix" | "" => MatcherKind::Prefix,
            "iprefix" => MatcherKind::CaseInsensitivePrefix,
            "glob" => MatcherKind::Glob,
            "exact" => MatcherKind::Exact,
            _ => MatcherKind::Prefix,
        }
    }
}

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
    /// Counter for round-robin selection. `Arc`-shared so `Route` clones within a
    /// single table build share one counter; it is NOT carried across a full table
    /// rebuild (each rebuild constructs fresh routes via `Route::new`), so the
    /// round-robin phase resets on every route reload.
    pub rr_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl Clone for Route {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            path: self.path.clone(),
            glob: self.glob.clone(),
            targets: self.targets.clone(), // Vec<Arc<Target>> clones cheaply
            w_targets: self.w_targets.clone(),
            rr_counter: Arc::clone(&self.rr_counter),
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
            rr_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
        // Bound per-target slot expansion: a pathological route weight (huge or
        // mis-scaled, e.g. from a Consul tag or admin route command) must not be
        // able to blow up `w_targets` and OOM/stall the process on the lock-held
        // rebuild path. 10x the granularity budget is well beyond any sane weight
        // (normal weights are fractions summing to ~1.0). `f64 as usize` saturates,
        // so this also caps non-finite/overflowing values defensively.
        const MAX_SLOTS_PER_TARGET: usize = 10 * 1000;
        for t in &self.targets {
            let count = ((t.weight * slots as f64).round() as usize).min(MAX_SLOTS_PER_TARGET);
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

        // Interleave w_targets for smoother round-robin distribution.
        // Without interleaving, equal-weight targets are grouped (all A, then all B),
        // causing round-robin to hit only the first target for small N.
        // We interleave proportionally: each target's slots are distributed uniformly
        // across the full range while preserving weight ratios.
        // Example with 3 equal targets: A B C A B C ... instead of A A A B B B C C C.
        // Example with 70/30 weights: A A B A A B A A B A ... (7:3 ratio preserved).
        if self.targets.len() > 1 && !self.w_targets.is_empty() {
            let n = self.w_targets.len();

            // Group consecutive identical targets into runs
            let mut runs: Vec<(Arc<Target>, usize)> = Vec::new();
            let mut i = 0;
            while i < n {
                let current = Arc::clone(&self.w_targets[i]);
                let mut count = 1;
                while i + count < n && Arc::ptr_eq(&self.w_targets[i + count], &current) {
                    count += 1;
                }
                runs.push((current, count));
                i += count;
            }

            if runs.len() > 1 {
                // Weighted interleaving: spread each group's slots uniformly.
                // Use fractional accumulators to distribute proportionally.
                let mut interleaved: Vec<Arc<Target>> = Vec::with_capacity(n);
                let num_groups = runs.len();
                let mut remaining: Vec<usize> = runs.iter().map(|(_, c)| *c).collect();
                let total_remaining: usize = remaining.iter().sum();

                // Use a fractional position for each group to determine next pick.
                // Each group advances by total_remaining / group_count per step,
                // which naturally maintains weight ratios.
                let mut positions: Vec<f64> = (0..num_groups)
                    .map(|g| {
                        let group_total = runs[g].1 as f64;
                        // Start position biased by group size (larger groups start earlier)
                        if group_total > 0.0 {
                            (total_remaining as f64 / group_total) * 0.5
                        } else {
                            f64::MAX
                        }
                    })
                    .collect();

                for _ in 0..n {
                    // Pick the group with the smallest position that still has remaining slots
                    let mut best_group = 0;
                    let mut best_pos = f64::MAX;
                    for g in 0..num_groups {
                        if remaining[g] > 0 && positions[g] < best_pos {
                            best_pos = positions[g];
                            best_group = g;
                        }
                    }
                    interleaved.push(Arc::clone(&runs[best_group].0));
                    remaining[best_group] -= 1;
                    // Advance this group's position by its stride (total / count)
                    let stride = if runs[best_group].1 > 0 {
                        n as f64 / runs[best_group].1 as f64
                    } else {
                        f64::MAX
                    };
                    positions[best_group] += stride;
                }
                self.w_targets = interleaved;
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
    /// Pre-computed unique targets for health checking (populated in finalize)
    all_targets_cache: Vec<Arc<Target>>,
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
            all_targets_cache: Vec::new(),
        }
    }

    pub fn with_stats_registry(stats_registry: Arc<TargetStatsRegistry>) -> Self {
        Self {
            routes: HashMap::new(),
            stats_registry: Some(stats_registry),
            cb_config: None,
            all_targets_cache: Vec::new(),
        }
    }

    pub fn with_cb_config(mut self, cb_config: crate::route::target::CircuitBreakerConfig) -> Self {
        self.cb_config = Some(cb_config);
        self
    }

    /// Lookup a route by host and path.
    /// Returns the matching route (with targets) for the given matcher strategy.
    /// Host is normalized to lowercase to match Fabio semantics (routes are stored lowercased).
    pub fn lookup_route(
        &self,
        host: &str,
        path: &str,
        matcher: MatcherKind,
    ) -> Option<&Arc<Route>> {
        // Normalize host to lowercase for case-insensitive matching.
        // Use Cow to avoid allocation when host is already lowercase.
        let host_key: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };

        // Try exact host match first
        if let Some(routes) = self.routes.get(host_key.as_ref())
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

    /// Returns all routes matching host+path in specificity order.
    /// Used when the first match might fail (e.g., header constraints)
    /// and fallback to less-specific routes is needed.
    pub fn matching_routes(
        &self,
        host: &str,
        path: &str,
        matcher: MatcherKind,
    ) -> SmallVec<[&Arc<Route>; 4]> {
        let host_key: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };

        let mut results = SmallVec::new();

        if let Some(routes) = self.routes.get(host_key.as_ref()) {
            Self::collect_matching_routes(routes, path, matcher, &mut results);
        }

        if !host_key.is_empty()
            && let Some(routes) = self.routes.get("")
        {
            Self::collect_matching_routes(routes, path, matcher, &mut results);
        }

        results
    }

    /// Does `route` match `path` under the active matcher. Single source of
    /// truth for matcher semantics so `collect_matching_routes` and
    /// `find_matching_route` can never drift apart.
    #[inline]
    fn route_matches(route: &Route, path: &str, matcher: MatcherKind) -> bool {
        match matcher {
            MatcherKind::Prefix => path.starts_with(&route.path) || route.path == "/",
            MatcherKind::CaseInsensitivePrefix => {
                starts_with_ignore_ascii_case(path, &route.path) || route.path == "/"
            }
            MatcherKind::Exact => route.path == path,
            // A literal route path carries no compiled glob `Pattern` (Route::new
            // only compiles one when the path has glob metacharacters), but a
            // literal pattern is a glob that matches itself exactly. Falling back
            // to equality keeps every literal route — including the "/" catch-all
            // — reachable under glob mode instead of silently black-holing it.
            MatcherKind::Glob => match route.glob.as_ref() {
                Some(g) => g.matches(path),
                None => route.path == path || route.path == "/",
            },
        }
    }

    #[inline]
    fn collect_matching_routes<'a>(
        routes: &'a [Arc<Route>],
        path: &str,
        matcher: MatcherKind,
        results: &mut SmallVec<[&'a Arc<Route>; 4]>,
    ) {
        for route in routes {
            let matches = Self::route_matches(route, path, matcher);
            if matches && !route.targets.is_empty() {
                results.push(route);
            }
        }
    }

    fn find_matching_route<'a>(
        routes: &'a [Arc<Route>],
        path: &str,
        matcher: MatcherKind,
    ) -> Option<&'a Arc<Route>> {
        for route in routes {
            let matches = Self::route_matches(route, path, matcher);

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
        let host = def.src_host().to_ascii_lowercase();
        let path = if def.src_path().is_empty() {
            "/".to_string()
        } else {
            format!("/{}", def.src_path())
        };

        let edge_stats_key = format!(
            "{host}\u{001f}{path}\u{001f}{}\u{001f}{}",
            def.service, def.dst
        );
        let mut target = Target {
            service: def.service.clone(),
            url: def.dst.clone(),
            fixed_weight: def.weight,
            weight: 0.0,
            tags: def.tags.clone(),
            opts: def.opts.clone(),
            source: def.source.clone(),
            active_connections: self.active_connections_for(&def.dst),
            health_tracker: self.health_tracker_for(&def.dst),
            stats: self.stats_for(&def.dst),
            edge_stats: self.edge_stats_for(&edge_stats_key),
            rate_limiter: Arc::new(crate::proxy::ratelimit::TokenBucket::new()),
            ..Default::default()
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
        }
    }

    fn apply_del(&mut self, def: &RouteDef) {
        let url = if def.dst.is_empty() {
            None
        } else {
            Some(def.dst.as_str())
        };

        if !def.tags.is_empty() {
            let host = def.src_host().to_ascii_lowercase();
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

        let host = def.src_host().to_ascii_lowercase();
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
        let host = def.src_host().to_ascii_lowercase();

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

    /// Sort all per-host route lists by specificity (longest path first).
    /// Must be called after bulk insertions (e.g. from_definitions*) to maintain
    /// Fabio's "longest prefix wins" semantics.
    fn finalize(&mut self) {
        for host_routes in self.routes.values_mut() {
            host_routes.sort_by(|a, b| {
                b.path
                    .len()
                    .cmp(&a.path.len())
                    .then_with(|| b.path.cmp(&a.path))
            });
        }
        // Pre-compute unique targets for health checking
        let mut seen: HashSet<&str> = HashSet::new();
        let mut targets = Vec::new();
        for target in self
            .routes
            .values()
            .flat_map(|r| r.iter())
            .flat_map(|route| &route.targets)
        {
            if seen.insert(&target.url) {
                targets.push(Arc::clone(target));
            }
        }
        self.all_targets_cache = targets;
    }

    /// Build a new table from a list of route definitions.
    pub fn from_definitions(defs: &[RouteDef]) -> Self {
        let mut table = Table::new();
        for def in defs {
            table.apply(def);
        }
        table.finalize();
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
            all_targets_cache: Vec::new(),
        };
        for def in defs {
            table.apply(def);
        }
        table.finalize();
        table
    }

    fn active_connections_for(&self, key: &str) -> Arc<std::sync::atomic::AtomicU64> {
        self.stats_registry
            .as_ref()
            .map(|registry| registry.active_connections_for(key))
            .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicU64::new(0)))
    }

    fn stats_for(&self, key: &str) -> Arc<crate::route::target::TargetStats> {
        self.stats_registry
            .as_ref()
            .map(|registry| registry.stats_for(key))
            .unwrap_or_else(|| Arc::new(crate::route::target::TargetStats::default()))
    }

    fn edge_stats_for(&self, key: &str) -> Arc<crate::route::target::TargetStats> {
        self.stats_registry
            .as_ref()
            .map(|registry| registry.edge_stats_for(key))
            .unwrap_or_else(|| Arc::new(crate::route::target::TargetStats::default()))
    }

    fn health_tracker_for(&self, key: &str) -> Arc<crate::route::target::TargetHealthTracker> {
        self.stats_registry
            .as_ref()
            .map(|registry| registry.health_tracker_for(key, self.cb_config.as_ref()))
            .unwrap_or_else(|| {
                Arc::new(
                    self.cb_config
                        .clone()
                        .map(crate::route::target::TargetHealthTracker::with_config)
                        .unwrap_or_default(),
                )
            })
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

    /// Get all unique targets across all routes (for health checking).
    /// Deduplicates by target URL to avoid probing the same backend twice.
    /// Returns pre-computed cache populated during finalize().
    pub fn all_targets(&self) -> &[Arc<Target>] {
        &self.all_targets_cache
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

    /// Iterate all (host, route, target) triples in the table.
    /// Used by admin API handlers to avoid duplicate iteration boilerplate.
    pub fn iter_targets(
        &self,
    ) -> impl Iterator<Item = (&str, &Arc<Route>, &Arc<crate::route::target::Target>)> {
        self.routes.iter().flat_map(|(host, routes)| {
            routes.iter().flat_map(move |route| {
                route
                    .targets
                    .iter()
                    .map(move |target| (host.as_str(), route, target))
            })
        })
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
    cb_config: std::sync::RwLock<Option<crate::route::target::CircuitBreakerConfig>>,
}

impl RouteTable {
    pub fn new() -> Self {
        let stats_registry = Arc::new(TargetStatsRegistry::new());
        Self {
            inner: ArcSwap::from(Arc::new(Table::with_stats_registry(stats_registry.clone()))),
            stats_registry,
            cb_config: std::sync::RwLock::new(None),
        }
    }

    pub fn with_cb_config(self, cb_config: crate::route::target::CircuitBreakerConfig) -> Self {
        *self.cb_config.write().unwrap_or_else(|e| e.into_inner()) = Some(cb_config);
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
        let table =
            Table::from_definitions_with_stats(defs, self.stats_registry.clone(), self.cb_config());
        self.swap(table);
    }

    pub fn stats_registry(&self) -> Arc<TargetStatsRegistry> {
        self.stats_registry.clone()
    }

    pub fn cb_config(&self) -> Option<crate::route::target::CircuitBreakerConfig> {
        self.cb_config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_cb_config(&self, cb_config: Option<crate::route::target::CircuitBreakerConfig>) {
        *self.cb_config.write().unwrap_or_else(|e| e.into_inner()) = cb_config;
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
    fn test_compute_weights_bounds_pathological_weight() {
        // A pathological/huge route weight must not expand w_targets without
        // bound (DoS guard on the lock-held rebuild path).
        let mut route = Route::new("example.com".to_string(), "/".to_string());
        route.add_target(make_target("svc", "http://10.0.0.1:80", 1.0e9, 1.0e9));
        route.compute_weights();
        assert!(
            !route.w_targets.is_empty(),
            "a positive-weight target must still receive slots"
        );
        assert!(
            route.w_targets.len() <= 10_000,
            "w_targets must be bounded, got {}",
            route.w_targets.len()
        );
    }

    #[test]
    fn test_exact_matcher_requires_full_path() {
        let defs = vec![RouteDef {
            cmd: RouteCmd::Add,
            service: "svc".to_string(),
            src: "example.com/admin".to_string(),
            dst: "http://127.0.0.1:8080/".to_string(),
            weight: 0.0,
            tags: vec![],
            opts: HashMap::new(),
            source: crate::route::definition::RouteSource::Static,
        }];
        let table = Table::from_definitions(&defs);
        assert!(
            table
                .lookup_route("example.com", "/admin", MatcherKind::Exact)
                .is_some(),
            "exact path must match"
        );
        assert!(
            table
                .lookup_route("example.com", "/admin-backup", MatcherKind::Exact)
                .is_none(),
            "exact matcher must NOT match a prefix superstring"
        );
        assert!(
            table
                .lookup_route("example.com", "/admin/secret", MatcherKind::Exact)
                .is_none(),
            "exact matcher must NOT match a subpath"
        );
    }

    #[test]
    fn test_glob_matcher_keeps_literal_and_catchall_reachable() {
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-literal".to_string(),
                src: "example.com/api".to_string(),
                dst: "http://127.0.0.1:8080/".to_string(),
                weight: 0.0,
                tags: vec![],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-catchall".to_string(),
                src: "/".to_string(),
                dst: "http://127.0.0.1:9090/".to_string(),
                weight: 0.0,
                tags: vec![],
                opts: HashMap::new(),
                source: crate::route::definition::RouteSource::Static,
            },
        ];
        let table = Table::from_definitions(&defs);
        // Regression: a literal route path (no compiled glob Pattern) must remain
        // reachable under glob mode instead of being silently black-holed.
        assert!(
            table
                .lookup_route("example.com", "/api", MatcherKind::Glob)
                .is_some(),
            "literal route must match itself under glob mode"
        );
        // The "/" catch-all must still match any path under glob mode.
        assert!(
            table
                .lookup_route("other.com", "/anything", MatcherKind::Glob)
                .is_some(),
            "catch-all must match under glob mode"
        );
    }

    #[test]
    fn test_glob_matcher_matches_wildcard_pattern() {
        let defs = vec![RouteDef {
            cmd: RouteCmd::Add,
            service: "svc".to_string(),
            src: "example.com/api/*".to_string(),
            dst: "http://127.0.0.1:8080/".to_string(),
            weight: 0.0,
            tags: vec![],
            opts: HashMap::new(),
            source: crate::route::definition::RouteSource::Static,
        }];
        let table = Table::from_definitions(&defs);
        assert!(
            table
                .lookup_route("example.com", "/api/users", MatcherKind::Glob)
                .is_some(),
            "wildcard glob must match a subpath"
        );
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
                .lookup_route(
                    "example.com",
                    "/api/users",
                    MatcherKind::CaseInsensitivePrefix
                )
                .is_some()
        );
        assert!(
            table
                .lookup_route(
                    "example.com",
                    "/API/users",
                    MatcherKind::CaseInsensitivePrefix
                )
                .is_some()
        );
    }

    #[test]
    fn test_static_route_host_is_normalized_to_lowercase() {
        let defs = vec![RouteDef {
            cmd: RouteCmd::Add,
            service: "svc".to_string(),
            src: "Example.COM/".to_string(),
            dst: "http://127.0.0.1:8080/".to_string(),
            weight: 0.0,
            tags: vec![],
            opts: HashMap::new(),
            source: crate::route::definition::RouteSource::Static,
        }];

        let table = Table::from_definitions(&defs);
        assert!(
            table
                .lookup_route("example.com", "/", MatcherKind::Prefix)
                .is_some()
        );
        assert!(
            table
                .lookup_route("EXAMPLE.COM", "/", MatcherKind::Prefix)
                .is_some()
        );
    }

    #[test]
    fn test_target_stats_and_health_are_preserved_across_rebuilds() {
        let registry = Arc::new(TargetStatsRegistry::new());
        let defs = vec![RouteDef {
            cmd: RouteCmd::Add,
            service: "svc".to_string(),
            src: "example.com/".to_string(),
            dst: "http://127.0.0.1:8080/".to_string(),
            weight: 0.0,
            tags: vec![],
            opts: HashMap::new(),
            source: crate::route::definition::RouteSource::Static,
        }];
        let cb_config = crate::route::target::CircuitBreakerConfig {
            error_threshold: 50,
            window_size: 2,
            recovery_timeout_secs: 30,
            half_open_max_requests: 1,
        };

        let first =
            Table::from_definitions_with_stats(&defs, registry.clone(), Some(cb_config.clone()));
        let first_target = first
            .lookup_route("example.com", "/", MatcherKind::Prefix)
            .unwrap()
            .targets[0]
            .clone();
        first_target.stats.record_request(100, 10, true);
        first_target.health_tracker.circuit_breaker().record_error();
        first_target.health_tracker.circuit_breaker().record_error();
        assert_eq!(
            first_target
                .health_tracker
                .circuit_breaker()
                .current_state(),
            crate::route::target::CircuitState::Open
        );

        let second = Table::from_definitions_with_stats(&defs, registry, Some(cb_config));
        let second_target = second
            .lookup_route("example.com", "/", MatcherKind::Prefix)
            .unwrap()
            .targets[0]
            .clone();
        assert_eq!(
            second_target
                .stats
                .requests_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            second_target
                .health_tracker
                .circuit_breaker()
                .current_state(),
            crate::route::target::CircuitState::Open
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
        let route = table
            .lookup_route("example.com", "/", MatcherKind::Prefix)
            .unwrap();
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
                .lookup_route("example.com", "/api", MatcherKind::Prefix)
                .is_none()
        );
        assert!(
            table
                .lookup_route("example.com", "/other", MatcherKind::Prefix)
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
        let route = table
            .lookup_route("example.com", "/", MatcherKind::Prefix)
            .unwrap();
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
            .lookup_route("example.com", "/api/v2/users", MatcherKind::Prefix)
            .unwrap();
        assert_eq!(
            route.targets[0].service, "svc-api",
            "/api/v2/users should match svc-api, not svc-api-short"
        );

        // `/api/other` must fall back to `/api`
        let route = table
            .lookup_route("example.com", "/api/other", MatcherKind::Prefix)
            .unwrap();
        assert_eq!(
            route.targets[0].service, "svc-api-short",
            "/api/other should match svc-api-short"
        );

        // `/z` must still match its own route
        let route = table
            .lookup_route("example.com", "/z", MatcherKind::Prefix)
            .unwrap();
        assert_eq!(route.targets[0].service, "svc-z", "/z should match svc-z");
    }

    #[test]
    fn test_matching_routes_returns_all_in_specificity_order() {
        use crate::route::definition::{RouteCmd, RouteSource};
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-specific".to_string(),
                src: "example.com/api/v2".to_string(),
                dst: "http://specific:8080".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-broad".to_string(),
                src: "example.com/api".to_string(),
                dst: "http://broad:8080".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
        ];

        let table = Table::from_definitions(&defs);
        let routes = table.matching_routes("example.com", "/api/v2/users", MatcherKind::Prefix);

        assert_eq!(routes.len(), 2, "Should find both matching routes");
        assert_eq!(
            routes[0].targets[0].service, "svc-specific",
            "Most specific first"
        );
        assert_eq!(
            routes[1].targets[0].service, "svc-broad",
            "Less specific second"
        );
    }

    #[test]
    fn test_matching_routes_includes_catch_all() {
        use crate::route::definition::{RouteCmd, RouteSource};
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-host".to_string(),
                src: "example.com/api".to_string(),
                dst: "http://host:8080".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
            // Catch-all route (empty host + "/" path)
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-catchall".to_string(),
                src: "/".to_string(),
                dst: "http://catchall:8080".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
        ];

        let table = Table::from_definitions(&defs);
        let routes = table.matching_routes("example.com", "/api", MatcherKind::Prefix);

        // Should include both host-specific and catch-all routes
        let services: Vec<&str> = routes
            .iter()
            .map(|r| r.targets[0].service.as_str())
            .collect();
        assert!(
            services.contains(&"svc-host"),
            "Should find host-specific route"
        );
        assert!(
            services.contains(&"svc-catchall"),
            "Should find catch-all route"
        );
    }

    #[test]
    fn test_rr_counter_preserved_across_clone() {
        let mut route = Route::new("example.com".to_string(), "/".to_string());
        route.add_target(make_target("svc1", "http://1.0.0.1:80", 1.0, 1.0));
        route.compute_weights();

        // Increment counter on original
        route
            .rr_counter
            .fetch_add(42, std::sync::atomic::Ordering::Relaxed);

        // Clone and verify counter is shared
        let cloned = route.clone();
        let val = cloned.rr_counter.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(val, 42, "Cloned route should share the same rr_counter");

        // Increment on clone and verify original sees it
        cloned
            .rr_counter
            .fetch_add(8, std::sync::atomic::Ordering::Relaxed);
        let val = route.rr_counter.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(val, 50, "Original should see increments from clone");
    }

    #[test]
    fn test_all_targets_cache_populated_on_finalize() {
        use crate::route::definition::{RouteCmd, RouteSource};
        let defs = vec![
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-a".to_string(),
                src: "host1.com/".to_string(),
                dst: "http://10.0.0.1:80".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-b".to_string(),
                src: "host2.com/".to_string(),
                dst: "http://10.0.0.2:80".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
            // Same URL as svc-a — should be deduplicated in cache
            RouteDef {
                cmd: RouteCmd::Add,
                service: "svc-a-dupe".to_string(),
                src: "host3.com/".to_string(),
                dst: "http://10.0.0.1:80".to_string(),
                weight: 1.0,
                tags: vec![],
                opts: HashMap::new(),
                source: RouteSource::Static,
            },
        ];

        let table = Table::from_definitions(&defs);
        let targets = table.all_targets();

        assert_eq!(targets.len(), 2, "Duplicate URLs should be deduplicated");
        let urls: Vec<&str> = targets.iter().map(|t| t.url.as_str()).collect();
        assert!(urls.contains(&"http://10.0.0.1:80"));
        assert!(urls.contains(&"http://10.0.0.2:80"));
    }
}

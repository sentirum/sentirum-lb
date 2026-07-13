use crate::route::definition::{RouteDef, RouteSource};
use crate::route::table::{RouteTable, Table};
use arc_swap::ArcSwap;
use std::sync::Arc;

/// Central registry that merges routes from multiple sources:
/// - Static routes (file)
/// - KV routes (Consul KV)
/// - Service routes (Consul health checks)
#[derive(Debug, Default, Clone)]
pub struct RouteRegistry {
    /// Static routes from file (never auto-updated)
    static_routes: Vec<RouteDef>,
    /// KV routes from Consul
    kv_routes: Vec<RouteDef>,
    /// Service routes from Consul health checks
    service_routes: Vec<RouteDef>,
}

impl RouteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set static routes (from file)
    pub fn set_static(&mut self, routes: Vec<RouteDef>) {
        self.static_routes = routes;
    }

    /// Get current static routes
    pub fn static_routes(&self) -> &[RouteDef] {
        &self.static_routes
    }

    /// Get current KV routes
    pub fn kv_routes(&self) -> &[RouteDef] {
        &self.kv_routes
    }

    /// Get current service routes
    pub fn service_routes(&self) -> &[RouteDef] {
        &self.service_routes
    }

    /// Update KV routes
    pub fn update_kv(&mut self, routes: Vec<RouteDef>) {
        self.kv_routes = routes;
    }

    /// Update service routes
    pub fn update_services(&mut self, routes: Vec<RouteDef>) {
        self.service_routes = routes;
    }

    /// Get all routes merged (priority: static > kv > service)
    pub fn get_all(&self) -> Vec<RouteDef> {
        let mut all = Vec::new();
        all.extend(self.static_routes.clone());
        all.extend(self.kv_routes.clone());
        all.extend(self.service_routes.clone());
        all
    }

    /// Check if any routes exist
    pub fn is_empty(&self) -> bool {
        self.static_routes.is_empty() && self.kv_routes.is_empty() && self.service_routes.is_empty()
    }
}

use std::sync::Mutex;

/// Route table that uses a registry for source management.
/// Supports multiple route sources (static, KV, service) without data loss.
/// This wraps RouteTable for thread-safe access.
pub struct ManagedRouteTable {
    inner: RouteTable,
    registry: ArcSwap<RouteRegistry>,
    update_lock: Mutex<()>,
}

impl ManagedRouteTable {
    pub fn new() -> Self {
        Self {
            inner: RouteTable::new(),
            registry: ArcSwap::from(Arc::new(RouteRegistry::new())),
            update_lock: Mutex::new(()),
        }
    }

    /// Load static routes (from file)
    pub fn load_static(&self, defs: &[RouteDef]) {
        let _guard = self.update_lock.lock().unwrap_or_else(|e| {
            tracing::warn!("Route update lock was poisoned; recovering");
            e.into_inner()
        });
        let mut registry = (**self.registry.load()).clone();
        registry.set_static(mark_sources(defs.to_vec(), RouteSource::Static));
        self.rebuild_and_swap(&registry, "static");
    }

    /// Append additional static routes to the existing set.
    /// Preserves existing KV and service-discovery routes.
    pub fn append_static(&self, new_defs: Vec<RouteDef>) {
        let _guard = self.update_lock.lock().unwrap_or_else(|e| {
            tracing::warn!("Route update lock was poisoned; recovering");
            e.into_inner()
        });
        let mut registry = (**self.registry.load()).clone();
        let mut existing = registry.static_routes.clone();
        existing.extend(mark_sources(new_defs, RouteSource::Static));
        registry.set_static(existing);
        self.rebuild_and_swap(&registry, "static");
    }

    /// Update KV routes
    pub fn update_kv(&self, defs: Vec<RouteDef>) {
        let _guard = self.update_lock.lock().unwrap_or_else(|e| {
            tracing::warn!("Route update lock was poisoned; recovering");
            e.into_inner()
        });
        let mut registry = (**self.registry.load()).clone();
        registry.update_kv(mark_sources(defs, RouteSource::ConsulKv));
        self.rebuild_and_swap(&registry, "kv");
    }

    /// Update service routes
    pub fn update_services(&self, defs: Vec<RouteDef>) {
        let _guard = self.update_lock.lock().unwrap_or_else(|e| {
            tracing::warn!("Route update lock was poisoned; recovering");
            e.into_inner()
        });
        let mut registry = (**self.registry.load()).clone();
        registry.update_services(mark_sources(defs, RouteSource::ConsulService));
        self.rebuild_and_swap(&registry, "service");
    }

    /// Rebuild table from registry and atomically swap
    fn rebuild_and_swap(&self, registry: &RouteRegistry, source: &str) {
        let all_defs = registry.get_all();
        let table = Table::from_definitions_with_stats(
            &all_defs,
            self.inner.stats_registry(),
            self.inner.cb_config(),
        );
        let route_count = table.route_count();
        let target_count = table.target_count();
        self.registry.store(Arc::new(registry.clone()));
        self.inner.swap(table);
        crate::metrics::prometheus::global().record_route_reload(source);
        tracing::info!(
            route_count,
            target_count,
            source,
            is_empty = registry.is_empty(),
            "Route table updated"
        );
    }

    /// Create a new managed route table with circuit breaker configuration.
    pub fn new_with_cb_config(cb_config: crate::route::target::CircuitBreakerConfig) -> Self {
        let route_table = RouteTable::new().with_cb_config(cb_config);
        Self {
            inner: route_table,
            registry: ArcSwap::from(Arc::new(RouteRegistry::new())),
            update_lock: Mutex::new(()),
        }
    }

    /// Reconfigure per-target circuit breaker settings and rebuild the table.
    ///
    /// **Note:** This rebuilds the entire route table. Existing circuit-breaker
    /// state (open / half-open windows, failure history) is **not** preserved —
    /// all breakers reset to Closed. Open breakers will immediately start
    /// accepting traffic again.
    pub fn reconfigure_circuit_breaker(
        &self,
        cb_config: Option<crate::route::target::CircuitBreakerConfig>,
    ) {
        let _guard = self.update_lock.lock().unwrap_or_else(|e| {
            tracing::warn!("Route update lock was poisoned; recovering");
            e.into_inner()
        });
        tracing::warn!(
            enabled = cb_config.is_some(),
            "Circuit breaker configuration changed — all breaker states will reset to Closed. \
             Active open/half-open breakers will allow traffic again."
        );
        self.inner.stats_registry().clear_health_trackers();
        self.inner.set_cb_config(cb_config.clone());
        let registry = self.registry.load();
        let table = Table::from_definitions_with_stats(
            &registry.get_all(),
            self.inner.stats_registry(),
            cb_config,
        );
        self.inner.swap(table);
        tracing::info!(
            enabled = self.inner.cb_config().is_some(),
            "Circuit breaker configuration updated"
        );
    }

    /// Get current snapshot of the routing table (for hot path)
    /// This returns `Arc<Table>`, which is what `RouteTable::get()` returns.
    pub fn get(&self) -> Arc<Table> {
        self.inner.get()
    }

    /// Apply and swap (legacy compatibility for static routes)
    pub fn apply_and_swap(&self, defs: &[RouteDef]) {
        self.load_static(defs);
    }
}

impl Default for ManagedRouteTable {
    fn default() -> Self {
        Self::new()
    }
}

fn mark_sources(defs: Vec<RouteDef>, source: RouteSource) -> Vec<RouteDef> {
    defs.into_iter()
        .map(|mut def| {
            def.source = source.clone();
            def
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::definition::{RouteCmd, RouteDef};
    use crate::route::picker::{LeastConnectionsPicker, Picker};
    use std::collections::HashMap;

    fn def(service: &str, src: &str, dst: &str) -> RouteDef {
        RouteDef {
            cmd: RouteCmd::Add,
            service: service.to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            weight: 0.0,
            tags: vec![],
            opts: HashMap::new(),
            source: RouteSource::Static,
        }
    }

    #[test]
    fn preserves_static_routes_when_kv_updates_arrive() {
        let table = ManagedRouteTable::new();
        table.load_static(&[def("static", "example.com/", "http://static/")]);
        table.update_kv(vec![def("kv", "kv.example.com/", "http://kv/")]);

        let snapshot = table.get();
        assert!(
            snapshot
                .lookup_route("example.com", "/", crate::route::table::MatcherKind::Prefix)
                .is_some()
        );
        assert!(
            snapshot
                .lookup_route(
                    "kv.example.com",
                    "/",
                    crate::route::table::MatcherKind::Prefix
                )
                .is_some()
        );
    }

    #[test]
    fn preserves_kv_routes_when_service_updates_arrive() {
        let table = ManagedRouteTable::new();
        table.update_kv(vec![def("kv", "kv.example.com/", "http://kv/")]);
        table.update_services(vec![def("svc", "/api", "http://svc/")]);

        let snapshot = table.get();
        assert!(
            snapshot
                .lookup_route(
                    "kv.example.com",
                    "/",
                    crate::route::table::MatcherKind::Prefix
                )
                .is_some()
        );
        assert!(
            snapshot
                .lookup_route("", "/api/users", crate::route::table::MatcherKind::Prefix)
                .is_some()
        );
    }

    #[test]
    fn preserves_active_connection_counters_across_rebuilds() {
        let table = ManagedRouteTable::new();
        table.update_services(vec![def("svc-a", "/", "http://10.0.0.1:8080/")]);

        let first_snapshot = table.get();
        let first_route = first_snapshot
            .lookup_route("", "/", crate::route::table::MatcherKind::Prefix)
            .unwrap();
        let first_target = first_route.targets[0].clone();
        first_target
            .active_connections
            .store(7, std::sync::atomic::Ordering::Relaxed);

        table.update_services(vec![def("svc-a", "/", "http://10.0.0.1:8080/")]);

        let second_snapshot = table.get();
        let second_route = second_snapshot
            .lookup_route("", "/", crate::route::table::MatcherKind::Prefix)
            .unwrap();
        let second_target = second_route.targets[0].clone();

        assert_eq!(
            second_target
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed),
            7
        );
    }

    #[test]
    fn least_connections_picker_uses_preserved_counters_after_rebuild() {
        let table = ManagedRouteTable::new();
        table.update_services(vec![
            def("svc-a", "/", "http://10.0.0.1:8080/"),
            def("svc-b", "/", "http://10.0.0.2:8080/"),
        ]);

        let first_snapshot = table.get();
        let first_route = first_snapshot
            .lookup_route("", "/", crate::route::table::MatcherKind::Prefix)
            .unwrap();
        first_route.targets[0]
            .active_connections
            .store(10, std::sync::atomic::Ordering::Relaxed);
        first_route.targets[1]
            .active_connections
            .store(2, std::sync::atomic::Ordering::Relaxed);

        table.update_services(vec![
            def("svc-a", "/", "http://10.0.0.1:8080/"),
            def("svc-b", "/", "http://10.0.0.2:8080/"),
        ]);

        let second_snapshot = table.get();
        let second_route = second_snapshot
            .lookup_route("", "/", crate::route::table::MatcherKind::Prefix)
            .unwrap();
        let picker = LeastConnectionsPicker;
        let picked = picker
            .pick(
                &second_route.targets,
                &second_route.w_targets,
                &second_route.rr_counter,
            )
            .unwrap();

        assert_eq!(picked.url, "http://10.0.0.2:8080/");
    }
}

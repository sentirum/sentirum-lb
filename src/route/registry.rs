use crate::route::definition::{RouteDef, RouteSource};
use crate::route::table::{Table, RouteTable};
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
        let _guard = self.update_lock.lock().unwrap();
        let mut registry = (**self.registry.load()).clone();
        registry.set_static(mark_sources(defs.to_vec(), RouteSource::Static));
        self.rebuild_and_swap(&registry);
    }

    /// Update KV routes
    pub fn update_kv(&self, defs: Vec<RouteDef>) {
        let _guard = self.update_lock.lock().unwrap();
        let mut registry = (**self.registry.load()).clone();
        registry.update_kv(mark_sources(defs, RouteSource::ConsulKv));
        self.rebuild_and_swap(&registry);
    }

    /// Update service routes
    pub fn update_services(&self, defs: Vec<RouteDef>) {
        let _guard = self.update_lock.lock().unwrap();
        let mut registry = (**self.registry.load()).clone();
        registry.update_services(mark_sources(defs, RouteSource::ConsulService));
        self.rebuild_and_swap(&registry);
    }

    /// Rebuild table from registry and atomically swap
    fn rebuild_and_swap(&self, registry: &RouteRegistry) {
        let all_defs = registry.get_all();
        let table = Table::from_definitions(&all_defs);
        let route_count = table.route_count();
        let target_count = table.target_count();
        self.registry.store(Arc::new(registry.clone()));
        self.inner.swap(table);
        tracing::info!(route_count, target_count, is_empty = registry.is_empty(), "Route table updated");
    }

    /// Get current snapshot of the routing table (for hot path)
    /// This returns Arc<Table> which is what RouteTable::get() returns
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
        assert!(snapshot.lookup_route("example.com", "/", "prefix").is_some());
        assert!(snapshot.lookup_route("kv.example.com", "/", "prefix").is_some());
    }

    #[test]
    fn preserves_kv_routes_when_service_updates_arrive() {
        let table = ManagedRouteTable::new();
        table.update_kv(vec![def("kv", "kv.example.com/", "http://kv/")]);
        table.update_services(vec![def("svc", "/api", "http://svc/")]);

        let snapshot = table.get();
        assert!(snapshot.lookup_route("kv.example.com", "/", "prefix").is_some());
        assert!(snapshot.lookup_route("", "/api/users", "prefix").is_some());
    }
}

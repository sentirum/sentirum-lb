//! Consul watcher for Sentirum LB
//! Implements blocking queries to watch for Consul state changes

use crate::consul::client::{ConsulClient, ConsulConfig, HealthCheck, HEALTH_STATUS_CRITICAL};
use crate::route::definition::{RouteCmd, RouteDef};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Route update event from Consul watcher
#[derive(Debug)]
pub enum RouteUpdate {
    /// Service-based routes from health checks
    Services(Vec<RouteDef>),
    /// Manual KV-based routes
    Manual(String),
    /// Error occurred
    Error(String),
}

/// Service health monitor
#[derive(Clone)]
pub struct ServiceMonitor {
    client: Arc<ConsulClient>,
    config: ConsulConfig,
}

impl ServiceMonitor {
    pub fn new(client: Arc<ConsulClient>, config: ConsulConfig) -> Self {
        Self { client, config }
    }

    /// Watch health checks and generate route updates
    pub async fn watch(&self, updates: mpsc::Sender<RouteUpdate>) {
        let mut last_index: u64 = 0;
        let tag_prefix = self.config.tag_prefix.clone();

        loop {
            match self.client.get_health_checks(last_index).await {
                Ok((checks, new_index)) => {
                    if new_index != last_index || !checks.is_empty() {
                        last_index = new_index;
                        let route_defs = self.process_checks(&checks, &tag_prefix).await;
                        if updates.send(RouteUpdate::Services(route_defs)).await.is_err() {
                            tracing::warn!("Consul watcher: channel closed, stopping");
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Consul health check error: {}", e);
                    let _ = updates.send(RouteUpdate::Error(e.to_string())).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Process health checks to determine passing services
    async fn process_checks(&self, checks: &[HealthCheck], tag_prefix: &str) -> Vec<RouteDef> {
        let relevant_checks: Vec<&HealthCheck> = checks
            .iter()
            .filter(|c| {
                c.check_id == "serfHealth"
                    || c.check_id == "_node_maintenance"
                    || c.check_id.starts_with("_service_maintenance:")
                    || c.service_tags.iter().any(|t| t.starts_with(tag_prefix))
            })
            .collect();

        tracing::debug!(
            relevant = relevant_checks.len(),
            total = checks.len(),
            "Filtered health checks"
        );

        let passing_services = self.passing_service_ids(&relevant_checks);

        if passing_services.is_empty() {
            return Vec::new();
        }

        // Concurrent catalog queries (like Fabio's goroutine approach)
        let service_names: Vec<String> = passing_services.keys().cloned().collect();
        let fetch_tasks: Vec<_> = service_names
            .iter()
            .map(|name| {
                let client = self.client.clone();
                let name_clone = name.clone();
                async move { client.get_catalog_service(&name_clone).await }
            })
            .collect();

        let catalog_results = futures::future::join_all(fetch_tasks).await;

        let mut config = Vec::new();
        for (idx, result) in catalog_results.into_iter().enumerate() {
            let service_name = &service_names[idx];
            let service_ids = passing_services.get(service_name).unwrap();

            match result {
                Ok(instances) => {
                    for instance in instances {
                        let instance_id = format!("{}.{}", instance.node, instance.id);
                        if !service_ids.contains(&instance_id) {
                            continue;
                        }

                        for tag in &instance.service_tags {
                            if tag.starts_with(tag_prefix)
                                && let Some(route_def) = self.parse_tag(
                                    tag,
                                    &instance.address,
                                    instance.service_port,
                                    service_name,
                                ) {
                                    config.push(route_def);
                                }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get catalog service {}: {}", service_name, e);
                }
            }
        }

        // Sort by path (reverse) for most specific first
        config.sort_by(|a, b| {
            let a_path = a.src_path();
            let b_path = b.src_path();
            b_path.cmp(a_path)
        });

        config
    }

    /// Get passing service IDs grouped by service name
    fn passing_service_ids(&self, checks: &[&HealthCheck]) -> HashMap<String, Vec<String>> {
        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        for check in checks {
            if check.check_id == "serfHealth" || check.check_id == "_node_maintenance" {
                if !check.service_name.is_empty() {
                    let id = format!("{}.{}", check.node, check.service_id);
                    result
                        .entry(check.service_name.clone())
                        .or_default()
                        .push(id);
                }
                continue;
            }

            if check.check_id.starts_with("_service_maintenance:") {
                continue;
            }

            if check.status != HEALTH_STATUS_CRITICAL {
                let id = format!("{}.{}", check.node, check.service_id);
                result
                    .entry(check.service_name.clone())
                    .or_default()
                    .push(id);
            }
        }

        result
    }

    /// Parse a tag like "urlprefix-/api" -> route add
    /// Supports both http and https schemes
    fn parse_tag(
        &self,
        tag: &str,
        address: &str,
        port: u16,
        service: &str,
    ) -> Option<RouteDef> {
        let tag_content = tag.strip_prefix(&self.config.tag_prefix)?;
        let parts: Vec<&str> = tag_content.splitn(2, ' ').collect();
        let path = parts.first().unwrap_or(&"/");

        // Determine scheme: check tag content for https, default to http
        let scheme = if tag.contains("https://") || tag.contains("proto=https") {
            "https"
        } else {
            "http"
        };
        let dst = format!("{}://{}:{}/", scheme, address, port);

        // Extract options from remaining parts
        let mut opts = HashMap::new();
        if let Some(rest) = parts.get(1) {
            for opt in rest.split_whitespace() {
                let opt_parts: Vec<&str> = opt.splitn(2, '=').collect();
                if opt_parts.len() == 2 {
                    opts.insert(opt_parts[0].to_string(), opt_parts[1].to_string());
                }
            }
        }

        // Build source path
        let src = if path.is_empty() || *path == "/" {
            format!("{}/", service)
        } else {
            format!("{}/{}", service, path.trim_start_matches('/'))
        };

        Some(RouteDef {
            cmd: RouteCmd::Add,
            service: service.to_string(),
            src,
            dst,
            weight: 0.0,
            tags: vec![],
            opts,
        })
    }
}

/// KV watcher for manual route configuration
#[derive(Clone)]
pub struct KVWatcher {
    client: Arc<ConsulClient>,
    config: ConsulConfig,
}

impl KVWatcher {
    pub fn new(client: Arc<ConsulClient>, config: ConsulConfig) -> Self {
        Self { client, config }
    }

    /// Watch KV path for manual route changes
    pub async fn watch(&self, updates: mpsc::Sender<RouteUpdate>) {
        let mut last_index: u64 = 0;
        let kv_path = self.config.kv_prefix.clone();

        loop {
            match self.client.watch_kv(&kv_path, last_index).await {
                Ok((value, new_index)) => {
                    if new_index != last_index {
                        last_index = new_index;
                        let update = RouteUpdate::Manual(value.unwrap_or_default());

                        if updates.send(update).await.is_err() {
                            tracing::warn!("KV watcher: channel closed, stopping");
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Consul KV error: {}", e);
                    let _ = updates.send(RouteUpdate::Error(e.to_string())).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}

/// Combined watcher that runs both service and KV watchers
pub struct ConsulWatcher {
    service_monitor: ServiceMonitor,
    kv_watcher: KVWatcher,
}

impl ConsulWatcher {
    pub fn new(client: Arc<ConsulClient>, config: ConsulConfig) -> Self {
        Self {
            service_monitor: ServiceMonitor::new(client.clone(), config.clone()),
            kv_watcher: KVWatcher::new(client, config),
        }
    }

    /// Start the watcher and send updates to the channel.
    /// Both watchers run independently — one crashing doesn't stop the other.
    pub async fn run(&self, updates: mpsc::Sender<RouteUpdate>) {
        let (svc_tx, kv_tx) = (updates.clone(), updates);

        // Spawn service monitor as independent task
        let svc_handle = tokio::spawn({
            let monitor = self.service_monitor.clone();
            async move {
                monitor.watch(svc_tx).await;
                tracing::warn!("Service monitor task ended");
            }
        });

        // Spawn KV watcher as independent task
        let kv_handle = tokio::spawn({
            let watcher = self.kv_watcher.clone();
            async move {
                watcher.watch(kv_tx).await;
                tracing::warn!("KV watcher task ended");
            }
        });

        // Wait for both — they run independently, neither blocks the other
        let (svc_res, kv_res) = tokio::join!(svc_handle, kv_handle);
        if let Err(e) = svc_res {
            tracing::error!(error = %e, "Service monitor task panicked");
        }
        if let Err(e) = kv_res {
            tracing::error!(error = %e, "KV watcher task panicked");
        }
    }
}

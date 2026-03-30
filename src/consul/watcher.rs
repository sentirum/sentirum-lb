//! Consul watcher for Sentirum LB
//! Implements blocking queries to watch for Consul state changes

use crate::consul::client::{ConsulClient, ConsulConfig, HealthCheck, HEALTH_STATUS_PASSING};
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

                        let address = if instance.service_address.is_empty() {
                            &instance.address
                        } else {
                            &instance.service_address
                        };

                        for tag in &instance.service_tags {
                            if tag.starts_with(tag_prefix)
                                && let Some(route_def) = self.parse_tag(
                                    tag,
                                    address,
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

    /// Get passing service IDs grouped by service name using Fabio-like health aggregation.
    fn passing_service_ids(&self, checks: &[&HealthCheck]) -> HashMap<String, Vec<String>> {
        let mut services: HashMap<(String, String, String), Vec<&HealthCheck>> = HashMap::new();

        for check in checks {
            if !is_service_check(check) {
                continue;
            }
            services
                .entry((
                    check.node.clone(),
                    check.service_name.clone(),
                    check.service_id.clone(),
                ))
                .or_default()
                .push(*check);
        }

        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        'services: for ((node, service_name, service_id), svc_checks) in services {
            let mut total = 0;
            let mut passing = 0;

            for check in checks {
                if check.node != node {
                    continue;
                }

                if check.check_id == "serfHealth" && check.status == "critical" {
                    continue 'services;
                }
                if check.check_id == "_node_maintenance" {
                    continue 'services;
                }
                if check.check_id == format!("_service_maintenance:{}", service_id) && check.status == "critical" {
                    continue 'services;
                }

                if check.service_id == service_id {
                    total += 1;
                    if check.status == HEALTH_STATUS_PASSING {
                        passing += 1;
                    }
                }
            }

            if passing == 0 || total != svc_checks.len() || total != passing {
                continue;
            }

            result
                .entry(service_name)
                .or_default()
                .push(format!("{}.{}", node, service_id));
        }

        result
    }

    /// Parse a Fabio-style tag like "urlprefix-/api" -> route add.
    fn parse_tag(
        &self,
        tag: &str,
        address: &str,
        port: u16,
        service: &str,
    ) -> Option<RouteDef> {
        let (src, raw_opts) = parse_urlprefix_tag(tag, &self.config.tag_prefix)?;
        let opts = parse_opts(raw_opts);

        let scheme = match opts.get("proto").map(String::as_str) {
            Some("https") => "https",
            Some("grpc") => "grpc",
            Some("grpcs") => "grpcs",
            Some("tcp") => "tcp",
            _ => "http",
        };
        let dst = if scheme == "tcp" {
            format!("tcp://{}:{}", address, port)
        } else {
            format!("{}://{}:{}/", scheme, address, port)
        };

        Some(RouteDef {
            cmd: RouteCmd::Add,
            service: service.to_string(),
            src,
            dst,
            weight: opts
                .get("weight")
                .and_then(|w| w.parse::<f64>().ok())
                .unwrap_or(0.0),
            tags: vec![],
            opts: opts
                .into_iter()
                .filter(|(k, _)| k != "weight")
                .collect(),
            source: crate::route::definition::RouteSource::ConsulService,
        })
    }
}

fn is_service_check(check: &HealthCheck) -> bool {
    !check.service_id.is_empty()
        && check.check_id != "serfHealth"
        && check.check_id != "_node_maintenance"
        && !check.check_id.starts_with("_service_maintenance:")
}

fn parse_urlprefix_tag<'a>(tag: &'a str, prefix: &str) -> Option<(String, &'a str)> {
    let tag = tag.trim();
    let tag = tag.strip_prefix(prefix)?.trim();
    let mut parts = tag.splitn(2, ' ');
    let route = parts.next()?.trim();
    let opts = parts.next().unwrap_or("").trim();

    if route.starts_with(':') {
        return Some((route.to_string(), opts));
    }

    if !route.contains('/') {
        return Some((route.to_ascii_lowercase(), opts));
    }

    let (host, path) = route.split_once('/')?;
    Some((format!("{}/{}", host.to_ascii_lowercase(), path), opts))
}

fn parse_opts(raw_opts: &str) -> HashMap<String, String> {
    let mut opts = HashMap::new();
    for opt in raw_opts.split_whitespace() {
        if let Some((k, v)) = opt.split_once('=') {
            opts.insert(k.to_string(), v.to_string());
        }
    }
    opts
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

#[cfg(test)]
mod tests {
    use super::*;

    fn check(
        node: &str,
        check_id: &str,
        status: &str,
        service_name: &str,
        service_id: &str,
        tags: &[&str],
    ) -> HealthCheck {
        HealthCheck {
            node: node.to_string(),
            check_id: check_id.to_string(),
            name: check_id.to_string(),
            status: status.to_string(),
            service_name: service_name.to_string(),
            service_id: service_id.to_string(),
            service_tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    #[test]
    fn parse_urlprefix_tag_matches_fabio_path_only_routes() {
        let (route, opts) = parse_urlprefix_tag("urlprefix-/api proto=https strip=/api", "urlprefix-")
            .expect("tag should parse");
        assert_eq!(route, "/api");
        assert_eq!(opts, "proto=https strip=/api");
    }

    #[test]
    fn parse_urlprefix_tag_matches_fabio_host_routes() {
        let (route, opts) = parse_urlprefix_tag("urlprefix-Example.com/api", "urlprefix-")
            .expect("tag should parse");
        assert_eq!(route, "example.com/api");
        assert_eq!(opts, "");
    }

    #[test]
    fn passing_services_require_all_service_checks_to_pass() {
        let monitor = ServiceMonitor {
            client: Arc::new(ConsulClient::new(ConsulConfig::default()).unwrap()),
            config: ConsulConfig::default(),
        };

        let checks = vec![
            check("node-1", "service:web:1", HEALTH_STATUS_PASSING, "web", "svc-1", &["urlprefix-/"]),
            check("node-1", "service:web:2", "critical", "web", "svc-1", &["urlprefix-/"]),
            check("node-1", "serfHealth", HEALTH_STATUS_PASSING, "", "", &[]),
        ];
        let refs: Vec<&HealthCheck> = checks.iter().collect();

        let passing = monitor.passing_service_ids(&refs);
        assert!(passing.is_empty());
    }

    #[test]
    fn passing_services_skip_node_maintenance() {
        let monitor = ServiceMonitor {
            client: Arc::new(ConsulClient::new(ConsulConfig::default()).unwrap()),
            config: ConsulConfig::default(),
        };

        let checks = vec![
            check("node-1", "service:web:1", HEALTH_STATUS_PASSING, "web", "svc-1", &["urlprefix-/"]),
            check("node-1", "_node_maintenance", HEALTH_STATUS_PASSING, "", "", &[]),
        ];
        let refs: Vec<&HealthCheck> = checks.iter().collect();

        let passing = monitor.passing_service_ids(&refs);
        assert!(passing.is_empty());
    }
}

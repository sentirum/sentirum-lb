//! Consul watcher for Sentirum LB
//! Implements blocking queries to watch for Consul state changes

use crate::consul::client::{ConsulClient, ConsulConfig, HEALTH_STATUS_PASSING, HealthCheck};
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
        let mut backoff_secs: u64 = 1;
        let mut pending_checks: Option<(Vec<HealthCheck>, u64)> = None;
        let metrics = crate::metrics::prometheus::global();
        metrics.set_consul_watcher_backoff_seconds("services", 0);
        metrics.set_consul_watcher_last_index("services", 0);

        loop {
            let (checks, new_index) = if let Some(snapshot) = pending_checks.take() {
                snapshot
            } else {
                match self.client.get_health_checks(last_index).await {
                    Ok((checks, new_index)) => {
                        metrics.set_consul_watcher_last_index("services", new_index);
                        (checks, new_index)
                    }
                    Err(e) => {
                        metrics.record_consul_watcher_error("services");
                        metrics.set_consul_watcher_backoff_seconds("services", backoff_secs);
                        tracing::warn!(backoff_secs, error = %e, "Consul health check error; retrying");
                        let _ = updates.send(RouteUpdate::Error(e.to_string())).await;
                        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue;
                    }
                }
            };

            if new_index == last_index {
                backoff_secs = 1;
                metrics.set_consul_watcher_backoff_seconds("services", 0);
                continue;
            }

            match self.process_checks(&checks, &tag_prefix).await {
                Ok(route_defs) => {
                    backoff_secs = 1;
                    metrics.set_consul_watcher_backoff_seconds("services", 0);
                    last_index = new_index;
                    if updates
                        .send(RouteUpdate::Services(route_defs))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Consul watcher: channel closed, stopping");
                        break;
                    }
                }
                Err(error) => {
                    metrics.record_consul_watcher_error("services");
                    metrics.set_consul_watcher_backoff_seconds("services", backoff_secs);
                    tracing::warn!(backoff_secs, error = %error, "Consul service route rebuild failed; preserving previous service routes");
                    let _ = updates.send(RouteUpdate::Error(error)).await;
                    pending_checks = Some((checks, new_index));
                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    }

    /// Process health checks to determine passing services
    async fn process_checks(
        &self,
        checks: &[HealthCheck],
        tag_prefix: &str,
    ) -> Result<Vec<RouteDef>, String> {
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

        // Apply service whitelist/blacklist filter
        let passing_services = self.filter_services(passing_services);

        if passing_services.is_empty() {
            return Ok(Vec::new());
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
        let mut failures = Vec::new();
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
                                )
                            {
                                config.push(route_def);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get catalog service {}: {}", service_name, e);
                    failures.push(format!("{service_name}: {e}"));
                }
            }
        }

        // Sort by path (reverse) for most specific first
        if !failures.is_empty() {
            return Err(format!(
                "catalog lookups failed for {}; preserving previous service routes",
                failures.join(", ")
            ));
        }

        config.sort_by(|a, b| {
            let a_path = a.src_path();
            let b_path = b.src_path();
            b_path.cmp(a_path)
        });

        Ok(config)
    }

    /// Get passing service IDs grouped by service name using Fabio-like health aggregation.
    fn passing_service_ids(&self, checks: &[&HealthCheck]) -> HashMap<String, Vec<String>> {
        let mut services: HashMap<(String, String, String), Vec<&HealthCheck>> = HashMap::new();
        let mut node_down: HashMap<String, bool> = HashMap::new();
        let mut node_maintenance: HashMap<String, bool> = HashMap::new();
        let mut service_maintenance: HashMap<(String, String), bool> = HashMap::new();

        for check in checks {
            match check.check_id.as_str() {
                "serfHealth" if check.status == "critical" => {
                    node_down.insert(check.node.clone(), true);
                }
                "_node_maintenance" => {
                    node_maintenance.insert(check.node.clone(), true);
                }
                _ if check.check_id.starts_with("_service_maintenance:")
                    && check.status == "critical" =>
                {
                    let service_id = check
                        .check_id
                        .trim_start_matches("_service_maintenance:")
                        .to_string();
                    service_maintenance.insert((check.node.clone(), service_id), true);
                }
                _ if is_service_check(check) => {
                    services
                        .entry((
                            check.node.clone(),
                            check.service_name.clone(),
                            check.service_id.clone(),
                        ))
                        .or_default()
                        .push(*check);
                }
                _ => {}
            }
        }

        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        for ((node, service_name, service_id), svc_checks) in services {
            if node_down.get(&node).copied().unwrap_or(false)
                || node_maintenance.get(&node).copied().unwrap_or(false)
                || service_maintenance
                    .get(&(node.clone(), service_id.clone()))
                    .copied()
                    .unwrap_or(false)
            {
                continue;
            }

            let total = svc_checks.len();
            let passing = svc_checks
                .iter()
                .filter(|check| check.status == HEALTH_STATUS_PASSING)
                .count();

            if passing == 0 || total != passing {
                continue;
            }

            result
                .entry(service_name)
                .or_default()
                .push(format!("{}.{}", node, service_id));
        }

        result
    }

    /// Apply whitelist/blacklist filters to service list
    fn filter_services(
        &self,
        services: HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        let whitelist = &self.config.service_whitelist;
        let blacklist = &self.config.service_blacklist;

        // If whitelist is non-empty, only include listed services
        if !whitelist.is_empty() {
            services
                .into_iter()
                .filter(|(name, _)| whitelist.iter().any(|w| w == name))
                .collect()
        } else {
            // Otherwise, exclude blacklisted services
            services
                .into_iter()
                .filter(|(name, _)| !blacklist.iter().any(|b| b == name))
                .collect()
        }
    }

    /// Parse a Fabio-style tag like "urlprefix-/api" -> route add.
    fn parse_tag(&self, tag: &str, address: &str, port: u16, service: &str) -> Option<RouteDef> {
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
            opts: opts.into_iter().filter(|(k, _)| k != "weight").collect(),
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
        let mut backoff_secs: u64 = 1;
        let metrics = crate::metrics::prometheus::global();
        metrics.set_consul_watcher_backoff_seconds("kv", 0);
        metrics.set_consul_watcher_last_index("kv", 0);

        loop {
            match self.client.watch_kv(&kv_path, last_index).await {
                Ok((value, new_index)) => {
                    backoff_secs = 1;
                    metrics.set_consul_watcher_backoff_seconds("kv", 0);
                    metrics.set_consul_watcher_last_index("kv", new_index);
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
                    metrics.record_consul_watcher_error("kv");
                    metrics.set_consul_watcher_backoff_seconds("kv", backoff_secs);
                    tracing::warn!(backoff_secs, error = %e, "Consul KV error; retrying");
                    let _ = updates.send(RouteUpdate::Error(e.to_string())).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    }
}

/// Combined watcher that runs both service and KV watchers
pub struct ConsulWatcher {
    service_monitor: ServiceMonitor,
    kv_watcher: KVWatcher,
    service_discovery_enabled: bool,
    kv_watching_enabled: bool,
}

impl ConsulWatcher {
    pub fn new(client: Arc<ConsulClient>, config: ConsulConfig) -> Self {
        Self {
            service_monitor: ServiceMonitor::new(client.clone(), config.clone()),
            kv_watcher: KVWatcher::new(client, config),
            service_discovery_enabled: true,
            kv_watching_enabled: true,
        }
    }

    pub fn with_flags(mut self, service_discovery: bool, kv_watching: bool) -> Self {
        self.service_discovery_enabled = service_discovery;
        self.kv_watching_enabled = kv_watching;
        self
    }

    /// Start the watcher and send updates to the channel.
    /// Only enabled watchers are spawned.
    pub async fn run(&self, updates: mpsc::Sender<RouteUpdate>) {
        let mut handles = Vec::new();

        if self.service_discovery_enabled {
            let monitor = self.service_monitor.clone();
            let tx = updates.clone();
            handles.push(tokio::spawn(async move {
                monitor.watch(tx).await;
                tracing::warn!("Service monitor task ended");
            }));
        } else {
            tracing::info!("Service discovery disabled, skipping service monitor");
        }

        if self.kv_watching_enabled {
            let watcher = self.kv_watcher.clone();
            let tx = updates;
            handles.push(tokio::spawn(async move {
                watcher.watch(tx).await;
                tracing::warn!("KV watcher task ended");
            }));
        } else {
            tracing::info!("KV watching disabled, skipping KV watcher");
        }

        let results = futures::future::join_all(handles).await;
        for result in results {
            if let Err(e) = result {
                tracing::error!(error = %e, "Watcher task panicked");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use http::StatusCode;
    use tokio::net::TcpListener;

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
        let (route, opts) =
            parse_urlprefix_tag("urlprefix-/api proto=https strip=/api", "urlprefix-")
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
    fn parse_urlprefix_tag_preserves_grpc_and_grpcs_opts() {
        let (route, opts) = parse_urlprefix_tag(
            "urlprefix-api.example.com/pkg.Service proto=grpc strip=/edge",
            "urlprefix-",
        )
        .expect("tag should parse");
        assert_eq!(route, "api.example.com/pkg.Service");
        assert_eq!(opts, "proto=grpc strip=/edge");

        let (route, opts) = parse_urlprefix_tag("urlprefix-/pkg.Service proto=grpcs", "urlprefix-")
            .expect("tag should parse");
        assert_eq!(route, "/pkg.Service");
        assert_eq!(opts, "proto=grpcs");
    }

    #[test]
    fn parse_tag_builds_grpc_destinations() {
        let monitor = ServiceMonitor {
            client: Arc::new(ConsulClient::new(ConsulConfig::default()).unwrap()),
            config: ConsulConfig::default(),
        };

        let grpc = monitor
            .parse_tag(
                "urlprefix-api.example.com/pkg.Service proto=grpc strip=/edge",
                "10.0.0.10",
                50051,
                "orders",
            )
            .expect("grpc tag should parse");
        assert_eq!(grpc.src, "api.example.com/pkg.Service");
        assert_eq!(grpc.dst, "grpc://10.0.0.10:50051/");
        assert_eq!(grpc.opts.get("proto"), Some(&"grpc".to_string()));
        assert_eq!(grpc.opts.get("strip"), Some(&"/edge".to_string()));

        let grpcs = monitor
            .parse_tag(
                "urlprefix-/pkg.Service proto=grpcs",
                "10.0.0.11",
                8443,
                "orders",
            )
            .expect("grpcs tag should parse");
        assert_eq!(grpcs.src, "/pkg.Service");
        assert_eq!(grpcs.dst, "grpcs://10.0.0.11:8443/");
        assert_eq!(grpcs.opts.get("proto"), Some(&"grpcs".to_string()));
    }

    #[test]
    fn passing_services_require_all_service_checks_to_pass() {
        let monitor = ServiceMonitor {
            client: Arc::new(ConsulClient::new(ConsulConfig::default()).unwrap()),
            config: ConsulConfig::default(),
        };

        let checks = vec![
            check(
                "node-1",
                "service:web:1",
                HEALTH_STATUS_PASSING,
                "web",
                "svc-1",
                &["urlprefix-/"],
            ),
            check(
                "node-1",
                "service:web:2",
                "critical",
                "web",
                "svc-1",
                &["urlprefix-/"],
            ),
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
            check(
                "node-1",
                "service:web:1",
                HEALTH_STATUS_PASSING,
                "web",
                "svc-1",
                &["urlprefix-/"],
            ),
            check(
                "node-1",
                "_node_maintenance",
                HEALTH_STATUS_PASSING,
                "",
                "",
                &[],
            ),
        ];
        let refs: Vec<&HealthCheck> = checks.iter().collect();

        let passing = monitor.passing_service_ids(&refs);
        assert!(passing.is_empty());
    }

    #[tokio::test]
    async fn process_checks_preserves_previous_routes_when_catalog_lookup_fails() {
        let app = Router::new().route(
            "/v1/catalog/service/{service}",
            get(
                |axum::extract::Path(service): axum::extract::Path<String>| async move {
                    if service == "web" {
                        (StatusCode::INTERNAL_SERVER_ERROR, "boom")
                    } else {
                        (StatusCode::OK, "[]")
                    }
                },
            ),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let monitor = ServiceMonitor {
            client: Arc::new(
                ConsulClient::new(ConsulConfig {
                    address: addr.to_string(),
                    ..ConsulConfig::default()
                })
                .unwrap(),
            ),
            config: ConsulConfig::default(),
        };

        let checks = vec![check(
            "node-1",
            "service:web:1",
            HEALTH_STATUS_PASSING,
            "web",
            "svc-1",
            &["urlprefix-/"],
        )];

        let error = monitor
            .process_checks(&checks, "urlprefix-")
            .await
            .expect_err("catalog failure should preserve previous routes");
        assert!(error.contains("web"));
    }
}

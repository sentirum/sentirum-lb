//! Consul watcher for Sentirum LB
//! Implements blocking queries to watch for Consul state changes

use crate::consul::client::{ConsulClient, ConsulConfig, HEALTH_STATUS_PASSING, HealthCheck};
use crate::route::definition::{RouteCmd, RouteDef};
use futures::stream::{self, StreamExt};
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
                        // Consul restart resets the index to a value lower than
                        // our last_index. Detect this and reset to avoid a tight
                        // loop of instant responses.
                        if new_index < last_index && last_index > 0 {
                            tracing::info!(
                                old_index = last_index,
                                new_index,
                                "Consul index reset detected (server restart?); resetting watcher state"
                            );
                        }
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

            // Index unchanged means the blocking query timed out with no change.
            // Index reset (new_index < last_index) must NOT be treated as
            // "unchanged": we must reprocess with the new index.
            //
            // A small floor sleep guards against a tight CPU spin if a missing
            // or unparseable X-Consul-Index ever yields a clamped index equal
            // to the previous one (blocking effectively disabled server-side).
            if new_index == last_index {
                backoff_secs = 1;
                metrics.set_consul_watcher_backoff_seconds("services", 0);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }

            match self.process_checks(&checks, &tag_prefix).await {
                Ok(route_defs) => {
                    // Only advance last_index after a successful process. Advancing
                    // before process_checks would make the next iteration's
                    // `new_index == last_index` guard discard a stashed pending
                    // retry, defeating the backoff mechanism in the Err arm.
                    last_index = new_index;
                    backoff_secs = 1;
                    metrics.set_consul_watcher_backoff_seconds("services", 0);
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

        // Concurrent catalog queries, bounded to avoid fan-out spikes on large Consul clusters.
        const MAX_CATALOG_LOOKUP_CONCURRENCY: usize = 32;
        let service_names: Vec<String> = passing_services.keys().cloned().collect();
        let catalog_results: Vec<_> = stream::iter(service_names.into_iter().map(|service_name| {
            let client = self.client.clone();
            async move {
                let result = client.get_catalog_service(&service_name).await;
                (service_name, result)
            }
        }))
        .buffer_unordered(MAX_CATALOG_LOOKUP_CONCURRENCY)
        .collect()
        .await;

        let mut config = Vec::new();
        let mut failures = Vec::new();
        for (service_name, result) in catalog_results {
            let service_ids_set: std::collections::HashSet<&str> = passing_services
                .get(service_name.as_str())
                .unwrap()
                .iter()
                .map(String::as_str)
                .collect();

            match result {
                Ok(instances) => {
                    for instance in instances {
                        let instance_id = format!("{}.{}", instance.node, instance.id);
                        if !service_ids_set.contains(instance_id.as_str()) {
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
                                    &service_name,
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
            let warning = svc_checks
                .iter()
                .filter(|check| check.status == crate::consul::client::HEALTH_STATUS_WARNING)
                .count();

            let healthy = if self.config.include_warning {
                passing + warning
            } else {
                passing
            };

            if healthy == 0 || total != healthy {
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
                    if new_index < last_index && last_index > 0 {
                        tracing::info!(
                            old_index = last_index,
                            new_index,
                            "Consul KV index reset detected (server restart?); resetting"
                        );
                    }
                    if new_index != last_index {
                        last_index = new_index;
                        let update = RouteUpdate::Manual(value.unwrap_or_default());

                        if updates.send(update).await.is_err() {
                            tracing::warn!("KV watcher: channel closed, stopping");
                            break;
                        }
                    } else {
                        // Index unchanged (blocking query timed out, or index
                        // missing/unparseable and clamped). A floor sleep avoids
                        // a tight CPU spin when blocking is disabled server-side.
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
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
    #![allow(clippy::useless_vec)]
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

    /// After a failing `process_checks`, the watcher must stash the snapshot and
    /// re-run `process_checks` on the next loop iteration without re-issuing the
    /// blocking query. Previously `last_index` was advanced *before*
    /// `process_checks`, so the next iteration's `new_index == last_index`
    /// guard discarded the stashed snapshot — the whole pending/backoff path
    /// was dead. This drives the real `watch` loop against a stub Consul server.
    #[tokio::test]
    async fn watch_retries_process_checks_after_catalog_failure() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Duration;

        let health_calls = Arc::new(AtomicU64::new(0));
        let catalog_calls = Arc::new(AtomicU64::new(0));
        // Park every health-check request after the first so the watch loop
        // cannot race ahead and re-fetch before the test observes the retry.
        let health_gate = Arc::new(tokio::sync::Notify::new());

        let health_calls_h = health_calls.clone();
        let health_gate_h = health_gate.clone();
        let catalog_calls_h = catalog_calls.clone();

        let app = Router::new()
            .route(
                "/v1/health/state/any",
                get(move || {
                    let health_calls = health_calls_h.clone();
                    let health_gate = health_gate_h.clone();
                    async move {
                        if health_calls.load(Ordering::SeqCst) >= 1 {
                            health_gate.notified().await;
                        }
                        let index = 10 + health_calls.fetch_add(1, Ordering::SeqCst);
                        let body = serde_json::json!([{
                            "Node": "node-1",
                            "CheckID": "service:web:1",
                            "Name": "service:web:1",
                            "Status": "passing",
                            "ServiceName": "web",
                            "ServiceID": "web:1",
                            "ServiceTags": ["urlprefix-/"],
                        }])
                        .to_string();
                        axum::http::Response::builder()
                            .status(StatusCode::OK)
                            .header(
                                "x-consul-index",
                                axum::http::HeaderValue::try_from(index.to_string().as_str())
                                    .unwrap(),
                            )
                            .body(axum::body::Body::from(body))
                            .unwrap()
                    }
                }),
            )
            .route(
                "/v1/catalog/service/{service}",
                get(
                    move |axum::extract::Path(service): axum::extract::Path<String>| {
                        let catalog_calls = catalog_calls_h.clone();
                        async move {
                            let n = catalog_calls.fetch_add(1, Ordering::SeqCst);
                            if n == 0 || service != "web" {
                                return (StatusCode::INTERNAL_SERVER_ERROR, "boom".to_string());
                            }
                            let body = serde_json::json!([{
                                "Node": "node-1",
                                "ServiceID": "web:1",
                                "Address": "10.0.0.5",
                                "ServiceAddress": "",
                                "ServicePort": 8080,
                                "ServiceTags": ["urlprefix-/"],
                                "ServiceMeta": {},
                            }])
                            .to_string();
                            (StatusCode::OK, body)
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

        let (tx, mut rx) = mpsc::channel::<RouteUpdate>(8);
        let handle = tokio::spawn(async move {
            monitor.watch(tx).await;
        });

        let mut saw_error = false;
        let mut services_with_health_calls = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            let Ok(recv) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await else {
                continue;
            };
            match recv {
                Some(RouteUpdate::Error(_)) => saw_error = true,
                Some(RouteUpdate::Services(_)) => {
                    services_with_health_calls = Some(health_calls.load(Ordering::SeqCst));
                    break;
                }
                _ => {}
            }
        }
        handle.abort();

        assert!(
            saw_error,
            "expected an Error update from the failed catalog lookup"
        );
        let calls = services_with_health_calls
            .expect("expected process_checks to be retried and emit a Services update");
        // The retry must reuse the stashed pending snapshot. In the buggy version
        // `last_index` was advanced before process_checks, the guard discarded
        // the snapshot, and the loop re-fetched health checks (calls >= 2) before
        // any Services update could be emitted.
        assert_eq!(
            calls, 1,
            "retry must reuse the pending snapshot without a fresh health-check fetch"
        );
    }
}

//! Metrics, topology, target status, and Consul status handlers.

use super::api::AdminState;
use crate::admin::topology_flow::{TopologyFlowMetrics, topology_target_key};
use crate::route::target::CircuitState;
use axum::extract::State;
use futures::stream::Stream;
use serde::Serialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Serialize)]
pub struct TargetMetrics {
    pub host: String,
    pub path: String,
    pub service: String,
    pub url: String,
    pub protocol: String,
    pub circuit_breaker: String,
    pub active_connections: u64,
    pub requests: u64,
    pub errors: u64,
    pub avg_latency_us: u64,
    pub bytes_total: u64,
    pub flow: TopologyFlowMetrics,
}

#[derive(Serialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_error_total: u64,
    pub active_connections: u64,
    pub route_count: usize,
    pub target_count: usize,
    pub targets: Vec<TargetMetrics>,
    pub timestamp: u64,
}

pub(super) async fn metrics_handler() -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        crate::metrics::prometheus::global().render(),
    )
}

pub(super) async fn metrics_stream_handler(
    State(state): State<AdminState>,
) -> axum::response::Sse<impl Stream<Item = Result<axum::response::sse::Event, Infallible>>> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{Duration, interval};

    async fn make_snapshot(state: &AdminState) -> MetricsSnapshot {
        let table = state.route_table.get();
        let hosts = table.hosts();
        let flow_snapshot = state.topology_flow_cache.snapshot(&state.route_table);

        let mut targets = Vec::new();
        for host in hosts {
            if let Some(routes) = table.get_routes(host) {
                for route in routes.iter() {
                    for target in route.targets.iter() {
                        let stats = target.stats.as_ref();
                        let flow_key =
                            topology_target_key(host, &route.path, &target.service, &target.url);
                        targets.push(TargetMetrics {
                            host: host.to_string(),
                            path: route.path.clone(),
                            service: target.service.clone(),
                            url: target.url.clone(),
                            protocol: format!("{:?}", target.parsed_protocol).to_lowercase(),
                            circuit_breaker: format!(
                                "{:?}",
                                target.health_tracker.circuit_breaker().current_state()
                            )
                            .to_lowercase(),
                            active_connections: target.active_connections.load(Ordering::Relaxed),
                            requests: stats.requests_total.load(Ordering::Relaxed),
                            errors: stats.errors_total.load(Ordering::Relaxed),
                            avg_latency_us: stats.avg_latency_us(),
                            bytes_total: stats.bytes_total.load(Ordering::Relaxed),
                            flow: flow_snapshot
                                .edges
                                .get(&flow_key)
                                .cloned()
                                .unwrap_or_default(),
                        });
                    }
                }
            }
        }

        MetricsSnapshot {
            requests_total: targets.iter().map(|t| t.requests).sum(),
            requests_error_total: targets.iter().map(|t| t.errors).sum(),
            active_connections: targets.iter().map(|t| t.active_connections).sum(),
            route_count: table.route_count(),
            target_count: table.target_count(),
            targets,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    // Per-state channel avoids the OnceLock global-static pitfall where the
    // spawned task captures the first AdminState forever.
    // Each SSE client subscribes to the same channel; the background task
    // stops when all receivers are dropped (stream disconnect).
    let rx = {
        let guard = state.metrics_stream_tx.read().await;
        if let Some(tx) = guard.as_ref() {
            tx.subscribe()
        } else {
            drop(guard);
            let mut guard = state.metrics_stream_tx.write().await;
            // Double-check after acquiring write lock
            if let Some(tx) = guard.as_ref() {
                tx.subscribe()
            } else {
                let (tx, rx) = tokio::sync::watch::channel(Arc::new(String::from("{}")));
                let _ = guard.insert(tx);
                let state_clone = state.clone();
                tokio::spawn(async move {
                    let mut timer = interval(Duration::from_secs(1));
                    loop {
                        timer.tick().await;
                        let snapshot = make_snapshot(&state_clone).await;
                        let json = Arc::new(
                            serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".into()),
                        );
                        // If all receivers are gone, stop the task
                        if state_clone
                            .metrics_stream_tx
                            .read()
                            .await
                            .as_ref()
                            .is_none_or(|tx| tx.receiver_count() == 0)
                        {
                            let mut guard = state_clone.metrics_stream_tx.write().await;
                            // Only clear if no new receivers appeared
                            if guard.as_ref().is_some_and(|tx| tx.receiver_count() == 0) {
                                guard.take();
                                tracing::debug!("Metrics stream task stopped: no receivers");
                                return;
                            }
                        }
                        let _ = state_clone
                            .metrics_stream_tx
                            .read()
                            .await
                            .as_ref()
                            .map(|tx| tx.send(json));
                    }
                });
                rx
            }
        }
    };

    let stream = async_stream::stream! {
        yield Ok::<_, Infallible>(Event::default().data("connected"));
        let mut rx = rx;
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let data = rx.borrow_and_update().clone();
            yield Ok(Event::default().data(data.as_ref()));
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Delegate to the canonical implementation in the metrics module.
pub fn escape_prometheus_label(s: &str) -> String {
    crate::metrics::prometheus::escape_prometheus_label(s)
}

pub(super) async fn targets_metrics_handler(
    State(state): State<AdminState>,
) -> impl axum::response::IntoResponse {
    let table = state.route_table.get();

    let mut output = String::from(
        "# HELP sentirum_lb_target_requests_total Requests per target\n\
# TYPE sentirum_lb_target_requests_total counter\n\
# HELP sentirum_lb_target_errors_total Errors per target\n\
# TYPE sentirum_lb_target_errors_total counter\n\
# HELP sentirum_lb_target_latency_us_total Total latency per target\n\
# TYPE sentirum_lb_target_latency_us_total counter\n\
# HELP sentirum_lb_target_bytes_total Bytes per target\n\
# TYPE sentirum_lb_target_bytes_total counter\n\
# HELP sentirum_lb_target_circuit_breaker_state Circuit breaker state (0=closed, 1=half-open, 2=open)\n\
# TYPE sentirum_lb_target_circuit_breaker_state gauge\n",
    );

    for (host, route, target) in table.iter_targets() {
        let stats = target.stats.as_ref();
        let requests = stats.requests_total.load(Ordering::Relaxed);
        let errors = stats.errors_total.load(Ordering::Relaxed);
        let latency_sum = stats.latency_sum_us.load(Ordering::Relaxed);
        let bytes = stats.bytes_total.load(Ordering::Relaxed);
        let cb_state = target.health_tracker.circuit_breaker().current_state();

        let svc = escape_prometheus_label(&target.service);
        let h = escape_prometheus_label(host);
        let p = escape_prometheus_label(&route.path);
        let proto =
            escape_prometheus_label(&format!("{:?}", target.parsed_protocol).to_lowercase());

        output.push_str(&format!(
            "sentirum_lb_target_requests_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {requests}\n"
        ));
        output.push_str(&format!(
            "sentirum_lb_target_errors_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {errors}\n"
        ));
        output.push_str(&format!(
            "sentirum_lb_target_latency_us_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {latency_sum}\n"
        ));
        output.push_str(&format!(
            "sentirum_lb_target_bytes_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {bytes}\n"
        ));

        let cb_value = match cb_state {
            CircuitState::Closed => 0,
            CircuitState::Open => 2,
            CircuitState::HalfOpen => 1,
        };
        output.push_str(&format!(
            "sentirum_lb_target_circuit_breaker_state{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {cb_value}\n"
        ));
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
}

pub(super) async fn targets_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    let table = state.route_table.get();
    let flow_snapshot = state.topology_flow_cache.snapshot(&state.route_table);

    let mut targets = Vec::new();
    for (host, route, target) in table.iter_targets() {
        let cb_state = target.health_tracker.circuit_breaker().current_state();
        let active_conns = target.active_connections.load(Ordering::Relaxed);
        let stats = target.stats.as_ref();
        let requests = stats.requests_total.load(Ordering::Relaxed);
        let errors = stats.errors_total.load(Ordering::Relaxed);
        let error_rate = if requests > 0 {
            (errors as f64 / requests as f64 * 100.0).round() as u64
        } else {
            0
        };
        let avg_latency = stats.avg_latency_us();

        let cb_history = target.health_tracker.circuit_breaker().transition_history();
        let cb_transitions: Vec<serde_json::Value> = cb_history
            .iter()
            .rev()
            .take(20)
            .map(|t| {
                let now_wall_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let now_mono_ms = crate::route::target::monotonic_elapsed_ms();
                let approx_unix_ms = now_wall_ms
                    .saturating_sub(now_mono_ms)
                    .saturating_add(t.elapsed_ms);
                serde_json::json!({
                    "from": format!("{:?}", t.from).to_lowercase(),
                    "to": format!("{:?}", t.to).to_lowercase(),
                    "timestamp_ms": approx_unix_ms,
                })
            })
            .collect();

        let flow_key = topology_target_key(host, &route.path, &target.service, &target.url);
        targets.push(serde_json::json!({
            "host": host,
            "path": &route.path,
            "service": &target.service,
            "url": &target.url,
            "protocol": format!("{:?}", target.parsed_protocol).to_lowercase(),
            "tls": target.parsed_tls,
            "http2": target.parsed_protocol.requires_http2(),
            "weight": target.weight,
            "fixed_weight": target.fixed_weight,
            "source": format!("{:?}", target.source).to_lowercase(),
            "active_connections": active_conns,
            "circuit_breaker": format!("{:?}", cb_state).to_lowercase(),
            "probe_healthy": target.health_tracker.is_probe_healthy(),
            "circuit_breaker_history": cb_transitions,
            "flow": flow_snapshot.edges.get(&flow_key).cloned().unwrap_or_default(),
            "stats": {
                "requests": requests,
                "errors": errors,
                "error_rate_pct": error_rate,
                "avg_latency_us": avg_latency,
                "bytes_total": stats.bytes_total.load(Ordering::Relaxed),
            }
        }));
    }

    axum::Json(serde_json::json!({
        "targets": targets,
        "total": targets.len(),
    }))
}

pub(super) async fn topology_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    let table = state.route_table.get();
    let hosts = table.hosts();
    let metrics = crate::metrics::prometheus::global();
    let ordering = Ordering::Relaxed;
    let flow_snapshot = state.topology_flow_cache.snapshot(&state.route_table);

    let total_requests = metrics.requests_total.load(ordering);
    let total_errors = metrics.requests_error_total.load(ordering);
    let error_rate = if total_requests > 0 {
        (total_errors as f64 / total_requests as f64 * 100.0).round()
    } else {
        0.0
    };

    let lb = serde_json::json!({
        "id": "lb",
        "requests": total_requests,
        "active_connections": metrics.active_connections.load(ordering),
        "error_rate": error_rate,
        "flow": flow_snapshot.lb,
    });

    let mut host_entries = Vec::new();
    for host in hosts {
        let mut route_entries = Vec::new();
        let mut host_flows = Vec::new();
        if let Some(routes) = table.get_routes(host) {
            for route in routes.iter() {
                let matcher = if route.glob.is_some() {
                    "glob"
                } else {
                    "prefix"
                };
                let mut target_entries = Vec::new();
                let mut route_flows = Vec::new();
                for target in route.targets.iter() {
                    let cb_state = target.health_tracker.circuit_breaker().current_state();
                    let active_conns = target.active_connections.load(ordering);
                    let edge_stats = target.edge_stats.as_ref();
                    let reqs = edge_stats.requests_total.load(ordering);
                    let errs = edge_stats.errors_total.load(ordering);
                    let err_pct = if reqs > 0 {
                        (errs as f64 / reqs as f64 * 100.0).round() as u64
                    } else {
                        0
                    };
                    let avg_lat = edge_stats
                        .latency_sum_us
                        .load(ordering)
                        .checked_div(reqs.max(1))
                        .unwrap_or(0);
                    let flow_key =
                        topology_target_key(host, &route.path, &target.service, &target.url);
                    let flow = flow_snapshot
                        .edges
                        .get(&flow_key)
                        .cloned()
                        .unwrap_or_default();
                    route_flows.push(flow.clone());

                    target_entries.push(serde_json::json!({
                        "service": target.service,
                        "url": target.url,
                        "protocol": format!("{:?}", target.parsed_protocol).to_lowercase(),
                        "tls": target.parsed_tls,
                        "weight": target.weight,
                        "active_connections": active_conns,
                        "circuit_breaker": format!("{:?}", cb_state).to_lowercase(),
                        "probe_healthy": target.health_tracker.is_probe_healthy(),
                        "flow": flow,
                        "stats": {
                            "requests": reqs,
                            "errors": errs,
                            "error_rate_pct": err_pct,
                            "avg_latency_us": avg_lat,
                            "bytes_total": edge_stats.bytes_total.load(ordering),
                        }
                    }));
                }
                let route_flow = TopologyFlowMetrics::combine(route_flows.iter());
                host_flows.push(route_flow.clone());
                route_entries.push(serde_json::json!({
                    "path": route.path,
                    "matcher": matcher,
                    "flow": route_flow,
                    "targets": target_entries,
                }));
            }
        }
        host_entries.push(serde_json::json!({
            "host": host,
            "flow": TopologyFlowMetrics::combine(host_flows.iter()),
            "routes": route_entries,
        }));
    }

    axum::Json(serde_json::json!({
        "lb": lb,
        "hosts": host_entries,
    }))
}

pub(super) async fn consul_status_handler() -> axum::Json<serde_json::Value> {
    let m = crate::metrics::prometheus::global();

    axum::Json(serde_json::json!({
        "services": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_services.load(Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_services.load(Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_services.load(Ordering::Relaxed),
        },
        "kv": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_kv.load(Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_kv.load(Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_kv.load(Ordering::Relaxed),
        },
        "tls": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_tls.load(Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_tls.load(Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_tls.load(Ordering::Relaxed),
        },
        "client_ca": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_client_ca.load(Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_client_ca.load(Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_client_ca.load(Ordering::Relaxed),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::definition::{RouteCmd, RouteDef, RouteSource};
    use crate::route::registry::ManagedRouteTable;
    use crate::test_support::admin_test_state;
    use std::collections::HashMap;

    fn test_state(route_table: Arc<ManagedRouteTable>) -> AdminState {
        admin_test_state(route_table)
    }

    #[tokio::test]
    async fn targets_handler_exposes_flow_payload() {
        let route_table = Arc::new(ManagedRouteTable::new());
        route_table.apply_and_swap(&[RouteDef {
            cmd: RouteCmd::Add,
            service: "svc-a".to_string(),
            src: "example.com/api".to_string(),
            dst: "http://127.0.0.1:8080".to_string(),
            weight: 1.0,
            tags: vec![],
            opts: HashMap::new(),
            source: RouteSource::Static,
        }]);

        let table = route_table.get();
        let target = table
            .lookup_route(
                "example.com",
                "/api",
                crate::route::table::MatcherKind::Prefix,
            )
            .unwrap()
            .targets[0]
            .clone();
        target.edge_stats.record_request(123, 456, false);
        target.stats.record_request(123, 456, false);

        let response = targets_handler(State(test_state(route_table))).await.0;
        let target_json = &response["targets"][0];
        assert_eq!(target_json["stats"]["requests"], 1);
        assert_eq!(target_json["stats"]["bytes_total"], 456);
        assert!(target_json["flow"].get("rps_1s").is_some());
        assert!(target_json["flow"].get("activity_level").is_some());
    }

    #[tokio::test]
    async fn topology_uses_edge_stats_and_exposes_flow_payload() {
        let route_table = Arc::new(ManagedRouteTable::new());
        route_table.apply_and_swap(&[RouteDef {
            cmd: RouteCmd::Add,
            service: "svc-a".to_string(),
            src: "example.com/api".to_string(),
            dst: "http://127.0.0.1:8080".to_string(),
            weight: 1.0,
            tags: vec![],
            opts: HashMap::new(),
            source: RouteSource::Static,
        }]);

        let table = route_table.get();
        let target = table
            .lookup_route(
                "example.com",
                "/api",
                crate::route::table::MatcherKind::Prefix,
            )
            .unwrap()
            .targets[0]
            .clone();
        target.edge_stats.record_request(123, 456, true);

        let response = topology_handler(State(test_state(route_table))).await.0;
        let target_json = &response["hosts"][0]["routes"][0]["targets"][0];

        assert_eq!(target_json["stats"]["requests"], 1);
        assert_eq!(target_json["stats"]["errors"], 1);
        assert_eq!(target_json["stats"]["bytes_total"], 456);
        assert_eq!(target_json["stats"]["avg_latency_us"], 123);
        assert!(target_json.get("flow").is_some());
        assert!(response["hosts"][0]["flow"].get("activity_level").is_some());
        assert!(response["lb"]["flow"].get("rps_1s").is_some());
    }
}

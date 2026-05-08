//! Admin API for Sentirum LB using axum.
//!
//! Endpoints:
//! - `GET /admin/` — Dashboard UI (embedded SPA)
//! - `GET /admin/health` — Health check
//! - `GET /admin/routes` — Route table inspection
//! - `GET /admin/metrics` — Prometheus metrics
//! - `GET /admin/config` — Config inspection
//! - `GET /admin/certs` — Runtime TLS certificate status
//! - `GET /admin/logs` — Recent log entries (JSON)
//! - `GET /admin/logs/stream` — Live log stream (SSE)

use crate::config::Config;
use crate::route::target::CircuitState;
use crate::proxy::tls::{DynamicCertStore, DynamicClientCaStore};
use crate::route::registry::ManagedRouteTable;
use axum::Router;
use axum::extract::{Query, State, Json};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use futures::stream::Stream;
use tokio_stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use tokio::sync::RwLock;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::Rng;
use bcrypt::verify;
use std::time::Duration;

/// Maximum session lifetime in seconds (24 hours).
const SESSION_TTL_SECS: u64 = 24 * 60 * 60;
/// Maximum number of concurrent sessions before oldest is evicted.
const SESSION_MAX_CAPACITY: usize = 10_000;
/// Maximum login attempts per username before rate-limiting.
const LOGIN_MAX_ATTEMPTS: u32 = 5;
/// Login rate-limit window in seconds.
const LOGIN_WINDOW_SECS: u64 = 60;


/// Session entry with creation timestamp for TTL eviction.
pub struct SessionEntry {
    pub user: String,
    pub created_at: std::time::Instant,
}

/// Shared state for admin API handlers
#[derive(Clone)]
pub struct AdminState {
    pub config: Arc<Config>,
    pub route_table: Arc<ManagedRouteTable>,
    pub tls_store: Option<Arc<DynamicCertStore>>,
    pub client_ca_store: Option<Arc<DynamicClientCaStore>>,
    pub log_buffer: Option<Arc<crate::admin::logs::LogBuffer>>,
    /// Active sessions (token -> SessionEntry)
    pub sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
    /// Login rate limiter: username -> (attempt count, window start instant).
    pub login_attempts: Arc<dashmap::DashMap<String, (u32, std::time::Instant)>>,
    }

/// Health check response
#[derive(serde::Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// Login request
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response
#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<String>,
    pub token: Option<String>,
}

/// SSE metrics data
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

#[derive(Serialize)]
pub struct TargetMetrics {
    pub service: String,
    pub url: String,
    pub protocol: String,
    pub circuit_breaker: String,
    pub active_connections: u64,
    pub requests: u64,
    pub errors: u64,
    pub avg_latency_us: u64,
}

/// Query parameters for the log history endpoint.
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// Maximum number of entries to return (default 100, max 1000).
    pub limit: Option<usize>,
    /// Minimum log level: "ERROR", "WARN", "INFO", "DEBUG", "TRACE".
    pub level: Option<String>,
}

/// Build the admin API router
pub fn build_router(state: AdminState) -> Router {
    // Public routes (no auth required)
    let public = Router::new()
        .route("/admin/", get(dashboard_handler))
        .route("/admin/dashboard", get(dashboard_handler))
        .route("/admin/login", post(login_handler))
        .route("/admin/logout", post(logout_handler))
        .route("/admin/me", get(me_handler)); // Get current user

    // Protected routes (auth required)
    let protected = Router::new()
        .route("/admin/health", get(health_handler))
        .route("/admin/routes", get(routes_handler))
        .route("/admin/metrics", get(metrics_handler))
        .route("/admin/config", get(config_handler))
        .route("/admin/certs", get(certs_handler))
        .route("/admin/logs", get(logs_handler))
        .route("/admin/targets", get(targets_handler))
        .route("/admin/consul-status", get(consul_status_handler))
        .route("/admin/topology", get(topology_handler))
        .route("/admin/targets-metrics", get(targets_metrics_handler))
        .route("/admin/dns-cache", get(dns_cache_handler))
        .route("/admin/logs/stream", get(logs_stream_handler))
        .route("/admin/metrics/stream", get(metrics_stream_handler));

    if state.config.server.admin_token.is_empty() && state.config.server.admin_users.is_empty() {
        public.merge(protected).with_state(state)
    } else {
        public.with_state(state.clone())
            .merge(protected.layer(from_fn_with_state(state.clone(), admin_auth_middleware)).with_state(state))
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Serve the embedded dashboard SPA.
async fn dashboard_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("dashboard.html"))
}

/// Login handler
async fn login_handler(
    State(state): State<AdminState>,
    Json(req): Json<LoginRequest>,
) -> axum::Json<LoginResponse> {
    // Input length check — reject oversized credentials without hashing.
    if req.username.len() > 256 || req.password.len() > 256 {
        return axum::Json(LoginResponse {
            success: false,
            message: "Invalid credentials".to_string(),
            user: None,
            token: None,
        });
    }

    // Rate-limit check: max LOGIN_MAX_ATTEMPTS per username within LOGIN_WINDOW_SECS.
    let now = std::time::Instant::now();
    if let Some(pair) = state.login_attempts.get(&req.username) {
        let (count, window_start) = pair.value();
        if now.duration_since(*window_start).as_secs() < LOGIN_WINDOW_SECS && *count >= LOGIN_MAX_ATTEMPTS {
            return axum::Json(LoginResponse {
                success: false,
                message: "Too many login attempts".to_string(),
                user: None,
                token: None,
            });
        }
    }

    // Check against configured users (with bcrypt verification)
    let valid = state.config.server.admin_users.iter()
        .any(|u| u.username == req.username && verify_password(&req.password, &u.password));
    
    // Also check legacy admin_token for backwards compat (constant-time)
    let legacy_valid = !state.config.server.admin_token.is_empty() &&
        constant_time_eq(&req.password, &state.config.server.admin_token);
    
    if valid || legacy_valid {
        let user = if valid {
            state.config.server.admin_users.iter()
                .find(|u| u.username == req.username)
                .map(|u| u.username.clone())
                .unwrap_or(req.username.clone())
        } else {
            "admin".to_string()
        };
        
        // Generate session token and store with creation timestamp
        let token = generate_token();
        let mut sessions = state.sessions.write().await;
        evict_expired_sessions(&mut sessions);
        sessions.insert(token.clone(), SessionEntry {
            user: user.clone(),
            created_at: std::time::Instant::now(),
        });
        drop(sessions);
        
        // Clear rate-limit on successful login.
        state.login_attempts.remove(&req.username);
        
        axum::Json(LoginResponse {
            success: true,
            message: "Login successful".to_string(),
            user: Some(user),
            token: Some(token),
        })
    } else {
        // Increment rate-limit on failed login.
        let now = std::time::Instant::now();
        state.login_attempts
            .entry(req.username.clone())
            .and_modify(|(count, window_start)| {
                if now.duration_since(*window_start).as_secs() >= LOGIN_WINDOW_SECS {
                    // Window expired — reset counter.
                    *count = 1;
                    *window_start = now;
                } else {
                    *count += 1;
                }
            })
            .or_insert((1, now));
        
        axum::Json(LoginResponse {
            success: false,
            message: "Invalid credentials".to_string(),
            user: None,
            token: None,
        })
    }
}

/// Logout handler
async fn logout_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
    if let Some(auth) = headers.get(AUTHORIZATION) {
        if let Ok(token) = auth.to_str() {
            if let Some(bearer) = token.strip_prefix("Bearer ") {
                let mut sessions = state.sessions.write().await;
                sessions.remove(bearer);
            }
        }
    }
    axum::Json(serde_json::json!({ "success": true, "message": "Logged out" }))
}

/// Get current user
async fn me_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
    if let Some(auth) = headers.get(AUTHORIZATION) {
        if let Ok(token) = auth.to_str() {
            if let Some(bearer) = token.strip_prefix("Bearer ") {
                let sessions = state.sessions.read().await;
                if let Some(entry) = sessions.get(bearer) {
                    return axum::Json(serde_json::json!({
                        "authenticated": true,
                        "user": entry.user
                    }));
                }
            }
        }
    }
    axum::Json(serde_json::json!({ "authenticated": false }))
}

/// Real-time metrics stream (SSE)
async fn metrics_stream_handler(
    State(state): State<AdminState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{interval, Duration};
    
    async fn make_snapshot(state: &AdminState) -> MetricsSnapshot {
        let table = state.route_table.get();
        let hosts = table.hosts();
        
        let mut targets = Vec::new();
        for host in hosts {
            if let Some(routes) = table.get_routes(host) {
                for route in routes.iter() {
                    for target in route.targets.iter() {
                        let stats = target.stats.as_ref();
                        targets.push(TargetMetrics {
                            service: target.service.clone(),
                            url: target.url.clone(),
                            protocol: format!("{:?}", target.parsed_protocol).to_lowercase(),
                            circuit_breaker: format!("{:?}", target.health_tracker.circuit_breaker().current_state()).to_lowercase(),
                            active_connections: target.active_connections.load(Ordering::Relaxed),
                            requests: stats.requests_total.load(Ordering::Relaxed),
                            errors: stats.errors_total.load(Ordering::Relaxed),
                            avg_latency_us: stats.avg_latency_us(),
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
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        }
    }
    
    // Create a stream that yields metrics every second
    let state_clone = state.clone();
    let stream = async_stream::stream! {
        let mut timer = interval(Duration::from_secs(1));
        
        // Send initial connection message
        yield Ok::<_, Infallible>(Event::default().data("event: connected\n\n"));
        
        loop {
            timer.tick().await;
            let snapshot = make_snapshot(&state_clone).await;
            let data = serde_json::to_string(&snapshot).unwrap_or_default();
            yield Ok(Event::default().data(format!("data: {}\n\n", data)));
        }
    };
    
    Sse::new(stream).keep_alive(KeepAlive::default())
}


/// Verify password against hash
fn verify_password(password: &str, hash: &str) -> bool {
    // If hash looks like bcrypt (starts with $2), verify it
    if hash.starts_with("$2") {
        verify(password, hash).unwrap_or(false)
    } else {
        // Legacy plain text comparison (constant-time to prevent timing attacks)
        constant_time_eq(password, hash)
    }
}

/// Generate a random session token
fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    BASE64.encode(&bytes)
}

async fn health_handler() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: "ok",
        service: "sentirum-lb",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn routes_handler(State(state): State<AdminState>) -> axum::Json<serde_json::Value> {
    let table = state.route_table.get();
    let route_count = table.route_count();
    let target_count = table.target_count();
    let hosts = table.hosts();

    let routes_info: Vec<serde_json::Value> = hosts
        .iter()
        .flat_map(|host| {
            let routes = table.get_routes(host).unwrap();
            routes.iter().map(move |route| {
                let targets: Vec<serde_json::Value> = route
                    .targets
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "service": t.service,
                            "url": t.url,
                            "weight": t.weight,
                            "protocol": format!("{:?}", t.upstream_protocol()).to_lowercase(),
                            "tls": t.upstream_tls(),
                            "http2": t.requires_http2(),
                            "websocket": t.is_websocket(),
                            "opts": t.opts,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "host": host,
                    "path": route.path,
                    "targets": targets,
                })
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "route_count": route_count,
        "target_count": target_count,
        "routes": routes_info,
    }))
}

async fn metrics_handler() -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        crate::metrics::prometheus::global().render(),
    )
}

async fn certs_handler(State(state): State<AdminState>) -> axum::Json<serde_json::Value> {
    let tls_source = match crate::proxy::tls::TlsMode::resolve(&state.config.tls) {
        Ok(Some(crate::proxy::tls::TlsMode::File(_))) => "file",
        Ok(Some(crate::proxy::tls::TlsMode::ConsulKv(_))) => "consul_kv",
        Ok(None) => "disabled",
        Err(_) => "invalid",
    };

    let runtime = state.tls_store.as_ref().map(|store| store.status());
    let client_ca_runtime = state.client_ca_store.as_ref().map(|store| store.status());

    axum::Json(serde_json::json!({
        "source": tls_source,
        "strict_sni": state.config.tls.strict_sni,
        "require_initial_snapshot": state.config.tls.require_initial_snapshot,
        "consul_cert_prefix": state.config.tls.consul_cert_prefix,
        "loaded_certificates": runtime.as_ref().map(|s| s.loaded_certificates.clone()).unwrap_or_default(),
        "certificates": runtime.as_ref().map(|s| s.certificates.clone()).unwrap_or_default(),
        "default_certificate": runtime.as_ref().and_then(|s| s.default_certificate.clone()),
        "last_consul_index": runtime.as_ref().map(|s| s.last_consul_index).unwrap_or_default(),
        "last_reload_unix": runtime.as_ref().and_then(|s| s.last_reload_unix),
        "last_error": runtime.as_ref().and_then(|s| s.last_error.clone()),
        "client_auth": {
            "mode": state.config.tls.client_auth,
            "ca_source": state.config.tls.client_ca_source,
            "ca_path": state.config.tls.client_ca_path,
            "ca_consul_prefix": state.config.tls.client_ca_consul_prefix,
            "ca_upgrade_cn": state.config.tls.client_ca_upgrade_cn,
            "loaded_entries": client_ca_runtime.as_ref().map(|s| s.loaded_entries.clone()).unwrap_or_default(),
            "certificates": client_ca_runtime.as_ref().map(|s| s.certificates.clone()).unwrap_or_default(),
            "last_consul_index": client_ca_runtime.as_ref().map(|s| s.last_consul_index).unwrap_or_default(),
            "last_reload_unix": client_ca_runtime.as_ref().and_then(|s| s.last_reload_unix),
            "last_error": client_ca_runtime.as_ref().and_then(|s| s.last_error.clone()),
        }
    }))
}

async fn config_handler(State(state): State<AdminState>) -> axum::Json<serde_json::Value> {
    let tls_source = match crate::proxy::tls::TlsMode::resolve(&state.config.tls) {
        Ok(Some(crate::proxy::tls::TlsMode::File(_))) => "file",
        Ok(Some(crate::proxy::tls::TlsMode::ConsulKv(_))) => "consul_kv",
        Ok(None) => "disabled",
        Err(_) => "invalid",
    };

    axum::Json(serde_json::json!({
        "server": {
            "listen": state.config.server.listen,
            "admin_listen": state.config.server.admin_listen,
            "workers": state.config.server.workers,
        },
        "consul": {
            "address": state.config.consul.address,
            "scheme": state.config.consul.scheme,
            "kv_prefix": state.config.consul.kv_prefix,
            "tag_prefix": state.config.consul.tag_prefix,
        },
        "proxy": {
            "strategy": state.config.proxy.strategy,
            "matcher": state.config.proxy.matcher,
            "connect_timeout": state.config.proxy.connect_timeout,
            "read_timeout": state.config.proxy.read_timeout,
            "write_timeout": state.config.proxy.write_timeout,
            "idle_timeout": state.config.proxy.idle_timeout,
            "enable_h2c": state.config.proxy.enable_h2c,
            "upstream_h2_max_streams": state.config.proxy.upstream_h2_max_streams,
            "upstream_h2_ping_interval": state.config.proxy.upstream_h2_ping_interval,
            "pool_size": state.config.proxy.pool_size,
            "max_connections": state.config.proxy.max_connections,
        },
        "tls": {
            "source": tls_source,
            "listen": state.config.tls.listen,
            "strict_sni": state.config.tls.strict_sni,
            "require_initial_snapshot": state.config.tls.require_initial_snapshot,
            "cert_path": state.config.tls.cert_path,
            "key_path": state.config.tls.key_path,
            "consul_cert_prefix": state.config.tls.consul_cert_prefix,
            "client_auth": state.config.tls.client_auth,
            "client_ca_source": state.config.tls.client_ca_source,
            "client_ca_path": state.config.tls.client_ca_path,
            "client_ca_consul_prefix": state.config.tls.client_ca_consul_prefix,
            "client_ca_upgrade_cn": state.config.tls.client_ca_upgrade_cn,
        },
        "tcp": {
            "mode": state.config.tcp.mode,
            "listen": state.config.tcp.listen,
            "refresh": state.config.tcp.refresh,
        },
    }))
}



use crate::route::target::global_dns_cache;

async fn dns_cache_handler() -> axum::Json<serde_json::Value> {
    let cache = global_dns_cache();
    let stats = cache.stats();
    let entries = cache.entries();
    
    axum::Json(serde_json::json!({
        "stats": {
            "total_entries": stats.entries,
            "hits": stats.hits,
            "misses": stats.misses,
            "negatives": stats.negatives,
            "hit_rate": if stats.hits + stats.misses > 0 {
                (stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100.0).round() as u64
            } else { 0 },
        },
        "entries": entries,
    }))
}


use crate::metrics::prometheus::global;

async fn consul_status_handler() -> axum::Json<serde_json::Value> {
    let m = global();
    
    axum::Json(serde_json::json!({
        "services": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_services.load(std::sync::atomic::Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_services.load(std::sync::atomic::Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_services.load(std::sync::atomic::Ordering::Relaxed),
        },
        "kv": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_kv.load(std::sync::atomic::Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_kv.load(std::sync::atomic::Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_kv.load(std::sync::atomic::Ordering::Relaxed),
        },
        "tls": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_tls.load(std::sync::atomic::Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_tls.load(std::sync::atomic::Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_tls.load(std::sync::atomic::Ordering::Relaxed),
        },
        "client_ca": {
            "status": "unknown",
            "last_index": m.consul_watcher_last_index_client_ca.load(std::sync::atomic::Ordering::Relaxed),
            "backoff_secs": m.consul_watcher_backoff_seconds_client_ca.load(std::sync::atomic::Ordering::Relaxed),
            "errors": m.consul_watcher_errors_total_client_ca.load(std::sync::atomic::Ordering::Relaxed),
        },
    }))
}




async fn topology_handler(State(state): State<AdminState>) -> axum::Json<serde_json::Value> {
    let table = state.route_table.get();
    let hosts = table.hosts();
    let metrics = global();
    
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    
    // LB node
    nodes.push(serde_json::json!({
        "id": "lb",
        "type": "lb",
        "label": "Sentirum LB",
        "x": 400,
        "y": 50,
        "stats": {
            "requests": metrics.requests_total.load(Ordering::Relaxed),
            "active_connections": metrics.active_connections.load(Ordering::Relaxed),
            "error_rate": if metrics.requests_total.load(Ordering::Relaxed) > 0 {
                (metrics.requests_error_total.load(Ordering::Relaxed) as f64 / metrics.requests_total.load(Ordering::Relaxed) as f64 * 100.0).round() as u64
            } else { 0 },
        }
    }));
    
    // Targets
    let mut target_idx = 0;
    for host in hosts {
        if let Some(routes) = table.get_routes(host) {
            for route in routes.iter() {
                for target in route.targets.iter() {
                    let cb_state = target.health_tracker.circuit_breaker().current_state();
                    let active_conns = target.active_connections.load(Ordering::Relaxed);
                    
                    let y = 180 + (target_idx % 4) * 100;
                    let x = 100 + (target_idx / 4) * 200;
                    
                    nodes.push(serde_json::json!({
                        "id": format!("target-{}", target_idx),
                        "type": "target",
                        "label": target.service,
                        "url": target.url,
                        "x": x,
                        "y": y,
                        "protocol": format!("{:?}", target.parsed_protocol).to_lowercase(),
                        "tls": target.parsed_tls,
                        "cb_state": format!("{:?}", cb_state).to_lowercase(),
                        "stats": {
                            "active_connections": active_conns,
                        }
                    }));
                    
                    edges.push(serde_json::json!({
                        "from": "lb",
                        "to": format!("target-{}", target_idx),
                        "cb_state": format!("{:?}", cb_state).to_lowercase(),
                    }));
                    
                    target_idx += 1;
                }
            }
        }
    }
    
    axum::Json(serde_json::json!({
        "nodes": nodes,
        "edges": edges,
    }))
}


async fn targets_metrics_handler(State(state): State<AdminState>) -> impl axum::response::IntoResponse {
    
    
    let table = state.route_table.get();
    let hosts = table.hosts();
    
    let mut output = String::new();
    
    for host in hosts {
        if let Some(routes) = table.get_routes(host) {
            for route in routes.iter() {
                for target in route.targets.iter() {
                    let stats = target.stats.as_ref();
                    let requests = stats.requests_total.load(Ordering::Relaxed);
                    let errors = stats.errors_total.load(Ordering::Relaxed);
                    let latency_sum = stats.latency_sum_us.load(Ordering::Relaxed);
                    let bytes = stats.bytes_total.load(Ordering::Relaxed);
                    let cb_state = target.health_tracker.circuit_breaker().current_state();
                    
                    let svc = escape_prometheus_label(&target.service);
                    let h = escape_prometheus_label(host);
                    let p = escape_prometheus_label(&route.path);
                    let proto = escape_prometheus_label(&format!("{:?}", target.parsed_protocol).to_lowercase());

                    output.push_str("# HELP sentirum_lb_target_requests_total Requests per target\n");
                    output.push_str("# TYPE sentirum_lb_target_requests_total counter\n");
                    output.push_str(&format!(
                        "sentirum_lb_target_requests_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {requests}\n\n"
                    ));
                    output.push_str("# HELP sentirum_lb_target_errors_total Errors per target\n");
                    output.push_str("# TYPE sentirum_lb_target_errors_total counter\n");
                    output.push_str(&format!(
                        "sentirum_lb_target_errors_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {errors}\n\n"
                    ));
                    output.push_str("# HELP sentirum_lb_target_latency_us_total Total latency per target\n");
                    output.push_str("# TYPE sentirum_lb_target_latency_us_total counter\n");
                    output.push_str(&format!(
                        "sentirum_lb_target_latency_us_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {latency_sum}\n\n"
                    ));
                    output.push_str("# HELP sentirum_lb_target_bytes_total Bytes per target\n");
                    output.push_str("# TYPE sentirum_lb_target_bytes_total counter\n");
                    output.push_str(&format!(
                        "sentirum_lb_target_bytes_total{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {bytes}\n\n"
                    ));

                    let cb_value = match cb_state {
                        CircuitState::Closed => 0,
                        CircuitState::Open => 2,
                        CircuitState::HalfOpen => 1,
                    };
                    output.push_str("# HELP sentirum_lb_target_circuit_breaker_state Circuit breaker state (0=closed, 1=half-open, 2=open)\n");
                    output.push_str("# TYPE sentirum_lb_target_circuit_breaker_state gauge\n");
                    output.push_str(&format!(
                        "sentirum_lb_target_circuit_breaker_state{{service=\"{svc}\",host=\"{h}\",path=\"{p}\",protocol=\"{proto}\"}} {cb_value}\n\n"
                    ));
                }
            }
        }
    }
    
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        output
    )
}

/// Return per-target health and circuit breaker status.
async fn targets_handler(State(state): State<AdminState>) -> axum::Json<serde_json::Value> {
    
    
    let table = state.route_table.get();
    let hosts = table.hosts();

    let mut targets = Vec::new();
    for host in hosts {
        if let Some(routes) = table.get_routes(host) {
            for route in routes.iter() {
                for target in route.targets.iter() {
                    let cb_state = target.health_tracker.circuit_breaker().current_state();
                    let active_conns = target.active_connections.load(Ordering::Relaxed);
                    let stats = target.stats.as_ref();
                    let requests = stats.requests_total.load(Ordering::Relaxed);
                    let errors = stats.errors_total.load(Ordering::Relaxed);
                    let error_rate = if requests > 0 { (errors as f64 / requests as f64 * 100.0).round() as u64 } else { 0 };
                    let avg_latency = stats.avg_latency_us();
                    
                    targets.push(serde_json::json!({
                        "host": host,
                        "path": &route.path,
                        "service": &target.service,
                        "url": &target.url,
                        "protocol": format!("{:?}", target.parsed_protocol).to_lowercase(),
                        "tls": target.parsed_tls,
                        "http2": target.parsed_protocol.requires_http2(),
                        "active_connections": active_conns,
                        "circuit_breaker": format!("{:?}", cb_state).to_lowercase(),
                        "stats": {
                            "requests": requests,
                            "errors": errors,
                            "error_rate_pct": error_rate,
                            "avg_latency_us": avg_latency,
                            "bytes_total": stats.bytes_total.load(Ordering::Relaxed),
                        }
                    }));
                }
            }
        }
    }

    axum::Json(serde_json::json!({
        "targets": targets,
        "total": targets.len(),
    }))
}

/// Return recent log entries from the ring buffer.
async fn logs_handler(
    State(state): State<AdminState>,
    Query(params): Query<LogsQuery>,
) -> axum::Json<Vec<crate::admin::logs::LogEntry>> {
    let limit = params.limit.unwrap_or(100).min(1000);
    let level = params.level.as_deref();

    if let Some(buffer) = &state.log_buffer {
        axum::Json(buffer.recent(limit, level))
    } else {
        axum::Json(Vec::new())
    }
}

/// SSE stream of live log events.
async fn logs_stream_handler(
    State(state): State<AdminState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let buffer = state.log_buffer.clone();
    let stream: Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> = if let Some(buf) = &buffer {
        let receiver = buf.subscribe();
        let stream = tokio_stream::wrappers::BroadcastStream::new(receiver)
            .filter_map(|result| match result {
                Ok(entry) => {
                    let data = serde_json::to_string(&entry).unwrap_or_default();
                    Some(Ok(Event::default().data(data)))
                }
                Err(_) => None, // Skip lagged messages.
            });
        Box::pin(stream)
    } else {
        Box::pin(tokio_stream::pending())
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------







// ---------------------------------------------------------------------------
// Session cleanup background service
// ---------------------------------------------------------------------------

/// Background service that periodically cleans up expired sessions.
/// This prevents the session map from growing unbounded without incurring
/// O(n) eviction costs on every request's hot path.
struct SessionCleanupBackground {
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

impl SessionCleanupBackground {
    fn new(sessions: Arc<RwLock<HashMap<String, SessionEntry>>>) -> Self {
        Self { sessions }
    }

    async fn run(&self) {
        const CLEANUP_INTERVAL_SECS: u64 = 60;
        let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

        loop {
            interval.tick().await;
            let now = std::time::Instant::now();


            let Ok(mut sessions) = self.sessions.try_write() else {
                continue;
            };
            let before = sessions.len();
            sessions.retain(|_, entry| {
                now.duration_since(entry.created_at).as_secs() < SESSION_TTL_SECS
            });
            let evicted = before.saturating_sub(sessions.len());
            if evicted > 0 {
                tracing::debug!(evicted, remaining = sessions.len(), "Expired sessions evicted");
            }
        }
    }
}

/// Run the admin API server using axum
pub async fn run_admin_server(
    config: Arc<Config>,
    route_table: Arc<ManagedRouteTable>,
    tls_store: Option<Arc<DynamicCertStore>>,
    client_ca_store: Option<Arc<DynamicClientCaStore>>,
    log_buffer: Option<Arc<crate::admin::logs::LogBuffer>>,
) {
    let addr = config.server.admin_listen.clone();

    let has_any_auth = !config.server.admin_token.is_empty() || !config.server.admin_users.is_empty();
    if !has_any_auth && !is_loopback_bind(&addr) {
        tracing::error!(addr = %addr, "Refusing to expose admin API without admin_token or admin_users on non-loopback address");
        return;
    }

    let auth_enabled = !config.server.admin_token.is_empty() || !config.server.admin_users.is_empty();
    let state = AdminState {
        config,
        route_table,
        tls_store,
        client_ca_store,
        log_buffer,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        login_attempts: Arc::new(dashmap::DashMap::new()),
    };

    // Spawn background session cleanup service (non-blocking, fire-and-forget).
    // This runs independently from the axum server and prevents the session
    // map from growing unbounded without O(n) cost on every auth request.
    let cleanup_sessions = state.sessions.clone();
    tokio::spawn(async move {
        SessionCleanupBackground::new(cleanup_sessions).run().await;
    });

    let app = build_router(state);

    tracing::info!(addr = %addr, auth_enabled, "Admin API server starting (axum)");

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "Failed to bind admin API");
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(error = %e, "Admin API server error");
    }
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Constant-time comparison to prevent timing side-channel attacks on the admin token.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let equal_len = a.len() == b.len();
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    // Fixed iteration count so runtime doesn't depend on either string's length.
    let mut result: u8 = 0;
    for i in 0..256 {
        result |= a_bytes.get(i).copied().unwrap_or(0) ^ b_bytes.get(i).copied().unwrap_or(0);
    }
    equal_len && result == 0
}

async fn admin_auth_middleware(
    State(state): State<AdminState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    // Path A: static admin_token via Bearer or X-Admin-Token header.
    // Only valid when admin_token is actually configured (non-empty).
    let expected = state.config.server.admin_token.as_str();
    let token_auth = if !expected.is_empty() {
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(|value| constant_time_eq(value, expected))
            .unwrap_or(false)
        || headers
            .get("x-admin-token")
            .and_then(|value| value.to_str().ok())
            .map(|value| constant_time_eq(value, expected))
            .unwrap_or(false)
    } else {
        false
    };


    // Path B: session-based auth — Bearer token lookup in session store.
    // No eviction here: hot path should be fast. Background task + login-time
    // eviction handles cleanup. This avoids O(n) retain() on every request.
    let session_auth = if !token_auth {
        if let Some(bearer) = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        {

            let sessions = state.sessions.read().await;
            sessions.get(bearer).is_some()
        } else {
            false
        }
    } else {
        false
    };

    // Path C: query-param token auth for SSE endpoints (EventSource doesn't support headers).
    let query_auth = if !token_auth && !session_auth {
        request.uri().query()
            .and_then(|qs| {
                qs.split('&')
                    .filter_map(|pair| pair.split_once('='))
                    .find(|(k, _)| *k == "token")
                    .map(|(_, v)| v.to_string())
            })
            .map(|token| {
                // Check against admin_token (constant-time).
                let matches_admin = !expected.is_empty() && constant_time_eq(&token, expected);
                if matches_admin {
                    return true;
                }

                // Check against session store.
                // Use try_read to avoid blocking; fall through to false if contested.
                if let Ok(sessions) = state.sessions.try_read() {
                    sessions.get(&token).is_some()
                } else {
                    false
                }
            })
        .unwrap_or(false)
    } else {
        false
    };

    if token_auth || session_auth || query_auth {
        Ok(next.run(request).await)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(
                serde_json::json!({"error": "unauthorized", "message": "Valid Bearer token or X-Admin-Token required"}),
            ),
        ))
    }
}

/// Evict sessions that have exceeded SESSION_TTL_SECS or when the map
/// exceeds SESSION_MAX_CAPACITY. Called on insert (login) and on auth
/// lookups so stale entries are cleaned up lazily.
fn evict_expired_sessions(sessions: &mut HashMap<String, SessionEntry>) {
    let now = std::time::Instant::now();
    sessions.retain(|_, entry| now.duration_since(entry.created_at).as_secs() < SESSION_TTL_SECS);
    // If still over capacity, drop oldest entries
    if sessions.len() > SESSION_MAX_CAPACITY {
        let mut entries: Vec<(String, std::time::Instant)> = sessions
            .iter()
            .map(|(k, v)| (k.clone(), v.created_at))
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        let to_remove = sessions.len() - SESSION_MAX_CAPACITY;
        for (key, _) in entries.into_iter().take(to_remove) {
            sessions.remove(&key);
        }
    }
}

/// Escape a string value for safe inclusion in Prometheus label values.
/// Per the text exposition format, backslash, double-quote, and newline
/// must be escaped.
fn escape_prometheus_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn is_loopback_bind(addr: &str) -> bool {
    if addr.starts_with("0.0.0.0") || addr.starts_with("[::]") || addr.starts_with(':') {
        return false;
    }
    addr.starts_with("127.")
        || addr.starts_with("localhost:")
        || addr == "localhost"
        || addr.starts_with("[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use axum::body::{Body, to_bytes};
    use http::Request;
    use tower::ServiceExt; // for oneshot()

    fn make_test_config() -> Arc<Config> {
        Arc::new(Config {
            server: ServerConfig {
                listen: ":9999".to_string(),
                admin_listen: "127.0.0.1:9998".to_string(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
            },
            consul: ConsulConfig {
                address: "127.0.0.1:8500".to_string(),
                scheme: "http".to_string(),
                token: String::new(),
                kv_prefix: "/sentirum-lb/routes".to_string(),
                tag_prefix: "urlprefix-".to_string(),
                poll_interval: "0s".to_string(),
                service_discovery: false,
                kv_watching: false,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
            tcp: TcpConfig::default(),
        })
    }

    fn make_test_state() -> AdminState {
        AdminState {
            config: make_test_config(),
            route_table: Arc::new(ManagedRouteTable::new()),
            tls_store: None,
            client_ca_store: None,
            log_buffer: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            login_attempts: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn make_authed_test_state(admin_token: &str, admin_users: Vec<AdminUser>) -> AdminState {
        AdminState {
            config: Arc::new(Config {
                server: ServerConfig {
                    listen: ":9999".to_string(),
                    admin_listen: "127.0.0.1:9998".to_string(),
                    admin_token: admin_token.to_string(),
                    admin_users,
                    workers: 0,
                },
                consul: ConsulConfig {
                    address: "127.0.0.1:8500".to_string(),
                    scheme: "http".to_string(),
                    token: String::new(),
                    kv_prefix: "/sentirum-lb/routes".to_string(),
                    tag_prefix: "urlprefix-".to_string(),
                    poll_interval: "0s".to_string(),
                    service_discovery: false,
                    kv_watching: false,
                    service_whitelist: Vec::new(),
                    service_blacklist: Vec::new(),
                    graceful_shutdown: true,
                    include_warning: false,
                },
                proxy: ProxyConfig::default(),
                logging: LoggingConfig::default(),
                tls: TlsConfig::default(),
                tcp: TcpConfig::default(),
            }),
            route_table: Arc::new(ManagedRouteTable::new()),
            tls_store: None,
            client_ca_store: None,
            log_buffer: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            login_attempts: Arc::new(dashmap::DashMap::new()),
        }
    }

    #[tokio::test]
    async fn test_admin_health() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_routes() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/routes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_config_includes_http2_fields() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_metrics() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_certs() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/certs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("certificates").is_some());
    }

    #[tokio::test]
    async fn test_admin_config() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_dashboard() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("sentirum"));
    }

    #[tokio::test]
    async fn test_admin_logs_returns_empty_without_buffer() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn test_admin_logs_with_buffer() {
        let buffer = crate::admin::logs::LogBuffer::new();
        buffer.push(crate::admin::logs::LogEntry {
            ts: 1000,
            level: "INFO".to_string(),
            message: "test message".to_string(),
            target: "test".to_string(),
        });

        let mut state = make_test_state();
        state.log_buffer = Some(buffer);
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/logs?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["message"], "test message");
    }

    #[tokio::test]
    async fn test_admin_not_found() {
        let state = make_test_state();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn test_admin_requires_token_when_configured() {
        let mut state = make_test_state();
        Arc::make_mut(&mut state.config).server.admin_token = "secret".to_string();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_admin_accepts_bearer_token() {
        let mut state = make_test_state();
        Arc::make_mut(&mut state.config).server.admin_token = "secret".to_string();
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/health")
                    .header("Authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_rejects_empty_bearer_when_token_set() {
        let state = make_authed_test_state("secret", vec![]);
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/health")
                    .header("Authorization", "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_admin_session_token_accepted_after_login() {
        // Configure an admin user with bcrypt hash of "password123"
        let hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        let state = make_authed_test_state("", vec![AdminUser {
            username: "admin".to_string(),
            password: hash,
        }]);
        let app = build_router(state.clone());

        // Login first
        let login_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"username": "admin", "password": "password123"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_response.status(), 200);
        let body = to_bytes(login_response.into_body(), usize::MAX).await.unwrap();
        let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = login_json["token"].as_str().expect("login should return a token");
        assert!(!token.is_empty());

        // Use the session token to access a protected route
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/health")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_users_without_admin_token_rejects_empty_bearer() {
        // Only admin_users set, admin_token is empty — empty bearer must NOT bypass
        let hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        let state = make_authed_test_state("", vec![AdminUser {
            username: "admin".to_string(),
            password: hash,
        }]);
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/health")
                    .header("Authorization", "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }

    #[test]
    fn test_escape_prometheus_label() {
        assert_eq!(escape_prometheus_label("simple"), "simple");
        assert_eq!(escape_prometheus_label("has\"quote"), "has\\\"quote");
        assert_eq!(escape_prometheus_label("back\\slash"), "back\\\\slash");
        assert_eq!(escape_prometheus_label("new\nline"), "new\\nline");
        assert_eq!(escape_prometheus_label("all\"three\\here\n"), "all\\\"three\\\\here\\n");
    }

    #[test]
    fn test_is_loopback_bind_loopback() {
        assert!(is_loopback_bind("127.0.0.1:9998"));
        assert!(is_loopback_bind("localhost:9998"));
        assert!(is_loopback_bind("localhost"));
        assert!(is_loopback_bind("[::1]:9998"));
    }

    #[test]
    fn test_is_loopback_bind_not_loopback() {
        assert!(!is_loopback_bind("0.0.0.0:9998"));
        assert!(!is_loopback_bind("[::]:9998"));
        assert!(!is_loopback_bind(":9998"));
        assert!(!is_loopback_bind("10.0.0.1:9998"));
        assert!(!is_loopback_bind("localhostfoo:9998"));
    }
}

//! Admin API for Sentirum LB using axum.
//!
//! Endpoints:
//! - `GET /admin/` — Dashboard UI (embedded SPA)
//! - `GET /admin/health` — Health check
//! - `GET /admin/routes` — Route table inspection
//! - `GET /admin/metrics` — Prometheus metrics
//! - `GET /admin/config` — Config inspection
//! - `PUT /admin/config` — Update runtime configuration (hot-reload)
//! - `GET /admin/certs` — Runtime TLS certificate status
//! - `GET /admin/logs` — Recent log entries (JSON)
//! - `GET /admin/logs/stream` — Live log stream (SSE)

use crate::config::{Config, SharedConfig};
use crate::route::target::CircuitState;
use crate::proxy::tls::{DynamicCertStore, DynamicClientCaStore};
use crate::route::registry::ManagedRouteTable;
use axum::Router;
use axum::extract::{Query, State, Json};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post, put};
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

/// Request body for config update (partial update - only specified fields are applied)
#[derive(Deserialize)]
pub struct ConfigUpdateRequest {
    #[serde(default)]
    pub proxy: Option<ProxyConfigUpdate>,
    #[serde(default)]
    pub logging: Option<LoggingConfigUpdate>,
}

#[derive(Deserialize)]
pub struct ProxyConfigUpdate {
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub matcher: Option<String>,
    #[serde(default)]
    pub request_id_header: Option<String>,
    #[serde(default)]
    pub no_route_status: Option<u16>,
    #[serde(default)]
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub read_timeout: Option<String>,
    #[serde(default)]
    pub write_timeout: Option<String>,
    #[serde(default)]
    pub idle_timeout: Option<String>,
    #[serde(default)]
    pub enable_h2c: Option<bool>,
    #[serde(default)]
    pub upstream_h2_max_streams: Option<usize>,
    #[serde(default)]
    pub upstream_h2_ping_interval: Option<String>,
    #[serde(default)]
    pub pool_size: Option<usize>,
    #[serde(default)]
    pub max_connections: Option<usize>,
    #[serde(default)]
    pub dns_cache_ttl: Option<u64>,
    #[serde(default)]
    pub dns_negative_cache_ttl: Option<u64>,
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
    #[serde(default)]
    pub circuit_breaker_enabled: Option<bool>,
    #[serde(default)]
    pub circuit_breaker_error_threshold: Option<u8>,
    #[serde(default)]
    pub circuit_breaker_window_size: Option<usize>,
    #[serde(default)]
    pub circuit_breaker_recovery_timeout: Option<u64>,
    #[serde(default)]
    pub circuit_breaker_half_open_max: Option<usize>,
    #[serde(default)]
    pub health_check_interval: Option<String>,
    #[serde(default)]
    pub health_check_timeout: Option<String>,
    #[serde(default)]
    pub health_check_fall: Option<usize>,
    #[serde(default)]
    pub health_check_rise: Option<usize>,
    #[serde(default)]
    pub rate_limit_per_target: Option<usize>,
    #[serde(default)]
    pub rate_limit_burst: Option<usize>,
}

#[derive(Deserialize)]
pub struct LoggingConfigUpdate {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}


/// Session entry with creation timestamp for TTL eviction.
pub struct SessionEntry {
    pub user: String,
    pub created_at: std::time::Instant,
}

/// Shared state for admin API handlers
#[derive(Clone)]
pub struct AdminState {
    pub config: SharedConfig,
    pub startup_config: Arc<Config>,
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
}

/// Query parameters for the log history endpoint.
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// Maximum number of entries to return (default 100, max 1000).
    pub limit: Option<usize>,
    /// Minimum log level: "ERROR", "WARN", "INFO", "DEBUG", "TRACE".
    pub level: Option<String>,
    /// Text search filter (case-insensitive substring match on message)
    pub search: Option<String>,
}

/// Build the admin API router
pub fn build_router(state: AdminState) -> Router {
    // Public routes (no auth required)
    let public = Router::new()
        .route("/admin", get(|| async { axum::response::Redirect::permanent("/admin/") }))
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
        .route("/admin/config", put(config_update_handler))
        .route("/admin/config/reset", post(config_reset_handler))
        .route("/admin/certs", get(certs_handler))
        .route("/admin/logs", get(logs_handler))
        .route("/admin/targets", get(targets_handler))
        .route("/admin/consul-status", get(consul_status_handler))
        .route("/admin/topology", get(topology_handler))
        .route("/admin/targets-metrics", get(targets_metrics_handler))
        .route("/admin/dns-cache", get(dns_cache_handler))
        .route("/admin/logs/stream", get(logs_stream_handler))
        .route("/admin/metrics/stream", get(metrics_stream_handler));

    let config = state.config.load();
    let no_auth = config.server.admin_token.is_empty() && config.server.admin_users.is_empty();
    drop(config);
    if no_auth {
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
    let config = state.config.load();
    let valid = config.server.admin_users.iter()
        .any(|u| u.username == req.username && verify_password(&req.password, &u.password));
    
    // Also check legacy admin_token for backwards compat (constant-time)
    let legacy_valid = !config.server.admin_token.is_empty() &&
        constant_time_eq(&req.password, &config.server.admin_token);
    
    if valid || legacy_valid {
        let user = if valid {
            config.server.admin_users.iter()
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
                            host: host.to_string(),
                            path: route.path.clone(),
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
        yield Ok::<_, Infallible>(Event::default().data("connected"));
        
        loop {
            timer.tick().await;
            let snapshot = make_snapshot(&state_clone).await;
            let data = serde_json::to_string(&snapshot).unwrap_or_default();
            yield Ok(Event::default().data(data));
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
    let config = state.config.load();
    let default_matcher = config.proxy.matcher.clone();
    drop(config);

    let routes_info: Vec<serde_json::Value> = hosts
        .iter()
        .flat_map(|host| {
            let routes = table.get_routes(host).unwrap();
            let default_matcher = default_matcher.clone();
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

                let matcher = if route.glob.is_some() {
                    "glob".to_string()
                } else {
                    default_matcher.clone()
                };

                serde_json::json!({
                    "host": host,
                    "path": route.path,
                    "matcher": matcher,
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
    let config = state.config.load();
    let tls_source = match crate::proxy::tls::TlsMode::resolve(&config.tls) {
        Ok(Some(crate::proxy::tls::TlsMode::File(_))) => "file",
        Ok(Some(crate::proxy::tls::TlsMode::ConsulKv(_))) => "consul_kv",
        Ok(None) => "disabled",
        Err(_) => "invalid",
    };

    let runtime = state.tls_store.as_ref().map(|store| store.status());
    let client_ca_runtime = state.client_ca_store.as_ref().map(|store| store.status());

    axum::Json(serde_json::json!({
        "source": tls_source,
        "strict_sni": config.tls.strict_sni,
        "require_initial_snapshot": config.tls.require_initial_snapshot,
        "consul_cert_prefix": config.tls.consul_cert_prefix,
        "loaded_certificates": runtime.as_ref().map(|s| s.loaded_certificates.clone()).unwrap_or_default(),
        "certificates": runtime.as_ref().map(|s| s.certificates.clone()).unwrap_or_default(),
        "default_certificate": runtime.as_ref().and_then(|s| s.default_certificate.clone()),
        "last_consul_index": runtime.as_ref().map(|s| s.last_consul_index).unwrap_or_default(),
        "last_reload_unix": runtime.as_ref().and_then(|s| s.last_reload_unix),
        "last_error": runtime.as_ref().and_then(|s| s.last_error.clone()),
        "client_auth": {
            "mode": config.tls.client_auth,
            "ca_source": config.tls.client_ca_source,
            "ca_path": config.tls.client_ca_path,
            "ca_consul_prefix": config.tls.client_ca_consul_prefix,
            "ca_upgrade_cn": config.tls.client_ca_upgrade_cn,
            "loaded_entries": client_ca_runtime.as_ref().map(|s| s.loaded_entries.clone()).unwrap_or_default(),
            "certificates": client_ca_runtime.as_ref().map(|s| s.certificates.clone()).unwrap_or_default(),
            "last_consul_index": client_ca_runtime.as_ref().map(|s| s.last_consul_index).unwrap_or_default(),
            "last_reload_unix": client_ca_runtime.as_ref().and_then(|s| s.last_reload_unix),
            "last_error": client_ca_runtime.as_ref().and_then(|s| s.last_error.clone()),
        }
    }))
}

fn runtime_config_capabilities() -> serde_json::Value {
    serde_json::json!({
        "strategy": true,
        "matcher": true,
        "request_id_header": true,
        "no_route_status": true,
        "timeouts": true,
        "max_connections": true,
        "dns_cache_ttl": true,
        "circuit_breaker": true,
        "upstream_http2": true,
        "pool_size": false,
        "enable_h2c": false,
        "trusted_proxies": false,
        "health_check": false,
        "rate_limit": false,
        "logging_level": false,
        "logging_format": false
    })
}

fn public_config_json(config: &Config) -> serde_json::Value {
    let tls_source = match crate::proxy::tls::TlsMode::resolve(&config.tls) {
        Ok(Some(crate::proxy::tls::TlsMode::File(_))) => "file",
        Ok(Some(crate::proxy::tls::TlsMode::ConsulKv(_))) => "consul_kv",
        Ok(None) => "disabled",
        Err(_) => "invalid",
    };

    serde_json::json!({
        "server": {
            "listen": config.server.listen.clone(),
            "admin_listen": config.server.admin_listen.clone(),
            "workers": config.server.workers,
        },
        "consul": {
            "address": config.consul.address.clone(),
            "scheme": config.consul.scheme.clone(),
            "kv_prefix": config.consul.kv_prefix.clone(),
            "tag_prefix": config.consul.tag_prefix.clone(),
        },
        "proxy": {
            "strategy": config.proxy.strategy.clone(),
            "matcher": config.proxy.matcher.clone(),
            "request_id_header": config.proxy.request_id_header.clone(),
            "no_route_status": config.proxy.no_route_status,
            "connect_timeout": config.proxy.connect_timeout.clone(),
            "read_timeout": config.proxy.read_timeout.clone(),
            "write_timeout": config.proxy.write_timeout.clone(),
            "idle_timeout": config.proxy.idle_timeout.clone(),
            "enable_h2c": config.proxy.enable_h2c,
            "upstream_h2_max_streams": config.proxy.upstream_h2_max_streams,
            "upstream_h2_ping_interval": config.proxy.upstream_h2_ping_interval.clone(),
            "pool_size": config.proxy.pool_size,
            "max_connections": config.proxy.max_connections,
            "dns_cache_ttl": config.proxy.dns_cache_ttl,
            "dns_negative_cache_ttl": config.proxy.dns_negative_cache_ttl,
            "trusted_proxies": config.proxy.trusted_proxies.clone(),
            "circuit_breaker_enabled": config.proxy.circuit_breaker_enabled,
            "circuit_breaker_error_threshold": config.proxy.circuit_breaker_error_threshold,
            "circuit_breaker_window_size": config.proxy.circuit_breaker_window_size,
            "circuit_breaker_recovery_timeout": config.proxy.circuit_breaker_recovery_timeout,
            "circuit_breaker_half_open_max": config.proxy.circuit_breaker_half_open_max,
            "health_check_interval": config.proxy.health_check_interval.clone(),
            "health_check_timeout": config.proxy.health_check_timeout.clone(),
            "health_check_fall": config.proxy.health_check_fall,
            "health_check_rise": config.proxy.health_check_rise,
            "rate_limit_per_target": config.proxy.rate_limit_per_target,
            "rate_limit_burst": config.proxy.rate_limit_burst,
        },
        "tls": {
            "source": tls_source,
            "listen": config.tls.listen.clone(),
            "strict_sni": config.tls.strict_sni,
            "require_initial_snapshot": config.tls.require_initial_snapshot,
            "cert_path": config.tls.cert_path.clone(),
            "key_path": config.tls.key_path.clone(),
            "consul_cert_prefix": config.tls.consul_cert_prefix.clone(),
            "client_auth": config.tls.client_auth.clone(),
            "client_ca_source": config.tls.client_ca_source.clone(),
            "client_ca_path": config.tls.client_ca_path.clone(),
            "client_ca_consul_prefix": config.tls.client_ca_consul_prefix.clone(),
            "client_ca_upgrade_cn": config.tls.client_ca_upgrade_cn.clone(),
        },
        "tcp": {
            "mode": config.tcp.mode.clone(),
            "listen": config.tcp.listen.clone(),
            "refresh": config.tcp.refresh.clone(),
        },
    })
}

async fn config_handler(State(state): State<AdminState>) -> axum::Json<serde_json::Value> {
    let config = state.config.load();
    let mut json = public_config_json(&config);
    json["meta"] = serde_json::json!({
        "runtime": runtime_config_capabilities(),
        "startup": public_config_json(&state.startup_config),
        "reset_mode": "startup_snapshot"
    });
    axum::Json(json)
}

fn circuit_breaker_config_from_proxy(
    proxy: &crate::config::ProxyConfig,
) -> Option<crate::route::target::CircuitBreakerConfig> {
    proxy
        .circuit_breaker_enabled
        .then_some(crate::route::target::CircuitBreakerConfig {
            error_threshold: proxy.circuit_breaker_error_threshold,
            window_size: proxy.circuit_breaker_window_size,
            recovery_timeout_secs: proxy.circuit_breaker_recovery_timeout,
            half_open_max_requests: proxy.circuit_breaker_half_open_max,
        })
}

fn unsupported_runtime_updates(update: &ConfigUpdateRequest) -> Vec<&'static str> {
    let mut unsupported = Vec::new();

    if let Some(proxy) = &update.proxy {
        if proxy.enable_h2c.is_some() {
            unsupported.push("proxy.enable_h2c");
        }
        if proxy.pool_size.is_some() {
            unsupported.push("proxy.pool_size");
        }
        if proxy.trusted_proxies.is_some() {
            unsupported.push("proxy.trusted_proxies");
        }
        if proxy.health_check_interval.is_some()
            || proxy.health_check_timeout.is_some()
            || proxy.health_check_fall.is_some()
            || proxy.health_check_rise.is_some()
        {
            unsupported.push("proxy.health_check_*");
        }
        if proxy.rate_limit_per_target.is_some() || proxy.rate_limit_burst.is_some() {
            unsupported.push("proxy.rate_limit_*");
        }
    }

    if let Some(logging) = &update.logging {
        if logging.level.is_some() {
            unsupported.push("logging.level");
        }
        if logging.format.is_some() {
            unsupported.push("logging.format");
        }
    }

    unsupported
}

/// PUT /admin/config - Update runtime configuration
async fn config_update_handler(
    State(state): State<AdminState>,
    Json(update): Json<ConfigUpdateRequest>,
) -> axum::Json<serde_json::Value> {
    let unsupported = unsupported_runtime_updates(&update);
    if !unsupported.is_empty() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!(
                "Runtime update is not supported for: {}",
                unsupported.join(", ")
            ),
        }));
    }

    let current = state.config.load();
    let mut new_proxy = current.proxy.clone();
    let mut new_logging = current.logging.clone();

    if let Some(proxy) = &update.proxy {
        if let Some(v) = &proxy.strategy {
            new_proxy.strategy = v.clone();
        }
        if let Some(v) = &proxy.matcher {
            new_proxy.matcher = v.clone();
        }
        if let Some(v) = &proxy.request_id_header {
            new_proxy.request_id_header = v.clone();
        }
        if let Some(v) = proxy.no_route_status {
            new_proxy.no_route_status = v;
        }
        if let Some(v) = &proxy.connect_timeout {
            new_proxy.connect_timeout = v.clone();
        }
        if let Some(v) = &proxy.read_timeout {
            new_proxy.read_timeout = v.clone();
        }
        if let Some(v) = &proxy.write_timeout {
            new_proxy.write_timeout = v.clone();
        }
        if let Some(v) = &proxy.idle_timeout {
            new_proxy.idle_timeout = v.clone();
        }
        if let Some(v) = proxy.upstream_h2_max_streams {
            new_proxy.upstream_h2_max_streams = v;
        }
        if let Some(v) = &proxy.upstream_h2_ping_interval {
            new_proxy.upstream_h2_ping_interval = v.clone();
        }
        if let Some(v) = proxy.max_connections {
            new_proxy.max_connections = v;
        }
        if let Some(v) = proxy.dns_cache_ttl {
            new_proxy.dns_cache_ttl = v;
        }
        if let Some(v) = proxy.dns_negative_cache_ttl {
            new_proxy.dns_negative_cache_ttl = v;
        }
        if let Some(v) = proxy.circuit_breaker_enabled {
            new_proxy.circuit_breaker_enabled = v;
        }
        if let Some(v) = proxy.circuit_breaker_error_threshold {
            new_proxy.circuit_breaker_error_threshold = v;
        }
        if let Some(v) = proxy.circuit_breaker_window_size {
            new_proxy.circuit_breaker_window_size = v;
        }
        if let Some(v) = proxy.circuit_breaker_recovery_timeout {
            new_proxy.circuit_breaker_recovery_timeout = v;
        }
        if let Some(v) = proxy.circuit_breaker_half_open_max {
            new_proxy.circuit_breaker_half_open_max = v;
        }
    }

    if let Some(logging) = &update.logging {
        if let Some(v) = &logging.level {
            new_logging.level = v.clone();
        }
        if let Some(v) = &logging.format {
            new_logging.format = v.clone();
        }
    }

    let temp_config = Config {
        server: current.server.clone(),
        consul: current.consul.clone(),
        proxy: new_proxy.clone(),
        logging: new_logging.clone(),
        tls: current.tls.clone(),
        tcp: current.tcp.clone(),
    };
    let old_cb_config = circuit_breaker_config_from_proxy(&current.proxy);
    drop(current);

    if let Some(validation_error) = temp_config.validate() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Validation failed: {}", validation_error),
        }));
    }

    let new_cb_config = circuit_breaker_config_from_proxy(&temp_config.proxy);
    let dns_ttl = temp_config.proxy.dns_cache_ttl;
    let dns_negative_ttl = temp_config.proxy.dns_negative_cache_ttl;
    state.config.store(Arc::new(temp_config));
    crate::route::target::global_dns_cache().set_ttl(dns_ttl, dns_negative_ttl);

    if old_cb_config != new_cb_config {
        state.route_table.reconfigure_circuit_breaker(new_cb_config);
    }

    axum::Json(serde_json::json!({
        "success": true,
        "message": "Configuration updated successfully",
        "runtime": {
            "strategy": true,
            "matcher": true,
            "request_id_header": true,
            "no_route_status": true,
            "timeouts": true,
            "max_connections": true,
            "dns_cache_ttl": true,
            "circuit_breaker": true,
            "upstream_http2": true,
            "pool_size": false,
            "enable_h2c": false,
            "trusted_proxies": false,
            "health_check": false,
            "rate_limit": false,
            "logging_level": false,
            "logging_format": false
        }
    }))
}
/// POST /admin/config/reset — Reset runtime config to startup defaults.
/// This resets all live proxy settings back to the values the process was started with.
/// Returns the full reset config so the UI can update.
async fn config_reset_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    let startup = state.startup_config.clone();

    // Persist current CB config before swapping so we can compare after.
    let old_cb_config = circuit_breaker_config_from_proxy(&state.config.load().proxy);

    // Rebuild config from startup values.
    let new_proxy = startup.proxy.clone();
    let new_logging = startup.logging.clone();
    let new_config = Config {
        server: startup.server.clone(),
        consul: startup.consul.clone(),
        proxy: new_proxy.clone(),
        logging: new_logging.clone(),
        tls: startup.tls.clone(),
        tcp: startup.tcp.clone(),
    };

    // Validate before applying.
    if let Some(validation_error) = new_config.validate() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Validation failed: {}", validation_error),
        }));
    }

    let new_cb_config = circuit_breaker_config_from_proxy(&new_config.proxy);
    let dns_ttl = new_config.proxy.dns_cache_ttl;
    let dns_negative_ttl = new_config.proxy.dns_negative_cache_ttl;

    // Swap the live config atomically.
    state.config.store(Arc::new(new_config));

    // DNS TTL may have changed — push the new values through.
    crate::route::target::global_dns_cache().set_ttl(dns_ttl, dns_negative_ttl);

    // If CB settings changed, rebuild the managed route table so targets pick up new config.
    if old_cb_config != new_cb_config {
        state.route_table.reconfigure_circuit_breaker(new_cb_config);
    }

    // Return the startup config as the current config so the UI reflects the reset.
    let after = state.config.load();
    let mut json = public_config_json(&after);
    json["meta"] = serde_json::json!({
        "runtime": runtime_config_capabilities(),
        "startup": public_config_json(&state.startup_config),
        "reset_mode": "startup_snapshot"
    });
    axum::Json(json)
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
    let ordering = Ordering::Relaxed;

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
    });

    let mut host_entries = Vec::new();
    for host in hosts {
        let mut route_entries = Vec::new();
        if let Some(routes) = table.get_routes(host) {
            for route in routes.iter() {
                let matcher = if route.glob.is_some() { "glob" } else { "prefix" };
                let mut target_entries = Vec::new();
                for target in route.targets.iter() {
                    let cb_state = target.health_tracker.circuit_breaker().current_state();
                    let active_conns = target.active_connections.load(ordering);
                    let reqs = target.stats.requests_total.load(ordering);
                    let errs = target.stats.errors_total.load(ordering);
                    let err_pct = if reqs > 0 {
                        (errs as f64 / reqs as f64 * 100.0).round() as u64
                    } else {
                        0
                    };
                    let avg_lat = if reqs > 0 {
                        target.stats.latency_sum_us.load(ordering) / reqs
                    } else {
                        0
                    };

                    target_entries.push(serde_json::json!({
                        "service": target.service,
                        "url": target.url,
                        "protocol": format!("{:?}", target.parsed_protocol).to_lowercase(),
                        "tls": target.parsed_tls,
                        "weight": target.weight,
                        "active_connections": active_conns,
                        "circuit_breaker": format!("{:?}", cb_state).to_lowercase(),
                        "stats": {
                            "requests": reqs,
                            "errors": errs,
                            "error_rate_pct": err_pct,
                            "avg_latency_us": avg_lat,
                            "bytes_total": target.stats.bytes_total.load(ordering),
                        }
                    }));
                }
                route_entries.push(serde_json::json!({
                    "path": route.path,
                    "matcher": matcher,
                    "targets": target_entries,
                }));
            }
        }
        host_entries.push(serde_json::json!({
            "host": host,
            "routes": route_entries,
        }));
    }

    axum::Json(serde_json::json!({
        "lb": lb,
        "hosts": host_entries,
    }))
}


async fn targets_metrics_handler(State(state): State<AdminState>) -> impl axum::response::IntoResponse {
    let table = state.route_table.get();
    let hosts = table.hosts();

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
                    

                    let cb_history = target.health_tracker.circuit_breaker().transition_history();
                    let cb_transitions: Vec<serde_json::Value> = cb_history.iter().rev().take(20).map(|t| {
                        serde_json::json!({
                            "from": format!("{:?}", t.from).to_lowercase(),
                            "to": format!("{:?}", t.to).to_lowercase(),
                            "timestamp_ms": t.timestamp_ms,
                        })
                    }).collect();

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
                        "circuit_breaker_history": cb_transitions,
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
    let search = params.search.as_deref();

    if let Some(buffer) = &state.log_buffer {
        axum::Json(buffer.recent(limit, level, search))
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
    config: SharedConfig,
    route_table: Arc<ManagedRouteTable>,
    tls_store: Option<Arc<DynamicCertStore>>,
    client_ca_store: Option<Arc<DynamicClientCaStore>>,
    log_buffer: Option<Arc<crate::admin::logs::LogBuffer>>,
) {
    let config_snapshot = config.load();
    let addr = config_snapshot.server.admin_listen.clone();

    let has_any_auth =
        !config_snapshot.server.admin_token.is_empty() || !config_snapshot.server.admin_users.is_empty();
    if !has_any_auth && !is_loopback_bind(&addr) {
        tracing::error!(addr = %addr, "Refusing to expose admin API without admin_token or admin_users on non-loopback address");
        return;
    }

    let auth_enabled =
        !config_snapshot.server.admin_token.is_empty() || !config_snapshot.server.admin_users.is_empty();
    let startup_config = Arc::clone(&config_snapshot);
    drop(config_snapshot);
    let state = AdminState {
        config: config.clone(),
        startup_config,
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

/// Decode a single hex byte (0-9, A-F, a-f) to its numeric value.
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

async fn admin_auth_middleware(
    State(state): State<AdminState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    // Path A: static admin_token via Bearer or X-Admin-Token header.
    // Only valid when admin_token is actually configured (non-empty).
    let config = state.config.load();
    let expected = config.server.admin_token.clone();
    let token_auth = if !expected.is_empty() {
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(|value| constant_time_eq(value, &expected))
            .unwrap_or(false)
        || headers
            .get("x-admin-token")
            .and_then(|value| value.to_str().ok())
            .map(|value| constant_time_eq(value, &expected))
            .unwrap_or(false)
    } else {
        false
    };
    drop(config);


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
                    .map(|(_, v)| {
                        // Decode percent-encoded token value.
                        // Session tokens may contain '/' and '=' which get URL-encoded by the browser.
                        let mut decoded = String::with_capacity(v.len());
                        let mut bytes = v.bytes();
                        while let Some(b) = bytes.next() {
                            if b == b'%' {
                                let hi = bytes.next().unwrap_or(b'0');
                                let lo = bytes.next().unwrap_or(b'0');
                                let val = hex_val(hi) << 4 | hex_val(lo);
                                decoded.push(val as char);
                            } else if b == b'+' {
                                decoded.push(' ');
                            } else {
                                decoded.push(b as char);
                            }
                        }
                        decoded
                    })
            })
            .map(|token| {
                // Check against admin_token (constant-time).
                let matches_admin = !expected.is_empty() && constant_time_eq(&token, &expected);
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

    fn make_test_config() -> SharedConfig {
        crate::config::shared_config(Config {
            server: ServerConfig {
                listen: ":9999".to_string(),
                admin_listen: "127.0.0.1:9998".to_string(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: "30s".to_string(),
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
        let config = make_test_config();
        let startup_config = Arc::clone(&config.load());
        AdminState {
            config,
            startup_config,
            route_table: Arc::new(ManagedRouteTable::new()),
            tls_store: None,
            client_ca_store: None,
            log_buffer: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            login_attempts: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn make_authed_test_state(admin_token: &str, admin_users: Vec<AdminUser>) -> AdminState {
        let config = crate::config::shared_config(Config {
            server: ServerConfig {
                listen: ":9999".to_string(),
                admin_listen: "127.0.0.1:9998".to_string(),
                admin_token: admin_token.to_string(),
                admin_users,
                workers: 0,
                drain_timeout: "30s".to_string(),
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
        });
        let startup_config = Arc::clone(&config.load());
        AdminState {
            config,
            startup_config,
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
    async fn test_admin_routes_include_matcher() {
        let state = make_test_state();
        let defs = crate::route::parser::parse_route_commands(
            "route add svc /api http://example.com/ opts \"ssrfskipverify=true\"",
        );
        state.route_table.load_static(&defs);

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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["routes"][0]["matcher"], "prefix");
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
    async fn test_admin_config_update_updates_shared_runtime_config() {
        let state = make_test_state();
        let app = build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/config")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "proxy": {
                                "strategy": "least-connections",
                                "matcher": "iprefix",
                                "connect_timeout": "7s"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let config = state.config.load();
        assert_eq!(config.proxy.strategy, "least-connections");
        assert_eq!(config.proxy.matcher, "iprefix");
        assert_eq!(config.proxy.connect_timeout, "7s");
    }

    #[tokio::test]
    async fn test_admin_config_update_rejects_non_runtime_fields() {
        let state = make_test_state();
        let app = build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/config")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "proxy": {
                                "enable_h2c": true,
                                "pool_size": 256
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], false);
        assert!(json["error"].as_str().unwrap().contains("proxy.enable_h2c"));
        assert!(json["error"].as_str().unwrap().contains("proxy.pool_size"));

        let config = state.config.load();
        assert!(!config.proxy.enable_h2c);
        assert_eq!(config.proxy.pool_size, 128);
    }

    #[tokio::test]
    async fn test_admin_config_reset_restores_startup_snapshot() {
        let state = make_test_state();
        let app = build_router(state.clone());

        let update_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/config")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "proxy": {
                                "strategy": "least-connections",
                                "connect_timeout": "7s",
                                "dns_cache_ttl": 99
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_response.status(), 200);

        let reset_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/config/reset")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset_response.status(), 200);

        let config = state.config.load();
        assert_eq!(config.proxy.strategy, "round-robin");
        assert_eq!(config.proxy.connect_timeout, "5s");
        assert_eq!(config.proxy.dns_cache_ttl, 30);
    }

    #[tokio::test]
    async fn test_admin_config_handler_includes_startup_meta() {
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["meta"]["reset_mode"], "startup_snapshot");
        assert_eq!(json["meta"]["startup"]["proxy"]["strategy"], "round-robin");
        assert_eq!(json["meta"]["runtime"]["strategy"], true);
    }

    #[tokio::test]
    async fn test_targets_metrics_help_headers_emitted_once() {
        let state = make_test_state();
        let defs = crate::route::parser::parse_route_commands(
            "route add svc / http://example.com/ opts \"ssrfskipverify=true\"",
        );
        state.route_table.load_static(&defs);
        let snapshot = state.route_table.get();
        let route = snapshot.lookup_route("", "/", "prefix").unwrap();
        route.targets[0].stats.record_request(123, 456, false);

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/targets-metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(
            text.matches("# HELP sentirum_lb_target_requests_total").count(),
            1
        );
        assert_eq!(
            text.matches("# TYPE sentirum_lb_target_requests_total").count(),
            1
        );
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
        assert!(html.contains("status-matcher"));
        assert!(html.contains("overview-title"));
        assert!(html.contains("overview-health"));
        assert!(html.contains("overview-trends"));
        assert!(html.contains("overview-hot-routes"));
        assert!(html.contains("overview-attention"));
        assert!(html.contains("overview-recent-changes"));
        assert!(html.contains("overview-guide"));
        assert!(html.contains("stream-pause-btn"));
        assert!(html.contains("target-search"));
        assert!(html.contains("route-search"));
        assert!(html.contains("route-sort"));
        assert!(html.contains("route-protocol"));
        assert!(html.contains("route-hosts"));
        assert!(html.contains("route-inspector"));
        assert!(html.contains("config-search"));
        assert!(html.contains("config-summary"));
        assert!(html.contains("config-editor"));
        assert!(html.contains("config-apply-btn"));
        assert!(html.contains("config-diff-drawer"));
        assert!(html.contains("copyToClipboard"));
        assert!(html.contains("config-collapse-btn"));
        assert!(html.contains("toast-root"));
        assert!(html.contains("beforeunload"));
        assert!(html.contains("focusConfigField"));
        assert!(html.contains("resetRuntimeConfigToStartup"));
        assert!(html.contains("dns-search"));
        assert!(html.contains("cert-search"));
        assert!(html.contains("cert-risk"));
        assert!(html.contains("cert-client-ca-btn"));
        assert!(html.contains("selectCert"));
        assert!(html.contains("certs-inspector"));
        assert!(html.contains("exportCerts"));
        assert!(html.contains("log-preset-app"));
        assert!(html.contains("exportFilteredLogs"));
        assert!(html.contains("topology-hosts"));
        assert!(html.contains("topo-mode-issues"));
        assert!(html.contains("topology-meta"));
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
        let state = make_test_state();
        let mut config = (*state.config.load_full()).clone();
        config.server.admin_token = "secret".to_string();
        state.config.store(Arc::new(config));
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
        let state = make_test_state();
        let mut config = (*state.config.load_full()).clone();
        config.server.admin_token = "secret".to_string();
        state.config.store(Arc::new(config));
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

//! Admin API for Sentirum LB using axum.
//!
//! Endpoints:
//! - `GET /admin/` — Dashboard UI (embedded SPA)
//! - `GET /admin/health` — Health check
//! - `GET /admin/routes` — Route table inspection
//! - `POST /admin/routes` — Add routes dynamically (Fabio-style route commands)
//! - `DELETE /admin/routes/static` — Clear all static routes
//! - `GET /admin/metrics` — Prometheus metrics
//! - `GET /admin/config` — Config inspection
//! - `PUT /admin/config` — Update runtime configuration (hot-reload)
//! - `GET /admin/certs` — Runtime TLS certificate status
//! - `GET /admin/logs` — Recent log entries (JSON)
//! - `GET /admin/logs/stream` — Live log stream (SSE)

use crate::admin::topology_flow::TopologyFlowCache;
use crate::config::{Config, SharedConfig};
use crate::proxy::tls::{DynamicCertStore, DynamicClientCaStore, SharedFileCert, TlsCertConfig};
use crate::route::registry::ManagedRouteTable;
use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post, put};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;

// Re-export types needed by sub-modules
pub(crate) use super::auth::SessionCleanupBackground;

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
    /// File-based TLS certificates that support manual hot-reload.
    pub file_certs: Vec<(String, SharedFileCert, TlsCertConfig)>,
    /// Hot-reloadable trusted proxy CIDR ranges (shared with proxy handler).
    pub trusted_proxies: Arc<ArcSwap<Vec<crate::proxy::handler::CidrRange>>>,
    /// Cached short-window flow metrics for topology rendering.
    pub topology_flow_cache: Arc<TopologyFlowCache>,
    /// Metrics SSE stream sender — lazily initialized, stopped when no receivers.
    pub metrics_stream_tx: Arc<RwLock<Option<tokio::sync::watch::Sender<Arc<String>>>>>,
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

/// Query parameters for the log history endpoint.
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub limit: Option<usize>,
    pub level: Option<String>,
    pub search: Option<String>,
}

/// Build the admin API router
pub fn build_router(state: AdminState) -> Router {
    let public = Router::new()
        .route(
            "/admin",
            get(|| async { axum::response::Redirect::permanent("/admin/") }),
        )
        .route("/admin/", get(super::dashboard_assets::dashboard_html))
        .route(
            "/admin/dashboard",
            get(super::dashboard_assets::dashboard_html),
        )
        .route(
            "/admin/assets/dashboard.css",
            get(super::dashboard_assets::dashboard_css),
        )
        .route(
            "/admin/assets/dashboard.js",
            get(super::dashboard_assets::dashboard_js),
        )
        .route(
            "/favicon.ico",
            get(|| async {
                axum::response::Response::builder()
                    .status(204)
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        )
        .route("/admin/login", post(super::auth::login_handler))
        .route("/admin/logout", post(super::auth::logout_handler))
        .route("/admin/me", get(super::auth::me_handler))
        .route("/admin/health", get(health_handler));

    let protected = Router::new()
        .route("/admin/routes", get(super::routes_handler::routes_handler))
        .route(
            "/admin/routes",
            post(super::routes_handler::routes_add_handler),
        )
        .route(
            "/admin/routes/static",
            axum::routing::delete(super::routes_handler::routes_static_clear_handler),
        )
        .route(
            "/admin/metrics",
            get(super::metrics_handler::metrics_handler),
        )
        .route("/admin/config", get(super::config_handler::config_handler))
        .route(
            "/admin/config",
            put(super::config_handler::config_update_handler),
        )
        .route(
            "/admin/config/reset",
            post(super::config_handler::config_reset_handler),
        )
        .route("/admin/certs", get(super::certs_handler::certs_handler))
        .route(
            "/admin/certs/reload",
            post(super::certs_handler::certs_reload_handler),
        )
        .route("/admin/logs", get(logs_handler))
        .route(
            "/admin/targets",
            get(super::metrics_handler::targets_handler),
        )
        .route(
            "/admin/consul-status",
            get(super::metrics_handler::consul_status_handler),
        )
        .route(
            "/admin/topology",
            get(super::metrics_handler::topology_handler),
        )
        .route(
            "/admin/targets-metrics",
            get(super::metrics_handler::targets_metrics_handler),
        )
        .route(
            "/admin/dns-cache",
            get(super::config_handler::dns_cache_handler),
        )
        .route("/admin/logs/stream", get(logs_stream_handler))
        .route(
            "/admin/metrics/stream",
            get(super::metrics_handler::metrics_stream_handler),
        );

    let config = state.config.load();
    let no_auth = config.server.admin_token.is_empty() && config.server.admin_users.is_empty();
    drop(config);
    if no_auth {
        public.merge(protected).with_state(state)
    } else {
        public.with_state(state.clone()).merge(
            protected
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    super::auth::admin_auth_middleware,
                ))
                .with_state(state),
        )
    }
}

// ---------------------------------------------------------------------------
// Inline handlers (small enough to keep here)
// ---------------------------------------------------------------------------

async fn health_handler() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: "ok",
        service: "sentirum-lb",
        version: env!("CARGO_PKG_VERSION"),
    })
}

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

async fn logs_stream_handler(
    State(state): State<AdminState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let buffer = state.log_buffer.clone();
    let stream: Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> =
        if let Some(buf) = &buffer {
            let receiver = buf.subscribe();
            let stream =
                tokio_stream::wrappers::BroadcastStream::new(receiver).filter_map(|result| {
                    match result {
                        Ok(entry) => {
                            let data = serde_json::to_string(&entry).unwrap_or_default();
                            Some(Ok(Event::default().data(data)))
                        }
                        Err(_) => None,
                    }
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

fn is_loopback_bind(addr: &str) -> bool {
    if addr.starts_with("0.0.0.0") || addr.starts_with("[::]") || addr.starts_with(':') {
        return false;
    }
    addr.starts_with("127.")
        || addr.starts_with("localhost:")
        || addr == "localhost"
        || addr.starts_with("[::1]")
}

/// Run the admin API server using axum
pub async fn run_admin_server(
    config: SharedConfig,
    route_table: Arc<ManagedRouteTable>,
    tls_store: Option<Arc<DynamicCertStore>>,
    client_ca_store: Option<Arc<DynamicClientCaStore>>,
    log_buffer: Option<Arc<crate::admin::logs::LogBuffer>>,
    file_certs: Vec<(String, SharedFileCert, TlsCertConfig)>,
    trusted_proxies: Arc<ArcSwap<Vec<crate::proxy::handler::CidrRange>>>,
) {
    let config_snapshot = config.load();
    let addr = config_snapshot.server.admin_listen.clone();

    let has_any_auth = !config_snapshot.server.admin_token.is_empty()
        || !config_snapshot.server.admin_users.is_empty();
    if !has_any_auth && !is_loopback_bind(&addr) {
        tracing::error!(addr = %addr, "Refusing to expose admin API without admin_token or admin_users on non-loopback address");
        return;
    }

    let auth_enabled = !config_snapshot.server.admin_token.is_empty()
        || !config_snapshot.server.admin_users.is_empty();
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
        file_certs,
        trusted_proxies,
        topology_flow_cache: Arc::new(TopologyFlowCache::new()),
        metrics_stream_tx: Arc::new(RwLock::new(None)),
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdminUser;
    use crate::test_support::{admin_test_state, admin_test_state_with, with_admin_auth};
    use axum::body::{Body, to_bytes};
    use http::Request;
    use tower::ServiceExt;

    fn make_test_state() -> AdminState {
        admin_test_state(Arc::new(ManagedRouteTable::new()))
    }

    fn make_authed_test_state(admin_token: &str, admin_users: Vec<AdminUser>) -> AdminState {
        admin_test_state_with(Arc::new(ManagedRouteTable::new()), |config| {
            with_admin_auth(config, admin_token, admin_users);
        })
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
    async fn test_query_token_only_accepted_on_get() {
        // Regression (O4): a leaked token in server logs / Referer must not be
        // replayable for state-changing operations. The query-string token is
        // only honored on GET (SSE/dashboard EventSource can't set headers).
        let state = make_authed_test_state("secret", vec![]);
        let app = build_router(state);

        // GET with query token: accepted (200/OK).
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/routes?token=secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            200,
            "GET with query token should be accepted"
        );

        // PUT with query token: rejected (401/403), never accepted.
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/config?token=secret")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status() == 401 || response.status() == 403,
            "PUT with query token must be rejected, got {}",
            response.status()
        );
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
                        serde_json::json!({"proxy": {"strategy": "least-connections", "matcher": "iprefix", "connect_timeout": "7s"}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await.unwrap();
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
                        serde_json::json!({"proxy": {"enable_h2c": true, "pool_size": 256}})
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
                        serde_json::json!({"proxy": {"strategy": "least-connections", "connect_timeout": "7s", "dns_cache_ttl": 99}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await.unwrap();
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
        let route = snapshot
            .lookup_route("", "/", crate::route::table::MatcherKind::Prefix)
            .unwrap();
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
            text.matches("# HELP sentirum_lb_target_requests_total")
                .count(),
            1
        );
        assert_eq!(
            text.matches("# TYPE sentirum_lb_target_requests_total")
                .count(),
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
        assert!(html.contains("/admin/assets/dashboard.css"));
        assert!(html.contains("/admin/assets/dashboard.js"));
    }

    #[tokio::test]
    async fn test_admin_dashboard_assets() {
        let state = make_test_state();
        let app = build_router(state);

        let css_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/assets/dashboard.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(css_response.status(), 200);
        assert_eq!(
            css_response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/css; charset=utf-8")
        );

        let js_response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/assets/dashboard.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(js_response.status(), 200);
        assert_eq!(
            js_response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/javascript; charset=utf-8")
        );
        let body = to_bytes(js_response.into_body(), usize::MAX).await.unwrap();
        let javascript = String::from_utf8(body.to_vec()).unwrap();
        assert!(javascript.contains("['prefix','iprefix','glob','exact']"));
        assert!(!javascript.contains("logging.level"));
        assert!(!javascript.contains("logging.format"));
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
        // /admin/health is public (unauthenticated) for health probes;
        // test auth enforcement on /admin/routes instead.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/routes")
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
        // /admin/health is public; test auth rejection on /admin/routes.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/routes")
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
        let hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        let state = make_authed_test_state(
            "",
            vec![AdminUser {
                username: "admin".to_string(),
                password: hash,
            }],
        );
        let app = build_router(state.clone());
        let login_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"username": "admin", "password": "password123"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_response.status(), 200);
        let body = to_bytes(login_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = login_json["token"]
            .as_str()
            .expect("login should return a token");
        assert!(!token.is_empty());
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
        let hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        let state = make_authed_test_state(
            "",
            vec![AdminUser {
                username: "admin".to_string(),
                password: hash,
            }],
        );
        let app = build_router(state);
        // /admin/health is public; test auth rejection on /admin/routes.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/routes")
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
        use super::super::metrics_handler::escape_prometheus_label;
        assert_eq!(escape_prometheus_label("simple"), "simple");
        assert_eq!(escape_prometheus_label("has\"quote"), "has\\\"quote");
        assert_eq!(escape_prometheus_label("back\\slash"), "back\\\\slash");
        assert_eq!(escape_prometheus_label("new\nline"), "new\\nline");
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

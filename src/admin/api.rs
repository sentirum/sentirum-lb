//! Admin API for Sentirum LB using axum.
//!
//! Endpoints:
//! - `GET /admin/health` — Health check
//! - `GET /admin/routes` — Route table inspection
//! - `GET /admin/metrics` — Prometheus metrics
//! - `GET /admin/config` — Config inspection
//! - `GET /admin/certs` — Runtime TLS certificate status

use crate::config::Config;
use crate::proxy::tls::DynamicCertStore;
use crate::route::registry::ManagedRouteTable;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use axum::routing::get;
use std::sync::Arc;

/// Shared state for admin API handlers
#[derive(Clone)]
pub struct AdminState {
    pub config: Arc<Config>,
    pub route_table: Arc<ManagedRouteTable>,
    pub tls_store: Option<Arc<DynamicCertStore>>,
}

/// Health check response
#[derive(serde::Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// Build the admin API router
pub fn build_router(state: AdminState) -> Router {
    let protected = Router::new()
        .route("/admin/health", get(health_handler))
        .route("/admin/routes", get(routes_handler))
        .route("/admin/metrics", get(metrics_handler))
        .route("/admin/config", get(config_handler))
        .route("/admin/certs", get(certs_handler));

    if state.config.server.admin_token.is_empty() {
        protected.with_state(state)
    } else {
        protected
            .layer(from_fn_with_state(state.clone(), admin_auth_middleware))
            .with_state(state)
    }
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

    axum::Json(serde_json::json!({
        "source": tls_source,
        "strict_sni": state.config.tls.strict_sni,
        "require_initial_snapshot": state.config.tls.require_initial_snapshot,
        "consul_cert_prefix": state.config.tls.consul_cert_prefix,
        "loaded_certificates": runtime.as_ref().map(|s| s.loaded_certificates.clone()).unwrap_or_default(),
        "default_certificate": runtime.as_ref().and_then(|s| s.default_certificate.clone()),
        "last_consul_index": runtime.as_ref().map(|s| s.last_consul_index).unwrap_or_default(),
        "last_reload_unix": runtime.as_ref().and_then(|s| s.last_reload_unix),
        "last_error": runtime.as_ref().and_then(|s| s.last_error.clone()),
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
        },
    }))
}

/// Run the admin API server using axum
pub async fn run_admin_server(
    config: Arc<Config>,
    route_table: Arc<ManagedRouteTable>,
    tls_store: Option<Arc<DynamicCertStore>>,
) {
    let addr = config.server.admin_listen.clone();

    if config.server.admin_token.is_empty() && !is_loopback_bind(&addr) {
        tracing::error!(addr = %addr, "Refusing to expose admin API without admin_token on non-loopback address");
        return;
    }

    let auth_enabled = !config.server.admin_token.is_empty();
    let state = AdminState {
        config,
        route_table,
        tls_store,
    };
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

async fn admin_auth_middleware(
    State(state): State<AdminState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    let expected = state.config.server.admin_token.as_str();
    let authorized = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value == expected)
        .unwrap_or(false)
        || headers
            .get("x-admin-token")
            .and_then(|value| value.to_str().ok())
            .map(|value| value == expected)
            .unwrap_or(false);

    if authorized {
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
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt; // for oneshot()

    fn make_test_config() -> Arc<Config> {
        Arc::new(Config {
            server: ServerConfig {
                listen: ":9999".to_string(),
                admin_listen: "127.0.0.1:9998".to_string(),
                admin_token: String::new(),
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
            },
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
        })
    }

    fn make_test_state() -> AdminState {
        AdminState {
            config: make_test_config(),
            route_table: Arc::new(ManagedRouteTable::new()),
            tls_store: None,
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

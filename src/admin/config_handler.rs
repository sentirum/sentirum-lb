//! Configuration inspection and hot-reload handlers.

use super::api::AdminState;
use crate::config::Config;
use axum::extract::{Json, State};
use serde::Deserialize;
use std::sync::Arc;

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
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default)]
    pub health_check_tls_skip_verify: Option<bool>,
}

#[derive(Deserialize)]
pub struct LoggingConfigUpdate {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}

pub(super) fn circuit_breaker_config_from_proxy(
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
    }
    unsupported
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
        "health_check": true,
        "rate_limit": true,
        "logging_level": true,
        "logging_format": true,
        "pool_size": false,
        "enable_h2c": false,
        "trusted_proxies": false,
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
            "health_check_path": config.proxy.health_check_path,
            "health_check_tls_skip_verify": config.proxy.health_check_tls_skip_verify,
        },
        "logging": {
            "level": config.logging.level.clone(),
            "format": config.logging.format.clone(),
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
        "tls_listeners": config.tls_listeners.iter().enumerate().map(|(i, tls)| {
            let source = match crate::proxy::tls::TlsMode::resolve(tls) {
                Ok(Some(crate::proxy::tls::TlsMode::File(_))) => "file",
                Ok(Some(crate::proxy::tls::TlsMode::ConsulKv(_))) => "consul_kv",
                Ok(None) => "disabled",
                Err(_) => "invalid",
            };
            serde_json::json!({
                "index": i,
                "listen": tls.listen.clone(),
                "source": source,
                "cert_path": tls.cert_path.clone(),
                "key_path": tls.key_path.clone(),
                "client_auth": tls.client_auth.clone(),
                "client_ca_source": tls.client_ca_source.clone(),
                "client_ca_path": tls.client_ca_path.clone(),
                "strict_sni": tls.strict_sni,
            })
        }).collect::<Vec<_>>(),
        "tcp": {
            "mode": config.tcp.mode.clone(),
            "listen": config.tcp.listen.clone(),
            "refresh": config.tcp.refresh.clone(),
        },
    })
}

pub(super) async fn config_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    let config = state.config.load();
    let mut json = public_config_json(&config);
    json["meta"] = serde_json::json!({
        "runtime": runtime_config_capabilities(),
        "startup": public_config_json(&state.startup_config),
        "reset_mode": "startup_snapshot"
    });
    axum::Json(json)
}

pub(super) async fn config_update_handler(
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
        if let Some(v) = &proxy.health_check_interval {
            new_proxy.health_check_interval = v.clone();
        }
        if let Some(v) = &proxy.health_check_timeout {
            new_proxy.health_check_timeout = v.clone();
        }
        if let Some(v) = proxy.health_check_fall {
            new_proxy.health_check_fall = v;
        }
        if let Some(v) = proxy.health_check_rise {
            new_proxy.health_check_rise = v;
        }
        if let Some(v) = &proxy.health_check_path {
            new_proxy.health_check_path = v.clone();
        }
        if let Some(v) = proxy.health_check_tls_skip_verify {
            new_proxy.health_check_tls_skip_verify = v;
        }
        if let Some(v) = proxy.rate_limit_per_target {
            new_proxy.rate_limit_per_target = v;
        }
        if let Some(v) = proxy.rate_limit_burst {
            new_proxy.rate_limit_burst = v;
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
        tls_listeners: current.tls_listeners.clone(),
        tcp: current.tcp.clone(),
        parsed_timeouts: Default::default(),
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
    // Apply DNS TTL *before* config store so that new requests immediately
    // see consistent DNS+proxy settings. If config.store fails (Arc::new can't
    // fail, but defensively), DNS TTL is still updated — this is acceptable
    // because set_ttl only performs an atomic swap + cache clear.
    crate::route::target::global_dns_cache().set_ttl(dns_ttl, dns_negative_ttl);
    state.config.store(Arc::new(temp_config));

    if old_cb_config != new_cb_config {
        state.route_table.reconfigure_circuit_breaker(new_cb_config);
    }

    axum::Json(serde_json::json!({
        "success": true,
        "message": "Configuration updated successfully",
        "runtime": runtime_config_capabilities()
    }))
}

pub(super) async fn config_reset_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    let startup = state.startup_config.clone();
    let old_cb_config = circuit_breaker_config_from_proxy(&state.config.load().proxy);

    let new_config = Config {
        server: startup.server.clone(),
        consul: startup.consul.clone(),
        proxy: startup.proxy.clone(),
        logging: startup.logging.clone(),
        tls: startup.tls.clone(),
        tls_listeners: startup.tls_listeners.clone(),
        tcp: startup.tcp.clone(),
        parsed_timeouts: Default::default(),
    };

    if let Some(validation_error) = new_config.validate() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Validation failed: {}", validation_error),
        }));
    }

    let new_cb_config = circuit_breaker_config_from_proxy(&new_config.proxy);
    let dns_ttl = new_config.proxy.dns_cache_ttl;
    let dns_negative_ttl = new_config.proxy.dns_negative_cache_ttl;

    // Apply DNS TTL *before* config store for consistency.
    crate::route::target::global_dns_cache().set_ttl(dns_ttl, dns_negative_ttl);
    state.config.store(Arc::new(new_config));

    if old_cb_config != new_cb_config {
        state.route_table.reconfigure_circuit_breaker(new_cb_config);
    }

    let after = state.config.load();
    let mut json = public_config_json(&after);
    json["meta"] = serde_json::json!({
        "runtime": runtime_config_capabilities(),
        "startup": public_config_json(&state.startup_config),
        "reset_mode": "startup_snapshot"
    });
    axum::Json(json)
}

pub(super) async fn dns_cache_handler() -> axum::Json<serde_json::Value> {
    let cache = crate::route::target::global_dns_cache();
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

use super::{AdminUser, LoggingConfig, ProxyConfig, TcpConfig, TlsConfig};

pub(super) fn default_admin_listen() -> String {
    "127.0.0.1:9998".to_string()
}

pub(super) fn default_admin_token() -> String {
    String::new()
}

pub(super) fn default_admin_users() -> Vec<AdminUser> {
    Vec::new()
}

pub(super) fn default_drain_timeout() -> String {
    "30s".to_string()
}

pub(super) fn default_consul_address() -> String {
    "127.0.0.1:8500".to_string()
}
pub(super) fn default_consul_scheme() -> String {
    "http".to_string()
}
pub(super) fn default_kv_prefix() -> String {
    "/sentirum-lb/routes".to_string()
}
pub(super) fn default_tag_prefix() -> String {
    "urlprefix-".to_string()
}
pub(super) fn default_poll_interval() -> String {
    "0s".to_string()
}
pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_dns_cache_ttl() -> u64 {
    30
}

pub(super) fn default_dns_negative_cache_ttl() -> u64 {
    10
}

pub(super) fn default_circuit_breaker_error_threshold() -> u8 {
    50
}

pub(super) fn default_circuit_breaker_window_size() -> usize {
    100
}

pub(super) fn default_circuit_breaker_recovery_timeout() -> u64 {
    30
}

pub(super) fn default_circuit_breaker_half_open_max() -> usize {
    3
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            strategy: default_strategy(),
            matcher: default_matcher(),
            request_id_header: default_request_id_header(),
            no_route_status: default_no_route_status(),
            connect_timeout: default_connect_timeout(),
            read_timeout: default_read_timeout(),
            write_timeout: default_write_timeout(),
            idle_timeout: default_idle_timeout(),
            enable_h2c: false,
            upstream_h2_max_streams: default_upstream_h2_max_streams(),
            upstream_h2_ping_interval: String::new(),
            pool_size: default_pool_size(),
            dns_cache_ttl: default_dns_cache_ttl(),
            dns_negative_cache_ttl: default_dns_negative_cache_ttl(),
            max_connections: default_max_connections(),
            trusted_proxies: Vec::new(),
            circuit_breaker_enabled: true,
            circuit_breaker_error_threshold: default_circuit_breaker_error_threshold(),
            circuit_breaker_window_size: default_circuit_breaker_window_size(),
            circuit_breaker_recovery_timeout: default_circuit_breaker_recovery_timeout(),
            circuit_breaker_half_open_max: default_circuit_breaker_half_open_max(),
            health_check_interval: default_health_check_interval(),
            health_check_timeout: default_health_check_timeout(),
            health_check_fall: default_health_check_fall(),
            health_check_rise: default_health_check_rise(),
            rate_limit_per_target: 0,
            rate_limit_burst: default_rate_limit_burst(),
            health_check_path: default_health_check_path(),
            health_check_tls_skip_verify: false,
            upstream_tcp_keepalive: default_upstream_tcp_keepalive(),
            upstream_user_timeout: default_upstream_user_timeout(),
            downstream_tcp_keepalive: default_downstream_tcp_keepalive(),
            stream_read_timeout: default_stream_read_timeout(),
        }
    }
}

/// Upstream pool keepalive: probe after 15s idle, re-probe every 5s, declare
/// dead after 3 misses (≈30s worst case). Detects silently-dead pooled
/// connections (Issue #22).
pub(super) fn default_upstream_tcp_keepalive() -> String {
    "15s,5s,3".to_string()
}

/// `TCP_USER_TIMEOUT` for upstream connections: a request written into a
/// black-holed connection fails within ~30s instead of waiting on read_timeout.
pub(super) fn default_upstream_user_timeout() -> String {
    "30s".to_string()
}

/// Downstream (CDN → LB) accepted-connection keepalive.
pub(super) fn default_downstream_tcp_keepalive() -> String {
    "15s,5s,3".to_string()
}

/// Streaming read timeout. Long-lived by default so WebSocket/SSE/long-poll
/// stay alive, while non-streaming requests use the shorter `read_timeout`.
pub(super) fn default_stream_read_timeout() -> String {
    "3600s".to_string()
}

pub(super) fn default_strategy() -> String {
    "round-robin".to_string()
}
pub(super) fn default_matcher() -> String {
    "prefix".to_string()
}
pub(super) fn default_request_id_header() -> String {
    "X-Request-ID".to_string()
}
pub(super) fn default_no_route_status() -> u16 {
    404
}
pub(super) fn default_connect_timeout() -> String {
    "5s".to_string()
}
pub(super) fn default_read_timeout() -> String {
    "30s".to_string()
}
pub(super) fn default_write_timeout() -> String {
    "30s".to_string()
}
pub(super) fn default_idle_timeout() -> String {
    "120s".to_string()
}
pub(super) fn default_upstream_h2_max_streams() -> usize {
    128
}
pub(super) fn default_pool_size() -> usize {
    128
}
pub(super) fn default_max_connections() -> usize {
    10000
}

pub(super) fn default_health_check_interval() -> String {
    "15s".to_string()
}

pub(super) fn default_health_check_timeout() -> String {
    "5s".to_string()
}

pub(super) fn default_health_check_fall() -> usize {
    3
}

pub(super) fn default_health_check_rise() -> usize {
    2
}

pub(super) fn default_rate_limit_burst() -> usize {
    100
}

pub(super) fn default_health_check_path() -> String {
    "/".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            mode: String::new(),
            listen: String::new(),
            refresh: default_tcp_refresh(),
        }
    }
}

pub(super) fn default_tcp_refresh() -> String {
    "5s".to_string()
}

pub(super) fn default_log_level() -> String {
    "info".to_string()
}
pub(super) fn default_log_format() -> String {
    "json".to_string()
}

pub(super) fn default_tls_consul_cert_prefix() -> String {
    "/fabio/cert".to_string()
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            source: String::new(),
            cert_path: String::new(),
            key_path: String::new(),
            listen: String::new(),
            consul_cert_prefix: default_tls_consul_cert_prefix(),
            strict_sni: false,
            require_initial_snapshot: false,
            client_auth: String::new(),
            client_ca_source: String::new(),
            client_ca_path: String::new(),
            client_ca_consul_prefix: String::new(),
            client_ca_upgrade_cn: String::new(),
            ocsp_stapling_enabled: false,
            http2: true,
        }
    }
}

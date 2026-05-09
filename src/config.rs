use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub consul: ConsulConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub tcp: TcpConfig,
}

/// Admin user for dashboard authentication
#[derive(Debug, Deserialize, Clone)]
pub struct AdminUser {
    pub username: String,
    pub password: String, // bcrypt hashed
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Proxy listen address (e.g. ":9999")
    pub listen: String,
    /// Admin API listen address (e.g. "127.0.0.1:9998")
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// Admin users (username/password pairs)
    #[serde(default = "default_admin_users")]
    pub admin_users: Vec<AdminUser>,
    /// Legacy: single admin token (for backwards compatibility)
    #[serde(default = "default_admin_token")]
    pub admin_token: String,
    /// Number of worker threads (0 = auto)
    #[serde(default)]
    pub workers: usize,
}

fn default_admin_listen() -> String {
    "127.0.0.1:9998".to_string()
}

fn default_admin_token() -> String {
    String::new()
}

fn default_admin_users() -> Vec<AdminUser> {
    Vec::new()
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConsulConfig {
    /// Consul agent address (e.g. "127.0.0.1:8500")
    #[serde(default = "default_consul_address")]
    pub address: String,
    /// HTTP scheme ("http" or "https")
    #[serde(default = "default_consul_scheme")]
    pub scheme: String,
    /// ACL token (optional)
    #[serde(default)]
    pub token: String,
    /// KV prefix for route commands
    #[serde(default = "default_kv_prefix")]
    pub kv_prefix: String,
    /// Service tag prefix (e.g. "urlprefix-")
    #[serde(default = "default_tag_prefix")]
    pub tag_prefix: String,
    /// Health poll interval. "0s" = use blocking queries
    #[serde(default = "default_poll_interval")]
    pub poll_interval: String,
    /// Enable Consul service discovery (health + catalog watch)
    #[serde(default = "default_true")]
    pub service_discovery: bool,
    /// Enable Consul KV route watching
    #[serde(default = "default_true")]
    pub kv_watching: bool,
    /// Only discover routes for these service names (empty = all).
    /// If non-empty, services not in this list are ignored.
    #[serde(default)]
    pub service_whitelist: Vec<String>,
    /// Never discover routes for these service names.
    /// Takes precedence over whitelist.
    #[serde(default)]
    pub service_blacklist: Vec<String>,
    /// Enable graceful shutdown (drain connections before exit).
    #[serde(default = "default_true")]
    pub graceful_shutdown: bool,

    /// Include services with "warning" health status in route discovery.
    /// When false (default), only fully "passing" services are included.
    /// When true, services with "warning" checks are also considered healthy.
    #[serde(default)]
    pub include_warning: bool,


}

fn default_consul_address() -> String {
    "127.0.0.1:8500".to_string()
}
fn default_consul_scheme() -> String {
    "http".to_string()
}
fn default_kv_prefix() -> String {
    "/sentirum-lb/routes".to_string()
}
fn default_tag_prefix() -> String {
    "urlprefix-".to_string()
}
fn default_poll_interval() -> String {
    "0s".to_string()
}
fn default_true() -> bool {
    true
}

fn default_dns_cache_ttl() -> u64 {
    30
}

fn default_dns_negative_cache_ttl() -> u64 {
    10
}

fn default_circuit_breaker_error_threshold() -> u8 {
    50
}

fn default_circuit_breaker_window_size() -> usize {
    100
}

fn default_circuit_breaker_recovery_timeout() -> u64 {
    30
}

fn default_circuit_breaker_half_open_max() -> usize {
    3
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    /// Load balancing strategy
    #[serde(default = "default_strategy")]
    pub strategy: String,
    /// Path matching strategy
    #[serde(default = "default_matcher")]
    pub matcher: String,
    /// Header name for request ID
    #[serde(default = "default_request_id_header")]
    pub request_id_header: String,
    /// HTTP status when no route matches
    #[serde(default = "default_no_route_status")]
    pub no_route_status: u16,
    /// Connect timeout
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: String,
    /// Read timeout
    #[serde(default = "default_read_timeout")]
    pub read_timeout: String,
    /// Write timeout
    #[serde(default = "default_write_timeout")]
    pub write_timeout: String,
    /// Idle timeout
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,
    /// Enable downstream cleartext HTTP/2 (h2c) on the plaintext listener.
    #[serde(default)]
    pub enable_h2c: bool,
    /// Max concurrent streams per upstream HTTP/2 connection.
    #[serde(default = "default_upstream_h2_max_streams")]
    pub upstream_h2_max_streams: usize,
    /// Optional upstream HTTP/2 ping interval for long-lived streams.
    #[serde(default)]
    pub upstream_h2_ping_interval: String,
    /// Upstream connection pool size per thread (Pingora default: 128)
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// DNS cache TTL in seconds (0 = disabled).
    #[serde(default = "default_dns_cache_ttl")]
    pub dns_cache_ttl: u64,
    /// DNS negative cache TTL in seconds.
    #[serde(default = "default_dns_negative_cache_ttl")]
    pub dns_negative_cache_ttl: u64,
    /// Max concurrent connections per upstream
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Trusted proxy CIDR ranges.
    /// When the peer IP is in this list, X-Forwarded-For and CF-Connecting-IP
    /// headers from the client are trusted. Otherwise they are overwritten.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Enable circuit breaker for upstream failure protection.
    #[serde(default)]
    pub circuit_breaker_enabled: bool,
    /// Error threshold percentage for circuit breaker (0-100).
    /// When this percentage of requests in the window fail, circuit opens.
    #[serde(default = "default_circuit_breaker_error_threshold")]
    pub circuit_breaker_error_threshold: u8,
    /// Number of requests to track in circuit breaker sliding window.
    #[serde(default = "default_circuit_breaker_window_size")]
    pub circuit_breaker_window_size: usize,
    /// Seconds to stay open before probing recovery.
    #[serde(default = "default_circuit_breaker_recovery_timeout")]
    pub circuit_breaker_recovery_timeout: u64,
    /// Max probe requests in half-open state.
    #[serde(default = "default_circuit_breaker_half_open_max")]
    pub circuit_breaker_half_open_max: usize,
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
        }
    }
}

fn default_strategy() -> String {
    "round-robin".to_string()
}
fn default_matcher() -> String {
    "prefix".to_string()
}
fn default_request_id_header() -> String {
    "X-Request-ID".to_string()
}
fn default_no_route_status() -> u16 {
    404
}
fn default_connect_timeout() -> String {
    "5s".to_string()
}
fn default_read_timeout() -> String {
    "30s".to_string()
}
fn default_write_timeout() -> String {
    "30s".to_string()
}
fn default_idle_timeout() -> String {
    "120s".to_string()
}
fn default_upstream_h2_max_streams() -> usize {
    128
}
fn default_pool_size() -> usize {
    128
}
fn default_max_connections() -> usize {
    10000
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format: json or text
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TcpConfig {
    /// Fabio-style TCP listener mode: "tcp", "tcp-dynamic", or empty/disabled.
    #[serde(default)]
    pub mode: String,
    /// Fixed TCP listener address when mode="tcp".
    #[serde(default)]
    pub listen: String,
    /// Poll interval for tcp-dynamic listener reconciliation.
    #[serde(default = "default_tcp_refresh")]
    pub refresh: String,
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

fn default_tcp_refresh() -> String {
    "5s".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    /// TLS source: "file" or "consul_kv". Empty keeps backwards-compatible auto-detection.
    #[serde(default)]
    pub source: String,
    /// Path to TLS certificate (PEM). Used when source=file.
    #[serde(default)]
    pub cert_path: String,
    /// Path to TLS private key (PEM). Used when source=file.
    #[serde(default)]
    pub key_path: String,
    /// TLS listen address (e.g. ":9443"). Empty = auto-derive from HTTP port +1
    #[serde(default)]
    pub listen: String,
    /// Consul KV prefix for Fabio-compatible bundled PEM certificates.
    /// Example: "/fabio/cert" with values like "/fabio/cert/example.com.pem".
    #[serde(default = "default_tls_consul_cert_prefix")]
    pub consul_cert_prefix: String,
    /// If true, only exact/wildcard SNI matches are served. If false, fallback to
    /// the first certificate in deterministic order when there is no match.
    #[serde(default)]
    pub strict_sni: bool,
    /// If true in consul_kv mode, startup fails unless the initial TLS snapshot
    /// yields at least one active certificate.
    #[serde(default)]
    pub require_initial_snapshot: bool,
    /// Downstream client certificate auth mode: "", "optional", or "required".
    #[serde(default)]
    pub client_auth: String,
    /// Client CA source: "file" or "consul_kv" when client_auth is enabled.
    #[serde(default)]
    pub client_ca_source: String,
    /// File or directory path containing trusted client CA PEM blocks.
    #[serde(default)]
    pub client_ca_path: String,
    /// Consul KV prefix containing trusted client CA PEM bundles.
    #[serde(default)]
    pub client_ca_consul_prefix: String,
    /// Fabio-compatible CA upgrade CN for self-signed/non-CA client auth certs.
    #[serde(default)]
    pub client_ca_upgrade_cn: String,
}

fn default_tls_consul_cert_prefix() -> String {
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
        }
    }
}

impl Config {
    pub fn parse_optional_duration(s: &str) -> Option<Duration> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        let result = if s.ends_with("ms") {
            s.trim_end_matches("ms")
                .parse::<u64>()
                .ok()
                .map(Duration::from_millis)
        } else if s.ends_with('s') {
            s.trim_end_matches('s')
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
        } else if s.ends_with('m') {
            s.trim_end_matches('m')
                .parse::<u64>()
                .ok()
                .map(|m| Duration::from_secs(m * 60))
        } else {
            None
        };

        result.or_else(|| {
            tracing::warn!(
                value = s,
                "Unrecognised duration format; ignoring optional duration"
            );
            None
        })
    }

    pub fn parse_duration(s: &str) -> Duration {
        let s = s.trim();
        Self::parse_optional_duration(s).unwrap_or_else(|| {
            if !s.is_empty() {
                tracing::warn!(value = s, "Unrecognised duration format; defaulting to 0s");
            }
            Duration::ZERO
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_optional_duration_accepts_empty_values() {
        assert_eq!(Config::parse_optional_duration(""), None);
        assert_eq!(Config::parse_optional_duration("   "), None);
    }

    #[test]
    fn parse_optional_duration_parses_supported_units() {
        assert_eq!(
            Config::parse_optional_duration("150ms"),
            Some(Duration::from_millis(150))
        );
        assert_eq!(
            Config::parse_optional_duration("5s"),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            Config::parse_optional_duration("2m"),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn proxy_config_defaults_long_lived_http2_fields() {
        let proxy = ProxyConfig::default();
        assert!(!proxy.enable_h2c);
        assert_eq!(proxy.upstream_h2_max_streams, 128);
        assert!(proxy.upstream_h2_ping_interval.is_empty());
    }

    #[test]
    fn tls_config_defaults_require_initial_snapshot_to_false() {
        let tls = TlsConfig::default();
        assert!(!tls.require_initial_snapshot);
        assert!(tls.client_auth.is_empty());
        assert!(tls.client_ca_source.is_empty());
        assert!(tls.client_ca_path.is_empty());
        assert!(tls.client_ca_consul_prefix.is_empty());
    }

    #[test]
    fn tcp_config_defaults_to_disabled_with_fabio_refresh() {
        let tcp = TcpConfig::default();
        assert!(tcp.mode.is_empty());
        assert!(tcp.listen.is_empty());
        assert_eq!(tcp.refresh, "5s");
    }
}

mod defaults;
mod parse;
mod validation;

#[cfg(test)]
mod tests;

pub use parse::ParsedProxyTimeouts;

use defaults::*;
use serde::Deserialize;
use std::sync::Arc;
#[cfg(test)]
pub(crate) use validation::validate_cidr;

pub type SharedConfig = Arc<arc_swap::ArcSwap<Config>>;

pub fn shared_config(config: Config) -> SharedConfig {
    Arc::new(arc_swap::ArcSwap::from_pointee(config))
}

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
    /// Additional TLS listeners. Each entry defines an independent TLS endpoint
    /// with its own certificate, listen address, and optional client auth.
    ///
    /// The legacy `[tls]` section is always listener 0 for backward compatibility.
    /// `[[tls_listeners]]` entries become listeners 1..N.
    #[serde(default)]
    pub tls_listeners: Vec<TlsConfig>,
    #[serde(default)]
    pub tcp: TcpConfig,
    /// Pre-parsed proxy timeouts (lazily computed on first access).
    /// Avoids re-parsing duration strings on every request.
    #[serde(skip)]
    pub parsed_timeouts: std::sync::OnceLock<ParsedProxyTimeouts>,
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
    /// Graceful connection drain timeout on shutdown.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout: String,
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
    #[serde(default = "default_true")]
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
    /// Health check interval (e.g., "15s"). 0 = disabled.
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: String,
    /// Health check timeout.
    #[serde(default = "default_health_check_timeout")]
    pub health_check_timeout: String,
    /// Consecutive failures to remove target from pool.
    #[serde(default = "default_health_check_fall")]
    pub health_check_fall: usize,
    /// Consecutive successes to add target back to pool.
    #[serde(default = "default_health_check_rise")]
    pub health_check_rise: usize,
    /// Rate limit per target (0 = unlimited).
    #[serde(default)]
    pub rate_limit_per_target: usize,
    /// Rate limit burst allowance.
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: usize,
    /// HTTP path for active health checks (default: "/").
    #[serde(default = "default_health_check_path")]
    pub health_check_path: String,
    /// Skip TLS certificate verification for HTTPS health check probes.
    /// **Warning:** Enabling this is insecure and should only be used for
    /// internal health checks where TLS verification is not possible.
    #[serde(default)]
    pub health_check_tls_skip_verify: bool,
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
    /// Enable OCSP stapling (default: false).
    /// When enabled, the stapler fetches and caches OCSP responses.
    /// Note: actual TLS stapling depends on Pingora exposing the SSL callback.
    #[serde(default)]
    pub ocsp_stapling_enabled: bool,
}

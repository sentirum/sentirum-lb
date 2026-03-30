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
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Proxy listen address (e.g. ":9999")
    pub listen: String,
    /// Admin API listen address (e.g. ":9998")
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// Number of worker threads (0 = auto)
    #[serde(default)]
    pub workers: usize,
}

fn default_admin_listen() -> String {
    ":9998".to_string()
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
    /// Upstream connection pool size per thread (Pingora default: 128)
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// Max concurrent connections per upstream
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
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
            pool_size: default_pool_size(),
            max_connections: default_max_connections(),
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

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[derive(Default)]
pub struct TlsConfig {
    /// Path to TLS certificate (PEM)
    pub cert_path: String,
    /// Path to TLS private key (PEM)
    pub key_path: String,
    /// TLS listen address (e.g. ":9443"). Empty = auto-derive from HTTP port +1
    #[serde(default)]
    pub listen: String,
}


impl Config {
    pub fn parse_duration(s: &str) -> Duration {
        let s = s.trim();
        if s.ends_with("ms") {
            let ms: u64 = s.trim_end_matches("ms").parse().unwrap_or(0);
            Duration::from_millis(ms)
        } else if s.ends_with('s') {
            let secs: u64 = s.trim_end_matches('s').parse().unwrap_or(0);
            Duration::from_secs(secs)
        } else if s.ends_with('m') {
            let mins: u64 = s.trim_end_matches('m').parse().unwrap_or(0);
            Duration::from_secs(mins * 60)
        } else {
            Duration::from_secs(0)
        }
    }
}

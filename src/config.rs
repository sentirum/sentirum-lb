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
    /// Admin API listen address (e.g. "127.0.0.1:9998")
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// Optional admin bearer/token auth secret
    #[serde(default)]
    pub admin_token: String,
    /// Number of worker threads (0 = auto)
    #[serde(default)]
    pub workers: usize,
}

fn default_admin_listen() -> String {
    "127.0.0.1:9998".to_string()
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
    /// Max concurrent connections per upstream
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Trusted proxy CIDR ranges.
    /// When the peer IP is in this list, X-Forwarded-For and CF-Connecting-IP
    /// headers from the client are trusted. Otherwise they are overwritten.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
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
            max_connections: default_max_connections(),
            trusted_proxies: Vec::new(),
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

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}

#[derive(Debug, Deserialize, Clone, Default)]
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
}

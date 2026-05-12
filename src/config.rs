use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

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
    /// Graceful connection drain timeout on shutdown.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout: String,
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

fn default_drain_timeout() -> String {
    "30s".to_string()
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

fn default_health_check_interval() -> String {
    "15s".to_string()
}

fn default_health_check_timeout() -> String {
    "5s".to_string()
}

fn default_health_check_fall() -> usize {
    3
}

fn default_health_check_rise() -> usize {
    2
}

fn default_rate_limit_burst() -> usize {
    100
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
        } else if s.ends_with('h') {
            s.trim_end_matches('h')
                .parse::<u64>()
                .ok()
                .map(|h| Duration::from_secs(h * 60 * 60))
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

    /// Validate configuration and return errors as a combined message.
    /// Returns None if valid, Some(String) with error description if invalid.
    pub fn validate(&self) -> Option<String> {
        let mut errors = Vec::new();

        validate_duration_field(&mut errors, "server.drain_timeout", &self.server.drain_timeout, false);
        validate_duration_field(&mut errors, "consul.poll_interval", &self.consul.poll_interval, true);
        validate_duration_field(&mut errors, "proxy.connect_timeout", &self.proxy.connect_timeout, true);
        validate_duration_field(&mut errors, "proxy.read_timeout", &self.proxy.read_timeout, true);
        validate_duration_field(&mut errors, "proxy.write_timeout", &self.proxy.write_timeout, true);
        validate_duration_field(&mut errors, "proxy.idle_timeout", &self.proxy.idle_timeout, true);
        if !self.proxy.upstream_h2_ping_interval.trim().is_empty() {
            validate_duration_field(
                &mut errors,
                "proxy.upstream_h2_ping_interval",
                &self.proxy.upstream_h2_ping_interval,
                true,
            );
        }
        validate_duration_field(&mut errors, "proxy.health_check_interval", &self.proxy.health_check_interval, true);
        validate_duration_field(&mut errors, "proxy.health_check_timeout", &self.proxy.health_check_timeout, true);
        validate_duration_field(&mut errors, "tcp.refresh", &self.tcp.refresh, true);

        // Validate circuit breaker threshold (0-100)
        if self.proxy.circuit_breaker_error_threshold > 100 {
            errors.push(format!(
                "circuit_breaker_error_threshold must be 0-100, got {}",
                self.proxy.circuit_breaker_error_threshold
            ));
        }

        // Validate circuit breaker window size
        if self.proxy.circuit_breaker_window_size == 0 {
            errors.push("circuit_breaker_window_size must be > 0".to_string());
        }

        // Validate circuit breaker recovery timeout
        if self.proxy.circuit_breaker_recovery_timeout == 0 {
            errors.push("circuit_breaker_recovery_timeout must be > 0".to_string());
        }

        // Validate circuit breaker half-open max
        if self.proxy.circuit_breaker_half_open_max == 0 {
            errors.push("circuit_breaker_half_open_max must be > 0".to_string());
        }

        // Validate DNS cache TTL
        if self.proxy.dns_cache_ttl > 3600 {
            errors.push(format!(
                "dns_cache_ttl should be <= 3600 (1 hour), got {} seconds",
                self.proxy.dns_cache_ttl
            ));
        }

        // Validate DNS negative cache TTL
        if self.proxy.dns_negative_cache_ttl > 300 {
            errors.push(format!(
                "dns_negative_cache_ttl should be <= 300 (5 min), got {} seconds",
                self.proxy.dns_negative_cache_ttl
            ));
        }

        // Validate trusted_proxies CIDR format
        for cidr in &self.proxy.trusted_proxies {
            if let Err(e) = validate_cidr(cidr) {
                errors.push(format!("Invalid CIDR '{}': {}", cidr, e));
            }
        }

        // Validate admin token length (security warning)
        if self.server.admin_token.len() > 0 && self.server.admin_token.len() < 16 {
            tracing::warn!(
                "admin_token is {} characters, recommend >= 16 for security",
                self.server.admin_token.len()
            );
        }

        // Validate TLS cert path when source=file
        if self.tls.source == "file" {
            if self.tls.cert_path.is_empty() {
                errors.push("tls.cert_path required when tls.source='file'".to_string());
            }
            if self.tls.key_path.is_empty() {
                errors.push("tls.key_path required when tls.source='file'".to_string());
            }
        }

        // Validate consul_cert_prefix format
        if !self.tls.consul_cert_prefix.is_empty() && !self.tls.consul_cert_prefix.starts_with('/') {
            errors.push("tls.consul_cert_prefix must start with '/'".to_string());
        }

        // Validate client_auth values
        if !self.tls.client_auth.is_empty()
            && self.tls.client_auth != "optional"
            && self.tls.client_auth != "required" {
            errors.push("tls.client_auth must be 'optional', 'required', or empty".to_string());
        }

        // Validate workers
        if self.server.workers > 256 {
            errors.push(format!(
                "workers should be <= 256, got {} (consider 0 for auto)",
                self.server.workers
            ));
        }

        // Validate upstream_h2_max_streams
        if self.proxy.upstream_h2_max_streams > 1000 {
            errors.push(format!(
                "upstream_h2_max_streams should be <= 1000, got {}",
                self.proxy.upstream_h2_max_streams
            ));
        }

        if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        }
    }
}

fn validate_duration_field(errors: &mut Vec<String>, name: &str, value: &str, allow_zero: bool) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        errors.push(format!("{name} must not be empty"));
        return;
    }

    match Config::parse_optional_duration(trimmed) {
        Some(duration) if allow_zero || !duration.is_zero() => {}
        Some(_) => errors.push(format!("{name} must be > 0, got {trimmed}")),
        None => errors.push(format!(
            "{name} has invalid duration '{trimmed}' (expected e.g. 150ms, 5s, 2m)"
        )),
    }
}

fn validate_cidr(cidr: &str) -> Result<(), String> {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return Err("empty CIDR".to_string());
    }

    let (ip, prefix_str) = cidr.split_once('/')
        .ok_or_else(|| format!("CIDR '{}' missing '/' separator", cidr))?;

    // Validate IP part
    ip.parse::<std::net::IpAddr>()
        .map_err(|e| format!("invalid IP '{}': {}", ip, e))?;

    // Validate prefix
    let prefix: u8 = prefix_str.parse()
        .map_err(|_| format!("prefix '{}' not a number", prefix_str))?;

    // Check prefix range for the IP family
    let ip_is_v4 = ip.contains('.') && !ip.contains(':');
    let max_prefix = if ip_is_v4 { 32 } else { 128 };

    if prefix > max_prefix {
        return Err(format!(
            "prefix {} > {} for {}",
            prefix, max_prefix, if ip_is_v4 { "IPv4" } else { "IPv6" }
        ));
    }

    Ok(())
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
        assert_eq!(
            Config::parse_optional_duration("1h"),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn validate_rejects_invalid_timeout_strings() {
        let mut config = Config {
            server: ServerConfig {
                listen: ":9999".to_string(),
                admin_listen: "127.0.0.1:9998".to_string(),
                admin_users: Vec::new(),
                admin_token: String::new(),
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
                service_discovery: true,
                kv_watching: true,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
            tcp: TcpConfig::default(),
        };
        config.proxy.connect_timeout = "abc".to_string();

        let error = config.validate().expect("invalid timeout should fail validation");
        assert!(error.contains("proxy.connect_timeout"));
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

    #[test]
    fn proxy_config_health_check_defaults() {
        let proxy = ProxyConfig::default();
        assert_eq!(proxy.health_check_interval, "15s");
        assert_eq!(proxy.health_check_timeout, "5s");
        assert_eq!(proxy.health_check_fall, 3);
        assert_eq!(proxy.health_check_rise, 2);
    }

    #[test]
    fn proxy_config_rate_limit_defaults() {
        let proxy = ProxyConfig::default();
        assert_eq!(proxy.rate_limit_per_target, 0);
        assert_eq!(proxy.rate_limit_burst, 100);
    }

    #[test]
    fn server_config_drain_timeout_default() {
        let toml_str = r#"
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = ""
admin_users = []
workers = 0
drain_timeout = "30s"
"#;
        let server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(server.drain_timeout, "30s");
    }

    #[test]
    fn validate_cidr_rejects_invalid() {
        // Empty CIDR
        assert!(validate_cidr("").is_err());
        // Missing prefix
        assert!(validate_cidr("192.168.1.1").is_err());
        // Invalid prefix
        assert!(validate_cidr("192.168.1.1/33").is_err());
        // Invalid IP
        assert!(validate_cidr("not.an.ip/24").is_err());
    }

    #[test]
    fn validate_cidr_accepts_valid() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("172.16.0.0/12").is_ok());
        assert!(validate_cidr("127.0.0.1/32").is_ok());
        assert!(validate_cidr("::1/128").is_ok());
        assert!(validate_cidr("2001:db8::/32").is_ok());
    }

    #[test]
    fn config_validate_rejects_invalid_settings() {
        // Use toml parsing or construct manually
        let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = ""
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []
"#
        .to_string();

        let mut config: Config = toml::from_str(&toml_str).unwrap();
        config.proxy.circuit_breaker_error_threshold = 150;  // > 100
        assert!(config.validate().is_some());

        let mut config: Config = toml::from_str(&toml_str).unwrap();
        config.proxy.circuit_breaker_window_size = 0;  // must be > 0
        assert!(config.validate().is_some());

        let mut config: Config = toml::from_str(&toml_str).unwrap();
        config.proxy.trusted_proxies = vec!["invalid-cidr".to_string()];
        assert!(config.validate().is_some());

        let mut config: Config = toml::from_str(&toml_str).unwrap();
        config.tls.source = "file".to_string();
        config.tls.cert_path = "".to_string();
        config.tls.key_path = "".to_string();
        assert!(config.validate().is_some());
    }

    #[test]
    fn config_validate_accepts_valid_settings() {
        let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = "averysecuretoken123456789"
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []
"#
        .to_string();

        let config: Config = toml::from_str(&toml_str).unwrap();
        assert!(config.validate().is_none());
    }
}

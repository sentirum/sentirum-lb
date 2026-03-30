use crate::route::definition::RouteSource;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A target backend for a route.
#[derive(Debug, Serialize, Deserialize)]
pub struct Target {
    /// Service name (e.g. "myservice")
    pub service: String,
    /// Target URL string (e.g. "http://10.0.0.1:8080/")
    pub url: String,
    /// Fixed weight for traffic distribution (0 = dynamic)
    #[serde(default)]
    pub fixed_weight: f64,
    /// Actual computed weight (percentage)
    #[serde(default)]
    pub weight: f64,
    /// Tags from Consul service
    #[serde(default)]
    pub tags: Vec<String>,
    /// Route options
    #[serde(default)]
    pub opts: HashMap<String, String>,
    /// Origin of the target definition
    #[serde(default)]
    pub source: RouteSource,

    // --- Pre-parsed fields (not serialized, computed from url) ---
    /// Pre-parsed host from URL
    #[serde(skip)]
    pub parsed_host: Option<String>,
    /// Pre-parsed port from URL
    #[serde(skip)]
    pub parsed_port: Option<u16>,
    /// Whether upstream uses TLS
    #[serde(skip)]
    pub parsed_tls: bool,
    /// Active connection count for least-connections picker
    #[serde(skip)]
    pub active_connections: std::sync::atomic::AtomicU64,
}

// Manual Clone impl because AtomicU64 doesn't impl Clone
impl Clone for Target {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            url: self.url.clone(),
            fixed_weight: self.fixed_weight,
            weight: self.weight,
            tags: self.tags.clone(),
            opts: self.opts.clone(),
            source: self.source.clone(),
            parsed_host: self.parsed_host.clone(),
            parsed_port: self.parsed_port,
            parsed_tls: self.parsed_tls,
            // Reset active connections on clone (fresh snapshot)
            active_connections: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for Target {
    fn default() -> Self {
        Self {
            service: String::new(),
            url: String::new(),
            fixed_weight: 0.0,
            weight: 0.0,
            tags: Vec::new(),
            opts: HashMap::new(),
            source: RouteSource::Static,
            parsed_host: None,
            parsed_port: None,
            parsed_tls: false,
            active_connections: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Target {
    /// Create a new target with URL auto-parsed.
    pub fn new(service: String, url: String) -> Self {
        let mut target = Self {
            service,
            url,
            ..Default::default()
        };
        target.pre_parse();
        target
    }

    /// Pre-parse the URL once to avoid per-request parsing.
    /// Also validates against SSRF risks (private/loopback IPs).
    pub fn pre_parse(&mut self) {
        if let Ok(parsed) = url::Url::parse(&self.url) {
            self.parsed_host = parsed.host_str().map(|h| h.to_string());
            self.parsed_port = parsed.port_or_known_default();
            self.parsed_tls = parsed.scheme() == "https";
        }
    }

    /// Check if the upstream host is safe for proxying.
    /// Consul-origin routes may use RFC1918/private IPs by default, but loopback,
    /// link-local, unspecified, and localhost-style hosts remain blocked unless
    /// explicitly bypassed.
    pub fn is_host_safe(&self) -> bool {
        let host = match self.parsed_host.as_deref() {
            Some(h) => h.trim_matches(&['[', ']'][..]),
            None => return false,
        };

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_ip_always_blocked(&ip) {
                return false;
            }
            if is_ip_rfc1918(&ip) {
                return self.source_allows_private_upstreams();
            }
            return true;
        }

        let lower = host.to_lowercase();
        if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
            return false;
        }

        true
    }

    /// Whether SSRF protection is explicitly bypassed for this target.
    pub fn ssrf_skip_verify(&self) -> bool {
        self.opts
            .get("ssrfskipverify")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    pub fn source_allows_private_upstreams(&self) -> bool {
        matches!(self.source, RouteSource::ConsulKv | RouteSource::ConsulService)
    }

    /// Get the upstream host (pre-parsed, no allocation)
    pub fn upstream_host(&self) -> &str {
        self.parsed_host
            .as_deref()
            .map(|h| h.trim_matches(&['[', ']'][..]))
            .unwrap_or("127.0.0.1")
    }

    /// Get the upstream port (pre-parsed)
    pub fn upstream_port(&self) -> u16 {
        self.parsed_port.unwrap_or(80)
    }

    /// Whether upstream uses TLS
    pub fn upstream_tls(&self) -> bool {
        self.parsed_tls
    }

    /// Get the strip path option.
    pub fn strip_path(&self) -> Option<&str> {
        self.opts.get("strip").map(|s| s.as_str())
    }

    /// Get the prepend path option.
    pub fn prepend_path(&self) -> Option<&str> {
        self.opts.get("prepend").map(|s| s.as_str())
    }

    /// Whether to skip TLS verification for upstream.
    pub fn tls_skip_verify(&self) -> bool {
        self.opts
            .get("tlsskipverify")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    /// Whether this is a TCP proxy target.
    pub fn is_tcp(&self) -> bool {
        self.opts.get("proto").map(|v| v == "tcp").unwrap_or(false)
    }

    /// Whether this is an HTTPS upstream target.
    pub fn is_https(&self) -> bool {
        self.parsed_tls
            || self.opts.get("proto").map(|v| v == "https").unwrap_or(false)
    }

    /// Get the host header override.
    pub fn host_override(&self) -> Option<&str> {
        self.opts.get("host").map(|s| s.as_str())
    }
}

/// Check if an IP address is private/reserved and should be blocked for SSRF protection.
pub fn is_ip_private(ip: &std::net::IpAddr) -> bool {
    is_ip_always_blocked(ip) || is_ip_rfc1918(ip)
}

pub fn is_ip_rfc1918(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => is_ipv6_unique_local(v6),
    }
}

pub fn is_ip_always_blocked(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local(),
    }
}

fn is_ipv6_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_blocks_private_ips() {
        let t = Target::new("svc".into(), "http://10.0.0.1:8080/".into());
        assert!(!t.is_host_safe()); // RFC1918

        let t = Target::new("svc".into(), "http://192.168.1.1:8080/".into());
        assert!(!t.is_host_safe()); // RFC1918

        let t = Target::new("svc".into(), "http://172.16.0.1:8080/".into());
        assert!(!t.is_host_safe()); // RFC1918

        let t = Target::new("svc".into(), "http://127.0.0.1:8080/".into());
        assert!(!t.is_host_safe()); // Loopback

        let t = Target::new("svc".into(), "http://169.254.169.254:80/".into());
        assert!(!t.is_host_safe()); // Cloud metadata
    }

    #[test]
    fn test_ssrf_allows_public_ips() {
        let t = Target::new("svc".into(), "http://8.8.8.8:80/".into());
        assert!(t.is_host_safe());

        let t = Target::new("svc".into(), "http://1.2.3.4:80/".into());
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_ssrf_blocks_localhost_hostname() {
        let t = Target::new("svc".into(), "http://localhost:8080/".into());
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_ssrf_allows_normal_hostnames() {
        let t = Target::new("svc".into(), "http://api.example.com/".into());
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_consul_sources_allow_private_rfc1918_hosts() {
        let mut t = Target::new("svc".into(), "http://10.0.0.1:8080/".into());
        t.source = RouteSource::ConsulService;
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_consul_sources_still_block_loopback_hosts() {
        let mut t = Target::new("svc".into(), "http://127.0.0.1:8080/".into());
        t.source = RouteSource::ConsulService;
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_static_sources_block_ipv6_unique_local_hosts() {
        let t = Target::new("svc".into(), "http://[fd00::1]:8080/".into());
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_consul_sources_allow_ipv6_unique_local_hosts() {
        let mut t = Target::new("svc".into(), "http://[fd00::1]:8080/".into());
        t.source = RouteSource::ConsulService;
        assert!(t.is_host_safe());
    }

    #[test]
    fn test_ipv6_link_local_hosts_are_blocked() {
        let t = Target::new("svc".into(), "http://[fe80::1]:8080/".into());
        assert!(!t.is_host_safe());
    }

    #[test]
    fn test_ssrf_skip_verify_opt() {
        let mut t = Target::new("svc".into(), "http://10.0.0.1:8080/".into());
        t.opts.insert("ssrfskipverify".to_string(), "true".to_string());
        assert!(t.ssrf_skip_verify());
    }
}

//! Target backend model with SSRF protection and DNS resolution.

use pingora::protocols::tls::ALPN;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::route::definition::RouteSource;

// Re-export types that live in their own modules but are widely used.
pub use crate::route::circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitState, CircuitTransition, monotonic_elapsed_ms,
};
pub use crate::route::dns_cache::{DnsCache, DnsCacheEntryView, DnsCacheStats, global_dns_cache};
pub use crate::route::health_tracker::TargetHealthTracker;
pub use crate::route::target_stats::{TargetStats, TargetStatsRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UpstreamProtocol {
    #[default]
    Http,
    Https,
    Grpc,
    Grpcs,
    Ws,
    Wss,
    Tcp,
}

impl UpstreamProtocol {
    pub(crate) fn from_scheme_or_proto(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "grpc" => Some(Self::Grpc),
            "grpcs" => Some(Self::Grpcs),
            "ws" => Some(Self::Ws),
            "wss" => Some(Self::Wss),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }

    pub fn uses_tls(self) -> bool {
        matches!(self, Self::Https | Self::Grpcs | Self::Wss)
    }

    pub fn requires_http2(self) -> bool {
        matches!(self, Self::Grpc | Self::Grpcs)
    }

    pub fn is_websocket(self) -> bool {
        matches!(self, Self::Ws | Self::Wss)
    }

    pub fn default_port(self) -> Option<u16> {
        match self {
            Self::Http | Self::Ws => Some(80),
            Self::Https | Self::Wss => Some(443),
            Self::Grpc => Some(80),
            Self::Grpcs => Some(443),
            Self::Tcp => None,
        }
    }

    pub fn preferred_alpn(self) -> ALPN {
        if self.requires_http2() {
            ALPN::H2
        } else if self.is_websocket() {
            ALPN::H1
        } else {
            ALPN::H2H1
        }
    }
}

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
    /// Parsed upstream transport protocol
    #[serde(skip)]
    pub parsed_protocol: UpstreamProtocol,
    /// Active connection count for least-connections picker
    #[serde(skip)]
    pub active_connections: Arc<AtomicU64>,
    /// Circuit breaker for upstream failure protection
    #[serde(skip)]
    pub health_tracker: Arc<TargetHealthTracker>,
    #[serde(skip)]
    pub stats: Arc<TargetStats>,
    /// Per-target token bucket rate limiter
    #[serde(skip)]
    pub rate_limiter: Arc<crate::proxy::ratelimit::TokenBucket>,
}

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
            parsed_protocol: self.parsed_protocol,
            active_connections: Arc::clone(&self.active_connections),
            health_tracker: Arc::clone(&self.health_tracker),
            stats: Arc::clone(&self.stats),
            rate_limiter: Arc::clone(&self.rate_limiter),
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
            parsed_protocol: UpstreamProtocol::Http,
            active_connections: Arc::new(AtomicU64::new(0)),
            health_tracker: Arc::new(TargetHealthTracker::new()),
            stats: Arc::new(TargetStats::default()),
            rate_limiter: Arc::new(crate::proxy::ratelimit::TokenBucket::new()),
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

    pub fn with_active_connections(
        service: String,
        url: String,
        active_connections: Arc<AtomicU64>,
    ) -> Self {
        let mut target = Self {
            service,
            url,
            active_connections,
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
            self.parsed_protocol = self
                .opts
                .get("proto")
                .and_then(|proto| UpstreamProtocol::from_scheme_or_proto(proto))
                .or_else(|| UpstreamProtocol::from_scheme_or_proto(parsed.scheme()))
                .unwrap_or(UpstreamProtocol::Http);
            self.parsed_port = parsed
                .port()
                .or_else(|| self.parsed_protocol.default_port())
                .or_else(|| parsed.port_or_known_default());
            self.parsed_tls = self.parsed_protocol.uses_tls();
        }

        // Configure per-target rate limiter from route opts
        if let Some(rate_str) = self.opts.get("ratelimit")
            && let Ok(rate) = rate_str.parse::<u64>() {
                let burst = self
                    .opts
                    .get("burst")
                    .and_then(|b| b.parse::<u64>().ok())
                    .unwrap_or(rate);
                self.rate_limiter.configure(rate, burst);
            }
    }

    /// Check if the upstream host is safe for proxying.
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
        matches!(
            self.source,
            RouteSource::ConsulKv | RouteSource::ConsulService
        )
    }

    pub fn try_acquire_connection_slot(&self, max_connections: u64) -> bool {
        if max_connections == 0 {
            self.active_connections.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        let mut current = self.active_connections.load(Ordering::Relaxed);
        loop {
            if current >= max_connections {
                return false;
            }
            match self.active_connections.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn release_connection_slot(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Try to acquire a rate limit token. Returns `true` if allowed.
    pub fn try_acquire_rate_limit(&self, global_rate: usize, global_burst: usize) -> bool {
        if self.rate_limiter.is_configured() {
            return self.rate_limiter.try_acquire();
        }

        if global_rate == 0 {
            return true;
        }

        self.rate_limiter.configure(global_rate as u64, global_burst as u64);
        self.rate_limiter.try_acquire()
    }

    pub async fn resolve_upstream_addr(&self) -> Result<SocketAddr, std::io::Error> {
        if !self.is_host_safe() && !self.ssrf_skip_verify() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "blocked private/reserved upstream target {}",
                    self.upstream_host()
                ),
            ));
        }

        let host = self.upstream_host();
        let port = self.upstream_port();
        let cache_key = format!("{host}:{port}");

        let cache = global_dns_cache();
        if let Some(addrs) = cache.lookup(&cache_key)
            && let Some(addr) = addrs.first()
        {
            tracing::trace!(host, port, "DNS cache hit");
            if !self.ssrf_skip_verify()
                && (is_ip_always_blocked(&addr.ip())
                    || (!self.source_allows_private_upstreams() && is_ip_rfc1918(&addr.ip())))
            {
                cache.remove(&cache_key);
                tracing::warn!(host, port, addr = %addr, "DNS cache hit failed SSRF check, re-resolving");
            } else {
                return Ok(*addr);
            }
        }

        let addr_str = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };

        let mut addrs = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    cache.store_negative(cache_key.clone());
                    tracing::warn!(host, port, error = %e, "DNS lookup failed (NXDOMAIN), storing negative result");
                } else {
                    tracing::warn!(host, port, error = %e, "DNS lookup failed (not cached)");
                }
                return Err(e);
            }
        };

        let resolved = addrs.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no upstream IP addresses found for {host}:{port}"),
            )
        })?;

        if !self.ssrf_skip_verify()
            && (is_ip_always_blocked(&resolved.ip())
                || (!self.source_allows_private_upstreams() && is_ip_rfc1918(&resolved.ip())))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "blocked upstream target during resolution {} -> {}",
                    host,
                    resolved.ip()
                ),
            ));
        }

        let mut addr_list = vec![resolved];
        for addr in addrs {
            if !self.ssrf_skip_verify()
                && (is_ip_always_blocked(&addr.ip())
                    || (!self.source_allows_private_upstreams() && is_ip_rfc1918(&addr.ip())))
            {
                tracing::debug!(
                    host,
                    addr = %addr,
                    "Filtered blocked IP from DNS multi-record response"
                );
                continue;
            }
            addr_list.push(addr);
        }
        cache.store(cache_key, addr_list);

        Ok(resolved)
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
        self.parsed_port
            .or_else(|| self.parsed_protocol.default_port())
            .unwrap_or(80)
    }

    /// Whether upstream uses TLS
    pub fn upstream_tls(&self) -> bool {
        self.parsed_tls
    }

    pub fn upstream_protocol(&self) -> UpstreamProtocol {
        self.parsed_protocol
    }

    pub fn requires_http2(&self) -> bool {
        self.parsed_protocol.requires_http2()
    }

    pub fn preferred_alpn(&self) -> ALPN {
        self.parsed_protocol.preferred_alpn()
    }

    pub fn is_websocket(&self) -> bool {
        self.parsed_protocol.is_websocket()
    }

    pub fn strip_path(&self) -> Option<&str> {
        self.opts.get("strip").map(|s| s.as_str())
    }

    pub fn prepend_path(&self) -> Option<&str> {
        self.opts.get("prepend").map(|s| s.as_str())
    }

    pub fn tls_skip_verify(&self) -> bool {
        self.opts
            .get("tlsskipverify")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    /// Parse header match constraints from opts.
    /// Format: `header=x-version:v2` or `header=x-version:v2,x-env:prod`
    pub fn header_matches(&self) -> Vec<(&str, &str)> {
        self.opts
            .iter()
            .filter(|(k, _)| *k == "header")
            .flat_map(|(_, v)| {
                v.split(',')
                    .filter_map(|pair| {
                        let trimmed = pair.trim();
                        trimmed.split_once(':').map(|(k, v)| (k, v))
                    })
            })
            .collect()
    }

    /// Check if this target's header constraints are satisfied by the given request headers.
    pub fn matches_headers(&self, headers: &http::HeaderMap) -> bool {
        let constraints = self.header_matches();
        if constraints.is_empty() {
            return true;
        }
        constraints.iter().all(|(name, expected)| {
            headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == *expected)
        })
    }

    pub fn is_tcp(&self) -> bool {
        self.parsed_protocol == UpstreamProtocol::Tcp
    }

    pub fn proxy_proto(&self) -> bool {
        self.opts
            .get("pxyproto")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    pub fn is_https(&self) -> bool {
        self.parsed_protocol == UpstreamProtocol::Https
    }

    pub fn is_grpc(&self) -> bool {
        matches!(
            self.parsed_protocol,
            UpstreamProtocol::Grpc | UpstreamProtocol::Grpcs
        )
    }

    pub fn host_override(&self) -> Option<&str> {
        self.opts.get("host").map(|s| s.as_str())
    }

    pub fn upstream_authority(&self) -> String {
        if let Some(host) = self.host_override() {
            return host.to_string();
        }

        let host = self.upstream_host();
        let port = self.upstream_port();
        match self.parsed_protocol.default_port() {
            Some(default_port) if default_port == port => host.to_string(),
            _ => format!("{host}:{port}"),
        }
    }
}

// ============================================================================
// SSRF protection helpers
// ============================================================================

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
            if v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                return true;
            }
            let octets = v4.octets();
            let is_cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 0x40;
            let is_documentation = (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19));
            is_cgnat || is_documentation
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
        }
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
        assert!(!t.is_host_safe());
        let t = Target::new("svc".into(), "http://192.168.1.1:8080/".into());
        assert!(!t.is_host_safe());
        let t = Target::new("svc".into(), "http://172.16.0.1:8080/".into());
        assert!(!t.is_host_safe());
        let t = Target::new("svc".into(), "http://127.0.0.1:8080/".into());
        assert!(!t.is_host_safe());
        let t = Target::new("svc".into(), "http://169.254.169.254:80/".into());
        assert!(!t.is_host_safe());
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

    #[test]
    fn test_proxy_proto_opt() {
        let mut t = Target::new("svc".into(), "tcp://10.0.0.1:4222".into());
        assert!(!t.proxy_proto());
        t.opts.insert("pxyproto".to_string(), "true".to_string());
        assert!(t.proxy_proto());
    }

    #[test]
    fn test_grpcs_targets_use_tls_and_require_http2() {
        let t = Target::new("svc".into(), "grpcs://api.example.com/".into());
        assert!(t.upstream_tls());
        assert!(t.requires_http2());
        assert!(t.is_grpc());
        assert_eq!(t.upstream_port(), 443);
    }

    #[test]
    fn test_wss_targets_use_tls_without_requiring_http2() {
        let t = Target::new("svc".into(), "wss://api.example.com/socket".into());
        assert!(t.upstream_tls());
        assert!(t.is_websocket());
        assert!(!t.requires_http2());
        assert_eq!(t.upstream_port(), 443);
    }

    #[test]
    fn test_proto_option_overrides_url_scheme_for_grpc() {
        let mut t = Target::new("svc".into(), "http://api.example.com/service".into());
        t.opts.insert("proto".into(), "grpc".into());
        t.pre_parse();
        assert_eq!(t.upstream_protocol(), UpstreamProtocol::Grpc);
        assert!(t.requires_http2());
        assert!(!t.upstream_tls());
    }

    #[test]
    fn test_websocket_targets_force_h1_alpn() {
        let t = Target::new("svc".into(), "wss://api.example.com/socket".into());
        assert_eq!(t.preferred_alpn().get_max_http_version(), 1);
        assert_eq!(t.preferred_alpn().get_min_http_version(), 1);
    }

    // SSRF IP range tests
    #[test]
    fn test_ssrf_blocks_multicast_ipv4() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(239, 255, 255, 255));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_multicast_ipv6() {
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_cgnat() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 127, 255, 255));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_allows_100_not_in_cgnat() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 0, 0, 1));
        assert!(!is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 128, 0, 1));
        assert!(!is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_documentation_ranges() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        assert!(is_ip_always_blocked(&ip));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_benchmark_range() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    #[test]
    fn test_ssrf_blocks_benchmark_range_upper() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 19, 255, 1));
        assert!(is_ip_always_blocked(&ip));
    }

    // Header-based routing tests
    #[test]
    fn test_header_matches_no_constraints() {
        let mut t = Target::default();
        t.opts = HashMap::new();
        let headers = http::HeaderMap::new();
        assert!(t.matches_headers(&headers));
    }

    #[test]
    fn test_header_matches_single_constraint() {
        let mut t = Target::default();
        t.opts = HashMap::from([("header".to_string(), "x-version:v2".to_string())]);

        let mut headers = http::HeaderMap::new();
        assert!(!t.matches_headers(&headers));
        headers.insert("x-version", http::HeaderValue::from_static("v1"));
        assert!(!t.matches_headers(&headers));
        headers.insert("x-version", http::HeaderValue::from_static("v2"));
        assert!(t.matches_headers(&headers));
    }

    #[test]
    fn test_header_matches_multiple_constraints() {
        let mut t = Target::default();
        t.opts = HashMap::from([("header".to_string(), "x-version:v2,x-env:prod".to_string())]);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-version", http::HeaderValue::from_static("v2"));
        assert!(!t.matches_headers(&headers));
        headers.insert("x-env", http::HeaderValue::from_static("prod"));
        assert!(t.matches_headers(&headers));
        headers.insert("x-env", http::HeaderValue::from_static("staging"));
        assert!(!t.matches_headers(&headers));
    }

    #[test]
    fn test_header_matches_case_insensitive_name() {
        let mut t = Target::default();
        t.opts = HashMap::from([("header".to_string(), "X-Version:v2".to_string())]);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-version", http::HeaderValue::from_static("v2"));
        assert!(t.matches_headers(&headers));
    }

    #[test]
    fn test_header_matches_separate_opts() {
        let mut t = Target::default();
        t.opts = HashMap::new();
        t.opts.insert("header".to_string(), "x-version:v2,x-env:prod".to_string());

        let mut headers = http::HeaderMap::new();
        headers.insert("x-version", http::HeaderValue::from_static("v2"));
        headers.insert("x-env", http::HeaderValue::from_static("prod"));
        assert!(t.matches_headers(&headers));
    }

    #[test]
    fn test_header_matches_empty_value() {
        let mut t = Target::default();
        t.opts = HashMap::from([("header".to_string(), "x-debug:".to_string())]);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-debug", http::HeaderValue::from_bytes(b"").unwrap());
        assert!(t.matches_headers(&headers));
    }
}

#[cfg(test)]
use crate::config::Config;
use crate::config::SharedConfig;
use crate::route::registry::ManagedRouteTable;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::modules::http::{
    HttpModules,
    grpc_web::{GrpcWeb, GrpcWebBridge},
};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
#[cfg(test)]
use pingora::tls::hash::MessageDigest;
use pingora::upstreams::peer::HttpPeer;
use std::net::IpAddr;
use std::sync::Arc;

mod access;
mod client_cert;
mod forwarded;
mod protocol;
mod rewrite;
mod upstream;

use access::*;
#[doc(hidden)]
pub use access::{client_ip_from_socket_addr, request_id_header_value};
pub(crate) use client_cert::remember_verified_client_certificate;
use client_cert::*;
use forwarded::*;
use protocol::*;
use rewrite::*;

/// Parsed CIDR for trusted proxy matching
#[derive(Debug, Clone)]
pub struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip_str, prefix_str) = s.split_once('/')?;
        let network: IpAddr = ip_str.trim().parse().ok()?;
        let prefix_len: u8 = prefix_str.trim().parse().ok()?;
        // Validate prefix length for the address family
        match network {
            IpAddr::V4(_) if prefix_len > 32 => return None,
            IpAddr::V6(_) if prefix_len > 128 => return None,
            _ => {}
        }
        Some(Self {
            network,
            prefix_len,
        })
    }

    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 32 {
                    return net == *ip;
                }
                let mask = u32::MAX << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 128 {
                    return net == *ip;
                }
                let net_bits = u128::from(net);
                let ip_bits = u128::from(*ip);
                let mask = u128::MAX << (128 - self.prefix_len);
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false,
        }
    }
}

/// Check if an IP is in any of the trusted proxy ranges
fn is_trusted_proxy(ip_str: &str, trusted: &[CidrRange]) -> bool {
    if trusted.is_empty() {
        return false;
    }
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    trusted.iter().any(|cidr| cidr.contains(&ip))
}

/// Request context — stores picked target to avoid double lookup
pub struct ProxyCtx {
    /// The target picked during upstream_peer (Arc for zero-copy sharing)
    /// Used in upstream_request_filter for path rewriting
    pub picked_target: Option<std::sync::Arc<crate::route::target::Target>>,
    /// Response status code (set in response_filter for access logging)
    pub response_status: u16,
    /// Request start time (for latency tracking)
    pub request_start: Option<std::time::Instant>,
    /// Whether downstream request is gRPC or gRPC-Web.
    pub is_grpc: bool,
    /// Whether downstream request is gRPC-Web.
    pub is_grpc_web: bool,
    /// Whether downstream request is a WebSocket upgrade.
    pub is_websocket: bool,
    /// Whether downstream request is a Server-Sent Events stream
    /// (`Accept: text/event-stream`). Used to apply the streaming read timeout.
    pub is_sse: bool,
    /// Approximate number of response bytes received from upstream.
    /// (Tracked via upstream_response_body_filter; downstream bytes are not
    /// directly observable in Pingora's ProxyHttp trait.)
    pub upstream_response_bytes: usize,
}

pub struct SentirumProxy {
    /// Managed routing table with atomic snapshots
    pub route_table: Arc<ManagedRouteTable>,
    pub config: SharedConfig,
    /// Parsed trusted proxy CIDR ranges — hot-reloadable via ArcSwap
    pub trusted_proxies: Arc<ArcSwap<Vec<CidrRange>>>,
}

/// Parse trusted proxy CIDR strings into CidrRange structs.
pub fn parse_trusted_proxies(raw: &[String]) -> Arc<ArcSwap<Vec<CidrRange>>> {
    let parsed: Vec<CidrRange> = raw
        .iter()
        .filter_map(|s| {
            let parsed = CidrRange::parse(s);
            if parsed.is_none() {
                tracing::warn!(cidr = %s, "Invalid trusted_proxies CIDR; skipping");
            }
            parsed
        })
        .collect();
    if !parsed.is_empty() {
        tracing::info!(count = parsed.len(), "Loaded trusted proxy ranges");
    }
    Arc::new(ArcSwap::from_pointee(parsed))
}

impl SentirumProxy {
    pub fn new(
        route_table: Arc<ManagedRouteTable>,
        config: SharedConfig,
        trusted_proxies: Arc<ArcSwap<Vec<CidrRange>>>,
    ) -> Self {
        Self {
            route_table,
            config,
            trusted_proxies,
        }
    }
}

#[async_trait]
impl ProxyHttp for SentirumProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        crate::metrics::prometheus::global().connect();
        ProxyCtx {
            picked_target: None,
            response_status: 0,
            request_start: Some(std::time::Instant::now()),
            is_grpc: false,
            is_grpc_web: false,
            is_websocket: false,
            is_sse: false,
            upstream_response_bytes: 0,
        }
    }

    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        modules.add_module(Box::new(GrpcWeb));
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let header = session.req_header();
        ctx.is_grpc_web = is_grpc_web_request(header);
        ctx.is_grpc = ctx.is_grpc_web || is_grpc_request(header);
        ctx.is_websocket = is_websocket_upgrade(header);
        ctx.is_sse = is_sse_request(header);

        if ctx.is_grpc_web {
            let grpc = session
                .downstream_modules_ctx
                .get_mut::<GrpcWebBridge>()
                .expect("GrpcWebBridge module added");
            grpc.init();
        }

        Ok(())
    }

    /// Intercept health check requests and WebSocket upgrades before proxying
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let header = session.req_header();

        // Health check endpoint — respond directly without proxying
        if header.uri.path() == "/health" || header.uri.path() == "/healthz" {
            let body = format!(
                r#"{{"status":"ok","service":"sentirum-lb","version":"{}"}}"#,
                env!("CARGO_PKG_VERSION")
            );

            let mut resp = ResponseHeader::build(200, None)?;
            resp.insert_header("Content-Type", "application/json")?;
            resp.insert_header("Content-Length", body.len().to_string())?;

            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;

            ctx.response_status = 200;
            return Ok(true); // Request handled, no proxy needed
        }

        if ctx.is_websocket {
            tracing::debug!("WebSocket upgrade detected, proxying as-is");
        }

        Ok(false) // Continue with normal proxy flow
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        self.select_upstream_peer(session, ctx).await
    }

    /// Log every completed request (access log) and record metrics
    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        record_access_log(self, session, e, ctx).await;
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let trusted = self.trusted_proxies.load();
        self.prepare_upstream_request(session, upstream_request, ctx, &trusted)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Store response status for access logging
        ctx.response_status = upstream_response.status.as_u16();
        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<std::time::Duration>> {
        if let Some(data) = body {
            ctx.upstream_response_bytes += data.len();
        }
        Ok(None)
    }

    fn upstream_response_trailer_filter(
        &self,
        _session: &mut Session,
        _upstream_trailers: &mut http::HeaderMap,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        Ok(())
    }

    async fn response_trailer_filter(
        &self,
        _session: &mut Session,
        _upstream_trailers: &mut http::HeaderMap,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<bytes::Bytes>>
    where
        Self::CTX: Send + Sync,
    {
        Ok(None)
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        log_connect_failure(e)
    }

    /// Handle proxy error — generate proper error response and return status
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> pingora::proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        write_proxy_error(session, e, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remember_verified_client_certificate_caches_rich_identity() {
        let mut params =
            rcgen::CertificateParams::new(vec!["client.sentirum.test".into()]).unwrap();
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "client.sentirum.test");
            dn
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_pem = cert.pem();
        let parsed = pingora::tls::x509::X509::from_pem(cert_pem.as_bytes()).unwrap();

        remember_verified_client_certificate(&parsed);

        let digest = parsed.digest(MessageDigest::sha256()).unwrap();
        let cached = cached_client_certificate_identity(digest.as_ref()).unwrap();
        assert_eq!(cached.common_name.as_deref(), Some("client.sentirum.test"));
        assert_eq!(
            cached.sha256.as_deref(),
            Some(hex_lower(digest.as_ref()).as_str())
        );
        assert!(
            cached
                .subject
                .as_deref()
                .is_some_and(|v| v.contains("CN=client.sentirum.test"))
        );
    }

    #[test]
    fn test_host_header_parsing() {
        // Test cases: (Host header value, expected stripped hostname)
        let test_cases = vec![
            // IPv6 literals
            ("[::1]:8080", "::1"),
            ("[fe80::1]:8080", "fe80::1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            // Bare IPv6 without brackets — no valid port after last ':', return as-is
            ("::1", "::1"),
            // Dotted hostnames with port
            ("192.168.1.1:8080", "192.168.1.1"),
            ("example.com:8080", "example.com"),
            // Dotless hostnames with port (the old bug: these returned host:port)
            ("localhost:8080", "localhost"),
            ("my-service:80", "my-service"),
            ("backend:3000", "backend"),
            // No port at all
            ("example.com", "example.com"),
            ("localhost", "localhost"),
        ];

        for (input, expected) in &test_cases {
            // Build a real RequestHeader and call parse_host_from_header directly
            // so the test exercises the actual function, not a copy of its logic.
            let mut header = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
            header.insert_header("Host", *input).unwrap();
            let result = parse_host_from_header(&header);
            assert_eq!(result, *expected, "Failed for Host: {}", input);
        }
    }

    #[test]
    fn test_client_cert_identity_cache_evicts_oldest() {
        let mut cache = ClientCertIdentityCache::default();
        cache.insert("a".to_string(), ClientCertIdentity::default());
        cache.insert("b".to_string(), ClientCertIdentity::default());
        assert_eq!(cache.order.front().map(String::as_str), Some("a"));
        assert_eq!(cache.order.back().map(String::as_str), Some("b"));
        // Verify get returns cached entry without O(n) reorder
        assert!(cache.get("a").is_some());
        // Order should NOT change on get (no LRU touch)
        assert_eq!(cache.order.front().map(String::as_str), Some("a"));
    }

    #[test]
    fn test_append_forwarded_headers_sets_host_and_proto() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, false, None, &[]).unwrap();

        assert_eq!(
            upstream.headers.get("x-forwarded-host").unwrap(),
            "example.com"
        );
        assert_eq!(upstream.headers.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn test_append_forwarded_headers_untrusted_ignores_client_proto() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        downstream
            .insert_header("X-Forwarded-Proto", "https")
            .unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        // Untrusted peer: client-supplied proto must be ignored
        append_forwarded_headers(&downstream, &mut upstream, false, None, &[]).unwrap();

        assert_eq!(upstream.headers.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn test_append_forwarded_headers_uses_tls_flag_when_header_missing() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, true, None, &[]).unwrap();

        assert_eq!(upstream.headers.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn test_rewrite_upstream_uri_preserves_query_and_chains_rewrites() {
        let mut target =
            crate::route::target::Target::new("svc".into(), "http://example.com".into());
        target.opts.insert("strip".into(), "/api".into());
        target.opts.insert("prepend".into(), "/v2".into());
        target.pre_parse();

        let uri: http::Uri = "/api/users?id=42".parse().unwrap();
        let rewritten = rewrite_upstream_uri(&uri, &target).unwrap();

        assert_eq!(rewritten.path(), "/v2/users");
        assert_eq!(rewritten.query(), Some("id=42"));
    }

    #[test]
    fn test_rewrite_upstream_uri_keeps_path_when_strip_misses() {
        let mut target =
            crate::route::target::Target::new("svc".into(), "http://example.com".into());
        target.opts.insert("strip".into(), "/api".into());
        target.opts.insert("prepend".into(), "/v2".into());
        target.pre_parse();

        let uri: http::Uri = "/users".parse().unwrap();
        let rewritten = rewrite_upstream_uri(&uri, &target).unwrap();

        assert_eq!(rewritten.path(), "/v2/users");
    }

    #[test]
    fn test_rewrite_upstream_uri_preserves_safe_grpc_method_paths() {
        let mut target =
            crate::route::target::Target::new("svc".into(), "grpc://example.com".into());
        target.opts.insert("strip".into(), "/api".into());
        target.pre_parse();

        let uri: http::Uri = "/api/pkg.Service/Method?x=1".parse().unwrap();
        let rewritten = rewrite_upstream_uri(&uri, &target).unwrap();

        assert_eq!(rewritten.path(), "/pkg.Service/Method");
        assert_eq!(rewritten.query(), Some("x=1"));
    }

    #[test]
    fn test_rewrite_upstream_uri_rejects_invalid_grpc_method_rewrites() {
        let mut target =
            crate::route::target::Target::new("svc".into(), "grpc://example.com".into());
        target.opts.insert("prepend".into(), "/v1".into());
        target.pre_parse();

        let uri: http::Uri = "/pkg.Service/Method".parse().unwrap();
        let rewritten = rewrite_upstream_uri(&uri, &target).unwrap();

        assert_eq!(rewritten, uri);
    }

    #[test]
    fn test_status_message_uses_http_reason() {
        assert_eq!(status_message(403), "Forbidden");
        assert_eq!(status_message(404), "Not Found");
        assert_eq!(status_message(503), "Service Unavailable");
    }

    #[test]
    fn test_append_forwarded_headers_with_peer_addr() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, false, Some("10.0.0.1"), &[]).unwrap();

        assert_eq!(upstream.headers.get("x-forwarded-for").unwrap(), "10.0.0.1");
    }

    #[test]
    fn test_untrusted_client_xff_overwritten() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        downstream
            .insert_header("X-Forwarded-For", "1.2.3.4")
            .unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, false, Some("10.0.0.1"), &[]).unwrap();

        // Untrusted: client XFF overwritten with real peer IP
        assert_eq!(upstream.headers.get("x-forwarded-for").unwrap(), "10.0.0.1");
    }

    #[test]
    fn test_trusted_proxy_preserves_xff_chain() {
        let trusted = vec![CidrRange::parse("10.0.0.0/8").unwrap()];
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        downstream
            .insert_header("X-Forwarded-For", "203.0.113.50")
            .unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(
            &downstream,
            &mut upstream,
            false,
            Some("10.0.0.1"),
            &trusted,
        )
        .unwrap();

        // Trusted: chain preserved + peer appended
        assert_eq!(
            upstream.headers.get("x-forwarded-for").unwrap(),
            "203.0.113.50, 10.0.0.1"
        );
    }

    #[test]
    fn test_trusted_proxy_forwards_cf_connecting_ip() {
        let trusted = vec![CidrRange::parse("173.245.48.0/20").unwrap()];
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        downstream
            .insert_header("CF-Connecting-IP", "203.0.113.99")
            .unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(
            &downstream,
            &mut upstream,
            false,
            Some("173.245.48.5"),
            &trusted,
        )
        .unwrap();

        assert_eq!(
            upstream.headers.get("cf-connecting-ip").unwrap(),
            "203.0.113.99"
        );
    }

    #[test]
    fn test_untrusted_peer_strips_cf_connecting_ip() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        downstream
            .insert_header("CF-Connecting-IP", "203.0.113.99")
            .unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, false, Some("8.8.8.8"), &[]).unwrap();

        // Untrusted: CF-Connecting-IP must NOT be forwarded
        assert!(upstream.headers.get("cf-connecting-ip").is_none());
    }

    #[test]
    fn test_trusted_proxy_preserves_forwarded_proto() {
        let trusted = vec![CidrRange::parse("10.0.0.0/8").unwrap()];
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        downstream
            .insert_header("X-Forwarded-Proto", "https")
            .unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(
            &downstream,
            &mut upstream,
            false,
            Some("10.0.0.1"),
            &trusted,
        )
        .unwrap();

        assert_eq!(upstream.headers.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn test_cidr_ipv6_trusted_proxy() {
        let trusted = vec![CidrRange::parse("2400:cb00::/32").unwrap()];
        assert!(is_trusted_proxy("2400:cb00::1", &trusted));
        assert!(!is_trusted_proxy("2401:cb00::1", &trusted));
    }

    #[test]
    fn test_cidr_no_trusted_proxies() {
        assert!(!is_trusted_proxy("10.0.0.1", &[]));
    }

    #[test]
    fn test_cidr_invalid_prefix_length_rejected() {
        assert!(CidrRange::parse("10.0.0.0/33").is_none());
        assert!(CidrRange::parse("2400:cb00::/129").is_none());
        // Valid edge cases
        assert!(CidrRange::parse("10.0.0.0/32").is_some());
        assert!(CidrRange::parse("10.0.0.0/0").is_some());
        assert!(CidrRange::parse("2400:cb00::/128").is_some());
        assert!(CidrRange::parse("2400:cb00::/0").is_some());
    }

    #[test]
    fn test_try_acquire_upstream_slot_enforces_limit() {
        let target = crate::route::target::Target::new("svc".into(), "http://example.com".into());

        assert!(target.try_acquire_connection_slot(1));
        assert!(!target.try_acquire_connection_slot(1));
        assert_eq!(
            target
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_configure_peer_options_enforces_h2_for_grpc_targets() {
        let config = Arc::new(Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: String::new(),
            },
            consul: crate::config::ConsulConfig {
                address: "127.0.0.1:8500".into(),
                scheme: "http".into(),
                token: String::new(),
                kv_prefix: "/sentirum-lb/routes".into(),
                tag_prefix: "urlprefix-".into(),
                poll_interval: "0s".into(),
                service_discovery: true,
                kv_watching: true,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: crate::config::ProxyConfig {
                upstream_h2_max_streams: 64,
                upstream_h2_ping_interval: "15s".into(),
                ..crate::config::ProxyConfig::default()
            },
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tls_listeners: Vec::new(),
            tcp: crate::config::TcpConfig::default(),
            parsed_timeouts: Default::default(),
        });
        let target =
            crate::route::target::Target::new("svc".into(), "grpcs://example.com/service".into());
        let mut peer = HttpPeer::new("127.0.0.1:443", true, "example.com".into());

        configure_peer_options(&mut peer, &target, &config, false);

        assert_eq!(peer.options.alpn.get_min_http_version(), 2);
        assert_eq!(peer.options.max_h2_streams, 64);
        assert_eq!(
            peer.options.h2_ping_interval,
            Some(std::time::Duration::from_secs(15))
        );
        assert_eq!(peer.sni, "example.com");
        // Issue #22: pooled upstream connections get TCP keepalive by default.
        let ka = peer
            .options
            .tcp_keepalive
            .as_ref()
            .expect("default config enables upstream keepalive");
        assert_eq!(ka.idle, std::time::Duration::from_secs(15));
        assert_eq!(ka.interval, std::time::Duration::from_secs(5));
        assert_eq!(ka.count, 3);
    }

    #[test]
    fn test_configure_peer_options_disables_keepalive_when_empty() {
        let config = Arc::new(Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: String::new(),
            },
            consul: crate::config::ConsulConfig {
                address: "127.0.0.1:8500".into(),
                scheme: "http".into(),
                token: String::new(),
                kv_prefix: "/sentirum-lb/routes".into(),
                tag_prefix: "urlprefix-".into(),
                poll_interval: "0s".into(),
                service_discovery: true,
                kv_watching: true,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: crate::config::ProxyConfig {
                upstream_tcp_keepalive: String::new(),
                ..crate::config::ProxyConfig::default()
            },
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tls_listeners: Vec::new(),
            tcp: crate::config::TcpConfig::default(),
            parsed_timeouts: Default::default(),
        });
        let target = crate::route::target::Target::new("svc".into(), "http://example.com".into());
        let mut peer = HttpPeer::new("127.0.0.1:80", false, "example.com".into());

        configure_peer_options(&mut peer, &target, &config, false);

        assert!(
            peer.options.tcp_keepalive.is_none(),
            "empty upstream_tcp_keepalive should disable keepalive"
        );
    }

    #[test]
    fn test_configure_peer_options_uses_host_override_for_tls_targets() {
        let config = Arc::new(Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: String::new(),
            },
            consul: crate::config::ConsulConfig {
                address: "127.0.0.1:8500".into(),
                scheme: "http".into(),
                token: String::new(),
                kv_prefix: "/sentirum-lb/routes".into(),
                tag_prefix: "urlprefix-".into(),
                poll_interval: "0s".into(),
                service_discovery: true,
                kv_watching: true,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: crate::config::ProxyConfig::default(),
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tls_listeners: Vec::new(),
            parsed_timeouts: Default::default(),
            tcp: crate::config::TcpConfig::default(),
        });
        let mut target =
            crate::route::target::Target::new("svc".into(), "wss://example.com/socket".into());
        target
            .opts
            .insert("host".into(), "override.example.com".into());
        target.pre_parse();
        let mut peer = HttpPeer::new("127.0.0.1:443", true, "example.com".into());

        configure_peer_options(&mut peer, &target, &config, false);

        assert_eq!(peer.sni, "override.example.com");
        assert_eq!(peer.options.alpn.get_min_http_version(), 1);
    }

    #[test]
    fn test_configure_peer_options_strips_port_from_sni() {
        let config = Arc::new(Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: String::new(),
            },
            consul: crate::config::ConsulConfig {
                address: "127.0.0.1:8500".into(),
                scheme: "http".into(),
                token: String::new(),
                kv_prefix: "/sentirum-lb/routes".into(),
                tag_prefix: "urlprefix-".into(),
                poll_interval: "0s".into(),
                service_discovery: true,
                kv_watching: true,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: crate::config::ProxyConfig::default(),
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            parsed_timeouts: Default::default(),
            tls_listeners: Vec::new(),
            tcp: crate::config::TcpConfig::default(),
        });
        let mut target =
            crate::route::target::Target::new("svc".into(), "grpcs://example.com/service".into());
        target
            .opts
            .insert("host".into(), "override.example.com:8443".into());
        target.pre_parse();
        let mut peer = HttpPeer::new("127.0.0.1:443", true, "example.com".into());

        configure_peer_options(&mut peer, &target, &config, false);

        assert_eq!(peer.sni, "override.example.com");
    }

    #[test]
    fn test_grpc_request_detection() {
        let mut header = pingora_http::RequestHeader::build("POST", b"/svc.Method", None).unwrap();
        header
            .insert_header("Content-Type", "application/grpc+proto")
            .unwrap();
        assert!(is_grpc_request(&header));
        assert!(!is_grpc_web_request(&header));
    }

    #[test]
    fn test_grpc_web_request_detection() {
        let mut header = pingora_http::RequestHeader::build("POST", b"/svc.Method", None).unwrap();
        header
            .insert_header("Content-Type", "application/grpc-web+proto")
            .unwrap();
        assert!(is_grpc_web_request(&header));
        assert!(!is_websocket_upgrade(&header));
    }

    #[test]
    fn test_websocket_upgrade_detection() {
        let mut header = pingora_http::RequestHeader::build("GET", b"/socket", None).unwrap();
        header.insert_header("Upgrade", "websocket").unwrap();
        assert!(is_websocket_upgrade(&header));
    }

    #[test]
    fn test_sse_request_detection() {
        let mut header = pingora_http::RequestHeader::build("GET", b"/events", None).unwrap();
        header.insert_header("Accept", "text/event-stream").unwrap();
        assert!(is_sse_request(&header));

        // Mixed Accept list still matches.
        let mut header2 = pingora_http::RequestHeader::build("GET", b"/events", None).unwrap();
        header2
            .insert_header("Accept", "text/html, text/event-stream;q=0.9")
            .unwrap();
        assert!(is_sse_request(&header2));

        // Plain JSON request is not SSE.
        let mut header3 = pingora_http::RequestHeader::build("POST", b"/api", None).unwrap();
        header3.insert_header("Accept", "application/json").unwrap();
        assert!(!is_sse_request(&header3));
    }

    #[test]
    fn test_resolve_read_timeout_streaming_vs_non_streaming() {
        use crate::proxy::handler::rewrite::resolve_read_timeout;
        let config = Arc::new(Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: String::new(),
            },
            consul: crate::config::ConsulConfig {
                address: "127.0.0.1:8500".into(),
                scheme: "http".into(),
                token: String::new(),
                kv_prefix: "/sentirum-lb/routes".into(),
                tag_prefix: "urlprefix-".into(),
                poll_interval: "0s".into(),
                service_discovery: true,
                kv_watching: true,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: crate::config::ProxyConfig {
                read_timeout: "30s".into(),
                stream_read_timeout: "3600s".into(),
                ..crate::config::ProxyConfig::default()
            },
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tls_listeners: Vec::new(),
            tcp: crate::config::TcpConfig::default(),
            parsed_timeouts: Default::default(),
        });
        let target = crate::route::target::Target::new("svc".into(), "http://example.com".into());

        // Non-streaming uses the short read_timeout.
        assert_eq!(
            resolve_read_timeout(&target, &config, false),
            std::time::Duration::from_secs(30)
        );
        // Streaming uses the long stream_read_timeout.
        assert_eq!(
            resolve_read_timeout(&target, &config, true),
            std::time::Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_resolve_read_timeout_per_route_override_wins() {
        use crate::proxy::handler::rewrite::resolve_read_timeout;
        let config = Arc::new(Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: String::new(),
            },
            consul: crate::config::ConsulConfig {
                address: "127.0.0.1:8500".into(),
                scheme: "http".into(),
                token: String::new(),
                kv_prefix: "/sentirum-lb/routes".into(),
                tag_prefix: "urlprefix-".into(),
                poll_interval: "0s".into(),
                service_discovery: true,
                kv_watching: true,
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: crate::config::ProxyConfig {
                read_timeout: "30s".into(),
                stream_read_timeout: "3600s".into(),
                ..crate::config::ProxyConfig::default()
            },
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tls_listeners: Vec::new(),
            tcp: crate::config::TcpConfig::default(),
            parsed_timeouts: Default::default(),
        });
        let mut target =
            crate::route::target::Target::new("svc".into(), "http://example.com".into());
        target.opts.insert("readtimeout".into(), "120s".into());
        target.pre_parse();

        // Override beats both streaming and non-streaming defaults.
        assert_eq!(
            resolve_read_timeout(&target, &config, false),
            std::time::Duration::from_secs(120)
        );
        assert_eq!(
            resolve_read_timeout(&target, &config, true),
            std::time::Duration::from_secs(120)
        );
    }

    #[test]
    fn test_grpc_status_mapping_for_http_errors() {
        assert_eq!(grpc_status_for_http_status(404), "12");
        assert_eq!(grpc_status_for_http_status(502), "14");
        assert_eq!(grpc_status_for_http_status(504), "4");
    }

    #[test]
    fn test_sanitize_grpc_message_percent_encodes_reserved_bytes() {
        assert_eq!(sanitize_grpc_message("bad%msg"), "bad%25msg");
        assert_eq!(sanitize_grpc_message("hi\nthere"), "hi there");
        assert_eq!(sanitize_grpc_message("ç"), "%C3%A7");
    }
}

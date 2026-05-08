use crate::config::Config;
use crate::route::picker::Picker;
use crate::route::registry::ManagedRouteTable;
use crate::route::table::Table;
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::modules::http::{
    HttpModules,
    grpc_web::{GrpcWeb, GrpcWebBridge},
};
use pingora::prelude::*;
use pingora::tls::{hash::MessageDigest, nid::Nid};
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;

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
}

pub struct SentirumProxy {
    /// Managed routing table with atomic snapshots
    pub route_table: Arc<ManagedRouteTable>,
    pub picker: Box<dyn Picker>,
    pub matcher: String,
    pub config: Arc<Config>,
    /// Parsed trusted proxy CIDR ranges
    pub trusted_proxies: Vec<CidrRange>,
}

impl SentirumProxy {
    pub fn new(route_table: Arc<ManagedRouteTable>, config: Arc<Config>) -> Self {
        let picker = crate::route::picker::create_picker(&config.proxy.strategy);
        let matcher = config.proxy.matcher.clone();
        let trusted_proxies: Vec<CidrRange> = config
            .proxy
            .trusted_proxies
            .iter()
            .filter_map(|s| {
                let parsed = CidrRange::parse(s);
                if parsed.is_none() {
                    tracing::warn!(cidr = %s, "Invalid trusted_proxies CIDR; skipping");
                }
                parsed
            })
            .collect();
        if !trusted_proxies.is_empty() {
            tracing::info!(count = trusted_proxies.len(), "Loaded trusted proxy ranges");
        }
        Self {
            route_table,
            picker,
            matcher,
            config,
            trusted_proxies,
        }
    }

    fn lookup_target(
        &self,
        host: &str,
        path: &str,
    ) -> Option<std::sync::Arc<crate::route::target::Target>> {
        let table = self.route_table.get();
        let table: &Table = &table;

        // Use Table's consolidated lookup (no duplication)
        if let Some(route) = table.lookup_route(host, path, &self.matcher)
            && !route.w_targets.is_empty()
        {
            return self
                .picker
                .pick(&route.targets, &route.w_targets, &route.rr_counter);
        }

        None
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
            resp.insert_header("X-Served-By", "sentirum-lb")?;

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
        let (host, path) = extract_host_path(session);

        tracing::debug!(host, path, "Looking up route");

        let target = self.lookup_target(host, path).ok_or_else(|| {
            tracing::warn!(host, path, "No route found");
            Error::new(ErrorType::HTTPStatus(self.config.proxy.no_route_status))
        })?;

        tracing::debug!(host, path, target_url = %target.url, "Route found");

        // SSRF protection: block private/loopback IPs unless explicitly allowed
        if !target.is_host_safe() && !target.ssrf_skip_verify() {
            tracing::warn!(
                host = target.upstream_host(),
                service = %target.service,
                "Blocked upstream target: private/reserved IP (SSRF protection)"
            );
            return Err(Error::new(ErrorType::HTTPStatus(403)));
        }

        // Store target in context for upstream_request_filter (avoids double lookup)
        if !try_acquire_upstream_slot(&target, self.config.proxy.max_connections) {
            tracing::warn!(
                host,
                path,
                target_url = %target.url,
                max_connections = self.config.proxy.max_connections,
                "Upstream concurrency limit reached"
            );
            return Err(Error::new(ErrorType::HTTPStatus(503)));
        }

        ctx.picked_target = Some(target.clone());

        let host = target.upstream_host();
        let port = target.upstream_port();

        // Perform async DNS resolution to prevent DNS rebinding attacks and check the actual IP
        let addr_str = if host.contains(':') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };
        let mut addrs = match tokio::net::lookup_host(&addr_str).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(host, port, error = %e, "DNS resolution failed");
                return Err(Error::new(ErrorType::ConnectNoRoute));
            }
        };

        let resolved_addr = match addrs.next() {
            Some(a) => a,
            None => {
                tracing::warn!(host, port, "No IP addresses found for host");
                return Err(Error::new(ErrorType::ConnectNoRoute));
            }
        };

        if !target.ssrf_skip_verify()
            && (crate::route::target::is_ip_always_blocked(&resolved_addr.ip())
                || (!target.source_allows_private_upstreams()
                    && crate::route::target::is_ip_rfc1918(&resolved_addr.ip())))
        {
            tracing::warn!(
                host = host,
                resolved_ip = %resolved_addr.ip(),
                service = %target.service,
                source = ?target.source,
                "Blocked upstream target during resolution (SSRF protection)"
            );
            return Err(Error::new(ErrorType::HTTPStatus(403)));
        }

        // Use pre-parsed URL fields (no per-request URL parsing!)
        let mut peer = HttpPeer::new(resolved_addr, target.upstream_tls(), host.to_string());
        configure_peer_options(&mut peer, &target, &self.config);

        Ok(Box::new(peer))
    }

    /// Log every completed request (access log) and record metrics
    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let header = session.req_header();
        let method = header.method.as_str();
        let path = header
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(header.uri.path());
        let host = header
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let target_url = ctx
            .picked_target
            .as_ref()
            .map(|t| t.url.as_str())
            .unwrap_or("-");

        // Determine status: use stored response_status, or infer from error
        let status = if ctx.response_status > 0 {
            ctx.response_status
        } else if let Some(err) = e {
            match err.etype() {
                ErrorType::HTTPStatus(code) => *code,
                ErrorType::ConnectTimedout => 504,
                ErrorType::ConnectRefused => 502,
                ErrorType::ConnectNoRoute => 502,
                ErrorType::InvalidHTTPHeader => 502,
                _ => 502,
            }
        } else {
            200
        };

        // Record Prometheus metrics
        let latency_us = ctx
            .request_start
            .map(|s| s.elapsed().as_micros() as u64)
            .unwrap_or(0);
        crate::metrics::prometheus::global().record_protocol_request(
            ctx.is_grpc,
            ctx.is_grpc_web,
            ctx.is_websocket,
        );
        crate::metrics::prometheus::global().record_request(status, latency_us);
        crate::metrics::prometheus::global().disconnect();

        if let Some(target) = &ctx.picked_target {
            target
                .active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        tracing::info!(
            method,
            host,
            path,
            status,
            latency_us,
            upstream = target_url,
            grpc = ctx.is_grpc,
            grpc_web = ctx.is_grpc_web,
            websocket = ctx.is_websocket,
            "access"
        );
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
        // Add request ID header (only if configured)
        if !self.config.proxy.request_id_header.is_empty() {
            let id = uuid::Uuid::new_v4().to_string();
            upstream_request.insert_header(self.config.proxy.request_id_header.clone(), id)?;
        }

        let downstream = session.req_header();
        let downstream_is_tls = session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
            .is_some();
        let peer_addr = session.client_addr().map(|a| {
            let s = a.to_string();
            // Strip port from "ip:port" or "[ipv6]:port"
            if s.starts_with('[') {
                s.split(']')
                    .next()
                    .unwrap_or(&s)
                    .trim_start_matches('[')
                    .to_string()
            } else if let Some(pos) = s.rfind(':') {
                s[..pos].to_string()
            } else {
                s
            }
        });
        append_forwarded_headers(
            downstream,
            upstream_request,
            downstream_is_tls,
            peer_addr.as_deref(),
            &self.trusted_proxies,
        )?;
        append_client_certificate_headers(session, upstream_request)?;

        // Use stored target from upstream_peer (no double lookup!)
        if let Some(target) = &ctx.picked_target {
            if let Some(uri) = rewrite_upstream_uri(&upstream_request.uri, target) {
                upstream_request.set_uri(uri);
            }
            if target.requires_http2() || target.host_override().is_some() {
                upstream_request.insert_header("Host", target.upstream_authority())?;
            }
        }

        Ok(())
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
        upstream_response.insert_header("X-Served-By", "sentirum-lb")?;
        Ok(())
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
        // Map connection errors to appropriate HTTP status codes
        match e.etype() {
            ErrorType::ConnectTimedout => {
                tracing::warn!(error = %e, "Upstream connection timeout (504)");
            }
            ErrorType::ConnectRefused | ErrorType::ConnectNoRoute => {
                tracing::warn!(error = %e, "Upstream refused/unreachable (502)");
            }
            ErrorType::InvalidHTTPHeader => {
                tracing::warn!(error = %e, "Upstream invalid HTTP (502)");
            }
            ErrorType::HTTPStatus(code) => {
                tracing::warn!(status = code, error = %e, "Upstream HTTP error");
            }
            _ => {
                tracing::error!(error = %e, "Upstream connection failed");
            }
        }
        e
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
        let (status, message) = match e.etype() {
            ErrorType::HTTPStatus(code) => (*code, status_message(*code)),
            ErrorType::ConnectTimedout => (504, "Gateway Timeout"),
            ErrorType::ConnectRefused => (502, "Bad Gateway: upstream refused connection"),
            ErrorType::ConnectNoRoute => (502, "Bad Gateway: no route to upstream"),
            ErrorType::InvalidHTTPHeader => (502, "Bad Gateway: invalid response from upstream"),
            _ => (502, "Internal Server Error"),
        };

        if status > 0 {
            let write_result = if ctx.is_grpc {
                write_grpc_error_response(session, status, message).await
            } else {
                let body = if ctx.is_websocket {
                    message.to_string()
                } else {
                    format!("{{\"error\":\"{}\",\"status\":{}}}", message, status)
                };
                let content_type = if ctx.is_websocket {
                    "text/plain; charset=utf-8"
                } else {
                    "application/json"
                };

                let mut resp = match ResponseHeader::build(status, None)
                    .or_else(|_| ResponseHeader::build(500, None))
                {
                    Ok(resp) => resp,
                    Err(build_err) => {
                        tracing::error!(error = %build_err, "Failed to build error response header");
                        return pingora::proxy::FailToProxy {
                            error_code: 500,
                            can_reuse_downstream: false,
                        };
                    }
                };
                resp.insert_header("Content-Type", content_type).ok();
                resp.insert_header("X-Served-By", "sentirum-lb").ok();

                session
                    .write_response_header(Box::new(resp), false)
                    .await
                    .map(|_| body)
            };

            match write_result {
                Ok(body) => {
                    if !body.is_empty() {
                        let _ = session
                            .write_response_body(Some(bytes::Bytes::from(body)), true)
                            .await;
                    }
                }
                Err(write_err) => {
                    tracing::error!(error = %write_err, "Failed to write error response");
                }
            }
        }

        pingora::proxy::FailToProxy {
            error_code: status,
            can_reuse_downstream: false,
        }
    }
}

/// Extract host and path from session's request header.
/// Returns borrowed &str to avoid allocations in the hot path.
fn extract_host_path(session: &Session) -> (&str, &str) {
    let header = session.req_header();
    let host = parse_host_from_header(header);
    let path = header.uri.path();
    (host, path)
}

/// Parse host from Host header, stripping port.
/// Parses the hostname from a Host header, stripping any port suffix.
///
/// Handles all forms correctly:
/// - `example.com:8080`  → `example.com`
/// - `localhost:8080`    → `localhost`  (dotless hostname with port)
/// - `my-service:80`     → `my-service`
/// - `[::1]:8080`        → `::1`        (IPv6 literal)
/// - `example.com`       → `example.com` (no port)
/// - `localhost`         → `localhost`
fn parse_host_from_header(header: &pingora_http::RequestHeader) -> &str {
    let host_header = header
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(bracket_end) = host_header.find("]:") {
        // IPv6 literal: `[::1]:8080` → `::1`
        &host_header[1..bracket_end]
    } else if let Some(colon_pos) = host_header.rfind(':') {
        // Check if the part after the last `:` is a valid port number AND
        // the part before it does not contain another `:` (which would mean
        // it's a bare IPv6 address like `::1` rather than `host:port`).
        let before_colon = &host_header[..colon_pos];
        let after_colon = &host_header[colon_pos + 1..];
        if !before_colon.contains(':') && after_colon.parse::<u16>().is_ok() {
            before_colon
        } else {
            // Either a bare IPv6 address (multiple colons) or no valid port.
            host_header
        }
    } else {
        host_header
    }
}

fn is_websocket_upgrade(header: &pingora_http::RequestHeader) -> bool {
    header
        .headers
        .get("upgrade")
        .map(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .unwrap_or(false)
}

fn is_grpc_content_type(content_type: &str) -> bool {
    let content_type = content_type.trim();
    content_type.len() >= "application/grpc".len()
        && content_type[.."application/grpc".len()].eq_ignore_ascii_case("application/grpc")
}

fn is_grpc_web_content_type(content_type: &str) -> bool {
    let content_type = content_type.trim();
    content_type.len() >= "application/grpc-web".len()
        && content_type[.."application/grpc-web".len()].eq_ignore_ascii_case("application/grpc-web")
}

fn is_grpc_request(header: &pingora_http::RequestHeader) -> bool {
    header
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(is_grpc_content_type)
        .unwrap_or(false)
}

fn is_grpc_web_request(header: &pingora_http::RequestHeader) -> bool {
    header
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(is_grpc_web_content_type)
        .unwrap_or(false)
}

async fn write_grpc_error_response(
    session: &mut Session,
    http_status: u16,
    message: &str,
) -> pingora::Result<String> {
    let mut resp =
        ResponseHeader::build(200, None).or_else(|_| ResponseHeader::build(500, None))?;
    resp.insert_header("Content-Type", "application/grpc")?;
    resp.insert_header("X-Served-By", "sentirum-lb")?;
    resp.insert_header("grpc-status", grpc_status_for_http_status(http_status))?;
    resp.insert_header("grpc-message", sanitize_grpc_message(message))?;
    session.write_response_header(Box::new(resp), true).await?;
    Ok(String::new())
}

fn sni_hostname(authority: &str) -> &str {
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            &authority[1..end]
        } else {
            authority
        }
    } else if let Some(host) = authority.strip_prefix("http://") {
        host.split(':').next().unwrap_or(host)
    } else if let Some(host) = authority.strip_prefix("https://") {
        host.split(':').next().unwrap_or(host)
    } else {
        authority.split(':').next().unwrap_or(authority)
    }
}

fn grpc_status_for_http_status(status: u16) -> &'static str {
    match status {
        400 => "3",
        401 => "16",
        403 => "7",
        404 => "12",
        408 => "4",
        429 => "8",
        499 => "1",
        500 => "13",
        501 => "12",
        502 => "14",
        503 => "14",
        504 => "4",
        _ => "2",
    }
}

fn sanitize_grpc_message(message: &str) -> String {
    let sanitized: String = message
        .chars()
        .map(|c| {
            if c.is_ascii_control() && c != ' ' {
                ' '
            } else {
                c
            }
        })
        .collect();

    let mut encoded = String::with_capacity(sanitized.len());
    for &b in sanitized.as_bytes() {
        match b {
            b' ' => encoded.push(' '),
            0x21..=0x7E if b != b'%' => encoded.push(b as char),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(HEX[(b >> 4) as usize] as char);
                encoded.push(HEX[(b & 0x0F) as usize] as char);
            }
        }
    }

    encoded
}

fn configure_peer_options(
    peer: &mut HttpPeer,
    target: &crate::route::target::Target,
    config: &Config,
) {
    peer.options.connection_timeout = Some(Config::parse_duration(&config.proxy.connect_timeout));
    peer.options.read_timeout = Some(Config::parse_duration(&config.proxy.read_timeout));
    peer.options.write_timeout = Some(Config::parse_duration(&config.proxy.write_timeout));
    peer.options.idle_timeout = Some(Config::parse_duration(&config.proxy.idle_timeout));
    peer.options.alpn = target.preferred_alpn();

    if target.requires_http2() {
        peer.options.max_h2_streams = config.proxy.upstream_h2_max_streams.max(1);
        peer.options.h2_ping_interval =
            Config::parse_optional_duration(&config.proxy.upstream_h2_ping_interval);
    }

    if target.upstream_tls() {
        let authority = target.host_override().unwrap_or(target.upstream_host());
        peer.sni = sni_hostname(authority).to_string();
        if target.tls_skip_verify() {
            // NOTE: Pingora's rustls upstream connector does not currently provide
            // a complete verification-bypass path for self-signed upstream TLS.
            // Keep setting this for compatibility with connector implementations
            // that honor it, but prefer trusted/internal CA certificates in docs
            // and tests for grpcs/wss upstreams.
            peer.options.verify_cert = false;
        }
    }
}

fn append_forwarded_headers(
    downstream_request: &pingora_http::RequestHeader,
    upstream_request: &mut pingora_http::RequestHeader,
    downstream_is_tls: bool,
    peer_addr: Option<&str>,
    trusted_proxies: &[CidrRange],
) -> pingora::Result<()> {
    let host = downstream_request
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let peer_ip = peer_addr.unwrap_or_default();
    let trusted = is_trusted_proxy(peer_ip, trusted_proxies);

    // X-Forwarded-For:
    // - Trusted proxy: preserve client chain, append peer IP
    // - Untrusted: overwrite with peer IP only (prevents spoofing)
    let forwarded_for = if trusted {
        match downstream_request
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            Some(existing) if !peer_ip.is_empty() => format!("{existing}, {peer_ip}"),
            Some(existing) => existing.to_string(),
            None => peer_ip.to_string(),
        }
    } else {
        peer_ip.to_string()
    };

    if !forwarded_for.is_empty() {
        upstream_request.insert_header("X-Forwarded-For", &forwarded_for)?;
    }

    // CF-Connecting-IP: only forward from trusted proxies (e.g. Cloudflare)
    if trusted
        && let Some(cf_ip) = downstream_request
            .headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
    {
        upstream_request.insert_header("CF-Connecting-IP", cf_ip)?;
    }

    if !host.is_empty() {
        upstream_request.insert_header("X-Forwarded-Host", host)?;
    }

    // X-Forwarded-Proto: only trust from trusted proxies
    let scheme = if trusted {
        downstream_request
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(if downstream_is_tls { "https" } else { "http" })
    } else {
        if downstream_is_tls { "https" } else { "http" }
    };
    upstream_request.insert_header("X-Forwarded-Proto", scheme)?;
    Ok(())
}

#[derive(Debug, Clone, Default)]
struct ClientCertIdentity {
    verified: bool,
    serial: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<String>,
    common_name: Option<String>,
    subject: Option<String>,
    sha256: Option<String>,
}

fn append_client_certificate_headers(
    session: &Session,
    upstream_request: &mut pingora_http::RequestHeader,
) -> pingora::Result<()> {
    let Some(identity) = client_certificate_identity(session) else {
        return Ok(());
    };
    if !identity.verified {
        return Ok(());
    }

    upstream_request.insert_header("X-Client-Cert-Verified", "true")?;
    if let Some(value) = &identity.serial {
        upstream_request.insert_header("X-Client-Cert-Serial", value)?;
    }
    if let Some(value) = &identity.organization {
        upstream_request.insert_header("X-Client-Cert-Organization", value)?;
    }
    if let Some(value) = &identity.organizational_unit {
        upstream_request.insert_header("X-Client-Cert-Organizational-Unit", value)?;
    }
    if let Some(value) = &identity.common_name {
        upstream_request.insert_header("X-Client-Cert-Common-Name", value)?;
    }
    if let Some(value) = &identity.subject {
        upstream_request.insert_header("X-Client-Cert-Subject", value)?;
    }
    if let Some(value) = &identity.sha256 {
        upstream_request.insert_header("X-Client-Cert-SHA256", value)?;
    }
    Ok(())
}

fn client_certificate_identity(session: &Session) -> Option<ClientCertIdentity> {
    let digest = session.digest()?.ssl_digest.as_ref()?;
    let mut identity = ClientCertIdentity {
        verified: !digest.cert_digest.is_empty(),
        serial: digest.serial_number.clone(),
        organization: digest.organization.clone(),
        organizational_unit: None,
        common_name: None,
        subject: None,
        sha256: (!digest.cert_digest.is_empty()).then(|| hex_lower(&digest.cert_digest)),
    };

    if let Some(stream) = session.stream()
        && let Some(ssl) = stream.get_ssl()
        && let Some(cert) = ssl.peer_certificate()
    {
        identity.common_name = first_subject_value(&cert, Nid::COMMONNAME);
        identity.organization = first_subject_value(&cert, Nid::ORGANIZATIONNAME)
            .or(identity.organization);
        identity.organizational_unit = first_subject_value(&cert, Nid::ORGANIZATIONALUNITNAME);
        identity.subject = Some(subject_string(&cert));
        identity.sha256 = cert
            .digest(MessageDigest::sha256())
            .ok()
            .map(|bytes| hex_lower(bytes.as_ref()))
            .or(identity.sha256);
        identity.verified = ssl.verify_result().as_raw() == pingora::tls::ssl_sys::X509_V_OK;
    }

    Some(identity)
}

fn first_subject_value(cert: &pingora::tls::x509::X509, nid: Nid) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(nid)
        .find_map(|entry| entry.data().as_utf8().ok().map(|value| value.to_string()))
}

fn subject_string(cert: &pingora::tls::x509::X509) -> String {
    let mut parts = Vec::new();
    if let Some(cn) = first_subject_value(cert, Nid::COMMONNAME) {
        parts.push(format!("CN={cn}"));
    }
    if let Some(org) = first_subject_value(cert, Nid::ORGANIZATIONNAME) {
        parts.push(format!("O={org}"));
    }
    if let Some(ou) = first_subject_value(cert, Nid::ORGANIZATIONALUNITNAME) {
        parts.push(format!("OU={ou}"));
    }
    if parts.is_empty() {
        "<unknown-subject>".to_string()
    } else {
        parts.join(", ")
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn rewrite_upstream_uri(
    uri: &http::Uri,
    target: &crate::route::target::Target,
) -> Option<http::Uri> {
    let mut path = uri.path().to_string();

    if let Some(strip) = target.strip_path()
        && let Some(new_path) = strip_path_prefix(&path, strip)
    {
        path = new_path.into_owned();
    }

    if let Some(prepend) = target.prepend_path() {
        path = prepend_path_prefix(prepend, &path);
    }

    if target.is_grpc() && !is_valid_grpc_path(&path) {
        return Some(uri.clone());
    }

    let rewritten = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };

    rewritten.parse().ok()
}

fn is_valid_grpc_path(path: &str) -> bool {
    let mut parts = path.split('/').filter(|segment| !segment.is_empty());
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(service), Some(method), None) if !service.is_empty() && !method.is_empty()
    )
}

fn strip_path_prefix<'a>(path: &'a str, strip: &str) -> Option<Cow<'a, str>> {
    let stripped = path.strip_prefix(strip)?;
    if stripped.is_empty() {
        Some(Cow::Borrowed("/"))
    } else if stripped.starts_with('/') {
        Some(Cow::Borrowed(stripped))
    } else {
        Some(Cow::Owned(format!("/{}", stripped)))
    }
}

fn prepend_path_prefix(prefix: &str, path: &str) -> String {
    let trimmed_prefix = prefix.trim_end_matches('/');
    let trimmed_path = path.trim_start_matches('/');

    match (trimmed_prefix.is_empty(), trimmed_path.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{}", trimmed_path),
        (false, true) => {
            if trimmed_prefix.starts_with('/') {
                format!("{}/", trimmed_prefix)
            } else {
                format!("/{}/", trimmed_prefix)
            }
        }
        (false, false) => {
            if trimmed_prefix.starts_with('/') {
                format!("{}/{}", trimmed_prefix, trimmed_path)
            } else {
                format!("/{}/{}", trimmed_prefix, trimmed_path)
            }
        }
    }
}

fn status_message(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("Request Failed")
}

fn try_acquire_upstream_slot(
    target: &crate::route::target::Target,
    max_connections: usize,
) -> bool {
    if max_connections == 0 {
        target
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return true;
    }

    let limit = max_connections as u64;
    let mut current = target
        .active_connections
        .load(std::sync::atomic::Ordering::Relaxed);

    loop {
        if current >= limit {
            return false;
        }

        match target.active_connections.compare_exchange_weak(
            current,
            current + 1,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let uri: http::Uri = "/users".parse().unwrap();
        let rewritten = rewrite_upstream_uri(&uri, &target).unwrap();

        assert_eq!(rewritten.path(), "/v2/users");
    }

    #[test]
    fn test_rewrite_upstream_uri_preserves_safe_grpc_method_paths() {
        let mut target =
            crate::route::target::Target::new("svc".into(), "grpc://example.com".into());
        target.opts.insert("strip".into(), "/api".into());

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

        assert!(try_acquire_upstream_slot(&target, 1));
        assert!(!try_acquire_upstream_slot(&target, 1));
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
                workers: 0,
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
            },
            proxy: crate::config::ProxyConfig {
                upstream_h2_max_streams: 64,
                upstream_h2_ping_interval: "15s".into(),
                ..crate::config::ProxyConfig::default()
            },
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tcp: crate::config::TcpConfig::default(),
        });
        let target =
            crate::route::target::Target::new("svc".into(), "grpcs://example.com/service".into());
        let mut peer = HttpPeer::new("127.0.0.1:443", true, "example.com".into());

        configure_peer_options(&mut peer, &target, &config);

        assert_eq!(peer.options.alpn.get_min_http_version(), 2);
        assert_eq!(peer.options.max_h2_streams, 64);
        assert_eq!(
            peer.options.h2_ping_interval,
            Some(std::time::Duration::from_secs(15))
        );
        assert_eq!(peer.sni, "example.com");
    }

    #[test]
    fn test_configure_peer_options_uses_host_override_for_tls_targets() {
        let config = Arc::new(Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                workers: 0,
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
            },
            proxy: crate::config::ProxyConfig::default(),
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tcp: crate::config::TcpConfig::default(),
        });
        let mut target =
            crate::route::target::Target::new("svc".into(), "wss://example.com/socket".into());
        target
            .opts
            .insert("host".into(), "override.example.com".into());
        target.pre_parse();
        let mut peer = HttpPeer::new("127.0.0.1:443", true, "example.com".into());

        configure_peer_options(&mut peer, &target, &config);

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
                workers: 0,
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
            },
            proxy: crate::config::ProxyConfig::default(),
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tcp: crate::config::TcpConfig::default(),
        });
        let mut target =
            crate::route::target::Target::new("svc".into(), "grpcs://example.com/service".into());
        target
            .opts
            .insert("host".into(), "override.example.com:8443".into());
        target.pre_parse();
        let mut peer = HttpPeer::new("127.0.0.1:443", true, "example.com".into());

        configure_peer_options(&mut peer, &target, &config);

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

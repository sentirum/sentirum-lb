use crate::config::Config;
use crate::route::picker::Picker;
use crate::route::registry::ManagedRouteTable;
use crate::route::table::Table;
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use std::borrow::Cow;
use std::sync::Arc;

/// Request context — stores picked target to avoid double lookup
pub struct ProxyCtx {
    /// The target picked during upstream_peer (Arc for zero-copy sharing)
    /// Used in upstream_request_filter for path rewriting
    pub picked_target: Option<std::sync::Arc<crate::route::target::Target>>,
    /// Response status code (set in response_filter for access logging)
    pub response_status: u16,
    /// Request start time (for latency tracking)
    pub request_start: Option<std::time::Instant>,
}

pub struct SentirumProxy {
    /// Managed routing table with atomic snapshots
    pub route_table: Arc<ManagedRouteTable>,
    pub picker: Box<dyn Picker>,
    pub matcher: String,
    pub config: Arc<Config>,
}

impl SentirumProxy {
    pub fn new(route_table: Arc<ManagedRouteTable>, config: Arc<Config>) -> Self {
        let picker = crate::route::picker::create_picker(&config.proxy.strategy);
        let matcher = config.proxy.matcher.clone();
        Self { route_table, picker, matcher, config }
    }

    fn lookup_target(&self, host: &str, path: &str) -> Option<std::sync::Arc<crate::route::target::Target>> {
        let table = self.route_table.get();
        let table: &Table = &table;

        // Use Table's consolidated lookup (no duplication)
        if let Some(route) = table.lookup_route(host, path, &self.matcher) {
            if !route.w_targets.is_empty() {
                return self.picker.pick(&route.targets, &route.w_targets, &route.rr_counter);
            }
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
        }
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
            session.write_response_body(Some(bytes::Bytes::from(body)), true).await?;

            ctx.response_status = 200;
            return Ok(true); // Request handled, no proxy needed
        }

        // WebSocket upgrade detection — just let Pingora handle it natively
        // Pingora supports HTTP/1.1 Upgrade for WebSocket proxy automatically
        if let Some(upgrade) = header.headers.get("upgrade") {
            if upgrade.as_bytes().eq_ignore_ascii_case(b"websocket") {
                tracing::debug!("WebSocket upgrade detected, proxying as-is");
            }
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
                    && crate::route::target::is_ip_rfc1918(&resolved_addr.ip()))) {
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
        let mut peer = HttpPeer::new(
            resolved_addr,
            target.upstream_tls(),
            host.to_string(),
        );

        // Apply connection pool timeouts from config
        peer.options.connection_timeout = Some(Config::parse_duration(&self.config.proxy.connect_timeout));
        peer.options.read_timeout = Some(Config::parse_duration(&self.config.proxy.read_timeout));
        peer.options.write_timeout = Some(Config::parse_duration(&self.config.proxy.write_timeout));
        peer.options.idle_timeout = Some(Config::parse_duration(&self.config.proxy.idle_timeout));

        // Configure TLS for upstream if needed
        if target.upstream_tls() {
            peer.sni = target.host_override().unwrap_or(target.upstream_host()).to_string();
            if target.tls_skip_verify() {
                peer.options.verify_cert = false;
            }
        }

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
        let path = header.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(header.uri.path());
        let host = header.headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("-");
        let target_url = ctx.picked_target.as_ref().map(|t| t.url.as_str()).unwrap_or("-");

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
        let latency_us = ctx.request_start.map(|s| s.elapsed().as_micros() as u64).unwrap_or(0);
        crate::metrics::prometheus::global().record_request(status, latency_us);
        crate::metrics::prometheus::global().disconnect();

        if let Some(target) = &ctx.picked_target {
            target.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        tracing::info!(
            method,
            host,
            path,
            status,
            latency_us,
            upstream = target_url,
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
        let peer_addr = session.client_addr().map(|addr| addr.to_string());
        append_forwarded_headers(
            downstream,
            upstream_request,
            downstream_is_tls,
            peer_addr.as_deref(),
        )?;

        // Use stored target from upstream_peer (no double lookup!)
        if let Some(target) = &ctx.picked_target {
            if let Some(uri) = rewrite_upstream_uri(&upstream_request.uri, target) {
                upstream_request.set_uri(uri);
            }
            if let Some(host_override) = target.host_override() {
                upstream_request.insert_header("Host", host_override)?;
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
        _ctx: &mut Self::CTX,
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
            let body = format!("{{\"error\":\"{}\",\"status\":{}}}", message, status);
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
            resp.insert_header("Content-Type", "application/json").ok();
            resp.insert_header("X-Served-By", "sentirum-lb").ok();

            if let Err(write_err) = session.write_response_header(Box::new(resp), false).await {
                tracing::error!(error = %write_err, "Failed to write error response header");
            } else {
                let _ = session.write_response_body(
                    Some(bytes::Bytes::from(body)),
                    true,
                ).await;
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
/// Handles IPv6 literals correctly: `[::1]:8080` → `::1`
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
        let potential_host = &host_header[..colon_pos];
        if potential_host.contains('.') || potential_host.parse::<std::net::Ipv6Addr>().is_ok() {
            potential_host
        } else {
            host_header
        }
    } else {
        host_header
    }
}

fn append_forwarded_headers(
    downstream_request: &pingora_http::RequestHeader,
    upstream_request: &mut pingora_http::RequestHeader,
    downstream_is_tls: bool,
    peer_addr: Option<&str>,
) -> pingora::Result<()> {
    let host = downstream_request
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let peer_ip = peer_addr.unwrap_or_default();

    let forwarded_for = match downstream_request
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        Some(existing) if !peer_ip.is_empty() => format!("{existing}, {peer_ip}"),
        Some(existing) => existing.to_string(),
        None => peer_ip.to_string(),
    };

    if !forwarded_for.is_empty() {
        upstream_request.insert_header("X-Forwarded-For", forwarded_for)?;
    }

    if !host.is_empty() {
        upstream_request.insert_header("X-Forwarded-Host", host)?;
    }

    let scheme = downstream_request
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(if downstream_is_tls { "https" } else { "http" });
    upstream_request.insert_header("X-Forwarded-Proto", scheme)?;
    Ok(())
}

fn rewrite_upstream_uri(uri: &http::Uri, target: &crate::route::target::Target) -> Option<http::Uri> {
    let mut path = uri.path().to_string();

    if let Some(strip) = target.strip_path() {
        if let Some(new_path) = strip_path_prefix(&path, strip) {
            path = new_path.into_owned();
        }
    }

    if let Some(prepend) = target.prepend_path() {
        path = prepend_path_prefix(prepend, &path);
    }

    let rewritten = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };

    rewritten.parse().ok()
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
    fn test_ipv6_host_parsing() {
        // Simulate what extract_host_path_from_req would do
        let test_cases = vec![
            ("[::1]:8080", "::1"),
            ("[fe80::1]:8080", "fe80::1"),
            ("192.168.1.1:8080", "192.168.1.1"),
            ("example.com:8080", "example.com"),
            ("example.com", "example.com"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ];

        for (input, expected) in test_cases {
            // Test the parsing logic inline
            let host = if let Some(bracket_end) = input.find("]:") {
                &input[1..bracket_end]
            } else if let Some(colon_pos) = input.rfind(':') {
                let potential_host = &input[..colon_pos];
                if potential_host.contains('.') || potential_host.parse::<std::net::Ipv6Addr>().is_ok() {
                    potential_host
                } else {
                    input
                }
            } else {
                input
            };

            assert_eq!(host, expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_append_forwarded_headers_sets_host_and_proto() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, false, None).unwrap();

        assert_eq!(upstream.headers.get("x-forwarded-host").unwrap(), "example.com");
        assert_eq!(upstream.headers.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn test_append_forwarded_headers_preserves_downstream_forwarded_proto() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        downstream.insert_header("X-Forwarded-Proto", "https").unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, false, None).unwrap();

        assert_eq!(upstream.headers.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn test_append_forwarded_headers_uses_tls_flag_when_header_missing() {
        let mut downstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        downstream.insert_header("Host", "example.com").unwrap();
        let mut upstream = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        append_forwarded_headers(&downstream, &mut upstream, true, None).unwrap();

        assert_eq!(upstream.headers.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn test_rewrite_upstream_uri_preserves_query_and_chains_rewrites() {
        let mut target = crate::route::target::Target::new(
            "svc".into(),
            "http://example.com".into(),
        );
        target.opts.insert("strip".into(), "/api".into());
        target.opts.insert("prepend".into(), "/v2".into());

        let uri: http::Uri = "/api/users?id=42".parse().unwrap();
        let rewritten = rewrite_upstream_uri(&uri, &target).unwrap();

        assert_eq!(rewritten.path(), "/v2/users");
        assert_eq!(rewritten.query(), Some("id=42"));
    }

    #[test]
    fn test_rewrite_upstream_uri_keeps_path_when_strip_misses() {
        let mut target = crate::route::target::Target::new(
            "svc".into(),
            "http://example.com".into(),
        );
        target.opts.insert("strip".into(), "/api".into());
        target.opts.insert("prepend".into(), "/v2".into());

        let uri: http::Uri = "/users".parse().unwrap();
        let rewritten = rewrite_upstream_uri(&uri, &target).unwrap();

        assert_eq!(rewritten.path(), "/v2/users");
    }

    #[test]
    fn test_status_message_uses_http_reason() {
        assert_eq!(status_message(403), "Forbidden");
        assert_eq!(status_message(404), "Not Found");
        assert_eq!(status_message(503), "Service Unavailable");
    }

    #[test]
    fn test_try_acquire_upstream_slot_enforces_limit() {
        let target = crate::route::target::Target::new(
            "svc".into(),
            "http://example.com".into(),
        );

        assert!(try_acquire_upstream_slot(&target, 1));
        assert!(!try_acquire_upstream_slot(&target, 1));
        assert_eq!(
            target
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }
}

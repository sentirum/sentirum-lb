use super::{
    CidrRange, ProxyCtx, SentirumProxy, append_client_certificate_headers,
    append_forwarded_headers, configure_peer_options, extract_host_path, rewrite_upstream_uri,
};
use crate::route::picker::pick_target_by_strategy;
use crate::route::table::{MatcherKind, Table};
use pingora::prelude::*;
use pingora::proxy::Session;
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;

impl SentirumProxy {
    pub(super) fn lookup_target(
        &self,
        host: &str,
        path: &str,
        matcher: MatcherKind,
        strategy: &str,
        cb_enabled: bool,
        headers: &http::HeaderMap,
    ) -> Option<std::sync::Arc<crate::route::target::Target>> {
        let table = self.route_table.get();
        let table: &Table = &table;

        let candidate_routes = table.matching_routes(host, path, matcher);

        for route in &candidate_routes {
            if route.w_targets.is_empty() {
                continue;
            }

            let any_header_constraint = route.targets.iter().any(|t| t.opts.contains_key("header"));

            // Header-constrained routes need filtered Vec copies.
            // Routes without header constraints borrow directly from the
            // ArcSwap'd route table — zero clone, zero allocation.
            enum Targets<'a> {
                Borrowed(&'a [Arc<crate::route::target::Target>]),
                Owned(Vec<Arc<crate::route::target::Target>>),
            }

            impl<'a> Targets<'a> {
                fn as_slice(&self) -> &[Arc<crate::route::target::Target>] {
                    match self {
                        Targets::Borrowed(s) => s,
                        Targets::Owned(v) => v,
                    }
                }
            }

            let (targets, w_targets) = if any_header_constraint {
                let matching: Vec<Arc<crate::route::target::Target>> = route
                    .targets
                    .iter()
                    .filter(|t| t.matches_headers(headers))
                    .cloned()
                    .collect();

                if matching.is_empty() {
                    // Header constraints not met — try next (less specific) route
                    tracing::debug!(
                        host,
                        path,
                        route_path = %route.path,
                        "No targets matched header constraints; trying next route"
                    );
                    continue;
                }

                let matching_w: Vec<Arc<crate::route::target::Target>> = route
                    .w_targets
                    .iter()
                    .filter(|t| t.matches_headers(headers))
                    .cloned()
                    .collect();
                (Targets::Owned(matching), Targets::Owned(matching_w))
            } else {
                // Zero-copy: borrow directly from the immutable route table snapshot.
                // The ArcSwap guard keeps the table alive for the duration of
                // this lookup.
                (
                    Targets::Borrowed(&route.targets),
                    Targets::Borrowed(&route.w_targets),
                )
            };

            let targets_slice = targets.as_slice();
            let w_list = w_targets.as_slice();
            let w_list = if w_list.is_empty() {
                targets_slice
            } else {
                w_list
            };

            if let Some(target) =
                pick_target_by_strategy(strategy, targets_slice, w_list, route.rr_counter.as_ref())
            {
                if !target.health_tracker.is_probe_healthy() {
                    tracing::debug!(
                        host,
                        path,
                        target_url = %target.url,
                        "Skipping unhealthy target (active health check)"
                    );
                } else if !cb_enabled
                    || target.health_tracker.circuit_breaker().can_accept_request()
                {
                    return Some(target);
                }

                let best_fallback = {
                    let healthy_fallbacks: Vec<Arc<crate::route::target::Target>> = targets_slice
                        .iter()
                        .filter(|t| {
                            t.url != target.url
                                && t.health_tracker.is_probe_healthy()
                                && t.health_tracker.circuit_breaker().can_accept_request()
                        })
                        .cloned()
                        .collect();
                    if !healthy_fallbacks.is_empty() {
                        pick_target_by_strategy(
                            strategy,
                            &healthy_fallbacks,
                            &healthy_fallbacks,
                            route.rr_counter.as_ref(),
                        )
                    } else {
                        None
                    }
                };
                if let Some(fallback) = &best_fallback {
                    tracing::debug!(
                        host,
                        path,
                        skipped_url = %target.url,
                        fallback_url = %fallback.url,
                        "Circuit breaker open on picked target; using fallback"
                    );
                }
                return best_fallback.or(Some(target));
            }
        }

        None
    }

    pub(super) async fn select_upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCtx,
    ) -> pingora::Result<Box<HttpPeer>> {
        let (host, path) = extract_host_path(session);
        let headers = session.req_header().headers.clone();

        tracing::debug!(host, path, "Looking up route");

        let config = self.config.load();
        let mut target = self
            .lookup_target(
                host,
                path,
                MatcherKind::from_config(&config.proxy.matcher),
                &config.proxy.strategy,
                config.proxy.circuit_breaker_enabled,
                &headers,
            )
            .ok_or_else(|| {
                tracing::warn!(host, path, "No route found");
                Error::new(ErrorType::HTTPStatus(config.proxy.no_route_status))
            })?;

        tracing::debug!(host, path, target_url = %target.url, "Route found");

        if !target.try_acquire_rate_limit(
            config.proxy.rate_limit_per_target,
            config.proxy.rate_limit_burst,
        ) {
            tracing::warn!(
                host,
                path,
                target_url = %target.url,
                rate_limit = config.proxy.rate_limit_per_target,
                burst = config.proxy.rate_limit_burst,
                "Rate limit exceeded"
            );
            crate::metrics::prometheus::global()
                .rate_limit_rejected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(Error::new(ErrorType::HTTPStatus(429)));
        }

        if config.proxy.circuit_breaker_enabled
            && !target.health_tracker.circuit_breaker().allow_request()
        {
            // CB rejected after lookup — try inline fallback before failing.
            // This handles the TOCTOU race where can_accept_request() returned true
            // during lookup_target but allow_request() fails here.
            let table = self.route_table.get();
            let matcher = MatcherKind::from_config(&config.proxy.matcher);
            let candidate_routes = table.matching_routes(host, path, matcher);

            let mut found_fallback = false;
            for route in &candidate_routes {
                if route.w_targets.is_empty() {
                    continue;
                }
                let any_header_constraint =
                    route.targets.iter().any(|t| t.opts.contains_key("header"));
                let fallback = route
                    .targets
                    .iter()
                    .find(|t| {
                        t.url != target.url
                            && t.health_tracker.is_probe_healthy()
                            && (!any_header_constraint || t.matches_headers(&headers))
                            && t.health_tracker.circuit_breaker().allow_request()
                    })
                    .cloned();

                if let Some(fb) = fallback {
                    tracing::debug!(
                        host,
                        path,
                        skipped_url = %target.url,
                        fallback_url = %fb.url,
                        "Circuit breaker rejected after lookup; using inline fallback"
                    );
                    target = fb;
                    found_fallback = true;
                    break;
                }
            }

            if !found_fallback {
                tracing::warn!(
                    host,
                    path,
                    target_url = %target.url,
                    service = %target.service,
                    state = ?target.health_tracker.circuit_breaker().current_state(),
                    "Circuit breaker OPEN — no fallback available, failing fast with 503"
                );
                crate::metrics::prometheus::global()
                    .circuit_breaker_fastfail_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(Error::new(ErrorType::HTTPStatus(503)));
            }
        }

        if !target.try_acquire_connection_slot(config.proxy.max_connections as u64) {
            tracing::warn!(
                host,
                path,
                target_url = %target.url,
                max_connections = config.proxy.max_connections,
                "Upstream concurrency limit reached"
            );
            return Err(Error::new(ErrorType::HTTPStatus(503)));
        }

        ctx.picked_target = Some(target.clone());

        let host = target.upstream_host();
        let port = target.upstream_port();
        let resolved_addr = match target.resolve_upstream_addr().await {
            Ok(addr) => addr,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::warn!(
                    host,
                    port,
                    service = %target.service,
                    source = ?target.source,
                    error = %error,
                    "Blocked upstream target during resolution (SSRF protection)"
                );
                return Err(Error::new(ErrorType::HTTPStatus(403)));
            }
            Err(error) => {
                tracing::warn!(host, port, error = %error, "DNS resolution failed");
                return Err(Error::new(ErrorType::ConnectNoRoute));
            }
        };

        let mut peer = HttpPeer::new(resolved_addr, target.upstream_tls(), host.to_string());
        configure_peer_options(&mut peer, &target, config.as_ref());

        Ok(Box::new(peer))
    }

    pub(super) fn prepare_upstream_request(
        &self,
        session: &Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut ProxyCtx,
        trusted_proxies: &[CidrRange],
    ) -> pingora::Result<()> {
        let config = self.config.load();

        if !config.proxy.request_id_header.is_empty() {
            upstream_request.insert_header(
                config.proxy.request_id_header.clone(),
                super::access::request_id_header_value(),
            )?;
        }

        let downstream = session.req_header();
        let downstream_is_tls = session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
            .is_some();
        let peer_addr = session
            .client_addr()
            .and_then(super::access::client_ip_from_pingora_socket_addr);
        append_forwarded_headers(
            downstream,
            upstream_request,
            downstream_is_tls,
            peer_addr.as_deref(),
            trusted_proxies,
        )?;
        append_client_certificate_headers(session, upstream_request)?;

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
}

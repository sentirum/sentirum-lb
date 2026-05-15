use super::{ProxyCtx, SentirumProxy, status_message, write_grpc_error_response};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::Session;

pub(super) fn response_status(ctx: &ProxyCtx, error: Option<&pingora::Error>) -> u16 {
    if ctx.response_status > 0 {
        ctx.response_status
    } else if let Some(err) = error {
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
    }
}

pub(super) fn should_record_target_error(status: u16, error: Option<&pingora::Error>) -> bool {
    status >= 500
        || matches!(error, Some(err) if err.etype() == &ErrorType::ConnectTimedout)
        || matches!(error, Some(err) if err.etype() == &ErrorType::ConnectRefused)
        || matches!(error, Some(err) if err.etype() == &ErrorType::ConnectNoRoute)
}

pub(super) async fn record_access_log(
    proxy: &SentirumProxy,
    session: &mut Session,
    error: Option<&pingora::Error>,
    ctx: &mut ProxyCtx,
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

    let status = response_status(ctx, error);
    let latency_us = ctx
        .request_start
        .map(|s| s.elapsed().as_micros() as u64)
        .unwrap_or(0);
    let metrics = crate::metrics::prometheus::global();
    metrics.record_protocol_request(ctx.is_grpc, ctx.is_grpc_web, ctx.is_websocket);
    metrics.record_request(status, latency_us);
    metrics.record_bytes(ctx.upstream_response_bytes);
    metrics.disconnect();

    if let Some(target) = &ctx.picked_target {
        target.release_connection_slot();

        let is_error = should_record_target_error(status, error);
        target
            .stats
            .record_request(latency_us, ctx.upstream_response_bytes, is_error);
        target
            .edge_stats
            .record_request(latency_us, ctx.upstream_response_bytes, is_error);

        let config = proxy.config.load();
        if config.proxy.circuit_breaker_enabled {
            if is_error {
                target.health_tracker.circuit_breaker().record_error();
            } else {
                target.health_tracker.circuit_breaker().record_success();
            }
        }
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

pub(super) fn log_connect_failure(error: Box<Error>) -> Box<Error> {
    match error.etype() {
        ErrorType::ConnectTimedout => {
            tracing::warn!(error = %error, "Upstream connection timeout (504)");
        }
        ErrorType::ConnectRefused | ErrorType::ConnectNoRoute => {
            tracing::warn!(error = %error, "Upstream refused/unreachable (502)");
        }
        ErrorType::InvalidHTTPHeader => {
            tracing::warn!(error = %error, "Upstream invalid HTTP (502)");
        }
        ErrorType::HTTPStatus(code) => {
            tracing::warn!(status = code, error = %error, "Upstream HTTP error");
        }
        _ => {
            tracing::error!(error = %error, "Upstream connection failed");
        }
    }
    error
}

pub(super) async fn write_proxy_error(
    session: &mut Session,
    error: &pingora::Error,
    ctx: &mut ProxyCtx,
) -> pingora::proxy::FailToProxy {
    let (status, message) = match error.etype() {
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

#[allow(dead_code)]
pub fn request_id_header_value() -> http::HeaderValue {
    let mut buffer = uuid::Uuid::encode_buffer();
    let id = uuid::Uuid::new_v4().hyphenated().encode_lower(&mut buffer);
    http::HeaderValue::from_str(id).expect("uuid must produce a valid header value")
}

#[allow(dead_code)]
pub fn client_ip_from_socket_addr(addr: std::net::SocketAddr) -> String {
    addr.ip().to_string()
}

pub(super) fn client_ip_from_pingora_socket_addr(
    addr: &pingora::protocols::l4::socket::SocketAddr,
) -> Option<String> {
    addr.as_inet().map(|addr| client_ip_from_socket_addr(*addr))
}

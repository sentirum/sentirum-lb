use super::{CidrRange, is_trusted_proxy};

pub(super) fn append_forwarded_headers(
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

    let scheme = if trusted {
        downstream_request
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(if downstream_is_tls { "https" } else { "http" })
    } else if downstream_is_tls {
        "https"
    } else {
        "http"
    };
    upstream_request.insert_header("X-Forwarded-Proto", scheme)?;
    Ok(())
}

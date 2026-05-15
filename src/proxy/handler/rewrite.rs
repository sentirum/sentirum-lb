use crate::config::Config;
use crate::proxy::handler::protocol::sni_hostname;
use pingora::upstreams::peer::HttpPeer;

pub(super) fn configure_peer_options(
    peer: &mut HttpPeer,
    target: &crate::route::target::Target,
    config: &Config,
) {
    let timeouts = config.parsed_timeouts();
    peer.options.connection_timeout = Some(timeouts.connect);
    peer.options.read_timeout = Some(timeouts.read);
    peer.options.write_timeout = Some(timeouts.write);
    peer.options.idle_timeout = Some(timeouts.idle);
    peer.options.alpn = target.preferred_alpn();

    if target.requires_http2() {
        peer.options.max_h2_streams = config.proxy.upstream_h2_max_streams.max(1);
        peer.options.h2_ping_interval = timeouts.h2_ping_interval;
    }

    if target.upstream_tls() {
        let authority = target.host_override().unwrap_or(target.upstream_host());
        peer.sni = sni_hostname(authority).to_string();
        if target.tls_skip_verify() {
            peer.options.verify_cert = false;
        }
    }
}

pub(super) fn rewrite_upstream_uri(
    uri: &http::Uri,
    target: &crate::route::target::Target,
) -> Option<http::Uri> {
    let original_path = uri.path();
    let mut rewritten_path: Option<String> = None;

    if let Some(strip) = target.strip_path()
        && let Some(new_path) = original_path.strip_prefix(strip)
    {
        let new_path = if new_path.is_empty() {
            "/".to_string()
        } else if new_path.starts_with('/') {
            new_path.to_string()
        } else {
            format!("/{}", new_path)
        };
        rewritten_path = Some(new_path);
    }

    if let Some(prepend) = target.prepend_path() {
        let current = rewritten_path.as_deref().unwrap_or(original_path);
        rewritten_path = Some(prepend_path_prefix(prepend, current));
    }

    // No rewrite happened
    let final_path = rewritten_path?;

    if target.is_grpc() && !is_valid_grpc_path(&final_path) {
        return Some(uri.clone());
    }

    let rewritten = match uri.query() {
        Some(query) => format!("{}?{}", final_path, query),
        None => final_path,
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

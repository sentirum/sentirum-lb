use crate::config::Config;
use crate::proxy::handler::protocol::sni_hostname;
use pingora::upstreams::peer::HttpPeer;
use std::borrow::Cow;

pub(super) fn configure_peer_options(
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
            peer.options.verify_cert = false;
        }
    }
}

pub(super) fn rewrite_upstream_uri(
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

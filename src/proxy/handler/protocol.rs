use pingora::http::ResponseHeader;
use pingora::proxy::Session;

pub(super) fn extract_host_path(session: &Session) -> (&str, &str) {
    let header = session.req_header();
    let host = parse_host_from_header(header);
    let path = header.uri.path();
    (host, path)
}

/// Parse host from Host header, stripping port.
///
/// Handles all forms correctly:
/// - `example.com:8080`  → `example.com`
/// - `localhost:8080`    → `localhost`
/// - `my-service:80`     → `my-service`
/// - `[::1]:8080`        → `::1`
/// - `example.com`       → `example.com`
/// - `localhost`         → `localhost`
pub(super) fn parse_host_from_header(header: &pingora_http::RequestHeader) -> &str {
    let host_header = header
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(bracket_end) = host_header.find("]:") {
        &host_header[1..bracket_end]
    } else if let Some(colon_pos) = host_header.rfind(':') {
        let before_colon = &host_header[..colon_pos];
        let after_colon = &host_header[colon_pos + 1..];
        if !before_colon.contains(':') && after_colon.parse::<u16>().is_ok() {
            before_colon
        } else {
            host_header
        }
    } else {
        host_header
    }
}

pub(super) fn is_websocket_upgrade(header: &pingora_http::RequestHeader) -> bool {
    header
        .headers
        .get("upgrade")
        .map(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .unwrap_or(false)
}

/// Check if content_type matches the given media type prefix, but only if
/// followed by a parameter delimiter (`;`, space, tab), media type suffix (`+`),
/// or end-of-string.
/// This prevents false positives like "application/grpcfoo" matching "application/grpc".
fn content_type_matches(content_type: &str, prefix: &str) -> bool {
    let content_type = content_type.trim();
    let n = prefix.len();
    content_type.len() >= n
        && content_type[..n].eq_ignore_ascii_case(prefix)
        && (content_type.len() == n
            || matches!(content_type.as_bytes()[n], b';' | b' ' | b'\t' | b'+'))
}

fn is_grpc_content_type(content_type: &str) -> bool {
    content_type_matches(content_type, "application/grpc")
}

fn is_grpc_web_content_type(content_type: &str) -> bool {
    content_type_matches(content_type, "application/grpc-web")
}

pub(super) fn is_grpc_request(header: &pingora_http::RequestHeader) -> bool {
    header
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(is_grpc_content_type)
        .unwrap_or(false)
}

pub(super) fn is_grpc_web_request(header: &pingora_http::RequestHeader) -> bool {
    header
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(is_grpc_web_content_type)
        .unwrap_or(false)
}

pub(super) async fn write_grpc_error_response(
    session: &mut Session,
    http_status: u16,
    message: &str,
) -> pingora::Result<String> {
    let mut resp =
        ResponseHeader::build(200, None).or_else(|_| ResponseHeader::build(500, None))?;
    resp.insert_header("Content-Type", "application/grpc")?;
    resp.insert_header("grpc-status", grpc_status_for_http_status(http_status))?;
    resp.insert_header("grpc-message", sanitize_grpc_message(message))?;
    session.write_response_header(Box::new(resp), true).await?;
    Ok(String::new())
}

pub(super) fn sni_hostname(authority: &str) -> &str {
    // Strip protocol prefixes first
    let authority = authority
        .strip_prefix("http://")
        .or_else(|| authority.strip_prefix("https://"))
        .unwrap_or(authority);

    // Bracketed IPv6: [::1]:port or [::1]
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            return &authority[1..end];
        }
        return authority;
    }

    // Bare IPv6 literal (contains multiple colons, no brackets, no port)
    if authority.matches(':').count() > 1 {
        return authority;
    }

    // host:port — strip the port if it parses as u16
    authority
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|_| host))
        .unwrap_or(authority)
}

pub(super) fn grpc_status_for_http_status(status: u16) -> &'static str {
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

pub(super) fn sanitize_grpc_message(message: &str) -> String {
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

pub(super) fn status_message(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("Request Failed")
}

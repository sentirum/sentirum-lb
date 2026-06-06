use super::{Config, ProxyConfig};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ParsedProxyTimeouts {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
    pub idle: Duration,
    pub h2_ping_interval: Option<Duration>,
    /// Read timeout for streaming responses (WebSocket/SSE/long-poll).
    /// `None` means fall back to `read` for every request.
    pub stream_read: Option<Duration>,
    /// Pre-parsed upstream (LB → backend) TCP keepalive. `None` = disabled.
    pub upstream_keepalive: Option<ParsedKeepalive>,
    /// Pre-parsed downstream (CDN → LB) TCP keepalive. `None` = disabled.
    pub downstream_keepalive: Option<ParsedKeepalive>,
}

impl ParsedProxyTimeouts {
    pub fn from_proxy_config(cfg: &ProxyConfig) -> Self {
        Self {
            connect: Config::parse_duration(&cfg.connect_timeout),
            read: Config::parse_duration(&cfg.read_timeout),
            write: Config::parse_duration(&cfg.write_timeout),
            idle: Config::parse_duration(&cfg.idle_timeout),
            h2_ping_interval: Config::parse_optional_duration(&cfg.upstream_h2_ping_interval),
            stream_read: Config::parse_optional_duration(&cfg.stream_read_timeout),
            upstream_keepalive: ParsedKeepalive::parse(
                &cfg.upstream_tcp_keepalive,
                &cfg.upstream_user_timeout,
            ),
            downstream_keepalive: ParsedKeepalive::parse(&cfg.downstream_tcp_keepalive, ""),
        }
    }
}

/// Parsed TCP keepalive configuration for pooled/accepted connections.
///
/// Built from the `"idle,interval,count"` config string (e.g. `"15s,5s,3"`).
/// An empty config string disables keepalive and yields `None` when parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedKeepalive {
    pub idle: Duration,
    pub interval: Duration,
    pub count: usize,
    /// `TCP_USER_TIMEOUT` (Linux only). `Duration::ZERO` means "use system
    /// default" — Pingora interprets a zero `user_timeout` as unset.
    pub user_timeout: Duration,
}

impl ParsedKeepalive {
    /// Parse an `"idle,interval,count"` keepalive spec.
    ///
    /// Returns `None` when `spec` is empty/blank (keepalive disabled). Returns
    /// `None` and logs a warning when the spec is malformed, so a bad config
    /// degrades to "disabled" rather than panicking on the hot path.
    pub fn parse(spec: &str, user_timeout: &str) -> Option<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return None;
        }

        let parts: Vec<&str> = spec.split(',').map(str::trim).collect();
        if parts.len() != 3 {
            tracing::warn!(
                value = spec,
                "Invalid tcp_keepalive (expected 'idle,interval,count' e.g. '15s,5s,3'); disabling"
            );
            return None;
        }

        let idle = Config::parse_optional_duration(parts[0]);
        let interval = Config::parse_optional_duration(parts[1]);
        let count = parts[2].parse::<usize>().ok();

        match (idle, interval, count) {
            (Some(idle), Some(interval), Some(count)) if count > 0 => Some(Self {
                idle,
                interval,
                count,
                user_timeout: Config::parse_optional_duration(user_timeout)
                    .unwrap_or(Duration::ZERO),
            }),
            _ => {
                tracing::warn!(
                    value = spec,
                    "Invalid tcp_keepalive components (idle/interval must be durations, count a positive integer); disabling"
                );
                None
            }
        }
    }
}

impl Config {
    /// Return the pre-parsed timeouts (no per-request string parsing).
    /// Lazily computes on first call; cached for the lifetime of this Config.
    /// When config is swapped (ArcSwap), a new Config is created with an empty
    /// OnceLock, so it re-computes automatically with the new values.
    #[inline]
    pub fn parsed_timeouts(&self) -> &ParsedProxyTimeouts {
        self.parsed_timeouts
            .get_or_init(|| ParsedProxyTimeouts::from_proxy_config(&self.proxy))
    }

    /// Parsed upstream (LB → backend) TCP keepalive. `None` = disabled.
    ///
    /// Reads from the lazily-computed, `OnceLock`-cached [`ParsedProxyTimeouts`]
    /// so the `"idle,interval,count"` string is parsed once per Config (not per
    /// request). Config swaps (ArcSwap) recompute automatically via a fresh
    /// `OnceLock`.
    #[inline]
    pub fn upstream_keepalive(&self) -> Option<ParsedKeepalive> {
        self.parsed_timeouts().upstream_keepalive
    }

    /// Parsed downstream (CDN → LB) TCP keepalive for accepted connections.
    /// `None` = disabled. `user_timeout` is not applicable to listener sockets.
    #[inline]
    pub fn downstream_keepalive(&self) -> Option<ParsedKeepalive> {
        self.parsed_timeouts().downstream_keepalive
    }

    pub fn parse_optional_duration(s: &str) -> Option<Duration> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        let result = if s.ends_with("ms") {
            s.trim_end_matches("ms")
                .parse::<u64>()
                .ok()
                .map(Duration::from_millis)
        } else if s.ends_with('s') {
            s.trim_end_matches('s')
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
        } else if s.ends_with('m') {
            s.trim_end_matches('m')
                .parse::<u64>()
                .ok()
                .and_then(|m| m.checked_mul(60))
                .map(Duration::from_secs)
        } else if s.ends_with('h') {
            s.trim_end_matches('h')
                .parse::<u64>()
                .ok()
                .and_then(|h| h.checked_mul(3600))
                .map(Duration::from_secs)
        } else {
            None
        };

        result.or_else(|| {
            tracing::warn!(
                value = s,
                "Unrecognised duration format; ignoring optional duration"
            );
            None
        })
    }

    pub fn parse_duration(s: &str) -> Duration {
        let s = s.trim();
        Self::parse_optional_duration(s).unwrap_or_else(|| {
            if !s.is_empty() {
                tracing::warn!(value = s, "Unrecognised duration format; defaulting to 0s");
            }
            Duration::ZERO
        })
    }
}

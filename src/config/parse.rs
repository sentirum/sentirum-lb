use super::{Config, ProxyConfig};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ParsedProxyTimeouts {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
    pub idle: Duration,
    pub h2_ping_interval: Option<Duration>,
}

impl ParsedProxyTimeouts {
    pub fn from_proxy_config(cfg: &ProxyConfig) -> Self {
        Self {
            connect: Config::parse_duration(&cfg.connect_timeout),
            read: Config::parse_duration(&cfg.read_timeout),
            write: Config::parse_duration(&cfg.write_timeout),
            idle: Config::parse_duration(&cfg.idle_timeout),
            h2_ping_interval: Config::parse_optional_duration(&cfg.upstream_h2_ping_interval),
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

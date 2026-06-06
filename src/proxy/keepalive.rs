//! TCP keepalive helpers (Issue #22).
//!
//! Converts the parsed config representation ([`ParsedKeepalive`]) into
//! Pingora's [`TcpKeepalive`] in a cross-platform way. Pingora gates the
//! `user_timeout` field (`TCP_USER_TIMEOUT`) behind `#[cfg(target_os =
//! "linux")]`, so the struct must be constructed conditionally to keep
//! non-Linux (e.g. local macOS dev) builds compiling. On non-Linux targets the
//! `user_timeout` value is silently ignored — keepalive probes still apply.

use crate::config::Config;
use crate::config::ParsedKeepalive;
use pingora::listeners::TcpSocketOptions;
use pingora::protocols::l4::ext::TcpKeepalive;

/// Build a Pingora [`TcpKeepalive`] from the parsed config.
///
/// `user_timeout` is only wired on Linux (where `TCP_USER_TIMEOUT` exists);
/// on other platforms it is dropped because the field does not exist.
pub fn to_pingora(ka: &ParsedKeepalive) -> TcpKeepalive {
    #[cfg(target_os = "linux")]
    {
        TcpKeepalive {
            idle: ka.idle,
            interval: ka.interval,
            count: ka.count,
            user_timeout: ka.user_timeout,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        TcpKeepalive {
            idle: ka.idle,
            interval: ka.interval,
            count: ka.count,
        }
    }
}

/// Build listener [`TcpSocketOptions`] carrying downstream keepalive, or `None`
/// when downstream keepalive is disabled.
///
/// Applied to accepted (edge/CDN → LB) connections so silently-dead downstream
/// connections are probed/cleanly closed rather than lingering as corpses
/// (Issue #22). `TcpSocketOptions` is `#[non_exhaustive]`; we mutate a
/// `Default` value to stay forward-compatible with new Pingora fields.
pub fn downstream_socket_options(config: &Config) -> Option<TcpSocketOptions> {
    let ka = config.downstream_keepalive()?;
    // `TcpSocketOptions` is `#[non_exhaustive]`, so it must be built from
    // `default()` and mutated (struct-literal syntax is not allowed for
    // non-exhaustive structs in downstream crates).
    #[allow(clippy::field_reassign_with_default)]
    let mut opts = TcpSocketOptions::default();
    opts.tcp_keepalive = Some(to_pingora(&ka));
    Some(opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config_with_downstream_keepalive(spec: &str) -> Config {
        let proxy = crate::config::ProxyConfig {
            downstream_tcp_keepalive: spec.to_string(),
            ..crate::config::ProxyConfig::default()
        };
        Config {
            server: crate::config::ServerConfig {
                listen: ":9999".into(),
                admin_listen: "127.0.0.1:9998".into(),
                admin_token: String::new(),
                admin_users: vec![],
                workers: 0,
                drain_timeout: "30s".into(),
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
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy,
            logging: crate::config::LoggingConfig::default(),
            tls: crate::config::TlsConfig::default(),
            tls_listeners: Vec::new(),
            tcp: crate::config::TcpConfig::default(),
            parsed_timeouts: Default::default(),
        }
    }

    #[test]
    fn downstream_socket_options_enabled_by_default() {
        let config = config_with_downstream_keepalive("15s,5s,3");
        let opts = super::downstream_socket_options(&config).expect("enabled");
        let ka = opts.tcp_keepalive.expect("keepalive set");
        assert_eq!(ka.idle, Duration::from_secs(15));
        assert_eq!(ka.count, 3);
    }

    #[test]
    fn downstream_socket_options_none_when_empty() {
        let config = config_with_downstream_keepalive("");
        assert!(super::downstream_socket_options(&config).is_none());
    }

    #[test]
    fn to_pingora_maps_core_fields() {
        let ka = ParsedKeepalive {
            idle: Duration::from_secs(15),
            interval: Duration::from_secs(5),
            count: 3,
            user_timeout: Duration::from_secs(30),
        };
        let out = to_pingora(&ka);
        assert_eq!(out.idle, Duration::from_secs(15));
        assert_eq!(out.interval, Duration::from_secs(5));
        assert_eq!(out.count, 3);
        #[cfg(target_os = "linux")]
        assert_eq!(out.user_timeout, Duration::from_secs(30));
    }
}

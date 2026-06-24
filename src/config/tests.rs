use super::*;
use std::time::Duration;

#[test]
fn parse_optional_duration_accepts_empty_values() {
    assert_eq!(Config::parse_optional_duration(""), None);
    assert_eq!(Config::parse_optional_duration("   "), None);
}

#[test]
fn parse_optional_duration_parses_supported_units() {
    assert_eq!(
        Config::parse_optional_duration("150ms"),
        Some(Duration::from_millis(150))
    );
    assert_eq!(
        Config::parse_optional_duration("5s"),
        Some(Duration::from_secs(5))
    );
    assert_eq!(
        Config::parse_optional_duration("2m"),
        Some(Duration::from_secs(120))
    );
    assert_eq!(
        Config::parse_optional_duration("1h"),
        Some(Duration::from_secs(3600))
    );
}

#[test]
fn validate_rejects_invalid_timeout_strings() {
    let mut config = Config {
        server: ServerConfig {
            listen: ":9999".to_string(),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_users: Vec::new(),
            admin_token: String::new(),
            workers: 0,
            drain_timeout: "30s".to_string(),
        },
        consul: ConsulConfig {
            address: "127.0.0.1:8500".to_string(),
            scheme: "http".to_string(),
            token: String::new(),
            kv_prefix: "/sentirum-lb/routes".to_string(),
            tag_prefix: "urlprefix-".to_string(),
            poll_interval: "0s".to_string(),
            service_discovery: true,
            kv_watching: true,
            service_whitelist: Vec::new(),
            service_blacklist: Vec::new(),
            graceful_shutdown: true,
            include_warning: false,
        },
        proxy: ProxyConfig::default(),
        logging: LoggingConfig::default(),
        tls: TlsConfig::default(),
        tls_listeners: Vec::new(),
        parsed_timeouts: Default::default(),
        tcp: TcpConfig::default(),
    };
    config.proxy.connect_timeout = "abc".to_string();

    let error = config
        .validate()
        .expect("invalid timeout should fail validation");
    assert!(error.contains("proxy.connect_timeout"));
}

#[test]
fn proxy_config_defaults_long_lived_http2_fields() {
    let proxy = ProxyConfig::default();
    assert!(!proxy.enable_h2c);
    assert_eq!(proxy.upstream_h2_max_streams, 128);
    assert!(proxy.upstream_h2_ping_interval.is_empty());
}

#[test]
fn tls_config_defaults_require_initial_snapshot_to_false() {
    let tls = TlsConfig::default();
    assert!(!tls.require_initial_snapshot);
    assert!(tls.client_auth.is_empty());
    assert!(tls.client_ca_source.is_empty());
    assert!(tls.client_ca_path.is_empty());
    assert!(tls.client_ca_consul_prefix.is_empty());
}

#[test]
fn tcp_config_defaults_to_disabled_with_fabio_refresh() {
    let tcp = TcpConfig::default();
    assert!(tcp.mode.is_empty());
    assert!(tcp.listen.is_empty());
    assert_eq!(tcp.refresh, "5s");
}

#[test]
fn proxy_config_health_check_defaults() {
    let proxy = ProxyConfig::default();
    assert_eq!(proxy.health_check_interval, "15s");
    assert_eq!(proxy.health_check_timeout, "5s");
    assert_eq!(proxy.health_check_fall, 3);
    assert_eq!(proxy.health_check_rise, 2);
    assert_eq!(proxy.health_check_path, "/");
    assert!(!proxy.health_check_tls_skip_verify);
}

#[test]
fn proxy_config_rate_limit_defaults() {
    let proxy = ProxyConfig::default();
    assert_eq!(proxy.rate_limit_per_target, 0);
    assert_eq!(proxy.rate_limit_burst, 100);
}

#[test]
fn server_config_drain_timeout_default() {
    let toml_str = r#"
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = ""
admin_users = []
workers = 0
drain_timeout = "30s"
"#;
    let server: ServerConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(server.drain_timeout, "30s");
}

#[test]
fn validate_cidr_rejects_invalid() {
    // Empty CIDR
    assert!(validate_cidr("").is_err());
    // Missing prefix
    assert!(validate_cidr("192.168.1.1").is_err());
    // Invalid prefix
    assert!(validate_cidr("192.168.1.1/33").is_err());
    // Invalid IP
    assert!(validate_cidr("not.an.ip/24").is_err());
}

#[test]
fn validate_cidr_accepts_valid() {
    assert!(validate_cidr("192.168.1.0/24").is_ok());
    assert!(validate_cidr("10.0.0.0/8").is_ok());
    assert!(validate_cidr("172.16.0.0/12").is_ok());
    assert!(validate_cidr("127.0.0.1/32").is_ok());
    assert!(validate_cidr("::1/128").is_ok());
    assert!(validate_cidr("2001:db8::/32").is_ok());
}

#[test]
fn config_validate_rejects_invalid_settings() {
    // Use toml parsing or construct manually
    let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = ""
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []
"#
    .to_string();

    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.circuit_breaker_error_threshold = 150; // > 100
    assert!(config.validate().is_some());

    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.circuit_breaker_window_size = 0; // must be > 0
    assert!(config.validate().is_some());

    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.trusted_proxies = vec!["invalid-cidr".to_string()];
    assert!(config.validate().is_some());

    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.tls.source = "file".to_string();
    config.tls.cert_path = "".to_string();
    config.tls.key_path = "".to_string();
    assert!(config.validate().is_some());
}

#[test]
fn config_validate_rejects_unknown_matcher_and_strategy() {
    let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = ""
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []
"#
    .to_string();

    // "exact" is now a supported matcher (previously silently fell back to prefix).
    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.matcher = "exact".to_string();
    assert!(
        config.validate().is_none(),
        "exact matcher must be accepted"
    );

    // Unknown matcher is rejected instead of silently degrading to prefix.
    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.matcher = "bogus".to_string();
    assert!(
        config.validate().is_some(),
        "unknown matcher must be rejected"
    );

    // Unknown strategy is rejected.
    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.strategy = "weighted".to_string();
    assert!(
        config.validate().is_some(),
        "unknown strategy must be rejected"
    );

    // rise/fall of 0 would make a single probe flip health.
    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.health_check_rise = 0;
    assert!(
        config.validate().is_some(),
        "health_check_rise=0 must be rejected"
    );

    // An invalid request_id_header name would fail every request's insert_header.
    let mut config: Config = toml::from_str(&toml_str).unwrap();
    config.proxy.request_id_header = "bad header".to_string();
    assert!(
        config.validate().is_some(),
        "invalid request_id_header must be rejected"
    );
}

#[test]
fn config_validate_accepts_valid_settings() {
    let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = "averysecuretoken123456789"
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []
"#
    .to_string();

    let config: Config = toml::from_str(&toml_str).unwrap();
    assert!(config.validate().is_none());
}

#[test]
fn config_validate_rejects_invalid_health_check_path() {
    let mut config = Config {
        server: ServerConfig {
            listen: ":9999".to_string(),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_token: String::new(),
            admin_users: vec![],
            workers: 0,
            drain_timeout: "30s".to_string(),
        },
        consul: ConsulConfig {
            address: "127.0.0.1:8500".to_string(),
            scheme: "http".to_string(),
            token: String::new(),
            kv_prefix: "/sentirum-lb/routes".to_string(),
            tag_prefix: "urlprefix-".to_string(),
            poll_interval: "0s".to_string(),
            service_discovery: true,
            kv_watching: true,
            service_whitelist: Vec::new(),
            service_blacklist: Vec::new(),
            graceful_shutdown: true,
            include_warning: false,
        },
        proxy: ProxyConfig::default(),
        logging: LoggingConfig::default(),
        tls: TlsConfig::default(),
        parsed_timeouts: Default::default(),
        tls_listeners: Vec::new(),
        tcp: TcpConfig::default(),
    };
    config.proxy.health_check_path = "../../etc/passwd".to_string();
    let error = config.validate().expect("should have validation error");
    assert!(error.contains("health_check_path"));
}

#[test]
fn config_validate_rejects_tls_listeners_with_empty_listen() {
    let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = "test-token-12345678"
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []

[[tls_listeners]]
cert_path = "/some/cert.pem"
key_path = "/some/key.pem"
"#;

    let config: Config = toml::from_str(toml_str).unwrap();
    let error = config.validate().expect("should have validation error");
    assert!(
        error.contains("tls_listeners[0].listen is required"),
        "expected tls_listeners[0].listen error, got: {error}"
    );
}

#[test]
fn config_validate_rejects_duplicate_tls_listener_addresses() {
    let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = "test-token-12345678"
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []

[tls]
cert_path = "/some/cert.pem"
key_path = "/some/key.pem"
listen = ":9443"

[[tls_listeners]]
cert_path = "/other/cert.pem"
key_path = "/other/key.pem"
listen = ":9443"
"#;

    let config: Config = toml::from_str(toml_str).unwrap();
    let error = config.validate().expect("should have validation error");
    assert!(
        error.contains("conflicts with primary [tls].listen"),
        "expected duplicate listen error, got: {error}"
    );
}

#[test]
fn config_validate_accepts_valid_tls_listeners() {
    let toml_str = r#"
[server]
listen = ":9999"
admin_listen = "127.0.0.1:9998"
admin_token = "test-token-12345678"
admin_users = []
workers = 0
drain_timeout = "30s"

[consul]
address = "127.0.0.1:8500"
services = []
tags = []

[tls]
cert_path = "/some/cert.pem"
key_path = "/some/key.pem"
listen = ":9443"

[[tls_listeners]]
cert_path = "/other/cert.pem"
key_path = "/other/key.pem"
listen = ":9444"
client_auth = "required"
client_ca_source = "file"
client_ca_path = "/some/ca.pem"
"#;

    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_none(), "config should be valid");
    assert_eq!(config.tls_listeners.len(), 1);
    assert_eq!(config.tls_listeners[0].listen, ":9444");
    assert_eq!(config.tls_listeners[0].client_auth, "required");
}

// ── Issue #22: TCP keepalive + streaming-aware read timeout ────────────────

#[test]
fn keepalive_defaults_are_enabled_with_issue22_values() {
    let proxy = ProxyConfig::default();
    assert_eq!(proxy.upstream_tcp_keepalive, "15s,5s,3");
    assert_eq!(proxy.downstream_tcp_keepalive, "15s,5s,3");
    assert_eq!(proxy.upstream_user_timeout, "30s");
    assert_eq!(proxy.stream_read_timeout, "3600s");
}

#[test]
fn parse_keepalive_parses_valid_spec() {
    let ka = ParsedKeepalive::parse("15s,5s,3", "30s").expect("valid spec");
    assert_eq!(ka.idle, Duration::from_secs(15));
    assert_eq!(ka.interval, Duration::from_secs(5));
    assert_eq!(ka.count, 3);
    assert_eq!(ka.user_timeout, Duration::from_secs(30));
}

#[test]
fn parse_keepalive_empty_disables() {
    assert_eq!(ParsedKeepalive::parse("", "30s"), None);
    assert_eq!(ParsedKeepalive::parse("   ", ""), None);
}

#[test]
fn parse_keepalive_empty_user_timeout_means_zero() {
    let ka = ParsedKeepalive::parse("15s,5s,3", "").expect("valid spec");
    assert_eq!(ka.user_timeout, Duration::ZERO);
}

#[test]
fn parse_keepalive_malformed_disables_gracefully() {
    // Wrong arity, bad duration, zero/non-numeric count all degrade to None.
    assert_eq!(ParsedKeepalive::parse("15s,5s", "30s"), None);
    assert_eq!(ParsedKeepalive::parse("abc,5s,3", "30s"), None);
    assert_eq!(ParsedKeepalive::parse("15s,5s,0", "30s"), None);
    assert_eq!(ParsedKeepalive::parse("15s,5s,x", "30s"), None);
}

#[test]
fn config_keepalive_accessors_use_proxy_fields() {
    let proxy = ProxyConfig {
        upstream_tcp_keepalive: "10s,2s,4".to_string(),
        upstream_user_timeout: "20s".to_string(),
        downstream_tcp_keepalive: String::new(),
        ..ProxyConfig::default()
    };
    let config = Config {
        server: ServerConfig {
            listen: ":9999".to_string(),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_users: Vec::new(),
            admin_token: String::new(),
            workers: 0,
            drain_timeout: "30s".to_string(),
        },
        consul: ConsulConfig {
            address: "127.0.0.1:8500".to_string(),
            scheme: "http".to_string(),
            token: String::new(),
            kv_prefix: "/sentirum-lb/routes".to_string(),
            tag_prefix: "urlprefix-".to_string(),
            poll_interval: "0s".to_string(),
            service_discovery: true,
            kv_watching: true,
            service_whitelist: Vec::new(),
            service_blacklist: Vec::new(),
            graceful_shutdown: true,
            include_warning: false,
        },
        proxy,
        logging: LoggingConfig::default(),
        tls: TlsConfig::default(),
        tls_listeners: Vec::new(),
        parsed_timeouts: Default::default(),
        tcp: TcpConfig::default(),
    };

    let up = config.upstream_keepalive().expect("upstream enabled");
    assert_eq!(up.idle, Duration::from_secs(10));
    assert_eq!(up.interval, Duration::from_secs(2));
    assert_eq!(up.count, 4);
    assert_eq!(up.user_timeout, Duration::from_secs(20));

    // Empty downstream spec disables keepalive.
    assert_eq!(config.downstream_keepalive(), None);
}

#[test]
fn validate_rejects_malformed_keepalive() {
    let proxy = ProxyConfig {
        upstream_tcp_keepalive: "15s,5s".to_string(),
        ..ProxyConfig::default()
    };
    let config = Config {
        server: ServerConfig {
            listen: ":9999".to_string(),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_users: Vec::new(),
            admin_token: String::new(),
            workers: 0,
            drain_timeout: "30s".to_string(),
        },
        consul: ConsulConfig {
            address: "127.0.0.1:8500".to_string(),
            scheme: "http".to_string(),
            token: String::new(),
            kv_prefix: "/sentirum-lb/routes".to_string(),
            tag_prefix: "urlprefix-".to_string(),
            poll_interval: "0s".to_string(),
            service_discovery: true,
            kv_watching: true,
            service_whitelist: Vec::new(),
            service_blacklist: Vec::new(),
            graceful_shutdown: true,
            include_warning: false,
        },
        proxy,
        logging: LoggingConfig::default(),
        tls: TlsConfig::default(),
        tls_listeners: Vec::new(),
        parsed_timeouts: Default::default(),
        tcp: TcpConfig::default(),
    };
    let error = config.validate().expect("malformed keepalive should fail");
    assert!(error.contains("proxy.upstream_tcp_keepalive"));
}

#[test]
fn validate_accepts_empty_keepalive_as_disabled() {
    let proxy = ProxyConfig {
        upstream_tcp_keepalive: String::new(),
        downstream_tcp_keepalive: String::new(),
        upstream_user_timeout: String::new(),
        stream_read_timeout: String::new(),
        ..ProxyConfig::default()
    };
    let config = Config {
        server: ServerConfig {
            listen: ":9999".to_string(),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_users: Vec::new(),
            admin_token: String::new(),
            workers: 0,
            drain_timeout: "30s".to_string(),
        },
        consul: ConsulConfig {
            address: "127.0.0.1:8500".to_string(),
            scheme: "http".to_string(),
            token: String::new(),
            kv_prefix: "/sentirum-lb/routes".to_string(),
            tag_prefix: "urlprefix-".to_string(),
            poll_interval: "0s".to_string(),
            service_discovery: true,
            kv_watching: true,
            service_whitelist: Vec::new(),
            service_blacklist: Vec::new(),
            graceful_shutdown: true,
            include_warning: false,
        },
        proxy,
        logging: LoggingConfig::default(),
        tls: TlsConfig::default(),
        tls_listeners: Vec::new(),
        parsed_timeouts: Default::default(),
        tcp: TcpConfig::default(),
    };
    assert!(
        config.validate().is_none(),
        "empty keepalive should be valid"
    );
}

#[test]
fn parsed_timeouts_includes_stream_read() {
    let proxy = ProxyConfig::default();
    let parsed = ParsedProxyTimeouts::from_proxy_config(&proxy);
    assert_eq!(parsed.stream_read, Some(Duration::from_secs(3600)));
}

#[test]
fn parsed_timeouts_caches_keepalive() {
    // Keepalive specs are parsed once into ParsedProxyTimeouts (F1: no
    // per-request parse/alloc), not re-parsed on every accessor call.
    let proxy = ProxyConfig::default();
    let parsed = ParsedProxyTimeouts::from_proxy_config(&proxy);
    let up = parsed.upstream_keepalive.expect("default enables upstream");
    assert_eq!(up.idle, Duration::from_secs(15));
    assert_eq!(up.interval, Duration::from_secs(5));
    assert_eq!(up.count, 3);
    assert_eq!(up.user_timeout, Duration::from_secs(30));
    let down = parsed
        .downstream_keepalive
        .expect("default enables downstream");
    assert_eq!(down.idle, Duration::from_secs(15));
    // Downstream has no user_timeout (listener sockets); ZERO = system default.
    assert_eq!(down.user_timeout, Duration::ZERO);
}

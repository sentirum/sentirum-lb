use crate::admin::api::AdminState;
use crate::admin::logs::LogBuffer;
use crate::admin::topology_flow::TopologyFlowCache;
use crate::config::{
    AdminUser, Config, ConsulConfig, LoggingConfig, ProxyConfig, ServerConfig, SharedConfig,
    TcpConfig, TlsConfig, shared_config,
};
use crate::route::registry::ManagedRouteTable;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub fn base_test_config() -> Config {
    Config {
        server: ServerConfig {
            listen: ":9999".to_string(),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_token: String::new(),
            admin_users: Vec::new(),
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
            service_discovery: false,
            kv_watching: false,
            service_whitelist: Vec::new(),
            service_blacklist: Vec::new(),
            graceful_shutdown: true,
            include_warning: false,
        },
        proxy: ProxyConfig::default(),
        logging: LoggingConfig::default(),
        tls: TlsConfig::default(),
        tls_listeners: Vec::new(),
        tcp: TcpConfig::default(),
        parsed_timeouts: Default::default(),
    }
}

pub fn shared_test_config() -> SharedConfig {
    shared_config(base_test_config())
}

pub fn shared_test_config_with(update: impl FnOnce(&mut Config)) -> SharedConfig {
    let mut config = base_test_config();
    update(&mut config);
    shared_config(config)
}

pub fn with_admin_auth(config: &mut Config, admin_token: &str, admin_users: Vec<AdminUser>) {
    config.server.admin_token = admin_token.to_string();
    config.server.admin_users = admin_users;
}

pub fn tcp_shared_test_config() -> SharedConfig {
    shared_test_config_with(|config| {
        config.server.drain_timeout.clear();
        config.consul.service_discovery = true;
        config.consul.kv_watching = true;
    })
}

pub fn admin_test_state(route_table: Arc<ManagedRouteTable>) -> AdminState {
    admin_test_state_with(route_table, |_| {})
}

pub fn admin_test_state_with(
    route_table: Arc<ManagedRouteTable>,
    update: impl FnOnce(&mut Config),
) -> AdminState {
    let config = shared_test_config_with(update);
    let startup_config = Arc::clone(&config.load());
    AdminState {
        config,
        startup_config,
        route_table,
        tls_store: None,
        client_ca_store: None,
        log_buffer: None,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        login_attempts: Arc::new(dashmap::DashMap::new()),
        file_certs: Vec::new(),
        topology_flow_cache: Arc::new(TopologyFlowCache::new()),
        metrics_stream_tx: Arc::new(RwLock::new(None)),
    }
}

pub fn admin_test_state_with_logs(
    route_table: Arc<ManagedRouteTable>,
    log_buffer: Arc<LogBuffer>,
) -> AdminState {
    let mut state = admin_test_state(route_table);
    state.log_buffer = Some(log_buffer);
    state
}

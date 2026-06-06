use arc_swap::ArcSwap;
use async_trait::async_trait;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::mpsc;

use pingora::services::background::{BackgroundService, background_service};
use sentirum_lb::config::Config;
use sentirum_lb::consul::{ConsulClient, ConsulConfig, ConsulWatcher, RouteUpdate};
use sentirum_lb::proxy::handler::SentirumProxy;
use sentirum_lb::proxy::tcp::{TcpBackgroundService, TcpMode};
use sentirum_lb::proxy::tls::{
    ClientAuthConfig, ClientAuthMode, ClientCaSource, DynamicCertStore, DynamicClientCaStore,
    FileCertWatcherService, TlsMode, build_static_tls_settings, build_tls_settings,
    load_shareable_cert, tls_listen_addr,
};
use sentirum_lb::route::parser::parse_route_commands;
use sentirum_lb::route::registry::ManagedRouteTable;

/// Sentirum LB -- High-performance Rust load balancer with Consul integration
#[derive(Parser, Debug)]
#[command(
    name = "sentirum-lb",
    version,
    about = "High-performance Rust load balancer with Consul integration"
)]
struct Args {
    /// Optional path to configuration file (TOML)
    #[arg(short, long)]
    config: Option<String>,

    /// Path to static routes file
    #[arg(short, long)]
    routes: Option<String>,

    /// Listen address (overrides config)
    #[arg(short, long)]
    listen: Option<String>,

    /// Consul address (overrides config)
    #[arg(long)]
    consul: Option<String>,

    /// Log level (overrides config)
    #[arg(long)]
    log_level: Option<String>,
}

fn init_logging(config: &Config) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry, fmt};

    let level = config.logging.level.clone();
    let format = config.logging.format.clone();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&level));
    let log_buffer = sentirum_lb::admin::logs::global_log_buffer();
    let capture_layer = sentirum_lb::admin::logs::LogCaptureLayer::new(log_buffer);

    if format == "json" {
        Registry::default()
            .with(fmt::layer().json())
            .with(capture_layer)
            .with(env_filter)
            .init();
    } else {
        Registry::default()
            .with(fmt::layer().pretty())
            .with(capture_layer)
            .with(env_filter)
            .init();
    }
}

fn load_static_routes(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    tracing::info!(path, "Loading static routes file");
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}

fn allocate_loopback_listen_addr() -> Result<String, std::io::Error> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    Ok(addr.to_string())
}

/// Handle route updates from Consul watcher
async fn route_update_handler(
    route_table: Arc<ManagedRouteTable>,
    mut rx: mpsc::Receiver<RouteUpdate>,
) {
    while let Some(update) = rx.recv().await {
        match update {
            RouteUpdate::Services(defs) => {
                if defs.is_empty() {
                    tracing::warn!(
                        "No service-based routes available from Consul; clearing service routes"
                    );
                } else {
                    tracing::info!(count = defs.len(), "Applying service-based routes");
                }
                route_table.update_services(defs);
            }
            RouteUpdate::Manual(content) => {
                let defs = parse_route_commands(&content);
                if defs.is_empty() {
                    tracing::warn!("No manual KV routes available from Consul; clearing KV routes");
                } else {
                    tracing::info!(count = defs.len(), "Applied manual routes");
                }
                route_table.update_kv(defs);
            }
            RouteUpdate::Error(e) => {
                tracing::error!(error = %e, "Consul watcher error");
            }
        }
    }
}

struct ConsulBackgroundService {
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
}

#[async_trait]
impl BackgroundService for ConsulBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        if !(self.config.consul.service_discovery || self.config.consul.kv_watching) {
            tracing::info!("Consul watching disabled, skipping background service");
            return;
        }

        let consul_config = ConsulConfig::from(&self.config.consul);
        let client = match ConsulClient::new(consul_config.clone()) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create Consul client");
                return;
            }
        };

        let watcher = ConsulWatcher::new(Arc::new(client), consul_config).with_flags(
            self.config.consul.service_discovery,
            self.config.consul.kv_watching,
        );
        let (tx, rx) = mpsc::channel(100);
        let route_table = self.route_table.clone();

        tracing::info!("Consul watcher started");

        tokio::select! {
            _ = async {
                tokio::join!(
                    route_update_handler(route_table, rx),
                    watcher.run(tx),
                );
            } => {}
            _ = shutdown.changed() => {
                tracing::info!("Consul background service shutting down");
            }
        }
    }
}

struct ConsulTlsBackgroundService {
    tls_store: Arc<DynamicCertStore>,
    consul_config: sentirum_lb::consul::ConsulConfig,
    cert_prefix: String,
    initial_index: u64,
}

#[async_trait]
impl BackgroundService for ConsulTlsBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let client = match ConsulClient::new(self.consul_config.clone()) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create Consul client for TLS certificate watcher");
                return;
            }
        };

        let mut last_index = self.initial_index;
        let mut backoff_secs: u64 = 1;
        let metrics = sentirum_lb::metrics::prometheus::global();
        metrics.set_consul_watcher_backoff_seconds("tls", 0);
        metrics.set_consul_watcher_last_index("tls", last_index);
        tracing::info!(prefix = %self.cert_prefix, "Consul TLS certificate watcher started");

        loop {
            let result = tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("Consul TLS certificate watcher shutting down");
                    break;
                }
                result = self.tls_store.refresh_from_consul(&client, &self.cert_prefix, last_index) => result,
            };

            match result {
                Ok(new_index) => {
                    backoff_secs = 1;
                    last_index = new_index;
                    metrics.set_consul_watcher_backoff_seconds("tls", 0);
                    metrics.set_consul_watcher_last_index("tls", new_index);
                }
                Err(e) => {
                    metrics.record_consul_watcher_error("tls");
                    metrics.set_consul_watcher_backoff_seconds("tls", backoff_secs);
                    tracing::warn!(
                        prefix = %self.cert_prefix,
                        backoff_secs,
                        error = %e,
                        "Consul TLS certificate watcher error; retrying"
                    );
                    tokio::select! {
                        _ = shutdown.changed() => {
                            tracing::info!("Consul TLS certificate watcher shutting down");
                            break;
                        }
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)) => {}
                    }
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    }
}

struct ConsulClientCaBackgroundService {
    client_ca_store: Arc<DynamicClientCaStore>,
    consul_config: sentirum_lb::consul::ConsulConfig,
    cert_prefix: String,
    initial_index: u64,
}

#[async_trait]
impl BackgroundService for ConsulClientCaBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let client = match ConsulClient::new(self.consul_config.clone()) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create Consul client for client CA watcher");
                return;
            }
        };

        let mut last_index = self.initial_index;
        let mut backoff_secs: u64 = 1;
        let metrics = sentirum_lb::metrics::prometheus::global();
        metrics.set_consul_watcher_backoff_seconds("client_ca", 0);
        metrics.set_consul_watcher_last_index("client_ca", last_index);
        tracing::info!(prefix = %self.cert_prefix, "Consul client CA watcher started");

        loop {
            let result = tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("Consul client CA watcher shutting down");
                    break;
                }
                result = self.client_ca_store.refresh_from_consul(&client, &self.cert_prefix, last_index) => result,
            };

            match result {
                Ok(new_index) => {
                    backoff_secs = 1;
                    last_index = new_index;
                    metrics.set_consul_watcher_backoff_seconds("client_ca", 0);
                    metrics.set_consul_watcher_last_index("client_ca", new_index);
                }
                Err(e) => {
                    metrics.record_consul_watcher_error("client_ca");
                    metrics.set_consul_watcher_backoff_seconds("client_ca", backoff_secs);
                    tracing::warn!(
                        prefix = %self.cert_prefix,
                        backoff_secs,
                        error = %e,
                        "Consul client CA watcher error; retrying"
                    );
                    tokio::select! {
                        _ = shutdown.changed() => {
                            tracing::info!("Consul client CA watcher shutting down");
                            break;
                        }
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)) => {}
                    }
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    }
}

struct AdminBackgroundService {
    config: sentirum_lb::config::SharedConfig,
    route_table: Arc<ManagedRouteTable>,
    tls_store: Option<Arc<DynamicCertStore>>,
    client_ca_store: Option<Arc<DynamicClientCaStore>>,
    log_buffer: Option<Arc<sentirum_lb::admin::logs::LogBuffer>>,
    file_certs: Vec<(
        String,
        sentirum_lb::proxy::tls::SharedFileCert,
        sentirum_lb::proxy::tls::TlsCertConfig,
    )>,
    trusted_proxies: Arc<ArcSwap<Vec<sentirum_lb::proxy::handler::CidrRange>>>,
}

struct HealthCheckBackgroundService {
    route_table: Arc<ManagedRouteTable>,
    config: sentirum_lb::config::SharedConfig,
}

#[async_trait]
impl BackgroundService for AdminBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        tokio::select! {
            _ = sentirum_lb::admin::run_admin_server(
                self.config.clone(),
                self.route_table.clone(),
                self.tls_store.clone(),
                self.client_ca_store.clone(),
                self.log_buffer.clone(),
                self.file_certs.clone(),
                self.trusted_proxies.clone(),
            ) => {}
            _ = shutdown.changed() => {
                tracing::info!("Admin background service shutting down");
            }
        }
    }
}

#[async_trait]
impl BackgroundService for HealthCheckBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        tokio::select! {
            _ = sentirum_lb::proxy::health::run_health_checks(
                self.route_table.clone(),
                self.config.clone(),
            ) => {}
            _ = shutdown.changed() => {
                tracing::info!("Health check background service shutting down");
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    // Load configuration
    let config_content = match args.config.as_ref() {
        Some(config_path) => match std::fs::read_to_string(config_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Error: failed to load config file '{}': {}", config_path, e);
                std::process::exit(1);
            }
        },
        None => String::new(),
    };

    let mut config: Config = if config_content.is_empty() {
        let server = sentirum_lb::config::ServerConfig {
            listen: args.listen.clone().unwrap_or_else(|| ":9999".to_string()),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_token: String::new(),
            admin_users: vec![],
            workers: 0,
            drain_timeout: "30s".to_string(),
        };
        let consul = sentirum_lb::config::ConsulConfig {
            address: args
                .consul
                .clone()
                .unwrap_or_else(|| "127.0.0.1:8500".to_string()),
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
        };
        Config {
            server,
            consul,
            proxy: sentirum_lb::config::ProxyConfig::default(),
            logging: sentirum_lb::config::LoggingConfig::default(),
            tls: sentirum_lb::config::TlsConfig::default(),
            tls_listeners: Vec::new(),
            tcp: sentirum_lb::config::TcpConfig::default(),
            parsed_timeouts: Default::default(),
        }
    } else {
        match toml::from_str::<Config>(&config_content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error: failed to parse config file: {e}");
                std::process::exit(1);
            }
        }
    };

    // Apply CLI overrides
    if let Some(listen) = &args.listen {
        config.server.listen = listen.clone();
    }

    if let Some(consul) = &args.consul {
        config.consul.address = consul.clone();
    }
    if let Some(log_level) = &args.log_level {
        config.logging.level = log_level.clone();
    }

    // Validate configuration
    if let Some(validation_error) = config.validate() {
        eprintln!("Config validation failed: {}", validation_error);
        std::process::exit(1);
    }

    // Initialize logging
    init_logging(&config);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %config.server.listen,
        consul = %config.consul.address,
        "Starting Sentirum LB"
    );

    // Apply DNS cache TTL from config to the global singleton
    sentirum_lb::route::target::global_dns_cache().set_ttl(
        config.proxy.dns_cache_ttl,
        config.proxy.dns_negative_cache_ttl,
    );

    // Create managed routing table (supports multiple sources)
    let managed_table = if config.proxy.circuit_breaker_enabled {
        let cb_config = sentirum_lb::route::target::CircuitBreakerConfig {
            error_threshold: config.proxy.circuit_breaker_error_threshold,
            window_size: config.proxy.circuit_breaker_window_size,
            recovery_timeout_secs: config.proxy.circuit_breaker_recovery_timeout,
            half_open_max_requests: config.proxy.circuit_breaker_half_open_max,
        };
        Arc::new(ManagedRouteTable::new_with_cb_config(cb_config))
    } else {
        Arc::new(ManagedRouteTable::new())
    };

    // Load static routes if provided (loaded FIRST, highest priority)
    if let Some(routes_path) = &args.routes {
        match load_static_routes(routes_path) {
            Ok(content) => {
                let defs = parse_route_commands(&content);
                tracing::info!(count = defs.len(), "Loaded static route definitions");
                managed_table.load_static(&defs);
            }
            Err(e) => {
                tracing::error!(path = routes_path, error = %e, "Failed to load static routes");
            }
        }
    }

    let mut tcp_mode = match sentirum_lb::proxy::tcp::resolve_tcp_mode(&config) {
        Ok(mode) => mode,
        Err(error) => {
            tracing::error!(%error, "Invalid TCP configuration; TCP proxy disabled");
            TcpMode::Disabled
        }
    };
    let public_tls_listen = tls_listen_addr(&config.server.listen, &config.tls.listen);
    let mut tcp_https_fallback_addr = None;
    if tcp_mode == TcpMode::HttpsTcpSni {
        match allocate_loopback_listen_addr() {
            Ok(addr) => tcp_https_fallback_addr = Some(addr),
            Err(error) => {
                tracing::error!(%error, "Failed to allocate internal HTTPS fallback listener; disabling https+tcp+sni mode");
                tcp_mode = TcpMode::Disabled;
            }
        }
    }

    // ── Pingora Server Setup ────────────────────────────────────────────────
    let mut server =
        pingora::server::Server::new(Some(pingora::server::configuration::Opt::default()))
            .expect("Failed to create Pingora server");

    if let Some(server_conf) = Arc::get_mut(&mut server.configuration) {
        if config.server.workers > 0 {
            server_conf.threads = config.server.workers;
        }
        server_conf.upstream_keepalive_pool_size = config.proxy.pool_size;

        // Wire graceful shutdown: drain_timeout gives in-flight requests time
        // to complete before the server exits. Pingora uses two phases:
        //   1. grace_period_seconds: stop accepting new connections, wait for active ones
        //   2. graceful_shutdown_timeout_seconds: hard deadline for tokio runtimes to exit
        let drain_secs =
            sentirum_lb::config::Config::parse_duration(&config.server.drain_timeout).as_secs();
        if config.consul.graceful_shutdown && drain_secs > 0 {
            server_conf.grace_period_seconds = Some(drain_secs);
            server_conf.graceful_shutdown_timeout_seconds = Some(5);
            tracing::info!(
                drain_timeout_secs = drain_secs,
                "Graceful shutdown enabled — in-flight requests will have {}s to complete",
                drain_secs
            );
        }
    } else {
        tracing::warn!("Could not mutate Pingora server configuration before bootstrap");
    }
    server.bootstrap();

    // Temporary single-threaded runtime for initial Consul loads.
    // This is safe because Pingora's own runtime has not started yet —
    // `run_forever()` is called at the end of main().
    let init_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create initialisation runtime");

    // Create proxy service
    let runtime_config = sentirum_lb::config::shared_config(config.clone());
    let trusted_proxies_arc = sentirum_lb::proxy::handler::parse_trusted_proxies(
        &runtime_config.load().proxy.trusted_proxies,
    );
    let proxy_handler = SentirumProxy::new(
        managed_table.clone(),
        runtime_config.clone(),
        trusted_proxies_arc.clone(),
    );
    let mut lb_service = pingora::proxy::http_proxy_service(&server.configuration, proxy_handler);
    if config.server.workers > 0 {
        lb_service.threads = Some(config.server.workers);
    }
    if let Some(app) = lb_service.app_logic_mut() {
        let mut server_options = pingora::apps::HttpServerOptions::default();
        server_options.h2c = config.proxy.enable_h2c;
        app.server_options = Some(server_options);
    }
    // Downstream (edge/CDN → LB) TCP keepalive on accepted connections (Issue
    // #22). Applied to the plaintext listener and, below, to every TLS
    // listener so silently-dead downstream connections are probed/closed
    // instead of lingering as corpses.
    let downstream_sock_opts = sentirum_lb::proxy::keepalive::downstream_socket_options(&config);
    match downstream_sock_opts.as_ref() {
        Some(opts) => lb_service.add_tcp_with_settings(&config.server.listen, opts.clone()),
        None => lb_service.add_tcp(&config.server.listen),
    }

    tracing::info!(
        addr = %config.server.listen,
        workers = config.server.workers,
        pool_size = config.proxy.pool_size,
        max_connections = config.proxy.max_connections,
        h2c_enabled = config.proxy.enable_h2c,
        downstream_keepalive = downstream_sock_opts.is_some(),
        "Proxy listening (HTTP)"
    );

    // ── TLS Listener Setup ──────────────────────────────────────────────────
    // Collect TLS background services for all listeners
    let mut tls_background_services: Vec<ConsulTlsBackgroundService> = Vec::new();
    let mut client_ca_background_services: Vec<ConsulClientCaBackgroundService> = Vec::new();
    let mut file_cert_watchers: Vec<FileCertWatcherService> = Vec::new();
    let mut file_cert_handles: Vec<(
        String,
        sentirum_lb::proxy::tls::SharedFileCert,
        sentirum_lb::proxy::tls::TlsCertConfig,
    )> = Vec::new();
    let mut tls_stores_for_admin: Vec<Arc<DynamicCertStore>> = Vec::new();
    let mut client_ca_stores_for_admin: Vec<Arc<DynamicClientCaStore>> = Vec::new();
    let mut https_fallback_ready = false;

    // Build the list of all TLS configs to process.
    // The legacy [tls] section is always the first (primary) listener.
    // [[tls_listeners]] entries are additional listeners.
    let all_tls_configs: Vec<(String, &sentirum_lb::config::TlsConfig)> =
        std::iter::once(("primary".to_string(), &config.tls))
            .chain(
                config
                    .tls_listeners
                    .iter()
                    .enumerate()
                    .map(|(i, tls_cfg)| (format!("tls_listeners[{i}]"), tls_cfg)),
            )
            .collect();

    let primary_tls_listen = public_tls_listen.clone();

    for (label, tls_cfg) in &all_tls_configs {
        let is_primary = label == "primary";

        // Resolve listen address for this listener
        let tls_listen = if is_primary {
            tcp_https_fallback_addr
                .clone()
                .unwrap_or_else(|| primary_tls_listen.clone())
        } else if tls_cfg.listen.trim().is_empty() {
            tracing::error!(
                listener = %label,
                "additional TLS listener must have a non-empty listen address"
            );
            continue;
        } else {
            tls_listen_addr(&config.server.listen, &tls_cfg.listen)
        };

        // Resolve client auth for this listener
        let client_auth_config = match ClientAuthConfig::resolve(tls_cfg) {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(listener = %label, %error, "Invalid mTLS configuration; skipping listener");
                if is_primary {
                    std::process::exit(1);
                }
                continue;
            }
        };

        let mut client_auth_state: Option<(ClientAuthMode, Arc<DynamicClientCaStore>)> = None;
        if let Some(client_auth) = client_auth_config.clone() {
            let client_ca_store =
                Arc::new(DynamicClientCaStore::new(client_auth.ca_upgrade_cn.clone()));
            match &client_auth.source {
                ClientCaSource::File { path } => {
                    if let Err(error) = client_ca_store.load_from_path(path) {
                        tracing::error!(listener = %label, path = %path, %error, "Failed to load initial client CA set");
                        if is_primary {
                            std::process::exit(1);
                        }
                        continue;
                    }
                    let status = client_ca_store.status();
                    tracing::info!(
                        listener = %label,
                        path = %path,
                        mode = ?client_auth.mode,
                        entries = ?status.loaded_entries,
                        "Loaded initial client CA set from filesystem"
                    );
                }
                ClientCaSource::ConsulKv { prefix } => {
                    let consul_config = ConsulConfig::for_tls_cert_watch(&config.consul);
                    let mut initial_index = 0;
                    let mut initial_snapshot_ready = false;

                    match ConsulClient::new(consul_config.clone()) {
                        Ok(client) => match init_runtime
                            .block_on(client_ca_store.refresh_from_consul(&client, prefix, 0))
                        {
                            Ok(index) => {
                                initial_index = index;
                                let status = client_ca_store.status();
                                initial_snapshot_ready = !status.loaded_entries.is_empty();
                                if initial_snapshot_ready {
                                    tracing::info!(
                                        listener = %label,
                                        prefix = %prefix,
                                        initial_index,
                                        mode = ?client_auth.mode,
                                        entries = ?status.loaded_entries,
                                        "Loaded initial client CA snapshot from Consul"
                                    );
                                } else {
                                    tracing::warn!(
                                        listener = %label,
                                        prefix = %prefix,
                                        initial_index,
                                        last_error = ?status.last_error,
                                        "Initial Consul client CA snapshot did not yield any active CA entries"
                                    );
                                }
                            }
                            Err(error) => {
                                tracing::warn!(listener = %label, prefix = %prefix, error = %error, "Initial Consul client CA load failed");
                            }
                        },
                        Err(error) => {
                            tracing::warn!(listener = %label, error = %error, "Failed to create Consul client for initial client CA load");
                        }
                    }

                    if !initial_snapshot_ready {
                        tracing::error!(listener = %label, prefix = %prefix, mode = ?client_auth.mode, "Initial client CA snapshot is required but unavailable");
                        if is_primary {
                            std::process::exit(1);
                        }
                        continue;
                    }

                    client_ca_background_services.push(ConsulClientCaBackgroundService {
                        client_ca_store: client_ca_store.clone(),
                        consul_config,
                        cert_prefix: prefix.clone(),
                        initial_index,
                    });
                }
            }

            client_ca_stores_for_admin.push(client_ca_store.clone());
            client_auth_state = Some((client_auth.mode, client_ca_store));
        }

        // Configure TLS certificate source and add listener
        match TlsMode::resolve(tls_cfg) {
            Ok(Some(TlsMode::File(tls))) => match tls.validate() {
                Ok(()) => {
                    let cert = match load_shareable_cert(&tls) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!(listener = %label, error = %e, "Failed to load file certificate");
                            continue;
                        }
                    };
                    match build_static_tls_settings(cert.clone(), client_auth_state.clone()) {
                        Ok(mut settings) => {
                            if tls_cfg.http2 {
                                settings.enable_h2();
                            }
                            lb_service.add_tls_with_settings(
                                &tls_listen,
                                downstream_sock_opts.clone(),
                                settings,
                            );
                            tracing::info!(
                                listener = %label,
                                addr = %tls_listen,
                                source = "file",
                                downstream_keepalive = downstream_sock_opts.is_some(),
                                client_auth = client_auth_config.as_ref().map(|cfg| format!("{:?}", cfg.mode).to_lowercase()).unwrap_or_else(|| "off".to_string()),
                                h2_enabled = tls_cfg.http2,
                                "Proxy listening (HTTPS/TLS)"
                            );
                            if is_primary {
                                https_fallback_ready = true;
                            }
                            // Register file cert watcher for hot-reload
                            file_cert_watchers.push(FileCertWatcherService::new(
                                label.clone(),
                                tls.clone(),
                                cert.clone(),
                                std::time::Duration::from_secs(30),
                            ));
                            // Expose to admin API for manual reload
                            file_cert_handles.push((label.clone(), cert, tls));
                        }
                        Err(e) => {
                            tracing::error!(listener = %label, error = %e, "Failed to configure file-based TLS listener");
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(listener = %label, error = %e, "TLS configuration invalid, skipping");
                }
            },
            Ok(Some(TlsMode::ConsulKv(consul_tls))) => {
                let tls_store = Arc::new(DynamicCertStore::new(consul_tls.strict_sni));
                let consul_config = ConsulConfig::for_tls_cert_watch(&config.consul);
                let mut initial_index = 0;
                let mut initial_snapshot_ready = false;

                match ConsulClient::new(consul_config.clone()) {
                    Ok(client) => {
                        match init_runtime.block_on(tls_store.refresh_from_consul(
                            &client,
                            &consul_tls.cert_prefix,
                            0,
                        )) {
                            Ok(index) => {
                                initial_index = index;
                                let status = tls_store.status();
                                initial_snapshot_ready = !status.loaded_certificates.is_empty();
                                if initial_snapshot_ready {
                                    tracing::info!(
                                        listener = %label,
                                        prefix = %consul_tls.cert_prefix,
                                        initial_index,
                                        strict_sni = consul_tls.strict_sni,
                                        certificates = ?status.loaded_certificates,
                                        "Loaded initial TLS certificate snapshot from Consul"
                                    );
                                } else {
                                    tracing::warn!(
                                        listener = %label,
                                        prefix = %consul_tls.cert_prefix,
                                        initial_index,
                                        strict_sni = consul_tls.strict_sni,
                                        require_initial_snapshot = consul_tls.require_initial_snapshot,
                                        last_error = ?status.last_error,
                                        "Initial Consul TLS snapshot did not yield any active certificates"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    listener = %label,
                                    prefix = %consul_tls.cert_prefix,
                                    require_initial_snapshot = consul_tls.require_initial_snapshot,
                                    error = %e,
                                    "Initial Consul TLS certificate load failed"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            listener = %label,
                            error = %e,
                            "Failed to create Consul client for initial TLS certificate load"
                        );
                    }
                }

                if consul_tls.require_initial_snapshot && !initial_snapshot_ready {
                    tracing::error!(
                        listener = %label,
                        prefix = %consul_tls.cert_prefix,
                        strict_sni = consul_tls.strict_sni,
                        "Initial Consul TLS snapshot is required but unavailable"
                    );
                    if is_primary {
                        std::process::exit(1);
                    }
                    continue;
                }

                match build_tls_settings(tls_store.clone(), client_auth_state.clone()) {
                    Ok(mut settings) => {
                        if tls_cfg.http2 {
                            settings.enable_h2();
                        }
                        lb_service.add_tls_with_settings(
                            &tls_listen,
                            downstream_sock_opts.clone(),
                            settings,
                        );
                        tracing::info!(
                            listener = %label,
                            addr = %tls_listen,
                            source = "consul_kv",
                            downstream_keepalive = downstream_sock_opts.is_some(),
                            prefix = %consul_tls.cert_prefix,
                            strict_sni = consul_tls.strict_sni,
                            client_auth = client_auth_config.as_ref().map(|cfg| format!("{:?}", cfg.mode).to_lowercase()).unwrap_or_else(|| "off".to_string()),
                            h2_enabled = tls_cfg.http2,
                            "Proxy listening (HTTPS/TLS)"
                        );
                        if is_primary {
                            https_fallback_ready = true;
                        }
                        tls_stores_for_admin.push(tls_store.clone());
                        tls_background_services.push(ConsulTlsBackgroundService {
                            tls_store,
                            consul_config,
                            cert_prefix: consul_tls.cert_prefix,
                            initial_index,
                        });
                    }
                    Err(e) => {
                        tracing::error!(
                            listener = %label,
                            error = %e,
                            "Failed to configure Consul-backed TLS listener"
                        );
                    }
                }
            }
            Ok(None) => {
                // No TLS configured for this listener — skip silently for primary
                // (it may just not have TLS configured at all).
            }
            Err(e) => {
                tracing::error!(listener = %label, error = %e, "Invalid TLS source configuration; skipping");
            }
        }
    }

    server.add_service(lb_service);

    // ── Background Services ─────────────────────────────────────────────────

    let service_config = Arc::new(config.clone());
    let shared_config = runtime_config.clone();
    let consul_enabled =
        service_config.consul.service_discovery || service_config.consul.kv_watching;

    if consul_enabled {
        let mut consul_service = background_service(
            "consul watcher",
            ConsulBackgroundService {
                route_table: managed_table.clone(),
                config: service_config.clone(),
            },
        );
        consul_service.threads = Some(1);
        server.add_service(consul_service);
    }

    for tls_service_cfg in tls_background_services {
        let mut tls_service = background_service("tls cert watcher", tls_service_cfg);
        tls_service.threads = Some(1);
        server.add_service(tls_service);
    }

    for client_ca_service_cfg in client_ca_background_services {
        let mut client_ca_service = background_service("client ca watcher", client_ca_service_cfg);
        client_ca_service.threads = Some(1);
        server.add_service(client_ca_service);
    }

    for file_cert_watcher in file_cert_watchers {
        let mut cert_service = background_service("file cert watcher", file_cert_watcher);
        cert_service.threads = Some(1);
        server.add_service(cert_service);
    }

    if tcp_mode == TcpMode::HttpsTcpSni && !https_fallback_ready {
        tracing::error!(
            "https+tcp+sni mode requested but HTTPS fallback listener was not configured; disabling TCP proxy mode"
        );
        tcp_mode = TcpMode::Disabled;
    }

    if tcp_mode != TcpMode::Disabled {
        let mut tcp_service = background_service(
            "tcp proxy",
            TcpBackgroundService {
                route_table: managed_table.clone(),
                config: shared_config.clone(),
                mode: tcp_mode.clone(),
                https_fallback_addr: tcp_https_fallback_addr.clone(),
            },
        );
        tcp_service.threads = Some(1);
        server.add_service(tcp_service);
    }

    let mut admin_service = background_service(
        "admin api",
        AdminBackgroundService {
            config: shared_config,
            route_table: managed_table.clone(),
            tls_store: tls_stores_for_admin.first().cloned(),
            client_ca_store: client_ca_stores_for_admin.first().cloned(),
            log_buffer: Some(sentirum_lb::admin::logs::global_log_buffer()),
            file_certs: file_cert_handles.clone(),
            trusted_proxies: trusted_proxies_arc,
        },
    );
    admin_service.threads = Some(1);
    server.add_service(admin_service);

    // Health check background service
    {
        let interval = sentirum_lb::config::Config::parse_duration(
            &service_config.proxy.health_check_interval,
        );
        if !interval.is_zero() {
            let mut health_service = background_service(
                "health checker",
                HealthCheckBackgroundService {
                    route_table: managed_table.clone(),
                    config: runtime_config.clone(),
                },
            );
            health_service.threads = Some(1);
            server.add_service(health_service);
        }
    }

    tracing::info!("Sentirum LB is ready");
    server.run_forever();
}

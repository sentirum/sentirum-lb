use async_trait::async_trait;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::mpsc;

use pingora::services::background::{BackgroundService, background_service};
use sentirum_lb::config::Config;
use sentirum_lb::consul::{ConsulClient, ConsulConfig, ConsulWatcher, RouteUpdate};
use sentirum_lb::proxy::handler::SentirumProxy;
use sentirum_lb::proxy::tls::{DynamicCertStore, TlsMode, build_dynamic_tls_settings, tls_listen_addr};
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
    use tracing_subscriber::{EnvFilter, fmt};

    let level = config.logging.level.clone();
    let format = config.logging.format.clone();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&level));

    if format == "json" {
        fmt().with_env_filter(env_filter).json().init();
    } else {
        fmt().pretty().with_env_filter(env_filter).init();
    }
}

fn load_static_routes(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    tracing::info!(path, "Loading static routes file");
    let content = std::fs::read_to_string(path)?;
    Ok(content)
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
                }
                Err(e) => {
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

struct AdminBackgroundService {
    config: Arc<Config>,
    route_table: Arc<ManagedRouteTable>,
}

#[async_trait]
impl BackgroundService for AdminBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        tokio::select! {
            _ = sentirum_lb::admin::run_admin_server(self.config.clone(), self.route_table.clone()) => {}
            _ = shutdown.changed() => {
                tracing::info!("Admin background service shutting down");
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
            workers: 0,
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
        };
        Config {
            server,
            consul,
            proxy: sentirum_lb::config::ProxyConfig::default(),
            logging: sentirum_lb::config::LoggingConfig::default(),
            tls: sentirum_lb::config::TlsConfig::default(),
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

    // Initialize logging
    init_logging(&config);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %config.server.listen,
        consul = %config.consul.address,
        "Starting Sentirum LB"
    );

    // Create managed routing table (supports multiple sources)
    let managed_table = Arc::new(ManagedRouteTable::new());

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

    // Build Pingora server
    let mut server =
        pingora::server::Server::new(Some(pingora::server::configuration::Opt::default()))
            .expect("Failed to create Pingora server");

    if let Some(server_conf) = Arc::get_mut(&mut server.configuration) {
        if config.server.workers > 0 {
            server_conf.threads = config.server.workers;
        }
        server_conf.upstream_keepalive_pool_size = config.proxy.pool_size;
    } else {
        tracing::warn!("Could not mutate Pingora server configuration before bootstrap");
    }
    server.bootstrap();

    // Create proxy service
    let proxy_handler = SentirumProxy::new(managed_table.clone(), Arc::new(config.clone()));
    let mut lb_service = pingora::proxy::http_proxy_service(&server.configuration, proxy_handler);
    if config.server.workers > 0 {
        lb_service.threads = Some(config.server.workers);
    }
    if let Some(app) = lb_service.app_logic_mut() {
        let mut server_options = pingora::apps::HttpServerOptions::default();
        server_options.h2c = config.proxy.enable_h2c;
        app.server_options = Some(server_options);
    }
    lb_service.add_tcp(&config.server.listen);

    tracing::info!(
        addr = %config.server.listen,
        workers = config.server.workers,
        pool_size = config.proxy.pool_size,
        max_connections = config.proxy.max_connections,
        h2c_enabled = config.proxy.enable_h2c,
        "Proxy listening (HTTP)"
    );

    // Add TLS listener if configured
    let tls_cert_config: Option<sentirum_lb::proxy::tls::TlsCertConfig> = (&config.tls).into();
    if let Some(tls) = &tls_cert_config {
        match tls.validate() {
            Ok(()) => {
                // Use explicit TLS listen address, or derive from HTTP port +1
                let tls_listen = if config.tls.listen.is_empty() {
                    let http_port: u16 = config
                        .server
                        .listen
                        .rsplit(':')
                        .next()
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(9999);
                    format!(":{}", http_port + 1)
                } else {
                    config.tls.listen.clone()
                };

                match pingora::listeners::tls::TlsSettings::intermediate(
                    &tls.cert_path,
                    &tls.key_path,
                ) {
                    Ok(mut settings) => {
                        settings.enable_h2();
                        lb_service.add_tls_with_settings(&tls_listen, None, settings);
                        tracing::info!(addr = %tls_listen, h2_enabled = true, "Proxy listening (HTTPS/TLS)");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to configure TLS listener");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "TLS configuration invalid, skipping HTTPS listener");
            }
        }
    }

    server.add_service(lb_service);

    let shared_config = Arc::new(config.clone());

    if config.consul.service_discovery || config.consul.kv_watching {
        let mut consul_service = background_service(
            "consul watcher",
            ConsulBackgroundService {
                route_table: managed_table.clone(),
                config: shared_config.clone(),
            },
        );
        consul_service.threads = Some(1);
        server.add_service(consul_service);
    }

    let mut admin_service = background_service(
        "admin api",
        AdminBackgroundService {
            config: shared_config,
            route_table: managed_table.clone(),
        },
    );
    admin_service.threads = Some(1);
    server.add_service(admin_service);

    tracing::info!("Sentirum LB is ready");
    server.run_forever();
}

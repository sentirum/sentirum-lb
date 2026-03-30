use clap::Parser;
use std::sync::Arc;
use tokio::sync::mpsc;

use sentirum_lb::config::Config;
use sentirum_lb::consul::{ConsulClient, ConsulConfig, ConsulWatcher, RouteUpdate};
use sentirum_lb::proxy::handler::SentirumProxy;
use sentirum_lb::route::parser::parse_route_commands;
use sentirum_lb::route::registry::ManagedRouteTable;

/// Sentirum LB -- High-performance Rust load balancer with Consul integration
#[derive(Parser, Debug)]
#[command(name = "sentirum-lb", version, about = "High-performance Rust load balancer with Consul integration")]
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
    use tracing_subscriber::{fmt, EnvFilter};

    let level = config.logging.level.clone();
    let format = config.logging.format.clone();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&level));

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
                    tracing::warn!("No service-based routes available from Consul; clearing service routes");
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

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Load configuration
    let config_content = args
        .config
        .as_ref()
        .map(|config_path| {
            std::fs::read_to_string(config_path)
                .unwrap_or_else(|e| panic!("Failed to load config file '{}': {}", config_path, e))
        })
        .unwrap_or_default();

    let mut config: Config = if config_content.is_empty() {
        let server = sentirum_lb::config::ServerConfig {
            listen: args.listen.clone().unwrap_or_else(|| ":9999".to_string()),
            admin_listen: "127.0.0.1:9998".to_string(),
            admin_token: String::new(),
            workers: 0,
        };
        let consul = sentirum_lb::config::ConsulConfig {
            address: args.consul.clone().unwrap_or_else(|| "127.0.0.1:8500".to_string()),
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
        toml::from_str(&config_content).expect("Failed to parse config file")
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
    let mut server = pingora::server::Server::new(Some(
        pingora::server::configuration::Opt::default(),
    )).expect("Failed to create Pingora server");

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
    let proxy_handler = SentirumProxy::new(
        managed_table.clone(),
        Arc::new(config.clone()),
    );
    let mut lb_service = pingora::proxy::http_proxy_service(&server.configuration, proxy_handler);
    if config.server.workers > 0 {
        lb_service.threads = Some(config.server.workers);
    }
    lb_service.add_tcp(&config.server.listen);

    tracing::info!(
        addr = %config.server.listen,
        workers = config.server.workers,
        pool_size = config.proxy.pool_size,
        max_connections = config.proxy.max_connections,
        "Proxy listening (HTTP)"
    );

    // Add TLS listener if configured
    let tls_cert_config: Option<sentirum_lb::proxy::tls::TlsCertConfig> =
        (&config.tls).into();
    if let Some(tls) = &tls_cert_config {
        match tls.validate() {
            Ok(()) => {
                // Use explicit TLS listen address, or derive from HTTP port +1
                let tls_listen = if config.tls.listen.is_empty() {
                    let http_port: u16 = config.server.listen
                        .trim_start_matches(':')
                        .parse()
                        .unwrap_or(9999);
                    format!(":{}", http_port + 1)
                } else {
                    config.tls.listen.clone()
                };

                if let Err(e) = lb_service.add_tls(&tls_listen, &tls.cert_path, &tls.key_path) {
                    tracing::error!(error = %e, "Failed to configure TLS listener");
                } else {
                    tracing::info!(addr = %tls_listen, "Proxy listening (HTTPS/TLS)");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "TLS configuration invalid, skipping HTTPS listener");
            }
        }
    }

    server.add_service(lb_service);

    // Start Consul watcher if enabled
    let (tx, rx) = mpsc::channel(100);
    // Shutdown signal for graceful drain
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    if config.consul.service_discovery || config.consul.kv_watching {
        let consul_config = ConsulConfig::from(&config.consul);
        match ConsulClient::new(consul_config.clone()) {
            Ok(client) => {
                let watcher = ConsulWatcher::new(Arc::new(client), consul_config);
                // Spawn route update handler
                let rt = managed_table.clone();
                let mut shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = route_update_handler(rt, rx) => {}
                        _ = shutdown.changed() => {
                            tracing::info!("Route update handler shutting down");
                        }
                    }
                });
                // Spawn watcher
                tokio::spawn(async move {
                    watcher.run(tx).await;
                });
                tracing::info!("Consul watcher started");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to create Consul client");
            }
        }
    }

    // TODO: Phase 4 -- Start admin API server
    // Start admin API server
    {
        let admin_config = Arc::new(config.clone());
        let admin_rt = managed_table.clone();
        tokio::spawn(async move {
            sentirum_lb::admin::run_admin_server(admin_config, admin_rt).await;
        });
    }

    // Spawn graceful shutdown handler
    let shutdown_signal = shutdown_tx;
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Received shutdown signal, draining connections...");
        let _ = shutdown_signal.send(true);
        // Give watchers time to drain (Pingora handles connection draining)
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        tracing::info!("Drain complete, shutting down");
        std::process::exit(0);
    });

    tracing::info!("Sentirum LB is ready");
    server.run_forever();
}

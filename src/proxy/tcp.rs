use crate::config::Config;
use crate::route::picker::create_picker;
use crate::route::registry::ManagedRouteTable;
use crate::route::table::Table;
use crate::route::target::Target;
use async_trait::async_trait;
use pingora::services::background::BackgroundService;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpMode {
    Disabled,
    Tcp { listen: String },
    TcpSni { listen: String },
    TcpDynamic { refresh: Duration },
}

pub fn resolve_tcp_mode(config: &Config) -> Result<TcpMode, String> {
    let mode = config.tcp.mode.trim().to_ascii_lowercase();
    match mode.as_str() {
        "" | "disabled" => Ok(TcpMode::Disabled),
        "tcp" => {
            let listen = config.tcp.listen.trim();
            if listen.is_empty() {
                return Err("tcp.listen cannot be empty when tcp.mode=tcp".to_string());
            }
            Ok(TcpMode::Tcp {
                listen: listen.to_string(),
            })
        }
        "tcp+sni" => {
            let listen = config.tcp.listen.trim();
            if listen.is_empty() {
                return Err("tcp.listen cannot be empty when tcp.mode=tcp+sni".to_string());
            }
            Ok(TcpMode::TcpSni {
                listen: listen.to_string(),
            })
        }
        "tcp-dynamic" => Ok(TcpMode::TcpDynamic {
            refresh: crate::config::Config::parse_optional_duration(&config.tcp.refresh)
                .unwrap_or_else(|| Duration::from_secs(5)),
        }),
        "https+tcp+sni" => Err(
            "tcp.mode=https+tcp+sni is not implemented yet; it requires downstream listener multiplexing with the HTTPS Pingora listener"
                .to_string(),
        ),
        other => Err(format!(
            "unknown tcp.mode '{other}', expected 'tcp', 'tcp+sni', or 'tcp-dynamic'"
        )),
    }
}

pub struct TcpBackgroundService {
    pub route_table: Arc<ManagedRouteTable>,
    pub config: Arc<Config>,
}

#[async_trait]
impl BackgroundService for TcpBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        match resolve_tcp_mode(&self.config) {
            Ok(TcpMode::Disabled) => {
                tracing::info!("TCP proxy mode disabled, skipping TCP background service");
            }
            Ok(TcpMode::Tcp { listen }) => {
                let port = match parse_listener_port(&listen) {
                    Some(port) => port,
                    None => {
                        tracing::error!(listen = %listen, "Invalid tcp.listen address");
                        return;
                    }
                };
                tracing::info!(addr = %listen, "TCP proxy listening (fixed)");
                run_tcp_listener(
                    listen,
                    port,
                    TcpListenerMode::Plain,
                    self.route_table.clone(),
                    self.config.clone(),
                    &mut shutdown,
                )
                .await;
            }
            Ok(TcpMode::TcpSni { listen }) => {
                let port = match parse_listener_port(&listen) {
                    Some(port) => port,
                    None => {
                        tracing::error!(listen = %listen, "Invalid tcp.listen address");
                        return;
                    }
                };
                tracing::info!(addr = %listen, "TCP proxy listening (SNI passthrough)");
                run_tcp_listener(
                    listen,
                    port,
                    TcpListenerMode::Sni,
                    self.route_table.clone(),
                    self.config.clone(),
                    &mut shutdown,
                )
                .await;
            }
            Ok(TcpMode::TcpDynamic { refresh }) => {
                tracing::info!(refresh_ms = refresh.as_millis(), "TCP proxy listening (dynamic)");
                run_dynamic_tcp_manager(
                    refresh,
                    self.route_table.clone(),
                    self.config.clone(),
                    &mut shutdown,
                )
                .await;
            }
            Err(error) => {
                tracing::error!(%error, "Invalid TCP configuration");
            }
        }
    }
}

async fn run_dynamic_tcp_manager(
    refresh: Duration,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
    shutdown: &mut pingora::server::ShutdownWatch,
) {
    let mut listeners: HashMap<u16, DynamicListenerHandle> = HashMap::new();
    let mut interval = tokio::time::interval(refresh);

    reconcile_dynamic_listeners(&mut listeners, route_table.clone(), config.clone()).await;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("TCP dynamic listener manager shutting down");
                break;
            }
            _ = interval.tick() => {
                reconcile_dynamic_listeners(&mut listeners, route_table.clone(), config.clone()).await;
            }
        }
    }

    for (port, handle) in listeners {
        let _ = handle.shutdown.send(true);
        tracing::info!(listen_port = port, "Stopping dynamic TCP listener");
        handle.task.abort();
    }
}

struct DynamicListenerHandle {
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

async fn reconcile_dynamic_listeners(
    listeners: &mut HashMap<u16, DynamicListenerHandle>,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
) {
    let ports = route_table.get().tcp_listener_ports();

    let existing_ports: Vec<u16> = listeners.keys().copied().collect();
    for port in existing_ports {
        if ports.contains(&port) {
            continue;
        }

        if let Some(handle) = listeners.remove(&port) {
            let _ = handle.shutdown.send(true);
            tracing::info!(listen_port = port, "Stopping dynamic TCP listener");
            handle.task.abort();
        }
    }

    for port in ports {
        if listeners.contains_key(&port) {
            continue;
        }

        let listen = format!(":{port}");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let route_table = route_table.clone();
        let config = config.clone();
        let task = tokio::spawn(async move {
            run_tcp_listener_with_watch(
                listen,
                port,
                TcpListenerMode::Plain,
                route_table,
                config,
                shutdown_rx,
            )
            .await;
        });
        listeners.insert(
            port,
            DynamicListenerHandle {
                shutdown: shutdown_tx,
                task,
            },
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpListenerMode {
    Plain,
    Sni,
}

async fn run_tcp_listener(
    listen: String,
    listen_port: u16,
    mode: TcpListenerMode,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
    shutdown: &mut pingora::server::ShutdownWatch,
) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener_task = tokio::spawn(async move {
        run_tcp_listener_with_watch(listen, listen_port, mode, route_table, config, shutdown_rx)
            .await;
    });

    let _ = shutdown.changed().await;
    let _ = shutdown_tx.send(true);
    tracing::info!(listen_port, "TCP listener shutting down");
    listener_task.abort();
}

async fn run_tcp_listener_with_watch(
    listen: String,
    listen_port: u16,
    mode: TcpListenerMode,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener = match TcpListener::bind(&listen).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(addr = %listen, %error, "Failed to bind TCP listener");
            return;
        }
    };

    tracing::info!(addr = %listen, listen_port, mode = ?mode, "TCP listener started");

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (downstream, peer_addr) = match accepted {
                    Ok(conn) => conn,
                    Err(error) => {
                        tracing::warn!(addr = %listen, %error, "TCP accept failed");
                        continue;
                    }
                };

                let route_table = route_table.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let result = match mode {
                        TcpListenerMode::Plain => {
                            handle_tcp_connection(downstream, route_table, config).await
                        }
                        TcpListenerMode::Sni => {
                            handle_tcp_sni_connection(downstream, route_table, config).await
                        }
                    };
                    if let Err(error) = result {
                        tracing::debug!(listen_port, client = %peer_addr, %error, "TCP proxy connection ended with error");
                    }
                });
            }
        }
    }
}

async fn handle_tcp_connection(
    mut downstream: TcpStream,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
) -> Result<(), std::io::Error> {
    let local_addr = downstream.local_addr()?;
    let local_addr_str = local_addr.to_string();
    let target = match lookup_target(&route_table, &config.proxy.strategy, &local_addr_str) {
        Some(target) => target,
        None => {
            tracing::warn!(local_addr = %local_addr_str, "No TCP route found for local listener");
            return Ok(());
        }
    };

    if !try_acquire_upstream_slot(&target, config.proxy.max_connections as u64) {
        tracing::warn!(local_addr = %local_addr_str, target_url = %target.url, max_connections = config.proxy.max_connections, "TCP upstream concurrency limit reached");
        return Ok(());
    }

    crate::metrics::prometheus::global().connect();
    let _guard = TcpConnectionGuard {
        target: target.clone(),
    };

    let mut upstream = match connect_upstream(&target, &config).await {
        Ok(upstream) => upstream,
        Err(error) => {
            tracing::warn!(target_url = %target.url, %error, "Failed to open TCP upstream connection");
            return Ok(());
        }
    };

    let _ = copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

async fn handle_tcp_sni_connection(
    mut downstream: TcpStream,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
) -> Result<(), std::io::Error> {
    let client_hello = read_client_hello(&mut downstream).await?;
    let server_name = read_server_name(&client_hello[5..]).ok_or_else(|| {
        std::io::Error::other("unable to parse TLS client hello server_name")
    })?;
    if server_name.is_empty() {
        tracing::debug!("tcp+sni: server_name missing");
        return Ok(());
    }

    let target = match lookup_sni_target(&route_table, &config.proxy.strategy, &server_name) {
        Some(target) => target,
        None => {
            tracing::warn!(server_name = %server_name, "No TCP SNI route found");
            return Ok(());
        }
    };

    if !try_acquire_upstream_slot(&target, config.proxy.max_connections as u64) {
        tracing::warn!(server_name = %server_name, target_url = %target.url, max_connections = config.proxy.max_connections, "TCP SNI upstream concurrency limit reached");
        return Ok(());
    }

    crate::metrics::prometheus::global().connect();
    let _guard = TcpConnectionGuard {
        target: target.clone(),
    };

    let mut upstream = match connect_upstream(&target, &config).await {
        Ok(upstream) => upstream,
        Err(error) => {
            tracing::warn!(server_name = %server_name, target_url = %target.url, %error, "Failed to open TCP SNI upstream connection");
            return Ok(());
        }
    };

    upstream.write_all(&client_hello).await?;
    upstream.flush().await?;

    let _ = copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

fn lookup_target(
    route_table: &Arc<ManagedRouteTable>,
    strategy: &str,
    local_addr: &str,
) -> Option<Arc<Target>> {
    let table = route_table.get();
    let table: &Table = &table;
    let route = table.lookup_tcp_route_for_local_addr(local_addr)?;
    create_picker(strategy).pick(&route.targets, &route.w_targets, &route.rr_counter)
}

fn lookup_sni_target(
    route_table: &Arc<ManagedRouteTable>,
    strategy: &str,
    server_name: &str,
) -> Option<Arc<Target>> {
    let table = route_table.get();
    let table: &Table = &table;
    let route = table.lookup_tcp_sni_route(server_name)?;
    create_picker(strategy).pick(&route.targets, &route.w_targets, &route.rr_counter)
}

async fn connect_upstream(target: &Target, config: &Config) -> Result<TcpStream, std::io::Error> {
    if !target.is_host_safe() && !target.ssrf_skip_verify() {
        return Err(std::io::Error::other("blocked private/reserved upstream target"));
    }

    let host = target.upstream_host();
    let port = target.upstream_port();
    let addr_str = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut addrs = tokio::net::lookup_host(&addr_str).await?;
    let resolved = addrs
        .next()
        .ok_or_else(|| std::io::Error::other("no upstream IP addresses found"))?;

    if !target.ssrf_skip_verify()
        && (crate::route::target::is_ip_always_blocked(&resolved.ip())
            || (!target.source_allows_private_upstreams()
                && crate::route::target::is_ip_rfc1918(&resolved.ip())))
    {
        return Err(std::io::Error::other(
            "blocked upstream target during resolution",
        ));
    }

    let timeout = crate::config::Config::parse_duration(&config.proxy.connect_timeout);
    if timeout.is_zero() {
        return TcpStream::connect(resolved).await;
    }

    tokio::time::timeout(timeout, TcpStream::connect(resolved))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP connect timed out"))?
}

struct TcpConnectionGuard {
    target: Arc<Target>,
}

impl Drop for TcpConnectionGuard {
    fn drop(&mut self) {
        self.target.active_connections.fetch_sub(1, Ordering::Relaxed);
        crate::metrics::prometheus::global().disconnect();
    }
}

fn try_acquire_upstream_slot(target: &Target, max_connections: u64) -> bool {
    if max_connections == 0 {
        target.active_connections.fetch_add(1, Ordering::Relaxed);
        return true;
    }

    let mut current = target.active_connections.load(Ordering::Relaxed);
    loop {
        if current >= max_connections {
            return false;
        }
        match target.active_connections.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn parse_listener_port(value: &str) -> Option<u16> {
    value.rsplit(':').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConsulConfig, LoggingConfig, ProxyConfig, ServerConfig, TcpConfig, TlsConfig};
    use crate::route::definition::{RouteCmd, RouteDef, RouteSource};
    use std::collections::HashMap;

    fn config() -> Arc<Config> {
        Arc::new(Config {
            server: ServerConfig {
                listen: ":9999".to_string(),
                admin_listen: "127.0.0.1:9998".to_string(),
                admin_token: String::new(),
                workers: 0,
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
            },
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
            tcp: TcpConfig::default(),
        })
    }

    fn tcp_def(src: &str, dst: &str) -> RouteDef {
        let mut opts = HashMap::new();
        opts.insert("proto".to_string(), "tcp".to_string());
        RouteDef {
            cmd: RouteCmd::Add,
            service: "nats".to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            weight: 0.0,
            tags: vec![],
            opts,
            source: RouteSource::ConsulService,
        }
    }

    #[test]
    fn resolve_tcp_mode_defaults_to_disabled() {
        assert_eq!(resolve_tcp_mode(&config()).unwrap(), TcpMode::Disabled);
    }

    #[test]
    fn resolve_tcp_mode_supports_fixed_and_dynamic_modes() {
        let mut fixed = (*config()).clone();
        fixed.tcp.mode = "tcp".to_string();
        fixed.tcp.listen = ":4222".to_string();
        assert_eq!(
            resolve_tcp_mode(&fixed).unwrap(),
            TcpMode::Tcp {
                listen: ":4222".to_string()
            }
        );

        let mut dynamic = (*config()).clone();
        dynamic.tcp.mode = "tcp-dynamic".to_string();
        dynamic.tcp.refresh = "7s".to_string();
        assert_eq!(
            resolve_tcp_mode(&dynamic).unwrap(),
            TcpMode::TcpDynamic {
                refresh: Duration::from_secs(7)
            }
        );
    }

    #[test]
    fn lookup_target_uses_exact_local_addr_then_port_fallback() {
        let table = Arc::new(ManagedRouteTable::new());
        table.update_services(vec![
            tcp_def("127.0.0.1:4222", "tcp://10.0.0.10:4222"),
            tcp_def(":4333", "tcp://10.0.0.11:4333"),
        ]);

        let exact = lookup_target(&table, "round-robin", "127.0.0.1:4222")
            .expect("exact local addr should match");
        assert_eq!(exact.url, "tcp://10.0.0.10:4222");

        let fallback = lookup_target(&table, "round-robin", "0.0.0.0:4333")
            .expect("port fallback should match");
        assert_eq!(fallback.url, "tcp://10.0.0.11:4333");
    }

    #[test]
    fn tcp_listener_ports_match_fabio_dynamic_semantics() {
        let table = Arc::new(ManagedRouteTable::new());
        table.update_services(vec![
            tcp_def(":4222", "tcp://10.0.0.10:4222"),
            tcp_def("127.0.0.1:4333", "tcp://10.0.0.11:4333"),
        ]);

        let ports = table.get().tcp_listener_ports();
        assert_eq!(ports, vec![4222, 4333]);
    }
}

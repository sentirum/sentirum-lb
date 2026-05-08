use crate::config::Config;
use crate::route::picker::create_picker;
use crate::route::registry::ManagedRouteTable;
use crate::route::table::Table;
use crate::route::target::Target;
use async_trait::async_trait;
use pingora::services::background::BackgroundService;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpMode {
    Disabled,
    Tcp { listen: String },
    TcpSni { listen: String },
    HttpsTcpSni,
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
        "https+tcp+sni" => Ok(TcpMode::HttpsTcpSni),
        other => Err(format!(
            "unknown tcp.mode '{other}', expected 'tcp', 'tcp+sni', 'https+tcp+sni', or 'tcp-dynamic'"
        )),
    }
}

pub struct TcpBackgroundService {
    pub route_table: Arc<ManagedRouteTable>,
    pub config: Arc<Config>,
    pub mode: TcpMode,
    pub https_fallback_addr: Option<String>,
}

#[async_trait]
impl BackgroundService for TcpBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        match self.mode.clone() {
            TcpMode::Disabled => {
                tracing::info!("TCP proxy mode disabled, skipping TCP background service");
            }
            TcpMode::Tcp { listen } => {
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
            TcpMode::TcpSni { listen } => {
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
            TcpMode::HttpsTcpSni => {
                let https_fallback_addr = match self.https_fallback_addr.clone() {
                    Some(addr) => addr,
                    None => {
                        tracing::error!(
                            "HTTPS+TCP+SNI mode requires an internal HTTPS fallback listener"
                        );
                        return;
                    }
                };
                let public_listen = crate::proxy::tls::tls_listen_addr(
                    &self.config.server.listen,
                    &self.config.tls.listen,
                );
                let port = match parse_listener_port(&public_listen) {
                    Some(port) => port,
                    None => {
                        tracing::error!(listen = %public_listen, "Invalid TLS listen address for https+tcp+sni mode");
                        return;
                    }
                };
                tracing::info!(addr = %public_listen, fallback = %https_fallback_addr, "TCP proxy listening (HTTPS+SNI fallthrough)");
                run_tcp_listener(
                    public_listen,
                    port,
                    TcpListenerMode::HttpsFallback(https_fallback_addr),
                    self.route_table.clone(),
                    self.config.clone(),
                    &mut shutdown,
                )
                .await;
            }
            TcpMode::TcpDynamic { refresh } => {
                tracing::info!(
                    refresh_ms = refresh.as_millis(),
                    "TCP proxy listening (dynamic)"
                );
                run_dynamic_tcp_manager(
                    refresh,
                    self.route_table.clone(),
                    self.config.clone(),
                    &mut shutdown,
                )
                .await;
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
        let task = handle.task;
        match tokio::time::timeout(Duration::from_secs(5), task).await {
            Ok(Ok(())) => {
                tracing::info!(listen_port = port, "Dynamic TCP listener shut down gracefully");
            }
            Ok(Err(_)) => {
                tracing::warn!(listen_port = port, "Dynamic TCP listener task failed during shutdown");
            }
            Err(_) => {
                tracing::warn!(listen_port = port, "Dynamic TCP listener grace period elapsed, aborting");
            }
        }
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
            tracing::info!(listen_port = port, "Stopping stale dynamic TCP listener");
            // Don't await in reconcile — stale listener shutdown is fire-and-forget
            // to avoid blocking the reconciliation loop. The task will respond to
            // the shutdown signal and exit, or be cleaned up when the handle drops.
            drop(handle);
        }
    }

    for port in ports {
        if listeners.contains_key(&port) {
            continue;
        }

        let listen = format!("0.0.0.0:{port}");
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpListenerMode {
    Plain,
    Sni,
    HttpsFallback(String),
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

    // Give in-flight connections a brief grace period to finish cleanly.
    match tokio::time::timeout(Duration::from_secs(5), listener_task).await {
        Ok(Ok(())) => {
            tracing::info!(listen_port, "TCP listener shut down gracefully");
        }
        Ok(Err(_)) => {
            tracing::warn!(listen_port, "TCP listener task failed during shutdown");
        }
        Err(_) => {
            tracing::warn!(listen_port, "TCP listener grace period elapsed, aborting");
        }
    }
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
                let mode = mode.clone();
                tokio::spawn(async move {
                    let result = match mode {
                        TcpListenerMode::Plain => {
                            handle_tcp_connection(downstream, route_table, config).await
                        }
                        TcpListenerMode::Sni => {
                            handle_tcp_sni_connection(downstream, route_table, config).await
                        }
                        TcpListenerMode::HttpsFallback(https_fallback_addr) => {
                            handle_https_tcp_sni_connection(
                                downstream,
                                route_table,
                                config,
                                &https_fallback_addr,
                            )
                            .await
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
    downstream: TcpStream,
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

    proxy_tcp_streams(downstream, Vec::new(), target, &config, None).await
}

async fn handle_tcp_sni_connection(
    mut downstream: TcpStream,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
) -> Result<(), std::io::Error> {
    let client_hello = read_client_hello(&mut downstream).await?;
    let server_name = read_server_name(&client_hello[5..])
        .ok_or_else(|| std::io::Error::other("unable to parse TLS client hello server_name"))?;
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

    proxy_tcp_streams(
        downstream,
        client_hello,
        target,
        &config,
        Some(&server_name),
    )
    .await
}

async fn handle_https_tcp_sni_connection(
    mut downstream: TcpStream,
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
    https_fallback_addr: &str,
) -> Result<(), std::io::Error> {
    let mut headers = [0_u8; 9];
    downstream.read_exact(&mut headers).await?;

    let client_hello = match client_hello_buffer_size(&headers) {
        Ok(buffer_size) => {
            let mut data = vec![0_u8; buffer_size];
            data[..9].copy_from_slice(&headers);
            downstream.read_exact(&mut data[9..]).await?;
            data
        }
        Err(_) => {
            return proxy_to_https_fallback(
                downstream,
                headers.to_vec(),
                config.as_ref(),
                https_fallback_addr,
            )
            .await;
        }
    };

    let target = read_server_name(&client_hello[5..])
        .filter(|server_name| !server_name.is_empty())
        .and_then(|server_name| {
            lookup_sni_target(&route_table, &config.proxy.strategy, &server_name)
                .map(|target| (server_name, target))
        });

    if let Some((server_name, target)) = target {
        return proxy_tcp_streams(
            downstream,
            client_hello,
            target,
            &config,
            Some(&server_name),
        )
        .await;
    }

    proxy_to_https_fallback(
        downstream,
        client_hello,
        config.as_ref(),
        https_fallback_addr,
    )
    .await
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

async fn proxy_tcp_streams(
    mut downstream: TcpStream,
    initial_bytes: Vec<u8>,
    target: Arc<Target>,
    config: &Arc<Config>,
    server_name: Option<&str>,
) -> Result<(), std::io::Error> {
    if !target.try_acquire_connection_slot(config.proxy.max_connections as u64) {
        match server_name {
            Some(server_name) => {
                tracing::warn!(server_name = %server_name, target_url = %target.url, max_connections = config.proxy.max_connections, "TCP SNI upstream concurrency limit reached")
            }
            None => {
                tracing::warn!(target_url = %target.url, max_connections = config.proxy.max_connections, "TCP upstream concurrency limit reached")
            }
        }
        return Ok(());
    }

    crate::metrics::prometheus::global().connect();
    let _guard = TcpConnectionGuard {
        target: target.clone(),
    };

    // SSRF check: block private/reserved IP upstreams unless explicitly bypassed.
    // This mirrors the protection already applied in HTTP proxy handler's upstream_peer.
    // We do this here (not in connect_upstream) so we can log with server_name context.
    if !target.is_host_safe() && !target.ssrf_skip_verify() {
        match server_name {
            Some(server_name) => {
                tracing::warn!(
                    server_name = %server_name,
                    target_url = %target.url,
                    host = %target.upstream_host(),
                    "TCP SNI upstream blocked by SSRF protection"
                );
            }
            None => {
                tracing::warn!(
                    target_url = %target.url,
                    host = %target.upstream_host(),
                    "TCP upstream blocked by SSRF protection"
                );
            }
        }
        return Ok(());
    }


    let mut upstream = match connect_upstream(&target, config.as_ref()).await {
        Ok(upstream) => upstream,
        Err(error) => {
            match server_name {
                Some(server_name) => {
                    tracing::warn!(server_name = %server_name, target_url = %target.url, %error, "Failed to open TCP SNI upstream connection")
                }
                None => {
                    tracing::warn!(target_url = %target.url, %error, "Failed to open TCP upstream connection")
                }
            }
            return Ok(());
        }
    };

    if target.proxy_proto() {
        write_proxy_header(&mut upstream, &downstream).await?;
    }

    if !initial_bytes.is_empty() {
        upstream.write_all(&initial_bytes).await?;
        upstream.flush().await?;
    }

    let _ = copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

async fn proxy_to_https_fallback(
    mut downstream: TcpStream,
    initial_bytes: Vec<u8>,
    config: &Config,
    fallback_addr: &str,
) -> Result<(), std::io::Error> {
    let mut upstream = connect_addr(fallback_addr, config).await?;
    if !initial_bytes.is_empty() {
        upstream.write_all(&initial_bytes).await?;
        upstream.flush().await?;
    }
    let _ = copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

async fn connect_upstream(target: &Target, config: &Config) -> Result<TcpStream, std::io::Error> {
    let resolved = target.resolve_upstream_addr().await?;
    connect_addr(&resolved.to_string(), config).await
}

async fn connect_addr(addr: &str, config: &Config) -> Result<TcpStream, std::io::Error> {
    let timeout = crate::config::Config::parse_duration(&config.proxy.connect_timeout);
    if timeout.is_zero() {
        return TcpStream::connect(addr).await;
    }

    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP connect timed out"))?
}

async fn write_proxy_header(
    upstream: &mut TcpStream,
    downstream: &TcpStream,
) -> Result<(), std::io::Error> {
    let client = downstream.peer_addr()?;
    let server = downstream.local_addr()?;
    let proto = if client.ip().is_ipv4() {
        "TCP4"
    } else {
        "TCP6"
    };
    let header = format!(
        "PROXY {proto} {} {} {} {}\r\n",
        client.ip(),
        server.ip(),
        client.port(),
        server.port()
    );
    upstream.write_all(header.as_bytes()).await?;
    Ok(())
}

async fn read_client_hello(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut headers = [0_u8; 9];
    stream.read_exact(&mut headers).await?;
    let buffer_size = client_hello_buffer_size(&headers)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut data = vec![0_u8; buffer_size];
    data[..9].copy_from_slice(&headers);
    stream.read_exact(&mut data[9..]).await?;
    Ok(data)
}

fn client_hello_buffer_size(data: &[u8]) -> Result<usize, &'static str> {
    if data.len() < 9 {
        return Err("at least 9 bytes required to determine client hello length");
    }
    if data[0] != 0x16 {
        return Err("not a TLS handshake");
    }

    let record_length = usize::from(data[3]) << 8 | usize::from(data[4]);
    if record_length == 0 || record_length > 16_384 {
        return Err("invalid TLS record length");
    }
    if data[5] != 0x01 {
        return Err("not a client hello");
    }

    let handshake_length =
        usize::from(data[6]) << 16 | usize::from(data[7]) << 8 | usize::from(data[8]);
    if handshake_length == 0 || handshake_length > record_length.saturating_sub(4) {
        return Err("invalid client hello length (fragmentation not implemented)");
    }

    Ok(handshake_length + 9)
}

fn read_server_name(client_hello_handshake_msg: &[u8]) -> Option<String> {
    if client_hello_handshake_msg.len() < 42 {
        return None;
    }

    let mut data = client_hello_handshake_msg;
    let session_id_len = usize::from(data[38]);
    if session_id_len > 32 || data.len() < 39 + session_id_len {
        return None;
    }
    data = &data[39 + session_id_len..];

    if data.len() < 2 {
        return None;
    }
    let cipher_suite_len = usize::from(data[0]) << 8 | usize::from(data[1]);
    if cipher_suite_len % 2 == 1 || data.len() < 2 + cipher_suite_len {
        return None;
    }
    data = &data[2 + cipher_suite_len..];

    if data.is_empty() {
        return None;
    }
    let compression_methods_len = usize::from(data[0]);
    if data.len() < 1 + compression_methods_len {
        return None;
    }
    data = &data[1 + compression_methods_len..];

    if data.is_empty() {
        return Some(String::new());
    }
    if data.len() < 2 {
        return None;
    }
    let extensions_length = usize::from(data[0]) << 8 | usize::from(data[1]);
    data = &data[2..];
    if extensions_length != data.len() {
        return None;
    }

    while !data.is_empty() {
        if data.len() < 4 {
            return None;
        }
        let extension = u16::from(data[0]) << 8 | u16::from(data[1]);
        let length = usize::from(data[2]) << 8 | usize::from(data[3]);
        data = &data[4..];
        if data.len() < length {
            return None;
        }

        if extension == 0 {
            let mut names = &data[..length];
            if names.len() < 2 {
                return None;
            }
            let names_len = usize::from(names[0]) << 8 | usize::from(names[1]);
            names = &names[2..];
            if names_len != names.len() {
                return None;
            }
            while !names.is_empty() {
                if names.len() < 3 {
                    return None;
                }
                let name_type = names[0];
                let name_len = usize::from(names[1]) << 8 | usize::from(names[2]);
                names = &names[3..];
                if names.len() < name_len {
                    return None;
                }
                if name_type == 0 {
                    return Some(String::from_utf8_lossy(&names[..name_len]).to_ascii_lowercase());
                }
                names = &names[name_len..];
            }
            return Some(String::new());
        }

        data = &data[length..];
    }

    Some(String::new())
}

struct TcpConnectionGuard {
    target: Arc<Target>,
}

impl Drop for TcpConnectionGuard {
    fn drop(&mut self) {
        self.target.release_connection_slot();
        crate::metrics::prometheus::global().disconnect();
    }
}

fn parse_listener_port(value: &str) -> Option<u16> {
    value.rsplit(':').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ConsulConfig, LoggingConfig, ProxyConfig, ServerConfig, TcpConfig, TlsConfig,
    };
    use crate::route::definition::{RouteCmd, RouteDef, RouteSource};
    use std::collections::HashMap;

    const CLIENT_HELLO_WITH_SNI_HEX: &str = "0100014803032657cacce41598fa82e5b75061050bc31c5affdba106b8e743185224af0fa1aa000098cc14cc13cc15c030c02cc028c024c014c00a00a3009f006b006a00390038ff8500c400c3008800870081c032c02ec02ac026c00fc005009d003d003500c00084c02fc02bc027c023c013c00900a2009e006700400033003200be00bd00450044c031c02dc029c025c00ec004009c003c002f00ba0041c011c007c00cc00200050004c012c00800160013c00dc003000a00150012000900ff010000870000000f000d00000a676f6f676c652e636f6d000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000d00260024060106020603efef050105020503040104020403eeeeeded030103020303020102020203";

    fn config() -> Arc<Config> {
        Arc::new(Config {
            server: ServerConfig {
                listen: ":9999".to_string(),
                admin_listen: "127.0.0.1:9998".to_string(),
                admin_token: String::new(),
                admin_users: vec![],
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
                service_whitelist: Vec::new(),
                service_blacklist: Vec::new(),
                graceful_shutdown: true,
                include_warning: false,
            },
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
            tcp: TcpConfig::default(),
        })
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(input.len() / 2);
        let mut chars = input.as_bytes().chunks_exact(2);
        for pair in &mut chars {
            let high = (pair[0] as char).to_digit(16).expect("valid hex") as u8;
            let low = (pair[1] as char).to_digit(16).expect("valid hex") as u8;
            bytes.push((high << 4) | low);
        }
        assert!(
            chars.remainder().is_empty(),
            "hex input must have even length"
        );
        bytes
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
    fn resolve_tcp_mode_supports_fixed_sni_and_dynamic_modes() {
        let mut fixed = (*config()).clone();
        fixed.tcp.mode = "tcp".to_string();
        fixed.tcp.listen = ":4222".to_string();
        assert_eq!(
            resolve_tcp_mode(&fixed).unwrap(),
            TcpMode::Tcp {
                listen: ":4222".to_string()
            }
        );

        let mut sni = (*config()).clone();
        sni.tcp.mode = "tcp+sni".to_string();
        sni.tcp.listen = ":443".to_string();
        assert_eq!(
            resolve_tcp_mode(&sni).unwrap(),
            TcpMode::TcpSni {
                listen: ":443".to_string()
            }
        );

        let mut https_sni = (*config()).clone();
        https_sni.tcp.mode = "https+tcp+sni".to_string();
        assert_eq!(resolve_tcp_mode(&https_sni).unwrap(), TcpMode::HttpsTcpSni);

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

    #[test]
    fn lookup_sni_target_matches_host_routes() {
        let table = Arc::new(ManagedRouteTable::new());
        table.update_services(vec![
            tcp_def("google.com", "tcp://10.0.0.20:443"),
            tcp_def(":443", "tcp://10.0.0.10:443"),
        ]);

        let target =
            lookup_sni_target(&table, "round-robin", "google.com").expect("sni route should exist");
        assert_eq!(target.url, "tcp://10.0.0.20:443");
        assert!(lookup_sni_target(&table, "round-robin", "missing.example.com").is_none());
    }

    #[test]
    fn client_hello_buffer_size_validates_tls_client_hello() {
        let valid = [0x16, 0x03, 0x01, 0x40, 0x00, 0x01, 0x00, 0x3f, 0xfc];
        assert_eq!(client_hello_buffer_size(&valid).unwrap(), 16_389);
        assert!(client_hello_buffer_size(&valid[..8]).is_err());
        assert!(
            client_hello_buffer_size(&[0x15, 0x03, 0x01, 0x01, 0xF4, 0x01, 0x00, 0x01, 0xeb])
                .is_err()
        );
    }

    #[test]
    fn read_server_name_extracts_sni_host() {
        let client_hello = decode_hex(CLIENT_HELLO_WITH_SNI_HEX);
        assert_eq!(
            read_server_name(&client_hello).as_deref(),
            Some("google.com")
        );
        assert!(read_server_name(b"not a client hello").is_none());
    }

    #[tokio::test]
    async fn write_proxy_header_formats_v1_line() {
        let downstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downstream_addr = downstream_listener.local_addr().unwrap();
        let downstream_accept =
            tokio::spawn(async move { downstream_listener.accept().await.unwrap().0 });
        let _downstream_client = TcpStream::connect(downstream_addr).await.unwrap();
        let downstream_server = downstream_accept.await.unwrap();

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_accept =
            tokio::spawn(async move { upstream_listener.accept().await.unwrap().0 });
        let mut upstream_client = TcpStream::connect(upstream_addr).await.unwrap();
        let mut upstream_server = upstream_accept.await.unwrap();

        write_proxy_header(&mut upstream_client, &downstream_server)
            .await
            .unwrap();

        let mut buf = [0_u8; 128];
        let n = upstream_server.read(&mut buf).await.unwrap();
        let header = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(header.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "));
        assert!(header.ends_with("\r\n"));

    #[test]
    fn tcp_target_blocks_loopback_by_default() {
        let table = Arc::new(ManagedRouteTable::new());
        table.update_services(vec![tcp_def("localhost:4222", "tcp://127.0.0.1:4222")]);

        // Route exists but targets loopback → blocked by SSRF in proxy_tcp_streams
        // lookup_target itself still returns the target (SSRF check is at proxy time)
        let target = lookup_target(&table, "round-robin", "127.0.0.1:4222");
        // SSRF is enforced in proxy_tcp_streams, not in lookup — we verify the
        // target is selected (route matches) and the SSRF check in proxy will block it.
        assert!(
            target.is_some(),
            "Route should be found; SSRF is enforced at proxy time"
        );
        let t = target.unwrap();
        assert!(
            !t.is_host_safe(),
            "Loopback target should not be host-safe (SSRF enforced at proxy)"
        );
    }

    #[test]
    fn tcp_target_blocks_rfc1918_static_source() {
        let table = Arc::new(ManagedRouteTable::new());
        // Static source blocks RFC1918; ConsulService would allow it
        let def = {
            let mut opts = HashMap::new();
            opts.insert("proto".to_string(), "tcp".to_string());
            RouteDef {
                cmd: RouteCmd::Add,
                service: "nats".to_string(),
                src: "localhost:4222".to_string(),
                dst: "tcp://10.0.0.1:4222".to_string(),
                weight: 0.0,
                tags: vec![],
                opts,
                source: RouteSource::Static,
            }
        };
        table.update_services(vec![def]);

        let target = lookup_target(&table, "round-robin", "127.0.0.1:4222");
        assert!(target.is_some(), "Route lookup succeeds");
        let t = target.unwrap();
        assert!(
            !t.is_host_safe(),
            "Static source with RFC1918 target should not be host-safe"
        );
    }

    #[test]
    fn tcp_target_allows_rfc1918_consul_service_source() {
        // ConsulService source allows RFC1918
        let table = Arc::new(ManagedRouteTable::new());
        table.update_services(vec![tcp_def("localhost:4222", "tcp://10.0.0.1:4222")]);

        let target = lookup_target(&table, "round-robin", "127.0.0.1:4222");
        assert!(target.is_some(), "Route should be found");
        let t = target.unwrap();
        assert!(
            t.is_host_safe(),
            "ConsulService source should allow RFC1918 targets"
        );
    }

    #[test]
    fn tcp_target_ssrf_skip_verify_bypasses_check() {
        let table = Arc::new(ManagedRouteTable::new());
        let def = {
            let mut opts = HashMap::new();
            opts.insert("proto".to_string(), "tcp".to_string());
            opts.insert("ssrfskipverify".to_string(), "true".to_string());
            RouteDef {
                cmd: RouteCmd::Add,
                service: "nats".to_string(),
                src: "localhost:4222".to_string(),
                dst: "tcp://10.0.0.1:4222".to_string(),
                weight: 0.0,
                tags: vec![],
                opts,
                source: RouteSource::Static,
            }
        };
        table.update_services(vec![def]);

        let target = lookup_target(&table, "round-robin", "127.0.0.1:4222");
        assert!(target.is_some(), "Route should be found");
        let t = target.unwrap();
        assert!(
            t.ssrf_skip_verify(),
            "Target should have ssrfskipverify enabled"
        );
        // With ssrfskipverify, SSRF check in proxy_tcp_streams passes
        assert!(
            !t.is_host_safe() && t.ssrf_skip_verify(),
            "Loopback blocked by SSRF but ssrfskipverify=true should bypass proxy check"
        );
    }

    }
}

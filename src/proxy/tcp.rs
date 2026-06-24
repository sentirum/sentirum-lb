use crate::config::{Config, SharedConfig};
use crate::route::picker::pick_target_by_strategy;
use crate::route::registry::ManagedRouteTable;
use crate::route::table::Table;
use crate::route::target::Target;
use async_trait::async_trait;
use pingora::services::background::BackgroundService;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::sync::watch;

/// Maximum number of in-flight TCP connections that have been accepted but not
/// yet fully established upstream — i.e. before a per-target slot is acquired
/// and the ClientHello is read/parsed. Caps the memory/CPU a slowloris-style
/// flood of half-open connections can consume before SNI routing completes.
const MAX_INFLIGHT_TCP_CONNS: usize = 8192;

/// Cooldown (wall-clock seconds) between "inflight limit saturated" warnings so
/// a sustained flood does not spam the log while backpressure is applied.
const TCP_INFLIGHT_WARN_COOLDOWN_SECS: u64 = 5;

/// Global bounded semaphore backing [`MAX_INFLIGHT_TCP_CONNS`]. An
/// `OwnedSemaphorePermit` is acquired in the accept loop and moved into each
/// connection task, so it is released automatically when the task ends
/// (success, error, or panic) — no manual bookkeeping required.
static TCP_INFLIGHT_SEMAPHORE: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_INFLIGHT_TCP_CONNS)));

/// Wall-clock seconds of the last "inflight limit saturated" warning; used to
/// rate-limit the log via [`warn_tcp_inflight_saturated`].
static LAST_TCP_INFLIGHT_WARN_SECS: AtomicU64 = AtomicU64::new(0);

/// Emit the "TCP inflight limit saturated" warning at most once per
/// [`TCP_INFLIGHT_WARN_COOLDOWN_SECS`]. Returns `true` when a warning was
/// emitted this call and `false` when it was suppressed by the rate limiter.
fn warn_tcp_inflight_saturated() -> bool {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_TCP_INFLIGHT_WARN_SECS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= TCP_INFLIGHT_WARN_COOLDOWN_SECS {
        LAST_TCP_INFLIGHT_WARN_SECS.store(now, Ordering::Relaxed);
        tracing::warn!(
            limit = MAX_INFLIGHT_TCP_CONNS,
            "TCP inflight connection limit saturated; applying backpressure to new accepts"
        );
        true
    } else {
        false
    }
}

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
    pub config: SharedConfig,
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
                let config = self.config.load();
                let public_listen =
                    crate::proxy::tls::tls_listen_addr(&config.server.listen, &config.tls.listen);
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
    config: SharedConfig,
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
                tracing::info!(
                    listen_port = port,
                    "Dynamic TCP listener shut down gracefully"
                );
            }
            Ok(Err(_)) => {
                tracing::warn!(
                    listen_port = port,
                    "Dynamic TCP listener task failed during shutdown"
                );
            }
            Err(_) => {
                tracing::warn!(
                    listen_port = port,
                    "Dynamic TCP listener grace period elapsed, aborting"
                );
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
    config: SharedConfig,
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
        // Treat a listener whose task has died (e.g. its `TcpListener::bind`
        // failed) as absent so the next reconcile rebinds it instead of
        // leaving a dead handle that is never recovered.
        if let Some(handle) = listeners.get(&port) {
            if !handle.task.is_finished() {
                continue;
            }
            tracing::warn!(
                listen_port = port,
                "Dynamic TCP listener task has exited; rebinding"
            );
            listeners.remove(&port);
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
    config: SharedConfig,
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
    config: SharedConfig,
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

                // Cap in-flight pre-routing connections so a slowloris-style
                // flood of half-open ClientHellos cannot exhaust memory before a
                // per-target slot is acquired. The permit is moved into the
                // spawned task and released automatically on drop.
                let inflight_permit = match TCP_INFLIGHT_SEMAPHORE.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn_tcp_inflight_saturated();
                        // Apply backpressure: wait for a slot. The semaphore is
                        // never closed in normal operation; if it is (teardown),
                        // abandon this accept.
                        match TCP_INFLIGHT_SEMAPHORE.clone().acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => continue,
                        }
                    }
                };

                let route_table = route_table.clone();
                let config = config.clone();
                let mode = mode.clone();
                tokio::spawn(async move {
                    // Hold the permit for the whole connection lifetime; it is
                    // released automatically when the task ends.
                    let _inflight_permit = inflight_permit;
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
    config: SharedConfig,
) -> Result<(), std::io::Error> {
    let local_addr = downstream.local_addr()?;
    let local_addr_str = local_addr.to_string();
    let config_snapshot = config.load();
    let target = match lookup_target(
        &route_table,
        &config_snapshot.proxy.strategy,
        &local_addr_str,
    ) {
        Some(target) => target,
        None => {
            tracing::warn!(local_addr = %local_addr_str, "No TCP route found for local listener");
            return Ok(());
        }
    };

    drop(config_snapshot);
    proxy_tcp_streams(downstream, Vec::new(), target, &config, None).await
}

async fn handle_tcp_sni_connection(
    mut downstream: TcpStream,
    route_table: Arc<ManagedRouteTable>,
    config: SharedConfig,
) -> Result<(), std::io::Error> {
    let config_snapshot = config.load();
    let read_timeout = crate::config::Config::parse_duration(&config_snapshot.proxy.read_timeout);
    let strategy = config_snapshot.proxy.strategy.clone();
    let client_hello = read_client_hello(&mut downstream, read_timeout).await?;
    let server_name = read_server_name(&client_hello[5..])
        .ok_or_else(|| std::io::Error::other("unable to parse TLS client hello server_name"))?;
    if server_name.is_empty() {
        tracing::debug!("tcp+sni: server_name missing");
        return Ok(());
    }

    let target = match lookup_sni_target(&route_table, &strategy, &server_name) {
        Some(target) => target,
        None => {
            tracing::warn!(server_name = %server_name, "No TCP SNI route found");
            return Ok(());
        }
    };

    drop(config_snapshot);
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
    config: SharedConfig,
    https_fallback_addr: &str,
) -> Result<(), std::io::Error> {
    let config_snapshot = config.load();
    let read_timeout = crate::config::Config::parse_duration(&config_snapshot.proxy.read_timeout);
    let strategy = config_snapshot.proxy.strategy.clone();
    // Pre-extract the timeouts used by the fallback path so we can drop the
    // arc_swap guard before the long-lived fallback copy.
    let connect_timeout =
        crate::config::Config::parse_duration(&config_snapshot.proxy.connect_timeout);
    let idle_timeout = crate::config::Config::parse_duration(&config_snapshot.proxy.idle_timeout);

    let mut headers = [0_u8; 9];
    read_exact_with_timeout(&mut downstream, &mut headers, read_timeout).await?;

    let client_hello = match client_hello_buffer_size(&headers) {
        Ok(buffer_size) => {
            let mut data = vec![0_u8; buffer_size];
            data[..9].copy_from_slice(&headers);
            read_exact_with_timeout(&mut downstream, &mut data[9..], read_timeout).await?;
            data
        }
        Err(_) => {
            // Drop the arc_swap guard before the long-lived fallback copy.
            drop(config_snapshot);
            return proxy_to_https_fallback(
                downstream,
                headers.to_vec(),
                https_fallback_addr,
                connect_timeout,
                idle_timeout,
            )
            .await;
        }
    };

    let target = read_server_name(&client_hello[5..])
        .filter(|server_name| !server_name.is_empty())
        .and_then(|server_name| {
            lookup_sni_target(&route_table, &strategy, &server_name)
                .map(|target| (server_name, target))
        });

    if let Some((server_name, target)) = target {
        drop(config_snapshot);
        return proxy_tcp_streams(
            downstream,
            client_hello,
            target,
            &config,
            Some(&server_name),
        )
        .await;
    }

    // Drop the arc_swap guard before the long-lived fallback copy.
    drop(config_snapshot);
    proxy_to_https_fallback(
        downstream,
        client_hello,
        https_fallback_addr,
        connect_timeout,
        idle_timeout,
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
    pick_target_by_strategy(
        strategy,
        &route.targets,
        &route.w_targets,
        &route.rr_counter,
    )
}

fn lookup_sni_target(
    route_table: &Arc<ManagedRouteTable>,
    strategy: &str,
    server_name: &str,
) -> Option<Arc<Target>> {
    let table = route_table.get();
    let table: &Table = &table;
    let route = table.lookup_tcp_sni_route(server_name)?;
    pick_target_by_strategy(
        strategy,
        &route.targets,
        &route.w_targets,
        &route.rr_counter,
    )
}

async fn proxy_tcp_streams(
    mut downstream: TcpStream,
    initial_bytes: Vec<u8>,
    target: Arc<Target>,
    config: &SharedConfig,
    server_name: Option<&str>,
) -> Result<(), std::io::Error> {
    let config_snapshot = config.load();
    let max_connections = config_snapshot.proxy.max_connections as u64;
    if !target.try_acquire_connection_slot(max_connections) {
        match server_name {
            Some(server_name) => {
                tracing::warn!(server_name = %server_name, target_url = %target.url, max_connections, "TCP SNI upstream concurrency limit reached")
            }
            None => {
                tracing::warn!(target_url = %target.url, max_connections, "TCP upstream concurrency limit reached")
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

    let mut upstream = match connect_upstream(&target, config_snapshot.as_ref()).await {
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

    // Extract the idle timeout while the snapshot is still valid, then drop the
    // arc_swap guard immediately. Holding it across the long-lived copy below
    // would pin an arc_swap debt slot for the whole connection lifetime and
    // stall the HTTP hot-path `load()`.
    let idle_timeout = crate::config::Config::parse_duration(&config_snapshot.proxy.idle_timeout);
    drop(config_snapshot);

    if target.proxy_proto() {
        write_proxy_header(&mut upstream, &downstream).await?;
    }

    if !initial_bytes.is_empty() {
        upstream.write_all(&initial_bytes).await?;
        upstream.flush().await?;
    }

    let _ = copy_bidirectional_with_idle(&mut downstream, &mut upstream, idle_timeout).await?;
    Ok(())
}

async fn proxy_to_https_fallback(
    mut downstream: TcpStream,
    initial_bytes: Vec<u8>,
    fallback_addr: &str,
    connect_timeout: Duration,
    idle_timeout: Duration,
) -> Result<(), std::io::Error> {
    let mut upstream = connect_with_timeout(fallback_addr, connect_timeout).await?;
    if !initial_bytes.is_empty() {
        upstream.write_all(&initial_bytes).await?;
        upstream.flush().await?;
    }
    let _ = copy_bidirectional_with_idle(&mut downstream, &mut upstream, idle_timeout).await?;
    Ok(())
}

async fn connect_upstream(target: &Target, config: &Config) -> Result<TcpStream, std::io::Error> {
    let resolved = target.resolve_upstream_addr().await?;
    // Connect with the already-resolved SocketAddr instead of round-tripping it
    // through a string parse; the string/hostname path is reserved for the
    // HTTPS fallback upstream.
    let connect_timeout = crate::config::Config::parse_duration(&config.proxy.connect_timeout);
    connect_with_timeout(resolved, connect_timeout).await
}

/// Connect to `addr` (a resolved `SocketAddr` for direct upstreams, or a
/// hostname:port string for the HTTPS fallback), applying the configured
/// connect timeout. A zero timeout disables the deadline.
async fn connect_with_timeout<A>(addr: A, timeout: Duration) -> Result<TcpStream, std::io::Error>
where
    A: tokio::net::ToSocketAddrs,
{
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
    let header = format_proxy_header(client, server);
    upstream.write_all(header.as_bytes()).await?;
    Ok(())
}

/// Build a PROXY protocol v1 header line for the given client/server pair.
///
/// Both addresses are normalized with [`IpAddr::to_canonical`] so an IPv4 client
/// accepted on a dual-stack (`::`) listener — which arrives as an IPv4-mapped
/// IPv6 address (`::ffff:a.b.c.d`) — yields a correct `PROXY TCP4` line instead
/// of the malformed `PROXY TCP6 ::ffff:a.b.c.d ...`.
fn format_proxy_header(client: SocketAddr, server: SocketAddr) -> String {
    let client_ip = client.ip().to_canonical();
    let server_ip = server.ip().to_canonical();
    let proto = if client_ip.is_ipv4() { "TCP4" } else { "TCP6" };
    format!(
        "PROXY {proto} {client_ip} {server_ip} {} {}\r\n",
        client.port(),
        server.port()
    )
}

/// Bidirectional copy between `downstream` and `upstream` with an idle timeout
/// that is reset on every chunk of progress.
///
/// Unlike a total-duration cap, only uninterrupted idleness (neither side sends
/// data) for `idle` triggers a `TimedOut` error. This reaps half-open
/// connections whose peer vanished without FIN/RST — which would otherwise pin
/// the connection, the per-target slot, and the copy buffers until the OS
/// keepalive (~2h) — while long-lived but chatty protocols (NATS heartbeats,
/// etc.) stay alive. `idle == Duration::ZERO` disables the cap and falls back
/// to the plain `copy_bidirectional`.
///
/// Returns `(downstream_to_upstream_bytes, upstream_to_downstream_bytes)`.
async fn copy_bidirectional_with_idle(
    downstream: &mut TcpStream,
    upstream: &mut TcpStream,
    idle: Duration,
) -> Result<(u64, u64), std::io::Error> {
    if idle.is_zero() {
        return copy_bidirectional(downstream, upstream).await;
    }

    let (mut down_read, mut down_write) = downstream.split();
    let (mut up_read, mut up_write) = upstream.split();
    let mut down_buf = [0_u8; 8 * 1024];
    let mut up_buf = [0_u8; 8 * 1024];
    let mut downstream_to_upstream: u64 = 0;
    let mut upstream_to_downstream: u64 = 0;

    // Half-close bookkeeping. tokio's `copy_bidirectional`, on a one-sided EOF,
    // shuts down the peer's write half and keeps relaying the other direction
    // until it also closes. We mirror that so request/response and half-close
    // protocols (FTP data channels, `nc -N`, RPC shutdown(WR)+read) are not
    // truncated when `idle` is non-zero — which it is by default
    // (`proxy.idle_timeout` defaults to 120s).
    let mut down_eof = false;
    let mut up_eof = false;

    loop {
        if down_eof && up_eof {
            return Ok((downstream_to_upstream, upstream_to_downstream));
        }

        // The sleep is re-armed every iteration, so the idle deadline only
        // fires after a full `idle` period with no progress in any still-open
        // direction. A disabled read branch (its EOF already seen) is never
        // polled again.
        tokio::select! {
            n = down_read.read(&mut down_buf), if !down_eof => {
                let n = n?;
                if n == 0 {
                    // Downstream finished sending: signal EOF to the upstream
                    // write side and stop polling this direction, but keep
                    // relaying upstream -> downstream.
                    let _ = up_write.shutdown().await;
                    down_eof = true;
                } else {
                    up_write.write_all(&down_buf[..n]).await?;
                    downstream_to_upstream += n as u64;
                }
            }
            n = up_read.read(&mut up_buf), if !up_eof => {
                let n = n?;
                if n == 0 {
                    let _ = down_write.shutdown().await;
                    up_eof = true;
                } else {
                    down_write.write_all(&up_buf[..n]).await?;
                    upstream_to_downstream += n as u64;
                }
            }
            _ = tokio::time::sleep(idle) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TCP proxy idle timeout",
                ));
            }
        }
    }
}

async fn read_exact_with_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), std::io::Error> {
    if timeout.is_zero() {
        stream.read_exact(buf).await?;
        return Ok(());
    }

    tokio::time::timeout(timeout, stream.read_exact(buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP read timed out"))??;
    Ok(())
}

async fn read_client_hello(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>, std::io::Error> {
    let mut headers = [0_u8; 9];
    read_exact_with_timeout(stream, &mut headers, timeout).await?;
    let buffer_size = client_hello_buffer_size(&headers)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut data = vec![0_u8; buffer_size];
    data[..9].copy_from_slice(&headers);
    read_exact_with_timeout(stream, &mut data[9..], timeout).await?;
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
    use crate::route::definition::{RouteCmd, RouteDef, RouteSource};
    use crate::test_support::tcp_shared_test_config;
    use std::collections::HashMap;

    const CLIENT_HELLO_WITH_SNI_HEX: &str = "0100014803032657cacce41598fa82e5b75061050bc31c5affdba106b8e743185224af0fa1aa000098cc14cc13cc15c030c02cc028c024c014c00a00a3009f006b006a00390038ff8500c400c3008800870081c032c02ec02ac026c00fc005009d003d003500c00084c02fc02bc027c023c013c00900a2009e006700400033003200be00bd00450044c031c02dc029c025c00ec004009c003c002f00ba0041c011c007c00cc00200050004c012c00800160013c00dc003000a00150012000900ff010000870000000f000d00000a676f6f676c652e636f6d000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000d00260024060106020603efef050105020503040104020403eeeeeded030103020303020102020203";

    fn config() -> SharedConfig {
        tcp_shared_test_config()
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
        let config = config();
        assert_eq!(
            resolve_tcp_mode(config.load().as_ref()).unwrap(),
            TcpMode::Disabled
        );
    }

    #[test]
    fn resolve_tcp_mode_supports_fixed_sni_and_dynamic_modes() {
        let mut fixed = (*config().load_full()).clone();
        fixed.tcp.mode = "tcp".to_string();
        fixed.tcp.listen = ":4222".to_string();
        assert_eq!(
            resolve_tcp_mode(&fixed).unwrap(),
            TcpMode::Tcp {
                listen: ":4222".to_string()
            }
        );

        let mut sni = (*config().load_full()).clone();
        sni.tcp.mode = "tcp+sni".to_string();
        sni.tcp.listen = ":443".to_string();
        assert_eq!(
            resolve_tcp_mode(&sni).unwrap(),
            TcpMode::TcpSni {
                listen: ":443".to_string()
            }
        );

        let mut https_sni = (*config().load_full()).clone();
        https_sni.tcp.mode = "https+tcp+sni".to_string();
        assert_eq!(resolve_tcp_mode(&https_sni).unwrap(), TcpMode::HttpsTcpSni);

        let mut dynamic = (*config().load_full()).clone();
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
    }

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
        table.load_static(&[def]);

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
        table.load_static(&[def]);

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
    #[test]
    fn format_proxy_header_canonicalizes_ipv4_mapped_ipv6() {
        // A real IPv4 client address → TCP4 line.
        let v4_client = SocketAddr::from(([10, 11, 12, 13], 1234));
        let v4_server = SocketAddr::from(([192, 0, 2, 1], 80));
        let header = format_proxy_header(v4_client, v4_server);
        assert!(
            header.starts_with("PROXY TCP4 10.11.12.13 192.0.2.1 1234 80\r\n"),
            "unexpected v4 header: {header}"
        );

        // A dual-stack listener yields the client as an IPv4-mapped IPv6 addr
        // (::ffff:a.b.c.d). It must be normalized to TCP4, not emitted as TCP6.
        let mapped_client: SocketAddr = "[::ffff:10.11.12.13]:1234".parse().unwrap();
        let mapped_server: SocketAddr = "[::ffff:192.0.2.1]:80".parse().unwrap();
        let header = format_proxy_header(mapped_client, mapped_server);
        assert!(
            header.starts_with("PROXY TCP4 10.11.12.13 192.0.2.1 1234 80\r\n"),
            "v4-mapped-v6 must canonicalize to TCP4: {header}"
        );
        assert!(
            !header.contains("::ffff"),
            "header must not contain a mapped-v6 literal: {header}"
        );

        // A genuine IPv6 client address stays TCP6.
        let v6_client: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        let v6_server: SocketAddr = "[2001:db8::2]:80".parse().unwrap();
        let header = format_proxy_header(v6_client, v6_server);
        assert!(
            header.starts_with("PROXY TCP6 2001:db8::1 2001:db8::2 1234 80\r\n"),
            "unexpected v6 header: {header}"
        );
    }

    #[tokio::test]
    async fn copy_bidirectional_with_idle_reaps_idle_connection() {
        // downstream pair (client side + server side)
        let d_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let d_addr = d_listener.local_addr().unwrap();
        let d_accept = tokio::spawn(async move { d_listener.accept().await.unwrap().0 });
        let mut d_client = TcpStream::connect(d_addr).await.unwrap();
        let d_server = d_accept.await.unwrap();

        // upstream pair (client side + server side)
        let u_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let u_addr = u_listener.local_addr().unwrap();
        let u_accept = tokio::spawn(async move { u_listener.accept().await.unwrap().0 });
        let mut u_client = TcpStream::connect(u_addr).await.unwrap();
        let u_server = u_accept.await.unwrap();

        let idle = Duration::from_millis(200);
        let mut d_server = d_server;
        let mut u_server = u_server;
        let copy = tokio::spawn(async move {
            copy_bidirectional_with_idle(&mut d_server, &mut u_server, idle).await
        });

        // 1) Data flows both ways while the connection is active (the idle timer
        //    is reset by each chunk of progress).
        d_client.write_all(b"hello-downstream").await.unwrap();
        let mut buf = [0_u8; 32];
        let n = u_client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-downstream");

        u_client.write_all(b"hello-upstream").await.unwrap();
        let n = d_client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-upstream");

        // 2) With no further data in either direction, the copy must time out
        //    rather than blocking forever (half-open reap). Allow generous
        //    slack for slow CI.
        let result = tokio::time::timeout(Duration::from_secs(3), copy)
            .await
            .expect("idle copy did not finish in time")
            .expect("copy task panicked");
        let err = result.expect_err("expected an idle-timeout error");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn copy_bidirectional_with_idle_preserves_half_close() {
        // downstream pair (client side + server side)
        let d_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let d_addr = d_listener.local_addr().unwrap();
        let d_accept = tokio::spawn(async move { d_listener.accept().await.unwrap().0 });
        let mut d_client = TcpStream::connect(d_addr).await.unwrap();
        let d_server = d_accept.await.unwrap();

        // upstream pair (client side + server side)
        let u_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let u_addr = u_listener.local_addr().unwrap();
        let u_accept = tokio::spawn(async move { u_listener.accept().await.unwrap().0 });
        let mut u_client = TcpStream::connect(u_addr).await.unwrap();
        let u_server = u_accept.await.unwrap();

        // Generous idle: this test exercises half-close, not the idle reaper.
        let mut d_server = d_server;
        let mut u_server = u_server;
        let copy = tokio::spawn(async move {
            copy_bidirectional_with_idle(&mut d_server, &mut u_server, Duration::from_secs(30))
                .await
        });

        // Client sends a request and half-closes its write side (shutdown(WR)).
        d_client.write_all(b"REQUEST").await.unwrap();
        d_client.shutdown().await.unwrap();

        // Upstream reads the full request, then sends a response larger than a
        // single relay buffer (exercises the loop), then also half-closes.
        let mut req = [0_u8; 64];
        let n = u_client.read(&mut req).await.unwrap();
        assert_eq!(&req[..n], b"REQUEST");

        let response: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
        u_client.write_all(&response).await.unwrap();
        u_client.shutdown().await.unwrap();

        // The client MUST receive the full response despite having half-closed
        // its write side first. A loop that `break`s on the first EOF (the old
        // bug) would truncate this to zero bytes.
        let mut received = Vec::new();
        let mut buf = [0_u8; 512];
        loop {
            let n = d_client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            received, response,
            "half-closed response must not be truncated"
        );

        // Both directions EOF'd → the copy returns Ok with accurate byte counts.
        let (down_to_up, up_to_down) = tokio::time::timeout(Duration::from_secs(5), copy)
            .await
            .expect("copy did not finish after both half-closes")
            .expect("copy task panicked")
            .expect("copy should complete cleanly on a symmetric half-close");
        assert_eq!(down_to_up, b"REQUEST".len() as u64);
        assert_eq!(up_to_down, response.len() as u64);
    }

    #[tokio::test]
    async fn reconcile_rebinds_dead_dynamic_listener() {
        // Reserve a free port; reconcile will bind 0.0.0.0:{port}.
        let probe = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let route_table = Arc::new(ManagedRouteTable::new());
        route_table.update_services(vec![tcp_def(&format!(":{port}"), "tcp://10.0.0.10:4222")]);

        let config = config();
        let mut listeners: HashMap<u16, DynamicListenerHandle> = HashMap::new();

        // Seed a handle whose task has already exited (simulates a failed bind
        // that returned immediately, leaving a dead handle that must be rebound).
        let (dead_tx, _dead_rx) = watch::channel(false);
        let dead_task = tokio::spawn(async {});
        while !dead_task.is_finished() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        listeners.insert(
            port,
            DynamicListenerHandle {
                shutdown: dead_tx,
                task: dead_task,
            },
        );

        reconcile_dynamic_listeners(&mut listeners, route_table, config).await;

        // The dead handle must have been replaced with a live, running listener.
        let handle = listeners
            .get(&port)
            .expect("listener should be present after reconcile");
        // Give the freshly spawned task a chance to bind; a live listener stays
        // running (blocked on accept), a failed one would finish immediately.
        for _ in 0..40 {
            if handle.task.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            !handle.task.is_finished(),
            "reconcile should have rebound a live listener, not left it dead"
        );

        // Tear down the spawned listener.
        let _ = handle.shutdown.send(true);
    }

    #[test]
    fn inflight_saturation_warning_is_rate_limited() {
        // Pretend we last warned at the epoch so the first call emits.
        LAST_TCP_INFLIGHT_WARN_SECS.store(0, Ordering::Relaxed);
        assert!(
            warn_tcp_inflight_saturated(),
            "first call after cooldown should warn"
        );
        assert!(
            !warn_tcp_inflight_saturated(),
            "immediate second call within cooldown should be suppressed"
        );
        // A last-warn timestamp far in the future also suppresses.
        LAST_TCP_INFLIGHT_WARN_SECS.store(u64::MAX, Ordering::Relaxed);
        assert!(
            !warn_tcp_inflight_saturated(),
            "call when last-warn is far in the future should be suppressed"
        );
        // Restore the shared static for any other tests.
        LAST_TCP_INFLIGHT_WARN_SECS.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn connect_with_timeout_accepts_socketaddr_and_str() {
        // SocketAddr-typed connect (fix #6: resolved upstream connects directly,
        // no string round-trip).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let via_socketaddr = connect_with_timeout(addr, Duration::from_secs(2))
            .await
            .expect("SocketAddr connect should succeed");
        drop(via_socketaddr);

        // String-typed connect (reserved for the fallback hostname path).
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let _accept2 = tokio::spawn(async move {
            let _ = listener2.accept().await;
        });
        let via_str = connect_with_timeout(addr2.to_string(), Duration::from_secs(2))
            .await
            .expect("string connect should succeed");
        drop(via_str);
    }
}

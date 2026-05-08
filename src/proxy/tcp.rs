use crate::config::Config;
use crate::route::picker::{Picker, create_picker};
use crate::route::registry::ManagedRouteTable;
use crate::route::table::Table;
use crate::route::target::Target;
use async_trait::async_trait;
use pingora::apps::ServerApp;
use pingora::connectors::TransportConnector;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service as ListeningService;
use pingora::upstreams::peer::BasicPeer;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct TcpProxyApp {
    route_table: Arc<ManagedRouteTable>,
    picker: Box<dyn Picker>,
    config: Arc<Config>,
    listen_port: u16,
    client_connector: TransportConnector,
}

impl TcpProxyApp {
    pub fn new(route_table: Arc<ManagedRouteTable>, config: Arc<Config>, listen_port: u16) -> Self {
        Self {
            route_table,
            picker: create_picker(&config.proxy.strategy),
            config,
            listen_port,
            client_connector: TransportConnector::new(None),
        }
    }

    fn lookup_target(&self) -> Option<Arc<Target>> {
        let table = self.route_table.get();
        let table: &Table = &table;
        let route = table.lookup_tcp_route(self.listen_port)?;
        self.picker
            .pick(&route.targets, &route.w_targets, &route.rr_counter)
    }

    async fn connect_upstream(&self, target: &Target) -> Option<Stream> {
        if !target.is_host_safe() && !target.ssrf_skip_verify() {
            tracing::warn!(
                listen_port = self.listen_port,
                host = target.upstream_host(),
                service = %target.service,
                "Blocked TCP upstream target: private/reserved IP (SSRF protection)"
            );
            return None;
        }

        let host = target.upstream_host();
        let port = target.upstream_port();
        let addr_str = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };

        let mut addrs = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs,
            Err(error) => {
                tracing::warn!(listen_port = self.listen_port, host, port, %error, "TCP DNS resolution failed");
                return None;
            }
        };

        let resolved = match addrs.next() {
            Some(addr) => addr,
            None => {
                tracing::warn!(listen_port = self.listen_port, host, port, "No TCP upstream IP addresses found");
                return None;
            }
        };

        if !target.ssrf_skip_verify()
            && (crate::route::target::is_ip_always_blocked(&resolved.ip())
                || (!target.source_allows_private_upstreams()
                    && crate::route::target::is_ip_rfc1918(&resolved.ip())))
        {
            tracing::warn!(
                listen_port = self.listen_port,
                host,
                resolved_ip = %resolved.ip(),
                service = %target.service,
                source = ?target.source,
                "Blocked TCP upstream target during resolution (SSRF protection)"
            );
            return None;
        }

        let peer = BasicPeer::new(&resolved.to_string());
        match self.client_connector.new_stream(&peer).await {
            Ok(stream) => Some(stream),
            Err(error) => {
                tracing::warn!(
                    listen_port = self.listen_port,
                    target_url = %target.url,
                    %error,
                    "Failed to open TCP upstream connection"
                );
                None
            }
        }
    }

    async fn duplex(&self, mut downstream: Stream, mut upstream: Stream) {
        let mut downstream_buf = [0_u8; 16 * 1024];
        let mut upstream_buf = [0_u8; 16 * 1024];

        loop {
            tokio::select! {
                read = downstream.read(&mut downstream_buf) => {
                    let read = match read {
                        Ok(read) => read,
                        Err(error) => {
                            tracing::debug!(listen_port = self.listen_port, %error, "TCP downstream read failed");
                            return;
                        }
                    };
                    if read == 0 {
                        return;
                    }
                    if upstream.write_all(&downstream_buf[..read]).await.is_err() {
                        return;
                    }
                    if upstream.flush().await.is_err() {
                        return;
                    }
                }
                read = upstream.read(&mut upstream_buf) => {
                    let read = match read {
                        Ok(read) => read,
                        Err(error) => {
                            tracing::debug!(listen_port = self.listen_port, %error, "TCP upstream read failed");
                            return;
                        }
                    };
                    if read == 0 {
                        return;
                    }
                    if downstream.write_all(&upstream_buf[..read]).await.is_err() {
                        return;
                    }
                    if downstream.flush().await.is_err() {
                        return;
                    }
                }
            }
        }
    }
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

#[async_trait]
impl ServerApp for TcpProxyApp {
    async fn process_new(self: &Arc<Self>, io: Stream, _shutdown: &ShutdownWatch) -> Option<Stream> {
        let target = match self.lookup_target() {
            Some(target) => target,
            None => {
                tracing::warn!(listen_port = self.listen_port, "No TCP route found for listener port");
                return None;
            }
        };

        if !try_acquire_upstream_slot(&target, self.config.proxy.max_connections) {
            tracing::warn!(
                listen_port = self.listen_port,
                target_url = %target.url,
                max_connections = self.config.proxy.max_connections,
                "TCP upstream concurrency limit reached"
            );
            return None;
        }

        crate::metrics::prometheus::global().connect();
        let _guard = TcpConnectionGuard {
            target: target.clone(),
        };

        let upstream = match self.connect_upstream(&target).await {
            Some(upstream) => upstream,
            None => return None,
        };

        self.duplex(io, upstream).await;
        None
    }
}

pub fn tcp_proxy_service(
    route_table: Arc<ManagedRouteTable>,
    config: Arc<Config>,
    listen_addr: String,
    listen_port: u16,
) -> ListeningService<TcpProxyApp> {
    let mut service = ListeningService::new(
        format!("TCP proxy :{listen_port}"),
        TcpProxyApp::new(route_table, config, listen_port),
    );
    service.add_tcp(&listen_addr);
    service
}

pub fn tcp_listen_addr(base_addr: &str, port: u16) -> String {
    if let Some(host) = base_addr.strip_prefix(':') {
        let _ = host;
        return format!(":{port}");
    }

    if let Some(end) = base_addr.find(']')
        && base_addr.starts_with('[')
        && base_addr[end..].starts_with("]:")
    {
        return format!("{}:{}", &base_addr[..=end], port);
    }

    if let Some((host, _)) = base_addr.rsplit_once(':') {
        return format!("{host}:{port}");
    }

    format!(":{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ConsulConfig, LoggingConfig, ProxyConfig, ServerConfig, TlsConfig};
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
            consul: ConsulConfig::default(),
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
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
    fn tcp_listen_addr_preserves_host() {
        assert_eq!(tcp_listen_addr(":9999", 4222), ":4222");
        assert_eq!(tcp_listen_addr("127.0.0.1:9999", 4222), "127.0.0.1:4222");
        assert_eq!(tcp_listen_addr("[::1]:9999", 4222), "[::1]:4222");
    }

    #[test]
    fn lookup_target_uses_tcp_port_route() {
        let table = Arc::new(ManagedRouteTable::new());
        table.update_services(vec![tcp_def(":4222", "tcp://10.0.0.10:4222")]);

        let app = TcpProxyApp::new(table, config(), 4222);
        let target = app.lookup_target().expect("tcp target should exist");
        assert_eq!(target.url, "tcp://10.0.0.10:4222");
    }
}

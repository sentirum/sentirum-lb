//! Active health checking for upstream targets.
//!
//! Periodic HTTP/TCP probes to upstream targets. Health status integrates
//! with the existing circuit breaker: consecutive probe failures mark a
//! target as unhealthy, and consecutive successes mark it healthy again.

use crate::config::SharedConfig;
use crate::route::registry::ManagedRouteTable;
use futures::stream::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing;

/// Active health checker for upstream targets.
pub struct HealthChecker {
    config: HealthCheckConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HealthCheckConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub fall: usize,
    pub rise: usize,
    pub path: String,
    /// Whether to skip TLS verification for HTTPS probes.
    pub tls_skip_verify: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            timeout: Duration::from_secs(5),
            fall: 3,
            rise: 2,
            path: "/".to_string(),
            tls_skip_verify: false,
        }
    }
}

impl HealthCheckConfig {
    pub fn from_proxy_config(config: &crate::config::ProxyConfig) -> Self {
        Self {
            interval: crate::config::Config::parse_duration(&config.health_check_interval),
            timeout: crate::config::Config::parse_duration(&config.health_check_timeout),
            fall: config.health_check_fall,
            rise: config.health_check_rise,
            path: config.health_check_path.clone(),
            tls_skip_verify: config.health_check_tls_skip_verify,
        }
    }
}

impl HealthChecker {
    pub fn new(config: HealthCheckConfig) -> Self {
        Self { config }
    }

    /// Perform an HTTP health check against the already SSRF-checked address.
    /// The URL keeps the original host for Host/SNI while Reqwest is pinned to
    /// `addr`, preventing a second DNS lookup from rebinding to a blocked IP.
    async fn probe_http(
        &self,
        scheme: &str,
        host: &str,
        port: u16,
        addr: SocketAddr,
    ) -> Result<(), String> {
        let mut client_builder = reqwest::Client::builder()
            .timeout(self.config.timeout)
            .no_proxy()
            .resolve(host, addr)
            .redirect(reqwest::redirect::Policy::none());
        if self.config.tls_skip_verify {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }
        let client = client_builder
            .build()
            .map_err(|e| format!("failed to build health check HTTP client: {e}"))?;
        let url_host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        let url = format!("{scheme}://{url_host}:{port}{}", self.config.path);
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("health check request failed: {e}"))?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("health check returned status {status}"))
        }
    }

    /// Perform a bounded TCP connect health check against an SSRF-checked address.
    async fn probe_tcp(&self, addr: SocketAddr) -> Result<(), String> {
        tokio::time::timeout(self.config.timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| format!("TCP connect timed out after {:?}", self.config.timeout))?
            .map(|_| ())
            .map_err(|e| format!("TCP connect failed: {e}"))
    }

    /// Run a single health check probe against a target.
    /// Returns true if the probe succeeded.
    pub async fn check_target(&self, target: &crate::route::target::Target) -> bool {
        let host = target.upstream_host();
        let port = target.upstream_port();

        // ponytail: security — resolve once through the proxy's SSRF filter,
        // then pin both HTTP and TCP probes to exactly that checked address.
        let resolved_addr = match target.resolve_upstream_addr().await {
            Ok(addr) => addr,
            Err(e) => {
                let metrics = crate::metrics::prometheus::global();
                metrics
                    .health_check_probes_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .health_check_probe_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    host,
                    port,
                    service = %target.service,
                    error = %e,
                    "Health check probe blocked by SSRF policy"
                );
                target
                    .health_tracker
                    .record_health_check_failure(self.config.fall);
                return false;
            }
        };

        let result = if target.upstream_tls() {
            self.probe_http("https", host, port, resolved_addr).await
        } else {
            // For non-TLS targets, try HTTP probe first, fallback to TCP.
            match self.probe_http("http", host, port, resolved_addr).await {
                Ok(()) => Ok(()),
                Err(http_err) => match self.probe_tcp(resolved_addr).await {
                    Ok(()) => Ok(()),
                    Err(tcp_err) => Err(format!("{http_err}; TCP fallback: {tcp_err}")),
                },
            }
        };

        let metrics = crate::metrics::prometheus::global();
        metrics
            .health_check_probes_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        match result {
            Ok(()) => {
                tracing::trace!(
                    host,
                    port,
                    service = %target.service,
                    "Health check probe succeeded"
                );
                target
                    .health_tracker
                    .record_health_check_success(self.config.rise);
                true
            }
            Err(err) => {
                metrics
                    .health_check_probe_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!(
                    host,
                    port,
                    service = %target.service,
                    error = %err,
                    "Health check probe failed"
                );
                target
                    .health_tracker
                    .record_health_check_failure(self.config.fall);
                false
            }
        }
    }

    /// Get a reference to the config.
    pub fn config(&self) -> &HealthCheckConfig {
        &self.config
    }
}

/// Run the background health check loop.
/// Periodically probes all targets in the route table.
/// Accepts an optional shutdown watcher for graceful termination.
pub async fn run_health_checks(route_table: Arc<ManagedRouteTable>, config: SharedConfig) {
    run_health_checks_with_shutdown(route_table, config, None).await
}

/// Run the background health check loop with optional shutdown signal.
///
/// Re-reads runtime config each tick so that `PUT /admin/config` changes
/// (interval, timeout, fall, rise, path, tls_skip_verify) take effect
/// immediately without restarting the process.
pub async fn run_health_checks_with_shutdown(
    route_table: Arc<ManagedRouteTable>,
    config: SharedConfig,
    mut shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) {
    let proxy_config = &config.load().proxy;
    let hc_config = HealthCheckConfig::from_proxy_config(proxy_config);

    // ponytail: never exit on a zero interval — that would make runtime
    // re-enabling impossible (the task would already be dead). Instead start
    // the loop unconditionally; when disabled we just sleep on a short guard
    // interval and re-read config until it is re-enabled.
    const DISABLED_GUARD: std::time::Duration = std::time::Duration::from_secs(1);

    let mut checker = Arc::new(HealthChecker::new(hc_config.clone()));
    let mut disabled = hc_config.interval.is_zero();
    let mut ticker_period = if disabled {
        DISABLED_GUARD
    } else {
        hc_config.interval
    };

    tracing::info!(
        enabled = !disabled,
        interval_secs = hc_config.interval.as_secs(),
        timeout_secs = hc_config.timeout.as_secs(),
        fall = hc_config.fall,
        rise = hc_config.rise,
        path = %hc_config.path,
        "Active health checker started"
    );

    let mut ticker =
        tokio::time::interval_at(tokio::time::Instant::now() + ticker_period, ticker_period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Check shutdown signal before each round
        if let Some(rx) = &mut shutdown
            && *rx.borrow()
        {
            tracing::info!("Health checker shutting down");
            return;
        }

        // Wait for next tick, checking shutdown
        tokio::select! {
            _ = ticker.tick() => {}
            _ = async {
                if let Some(rx) = &mut shutdown {
                    let _ = rx.changed().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                tracing::info!("Health checker shutting down");
                return;
            }
        }

        // Hot-reload: re-read config each tick so runtime changes take effect.
        let proxy_config = &config.load().proxy;
        let new_hc_config = HealthCheckConfig::from_proxy_config(proxy_config);

        let new_disabled = new_hc_config.interval.is_zero();
        let new_ticker_period = if new_disabled {
            DISABLED_GUARD
        } else {
            new_hc_config.interval
        };

        // Keep scheduler state separate from checker config. Otherwise a
        // disable -> enable transition with unchanged settings leaves the
        // ticker stuck at the one-second disabled guard period.
        if new_ticker_period != ticker_period {
            ticker_period = new_ticker_period;
            ticker = tokio::time::interval_at(
                tokio::time::Instant::now() + ticker_period,
                ticker_period,
            );
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        }
        if new_disabled != disabled {
            disabled = new_disabled;
            tracing::info!(enabled = !disabled, "Active health checking state changed");
        }
        if disabled {
            continue;
        }

        // Rebuild checker if any probe parameter changed.
        if new_hc_config != checker.config {
            tracing::info!(
                old_interval_secs = checker.config.interval.as_secs(),
                new_interval_secs = new_hc_config.interval.as_secs(),
                old_timeout_secs = checker.config.timeout.as_secs(),
                new_timeout_secs = new_hc_config.timeout.as_secs(),
                old_fall = checker.config.fall,
                new_fall = new_hc_config.fall,
                old_rise = checker.config.rise,
                new_rise = new_hc_config.rise,
                old_path = %checker.config.path,
                new_path = %new_hc_config.path,
                "Health checker config hot-reloaded"
            );
            checker = Arc::new(HealthChecker::new(new_hc_config));
        }

        let table = route_table.get();
        let targets = table.all_targets();

        if targets.is_empty() {
            continue;
        }

        tracing::debug!(target_count = targets.len(), "Running health check probes");

        // Probe all targets concurrently with bounded parallelism
        // to avoid DNS/connection pool fan-out spikes.
        const MAX_PROBE_CONCURRENCY: usize = 32;
        let probe_futures: Vec<_> = targets
            .iter()
            .map(|target| {
                let checker = Arc::clone(&checker);
                let target = Arc::clone(target);
                async move { checker.check_target(&target).await }
            })
            .collect();
        let results: Vec<bool> = futures::stream::iter(probe_futures)
            .buffer_unordered(MAX_PROBE_CONCURRENCY)
            .collect()
            .await;
        let successes = results.iter().filter(|&&r| r).count();
        let failures = results.len() - successes;

        if failures > 0 {
            tracing::info!(
                total = results.len(),
                successes,
                failures,
                "Health check round completed"
            );
        } else {
            tracing::trace!(
                total = results.len(),
                successes,
                "Health check round completed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::target::TargetHealthTracker;

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert_eq!(config.interval, Duration::from_secs(15));
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.fall, 3);
        assert_eq!(config.rise, 2);
        assert_eq!(config.path, "/");
    }

    #[test]
    fn test_health_check_config_from_proxy() {
        let proxy = crate::config::ProxyConfig::default();
        let config = HealthCheckConfig::from_proxy_config(&proxy);
        assert_eq!(config.interval, Duration::from_secs(15));
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.fall, 3);
        assert_eq!(config.rise, 2);
    }

    #[test]
    fn test_health_checker_marks_unhealthy_after_fall() {
        let tracker = TargetHealthTracker::new();
        // Record 3 consecutive failures (fall=3)
        tracker.record_health_check_failure(3); // consecutive_failures = 1
        assert!(tracker.is_probe_healthy()); // still healthy (need 3)
        tracker.record_health_check_failure(3); // consecutive_failures = 2
        assert!(tracker.is_probe_healthy()); // still healthy (need 3)
        tracker.record_health_check_failure(3); // consecutive_failures = 3
        assert!(
            !tracker.is_probe_healthy(),
            "Should be unhealthy after fall consecutive failures"
        );
    }

    #[test]
    fn test_health_checker_marks_healthy_after_rise() {
        let tracker = TargetHealthTracker::new();
        // First mark unhealthy with 3 failures
        tracker.record_health_check_failure(3);
        tracker.record_health_check_failure(3);
        tracker.record_health_check_failure(3);
        assert!(!tracker.is_probe_healthy());

        // Then mark healthy with consecutive successes (rise=2)
        tracker.record_health_check_success(2); // consecutive_successes = 1
        assert!(!tracker.is_probe_healthy()); // still unhealthy (need 2)
        tracker.record_health_check_success(2); // consecutive_successes = 2
        assert!(
            tracker.is_probe_healthy(),
            "Should be healthy after rise consecutive successes"
        );
    }

    #[test]
    fn test_health_checker_starts_healthy() {
        let tracker = TargetHealthTracker::new();
        assert!(
            tracker.is_probe_healthy(),
            "Should start healthy by default"
        );
    }

    #[test]
    fn test_health_check_mixed_results() {
        let tracker = TargetHealthTracker::new();
        // 2 failures not enough for fall=3
        tracker.record_health_check_failure(3); // consecutive_failures = 1
        assert!(tracker.is_probe_healthy());
        tracker.record_health_check_failure(3); // consecutive_failures = 2
        assert!(tracker.is_probe_healthy()); // still need 3
        // Success resets consecutive failures
        tracker.record_health_check_success(2); // resets failures, consecutive_successes = 1
        // Now 1 more failure should not make unhealthy (counter reset)
        tracker.record_health_check_failure(3); // consecutive_failures = 1
        assert!(tracker.is_probe_healthy()); // still healthy
    }

    #[tokio::test]
    async fn test_check_target_blocks_loopback_ssrf() {
        // S2: a health probe must route through the same SSRF filter as the
        // proxy hot path. A loopback target (ssrf_skip_verify=false) must be
        // rejected, not probed directly.
        let target = crate::route::target::Target::new(
            "loopback".to_string(),
            "http://127.0.0.1:1/".to_string(),
        );
        // Confirm the target is SSRF-protected (no skip opt).
        assert!(!target.ssrf_skip_verify());

        let checker = HealthChecker::new(HealthCheckConfig {
            interval: Duration::from_secs(0),
            timeout: Duration::from_millis(500),
            fall: 1,
            rise: 1,
            path: "/health".to_string(),
            tls_skip_verify: false,
        });
        let healthy = checker.check_target(&target).await;
        assert!(!healthy, "loopback target must be blocked by SSRF policy");
        // The block must also mark the target unhealthy.
        assert!(!target.health_tracker.is_probe_healthy());
    }

    #[tokio::test]
    async fn test_http_probe_uses_pre_resolved_address() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let checker = HealthChecker::new(HealthCheckConfig {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            fall: 1,
            rise: 1,
            path: "/health".to_string(),
            tls_skip_verify: false,
        });
        checker
            .probe_http("http", "does-not-resolve.invalid", addr.port(), addr)
            .await
            .expect("probe should connect to the pinned address without DNS");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_health_check_reenable_restores_configured_interval() {
        use crate::route::definition::{RouteCmd, RouteDef, RouteSource};
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let probes = Arc::new(AtomicUsize::new(0));
        let server_probes = probes.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let server_probes = server_probes.clone();
                tokio::spawn(async move {
                    let mut request = [0_u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    server_probes.fetch_add(1, Ordering::SeqCst);
                });
            }
        });

        let mut opts = HashMap::new();
        opts.insert("ssrfskipverify".to_string(), "true".to_string());
        let table = Arc::new(crate::route::registry::ManagedRouteTable::new());
        table.load_static(&[RouteDef {
            cmd: RouteCmd::Add,
            service: "health-test".to_string(),
            src: "example.com/".to_string(),
            dst: format!("http://{addr}"),
            weight: 0.0,
            tags: vec![],
            opts,
            source: RouteSource::Static,
        }]);

        let mut runtime = crate::test_support::base_test_config();
        runtime.proxy.health_check_interval = "20ms".to_string();
        runtime.proxy.health_check_timeout = "200ms".to_string();
        let config = crate::config::shared_config(runtime);
        let health = tokio::spawn(run_health_checks(table, config.clone()));

        tokio::time::timeout(Duration::from_secs(1), async {
            while probes.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let mut disabled = (**config.load()).clone();
        disabled.proxy.health_check_interval = "0s".to_string();
        config.store(Arc::new(disabled));
        tokio::time::sleep(Duration::from_millis(80)).await;
        let disabled_count = probes.load(Ordering::SeqCst);

        let mut enabled = (**config.load()).clone();
        enabled.proxy.health_check_interval = "20ms".to_string();
        config.store(Arc::new(enabled));
        tokio::time::timeout(Duration::from_secs(2), async {
            while probes.load(Ordering::SeqCst) <= disabled_count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("health checks should resume after runtime re-enable");
        let resumed_count = probes.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            probes.load(Ordering::SeqCst) >= resumed_count + 2,
            "re-enabled checker must restore the configured 20ms cadence"
        );

        health.abort();
        server.abort();
    }

    #[tokio::test]
    async fn test_run_health_checks_does_not_exit_on_zero_interval() {
        // R2: a zero interval must NOT cause the task to exit immediately —
        // that would make runtime re-enabling impossible. Instead it sleeps on
        // a guard interval. Spawn briefly and confirm it stays alive past the
        // point where the old early-return would have finished.
        let mut config = crate::test_support::base_test_config();
        // Force interval = 0 (disabled).
        config.proxy.health_check_interval = "0s".to_string();
        let config = crate::config::shared_config(config);

        let table = Arc::new(crate::route::registry::ManagedRouteTable::new());
        let handle = tokio::spawn(run_health_checks(table, config));
        // Give it a moment; if the old early-return were present, the task
        // would have already completed.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "health checker task must stay alive when interval is 0"
        );
        handle.abort();
    }
}

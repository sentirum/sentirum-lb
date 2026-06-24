//! Active health checking for upstream targets.
//!
//! Periodic HTTP/TCP probes to upstream targets. Health status integrates
//! with the existing circuit breaker: consecutive probe failures mark a
//! target as unhealthy, and consecutive successes mark it healthy again.

use crate::config::SharedConfig;
use crate::route::registry::ManagedRouteTable;
use futures::stream::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tracing;

/// Active health checker for upstream targets.
pub struct HealthChecker {
    client: reqwest::Client,
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
        let mut client_builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .no_proxy();
        if config.tls_skip_verify {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }
        let client = client_builder
            .build()
            .expect("Failed to build health check HTTP client");
        Self { client, config }
    }

    /// Perform an HTTP health check against a target.
    /// Returns Ok(()) if the target responded with 2xx, Err otherwise.
    async fn probe_http(&self, scheme: &str, host: &str, port: u16) -> Result<(), String> {
        let url = format!("{}://{}:{}{}", scheme, host, port, self.config.path);
        let response = self
            .client
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

    /// Perform a TCP connect health check.
    /// Returns Ok(()) if connection succeeded, Err otherwise.
    async fn probe_tcp(&self, host: &str, port: u16) -> Result<(), String> {
        let addr = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        // Bound the connect with the configured probe timeout so a
        // SYN-black-holing target cannot occupy a `buffer_unordered` probe slot
        // for the OS connect timeout (the HTTP probe path already has a timeout).
        match tokio::time::timeout(self.config.timeout, tokio::net::TcpStream::connect(&addr)).await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("TCP connect failed: {e}")),
            Err(_) => Err(format!(
                "TCP connect timed out after {:?}",
                self.config.timeout
            )),
        }
    }

    /// Run a single health check probe against a target.
    /// Returns true if the probe succeeded.
    pub async fn check_target(&self, target: &crate::route::target::Target) -> bool {
        let host = target.upstream_host();
        let port = target.upstream_port();

        let result = if target.upstream_tls() {
            self.probe_http("https", host, port).await
        } else {
            // For non-TLS targets, try HTTP probe first, fallback to TCP
            match self.probe_http("http", host, port).await {
                Ok(()) => Ok(()),
                Err(http_err) => {
                    // HTTP failed — try TCP connect as fallback
                    match self.probe_tcp(host, port).await {
                        Ok(()) => Ok(()),
                        Err(tcp_err) => Err(format!("{http_err}; TCP fallback: {tcp_err}")),
                    }
                }
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

    // If interval is zero, health checking is disabled
    if hc_config.interval.is_zero() {
        tracing::info!("Active health checking disabled (interval is 0)");
        return;
    }

    let mut checker = Arc::new(HealthChecker::new(hc_config.clone()));
    let mut interval = hc_config.interval;

    tracing::info!(
        interval_secs = interval.as_secs(),
        timeout_secs = hc_config.timeout.as_secs(),
        fall = hc_config.fall,
        rise = hc_config.rise,
        path = %hc_config.path,
        "Active health checker started"
    );

    let mut ticker = tokio::time::interval(interval);
    // Delay (not Burst) so a stalled tick doesn't fire a back-to-back catch-up
    // storm of probe rounds; the immediate first tick is consumed on the next line.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // First tick is immediate

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

        if new_hc_config.interval.is_zero() {
            tracing::info!("Active health checking disabled via runtime config");
            return;
        }

        // Rebuild checker if any config parameter changed.
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
            checker = Arc::new(HealthChecker::new(new_hc_config.clone()));

            // Reset ticker if interval changed
            if new_hc_config.interval != interval {
                interval = new_hc_config.interval;
                // The interval period cannot be changed in place, so the ticker
                // must be rebuilt. A freshly-created interval's first tick fires
                // immediately; consume it here so the next loop iteration doesn't
                // fire an extra probe round right after the hot-reload.
                ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // consume the immediate first tick
            }
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
}

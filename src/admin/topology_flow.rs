use crate::metrics::prometheus::global as global_metrics;
use crate::route::registry::ManagedRouteTable;
use crate::route::target::monotonic_elapsed_ms;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::Ordering;

const SAMPLE_INTERVAL_MS: u64 = 1_000;
const HISTORY_RETENTION_MS: u64 = 6_000;
const STALE_RETENTION_MS: u64 = 60_000;

#[derive(Debug, Clone, Serialize, Default)]
pub struct TopologyFlowMetrics {
    pub rps_1s: f64,
    pub rps_5s: f64,
    pub bps_1s: f64,
    pub bps_5s: f64,
    pub delta_requests: u64,
    pub delta_bytes: u64,
    pub last_active_ms_ago: Option<u64>,
    pub activity_level: &'static str,
}

impl TopologyFlowMetrics {
    pub fn combine<'a>(flows: impl IntoIterator<Item = &'a TopologyFlowMetrics>) -> Self {
        let mut combined = Self::default();
        let mut activity_rank = 0u8;

        for flow in flows {
            combined.rps_1s += flow.rps_1s;
            combined.rps_5s += flow.rps_5s;
            combined.bps_1s += flow.bps_1s;
            combined.bps_5s += flow.bps_5s;
            combined.delta_requests = combined.delta_requests.saturating_add(flow.delta_requests);
            combined.delta_bytes = combined.delta_bytes.saturating_add(flow.delta_bytes);
            combined.last_active_ms_ago =
                match (combined.last_active_ms_ago, flow.last_active_ms_ago) {
                    (Some(current), Some(next)) => Some(current.min(next)),
                    (None, some @ Some(_)) => some,
                    (current, None) => current,
                };
            activity_rank = activity_rank.max(activity_level_rank(flow.activity_level));
        }

        combined.activity_level = activity_level_name(activity_rank);
        combined
    }
}

#[derive(Debug, Clone, Default)]
pub struct TopologyFlowSnapshot {
    pub lb: TopologyFlowMetrics,
    pub edges: HashMap<String, TopologyFlowMetrics>,
}

#[derive(Debug, Clone, Copy)]
struct CounterSample {
    at_ms: u64,
    requests: u64,
    bytes: u64,
}

#[derive(Debug, Default)]
struct FlowHistory {
    samples: VecDeque<CounterSample>,
    last_active_ms: Option<u64>,
}

impl FlowHistory {
    fn record(&mut self, at_ms: u64, requests: u64, bytes: u64, last_access_secs: Option<u64>) {
        let sample = CounterSample {
            at_ms,
            requests,
            bytes,
        };

        if let Some(last) = self.samples.back_mut()
            && last.at_ms == at_ms
        {
            *last = sample;
        } else {
            self.samples.push_back(sample);
        }

        while self
            .samples
            .front()
            .is_some_and(|front| at_ms.saturating_sub(front.at_ms) > HISTORY_RETENTION_MS)
        {
            self.samples.pop_front();
        }

        match last_access_secs {
            Some(last_access_secs) if last_access_secs > 0 => {
                self.last_active_ms = Some(last_access_secs.saturating_mul(1_000));
            }
            None => {
                let previous = self
                    .samples
                    .iter()
                    .rev()
                    .nth(1)
                    .copied()
                    .unwrap_or(CounterSample {
                        at_ms,
                        requests,
                        bytes,
                    });
                if requests > previous.requests || bytes > previous.bytes {
                    self.last_active_ms = Some(at_ms);
                }
            }
            _ => {}
        }
    }

    fn flow(&self, now_ms: u64) -> TopologyFlowMetrics {
        let Some(latest) = self.samples.back().copied() else {
            return TopologyFlowMetrics::default();
        };

        let previous = self.samples.iter().rev().nth(1).copied();
        let delta_requests = previous
            .map(|prev| latest.requests.saturating_sub(prev.requests))
            .unwrap_or(0);
        let delta_bytes = previous
            .map(|prev| latest.bytes.saturating_sub(prev.bytes))
            .unwrap_or(0);

        let rps_1s = self.rate_over_window(latest, 1_000, |sample| sample.requests);
        let rps_5s = self.rate_over_window(latest, 5_000, |sample| sample.requests);
        let bps_1s = self.rate_over_window(latest, 1_000, |sample| sample.bytes);
        let bps_5s = self.rate_over_window(latest, 5_000, |sample| sample.bytes);
        let last_active_ms_ago = self.last_active_ms.map(|last| now_ms.saturating_sub(last));

        let activity_level = if delta_requests > 0 || delta_bytes > 0 || rps_1s >= 1.0 {
            "hot"
        } else if rps_5s > 0.0
            || bps_5s > 0.0
            || last_active_ms_ago.is_some_and(|age| age <= 30_000)
        {
            "warm"
        } else {
            "idle"
        };

        TopologyFlowMetrics {
            rps_1s,
            rps_5s,
            bps_1s,
            bps_5s,
            delta_requests,
            delta_bytes,
            last_active_ms_ago,
            activity_level,
        }
    }

    fn rate_over_window(
        &self,
        latest: CounterSample,
        window_ms: u64,
        value: impl Fn(CounterSample) -> u64,
    ) -> f64 {
        let baseline = self
            .samples
            .iter()
            .rev()
            .find(|sample| latest.at_ms.saturating_sub(sample.at_ms) >= window_ms)
            .copied()
            .or_else(|| self.samples.front().copied());

        let Some(baseline) = baseline else {
            return 0.0;
        };

        let elapsed_ms = latest.at_ms.saturating_sub(baseline.at_ms);
        if elapsed_ms == 0 {
            return 0.0;
        }

        let delta = value(latest).saturating_sub(value(baseline));
        (delta as f64 * 1_000.0) / elapsed_ms as f64
    }

    fn has_recent_samples(&self, now_ms: u64) -> bool {
        self.samples
            .back()
            .is_some_and(|sample| now_ms.saturating_sub(sample.at_ms) <= STALE_RETENTION_MS)
    }
}

#[derive(Debug, Default)]
struct TopologyFlowState {
    last_refresh_ms: u64,
    lb: FlowHistory,
    edges: HashMap<String, FlowHistory>,
}

#[derive(Debug, Default)]
pub struct TopologyFlowCache {
    inner: Mutex<TopologyFlowState>,
}

impl TopologyFlowCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self, route_table: &ManagedRouteTable) -> TopologyFlowSnapshot {
        let now_ms = monotonic_elapsed_ms();
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if now_ms.saturating_sub(state.last_refresh_ms) >= SAMPLE_INTERVAL_MS
            || state.last_refresh_ms == 0
        {
            let metrics = global_metrics();
            state.lb.record(
                now_ms,
                metrics.requests_total.load(Ordering::Relaxed),
                metrics.bytes_received_total.load(Ordering::Relaxed),
                None,
            );

            let table = route_table.get();
            let mut current_keys = HashSet::new();
            for (host, route, target) in table.iter_targets() {
                let key = topology_target_key(host, &route.path, &target.service, &target.url);
                current_keys.insert(key.clone());
                let stats = target.edge_stats.as_ref();
                state.edges.entry(key).or_default().record(
                    now_ms,
                    stats.requests_total.load(Ordering::Relaxed),
                    stats.bytes_total.load(Ordering::Relaxed),
                    Some(stats.last_access.load(Ordering::Relaxed)),
                );
            }

            state.edges.retain(|key, history| {
                current_keys.contains(key) || history.has_recent_samples(now_ms)
            });
            state.last_refresh_ms = now_ms;
        }

        let edges = state
            .edges
            .iter()
            .map(|(key, history)| (key.clone(), history.flow(now_ms)))
            .collect();

        TopologyFlowSnapshot {
            lb: state.lb.flow(now_ms),
            edges,
        }
    }
}

pub fn topology_target_key(host: &str, path: &str, service: &str, url: &str) -> String {
    format!("{host}\u{001f}{path}\u{001f}{service}\u{001f}{url}")
}

fn activity_level_rank(level: &str) -> u8 {
    match level {
        "hot" => 2,
        "warm" => 1,
        _ => 0,
    }
}

fn activity_level_name(rank: u8) -> &'static str {
    match rank {
        2 => "hot",
        1 => "warm",
        _ => "idle",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_history_computes_windowed_rates_and_activity() {
        let mut history = FlowHistory::default();
        history.record(1_000, 10, 1_000, Some(1));
        history.record(2_000, 16, 4_000, Some(2));
        history.record(6_000, 26, 9_000, Some(6));

        let flow = history.flow(6_000);
        assert_eq!(flow.delta_requests, 10);
        assert_eq!(flow.delta_bytes, 5_000);
        assert_eq!(flow.last_active_ms_ago, Some(0));
        assert_eq!(flow.activity_level, "hot");
        assert!((flow.rps_1s - 2.5).abs() < 0.001);
        assert!((flow.rps_5s - 3.2).abs() < 0.001);
        assert!((flow.bps_1s - 1_250.0).abs() < 0.001);
        assert!((flow.bps_5s - 1_600.0).abs() < 0.001);
    }

    #[test]
    fn combine_sums_rates_and_keeps_hottest_activity() {
        let combined = TopologyFlowMetrics::combine([
            &TopologyFlowMetrics {
                rps_1s: 1.0,
                rps_5s: 2.0,
                bps_1s: 10.0,
                bps_5s: 20.0,
                delta_requests: 1,
                delta_bytes: 10,
                last_active_ms_ago: Some(500),
                activity_level: "warm",
            },
            &TopologyFlowMetrics {
                rps_1s: 3.0,
                rps_5s: 4.0,
                bps_1s: 30.0,
                bps_5s: 40.0,
                delta_requests: 3,
                delta_bytes: 30,
                last_active_ms_ago: Some(250),
                activity_level: "hot",
            },
        ]);

        assert_eq!(combined.delta_requests, 4);
        assert_eq!(combined.delta_bytes, 40);
        assert_eq!(combined.last_active_ms_ago, Some(250));
        assert_eq!(combined.activity_level, "hot");
        assert_eq!(combined.rps_1s, 4.0);
        assert_eq!(combined.bps_5s, 60.0);
    }
}

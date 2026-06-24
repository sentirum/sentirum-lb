//! Thread-safe DNS cache with TTL-based expiration and global singleton.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::circuit_breaker::monotonic_elapsed_ms;

/// Global DNS cache instance
static DNS_CACHE: std::sync::OnceLock<DnsCache> = std::sync::OnceLock::new();

/// Get the global DNS cache
pub fn global_dns_cache() -> &'static DnsCache {
    DNS_CACHE.get_or_init(DnsCache::new)
}

/// DNS cache entry with TTL and expiration
#[derive(Debug, Clone)]
pub(crate) struct DnsCacheEntry {
    /// Resolved IP addresses (Arc for cheap cloning on cache hits)
    addrs: Arc<[SocketAddr]>,
    /// Expiration timestamp (milliseconds since epoch)
    expires_at_ms: u64,
    /// Whether this was a negative lookup (NXDOMAIN)
    negative: bool,
}

/// Thread-safe DNS cache with TTL-based expiration
#[derive(Debug)]
pub struct DnsCache {
    inner: dashmap::DashMap<String, DnsCacheEntry>,
    /// Default TTL in seconds
    default_ttl_secs: AtomicU64,
    /// Negative cache TTL in seconds
    negative_ttl_secs: AtomicU64,
    /// Local counters (fast, no indirection)
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    negatives: std::sync::atomic::AtomicU64,
    /// Cached reference to global Prometheus metrics (avoids OnceLock lookup per hit)
    prom: &'static crate::metrics::prometheus::Metrics,
}

/// Maximum number of entries in the DNS cache before eviction kicks in.
const DNS_CACHE_MAX_ENTRIES: usize = 10_000;

/// Result of a DNS cache lookup. Distinguishes a live negative (NXDOMAIN) entry
/// from a true miss so the caller can fast-fail instead of re-resolving a host
/// that is known not to exist.
pub enum DnsLookup {
    /// Live positive entry with resolved addresses.
    Hit(Arc<[SocketAddr]>),
    /// Live negative entry (host recently failed to resolve).
    NegativeCached,
    /// No live entry — the caller should resolve.
    Miss,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: dashmap::DashMap::new(),
            default_ttl_secs: AtomicU64::new(30),
            negative_ttl_secs: AtomicU64::new(10),
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            negatives: std::sync::atomic::AtomicU64::new(0),
            prom: crate::metrics::prometheus::global(),
        }
    }

    pub fn with_ttl(default_ttl_secs: u64, negative_ttl_secs: u64) -> Self {
        Self {
            inner: dashmap::DashMap::new(),
            default_ttl_secs: AtomicU64::new(default_ttl_secs),
            negative_ttl_secs: AtomicU64::new(negative_ttl_secs),
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            negatives: std::sync::atomic::AtomicU64::new(0),
            prom: crate::metrics::prometheus::global(),
        }
    }

    /// Set the TTL values (thread-safe, can be called after OnceLock init)
    pub fn set_ttl(&self, default_secs: u64, negative_secs: u64) {
        let previous_default = self.default_ttl_secs.swap(default_secs, Ordering::Relaxed);
        let previous_negative = self
            .negative_ttl_secs
            .swap(negative_secs, Ordering::Relaxed);
        if previous_default != default_secs || previous_negative != negative_secs {
            self.clear();
        }
    }

    /// Look up a cached DNS entry.
    ///
    /// The common live-entry path takes a single read lock; the write lock is
    /// only acquired to evict an entry that has actually expired.
    pub fn lookup(&self, host: &str) -> DnsLookup {
        let now_ms = monotonic_elapsed_ms();

        if let Some(entry) = self.inner.get(host) {
            if now_ms < entry.expires_at_ms {
                if entry.negative {
                    self.negatives.fetch_add(1, Ordering::Relaxed);
                    self.prom
                        .dns_cache_negatives_total
                        .fetch_add(1, Ordering::Relaxed);
                    return DnsLookup::NegativeCached;
                }
                self.hits.fetch_add(1, Ordering::Relaxed);
                self.prom
                    .dns_cache_hits_total
                    .fetch_add(1, Ordering::Relaxed);
                return DnsLookup::Hit(Arc::clone(&entry.addrs));
            }
            // Expired — drop the read guard before taking the write lock to evict.
            // The predicate re-checks expiry so a concurrent refresh is preserved.
            drop(entry);
            self.inner.remove_if(host, |_, e| now_ms >= e.expires_at_ms);
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        self.prom
            .dns_cache_misses_total
            .fetch_add(1, Ordering::Relaxed);
        DnsLookup::Miss
    }

    /// Store a positive DNS lookup result
    pub fn store(&self, host: String, addrs: Vec<SocketAddr>) {
        let ttl_secs = self.default_ttl_secs.load(Ordering::Relaxed);
        if ttl_secs == 0 {
            return;
        }

        let now_ms = monotonic_elapsed_ms();
        let entry = DnsCacheEntry {
            addrs: addrs.into(),
            expires_at_ms: now_ms + (ttl_secs * 1000),
            negative: false,
        };

        self.inner.insert(host, entry);
        self.evict_if_over_capacity(now_ms);
    }

    /// Store a negative DNS lookup result (NXDOMAIN)
    pub fn store_negative(&self, host: String) {
        let ttl_secs = self.negative_ttl_secs.load(Ordering::Relaxed);
        if ttl_secs == 0 {
            return;
        }

        let now_ms = monotonic_elapsed_ms();
        let entry = DnsCacheEntry {
            addrs: Vec::<SocketAddr>::new().into(),
            expires_at_ms: now_ms + (ttl_secs * 1000),
            negative: true,
        };

        self.inner.insert(host, entry);
        self.evict_if_over_capacity(now_ms);
    }

    /// Evict entries when the cache exceeds DNS_CACHE_MAX_ENTRIES.
    fn evict_if_over_capacity(&self, now_ms: u64) {
        if self.inner.len() <= DNS_CACHE_MAX_ENTRIES {
            return;
        }

        let expired_keys: Vec<String> = self
            .inner
            .iter()
            .filter(|e| now_ms >= e.expires_at_ms)
            .map(|e| e.key().clone())
            .collect();
        for key in expired_keys {
            self.inner.remove(&key);
        }

        if self.inner.len() <= DNS_CACHE_MAX_ENTRIES {
            return;
        }

        let mut entries: Vec<(String, u64)> = self
            .inner
            .iter()
            .map(|e| (e.key().clone(), e.expires_at_ms))
            .collect();

        let to_remove = self.inner.len() - DNS_CACHE_MAX_ENTRIES;
        if to_remove < entries.len() {
            entries.select_nth_unstable_by_key(to_remove, |(_, exp)| *exp);
        }

        for (key, _) in entries.into_iter().take(to_remove) {
            self.inner.remove(&key);
        }
    }

    /// Remove a single cached entry.
    pub fn remove(&self, host: &str) {
        self.inner.remove(host);
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> DnsCacheStats {
        DnsCacheStats {
            entries: self.inner.len() as u64,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            negatives: self.negatives.load(Ordering::Relaxed),
        }
    }

    /// Get all cached entries with expiration info (for admin API).
    pub fn entries(&self) -> Vec<DnsCacheEntryView> {
        let now_ms = monotonic_elapsed_ms();

        self.inner
            .iter()
            .map(|entry| {
                let ttl_remaining_ms = entry.expires_at_ms.saturating_sub(now_ms);
                DnsCacheEntryView {
                    host: entry.key().clone(),
                    addrs: entry.addrs.iter().map(|a| a.to_string()).collect(),
                    ttl_remaining_secs: ttl_remaining_ms as i64 / 1000,
                    is_negative: entry.negative,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsCacheEntryView {
    pub host: String,
    pub addrs: Vec<String>,
    pub ttl_remaining_secs: i64,
    pub is_negative: bool,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS cache statistics
#[derive(Debug, Clone, Default)]
pub struct DnsCacheStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub negatives: u64,
}

impl std::fmt::Display for DnsCacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "entries={} hits={} misses={} negatives={}",
            self.entries, self.hits, self.misses, self.negatives
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_cache_eviction_enforced() {
        let cache = DnsCache::with_ttl(300, 10);
        for i in 0..(DNS_CACHE_MAX_ENTRIES + 50) {
            let hi = (i / 256) % 256;
            let lo = i % 256;
            let addr: SocketAddr = format!("10.0.{hi}.{lo}:80").parse().unwrap();
            cache.store(format!("host-{i}"), vec![addr]);
        }
        assert!(
            cache.inner.len() <= DNS_CACHE_MAX_ENTRIES,
            "cache should be capped at DNS_CACHE_MAX_ENTRIES, got {}",
            cache.inner.len()
        );
    }

    #[test]
    fn test_dns_cache_absent_key_counts_as_miss() {
        let cache = DnsCache::with_ttl(30, 10);
        assert!(matches!(cache.lookup("missing.example"), DnsLookup::Miss));
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn test_dns_cache_negative_entry_reported_as_negative_cached() {
        let cache = DnsCache::with_ttl(30, 10);
        cache.store_negative("nxdomain.example:80".to_string());
        assert!(matches!(
            cache.lookup("nxdomain.example:80"),
            DnsLookup::NegativeCached
        ));
    }

    #[test]
    fn test_dns_cache_ttl_zero_bypasses_positive_store() {
        let cache = DnsCache::with_ttl(0, 10);
        let addr: SocketAddr = "203.0.113.10:80".parse().unwrap();
        cache.store("no-cache.example:80".to_string(), vec![addr]);
        assert!(matches!(
            cache.lookup("no-cache.example:80"),
            DnsLookup::Miss
        ));
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn test_dns_cache_ttl_change_clears_existing_entries() {
        let cache = DnsCache::with_ttl(30, 10);
        let addr: SocketAddr = "203.0.113.11:80".parse().unwrap();
        cache.store("ttl-change.example:80".to_string(), vec![addr]);
        assert_eq!(cache.stats().entries, 1);

        cache.set_ttl(60, 10);
        assert_eq!(cache.stats().entries, 0);
    }
}

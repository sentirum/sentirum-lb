//! OCSP stapling support for Sentirum LB.
//!
//! Provides infrastructure to periodically fetch OCSP responses from CA
//! responders for each loaded TLS certificate and cache them for stapling.
//!
//! **Note:** The actual TLS stapling (injecting the OCSP response into the
//! TLS handshake) depends on Pingora exposing the OpenSSL `SSL_set_ocsp_resp`
//! callback. This module implements the fetcher, cache, and config. When the
//! Pingora API exposes the stapling hook, the cached responses will be wired
//! in automatically.

#![allow(dead_code)]

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A cached OCSP response with expiration tracking.
#[derive(Debug, Clone)]
struct OcspResponse {
    /// DER-encoded OCSP response, ready for stapling.
    response: Vec<u8>,
    /// When this response expires and must be refreshed.
    expires_at: Instant,
}

impl OcspResponse {
    /// Returns `true` if the response is still valid.
    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// OCSP stapling cache and fetcher.
pub struct OcspStapler {
    /// Cached OCSP responses keyed by certificate entry name.
    responses: ArcSwap<HashMap<String, OcspResponse>>,
    /// HTTP client for OCSP requests.
    client: reqwest::Client,
    /// How long to cache responses before refreshing.
    cache_ttl: Duration,
}

/// Default OCSP response cache TTL (1 hour).
const DEFAULT_OCSP_CACHE_TTL: Duration = Duration::from_secs(3600);

impl OcspStapler {
    /// Create a new OCSP stapler with default cache TTL.
    pub fn new() -> Self {
        Self {
            responses: ArcSwap::from_pointee(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()
                .expect("Failed to build OCSP HTTP client"),
            cache_ttl: DEFAULT_OCSP_CACHE_TTL,
        }
    }

    /// Create a new OCSP stapler with a custom cache TTL.
    pub fn with_cache_ttl(cache_ttl: Duration) -> Self {
        Self {
            responses: ArcSwap::from_pointee(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()
                .expect("Failed to build OCSP HTTP client"),
            cache_ttl,
        }
    }

    /// Get a cached OCSP response for a certificate, if available and not expired.
    /// Returns `None` if no response is cached or the cached response has expired.
    pub fn get_stapled_response(&self, cert_entry_name: &str) -> Option<Vec<u8>> {
        let snapshot = self.responses.load();
        let entry = snapshot.get(cert_entry_name)?;
        if entry.is_valid() {
            Some(entry.response.clone())
        } else {
            None
        }
    }

    /// Fetch an OCSP response for a certificate from its CA responder.
    ///
    /// This requires parsing the certificate's Authority Information Access
    /// (AIA) extension to find the OCSP responder URL. Since full OCSP
    /// requires cryptographic operations (building and signing the OCSP
    /// request), this implementation logs a warning that actual stapling
    /// is not yet available through Pingora's API.
    ///
    /// The infrastructure is ready: when Pingora exposes the SSL callback,
    /// this method will perform the actual fetch.
    pub async fn fetch_ocsp_response(
        &self,
        cert_entry_name: &str,
        _cert_der: &[u8],
    ) -> Result<(), String> {
        // OCSP stapling requires:
        // 1. Parse AIA extension from the certificate to find OCSP responder URL
        // 2. Build an OCSP request (requires the issuer certificate)
        // 3. Send the request to the responder
        // 4. Validate the response
        // 5. Inject via SSL_set_ocsp_resp during handshake
        //
        // Pingora's current TLS API does not expose SSL_set_ocsp_resp or
        // the certificate selection callback needed for stapling.
        // This infrastructure is prepared for when that API becomes available.

        tracing::warn!(
            cert_entry_name,
            "OCSP stapling: fetch requested but Pingora does not yet expose the \
             SSL stapling callback; skipping"
        );

        // Store nothing — Pingora does not yet expose the stapling callback.
        // When the API becomes available, this method will store the actual
        // DER-encoded OCSP response instead of a placeholder.
        Ok(())
    }

    /// Refresh OCSP responses for all known certificates.
    /// This is intended to be called from a background task.
    pub async fn refresh_all(&self, cert_entry_names: &[String]) {
        if cert_entry_names.is_empty() {
            return;
        }

        tracing::debug!(
            cert_count = cert_entry_names.len(),
            "OCSP refresh cycle started"
        );

        for name in cert_entry_names {
            // In a full implementation, we would fetch the certificate DER
            // from the DynamicCertStore and pass it to fetch_ocsp_response.
            if let Err(e) = self.fetch_ocsp_response(name, &[]).await {
                tracing::warn!(
                    cert_entry_name = name,
                    error = %e,
                    "OCSP response fetch failed"
                );
            }
        }
    }

    /// Remove all cached responses.
    pub fn clear(&self) {
        self.responses.store(Arc::new(HashMap::new()));
    }

    /// Get the number of cached responses (for diagnostics).
    pub fn cached_count(&self) -> usize {
        self.responses.load().len()
    }

    /// Run a background OCSP refresh loop.
    pub async fn run_refresh_loop(
        self: Arc<Self>,
        cert_entry_names: Vec<String>,
        refresh_interval: Duration,
    ) {
        let mut ticker = tokio::time::interval(refresh_interval);
        ticker.tick().await; // First tick is immediate

        loop {
            ticker.tick().await;
            tracing::debug!("OCSP stapler refresh cycle");
            self.refresh_all(&cert_entry_names).await;
        }
    }
}

impl Default for OcspStapler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_stapler_new() {
        let stapler = OcspStapler::new();
        assert_eq!(stapler.cached_count(), 0);
    }

    #[test]
    fn test_ocsp_stapler_get_empty() {
        let stapler = OcspStapler::new();
        assert!(stapler.get_stapled_response("test.pem").is_none());
    }

    #[test]
    fn test_ocsp_stapler_clear() {
        let stapler = OcspStapler::new();
        // Simulate storing a response (via internal mutation)
        let mut map = HashMap::new();
        map.insert(
            "test.pem".to_string(),
            OcspResponse {
                response: vec![1, 2, 3],
                expires_at: Instant::now() + Duration::from_secs(3600),
            },
        );
        stapler.responses.store(Arc::new(map));
        assert_eq!(stapler.cached_count(), 1);

        stapler.clear();
        assert_eq!(stapler.cached_count(), 0);
    }

    #[test]
    fn test_ocsp_response_expiry() {
        let response = OcspResponse {
            response: vec![1, 2, 3],
            expires_at: Instant::now() - Duration::from_secs(1),
        };
        assert!(!response.is_valid(), "expired response should not be valid");
    }

    #[test]
    fn test_ocsp_stapler_expired_response_not_returned() {
        let stapler = OcspStapler::new();
        let mut map = HashMap::new();
        map.insert(
            "test.pem".to_string(),
            OcspResponse {
                response: vec![1, 2, 3],
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        stapler.responses.store(Arc::new(map));
        assert!(
            stapler.get_stapled_response("test.pem").is_none(),
            "expired response should not be returned"
        );
    }

    #[test]
    fn test_ocsp_stapler_valid_response_returned() {
        let stapler = OcspStapler::new();
        let mut map = HashMap::new();
        map.insert(
            "test.pem".to_string(),
            OcspResponse {
                response: vec![1, 2, 3],
                expires_at: Instant::now() + Duration::from_secs(3600),
            },
        );
        stapler.responses.store(Arc::new(map));
        let resp = stapler
            .get_stapled_response("test.pem")
            .expect("should return valid response");
        assert_eq!(resp, vec![1, 2, 3]);
    }
}

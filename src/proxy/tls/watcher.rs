//! File-based TLS certificate hot-reload via polling.
//!
//! Watches configured cert/key file pairs for changes by comparing file
//! modification timestamps. When a change is detected, the certificate is
//! reloaded from disk and swapped atomically via `ArcSwap<LoadedCertificate>`.
//! New TLS handshakes immediately use the refreshed certificate.

use crate::proxy::tls::{
    LoadedCertificate, TlsCertConfig, TlsError, asn1_time_to_unix_seconds,
    certificate_subject_string_ref, first_subject_value, load_static_certificate, now_unix,
};
use arc_swap::ArcSwap;
use pingora::services::background::BackgroundService;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Shared, atomically-swappable certificate for a single file-based TLS listener.
pub type SharedFileCert = Arc<ArcSwap<LoadedCertificate>>;

/// Load a certificate from disk and wrap it in an atomically-swappable handle.
pub fn load_shareable_cert(config: &TlsCertConfig) -> Result<SharedFileCert, TlsError> {
    let cert: Arc<LoadedCertificate> = load_static_certificate(config)?;
    // ArcSwap<LoadedCertificate> is actually ArcSwapAny<Arc<LoadedCertificate>>.
    // We give it the Arc directly.
    let swap: ArcSwap<LoadedCertificate> = ArcSwap::new(cert);
    Ok(Arc::new(swap))
}

/// Metadata snapshot used to detect file changes without re-reading PEM content.
#[derive(Clone, Default)]
struct FileMeta {
    cert_mtime: Option<SystemTime>,
    key_mtime: Option<SystemTime>,
}

impl FileMeta {
    fn read(cert_path: &str, key_path: &str) -> Self {
        let cert_mtime = std::fs::metadata(cert_path)
            .ok()
            .and_then(|m| m.modified().ok());
        let key_mtime = std::fs::metadata(key_path)
            .ok()
            .and_then(|m| m.modified().ok());
        Self {
            cert_mtime,
            key_mtime,
        }
    }

    fn has_changed(&self, other: &Self) -> bool {
        self.cert_mtime != other.cert_mtime || self.key_mtime != other.key_mtime
    }
}

/// Background service that polls file-based TLS certificates and hot-reloads on change.
pub struct FileCertWatcherService {
    /// Human-readable label for logging (e.g. "primary", "tls_listeners[0]").
    label: String,
    /// Cert/key paths to watch.
    config: TlsCertConfig,
    /// Atomically-swappable certificate handle shared with the TLS selector.
    cert: SharedFileCert,
    /// Polling interval.
    interval: Duration,
}

impl FileCertWatcherService {
    pub fn new(
        label: String,
        config: TlsCertConfig,
        cert: SharedFileCert,
        poll_interval: Duration,
    ) -> Self {
        Self {
            label,
            config,
            cert,
            interval: poll_interval,
        }
    }
}

#[async_trait::async_trait]
impl BackgroundService for FileCertWatcherService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut last_meta = FileMeta::read(&self.config.cert_path, &self.config.key_path);
        tracing::info!(
            listener = %self.label,
            cert_path = %self.config.cert_path,
            poll_interval_secs = self.interval.as_secs(),
            "File cert watcher started"
        );

        let mut ticker = tokio::time::interval(self.interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {
                    tracing::info!(listener = %self.label, "File cert watcher shutting down");
                    return;
                }
            }

            let current_meta = FileMeta::read(&self.config.cert_path, &self.config.key_path);
            if !current_meta.has_changed(&last_meta) {
                continue;
            }
            // Files changed — try to reload
            tracing::info!(
                listener = %self.label,
                cert_path = %self.config.cert_path,
                "Detected certificate file change, reloading"
            );

            match load_static_certificate(&self.config) {
                Ok(new_cert) => {
                    // Log certificate details
                    let subject = certificate_subject_string_ref(&new_cert.leaf);
                    let cn =
                        first_subject_value(&new_cert.leaf, pingora::tls::nid::Nid::COMMONNAME);
                    let not_after_unix = asn1_time_to_unix_seconds(new_cert.leaf.not_after());
                    let days =
                        not_after_unix.map(|exp| ((exp as i64) - (now_unix() as i64)) / 86400);

                    self.cert.store(new_cert);
                    last_meta = current_meta;

                    tracing::info!(
                        listener = %self.label,
                        subject = %subject,
                        common_name = ?cn,
                        days_remaining = ?days,
                        "Certificate hot-reloaded successfully"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        listener = %self.label,
                        error = %error,
                        "Failed to reload certificate; keeping current certificate"
                    );
                    // Don't update last_meta so we'll retry on next poll
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn self_signed_pem() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["test.local".to_string()]).unwrap();
        (cert.cert.pem(), cert.signing_key.serialize_pem())
    }

    #[test]
    fn file_meta_detects_change() {
        let dir = std::env::temp_dir().join("sentirum_lb_cert_meta_test");
        std::fs::create_dir_all(&dir).unwrap();

        let cert_path = dir.join("cert.pem").to_string_lossy().to_string();
        let key_path = dir.join("key.pem").to_string_lossy().to_string();

        let (cert_pem, key_pem) = self_signed_pem();
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let meta1 = FileMeta::read(&cert_path, &key_path);
        assert!(meta1.cert_mtime.is_some());
        assert!(meta1.key_mtime.is_some());

        // No change yet
        let meta2 = FileMeta::read(&cert_path, &key_path);
        assert!(!meta1.has_changed(&meta2));

        // Modify cert
        std::thread::sleep(std::time::Duration::from_millis(100));
        let (cert_pem2, _) = self_signed_pem();
        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert_pem2.as_bytes()).unwrap();
        drop(f);

        let meta3 = FileMeta::read(&cert_path, &key_path);
        assert!(meta1.has_changed(&meta3), "Should detect cert file change");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_shareable_cert_works() {
        let dir = std::env::temp_dir().join("sentirum_lb_shareable_test");
        std::fs::create_dir_all(&dir).unwrap();

        let cert_path = dir.join("cert.pem").to_string_lossy().to_string();
        let key_path = dir.join("key.pem").to_string_lossy().to_string();

        let (cert_pem, key_pem) = self_signed_pem();
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let config = TlsCertConfig::new(cert_path, key_path);
        let shared = load_shareable_cert(&config).unwrap();

        let cert = shared.load();
        assert_eq!(cert.entry_name, "static-file");

        std::fs::remove_dir_all(&dir).ok();
    }
}

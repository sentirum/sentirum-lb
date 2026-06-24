//! TLS termination support for Sentirum LB.
//!
//! Supports either classic file-based TLS configuration or Fabio-compatible
//! Consul KV driven certificate discovery under `/fabio/cert/*.pem`.

use crate::consul::ConsulClient;
use arc_swap::ArcSwap;
#[cfg(test)]
use pingora::tls::ssl_sys;
use pingora::tls::{
    pkey::{PKey, Private},
    x509::{X509, store::X509Store},
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

mod config;
mod helpers;
mod ocsp;
mod selector;
mod watcher;

pub use config::{
    ClientAuthConfig, ClientAuthMode, ClientCaSource, ConsulTlsConfig, TlsCertConfig, TlsMode,
    tls_listen_addr,
};
use helpers::*;
pub(crate) use helpers::{
    asn1_time_to_unix_seconds, certificate_subject_string_ref, first_subject_value, now_unix,
    parse_certificate_chain,
};
pub use selector::{build_static_tls_settings, build_tls_settings, load_static_certificate};
pub use watcher::{FileCertWatcherService, SharedFileCert, load_shareable_cert};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DynamicTlsCertificateStatus {
    pub entry_name: String,
    pub primary_name: Option<String>,
    pub not_after_unix: Option<u64>,
    pub days_remaining: Option<i64>,
}

/// Lightweight runtime view for admin/config visibility.
#[derive(Debug, Clone, Default)]
pub struct DynamicTlsStatus {
    pub loaded_certificates: Vec<String>,
    pub certificates: Vec<DynamicTlsCertificateStatus>,
    pub default_certificate: Option<String>,
    pub last_consul_index: u64,
    pub last_reload_unix: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DynamicClientCaCertificateStatus {
    pub entry_name: String,
    pub subject: String,
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicClientCaStatus {
    pub loaded_entries: Vec<String>,
    pub certificates: Vec<DynamicClientCaCertificateStatus>,
    pub last_consul_index: u64,
    pub last_reload_unix: Option<u64>,
    pub last_error: Option<String>,
}

pub struct DynamicCertStore {
    snapshot: ArcSwap<CertSnapshot>,
    status: RwLock<DynamicTlsStatus>,
    strict_sni: bool,
}

const MAX_CONSUL_CERT_ENTRY_BYTES: usize = 1 << 20;

fn rwlock_read_or_recover<'a, T>(
    lock: &'a RwLock<T>,
    label: &'static str,
) -> std::sync::RwLockReadGuard<'a, T> {
    lock.read().unwrap_or_else(|e| {
        tracing::warn!(lock = label, "RWLock poisoned; recovering read access");
        e.into_inner()
    })
}

fn rwlock_write_or_recover<'a, T>(
    lock: &'a RwLock<T>,
    label: &'static str,
) -> std::sync::RwLockWriteGuard<'a, T> {
    lock.write().unwrap_or_else(|e| {
        tracing::warn!(lock = label, "RWLock poisoned; recovering write access");
        e.into_inner()
    })
}

impl DynamicCertStore {
    pub fn new(strict_sni: bool) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(CertSnapshot::default()),
            status: RwLock::new(DynamicTlsStatus::default()),
            strict_sni,
        }
    }

    pub fn status(&self) -> DynamicTlsStatus {
        rwlock_read_or_recover(&self.status, "tls status").clone()
    }

    pub async fn refresh_from_consul(
        &self,
        client: &ConsulClient,
        cert_prefix: &str,
        index: u64,
    ) -> Result<u64, TlsError> {
        let (entries, new_index) = client
            .watch_kv_basenames(cert_prefix, index)
            .await
            .map_err(|e| TlsError::ConfigError(e.to_string()))?;
        self.apply_consul_snapshot(entries, new_index);
        Ok(new_index)
    }

    pub fn apply_consul_snapshot(&self, entries: BTreeMap<String, Vec<u8>>, consul_index: u64) {
        if entries.is_empty() {
            let metrics = crate::metrics::prometheus::global();
            metrics.record_cert_reload_error();
            metrics.record_cert_reload_skipped("empty");
            let mut status = rwlock_write_or_recover(&self.status, "tls status");
            status.last_consul_index = consul_index;
            status.last_error = Some(
                "received empty certificate snapshot from Consul; keeping last known good store"
                    .to_string(),
            );
            tracing::warn!(
                consul_index,
                "Received empty TLS certificate snapshot; keeping last known good store"
            );
            return;
        }

        let previous = self.snapshot.load_full();
        let (next_snapshot, warnings) = CertSnapshot::from_fabio_entries(&entries, &previous);

        if next_snapshot.ordered.is_empty() {
            let metrics = crate::metrics::prometheus::global();
            metrics.record_cert_reload_error();
            record_warning_metrics(metrics, &warnings);
            let mut status = rwlock_write_or_recover(&self.status, "tls status");
            status.last_consul_index = consul_index;
            status.last_error = Some(
                warnings.first().cloned().unwrap_or_else(|| {
                    "no valid TLS certificates remain after Consul reload; keeping last known good store"
                        .to_string()
                }),
            );
            tracing::error!(
                consul_index,
                "No valid TLS certificates remain after reload; keeping last known good store"
            );
            return;
        }

        let default_certificate = next_snapshot.default_certificate_name();
        let loaded_certificates = next_snapshot.entry_names();
        let certificate_statuses = next_snapshot.runtime_certificates();
        self.snapshot.store(Arc::new(next_snapshot));

        let metrics = crate::metrics::prometheus::global();
        metrics.record_cert_reload_success();
        record_warning_metrics(metrics, &warnings);
        metrics.set_cert_expiry_entries(
            certificate_statuses
                .iter()
                .filter_map(|cert| {
                    cert.not_after_unix.map(|not_after_unix| {
                        crate::metrics::prometheus::CertificateExpiryMetric {
                            entry: cert.entry_name.clone(),
                            cn: cert
                                .primary_name
                                .clone()
                                .unwrap_or_else(|| cert.entry_name.clone()),
                            not_after_unix,
                        }
                    })
                })
                .collect(),
        );

        let mut status = rwlock_write_or_recover(&self.status, "tls status");
        status.loaded_certificates = loaded_certificates.clone();
        status.certificates = certificate_statuses;
        status.default_certificate = default_certificate.clone();
        status.last_consul_index = consul_index;
        status.last_reload_unix = Some(now_unix());
        status.last_error = if warnings.is_empty() {
            None
        } else {
            Some(warnings.join(" | "))
        };

        tracing::info!(
            consul_index,
            certificate_count = loaded_certificates.len(),
            default_certificate = ?default_certificate,
            certificates = ?loaded_certificates,
            "Applied Consul TLS certificate snapshot"
        );

        for warning in warnings {
            tracing::warn!(consul_index, warning = %warning, "Applied TLS snapshot with warnings");
        }
    }

    fn select_for_server_name(&self, server_name: Option<&str>) -> Option<Arc<LoadedCertificate>> {
        let snapshot = self.snapshot.load_full();
        snapshot.select(server_name, self.strict_sni)
    }
}

#[derive(Default)]
struct ClientCaSnapshot {
    store: Option<X509Store>,
    entry_names: Vec<String>,
    certificates: Vec<DynamicClientCaCertificateStatus>,
}

pub struct DynamicClientCaStore {
    snapshot: ArcSwap<ClientCaSnapshot>,
    status: RwLock<DynamicClientCaStatus>,
    ca_upgrade_cn: String,
}

impl DynamicClientCaStore {
    pub fn new(ca_upgrade_cn: String) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(ClientCaSnapshot::default()),
            status: RwLock::new(DynamicClientCaStatus::default()),
            ca_upgrade_cn,
        }
    }

    pub fn status(&self) -> DynamicClientCaStatus {
        rwlock_read_or_recover(&self.status, "client ca status").clone()
    }

    pub async fn refresh_from_consul(
        &self,
        client: &ConsulClient,
        cert_prefix: &str,
        index: u64,
    ) -> Result<u64, TlsError> {
        let (entries, new_index) = client
            .watch_kv_basenames(cert_prefix, index)
            .await
            .map_err(|e| TlsError::ConfigError(e.to_string()))?;
        self.apply_consul_snapshot(entries, new_index);
        Ok(new_index)
    }

    pub fn load_from_path(&self, path: &str) -> Result<(), TlsError> {
        let entries = load_pem_entries_from_path(path)?;
        self.apply_snapshot(entries, 0);
        let status = self.status();
        if status.loaded_entries.is_empty() {
            return Err(TlsError::ConfigError(status.last_error.unwrap_or_else(
                || "no valid client CA certificates loaded from path".to_string(),
            )));
        }
        Ok(())
    }

    pub fn apply_consul_snapshot(&self, entries: BTreeMap<String, Vec<u8>>, consul_index: u64) {
        self.apply_snapshot(entries, consul_index);
    }

    fn apply_snapshot(&self, entries: BTreeMap<String, Vec<u8>>, consul_index: u64) {
        if entries.is_empty() {
            let mut status = rwlock_write_or_recover(&self.status, "client ca status");
            status.last_consul_index = consul_index;
            status.last_error = Some(
                "received empty client CA snapshot; keeping last known good store".to_string(),
            );
            tracing::warn!(
                consul_index,
                "Received empty client CA snapshot; keeping last known good store"
            );
            return;
        }

        match ClientCaSnapshot::from_entries(&entries, &self.ca_upgrade_cn) {
            Ok((next_snapshot, warnings)) => {
                if next_snapshot.store.is_none() {
                    let mut status = rwlock_write_or_recover(&self.status, "client ca status");
                    status.last_consul_index = consul_index;
                    status.last_error = Some(
                        warnings.first().cloned().unwrap_or_else(|| {
                            "no valid client CA certificates remain after reload; keeping last known good store".to_string()
                        }),
                    );
                    tracing::error!(
                        consul_index,
                        "No valid client CA certificates remain after reload; keeping last known good store"
                    );
                    return;
                }

                let loaded_entries = next_snapshot.entry_names.clone();
                let certificates = next_snapshot.certificates.clone();
                self.snapshot.store(Arc::new(next_snapshot));

                let mut status = rwlock_write_or_recover(&self.status, "client ca status");
                status.loaded_entries = loaded_entries.clone();
                status.certificates = certificates;
                status.last_consul_index = consul_index;
                status.last_reload_unix = Some(now_unix());
                status.last_error = if warnings.is_empty() {
                    None
                } else {
                    Some(warnings.join(" | "))
                };

                tracing::info!(
                    consul_index,
                    client_ca_count = loaded_entries.len(),
                    client_ca_entries = ?loaded_entries,
                    "Applied client CA snapshot"
                );
                for warning in warnings {
                    tracing::warn!(consul_index, warning = %warning, "Applied client CA snapshot with warnings");
                }
            }
            Err(error) => {
                let mut status = rwlock_write_or_recover(&self.status, "client ca status");
                status.last_consul_index = consul_index;
                status.last_error = Some(error.to_string());
                tracing::error!(consul_index, error = %error, "Failed to apply client CA snapshot; keeping last known good store");
            }
        }
    }

    fn current_store(&self) -> Option<Arc<ClientCaSnapshot>> {
        let snapshot = self.snapshot.load_full();
        snapshot.store.as_ref()?;
        Some(snapshot)
    }
}

impl ClientCaSnapshot {
    fn from_entries(
        entries: &BTreeMap<String, Vec<u8>>,
        ca_upgrade_cn: &str,
    ) -> Result<(Self, Vec<String>), TlsError> {
        let mut builder = pingora::tls::x509::store::X509StoreBuilder::new()
            .map_err(|e| TlsError::ConfigError(format!("failed to create client CA store: {e}")))?;
        let mut warnings = Vec::new();
        let mut entry_names = Vec::new();
        let mut certificates = Vec::new();

        for (entry_name, pem_bytes) in entries {
            if let Err(warning) = validate_entry_size(entry_name, pem_bytes.len()) {
                warnings.push(warning);
                continue;
            }
            match parse_client_ca_certificates(entry_name, pem_bytes, ca_upgrade_cn) {
                Ok(certs) => {
                    if certs.is_empty() {
                        warnings.push(format!(
                            "client CA entry '{entry_name}' contains no valid CERTIFICATE blocks"
                        ));
                        continue;
                    }
                    entry_names.push(entry_name.clone());
                    for cert in certs {
                        certificates.push(client_ca_certificate_status(entry_name, &cert));
                        builder.add_cert(cert).map_err(|e| {
                            TlsError::ConfigError(format!(
                                "failed to add client CA cert from '{entry_name}' to store: {e}"
                            ))
                        })?;
                    }
                }
                Err(error) => warnings.push(error.to_string()),
            }
        }

        let store = if entry_names.is_empty() {
            None
        } else {
            Some(builder.build())
        };

        Ok((
            Self {
                store,
                entry_names,
                certificates,
            },
            warnings,
        ))
    }
}

pub struct LoadedCertificate {
    entry_name: String,
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
    names: Vec<String>,
}

impl LoadedCertificate {
    fn from_pem_pair(entry_name: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
        let certificates = parse_certificate_chain(cert_pem)?;
        if certificates.is_empty() {
            return Err(TlsError::ConfigError(format!(
                "certificate bundle '{entry_name}' contains no CERTIFICATE blocks"
            )));
        }

        let mut iter = certificates.into_iter();
        let leaf = iter.next().ok_or_else(|| {
            TlsError::ConfigError(format!("certificate bundle '{entry_name}' is empty"))
        })?;
        let chain: Vec<X509> = iter.collect();
        let key = parse_private_key(key_pem)?;
        // Reject mismatched cert/key pairs (e.g. a partial rotation observed
        // mid-write by the watcher). Returning Err keeps the current cert and
        // lets the next poll retry once the files are consistent again.
        match leaf.public_key() {
            Ok(pk) if key.public_eq(&pk) => {}
            _ => {
                return Err(TlsError::ConfigError(format!(
                    "certificate bundle '{entry_name}' private key does not match certificate"
                )));
            }
        }
        let names = extract_certificate_names(&leaf);

        Ok(Self {
            entry_name: entry_name.to_string(),
            leaf,
            chain,
            key,
            names,
        })
    }

    fn runtime_status(&self) -> DynamicTlsCertificateStatus {
        let not_after_unix = asn1_time_to_unix_seconds(self.leaf.not_after());
        let now = now_unix() as i64;
        let days_remaining = not_after_unix.map(|not_after| (not_after as i64 - now) / 86_400);

        DynamicTlsCertificateStatus {
            entry_name: self.entry_name.clone(),
            primary_name: self.names.first().cloned(),
            not_after_unix,
            days_remaining,
        }
    }
}

#[derive(Default)]
struct CertSnapshot {
    ordered: Vec<Arc<LoadedCertificate>>,
    by_name: HashMap<String, usize>,
    by_entry_name: HashMap<String, Arc<LoadedCertificate>>,
}

impl CertSnapshot {
    fn from_fabio_entries(
        entries: &BTreeMap<String, Vec<u8>>,
        previous: &CertSnapshot,
    ) -> (Self, Vec<String>) {
        let mut ordered = Vec::new();
        let mut by_entry_name = HashMap::new();
        let mut handled = HashSet::new();
        let mut warnings = Vec::new();

        for name in entries.keys() {
            let Some((entry_name, cert_name, key_name)) = classify_fabio_entry(name) else {
                continue;
            };

            if !handled.insert(cert_name.clone()) {
                continue;
            }
            handled.insert(key_name.clone());

            let Some(cert_pem) = entries.get(&cert_name) else {
                maybe_reuse_previous(
                    previous,
                    &entry_name,
                    &mut ordered,
                    &mut by_entry_name,
                    &mut warnings,
                    format!("missing certificate blob '{cert_name}' for entry '{entry_name}'"),
                );
                continue;
            };
            let Some(key_pem) = entries.get(&key_name) else {
                maybe_reuse_previous(
                    previous,
                    &entry_name,
                    &mut ordered,
                    &mut by_entry_name,
                    &mut warnings,
                    format!("missing private key blob '{key_name}' for entry '{entry_name}'"),
                );
                continue;
            };

            if let Err(reason) = validate_entry_size(&cert_name, cert_pem.len()) {
                maybe_reuse_previous(
                    previous,
                    &entry_name,
                    &mut ordered,
                    &mut by_entry_name,
                    &mut warnings,
                    reason,
                );
                continue;
            }

            if key_name != cert_name
                && let Err(reason) = validate_entry_size(&key_name, key_pem.len())
            {
                maybe_reuse_previous(
                    previous,
                    &entry_name,
                    &mut ordered,
                    &mut by_entry_name,
                    &mut warnings,
                    reason,
                );
                continue;
            }

            match LoadedCertificate::from_pem_pair(&entry_name, cert_pem, key_pem) {
                Ok(cert) => {
                    let cert = Arc::new(cert);
                    ordered.push(cert.clone());
                    by_entry_name.insert(entry_name, cert);
                }
                Err(err) => {
                    maybe_reuse_previous(
                        previous,
                        &entry_name,
                        &mut ordered,
                        &mut by_entry_name,
                        &mut warnings,
                        format!("{entry_name}: {err}"),
                    );
                }
            }
        }

        let mut by_name = HashMap::new();
        for (idx, cert) in ordered.iter().enumerate() {
            for name in &cert.names {
                by_name.entry(name.clone()).or_insert(idx);
            }
        }

        (
            Self {
                ordered,
                by_name,
                by_entry_name,
            },
            warnings,
        )
    }

    fn default_certificate_name(&self) -> Option<String> {
        self.ordered.first().map(|cert| cert.entry_name.clone())
    }

    fn entry_names(&self) -> Vec<String> {
        self.ordered
            .iter()
            .map(|cert| cert.entry_name.clone())
            .collect()
    }

    fn runtime_certificates(&self) -> Vec<DynamicTlsCertificateStatus> {
        self.ordered
            .iter()
            .map(|cert| cert.runtime_status())
            .collect()
    }

    fn select(
        &self,
        server_name: Option<&str>,
        strict_sni: bool,
    ) -> Option<Arc<LoadedCertificate>> {
        if self.ordered.is_empty() {
            return None;
        }

        let normalized = normalize_server_name(server_name);

        if let Some(name) = normalized.as_deref() {
            if let Some(index) = self.by_name.get(name) {
                return self.ordered.get(*index).cloned();
            }

            // Try first-level wildcard only (e.g. *.example.com).
            // Multi-level wildcards are rare; if needed they should be pre-indexed
            // in by_name during snapshot build.
            if let Some(dot_pos) = name.find('.') {
                let wildcard = format!("*.{}", &name[dot_pos + 1..]);
                if let Some(index) = self.by_name.get(&wildcard) {
                    return self.ordered.get(*index).cloned();
                }
            }
        }

        if strict_sni {
            None
        } else {
            self.ordered.first().cloned()
        }
    }
}

/// TLS-related errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("Certificate file not found: {0}")]
    CertNotFound(String),

    #[error("Private key file not found: {0}")]
    KeyNotFound(String),

    #[error("Cannot read certificate file '{0}': {1}")]
    CertReadError(String, String),

    #[error("Cannot read private key file '{0}': {1}")]
    KeyReadError(String, String),

    #[error("TLS configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, generate_simple_self_signed};

    fn self_signed_cert(names: &[&str]) -> rcgen::CertifiedKey<rcgen::KeyPair> {
        generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>(),
        )
        .expect("cert should build")
    }

    fn self_signed_pem(names: &[&str]) -> (String, String) {
        let cert = self_signed_cert(names);
        (cert.cert.pem(), cert.signing_key.serialize_pem())
    }

    fn self_signed_cn_pem(common_name: &str) -> String {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.self_signed(&key_pair).unwrap().pem()
    }

    #[test]
    fn test_tls_not_configured_with_empty_paths() {
        let config = TlsCertConfig::new(String::new(), String::new());
        assert!(!config.is_configured());
    }

    #[test]
    fn test_tls_not_configured_with_one_empty_path() {
        let config = TlsCertConfig::new("/path/to/cert.pem".to_string(), String::new());
        assert!(!config.is_configured());
    }

    #[test]
    fn test_tls_configured_with_both_paths() {
        let config = TlsCertConfig::new(
            "/path/to/cert.pem".to_string(),
            "/path/to/key.pem".to_string(),
        );
        assert!(config.is_configured());
    }

    #[test]
    fn test_tls_validate_missing_cert() {
        let config = TlsCertConfig::new(
            "/nonexistent/cert.pem".to_string(),
            "/nonexistent/key.pem".to_string(),
        );
        assert!(matches!(config.validate(), Err(TlsError::CertNotFound(_))));
    }

    #[test]
    fn test_tls_mode_defaults_to_file_when_paths_present() {
        let config = crate::config::TlsConfig {
            source: String::new(),
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
            listen: ":9443".to_string(),
            consul_cert_prefix: "/fabio/cert".to_string(),
            strict_sni: false,
            require_initial_snapshot: false,
            ..crate::config::TlsConfig::default()
        };
        assert!(matches!(
            TlsMode::resolve(&config).unwrap(),
            Some(TlsMode::File(_))
        ));
    }

    #[test]
    fn test_tls_mode_supports_consul_source() {
        let config = crate::config::TlsConfig {
            source: "consul_kv".to_string(),
            cert_path: String::new(),
            key_path: String::new(),
            listen: ":9443".to_string(),
            consul_cert_prefix: "/fabio/cert".to_string(),
            strict_sni: true,
            require_initial_snapshot: true,
            ..crate::config::TlsConfig::default()
        };
        match TlsMode::resolve(&config).unwrap() {
            Some(TlsMode::ConsulKv(consul)) => {
                assert_eq!(consul.cert_prefix, "/fabio/cert");
                assert!(consul.strict_sni);
                assert!(consul.require_initial_snapshot);
            }
            other => panic!("unexpected mode: {other:?}"),
        }
    }

    #[test]
    fn test_from_tls_config_empty() {
        let config = crate::config::TlsConfig::default();
        let result: Option<TlsCertConfig> = (&config).into();
        assert!(result.is_none());
    }

    #[test]
    fn test_from_tls_config_with_values() {
        let config = crate::config::TlsConfig {
            source: "file".to_string(),
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
            listen: ":9443".to_string(),
            consul_cert_prefix: "/fabio/cert".to_string(),
            strict_sni: false,
            require_initial_snapshot: false,
            ..crate::config::TlsConfig::default()
        };
        let result: Option<TlsCertConfig> = (&config).into();
        assert!(result.is_some());
        let tls = result.unwrap();
        assert_eq!(tls.cert_path, "/path/to/cert.pem");
        assert_eq!(tls.key_path, "/path/to/key.pem");
    }

    #[test]
    fn test_tls_listen_addr_uses_explicit_value() {
        assert_eq!(tls_listen_addr(":80", ":443"), ":443");
    }

    #[test]
    fn test_tls_listen_addr_derives_from_http_listener() {
        assert_eq!(tls_listen_addr(":80", ""), ":81");
        assert_eq!(tls_listen_addr("127.0.0.1:9999", ""), "127.0.0.1:10000");
        assert_eq!(tls_listen_addr("localhost:443", ""), "localhost:444");
        assert_eq!(tls_listen_addr("[::1]:9443", ""), "[::1]:9444");
        assert_eq!(tls_listen_addr("127.0.0.1:65535", ""), "127.0.0.1:10000");
    }

    #[test]
    fn test_client_auth_mode_resolve_required() {
        let config = crate::config::TlsConfig {
            client_auth: "required".to_string(),
            ..crate::config::TlsConfig::default()
        };
        assert_eq!(
            ClientAuthMode::resolve(&config).unwrap(),
            ClientAuthMode::Required
        );
    }

    #[test]
    fn test_client_auth_config_resolve_consul_source() {
        let config = crate::config::TlsConfig {
            client_auth: "required".to_string(),
            client_ca_source: "consul_kv".to_string(),
            client_ca_consul_prefix: "/fabio/client-ca".to_string(),
            ..crate::config::TlsConfig::default()
        };

        match ClientAuthConfig::resolve(&config).unwrap() {
            Some(ClientAuthConfig {
                mode,
                source: ClientCaSource::ConsulKv { prefix },
                ..
            }) => {
                assert_eq!(mode, ClientAuthMode::Required);
                assert_eq!(prefix, "/fabio/client-ca");
            }
            other => panic!("unexpected client auth config: {other:?}"),
        }
    }

    #[test]
    fn test_dynamic_client_ca_store_accepts_valid_snapshot() {
        let cert = self_signed_cert(&["client-ca.local"]);
        let store = DynamicClientCaStore::new(String::new());
        let mut entries = BTreeMap::new();
        entries.insert("client-ca.pem".to_string(), cert.cert.pem().into_bytes());
        store.apply_consul_snapshot(entries, 42);

        let status = store.status();
        assert_eq!(status.loaded_entries, vec!["client-ca.pem"]);
        assert_eq!(status.last_consul_index, 42);
        assert!(
            status
                .certificates
                .iter()
                .any(|c| c.entry_name == "client-ca.pem")
        );
    }

    #[test]
    fn test_should_treat_as_upgraded_ca_matches_configured_cn_on_ca_errors() {
        let cert_pem = self_signed_cn_pem("ApiGateway");
        let cert = X509::from_pem(cert_pem.as_bytes()).unwrap();
        assert!(should_treat_as_upgraded_ca(
            "ApiGateway",
            ssl_sys::X509_V_ERR_INVALID_CA,
            &cert
        ));
        assert!(should_treat_as_upgraded_ca(
            "ApiGateway",
            ssl_sys::X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
            &cert
        ));
        assert!(!should_treat_as_upgraded_ca(
            "OtherCN",
            ssl_sys::X509_V_ERR_INVALID_CA,
            &cert
        ));
        assert!(!should_treat_as_upgraded_ca(
            "ApiGateway",
            ssl_sys::X509_V_ERR_CERT_HAS_EXPIRED,
            &cert
        ));
    }

    #[test]
    fn test_dynamic_store_loads_fabio_style_combined_pem() {
        // rcgen 0.14 `Certificate` no longer exposes `params()`, so build the
        // cert explicitly and keep the `not_after` we configured for the assert.
        let mut params =
            CertificateParams::new(vec!["example.com".to_string(), "*.example.com".to_string()])
                .unwrap();
        let not_after = rcgen::date_time_ymd(2030, 1, 1);
        params.not_after = not_after;
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&signing_key).unwrap();
        let expected_not_after = not_after.unix_timestamp() as u64;
        let combined = format!("{}{}", cert.pem(), signing_key.serialize_pem());
        let mut entries = BTreeMap::new();
        entries.insert("example.com.pem".to_string(), combined.into_bytes());

        let store = DynamicCertStore::new(false);
        store.apply_consul_snapshot(entries, 42);

        let status = store.status();
        assert_eq!(status.last_consul_index, 42);
        assert_eq!(
            status.loaded_certificates,
            vec!["example.com.pem".to_string()]
        );
        assert_eq!(
            status.default_certificate,
            Some("example.com.pem".to_string())
        );
        assert_eq!(status.certificates.len(), 1);
        assert_eq!(status.certificates[0].entry_name, "example.com.pem");
        assert_eq!(
            status.certificates[0].primary_name.as_deref(),
            Some("example.com")
        );
        assert_eq!(
            status.certificates[0].not_after_unix,
            Some(expected_not_after)
        );
        assert!(status.certificates[0].days_remaining.is_some());
        assert!(status.last_error.is_none());
        assert!(store.select_for_server_name(Some("example.com")).is_some());
        assert!(
            store
                .select_for_server_name(Some("api.example.com"))
                .is_some()
        );
    }

    #[test]
    fn test_dynamic_store_falls_back_to_first_cert_when_not_strict() {
        let (cert_pem, key_pem) = self_signed_pem(&["alpha.example.com"]);
        let combined = format!("{cert_pem}{key_pem}");
        let mut entries = BTreeMap::new();
        entries.insert("alpha.example.com.pem".to_string(), combined.into_bytes());

        let store = DynamicCertStore::new(false);
        store.apply_consul_snapshot(entries, 1);
        let selected = store
            .select_for_server_name(Some("unknown.example.com"))
            .expect("fallback cert should exist");
        assert_eq!(selected.entry_name, "alpha.example.com.pem");
    }

    #[test]
    fn test_dynamic_store_reuses_previous_cert_on_invalid_update() {
        let (cert_pem, key_pem) = self_signed_pem(&["example.com"]);
        let combined = format!("{cert_pem}{key_pem}");
        let mut entries = BTreeMap::new();
        entries.insert("example.com.pem".to_string(), combined.into_bytes());

        let store = DynamicCertStore::new(false);
        store.apply_consul_snapshot(entries, 1);

        let mut broken = BTreeMap::new();
        broken.insert(
            "example.com.pem".to_string(),
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----".to_vec(),
        );
        store.apply_consul_snapshot(broken, 2);

        let status = store.status();
        assert_eq!(status.last_consul_index, 2);
        assert!(status.last_error.is_some());
        assert!(store.select_for_server_name(Some("example.com")).is_some());
    }

    #[test]
    fn test_dynamic_store_rejects_oversized_entries() {
        let (cert_pem, key_pem) = self_signed_pem(&["example.com"]);
        let combined = format!("{cert_pem}{key_pem}");
        let mut entries = BTreeMap::new();
        entries.insert("example.com.pem".to_string(), combined.into_bytes());

        let store = DynamicCertStore::new(false);
        store.apply_consul_snapshot(entries, 1);

        let mut oversized = BTreeMap::new();
        oversized.insert(
            "example.com.pem".to_string(),
            vec![b'x'; MAX_CONSUL_CERT_ENTRY_BYTES + 1],
        );
        store.apply_consul_snapshot(oversized, 2);

        let status = store.status();
        assert_eq!(status.last_consul_index, 2);
        assert!(
            status
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("exceeds max size")
        );
        assert!(store.select_for_server_name(Some("example.com")).is_some());
    }
    #[test]
    fn test_from_pem_pair_accepts_matching_key() {
        let cert = self_signed_cert(&["match.example.com"]);
        let (cert_pem, key_pem) = (cert.cert.pem(), cert.signing_key.serialize_pem());
        let loaded =
            LoadedCertificate::from_pem_pair("match", cert_pem.as_bytes(), key_pem.as_bytes());
        assert!(
            loaded.is_ok(),
            "matching cert/key should load: {:?}",
            loaded.err()
        );
    }

    #[test]
    fn test_from_pem_pair_rejects_mismatched_key() {
        // A partial rotation could observe a cert written alongside the wrong
        // (previous) key; the loader must reject the pair rather than publish
        // a mismatched cert that breaks every handshake on the listener.
        let cert_a = self_signed_cert(&["alpha.example.com"]);
        let cert_b = self_signed_cert(&["beta.example.com"]);
        let result = LoadedCertificate::from_pem_pair(
            "mismatch",
            cert_a.cert.pem().as_bytes(),
            cert_b.signing_key.serialize_pem().as_bytes(),
        );
        match result {
            Err(TlsError::ConfigError(msg))
                if msg.contains("private key does not match certificate") => {}
            Err(_) => panic!("expected key-mismatch ConfigError, got a different TlsError"),
            Ok(_) => panic!("expected key-mismatch error, but from_pem_pair succeeded"),
        }
    }
}

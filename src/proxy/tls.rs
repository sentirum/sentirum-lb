//! TLS termination support for Sentirum LB.
//!
//! Supports either classic file-based TLS configuration or Fabio-compatible
//! Consul KV driven certificate discovery under `/fabio/cert/*.pem`.

use crate::config::TlsConfig;
use crate::consul::ConsulClient;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::listeners::tls::TlsSettings;
use pingora::tls::{
    ext,
    nid::Nid,
    pkey::{PKey, Private},
    ssl,
    ssl_sys,
    x509::{X509, X509VerifyResult, store::X509Store},
};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};
use time::{Date, Month, PrimitiveDateTime, Time};
use std::time::{SystemTime, UNIX_EPOCH};

/// File-based TLS certificate and key configuration.
#[derive(Debug, Clone)]
pub struct TlsCertConfig {
    /// Path to the TLS certificate (PEM format)
    pub cert_path: String,
    /// Path to the TLS private key (PEM format)
    pub key_path: String,
}

impl TlsCertConfig {
    /// Create a new TLS certificate configuration.
    pub fn new(cert_path: String, key_path: String) -> Self {
        Self {
            cert_path,
            key_path,
        }
    }

    /// Validate that the certificate and key files exist and are readable.
    pub fn validate(&self) -> Result<(), TlsError> {
        if !Path::new(&self.cert_path).exists() {
            return Err(TlsError::CertNotFound(self.cert_path.clone()));
        }
        if !Path::new(&self.key_path).exists() {
            return Err(TlsError::KeyNotFound(self.key_path.clone()));
        }

        std::fs::read_to_string(&self.cert_path)
            .map_err(|e| TlsError::CertReadError(self.cert_path.clone(), e.to_string()))?;
        std::fs::read_to_string(&self.key_path)
            .map_err(|e| TlsError::KeyReadError(self.key_path.clone(), e.to_string()))?;

        Ok(())
    }

    /// Check if TLS is configured (both paths are non-empty).
    pub fn is_configured(&self) -> bool {
        !self.cert_path.is_empty() && !self.key_path.is_empty()
    }
}

/// Fabio-compatible Consul KV TLS configuration.
#[derive(Debug, Clone)]
pub struct ConsulTlsConfig {
    pub cert_prefix: String,
    pub strict_sni: bool,
    pub require_initial_snapshot: bool,
}

/// Resolved TLS runtime mode.
#[derive(Debug, Clone)]
pub enum TlsMode {
    File(TlsCertConfig),
    ConsulKv(ConsulTlsConfig),
}

impl TlsMode {
    pub fn resolve(config: &TlsConfig) -> Result<Option<Self>, TlsError> {
        let source = config.source.trim().to_ascii_lowercase();

        match source.as_str() {
            "" => {
                if !config.cert_path.is_empty() || !config.key_path.is_empty() {
                    Ok(Some(TlsMode::File(TlsCertConfig::new(
                        config.cert_path.clone(),
                        config.key_path.clone(),
                    ))))
                } else {
                    Ok(None)
                }
            }
            "file" => Ok(Some(TlsMode::File(TlsCertConfig::new(
                config.cert_path.clone(),
                config.key_path.clone(),
            )))),
            "consul" | "consul_kv" | "fabio_consul" => {
                let cert_prefix = config.consul_cert_prefix.trim().to_string();
                if cert_prefix.is_empty() {
                    return Err(TlsError::ConfigError(
                        "tls.consul_cert_prefix cannot be empty when tls.source=consul_kv"
                            .to_string(),
                    ));
                }
                Ok(Some(TlsMode::ConsulKv(ConsulTlsConfig {
                    cert_prefix,
                    strict_sni: config.strict_sni,
                    require_initial_snapshot: config.require_initial_snapshot,
                })))
            }
            other => Err(TlsError::ConfigError(format!(
                "unknown tls.source '{other}', expected 'file' or 'consul_kv'"
            ))),
        }
    }
}

impl From<&TlsConfig> for Option<TlsCertConfig> {
    fn from(config: &TlsConfig) -> Self {
        match TlsMode::resolve(config) {
            Ok(Some(TlsMode::File(file))) => Some(file),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMode {
    Off,
    Optional,
    Required,
}

impl ClientAuthMode {
    pub fn resolve(config: &TlsConfig) -> Result<Self, TlsError> {
        match config.client_auth.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "disabled" | "none" => Ok(Self::Off),
            "optional" | "request" => Ok(Self::Optional),
            "required" | "require" | "verify" => Ok(Self::Required),
            other => Err(TlsError::ConfigError(format!(
                "unknown tls.client_auth '{other}', expected 'optional' or 'required'"
            ))),
        }
    }

    fn verify_mode(self) -> Option<ssl::SslVerifyMode> {
        match self {
            Self::Off => None,
            Self::Optional => Some(ssl::SslVerifyMode::PEER),
            Self::Required => Some(
                ssl::SslVerifyMode::PEER | ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClientCaSource {
    File { path: String },
    ConsulKv { prefix: String },
}

#[derive(Debug, Clone)]
pub struct ClientAuthConfig {
    pub mode: ClientAuthMode,
    pub source: ClientCaSource,
    pub ca_upgrade_cn: String,
}

impl ClientAuthConfig {
    pub fn resolve(config: &TlsConfig) -> Result<Option<Self>, TlsError> {
        let mode = ClientAuthMode::resolve(config)?;
        if mode == ClientAuthMode::Off {
            return Ok(None);
        }

        let source = match config.client_ca_source.trim().to_ascii_lowercase().as_str() {
            "file" => {
                let path = config.client_ca_path.trim().to_string();
                if path.is_empty() {
                    return Err(TlsError::ConfigError(
                        "tls.client_ca_path cannot be empty when tls.client_ca_source=file"
                            .to_string(),
                    ));
                }
                ClientCaSource::File { path }
            }
            "consul" | "consul_kv" | "fabio_consul" => {
                let prefix = config.client_ca_consul_prefix.trim().to_string();
                if prefix.is_empty() {
                    return Err(TlsError::ConfigError(
                        "tls.client_ca_consul_prefix cannot be empty when tls.client_ca_source=consul_kv"
                            .to_string(),
                    ));
                }
                ClientCaSource::ConsulKv { prefix }
            }
            "" => {
                return Err(TlsError::ConfigError(
                    "tls.client_ca_source is required when tls.client_auth is enabled"
                        .to_string(),
                ));
            }
            other => {
                return Err(TlsError::ConfigError(format!(
                    "unknown tls.client_ca_source '{other}', expected 'file' or 'consul_kv'"
                )));
            }
        };

        Ok(Some(Self {
            mode,
            source,
            ca_upgrade_cn: config.client_ca_upgrade_cn.trim().to_string(),
        }))
    }
}

/// Derive the TLS listen address from config.
pub fn tls_listen_addr(http_listen: &str, tls_listen: &str) -> String {
    if !tls_listen.trim().is_empty() {
        return tls_listen.to_string();
    }

    let http_port: u16 = http_listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9999);
    format!(":{}", http_port + 1)
}

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

impl DynamicCertStore {
    pub fn new(strict_sni: bool) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(CertSnapshot::default()),
            status: RwLock::new(DynamicTlsStatus::default()),
            strict_sni,
        }
    }

    pub fn status(&self) -> DynamicTlsStatus {
        self.status.read().expect("tls status poisoned").clone()
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
            let mut status = self.status.write().expect("tls status poisoned");
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
            let mut status = self.status.write().expect("tls status poisoned");
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

        let mut status = self.status.write().expect("tls status poisoned");
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
        self.status
            .read()
            .expect("client ca status poisoned")
            .clone()
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
            return Err(TlsError::ConfigError(
                status.last_error.unwrap_or_else(|| {
                    "no valid client CA certificates loaded from path".to_string()
                }),
            ));
        }
        Ok(())
    }

    pub fn apply_consul_snapshot(&self, entries: BTreeMap<String, Vec<u8>>, consul_index: u64) {
        self.apply_snapshot(entries, consul_index);
    }

    fn apply_snapshot(&self, entries: BTreeMap<String, Vec<u8>>, consul_index: u64) {
        if entries.is_empty() {
            let mut status = self.status.write().expect("client ca status poisoned");
            status.last_consul_index = consul_index;
            status.last_error = Some(
                "received empty client CA snapshot; keeping last known good store".to_string(),
            );
            tracing::warn!(consul_index, "Received empty client CA snapshot; keeping last known good store");
            return;
        }

        match ClientCaSnapshot::from_entries(&entries, &self.ca_upgrade_cn) {
            Ok((next_snapshot, warnings)) => {
                if next_snapshot.store.is_none() {
                    let mut status = self.status.write().expect("client ca status poisoned");
                    status.last_consul_index = consul_index;
                    status.last_error = Some(
                        warnings.first().cloned().unwrap_or_else(|| {
                            "no valid client CA certificates remain after reload; keeping last known good store".to_string()
                        }),
                    );
                    tracing::error!(consul_index, "No valid client CA certificates remain after reload; keeping last known good store");
                    return;
                }

                let loaded_entries = next_snapshot.entry_names.clone();
                let certificates = next_snapshot.certificates.clone();
                self.snapshot.store(Arc::new(next_snapshot));

                let mut status = self.status.write().expect("client ca status poisoned");
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
                let mut status = self.status.write().expect("client ca status poisoned");
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

            if key_name != cert_name {
                if let Err(reason) = validate_entry_size(&key_name, key_pem.len()) {
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

            let mut labels: Vec<String> = name.split('.').map(|part| part.to_string()).collect();
            for idx in 0..labels.len() {
                labels[idx] = "*".to_string();
                let wildcard = labels.join(".");
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

fn maybe_reuse_previous(
    previous: &CertSnapshot,
    entry_name: &str,
    ordered: &mut Vec<Arc<LoadedCertificate>>,
    by_entry_name: &mut HashMap<String, Arc<LoadedCertificate>>,
    warnings: &mut Vec<String>,
    reason: String,
) {
    if let Some(cert) = previous.by_entry_name.get(entry_name) {
        ordered.push(cert.clone());
        by_entry_name.insert(entry_name.to_string(), cert.clone());
        warnings.push(format!("{reason}; reusing previous certificate"));
    } else {
        warnings.push(reason);
    }
}

fn record_warning_metrics(metrics: &crate::metrics::prometheus::Metrics, warnings: &[String]) {
    for warning in warnings {
        let reason = if warning.contains("exceeds max size") {
            "oversize"
        } else {
            "invalid"
        };
        metrics.record_cert_reload_skipped(reason);
    }
}

fn classify_fabio_entry(name: &str) -> Option<(String, String, String)> {
    if let Some(base) = name.strip_suffix("-cert.pem") {
        return Some((
            name.to_string(),
            name.to_string(),
            format!("{base}-key.pem"),
        ));
    }
    if let Some(base) = name.strip_suffix("-key.pem") {
        return Some((
            format!("{base}-cert.pem"),
            format!("{base}-cert.pem"),
            name.to_string(),
        ));
    }
    if name.ends_with(".pem") {
        return Some((name.to_string(), name.to_string(), name.to_string()));
    }
    None
}

fn validate_entry_size(entry_name: &str, byte_len: usize) -> Result<(), String> {
    if byte_len > MAX_CONSUL_CERT_ENTRY_BYTES {
        return Err(format!(
            "entry '{entry_name}' exceeds max size {} bytes ({byte_len} bytes)",
            MAX_CONSUL_CERT_ENTRY_BYTES
        ));
    }
    Ok(())
}

fn extract_certificate_names(cert: &X509) -> Vec<String> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();

    if let Some(sans) = cert.subject_alt_names() {
        for san in sans {
            if let Some(dns) = san.dnsname() {
                let normalized = normalize_dns_name(dns);
                if !normalized.is_empty() && seen.insert(normalized.clone()) {
                    names.push(normalized);
                }
            }
        }
    }

    for entry in cert.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(value) = entry.data().as_utf8() {
            let normalized = normalize_dns_name(value.as_ref());
            if !normalized.is_empty() && seen.insert(normalized.clone()) {
                names.push(normalized);
            }
        }
    }

    names
}

fn normalize_server_name(server_name: Option<&str>) -> Option<String> {
    server_name
        .map(normalize_dns_name)
        .filter(|name| !name.is_empty())
}

fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_certificate_chain(input: &[u8]) -> Result<Vec<X509>, TlsError> {
    let text = std::str::from_utf8(input)
        .map_err(|e| TlsError::ConfigError(format!("certificate PEM is not valid UTF-8: {e}")))?;
    let mut certs = Vec::new();
    for block in pem_blocks(text) {
        if block.kind == "CERTIFICATE" {
            let cert = X509::from_pem(block.pem.as_bytes()).map_err(|e| {
                TlsError::ConfigError(format!("invalid CERTIFICATE PEM block: {e}"))
            })?;
            certs.push(cert);
        }
    }
    Ok(certs)
}

fn parse_private_key(input: &[u8]) -> Result<PKey<Private>, TlsError> {
    let text = std::str::from_utf8(input)
        .map_err(|e| TlsError::ConfigError(format!("private key PEM is not valid UTF-8: {e}")))?;

    for block in pem_blocks(text) {
        if block.kind.ends_with("PRIVATE KEY") {
            return PKey::private_key_from_pem(block.pem.as_bytes())
                .map_err(|e| TlsError::ConfigError(format!("invalid PRIVATE KEY PEM block: {e}")));
        }
    }

    Err(TlsError::ConfigError(
        "private key bundle contains no PRIVATE KEY block".to_string(),
    ))
}

fn parse_client_ca_certificates(
    entry_name: &str,
    input: &[u8],
    ca_upgrade_cn: &str,
) -> Result<Vec<X509>, TlsError> {
    let text = std::str::from_utf8(input).map_err(|e| {
        TlsError::ConfigError(format!(
            "client CA entry '{entry_name}' is not valid UTF-8 PEM: {e}"
        ))
    })?;

    let mut certs = Vec::new();
    for block in pem_blocks(text) {
        if block.kind == "CERTIFICATE" {
            let cert = X509::from_pem(block.pem.as_bytes()).map_err(|e| {
                TlsError::ConfigError(format!(
                    "invalid client CA CERTIFICATE block in '{entry_name}': {e}"
                ))
            })?;
            maybe_upgrade_ca_certificate(&cert, ca_upgrade_cn);
            certs.push(cert);
        }
    }
    Ok(certs)
}

fn load_pem_entries_from_path(path: &str) -> Result<BTreeMap<String, Vec<u8>>, TlsError> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| TlsError::ConfigError(format!("failed to stat client CA path '{path}': {e}")))?;

    let mut entries = BTreeMap::new();
    if metadata.is_dir() {
        let mut dir_entries = std::fs::read_dir(path).map_err(|e| {
            TlsError::ConfigError(format!("failed to read client CA directory '{path}': {e}"))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::ConfigError(format!("failed to enumerate client CA directory '{path}': {e}")))?;
        dir_entries.sort_by_key(|entry| entry.file_name());

        for entry in dir_entries {
            let file_type = entry.file_type().map_err(|e| {
                TlsError::ConfigError(format!(
                    "failed to inspect client CA directory entry '{}': {e}",
                    entry.path().display()
                ))
            })?;
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let bytes = std::fs::read(entry.path()).map_err(|e| {
                TlsError::ConfigError(format!(
                    "failed to read client CA file '{}': {e}",
                    entry.path().display()
                ))
            })?;
            entries.insert(name, bytes);
        }
    } else {
        let name = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("client-ca.pem")
            .to_string();
        let bytes = std::fs::read(path).map_err(|e| {
            TlsError::ConfigError(format!("failed to read client CA file '{path}': {e}"))
        })?;
        entries.insert(name, bytes);
    }

    Ok(entries)
}

fn client_ca_certificate_status(
    entry_name: &str,
    cert: &X509,
) -> DynamicClientCaCertificateStatus {
    DynamicClientCaCertificateStatus {
        entry_name: entry_name.to_string(),
        subject: certificate_subject_string(cert),
        common_name: first_subject_value(cert, Nid::COMMONNAME),
        organization: first_subject_value(cert, Nid::ORGANIZATIONNAME),
        organizational_unit: first_subject_value(cert, Nid::ORGANIZATIONALUNITNAME),
    }
}

fn first_subject_value(cert: &X509, nid: Nid) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(nid)
        .find_map(|entry| entry.data().as_utf8().ok().map(|value| value.to_string()))
}

fn certificate_subject_string(cert: &X509) -> String {
    certificate_subject_string_ref(cert)
}

fn certificate_subject_string_ref(cert: &pingora::tls::x509::X509Ref) -> String {
    let mut parts = Vec::new();
    if let Some(cn) = first_name_value(cert.subject_name(), Nid::COMMONNAME) {
        parts.push(format!("CN={cn}"));
    }
    if let Some(org) = first_name_value(cert.subject_name(), Nid::ORGANIZATIONNAME) {
        parts.push(format!("O={org}"));
    }
    if let Some(ou) = first_name_value(cert.subject_name(), Nid::ORGANIZATIONALUNITNAME) {
        parts.push(format!("OU={ou}"));
    }
    if parts.is_empty() {
        "<unknown-subject>".to_string()
    } else {
        parts.join(", ")
    }
}

fn maybe_upgrade_ca_certificate(cert: &X509, ca_upgrade_cn: &str) {
    if should_treat_as_upgraded_ca(ca_upgrade_cn, ssl_sys::X509_V_ERR_INVALID_CA, cert) {
        tracing::info!(
            subject = %certificate_subject_string(cert),
            ca_upgrade_cn,
            "Loaded client CA certificate matches CA upgrade CN; enabling Fabio-compatible verify override"
        );
    }
}

fn should_accept_ca_upgrade_error(
    ca_upgrade_cn: &str,
    store_ctx: &mut pingora::tls::x509::X509StoreContextRef,
) -> bool {
    let Some(cert) = store_ctx.current_cert() else {
        return false;
    };
    should_treat_as_upgraded_ca(ca_upgrade_cn, store_ctx.error().as_raw(), cert)
}

fn should_treat_as_upgraded_ca(
    ca_upgrade_cn: &str,
    error_code: i32,
    cert: &pingora::tls::x509::X509Ref,
) -> bool {
    if ca_upgrade_cn.is_empty() {
        return false;
    }

    let is_ca_flag_error = matches!(
        error_code,
        ssl_sys::X509_V_ERR_INVALID_CA
            | ssl_sys::X509_V_ERR_INVALID_PURPOSE
            | ssl_sys::X509_V_ERR_KEYUSAGE_NO_CERTSIGN
            | ssl_sys::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
            | ssl_sys::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
            | ssl_sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            | ssl_sys::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
    );
    if !is_ca_flag_error {
        return false;
    }

    let issuer_cn = first_name_value(cert.issuer_name(), Nid::COMMONNAME);
    let subject_cn = first_name_value(cert.subject_name(), Nid::COMMONNAME);
    issuer_cn.as_deref() == Some(ca_upgrade_cn) || subject_cn.as_deref() == Some(ca_upgrade_cn)
}

fn first_name_value(name: &pingora::tls::x509::X509NameRef, nid: Nid) -> Option<String> {
    name.entries_by_nid(nid)
        .find_map(|entry| entry.data().as_utf8().ok().map(|value| value.to_string()))
}

struct PemBlock<'a> {
    kind: &'a str,
    pem: &'a str,
}

fn pem_blocks(input: &str) -> Vec<PemBlock<'_>> {
    let begin_re = Regex::new(r"-----BEGIN ([A-Z0-9 ]+)-----").expect("valid PEM regex");
    let mut blocks = Vec::new();
    let mut offset = 0;

    while let Some(capture) = begin_re.captures(&input[offset..]) {
        let whole = match capture.get(0) {
            Some(m) => m,
            None => break,
        };
        let kind = match capture.get(1) {
            Some(m) => m.as_str(),
            None => break,
        };

        let start = offset + whole.start();
        let end_marker = format!("-----END {kind}-----");
        let search_from = offset + whole.end();
        let Some(relative_end) = input[search_from..].find(&end_marker) else {
            break;
        };
        let end = search_from + relative_end + end_marker.len();
        blocks.push(PemBlock {
            kind,
            pem: &input[start..end],
        });
        offset = end;
    }

    blocks
}

fn asn1_time_to_unix_seconds(time: &impl std::fmt::Display) -> Option<u64> {
    let display = time.to_string();
    let mut parts = display.split_whitespace();
    let month = parse_month(parts.next()?)?;
    let day = parts.next()?.parse::<u8>().ok()?;
    let hms = parts.next()?;
    let year = parts.next()?.parse::<i32>().ok()?;
    let _gmt = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let mut hms_parts = hms.split(':');
    let hour = hms_parts.next()?.parse::<u8>().ok()?;
    let minute = hms_parts.next()?.parse::<u8>().ok()?;
    let second = hms_parts.next()?.parse::<u8>().ok()?;
    if hms_parts.next().is_some() {
        return None;
    }

    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    let unix = PrimitiveDateTime::new(date, time).assume_utc().unix_timestamp();
    u64::try_from(unix).ok()
}

fn parse_month(value: &str) -> Option<Month> {
    match value {
        "Jan" => Some(Month::January),
        "Feb" => Some(Month::February),
        "Mar" => Some(Month::March),
        "Apr" => Some(Month::April),
        "May" => Some(Month::May),
        "Jun" => Some(Month::June),
        "Jul" => Some(Month::July),
        "Aug" => Some(Month::August),
        "Sep" => Some(Month::September),
        "Oct" => Some(Month::October),
        "Nov" => Some(Month::November),
        "Dec" => Some(Month::December),
        _ => None,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

enum ServerCertificateSource {
    Static(Arc<LoadedCertificate>),
    Dynamic(Arc<DynamicCertStore>),
}

impl ServerCertificateSource {
    fn select(&self, server_name: Option<&str>) -> Option<Arc<LoadedCertificate>> {
        match self {
            Self::Static(cert) => Some(cert.clone()),
            Self::Dynamic(store) => store.select_for_server_name(server_name),
        }
    }
}

struct ClientAuthState {
    mode: ClientAuthMode,
    store: Arc<DynamicClientCaStore>,
    ca_upgrade_cn: String,
}

impl ClientAuthState {
    fn configure_ssl(&self, ssl: &mut pingora::tls::ssl::SslRef) -> Result<(), TlsError> {
        let Some(verify_mode) = self.mode.verify_mode() else {
            return Ok(());
        };

        let Some(snapshot) = self.store.current_store() else {
            ssl.set_verify(ssl::SslVerifyMode::NONE);
            return Ok(());
        };

        let verify_store = snapshot.store.as_ref().ok_or_else(|| {
            TlsError::ConfigError("client CA snapshot missing verify store".to_string())
        })?;

        ext::ssl_set_verify_cert_store(ssl, verify_store).map_err(|e| {
            TlsError::ConfigError(format!("failed to attach client CA verify store: {e}"))
        })?;

        let ca_upgrade_cn = self.ca_upgrade_cn.clone();
        ssl.set_verify_callback(verify_mode, move |preverify_ok, store_ctx| {
            if preverify_ok {
                if store_ctx.error_depth() == 0
                    && let Some(cert) = store_ctx.current_cert()
                {
                    crate::proxy::handler::remember_verified_client_certificate(cert);
                }
                return true;
            }
            tracing::debug!(
                ca_upgrade_cn,
                error_code = store_ctx.error().as_raw(),
                error = %store_ctx.error(),
                subject = store_ctx.current_cert().map(certificate_subject_string_ref),
                "client certificate verification failed before CA-upgrade override"
            );
            if should_accept_ca_upgrade_error(&ca_upgrade_cn, store_ctx) {
                tracing::info!(
                    ca_upgrade_cn,
                    error_code = store_ctx.error().as_raw(),
                    error = %store_ctx.error(),
                    subject = store_ctx.current_cert().map(certificate_subject_string_ref),
                    "accepting client certificate verification failure via CA-upgrade override"
                );
                if store_ctx.error_depth() == 0
                    && let Some(cert) = store_ctx.current_cert()
                {
                    crate::proxy::handler::remember_verified_client_certificate(cert);
                }
                store_ctx.set_error(X509VerifyResult::OK);
                return true;
            }
            false
        });
        Ok(())
    }
}

struct TlsSelector {
    server_certs: ServerCertificateSource,
    client_auth: Option<ClientAuthState>,
}

#[async_trait]
impl pingora::listeners::TlsAccept for TlsSelector {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        if let Some(client_auth) = &self.client_auth
            && let Err(error) = client_auth.configure_ssl(ssl)
        {
            tracing::error!(%error, "Failed to configure client certificate verification during handshake");
            return;
        }

        let server_name = ssl.servername(ssl::NameType::HOST_NAME);
        let Some(cert) = self.server_certs.select(server_name) else {
            tracing::debug!(server_name = ?server_name, "No TLS certificate matched requested SNI");
            return;
        };

        if let Err(error) = ext::ssl_use_certificate(ssl, &cert.leaf) {
            tracing::error!(entry = %cert.entry_name, %error, "Failed to attach TLS leaf certificate during handshake");
            return;
        }

        if let Err(error) = ext::ssl_use_private_key(ssl, &cert.key) {
            tracing::error!(entry = %cert.entry_name, %error, "Failed to attach TLS private key during handshake");
            return;
        }

        for chain_cert in &cert.chain {
            if let Err(error) = ext::ssl_add_chain_cert(ssl, chain_cert) {
                tracing::error!(entry = %cert.entry_name, %error, "Failed to attach TLS chain certificate during handshake");
                return;
            }
        }
    }
}

pub fn load_static_certificate(config: &TlsCertConfig) -> Result<Arc<LoadedCertificate>, TlsError> {
    let cert_pem = std::fs::read(&config.cert_path)
        .map_err(|e| TlsError::CertReadError(config.cert_path.clone(), e.to_string()))?;
    let key_pem = std::fs::read(&config.key_path)
        .map_err(|e| TlsError::KeyReadError(config.key_path.clone(), e.to_string()))?;
    Ok(Arc::new(LoadedCertificate::from_pem_pair(
        "static-file",
        &cert_pem,
        &key_pem,
    )?))
}

pub fn build_tls_settings(
    server_certs: Arc<DynamicCertStore>,
    client_auth: Option<(ClientAuthMode, Arc<DynamicClientCaStore>)>,
) -> Result<TlsSettings, TlsError> {
    build_tls_settings_from_source(ServerCertificateSource::Dynamic(server_certs), client_auth)
}

pub fn build_static_tls_settings(
    cert: Arc<LoadedCertificate>,
    client_auth: Option<(ClientAuthMode, Arc<DynamicClientCaStore>)>,
) -> Result<TlsSettings, TlsError> {
    build_tls_settings_from_source(ServerCertificateSource::Static(cert), client_auth)
}

fn build_tls_settings_from_source(
    server_certs: ServerCertificateSource,
    client_auth: Option<(ClientAuthMode, Arc<DynamicClientCaStore>)>,
) -> Result<TlsSettings, TlsError> {
    let callbacks = Box::new(TlsSelector {
        server_certs,
        client_auth: client_auth.map(|(mode, store)| ClientAuthState {
            mode,
            store: store.clone(),
            ca_upgrade_cn: store.ca_upgrade_cn.clone(),
        }),
    });
    TlsSettings::with_callbacks(callbacks).map_err(|e| TlsError::ConfigError(e.to_string()))
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

    fn self_signed_cert(names: &[&str]) -> rcgen::CertifiedKey {
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
        (cert.cert.pem(), cert.key_pair.serialize_pem())
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
        assert_eq!(tls_listen_addr("127.0.0.1:9999", ""), ":10000");
    }

    #[test]
    fn test_client_auth_mode_resolve_required() {
        let config = crate::config::TlsConfig {
            client_auth: "required".to_string(),
            ..crate::config::TlsConfig::default()
        };
        assert_eq!(ClientAuthMode::resolve(&config).unwrap(), ClientAuthMode::Required);
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
            Some(ClientAuthConfig { mode, source: ClientCaSource::ConsulKv { prefix }, .. }) => {
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
        assert!(status.certificates.iter().any(|c| c.entry_name == "client-ca.pem"));
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
        let cert = self_signed_cert(&["example.com", "*.example.com"]);
        let expected_not_after = cert.cert.params().not_after.unix_timestamp() as u64;
        let combined = format!("{}{}", cert.cert.pem(), cert.key_pair.serialize_pem());
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
        assert_eq!(status.certificates[0].primary_name.as_deref(), Some("example.com"));
        assert_eq!(status.certificates[0].not_after_unix, Some(expected_not_after));
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
}

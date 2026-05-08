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
    x509::X509,
};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};
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

/// Lightweight runtime view for admin/config visibility.
#[derive(Debug, Clone, Default)]
pub struct DynamicTlsStatus {
    pub loaded_certificates: Vec<String>,
    pub default_certificate: Option<String>,
    pub last_consul_index: u64,
    pub last_reload_unix: Option<u64>,
    pub last_error: Option<String>,
}

pub struct DynamicCertStore {
    snapshot: ArcSwap<CertSnapshot>,
    status: RwLock<DynamicTlsStatus>,
    strict_sni: bool,
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
        self.snapshot.store(Arc::new(next_snapshot));

        let mut status = self.status.write().expect("tls status poisoned");
        status.loaded_certificates = loaded_certificates.clone();
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

struct LoadedCertificate {
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

fn extract_certificate_names(cert: &X509) -> Vec<String> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();

    for entry in cert.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(value) = entry.data().as_utf8() {
            let normalized = normalize_dns_name(value.as_ref());
            if !normalized.is_empty() && seen.insert(normalized.clone()) {
                names.push(normalized);
            }
        }
    }

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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct ConsulCertSelector {
    store: Arc<DynamicCertStore>,
}

#[async_trait]
impl pingora::listeners::TlsAccept for ConsulCertSelector {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        let server_name = ssl.servername(ssl::NameType::HOST_NAME);
        let Some(cert) = self.store.select_for_server_name(server_name) else {
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

pub fn build_dynamic_tls_settings(store: Arc<DynamicCertStore>) -> Result<TlsSettings, TlsError> {
    let callbacks = Box::new(ConsulCertSelector { store });
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
    use rcgen::generate_simple_self_signed;

    fn self_signed_pem(names: &[&str]) -> (String, String) {
        let cert = generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>(),
        )
        .expect("cert should build");
        (cert.cert.pem(), cert.key_pair.serialize_pem())
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
        };
        match TlsMode::resolve(&config).unwrap() {
            Some(TlsMode::ConsulKv(consul)) => {
                assert_eq!(consul.cert_prefix, "/fabio/cert");
                assert!(consul.strict_sni);
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
    fn test_dynamic_store_loads_fabio_style_combined_pem() {
        let (cert_pem, key_pem) = self_signed_pem(&["example.com", "*.example.com"]);
        let combined = format!("{cert_pem}{key_pem}");
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
}

use crate::config::TlsConfig;
use crate::proxy::tls::TlsError;
use pingora::tls::ssl;
use std::path::Path;

/// File-based TLS certificate and key configuration.
#[derive(Debug, Clone)]
pub struct TlsCertConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl TlsCertConfig {
    pub fn new(cert_path: String, key_path: String) -> Self {
        Self { cert_path, key_path }
    }

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

    pub fn is_configured(&self) -> bool {
        !self.cert_path.is_empty() && !self.key_path.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct ConsulTlsConfig {
    pub cert_prefix: String,
    pub strict_sni: bool,
    pub require_initial_snapshot: bool,
}

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

    pub(super) fn verify_mode(self) -> Option<ssl::SslVerifyMode> {
        match self {
            Self::Off => None,
            Self::Optional => Some(ssl::SslVerifyMode::PEER),
            Self::Required => {
                Some(ssl::SslVerifyMode::PEER | ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT)
            }
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
                    "tls.client_ca_source is required when tls.client_auth is enabled".to_string(),
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

pub fn tls_listen_addr(http_listen: &str, tls_listen: &str) -> String {
    if !tls_listen.trim().is_empty() {
        return tls_listen.to_string();
    }

    let trimmed = http_listen.trim();
    if let Some((host, port)) = trimmed.rsplit_once(':')
        && let Ok(http_port) = port.parse::<u16>()
    {
        let tls_port = http_port.checked_add(1).unwrap_or(10000);
        return format!("{}:{}", host, tls_port);
    }

    ":10000".to_string()
}

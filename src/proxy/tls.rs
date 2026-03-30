//! TLS termination support for Sentirum LB.
//!
//! Handles loading TLS certificates and configuring TLS listeners.
//! Uses Pingora's built-in rustls support for TLS termination.

use crate::config::TlsConfig;
use std::path::Path;

/// TLS certificate and key configuration.
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
        Self { cert_path, key_path }
    }

    /// Validate that the certificate and key files exist and are readable.
    pub fn validate(&self) -> Result<(), TlsError> {
        if !Path::new(&self.cert_path).exists() {
            return Err(TlsError::CertNotFound(self.cert_path.clone()));
        }
        if !Path::new(&self.key_path).exists() {
            return Err(TlsError::KeyNotFound(self.key_path.clone()));
        }

        // Try to read the files to verify permissions
        std::fs::read_to_string(&self.cert_path).map_err(|e| {
            TlsError::CertReadError(self.cert_path.clone(), e.to_string())
        })?;
        std::fs::read_to_string(&self.key_path).map_err(|e| {
            TlsError::KeyReadError(self.key_path.clone(), e.to_string())
        })?;

        Ok(())
    }

    /// Check if TLS is configured (both paths are non-empty).
    pub fn is_configured(&self) -> bool {
        !self.cert_path.is_empty() && !self.key_path.is_empty()
    }
}

impl From<&TlsConfig> for Option<TlsCertConfig> {
    fn from(config: &TlsConfig) -> Self {
        if config.cert_path.is_empty() || config.key_path.is_empty() {
            return None;
        }
        Some(TlsCertConfig::new(
            config.cert_path.clone(),
            config.key_path.clone(),
        ))
    }
}

/// TLS-related errors
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
    fn test_from_tls_config_empty() {
        let config = crate::config::TlsConfig::default();
        let result: Option<TlsCertConfig> = (&config).into();
        assert!(result.is_none());
    }

    #[test]
    fn test_from_tls_config_with_values() {
        let config = crate::config::TlsConfig {
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
            listen: ":9443".to_string(),
        };
        let result: Option<TlsCertConfig> = (&config).into();
        assert!(result.is_some());
        let tls = result.unwrap();
        assert_eq!(tls.cert_path, "/path/to/cert.pem");
        assert_eq!(tls.key_path, "/path/to/key.pem");
    }
}

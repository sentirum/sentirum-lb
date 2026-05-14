use crate::proxy::tls::{
    ClientAuthMode, DynamicCertStore, DynamicClientCaStore, LoadedCertificate, TlsError,
    certificate_subject_string_ref, should_accept_ca_upgrade_error,
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::listeners::tls::TlsSettings;
use pingora::tls::{ext, ssl, x509::X509VerifyResult};
use std::sync::Arc;

enum ServerCertificateSource {
    Static(Arc<ArcSwap<LoadedCertificate>>),
    Dynamic(Arc<DynamicCertStore>),
}

impl ServerCertificateSource {
    fn select(&self, server_name: Option<&str>) -> Option<Arc<LoadedCertificate>> {
        match self {
            Self::Static(swap) => Some(swap.load_full()),
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

pub fn load_static_certificate(
    config: &super::TlsCertConfig,
) -> Result<Arc<LoadedCertificate>, TlsError> {
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
    cert: Arc<ArcSwap<LoadedCertificate>>,
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

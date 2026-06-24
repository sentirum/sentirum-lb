//! TLS certificate inspection and manual reload handlers.

use super::api::AdminState;
use axum::extract::State;

/// Extract certificate info from a PEM file on disk.
fn file_cert_info(
    label: &str,
    listen: &str,
    cert_path: &str,
    client_auth: &str,
) -> serde_json::Value {
    let mut cert_info = serde_json::json!({
        "label": label,
        "listen": listen,
        "source": "file",
        "cert_path": cert_path,
        "client_auth": if client_auth.is_empty() { "off" } else { client_auth },
    });

    if let Ok(pem_bytes) = std::fs::read(cert_path)
        && let Ok(certs) = crate::proxy::tls::parse_certificate_chain(&pem_bytes)
        && let Some(leaf) = certs.first()
    {
        let subject = crate::proxy::tls::certificate_subject_string_ref(leaf);
        let cn = crate::proxy::tls::first_subject_value(leaf, pingora::tls::nid::Nid::COMMONNAME);
        let not_after = leaf.not_after().to_string();
        let not_after_unix = crate::proxy::tls::asn1_time_to_unix_seconds(leaf.not_after());
        let now = crate::proxy::tls::now_unix();
        let days_remaining = not_after_unix.map(|exp| ((exp as i64) - (now as i64)) / 86400);
        cert_info["subject"] = serde_json::json!(subject);
        cert_info["common_name"] = serde_json::json!(cn);
        cert_info["not_after"] = serde_json::json!(not_after);
        cert_info["not_after_unix"] = serde_json::json!(not_after_unix);
        cert_info["days_remaining"] = serde_json::json!(days_remaining);
        cert_info["chain_length"] = serde_json::json!(certs.len());
    }
    cert_info
}

pub(super) async fn certs_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    let config = state.config.load();
    let tls_source = match crate::proxy::tls::TlsMode::resolve(&config.tls) {
        Ok(Some(crate::proxy::tls::TlsMode::File(_))) => "file",
        Ok(Some(crate::proxy::tls::TlsMode::ConsulKv(_))) => "consul_kv",
        Ok(None) => "disabled",
        Err(_) => "invalid",
    };

    let runtime = state.tls_store.as_ref().map(|store| store.status());
    let client_ca_runtime = state.client_ca_store.as_ref().map(|store| store.status());

    // Gather file-listener descriptors, then read + parse the certificate files
    // off the async executor (fs I/O and X509 parsing are blocking).
    let mut file_listeners: Vec<(String, String, String, String)> = Vec::new();
    if tls_source == "file" && !config.tls.cert_path.is_empty() {
        file_listeners.push((
            "primary".to_string(),
            config.tls.listen.clone(),
            config.tls.cert_path.clone(),
            config.tls.client_auth.clone(),
        ));
    }
    for (i, tls_cfg) in config.tls_listeners.iter().enumerate() {
        let is_file = matches!(
            crate::proxy::tls::TlsMode::resolve(tls_cfg),
            Ok(Some(crate::proxy::tls::TlsMode::File(_)))
        );
        if is_file && !tls_cfg.cert_path.is_empty() {
            file_listeners.push((
                format!("tls_listeners[{}]", i),
                tls_cfg.listen.clone(),
                tls_cfg.cert_path.clone(),
                tls_cfg.client_auth.clone(),
            ));
        }
    }
    let listeners: Vec<serde_json::Value> = if file_listeners.is_empty() {
        Vec::new()
    } else {
        tokio::task::spawn_blocking(move || {
            file_listeners
                .iter()
                .map(|(label, listen, cert_path, client_auth)| {
                    file_cert_info(label, listen, cert_path, client_auth)
                })
                .collect()
        })
        .await
        .unwrap_or_default()
    };

    axum::Json(serde_json::json!({
        "source": tls_source,
        "strict_sni": config.tls.strict_sni,
        "require_initial_snapshot": config.tls.require_initial_snapshot,
        "consul_cert_prefix": config.tls.consul_cert_prefix,
        "loaded_certificates": runtime.as_ref().map(|s| s.loaded_certificates.clone()).unwrap_or_default(),
        "certificates": runtime.as_ref().map(|s| s.certificates.clone()).unwrap_or_default(),
        "default_certificate": runtime.as_ref().and_then(|s| s.default_certificate.clone()),
        "last_consul_index": runtime.as_ref().map(|s| s.last_consul_index).unwrap_or_default(),
        "last_reload_unix": runtime.as_ref().and_then(|s| s.last_reload_unix),
        "last_error": runtime.as_ref().and_then(|s| s.last_error.clone()),
        "listeners": listeners,
        "client_auth": {
            "mode": config.tls.client_auth,
            "ca_source": config.tls.client_ca_source,
            "ca_path": config.tls.client_ca_path,
            "ca_consul_prefix": config.tls.client_ca_consul_prefix,
            "ca_upgrade_cn": config.tls.client_ca_upgrade_cn,
            "loaded_entries": client_ca_runtime.as_ref().map(|s| s.loaded_entries.clone()).unwrap_or_default(),
            "certificates": client_ca_runtime.as_ref().map(|s| s.certificates.clone()).unwrap_or_default(),
            "last_consul_index": client_ca_runtime.as_ref().map(|s| s.last_consul_index).unwrap_or_default(),
            "last_reload_unix": client_ca_runtime.as_ref().and_then(|s| s.last_reload_unix),
            "last_error": client_ca_runtime.as_ref().and_then(|s| s.last_error.clone()),
        }
    }))
}

pub(super) async fn certs_reload_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    if state.file_certs.is_empty() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "No file-based TLS listeners configured"
        }));
    }

    // Cert load + file read + X509 parse are blocking; run them off the executor.
    // file_certs holds Arc/Config clones, so this is cheap to move into the task.
    let file_certs = state.file_certs.clone();
    let (results, errors) = tokio::task::spawn_blocking(move || {
        let mut results = Vec::new();
        let mut errors = Vec::new();
        for (label, shared_cert, config) in &file_certs {
            match crate::proxy::tls::load_static_certificate(config) {
                Ok(new_cert) => {
                    let cert_path = &config.cert_path;
                    let subject;
                    let cn;
                    let days: Option<i64>;

                    if let Ok(pem_bytes) = std::fs::read(cert_path) {
                        if let Ok(certs) = crate::proxy::tls::parse_certificate_chain(&pem_bytes) {
                            if let Some(leaf) = certs.first() {
                                subject = crate::proxy::tls::certificate_subject_string_ref(leaf);
                                cn = crate::proxy::tls::first_subject_value(
                                    leaf,
                                    pingora::tls::nid::Nid::COMMONNAME,
                                );
                                let not_after_unix =
                                    crate::proxy::tls::asn1_time_to_unix_seconds(leaf.not_after());
                                days = not_after_unix.map(|exp| {
                                    ((exp as i64) - (crate::proxy::tls::now_unix() as i64)) / 86400
                                });
                            } else {
                                subject = "unknown".to_string();
                                cn = None;
                                days = None;
                            }
                        } else {
                            subject = "parse-error".to_string();
                            cn = None;
                            days = None;
                        }
                    } else {
                        subject = "read-error".to_string();
                        cn = None;
                        days = None;
                    }

                    shared_cert.store(new_cert);

                    tracing::info!(
                        listener = %label,
                        subject = %subject,
                        common_name = ?cn,
                        days_remaining = ?days,
                        "Certificate manually reloaded via admin API"
                    );

                    results.push(serde_json::json!({
                        "listener": label,
                        "subject": subject,
                        "common_name": cn,
                        "days_remaining": days,
                    }));
                }
                Err(error) => {
                    tracing::warn!(
                        listener = %label,
                        error = %error,
                        "Failed to reload certificate via admin API"
                    );
                    errors.push(serde_json::json!({
                        "listener": label,
                        "error": error.to_string(),
                    }));
                }
            }
        }
        (results, errors)
    })
    .await
    .unwrap_or_else(|_| {
        (
            Vec::new(),
            vec![serde_json::json!({ "error": "certificate reload task failed" })],
        )
    });

    axum::Json(serde_json::json!({
        "success": errors.is_empty(),
        "reloaded": results.len(),
        "failed": errors.len(),
        "details": results,
        "errors": errors,
    }))
}

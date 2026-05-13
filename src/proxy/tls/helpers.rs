use crate::proxy::tls::{
    DynamicClientCaCertificateStatus, LoadedCertificate, MAX_CONSUL_CERT_ENTRY_BYTES, TlsError,
};
use pingora::tls::{
    nid::Nid,
    pkey::{PKey, Private},
    ssl_sys,
    x509::X509,
};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use time::{Date, Month, PrimitiveDateTime, Time};

pub(super) fn maybe_reuse_previous(
    previous: &super::CertSnapshot,
    entry_name: &str,
    ordered: &mut Vec<std::sync::Arc<LoadedCertificate>>,
    by_entry_name: &mut HashMap<String, std::sync::Arc<LoadedCertificate>>,
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

pub(super) fn record_warning_metrics(
    metrics: &crate::metrics::prometheus::Metrics,
    warnings: &[String],
) {
    for warning in warnings {
        let reason = if warning.contains("exceeds max size") {
            "oversize"
        } else {
            "invalid"
        };
        metrics.record_cert_reload_skipped(reason);
    }
}

pub(super) fn classify_fabio_entry(name: &str) -> Option<(String, String, String)> {
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

pub(super) fn validate_entry_size(entry_name: &str, byte_len: usize) -> Result<(), String> {
    if byte_len > MAX_CONSUL_CERT_ENTRY_BYTES {
        return Err(format!(
            "entry '{entry_name}' exceeds max size {} bytes ({byte_len} bytes)",
            MAX_CONSUL_CERT_ENTRY_BYTES
        ));
    }
    Ok(())
}

pub(super) fn extract_certificate_names(cert: &X509) -> Vec<String> {
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

pub(super) fn normalize_server_name(server_name: Option<&str>) -> Option<String> {
    server_name
        .map(normalize_dns_name)
        .filter(|name| !name.is_empty())
}

pub(super) fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn parse_certificate_chain(input: &[u8]) -> Result<Vec<X509>, TlsError> {
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

pub(super) fn parse_private_key(input: &[u8]) -> Result<PKey<Private>, TlsError> {
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

pub(super) fn parse_client_ca_certificates(
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

pub(super) fn load_pem_entries_from_path(
    path: &str,
) -> Result<BTreeMap<String, Vec<u8>>, TlsError> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| TlsError::ConfigError(format!("failed to stat PEM path '{path}': {e}")))?;

    let mut entries = BTreeMap::new();
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)
            .map_err(|e| TlsError::ConfigError(format!("failed to read PEM dir '{path}': {e}")))?
        {
            let entry = entry
                .map_err(|e| TlsError::ConfigError(format!("failed to read PEM dir entry: {e}")))?;
            let file_type = entry.file_type().map_err(|e| {
                TlsError::ConfigError(format!("failed to inspect PEM dir entry type: {e}"))
            })?;
            if !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy().to_string();
            if !file_name.ends_with(".pem") {
                continue;
            }
            let pem_bytes = std::fs::read(entry.path()).map_err(|e| {
                TlsError::ConfigError(format!("failed to read PEM file '{}': {e}", file_name))
            })?;
            entries.insert(file_name, pem_bytes);
        }
    } else {
        let pem_bytes = std::fs::read(path)
            .map_err(|e| TlsError::ConfigError(format!("failed to read PEM file '{path}': {e}")))?;
        let file_name = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("bundle.pem")
            .to_string();
        entries.insert(file_name, pem_bytes);
    }

    Ok(entries)
}

pub(super) fn client_ca_certificate_status(
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

pub(crate) fn first_subject_value(cert: &pingora::tls::x509::X509Ref, nid: Nid) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(nid)
        .find_map(|entry| entry.data().as_utf8().ok().map(|value| value.to_string()))
}

fn certificate_subject_string(cert: &X509) -> String {
    certificate_subject_string_ref(cert)
}

pub(crate) fn certificate_subject_string_ref(cert: &pingora::tls::x509::X509Ref) -> String {
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

pub(super) fn should_accept_ca_upgrade_error(
    ca_upgrade_cn: &str,
    store_ctx: &mut pingora::tls::x509::X509StoreContextRef,
) -> bool {
    let Some(cert) = store_ctx.current_cert() else {
        return false;
    };
    should_treat_as_upgraded_ca(ca_upgrade_cn, store_ctx.error().as_raw(), cert)
}

pub(super) fn should_treat_as_upgraded_ca(
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

static PEM_BEGIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN ([A-Z0-9 ]+)-----").expect("valid PEM regex"));

fn pem_blocks(input: &str) -> Vec<PemBlock<'_>> {
    let mut blocks = Vec::new();
    let mut offset = 0;

    while let Some(capture) = PEM_BEGIN_RE.captures(&input[offset..]) {
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

pub(crate) fn asn1_time_to_unix_seconds(time: &impl std::fmt::Display) -> Option<u64> {
    let value = time.to_string();
    let mut parts = value.split_whitespace();
    let month = parse_month(parts.next()?)?;
    let day = parts.next()?.parse::<u8>().ok()?;
    let hhmmss = parts.next()?;
    let year = parts.next()?.parse::<i32>().ok()?;

    let mut hhmmss_parts = hhmmss.split(':');
    let hour = hhmmss_parts.next()?.parse::<u8>().ok()?;
    let minute = hhmmss_parts.next()?.parse::<u8>().ok()?;
    let second = hhmmss_parts.next()?.parse::<u8>().ok()?;

    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    let datetime = PrimitiveDateTime::new(date, time);
    datetime.assume_utc().unix_timestamp().try_into().ok()
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

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

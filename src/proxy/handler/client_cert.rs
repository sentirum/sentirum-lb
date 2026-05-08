use pingora::proxy::Session;
use pingora::tls::{hash::MessageDigest, nid::Nid};
use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClientCertIdentity {
    pub(crate) verified: bool,
    pub(crate) serial: Option<String>,
    pub(crate) organization: Option<String>,
    pub(crate) organizational_unit: Option<String>,
    pub(crate) common_name: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) sha256: Option<String>,
}

const CLIENT_CERT_IDENTITY_CACHE_CAPACITY: usize = 4096;

static CLIENT_CERT_IDENTITY_CACHE: LazyLock<Mutex<ClientCertIdentityCache>> =
    LazyLock::new(|| Mutex::new(ClientCertIdentityCache::default()));

#[derive(Default)]
pub(super) struct ClientCertIdentityCache {
    entries: HashMap<String, ClientCertIdentity>,
    pub(super) order: VecDeque<String>,
}

impl ClientCertIdentityCache {
    /// Remove the oldest entries when capacity is exceeded.
    /// Called only on insert, not on get — avoids O(n) scans on the hot path.
    fn evict_if_needed(&mut self) {
        while self.entries.len() > CLIENT_CERT_IDENTITY_CACHE_CAPACITY {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    pub(super) fn insert(&mut self, digest_hex: String, identity: ClientCertIdentity) {
        self.entries.insert(digest_hex.clone(), identity);
        // If this key already existed, remove it from its old position
        self.order.retain(|entry| entry != &digest_hex);
        self.order.push_back(digest_hex);
        self.evict_if_needed();
    }

    pub(super) fn get(&mut self, digest_hex: &str) -> Option<ClientCertIdentity> {
        self.entries.get(digest_hex).cloned()
    }
}

pub(crate) fn remember_verified_client_certificate(cert: &pingora::tls::x509::X509Ref) {
    let Ok(digest_bytes) = cert.digest(MessageDigest::sha256()) else {
        return;
    };
    let digest_hex = hex_lower(digest_bytes.as_ref());
    let identity = ClientCertIdentity {
        verified: true,
        serial: cert
            .serial_number()
            .to_bn()
            .ok()
            .and_then(|bn| bn.to_hex_str().ok())
            .map(|v| v.to_string()),
        organization: crate::proxy::tls::first_subject_value(cert, Nid::ORGANIZATIONNAME),
        organizational_unit: crate::proxy::tls::first_subject_value(
            cert,
            Nid::ORGANIZATIONALUNITNAME,
        ),
        common_name: crate::proxy::tls::first_subject_value(cert, Nid::COMMONNAME),
        subject: Some(crate::proxy::tls::certificate_subject_string_ref(cert)),
        sha256: Some(digest_hex.clone()),
    };
    if let Ok(mut cache) = CLIENT_CERT_IDENTITY_CACHE.lock() {
        cache.insert(digest_hex, identity);
    }
}

pub(super) fn cached_client_certificate_identity(cert_digest: &[u8]) -> Option<ClientCertIdentity> {
    if cert_digest.is_empty() {
        return None;
    }
    let digest_hex = hex_lower(cert_digest);
    CLIENT_CERT_IDENTITY_CACHE
        .lock()
        .ok()
        .and_then(|mut cache| cache.get(&digest_hex))
}

pub(super) fn append_client_certificate_headers(
    session: &Session,
    upstream_request: &mut pingora_http::RequestHeader,
) -> pingora::Result<()> {
    let Some(identity) = client_certificate_identity(session) else {
        return Ok(());
    };
    if !identity.verified {
        return Ok(());
    }

    upstream_request.insert_header("X-Client-Cert-Verified", "true")?;
    if let Some(value) = &identity.serial {
        upstream_request.insert_header("X-Client-Cert-Serial", value)?;
    }
    if let Some(value) = &identity.organization {
        upstream_request.insert_header("X-Client-Cert-Organization", value)?;
    }
    if let Some(value) = &identity.organizational_unit {
        upstream_request.insert_header("X-Client-Cert-Organizational-Unit", value)?;
    }
    if let Some(value) = &identity.common_name {
        upstream_request.insert_header("X-Client-Cert-Common-Name", value)?;
    }
    if let Some(value) = &identity.subject {
        upstream_request.insert_header("X-Client-Cert-Subject", value)?;
    }
    if let Some(value) = &identity.sha256 {
        upstream_request.insert_header("X-Client-Cert-SHA256", value)?;
    }
    Ok(())
}

fn client_certificate_identity(session: &Session) -> Option<ClientCertIdentity> {
    // Phase 1: Extract basic identity from Pingora's TLS digest.
    // The `verified` flag here is a heuristic: if cert_digest is non-empty,
    // Pingora saw *some* certificate during the handshake.
    let digest = session.digest()?.ssl_digest.as_ref()?;
    let mut identity = ClientCertIdentity {
        verified: !digest.cert_digest.is_empty(),
        serial: digest.serial_number.clone(),
        organization: digest.organization.clone(),
        organizational_unit: None,
        common_name: None,
        subject: None,
        sha256: (!digest.cert_digest.is_empty()).then(|| hex_lower(&digest.cert_digest)),
    };

    // Phase 2: Merge cached identity (from a previous handshake's verify callback).
    // Cache entries are richer (have CN, OU, subject) and carry their own `verified`
    // from the X509 verify callback.  We OR the flags so that either source of
    // truth is sufficient.
    if let Some(cached) = cached_client_certificate_identity(&digest.cert_digest) {
        identity.serial = cached.serial.or(identity.serial);
        identity.organization = cached.organization.or(identity.organization);
        identity.organizational_unit = cached.organizational_unit;
        identity.common_name = cached.common_name;
        identity.subject = cached.subject;
        identity.sha256 = cached.sha256.or(identity.sha256);
        identity.verified = cached.verified || identity.verified;
    }

    // Phase 3: Re-derive identity directly from the live SSL session.
    // This is the authoritative source: it re-reads the peer certificate,
    // refreshes the cache, and overwrites `verified` with the final
    // `ssl.verify_result()`.  If no peer certificate is present (e.g. the
    // handshake is in Optional mode and the client sent no cert), this
    // block is skipped entirely, preserving the merged result from phases 1+2.
    if let Some(stream) = session.stream()
        && let Some(ssl) = stream.get_ssl()
        && let Some(cert) = ssl.peer_certificate()
    {
        remember_verified_client_certificate(&cert);
        identity.common_name = crate::proxy::tls::first_subject_value(&cert, Nid::COMMONNAME);
        identity.organization =
            crate::proxy::tls::first_subject_value(&cert, Nid::ORGANIZATIONNAME)
                .or(identity.organization);
        identity.organizational_unit =
            crate::proxy::tls::first_subject_value(&cert, Nid::ORGANIZATIONALUNITNAME);
        identity.subject = Some(crate::proxy::tls::certificate_subject_string_ref(&cert));
        identity.sha256 = cert
            .digest(MessageDigest::sha256())
            .ok()
            .map(|bytes| hex_lower(bytes.as_ref()))
            .or(identity.sha256);
        // Authoritative: the OpenSSL verify result is the final word on
        // whether the chain is valid, overriding heuristics from phases 1–2.
        identity.verified = ssl.verify_result().as_raw() == pingora::tls::ssl_sys::X509_V_OK;
    }

    Some(identity)
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

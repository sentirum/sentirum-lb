use std::process::{Child, Command, Stdio};
use std::time::Duration;

use axum::{Json, Router, extract::State, routing::get};
use http::Version;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, generate_simple_self_signed,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::sleep;

struct TestRuntime {
    _tempdir: TempDir,
    child: Child,
    tls_port: u16,
    proxy_cert_pem: String,
}

impl Drop for TestRuntime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone)]
struct EchoState {
    expected_path: String,
}

struct ClientAuthFixture {
    ca_cert_pem: String,
    client_identity_pem: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downstream_mtls_ca_upgrade_cn_smoke() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream = spawn_header_echo_server("/whoami").await;
    let client_auth = generate_client_auth_fixture("ApiGateway");

    let no_upgrade_runtime = spawn_mtls_proxy(
        format!(
            "route add echo / http://127.0.0.1:{}/ opts \"ssrfskipverify=true\"\n",
            upstream.port(),
        ),
        &client_auth.ca_cert_pem,
        "",
    )
    .await;

    let no_upgrade_client = mtls_client(
        &no_upgrade_runtime.proxy_cert_pem,
        Some(&client_auth.client_identity_pem),
        true,
    );
    assert!(
        no_upgrade_client
            .get(format!(
                "https://localhost:{}/whoami",
                no_upgrade_runtime.tls_port
            ))
            .send()
            .await
            .is_err()
    );
    drop(no_upgrade_runtime);

    let upgrade_runtime = spawn_mtls_proxy(
        format!(
            "route add echo / http://127.0.0.1:{}/ opts \"ssrfskipverify=true\"\n",
            upstream.port(),
        ),
        &client_auth.ca_cert_pem,
        "ApiGateway",
    )
    .await;

    let no_cert_client = mtls_client(&upgrade_runtime.proxy_cert_pem, None, true);
    assert!(
        no_cert_client
            .get(format!(
                "https://localhost:{}/whoami",
                upgrade_runtime.tls_port
            ))
            .send()
            .await
            .is_err()
    );

    let h1_client = mtls_client(
        &upgrade_runtime.proxy_cert_pem,
        Some(&client_auth.client_identity_pem),
        true,
    );
    let h1_resp = h1_client
        .get(format!(
            "https://localhost:{}/whoami",
            upgrade_runtime.tls_port
        ))
        .send()
        .await
        .unwrap();
    assert!(h1_resp.status().is_success());

    let h1_body: serde_json::Value = h1_resp.json().await.unwrap();
    assert_eq!(h1_body["verified"], "true");
    assert_eq!(h1_body["common_name"], "client.sentirum.test");
    assert_eq!(h1_body["organization"], "Sentirum");
    assert_eq!(h1_body["organizational_unit"], "Platform");
    assert_eq!(
        h1_body["subject"],
        "CN=client.sentirum.test, O=Sentirum, OU=Platform"
    );
    assert!(h1_body["serial"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(h1_body["sha256"].as_str().is_some_and(|v| v.len() == 64));

    let h2_client = mtls_client(
        &upgrade_runtime.proxy_cert_pem,
        Some(&client_auth.client_identity_pem),
        false,
    );
    let h2_resp = h2_client
        .get(format!(
            "https://localhost:{}/whoami",
            upgrade_runtime.tls_port
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(h2_resp.version(), Version::HTTP_2);
    assert!(h2_resp.status().is_success());

    let h2_body: serde_json::Value = h2_resp.json().await.unwrap();
    assert_eq!(h2_body["verified"], "true");
    assert_eq!(h2_body["common_name"], "client.sentirum.test");
    assert_eq!(h2_body["organization"], "Sentirum");
    assert_eq!(h2_body["organizational_unit"], "Platform");
    assert_eq!(
        h2_body["subject"],
        "CN=client.sentirum.test, O=Sentirum, OU=Platform"
    );
    assert!(h2_body["serial"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(h2_body["sha256"].as_str().is_some_and(|v| v.len() == 64));
}

async fn spawn_header_echo_server(expected_path: &str) -> std::net::SocketAddr {
    let state = EchoState {
        expected_path: expected_path.to_string(),
    };
    let app = Router::new()
        .route(
            "/whoami",
            get(
                |State(state): State<EchoState>, headers: axum::http::HeaderMap| async move {
                    let verified = headers
                        .get("x-client-cert-verified")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let serial = headers
                        .get("x-client-cert-serial")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let organization = headers
                        .get("x-client-cert-organization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let common_name = headers
                        .get("x-client-cert-common-name")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let organizational_unit = headers
                        .get("x-client-cert-organizational-unit")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let subject = headers
                        .get("x-client-cert-subject")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let sha256 = headers
                        .get("x-client-cert-sha256")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    Json(json!({
                        "path": state.expected_path,
                        "verified": verified,
                        "serial": serial,
                        "organization": organization,
                        "common_name": common_name,
                        "organizational_unit": organizational_unit,
                        "subject": subject,
                        "sha256": sha256,
                    }))
                },
            ),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn spawn_mtls_proxy(
    routes: String,
    client_ca_pem: &str,
    client_ca_upgrade_cn: &str,
) -> TestRuntime {
    let tempdir = TempDir::new().unwrap();
    let http_port = free_port().await;
    let tls_port = free_port().await;
    let admin_port = free_port().await;

    let (proxy_cert_pem, proxy_key_pem) = generate_cert_material("localhost");
    let cert_path = tempdir.path().join("proxy-cert.pem");
    let key_path = tempdir.path().join("proxy-key.pem");
    let client_ca_path = tempdir.path().join("client-ca.pem");
    std::fs::write(&cert_path, &proxy_cert_pem).unwrap();
    std::fs::write(&key_path, &proxy_key_pem).unwrap();
    std::fs::write(&client_ca_path, client_ca_pem).unwrap();

    let routes_path = tempdir.path().join("routes.txt");
    std::fs::write(&routes_path, routes).unwrap();

    let config_path = tempdir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"[server]
listen = "127.0.0.1:{http_port}"
admin_listen = "127.0.0.1:{admin_port}"
workers = 0

[consul]
address = "127.0.0.1:8500"
scheme = "http"
kv_prefix = "/sentirum-lb/routes"
tag_prefix = "urlprefix-"
poll_interval = "0s"
service_discovery = false
kv_watching = false

[proxy]
strategy = "round-robin"
matcher = "prefix"
request_id_header = "X-Request-ID"
no_route_status = 404
connect_timeout = "5s"
read_timeout = "30s"
write_timeout = "30s"
idle_timeout = "300s"
enable_h2c = false
upstream_h2_max_streams = 64
upstream_h2_ping_interval = ""
pool_size = 128
max_connections = 10000

[logging]
level = "warn"
format = "text"

[tls]
source = "file"
cert_path = "{cert_path}"
key_path = "{key_path}"
listen = "127.0.0.1:{tls_port}"
client_auth = "required"
client_ca_source = "file"
client_ca_path = "{client_ca_path}"
client_ca_upgrade_cn = "{client_ca_upgrade_cn}"
"#,
            cert_path = cert_path.display(),
            key_path = key_path.display(),
            client_ca_path = client_ca_path.display(),
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_sentirum-lb"))
        .arg("--config")
        .arg(&config_path)
        .arg("--routes")
        .arg(&routes_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    wait_for_ready(http_port).await;

    TestRuntime {
        _tempdir: tempdir,
        child,
        tls_port,
        proxy_cert_pem,
    }
}

fn generate_client_auth_fixture(ca_common_name: &str) -> ClientAuthFixture {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, ca_common_name);
    ca_dn.push(DnType::OrganizationName, "Sentirum");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::NoCa;
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, "client.sentirum.test");
    client_dn.push(DnType::OrganizationName, "Sentirum");
    client_dn.push(DnType::OrganizationalUnitName, "Platform");
    client_params.distinguished_name = client_dn;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    ClientAuthFixture {
        ca_cert_pem: ca_cert.pem(),
        client_identity_pem: format!(
            "{}\n{}\n{}",
            client_cert.pem(),
            ca_cert.pem(),
            client_key.serialize_pem()
        ),
    }
}

fn mtls_client(
    proxy_cert_pem: &str,
    identity_pem: Option<&str>,
    http1_only: bool,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(proxy_cert_pem.as_bytes()).unwrap());

    if http1_only {
        builder = builder.http1_only();
    }

    if let Some(identity_pem) = identity_pem {
        builder = builder.identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap());
    }

    builder.build().unwrap()
}

async fn wait_for_ready(http_port: u16) {
    let client = reqwest::Client::new();
    for _ in 0..60 {
        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{http_port}/health"))
            .send()
            .await
            && resp.status().is_success()
        {
            return;
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("proxy did not become ready in time");
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn generate_cert_material(name: &str) -> (String, String) {
    let cert = generate_simple_self_signed(vec![name.into()]).unwrap();
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

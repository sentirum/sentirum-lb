use std::io::Cursor;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::ClientConfig as RustlsClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct TcpTestRuntime {
    _tempdir: TempDir,
    child: Child,
}

impl Drop for TcpTestRuntime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "end-to-end TCP/TCP+SNI smoke test"]
async fn tcp_plain_proxy_proto_and_tcp_sni_smoke() {
    let plain = spawn_plain_tcp_backend_with_proxy_proto().await;
    let tcp_listen_port = free_port().await;
    let plain_runtime = spawn_tcp_proxy(
        "tcp",
        Some(format!("127.0.0.1:{tcp_listen_port}")),
        format!(
            "route add nats :{tcp_listen_port} tcp://127.0.0.1:{backend} opts \"ssrfskipverify=true proto=tcp pxyproto=true\"\n",
            backend = plain.addr.port(),
        ),
        None,
    )
    .await;

    let mut plain_client = TcpStream::connect(("127.0.0.1", tcp_listen_port))
        .await
        .unwrap();
    plain_client.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    plain_client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    let proxy_header = plain.header.await.unwrap();
    assert!(proxy_header.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "));
    drop(plain_runtime);

    let sni = spawn_tls_echo_backend("nats.example.com").await;
    let sni_listen_port = free_port().await;
    let _sni_runtime = spawn_tcp_proxy(
        "tcp+sni",
        Some(format!("127.0.0.1:{sni_listen_port}")),
        format!(
            "route add nats nats.example.com tcp://127.0.0.1:{backend} opts \"ssrfskipverify=true proto=tcp\"\n",
            backend = sni.addr.port(),
        ),
        None,
    )
    .await;

    let mut roots = RootCertStore::empty();
    for cert in load_certs(&sni.cert_pem) {
        roots.add(cert).unwrap();
    }
    let client_config = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(("127.0.0.1", sni_listen_port))
        .await
        .unwrap();
    let server_name = ServerName::try_from("nats.example.com")
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(b"hello-sni").await.unwrap();
    let mut echoed = [0_u8; 9];
    tls.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello-sni");
}

struct PlainBackend {
    addr: std::net::SocketAddr,
    header: tokio::task::JoinHandle<String>,
}

async fn spawn_plain_tcp_backend_with_proxy_proto() -> PlainBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let header = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut proxy_header = String::new();
        reader.read_line(&mut proxy_header).await.unwrap();
        let mut payload = [0_u8; 4];
        reader.read_exact(&mut payload).await.unwrap();
        reader.get_mut().write_all(&payload).await.unwrap();
        proxy_header
    });

    PlainBackend { addr, header }
}

struct TlsBackend {
    addr: std::net::SocketAddr,
    cert_pem: String,
    _task: tokio::task::JoinHandle<()>,
}

async fn spawn_tls_echo_backend(name: &str) -> TlsBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cert = generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let acceptor = TlsAcceptor::from(Arc::new(server_rustls_config(&cert_pem, &key_pem)));

    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut buf = [0_u8; 9];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    TlsBackend {
        addr,
        cert_pem,
        _task: task,
    }
}

async fn spawn_tcp_proxy(
    tcp_mode: &str,
    tcp_listen: Option<String>,
    routes: String,
    tls_material: Option<(String, String, String)>,
) -> TcpTestRuntime {
    let tempdir = TempDir::new().unwrap();
    let http_port = free_port().await;
    let admin_port = free_port().await;

    let routes_path = tempdir.path().join("routes.txt");
    std::fs::write(&routes_path, routes).unwrap();

    let tls_block = if let Some((cert_pem, key_pem, listen)) = tls_material {
        let cert_path = tempdir.path().join("proxy-cert.pem");
        let key_path = tempdir.path().join("proxy-key.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        format!(
            "[tls]\nsource = \"file\"\ncert_path = \"{}\"\nkey_path = \"{}\"\nlisten = \"{}\"\n",
            cert_path.display(),
            key_path.display(),
            listen,
        )
    } else {
        String::from("[tls]\nsource = \"\"\ncert_path = \"\"\nkey_path = \"\"\nlisten = \"\"\n")
    };

    let tcp_listen_line = tcp_listen
        .map(|listen| format!("listen = \"{listen}\"\n"))
        .unwrap_or_default();

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
pool_size = 128
max_connections = 10000

[logging]
level = "warn"
format = "text"

{tls_block}
[tcp]
mode = "{tcp_mode}"
{tcp_listen_line}refresh = "1s"
"#,
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_sentirum-lb"))
        .arg("--config")
        .arg(&config_path)
        .arg("--routes")
        .arg(&routes_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    wait_for_ready(http_port).await;

    TcpTestRuntime {
        _tempdir: tempdir,
        child,
    }
}

async fn wait_for_ready(http_port: u16) {
    let client = reqwest::Client::new();
    for _ in 0..60 {
        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{http_port}/health"))
            .send()
            .await
        {
            if resp.status().is_success() {
                return;
            }
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

fn server_rustls_config(cert_pem: &str, key_pem: &str) -> RustlsServerConfig {
    let certs = load_certs(cert_pem);
    let key = load_private_key(key_pem);
    RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap()
}

fn load_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn load_private_key(pem: &str) -> PrivateKeyDer<'static> {
    let mut cursor = Cursor::new(pem);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut cursor);
    let key = keys.next().unwrap().unwrap();
    PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec()))
}

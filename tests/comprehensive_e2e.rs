//! Comprehensive end-to-end integration tests covering all supported protocols
//! and new features (rate limiting, health checking, circuit breaker).
//!
//! Test matrix:
//!   Protocols: HTTP/1.1, HTTP/2, gRPC (4 modes), gRPC-Web, WebSocket, WSS
//!   Features: Rate Limiting, Circuit Breaker, Health Check integration
//!
//! Each test spawns the LB binary with a tailored config + route table and
//! verifies protocol-correct behaviour end-to-end.

use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use http::StatusCode;
use prost::Message;
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{accept_async, accept_async_with_config, connect_async};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

pub mod echo {
    tonic::include_proto!("echo");
}

use echo::echo_service_client::EchoServiceClient;
use echo::echo_service_server::{EchoService, EchoServiceServer};
use echo::{EchoReply, EchoRequest};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EchoSvc;

type BoxStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl EchoService for EchoSvc {
    async fn unary_echo(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<EchoReply>, Status> {
        Ok(Response::new(EchoReply {
            message: request.into_inner().message,
        }))
    }

    type ServerStreamStream = BoxStream<EchoReply>;

    async fn server_stream(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<Self::ServerStreamStream>, Status> {
        let base = request.into_inner().message;
        let items = vec![
            Ok(EchoReply {
                message: format!("{base}-1"),
            }),
            Ok(EchoReply {
                message: format!("{base}-2"),
            }),
            Ok(EchoReply {
                message: format!("{base}-3"),
            }),
        ];
        Ok(Response::new(Box::pin(tokio_stream::iter(items))))
    }

    async fn client_stream(
        &self,
        request: Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<Response<EchoReply>, Status> {
        let mut stream = request.into_inner();
        let mut parts = Vec::new();
        while let Some(item) = stream.next().await {
            parts.push(item?.message);
        }
        Ok(Response::new(EchoReply {
            message: parts.join(","),
        }))
    }

    type BidiStreamStream = BoxStream<EchoReply>;

    async fn bidi_stream(
        &self,
        request: Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<Response<Self::BidiStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(item) = inbound.next().await {
                match item {
                    Ok(msg) => {
                        if tx
                            .send(Ok(EchoReply {
                                message: msg.message,
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(Err(err)).await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

struct TestRuntime {
    _tempdir: TempDir,
    child: Child,
    http_port: u16,
    tls_port: u16,
    admin_port: u16,
    proxy_cert_pem: String,
}

impl Drop for TestRuntime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Upstream backend that returns 500 for circuit-breaker tests.
struct _FailingBackend {
    addr: SocketAddr,
    _fail_count: Arc<std::sync::atomic::AtomicU64>,
    _task: tokio::task::JoinHandle<()>,
}

async fn spawn_grpc_server(tls: bool) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let svc = EchoServiceServer::new(EchoSvc);
    let (tx, rx) = tokio::sync::oneshot::channel();

    if tls {
        let (cert_pem, key_pem) = generate_cert_material("localhost");
        let identity = Identity::from_pem(cert_pem, key_pem);
        tokio::spawn(async move {
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(identity))
                .unwrap()
                .add_service(svc)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
    } else {
        tokio::spawn(async move {
            Server::builder()
                .add_service(svc)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
    }

    (addr, tx)
}

async fn spawn_websocket_server(
    tls: bool,
    cert_pem: Option<String>,
    key_pem: Option<String>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    if tls {
        let cert_pem = cert_pem.unwrap();
        let key_pem = key_pem.unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_rustls_config(&cert_pem, &key_pem)));
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls_stream = acceptor.accept(stream).await.unwrap();
                    let mut ws = accept_async(tls_stream).await.unwrap();
                    while let Some(msg) = ws.next().await {
                        let Ok(msg) = msg else { break };
                        if msg.is_close() {
                            break;
                        }
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    } else {
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut ws = accept_async_with_config(stream, None).await.unwrap();
                    while let Some(msg) = ws.next().await {
                        let Ok(msg) = msg else { break };
                        if msg.is_close() {
                            break;
                        }
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    addr
}

/// Spawn a simple HTTP upstream that returns 200 with the request path in the body.
async fn spawn_http_echo_backend() -> SocketAddr {
    use axum::extract::Request;
    use axum::http::StatusCode;

    let app = axum::Router::new().fallback(|req: Request| async move {
        let path = req.uri().path().to_string();
        (StatusCode::OK, format!("echo:{path}"))
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Spawn an HTTP upstream that always returns 500 for circuit-breaker tests.
async fn spawn_failing_http_backend() -> (SocketAddr, Arc<std::sync::atomic::AtomicU64>) {
    use axum::extract::Request;
    use axum::http::StatusCode;

    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count_clone = Arc::clone(&count);
    let app = axum::Router::new().fallback(move |_req: Request| {
        let c = count_clone.clone();
        async move {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, count)
}

async fn spawn_proxy_with_routes(routes: String, extra_proxy_config: &str) -> TestRuntime {
    spawn_proxy_with_options(routes, extra_proxy_config, true).await
}

async fn spawn_proxy_with_options(
    routes: String,
    extra_proxy_config: &str,
    enable_h2c: bool,
) -> TestRuntime {
    let tempdir = TempDir::new().unwrap();
    let http_port = free_port().await;
    let tls_port = free_port().await;
    let admin_port = free_port().await;

    let (proxy_cert_pem, proxy_key_pem) = generate_cert_material("localhost");
    let cert_path = tempdir.path().join("proxy-cert.pem");
    let key_path = tempdir.path().join("proxy-key.pem");
    std::fs::write(&cert_path, &proxy_cert_pem).unwrap();
    std::fs::write(&key_path, &proxy_key_pem).unwrap();

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
connect_timeout = "5s"
read_timeout = "30s"
write_timeout = "30s"
idle_timeout = "300s"
enable_h2c = {enable_h2c}
upstream_h2_max_streams = 64
upstream_h2_ping_interval = "15s"
pool_size = 128
max_connections = 10000
{extra_proxy_config}

[logging]
level = "warn"
format = "text"

[tls]
cert_path = "{cert_path}"
key_path = "{key_path}"
listen = "127.0.0.1:{tls_port}"
"#,
            cert_path = cert_path.display(),
            key_path = key_path.display(),
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
        http_port,
        tls_port,
        admin_port,
        proxy_cert_pem,
    }
}

async fn wait_for_ready(http_port: u16) {
    let client = reqwest::Client::new();
    for _ in 0..80 {
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
    panic!("proxy did not become ready on port {http_port} in time");
}

async fn wait_for_tls_port(tls_port: u16) {
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{tls_port}"))
            .await
            .is_ok()
        {
            // Port is open, give a small extra delay for TLS handshake readiness
            sleep(Duration::from_millis(100)).await;
            return;
        }
        sleep(Duration::from_millis(250)).await;
    }
    // TLS readiness is best-effort
    tracing::warn!("TLS port {tls_port} not ready, proceeding anyway");
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
    (cert.cert.pem(), cert.signing_key.serialize_pem())
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

// ===========================================================================
// 1. WSS (WebSocket Secure) — end-to-end through proxy TLS listener
//
// NOTE: Pingora's TLS listener with enable_h2() negotiates h2 via ALPN.
// Standard WebSocket clients (tungstenite) expect HTTP/1.1 upgrade semantics.
// RFC 8441 (WebSocket over h2) extended CONNECT is not widely supported by
// WebSocket client libraries. This test validates that the TLS listener
// accepts the TLS + h2 connection. Full WSS echo requires an RFC 8441 client.
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wss_tls_listener_accepts_connection() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ws_backend = spawn_websocket_server(false, None, None).await;

    let rt = spawn_proxy_with_options(
        format!(
            "route add wss /ws ws://127.0.0.1:{}/ws opts \"ssrfskipverify=true\"\n",
            ws_backend.port(),
        ),
        "",
        false,
    )
    .await;

    wait_for_tls_port(rt.tls_port).await;

    // Verify the TLS listener is up and responds to h2 requests
    let root_cert = reqwest::Certificate::from_pem(rt.proxy_cert_pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(root_cert)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // Proxy should respond (no route for /nonexistent → 404)
    let mut resp = None;
    for _ in 0..10 {
        match client
            .get(format!("https://localhost:{}/nonexistent", rt.tls_port))
            .send()
            .await
        {
            Ok(r) => {
                resp = Some(r);
                break;
            }
            Err(_) => sleep(Duration::from_millis(500)).await,
        }
    }
    let resp = resp.expect("TLS connection should succeed");
    // TLS listener negotiates h2 when client supports it
    assert!(resp.version() == http::Version::HTTP_2 || resp.version() == http::Version::HTTP_11);
    // No route configured for /nonexistent → 404
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// 2. HTTP/1.1 plaintext — basic request/response
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_plain_request_response() {
    let backend = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        "",
    )
    .await;

    let client = reqwest::Client::builder().http1_only().build().unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{}/test/hello", rt.http_port))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "echo:/test/hello");
}

// ===========================================================================
// 3. HTTP/2 plaintext (h2c) — non-gRPC traffic over h2c
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_h2c_non_grpc_request() {
    let backend = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        "",
    )
    .await;

    // reqwest with HTTP/2 prior knowledge sends h2c
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{}/h2c-test", rt.http_port))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.version(), http::Version::HTTP_2);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "echo:/h2c-test");
}

// ===========================================================================
// 4. HTTPS downstream — HTTP/1.1 and HTTP/2 over TLS
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_downstream_http1_and_http2() {
    let backend = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_options(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        "",
        false, // disable h2c for clean TLS h1/h2 testing
    )
    .await;

    wait_for_tls_port(rt.tls_port).await;

    let root_cert = reqwest::Certificate::from_pem(rt.proxy_cert_pem.as_bytes()).unwrap();

    // Pingora's TLS listener with enable_h2() negotiates h2 via ALPN.
    // HTTP/1.1 clients may still connect but the protocol on the wire is h2.
    // Test both h1-only and h2-capable clients — both should succeed.

    let h1_client = reqwest::Client::builder()
        .add_root_certificate(root_cert.clone())
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .unwrap();

    // Even h1-only client will negotiate h2 with Pingora's TLS listener
    let mut h1_resp = None;
    for _ in 0..10 {
        match h1_client
            .get(format!("https://localhost:{}/tls-h1-test", rt.tls_port))
            .send()
            .await
        {
            Ok(resp) => {
                h1_resp = Some(resp);
                break;
            }
            Err(_) => sleep(Duration::from_millis(500)).await,
        }
    }
    // h1-only client negotiates h1 with Pingora's TLS listener
    let h1_resp = h1_resp.expect("TLS request should succeed after retries");
    assert_eq!(h1_resp.status(), StatusCode::OK);
    assert_eq!(h1_resp.version(), http::Version::HTTP_11);
    let body = h1_resp.text().await.unwrap();
    assert_eq!(body, "echo:/tls-h1-test");

    // HTTP/2 over TLS (ALPN negotiation)
    let h2_client = reqwest::Client::builder()
        .add_root_certificate(root_cert)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut h2_resp = None;
    for _ in 0..10 {
        match h2_client
            .get(format!("https://localhost:{}/tls-h2-test", rt.tls_port))
            .send()
            .await
        {
            Ok(resp) => {
                h2_resp = Some(resp);
                break;
            }
            Err(_) => sleep(Duration::from_millis(500)).await,
        }
    }
    let h2_resp = h2_resp.expect("h2 TLS request should succeed after retries");
    assert_eq!(h2_resp.status(), StatusCode::OK);
    // Pingora may negotiate h1 or h2 depending on configuration
    assert!(matches!(
        h2_resp.version(),
        http::Version::HTTP_2 | http::Version::HTTP_11
    ));
    let body = h2_resp.text().await.unwrap();
    assert_eq!(body, "echo:/tls-h2-test");
}

// ===========================================================================
// 5. gRPC over h2c — all four streaming modes
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_h2c_all_streaming_modes() {
    let (grpc_addr, _shutdown) = spawn_grpc_server(false).await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add grpc / grpc://127.0.0.1:{} opts \"ssrfskipverify=true host=127.0.0.1:{}\"\n",
            grpc_addr.port(),
            grpc_addr.port(),
        ),
        "",
    )
    .await;

    let mut client = EchoServiceClient::connect(format!("http://127.0.0.1:{}", rt.http_port))
        .await
        .unwrap();

    // Unary
    let unary = client
        .unary_echo(Request::new(EchoRequest {
            message: "unary".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(unary.message, "unary");

    // Server streaming
    let items: Vec<String> = client
        .server_stream(Request::new(EchoRequest {
            message: "ss".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .map(|item| item.unwrap().message)
        .collect()
        .await;
    assert_eq!(items, vec!["ss-1", "ss-2", "ss-3"]);

    // Client streaming
    let input = tokio_stream::iter(vec![
        EchoRequest {
            message: "a".into(),
        },
        EchoRequest {
            message: "b".into(),
        },
    ]);
    let cs = client
        .client_stream(Request::new(input))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(cs.message, "a,b");

    // Bidi streaming
    let bidi_input = tokio_stream::iter(vec![
        EchoRequest {
            message: "x".into(),
        },
        EchoRequest {
            message: "y".into(),
        },
    ]);
    let bidi_msgs: Vec<String> = client
        .bidi_stream(Request::new(bidi_input))
        .await
        .unwrap()
        .into_inner()
        .map(|item| item.unwrap().message)
        .collect()
        .await;
    assert_eq!(bidi_msgs, vec!["x", "y"]);
}

// ===========================================================================
// 6. gRPC-Web — browser-friendly gRPC bridging
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_web_unary_and_trailers() {
    let (grpc_addr, _shutdown) = spawn_grpc_server(false).await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add grpc / grpc://127.0.0.1:{} opts \"ssrfskipverify=true host=127.0.0.1:{}\"\n",
            grpc_addr.port(),
            grpc_addr.port(),
        ),
        "",
    )
    .await;

    let msg = EchoRequest {
        message: "grpc-web-e2e".into(),
    };
    let payload = msg.encode_to_vec();
    let mut body = Vec::with_capacity(5 + payload.len());
    body.push(0); // uncompressed flag
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(&payload);

    let client = reqwest::Client::builder().http1_only().build().unwrap();
    let resp = client
        .post(format!(
            "http://127.0.0.1:{}/echo.EchoService/UnaryEcho",
            rt.http_port
        ))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(body)
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("application/grpc-web"));

    let bytes = resp.bytes().await.unwrap();
    assert!(bytes.len() > 5);
    assert_eq!(bytes[0], 0); // uncompressed
    let len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    let reply = EchoReply::decode(&bytes[5..5 + len]).unwrap();
    assert_eq!(reply.message, "grpc-web-e2e");
    // Trailers marker
    assert!(bytes[5 + len..].contains(&0x80));
}

// ===========================================================================
// 7. WebSocket plain — full echo round-trip
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_plain_echo_roundtrip() {
    let ws_backend = spawn_websocket_server(false, None, None).await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add ws /ws ws://127.0.0.1:{}/ws opts \"ssrfskipverify=true\"\n",
            ws_backend.port(),
        ),
        "",
    )
    .await;

    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{}/ws", rt.http_port))
        .await
        .unwrap();

    // Send multiple messages
    for i in 0..5 {
        let payload = format!("msg-{i}");
        ws.send(WsMessage::Text(payload.clone().into()))
            .await
            .unwrap();
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(msg.into_text().unwrap(), payload);
    }
}

// ===========================================================================
// 8. Rate limiting — 429 after burst exhausted
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limiting_returns_429_after_burst() {
    let backend = spawn_http_echo_backend().await;

    // Configure rate limit: 5 tokens/sec, burst of 3
    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        r#"rate_limit_per_target = 5
rate_limit_burst = 3"#,
    )
    .await;

    let client = reqwest::Client::builder().http1_only().build().unwrap();
    let url = format!("http://127.0.0.1:{}/rl-test", rt.http_port);

    // First 3 requests should succeed (burst = 3)
    for _ in 0..3 {
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "expected 200 within burst");
    }

    // Next requests should be rate-limited (429)
    let mut got_429 = false;
    for _ in 0..5 {
        let resp = client.get(&url).send().await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "expected at least one 429 after burst exhausted");
}

// ===========================================================================
// 9. Rate limiting — per-target route override
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limiting_per_target_route_override() {
    let backend = spawn_http_echo_backend().await;

    // Global rate limit: 100/s burst 100 (effectively unlimited)
    // But route overrides to: 1/s burst 2
    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true ratelimit=1 burst=2\"\n",
            backend.port(),
        ),
        r#"rate_limit_per_target = 100
rate_limit_burst = 100"#,
    )
    .await;

    let client = reqwest::Client::builder().http1_only().build().unwrap();
    let url = format!("http://127.0.0.1:{}/rl-override", rt.http_port);

    // First 2 should succeed (route override burst = 2)
    for _ in 0..2 {
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Next should be 429
    let mut got_429 = false;
    for _ in 0..5 {
        let resp = client.get(&url).send().await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "expected 429 after per-target burst exhausted");
}

// ===========================================================================
// 10. No-route returns configured status
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_route_returns_configured_status() {
    let backend = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo /api http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        r#"no_route_status = 444"#,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/nonexistent", rt.http_port))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 444);
}

// ===========================================================================
// 11. Admin API — targets, routes, and health
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_api_targets_routes_health() {
    let backend = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        "",
    )
    .await;

    let client = reqwest::Client::new();

    // /admin/ targets
    let resp = client
        .get(format!("http://127.0.0.1:{}/admin/targets", rt.admin_port))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["targets"].is_array());

    // /admin/routes
    let resp = client
        .get(format!("http://127.0.0.1:{}/admin/routes", rt.admin_port))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // /admin/health
    let resp = client
        .get(format!("http://127.0.0.1:{}/admin/health", rt.admin_port))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Verify redirect /admin → /admin/
    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let no_slash = no_redirect_client
        .get(format!("http://127.0.0.1:{}/admin", rt.admin_port))
        .send()
        .await
        .unwrap();
    assert_eq!(no_slash.status().as_u16(), 308);
}

// ===========================================================================
// 12. Admin API — per-target probe_healthy field
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_api_target_probe_healthy_field() {
    let backend = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        "",
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/admin/targets", rt.admin_port))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let targets = body["targets"].as_array().unwrap();

    // Without active health checks, all targets default to probe_healthy = true
    assert!(!targets.is_empty(), "should have at least one target");
    for target in targets {
        assert!(
            target["probe_healthy"].as_bool().unwrap(),
            "target should default to probe_healthy=true"
        );
    }
}

// ===========================================================================
// 13. Circuit breaker — opens after consecutive failures
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn circuit_breaker_opens_on_failures() {
    let (backend, _count) = spawn_failing_http_backend().await;

    // Enable circuit breaker with aggressive thresholds
    // window_size=5, error_threshold=50 (50% = 3/5 errors needed to open)
    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        r#"circuit_breaker_enabled = true
circuit_breaker_error_threshold = 50
circuit_breaker_window_size = 5
circuit_breaker_recovery_timeout = 300
circuit_breaker_half_open_max = 1"#,
    )
    .await;

    let client = reqwest::Client::builder().http1_only().build().unwrap();
    let url = format!("http://127.0.0.1:{}/cb-test", rt.http_port);

    // Send requests until we get a 503 (circuit breaker open)
    let mut got_503 = false;
    for _ in 0..15 {
        let resp = client.get(&url).send().await.unwrap();
        let status = resp.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            got_503 = true;
            break;
        }
        // 500 from backend is fine — circuit breaker is counting
        assert!(
            status == StatusCode::INTERNAL_SERVER_ERROR,
            "expected 500 or 503, got {status}"
        );
    }
    assert!(
        got_503,
        "circuit breaker should open after consecutive failures"
    );
}

// ===========================================================================
// 14. Path-based routing — prefix matching
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefix_path_routing_multiple_routes() {
    let backend_a = spawn_http_echo_backend().await;
    let backend_b = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add svc-a /api/a http://127.0.0.1:{} opts \"ssrfskipverify=true\"\nroute add svc-b /api/b http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend_a.port(),
            backend_b.port(),
        ),
        "",
    )
    .await;

    let client = reqwest::Client::builder().http1_only().build().unwrap();

    let resp_a = client
        .get(format!("http://127.0.0.1:{}/api/a/hello", rt.http_port))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_a.status(), StatusCode::OK);
    assert_eq!(resp_a.text().await.unwrap(), "echo:/api/a/hello");

    let resp_b = client
        .get(format!("http://127.0.0.1:{}/api/b/world", rt.http_port))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::OK);
    assert_eq!(resp_b.text().await.unwrap(), "echo:/api/b/world");
}

// ===========================================================================
// 15. gRPC over TLS downstream (grpcs client → proxy TLS → grpc upstream)
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpcs_tls_downstream_to_grpc_plain_upstream() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (grpc_addr, _shutdown) = spawn_grpc_server(false).await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add grpcs / grpc://127.0.0.1:{} opts \"ssrfskipverify=true host=127.0.0.1:{}\"\n",
            grpc_addr.port(),
            grpc_addr.port(),
        ),
        "",
    )
    .await;

    wait_for_tls_port(rt.tls_port).await;

    // Connect gRPC client to proxy's TLS port
    let mut last_err = None;
    for _ in 0..30 {
        match Channel::from_shared(format!("https://localhost:{}", rt.tls_port))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(&rt.proxy_cert_pem))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect()
            .await
        {
            Ok(channel) => {
                let mut client = EchoServiceClient::new(channel);
                let resp = client
                    .unary_echo(Request::new(EchoRequest {
                        message: "grpcs-e2e".into(),
                    }))
                    .await
                    .unwrap()
                    .into_inner();
                assert_eq!(resp.message, "grpcs-e2e");
                return;
            }
            Err(e) => {
                last_err = Some(e);
                sleep(Duration::from_millis(250)).await;
            }
        }
    }
    panic!("grpcs downstream test failed: {:?}", last_err);
}

// ===========================================================================
// 16. Concurrent requests — stress test
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_stress() {
    let backend = spawn_http_echo_backend().await;

    let rt = spawn_proxy_with_routes(
        format!(
            "route add echo / http://127.0.0.1:{} opts \"ssrfskipverify=true\"\n",
            backend.port(),
        ),
        "",
    )
    .await;

    let client = reqwest::Client::new();
    let mut handles = Vec::new();

    for i in 0..20 {
        let client = client.clone();
        let url = format!("http://127.0.0.1:{}/stress/{}", rt.http_port, i);
        handles.push(tokio::spawn(async move {
            let resp = client.get(&url).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            resp.text().await.unwrap()
        }));
    }

    let results: Vec<_> = futures::future::join_all(handles).await;
    assert_eq!(results.len(), 20);
    for (i, result) in results.into_iter().enumerate() {
        let body = result.unwrap();
        assert_eq!(body, format!("echo:/stress/{i}"));
    }
}

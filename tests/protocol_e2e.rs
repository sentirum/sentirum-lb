use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use prost::Message;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
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

#[derive(Default)]
struct EchoSvc;

type BoxStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl EchoService for EchoSvc {
    async fn unary_echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoReply>, Status> {
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
            Ok(EchoReply { message: format!("{base}-1") }),
            Ok(EchoReply { message: format!("{base}-2") }),
            Ok(EchoReply { message: format!("{base}-3") }),
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
                        if tx.send(Ok(EchoReply { message: msg.message })).await.is_err() {
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
    proxy_cert_pem: String,
}

impl Drop for TestRuntime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "end-to-end protocol smoke test"]
async fn protocol_end_to_end_smoke() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let grpc_plain = spawn_grpc_server(false).await;
    let ws_plain = spawn_websocket_server(false).await;

    let plain_runtime = spawn_proxy(
        format!(
            "route add grpc / grpc://127.0.0.1:{grpc}/ opts \"ssrfskipverify=true host=127.0.0.1:{grpc}\"\nroute add ws /ws ws://127.0.0.1:{ws}/ws opts \"ssrfskipverify=true\"\n",
            grpc = grpc_plain.addr.port(),
            ws = ws_plain.addr.port(),
        ),
    )
    .await;

    run_grpc_h2c_checks(plain_runtime.http_port).await;
    run_grpc_web_check(plain_runtime.http_port).await;
    run_ws_check(plain_runtime.http_port).await;
    drop(plain_runtime);

    let grpc_secure_upstream = spawn_grpc_server(false).await;
    let ws_secure_upstream = spawn_websocket_server(false).await;

    let secure_runtime = spawn_proxy(
        format!(
            "route add grpcs / grpc://127.0.0.1:{}/ opts \"ssrfskipverify=true\"\nroute add wss /wss ws://127.0.0.1:{}/wss opts \"ssrfskipverify=true\"\n",
            grpc_secure_upstream.addr.port(),
            ws_secure_upstream.addr.port(),
        ),
    )
    .await;

    run_grpcs_checks(secure_runtime.tls_port, &secure_runtime.proxy_cert_pem).await;
}

struct SpawnedGrpc {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn spawn_grpc_server(tls: bool) -> SpawnedGrpc {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
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

    SpawnedGrpc { addr, _shutdown: tx }
}

struct SpawnedWs {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn spawn_websocket_server(tls: bool) -> SpawnedWs {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

    if tls {
        let (cert_pem, key_pem) = generate_cert_material("localhost");
        let acceptor = TlsAcceptor::from(Arc::new(server_rustls_config(&cert_pem, &key_pem)));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept = listener.accept() => {
                        let (stream, _) = accept.unwrap();
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let tls_stream = acceptor.accept(stream).await.unwrap();
                            let mut ws = accept_async(tls_stream).await.unwrap();
                            while let Some(msg) = ws.next().await {
                                let Ok(msg) = msg else { break; };
                                if msg.is_close() {
                                    break;
                                }
                                if ws.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                }
            }
        });
    } else {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept = listener.accept() => {
                        let (stream, _) = accept.unwrap();
                        tokio::spawn(async move {
                            let mut ws = accept_async_with_config(stream, None).await.unwrap();
                            while let Some(msg) = ws.next().await {
                                let Ok(msg) = msg else { break; };
                                if msg.is_close() {
                                    break;
                                }
                                if ws.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                }
            }
        });
    }

    SpawnedWs { addr, _shutdown: tx }
}

async fn spawn_proxy(routes: String) -> TestRuntime {
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
no_route_status = 404
connect_timeout = "5s"
read_timeout = "30s"
write_timeout = "30s"
idle_timeout = "300s"
enable_h2c = true
upstream_h2_max_streams = 64
upstream_h2_ping_interval = "15s"
pool_size = 128
max_connections = 10000

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
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    wait_for_ready(http_port).await;

    TestRuntime {
        _tempdir: tempdir,
        child,
        http_port,
        tls_port,
        proxy_cert_pem,
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


async fn run_grpc_h2c_checks(http_port: u16) {
    let mut client = EchoServiceClient::connect(format!("http://127.0.0.1:{http_port}"))
        .await
        .unwrap();

    let unary = client
        .unary_echo(Request::new(EchoRequest {
            message: "hello-h2c".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(unary.message, "hello-h2c");

    let items = client
        .server_stream(Request::new(EchoRequest {
            message: "stream".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .map(|item| item.unwrap().message)
        .collect::<Vec<_>>()
        .await;
    assert_eq!(items, vec!["stream-1", "stream-2", "stream-3"]);

    let input = tokio_stream::iter(vec![
        EchoRequest { message: "a".into() },
        EchoRequest { message: "b".into() },
        EchoRequest { message: "c".into() },
    ]);
    let client_stream = client.client_stream(Request::new(input)).await.unwrap().into_inner();
    assert_eq!(client_stream.message, "a,b,c");

    let bidi_input = tokio_stream::iter(vec![
        EchoRequest { message: "x".into() },
        EchoRequest { message: "y".into() },
    ]);
    let bidi = client.bidi_stream(Request::new(bidi_input)).await.unwrap().into_inner();
    let messages = bidi.map(|item| item.unwrap().message).collect::<Vec<_>>().await;
    assert_eq!(messages, vec!["x", "y"]);
}

async fn run_grpcs_checks(tls_port: u16, proxy_cert_pem: &str) {
    let mut last_err = None;
    for _ in 0..20 {
        match Channel::from_shared(format!("https://localhost:{tls_port}"))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(proxy_cert_pem))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect()
            .await
        {
            Ok(channel) => {
                let mut client = EchoServiceClient::new(channel);
                let unary = client
                    .unary_echo(Request::new(EchoRequest {
                        message: "hello-grpcs".into(),
                    }))
                    .await
                    .unwrap()
                    .into_inner();
                assert_eq!(unary.message, "hello-grpcs");
                return;
            }
            Err(err) => {
                last_err = Some(err);
                sleep(Duration::from_millis(250)).await;
            }
        }
    }
    panic!("grpcs check failed: {:?}", last_err);
}

async fn run_grpc_web_check(http_port: u16) {
    let mut body = Vec::new();
    let msg = EchoRequest {
        message: "grpc-web".into(),
    };
    let payload = msg.encode_to_vec();
    body.push(0);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(&payload);

    let resp = reqwest::Client::builder()
        .http1_only()
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{http_port}/echo.EchoService/UnaryEcho"))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(body)
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());
    let content_type = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(content_type.starts_with("application/grpc-web"));

    let bytes = resp.bytes().await.unwrap();
    assert!(bytes.len() > 5);
    assert_eq!(bytes[0], 0);
    let len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    let reply = EchoReply::decode(&bytes[5..5 + len]).unwrap();
    assert_eq!(reply.message, "grpc-web");
    assert!(bytes[5 + len..].contains(&0x80));
}

async fn run_ws_check(http_port: u16) {
    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{http_port}/ws"))
        .await
        .unwrap();
    ws.send(WsMessage::Text("ping".into())).await.unwrap();
    let msg = ws.next().await.unwrap().unwrap();
    assert_eq!(msg.into_text().unwrap(), "ping");
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
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    (cert_pem, key_pem)
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

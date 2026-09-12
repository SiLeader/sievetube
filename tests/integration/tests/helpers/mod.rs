// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub type TestBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Allocate an available TCP port by binding to port 0.
pub fn find_free_port() -> u16 {
    let l = StdTcpListener::bind("127.0.0.1:0").expect("bind port 0");
    l.local_addr().unwrap().port()
}

/// Compute workspace root from this crate's manifest dir (../../).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// Path to a compiled binary in target/debug.
fn binary(name: &str) -> PathBuf {
    workspace_root().join("target").join("debug").join(format!(
        "{}{}",
        name,
        std::env::consts::EXE_SUFFIX
    ))
}

/// Generate a unique suffix for temp files.
pub fn unique_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Create a fresh temporary directory.
pub fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sievetube-{prefix}-{}", unique_id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Generate a signed JWT for testing.
pub fn make_jwt(secret: &str, sub: &str, hostnames: &[&str]) -> String {
    use sievetube_common::auth::{sign_jwt, TunnelClaims};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = TunnelClaims {
        sub: sub.to_string(),
        hostnames: hostnames.iter().map(|s| s.to_string()).collect(),
        exp: now + 3600,
        iat: now,
    };
    sign_jwt(&claims, secret.as_bytes()).expect("sign_jwt failed")
}

/// Edge configuration builder for tests. Ports are allocated on creation.
pub struct EdgeTestConfig {
    pub quic_port: u16,
    pub http_port: u16,
    pub https_port: u16,
    pub health_port: u16,
    pub jwt_secret: String,
    pub tcp_listeners: Vec<(u16, String)>,
    pub udp_listeners: Vec<(u16, String)>,
    pub cert_dir: String,
    /// Additional TOML appended verbatim (e.g. `[policy]` sections)
    pub extra: String,
    /// Top-level keys written before any table (e.g. `config_version`)
    pub prefix: String,
    /// Certificate and key presented to Connectors
    pub quic_cert: Option<(PathBuf, PathBuf)>,
}

impl EdgeTestConfig {
    pub fn new(jwt_secret: &str) -> Self {
        EdgeTestConfig {
            quic_port: find_free_port(),
            http_port: find_free_port(),
            https_port: find_free_port(),
            health_port: find_free_port(),
            jwt_secret: jwt_secret.to_string(),
            tcp_listeners: Vec::new(),
            udp_listeners: Vec::new(),
            cert_dir: "/nonexistent/test-certs".to_string(),
            extra: String::new(),
            prefix: String::new(),
            quic_cert: None,
        }
    }

    pub fn quic_addr(&self) -> String {
        format!("127.0.0.1:{}", self.quic_port)
    }

    pub fn write(&self) -> PathBuf {
        let path = std::env::temp_dir().join(format!("sievetube-edge-{}.toml", unique_id()));
        self.write_to(&path);
        path
    }

    /// (Re)write the configuration to an existing path, e.g. before SIGHUP.
    pub fn write_to(&self, path: &Path) {
        let mut listeners = String::new();
        for (port, hostname) in &self.tcp_listeners {
            listeners.push_str(&format!(
                "\n[[server.tcp_listen]]\naddr = \"127.0.0.1:{port}\"\nhostname = \"{hostname}\"\n"
            ));
        }
        for (port, hostname) in &self.udp_listeners {
            listeners.push_str(&format!(
                "\n[[server.udp_listen]]\naddr = \"127.0.0.1:{port}\"\nhostname = \"{hostname}\"\n"
            ));
        }
        let content = format!(
            r#"{prefix}
[server]
quic_listen = "127.0.0.1:{quic}"
{quic_cert}
http_listen = "127.0.0.1:{http}"
https_listen = "127.0.0.1:{https}"
health_listen = "127.0.0.1:{health}"
drain_timeout_secs = 1
{listeners}
[auth]
jwt_secret = "{secret}"

[tls]
cert_dir = "{cert_dir}"
reload_interval_secs = 1

{extra}
"#,
            quic = self.quic_port,
            http = self.http_port,
            https = self.https_port,
            health = self.health_port,
            secret = self.jwt_secret,
            cert_dir = self.cert_dir,
            extra = self.extra,
            prefix = self.prefix,
            quic_cert = match &self.quic_cert {
                Some((cert, key)) => format!(
                    "quic_cert = \"{}\"\nquic_key = \"{}\"",
                    cert.display(),
                    key.display()
                ),
                None => String::new(),
            },
        );
        std::fs::write(path, content).expect("write edge config");
    }
}

/// Fetch the Prometheus exposition from the health server.
pub async fn metrics(health_port: u16) -> String {
    health_get(health_port, "/metrics")
        .await
        .map(|(_, body)| body)
        .unwrap_or_default()
}

/// Start an edge from `edge` and one connector with explicit ingress rules.
/// Returns (edge config path, edge process, connector process).
pub async fn start_tunnel(
    edge: &EdgeTestConfig,
    tenant: &str,
    hostnames: &[&str],
    ingress: &[(&str, &str, &str)],
) -> (PathBuf, ProcessGuard, ProcessGuard) {
    let edge_cfg = edge.write();
    let jwt = make_jwt(&edge.jwt_secret, tenant, hostnames);
    let conn_cfg = write_connector_config(&jwt, &edge.quic_addr(), ingress);
    let edge_process = start_edge(&edge_cfg).await;
    wait_for_health(edge.health_port).await;
    let connector_process = start_connector(&conn_cfg).await;
    wait_for_connectors(edge.health_port, 1).await;
    (edge_cfg, edge_process, connector_process)
}

/// Write an edge config to a temp file.
/// `tcp_listeners` is a list of (listen_port, hostname) for raw TCP tunnels.
pub fn write_edge_config(
    quic_port: u16,
    http_port: u16,
    health_port: u16,
    jwt_secret: &str,
    tcp_listeners: &[(u16, &str)],
) -> PathBuf {
    let mut cfg = EdgeTestConfig::new(jwt_secret);
    cfg.quic_port = quic_port;
    cfg.http_port = http_port;
    cfg.health_port = health_port;
    cfg.tcp_listeners = tcp_listeners
        .iter()
        .map(|(port, hostname)| (*port, hostname.to_string()))
        .collect();
    cfg.write()
}

/// Write a connector config to a temp file.
/// `ingress` entries: (hostname, protocol, target_addr).
pub fn write_connector_config(
    jwt: &str,
    quic_addr: &str,
    ingress: &[(&str, &str, &str)],
) -> PathBuf {
    write_connector_config_multi(jwt, &[quic_addr], ingress)
}

/// Connector config connecting to several Edges.
pub fn write_connector_config_multi(
    jwt: &str,
    quic_addrs: &[&str],
    ingress: &[(&str, &str, &str)],
) -> PathBuf {
    write_connector_config_with_network(jwt, quic_addrs, ingress, "")
}

/// Connector config with extra `[network]` keys (e.g. edge certificate verification).
pub fn write_connector_config_with_network(
    jwt: &str,
    quic_addrs: &[&str],
    ingress: &[(&str, &str, &str)],
    network_extra: &str,
) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sievetube-connector-{}.toml", unique_id()));

    let mut ingress_toml = String::new();
    for (hostname, protocol, target) in ingress {
        ingress_toml.push_str(&format!(
            "\n[[ingress]]\nhostname = \"{hostname}\"\nprotocol = \"{protocol}\"\ntarget = \"{target}\"\n"
        ));
    }
    // Catch-all
    ingress_toml.push_str("\n[[ingress]]\ntarget = \"http_status:404\"\n");

    let servers = quic_addrs
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let content = format!(
        r#"[auth]
token = "{jwt}"

[network]
public_servers = [{servers}]
{network_extra}
{ingress_toml}"#
    );
    std::fs::write(&path, content).expect("write connector config");
    path
}

/// RAII wrapper for a spawned child process. Sends SIGKILL on drop.
pub struct ProcessGuard {
    child: Child,
}

impl ProcessGuard {
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Send a signal (e.g. "HUP", "TERM") to the process.
    pub fn signal(&self, name: &str) {
        if let Some(pid) = self.pid() {
            let _ = std::process::Command::new("kill")
                .arg(format!("-{name}"))
                .arg(pid.to_string())
                .status();
        }
    }

    pub async fn wait_exit(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        timeout(limit, self.child.wait())
            .await
            .ok()
            .and_then(|r| r.ok())
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn log_stdio() -> std::process::Stdio {
    if std::env::var_os("SIEVETUBE_TEST_LOGS").is_some() {
        std::process::Stdio::inherit()
    } else {
        std::process::Stdio::null()
    }
}

fn spawn_binary(name: &str, config_path: &Path, envs: &[(&str, &str)]) -> ProcessGuard {
    let level = if std::env::var_os("SIEVETUBE_TEST_LOGS").is_some() {
        "debug"
    } else {
        "error"
    };
    let child = Command::new(binary(name))
        .arg(config_path)
        .env("RUST_LOG", level)
        .envs(envs.iter().copied())
        .stdout(log_stdio())
        .stderr(log_stdio())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| {
            panic!("failed to spawn {name}: {e}\nRun `cargo build -p sievetube-edge -p sievetube-connector` first.")
        });
    ProcessGuard { child }
}

/// Spawn the edge binary with the given config file.
pub async fn start_edge(config_path: &Path) -> ProcessGuard {
    spawn_binary("sievetube-edge", config_path, &[])
}

/// Spawn the edge binary with extra environment variables.
pub async fn start_edge_with_env(config_path: &Path, envs: &[(&str, &str)]) -> ProcessGuard {
    spawn_binary("sievetube-edge", config_path, envs)
}

/// Spawn the connector binary with the given config file.
pub async fn start_connector(config_path: &Path) -> ProcessGuard {
    spawn_binary("sievetube-connector", config_path, &[])
}

/// Poll /healthz on the given port until it returns 200, up to 10 seconds.
pub async fn wait_for_health(port: u16) {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok((status, _)) = health_get(port, "/healthz").await {
                if status == 200 {
                    return;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("edge health check timed out (10s)");
}

/// GET a path on the health server; returns (status, body).
pub async fn health_get(port: u16, path: &str) -> anyhow::Result<(u16, String)> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())
        .await?;
    let mut buf = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, body))
}

/// Poll /healthz until `active_connectors` reaches the expected count (max 10 seconds).
pub async fn wait_for_connectors(health_port: u16, expected: usize) {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(count) = connector_count(health_port).await {
                if count >= expected {
                    return;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("connectors did not register within 10 seconds");
}

pub async fn connector_count(health_port: u16) -> anyhow::Result<usize> {
    let (_, body) = health_get(health_port, "/healthz").await?;
    // Response body: {"status":"ok","active_connectors":N}
    if let Some(pos) = body.find("\"active_connectors\":") {
        let rest = &body[pos + 20..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        return Ok(rest[..end].parse().unwrap_or(0));
    }
    Ok(0)
}

/// Spawn a minimal HTTP server that responds 200 with a fixed body.
/// Returns the port it's listening on.
pub async fn start_mock_http_server(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    port
}

/// Spawn a TCP echo server. Returns the port it's listening on.
pub async fn start_tcp_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// Spawn a UDP echo server. Returns the port it's listening on.
pub async fn start_udp_echo_server() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    port
}

fn full(data: impl Into<Bytes>) -> TestBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// HTTP/1.1 backend used by proxy tests:
/// - `/echo` streams the request body back
/// - `/headers` returns the received request headers, one per line
/// - `/ws` accepts an upgrade and echoes bytes on the upgraded connection
/// - `/count` returns the number of requests received so far
/// - anything else returns `hello from backend <path>`
pub async fn start_backend() -> (u16, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let counter = Arc::new(AtomicU64::new(0));
    let served = counter.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let counter = served.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let counter = counter.clone();
                    async move { backend_handler(req, counter).await }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    (port, counter)
}

async fn backend_handler(
    mut req: Request<Incoming>,
    counter: Arc<AtomicU64>,
) -> Result<Response<TestBody>, Infallible> {
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    let response = match req.uri().path() {
        "/echo" => Response::new(req.into_body().map_err(|e| e.into()).boxed()),
        "/headers" => {
            let mut lines = format!("version: {:?}\n", req.version());
            for (name, value) in req.headers() {
                lines.push_str(&format!("{name}: {}\n", value.to_str().unwrap_or("?")));
            }
            Response::new(full(lines))
        }
        "/ws" => {
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    let (mut r, mut w) = tokio::io::split(TokioIo::new(upgraded));
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
            Response::builder()
                .status(101)
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .body(full(Bytes::new()))
                .unwrap()
        }
        "/count" => Response::new(full(count.to_string())),
        path => Response::new(full(format!("hello from backend {path}"))),
    };
    Ok(response)
}

/// A request body that yields `chunks` copies of a 16 KiB pattern without buffering.
pub struct PatternBody {
    remaining: usize,
    chunk: Bytes,
}

impl PatternBody {
    pub fn new(chunks: usize) -> Self {
        let chunk: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
        PatternBody {
            remaining: chunks,
            chunk: Bytes::from(chunk),
        }
    }

    pub fn expected_len(chunks: usize) -> usize {
        chunks * 16 * 1024
    }
}

impl Body for PatternBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        self.remaining -= 1;
        Poll::Ready(Some(Ok(Frame::data(self.chunk.clone()))))
    }
}

/// Everything needed for an HTTP tunnel test: edge + connector + backend.
pub struct HttpTunnel {
    pub edge: EdgeTestConfig,
    pub backend_port: u16,
    pub backend_requests: Arc<AtomicU64>,
    pub edge_process: ProcessGuard,
    pub connector_process: ProcessGuard,
}

/// Start an edge (customized by `configure`), a connector for `hostnames` and a backend.
pub async fn start_http_tunnel(
    secret: &str,
    tenant: &str,
    hostnames: &[&str],
    configure: impl FnOnce(&mut EdgeTestConfig),
) -> HttpTunnel {
    let (backend_port, backend_requests) = start_backend().await;
    let mut edge = EdgeTestConfig::new(secret);
    configure(&mut edge);
    let edge_cfg = edge.write();

    let jwt = make_jwt(secret, tenant, hostnames);
    let target = format!("127.0.0.1:{backend_port}");
    let ingress: Vec<(&str, &str, &str)> = hostnames
        .iter()
        .map(|h| (*h, "http", target.as_str()))
        .collect();
    let conn_cfg = write_connector_config(&jwt, &edge.quic_addr(), &ingress);

    let edge_process = start_edge(&edge_cfg).await;
    wait_for_health(edge.health_port).await;
    let connector_process = start_connector(&conn_cfg).await;
    wait_for_connectors(edge.health_port, 1).await;

    HttpTunnel {
        edge,
        backend_port,
        backend_requests,
        edge_process,
        connector_process,
    }
}

/// Send a plain HTTP/1.0 GET request through the edge HTTP listener.
/// Returns the full response (headers + body) as a string.
pub async fn http_get(edge_http_port: u16, host: &str, path: &str) -> anyhow::Result<String> {
    raw_request(
        edge_http_port,
        format!("GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes(),
    )
    .await
}

/// Write raw bytes to the edge HTTP port and read until the server closes.
pub async fn raw_request(port: u16, request: &[u8]) -> anyhow::Result<String> {
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{port}")),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout connecting to port {port}"))?
    .map_err(|e| anyhow::anyhow!("connect error: {e}"))?;

    stream.write_all(request).await?;

    let mut resp = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading response"))?
        .map_err(|e| anyhow::anyhow!("read error: {e}"))?;

    Ok(String::from_utf8_lossy(&resp).into_owned())
}

/// HTTP/1.1 client connection to the given port.
pub async fn h1_connect<B>(port: u16) -> hyper::client::conn::http1::SendRequest<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    sender
}

/// Collect a response into (status, body).
pub async fn read_response(response: Response<Incoming>) -> (u16, Bytes) {
    let status = response.status().as_u16();
    let body = timeout(Duration::from_secs(10), response.into_body().collect())
        .await
        .expect("timeout reading body")
        .expect("body error")
        .to_bytes();
    (status, body)
}

/// A test CA and helpers to issue server certificates signed by it.
pub struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
    pub pem: String,
}

impl TestCa {
    pub fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "sievetube test CA");
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        TestCa { cert, key, pem }
    }

    /// Issue a certificate for `names`; returns (cert_pem, key_pem).
    pub fn issue(&self, names: &[&str]) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// Write `<name>.crt` / `<name>.key` into `dir`.
    pub fn write_pair(&self, dir: &Path, file_name: &str, names: &[&str]) {
        let (cert, key) = self.issue(names);
        std::fs::write(dir.join(format!("{file_name}.crt")), cert).unwrap();
        std::fs::write(dir.join(format!("{file_name}.key")), key).unwrap();
    }
}

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Open a TLS connection trusting `ca_pem`, with the given SNI and ALPN protocols.
pub async fn tls_connect(
    port: u16,
    sni: &str,
    ca_pem: &str,
    alpn: &[&[u8]],
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    let der = rustls::pki_types::CertificateDer::from(
        pem_to_der(ca_pem).ok_or_else(|| anyhow::anyhow!("invalid CA PEM"))?,
    );
    roots.add(der)?;
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;
    let tls = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, stream),
    )
    .await??;
    Ok(tls)
}

pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64_decode(&body)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [0xffu8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in input
        .bytes()
        .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
    {
        let v = lookup[b as usize];
        if v == 0xff {
            return None;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Retry `f` until it returns `Some`, up to `limit`.
pub async fn eventually<T, F, Fut>(limit: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    timeout(limit, async {
        loop {
            if let Some(v) = f().await {
                return v;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .ok()
}

use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

static COUNTER: AtomicU64 = AtomicU64::new(0);

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
    workspace_root()
        .join("target")
        .join("debug")
        .join(format!("{}{}", name, std::env::consts::EXE_SUFFIX))
}

/// Generate a unique suffix for temp files.
fn unique_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
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

/// Write an edge config to a temp file.
/// `tcp_listeners` is a list of (listen_port, hostname) for raw TCP tunnels.
pub fn write_edge_config(
    quic_port: u16,
    http_port: u16,
    health_port: u16,
    jwt_secret: &str,
    tcp_listeners: &[(u16, &str)],
) -> PathBuf {
    let path = std::env::temp_dir()
        .join(format!("sievetube-edge-{}.toml", unique_id()));

    let tcp_section: String = tcp_listeners
        .iter()
        .map(|(port, hostname)| {
            format!(
                "\n[[server.tcp_listen]]\naddr = \"127.0.0.1:{port}\"\nhostname = \"{hostname}\"\n"
            )
        })
        .collect();

    let content = format!(
        r#"[server]
quic_listen = "127.0.0.1:{quic_port}"
http_listen = "127.0.0.1:{http_port}"
https_listen = "127.0.0.1:0"
health_listen = "127.0.0.1:{health_port}"
{tcp_section}
[auth]
jwt_secret = "{jwt_secret}"

[tls]
cert_dir = "/nonexistent/test-certs"
"#
    );
    std::fs::write(&path, content).expect("write edge config");
    path
}

/// Write a connector config to a temp file.
/// `ingress` entries: (hostname, protocol, target_addr).
pub fn write_connector_config(
    jwt: &str,
    quic_addr: &str,
    ingress: &[(&str, &str, &str)],
) -> PathBuf {
    let path = std::env::temp_dir()
        .join(format!("sievetube-connector-{}.toml", unique_id()));

    let mut ingress_toml = String::new();
    for (hostname, protocol, target) in ingress {
        ingress_toml.push_str(&format!(
            "\n[[ingress]]\nhostname = \"{hostname}\"\nprotocol = \"{protocol}\"\ntarget = \"{target}\"\n"
        ));
    }
    // Catch-all
    ingress_toml.push_str("\n[[ingress]]\ntarget = \"http_status:404\"\n");

    let content = format!(
        r#"[auth]
token = "{jwt}"

[network]
public_servers = ["{quic_addr}"]
{ingress_toml}"#
    );
    std::fs::write(&path, content).expect("write connector config");
    path
}

/// RAII wrapper for a spawned child process. Sends SIGKILL on drop.
pub struct ProcessGuard {
    child: Child,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Spawn the edge binary with the given config file.
pub async fn start_edge(config_path: &PathBuf) -> ProcessGuard {
    let child = Command::new(binary("sievetube-edge"))
        .arg(config_path)
        .env("RUST_LOG", "error")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn sievetube-edge: {e}\n\
                 Run `cargo build -p sievetube-edge` first."
            )
        });
    ProcessGuard { child }
}

/// Spawn the connector binary with the given config file.
pub async fn start_connector(config_path: &PathBuf) -> ProcessGuard {
    let child = Command::new(binary("sievetube-connector"))
        .arg(config_path)
        .env("RUST_LOG", "error")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn sievetube-connector: {e}\n\
                 Run `cargo build -p sievetube-connector` first."
            )
        });
    ProcessGuard { child }
}

/// Poll /healthz on the given port until it returns 200, up to 10 seconds.
pub async fn wait_for_health(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(&addr).await {
                let req = b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n";
                if stream.write_all(req).await.is_ok() {
                    let mut buf = [0u8; 256];
                    if let Ok(n) = stream.read(&mut buf).await {
                        if std::str::from_utf8(&buf[..n])
                            .unwrap_or("")
                            .contains("200 OK")
                        {
                            return;
                        }
                    }
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("edge health check timed out (10s)");
}

/// Poll /healthz until `active_connectors` reaches the expected count (max 10 seconds).
pub async fn wait_for_connectors(health_port: u16, expected: usize) {
    let addr = format!("127.0.0.1:{health_port}");
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(count) = connector_count(&addr).await {
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

async fn connector_count(addr: &str) -> anyhow::Result<usize> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await?;
    let text = std::str::from_utf8(&buf[..n]).unwrap_or("");
    // Response body: {"status":"ok","active_connectors":N}
    if let Some(pos) = text.find("\"active_connectors\":") {
        let rest = &text[pos + 20..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
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

/// Send a plain HTTP/1.0 GET request through the edge HTTP listener.
/// Returns the full response (headers + body) as a string.
pub async fn http_get(edge_http_port: u16, host: &str, path: &str) -> anyhow::Result<String> {
    let mut stream = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{edge_http_port}")),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout connecting to edge HTTP port {edge_http_port}"))?
    .map_err(|e| anyhow::anyhow!("connect error: {e}"))?;

    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut resp = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading response"))?
        .map_err(|e| anyhow::anyhow!("read error: {e}"))?;

    Ok(String::from_utf8_lossy(&resp).into_owned())
}

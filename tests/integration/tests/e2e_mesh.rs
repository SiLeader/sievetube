//! Edge-to-Edge forwarding (M1-M5).
//!
//! Needs Valkey for route advertisement: SIEVETUBE_TEST_VALKEY_URL=redis://...

mod helpers;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

fn valkey_url() -> Option<String> {
    std::env::var("SIEVETUBE_TEST_VALKEY_URL").ok()
}

fn edge_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .join("target/debug/sievetube-edge")
}

/// Create a mesh CA and certificates with the Edge's own PKI commands.
fn mesh_pki(edges: &[&str]) -> PathBuf {
    let dir = helpers::temp_dir("mesh-pki");
    let status = Command::new(edge_binary())
        .arg("mesh-ca")
        .arg(&dir)
        .status()
        .expect("mesh-ca");
    assert!(status.success(), "mesh-ca failed");
    for edge in edges {
        let status = Command::new(edge_binary())
            .arg("mesh-cert")
            .arg(&dir)
            .arg(edge)
            .status()
            .expect("mesh-cert");
        assert!(status.success(), "mesh-cert for {edge} failed");
    }
    dir
}

fn mesh_section(
    pki: &Path,
    edge_id: &str,
    mesh_port: u16,
    peers: &[&str],
    valkey: &str,
    mode: &str,
) -> String {
    let peer_entries: String = peers
        .iter()
        .map(|peer| format!("\n[[mesh.peers]]\nedge_id = \"{peer}\"\n"))
        .collect();
    format!(
        r#"
[valkey]
url = "{valkey}"

[routing]
mode = "{mode}"

[mesh]
edge_id = "{edge_id}"
listen = "127.0.0.1:{mesh_port}"
advertise = "127.0.0.1:{mesh_port}"
ca_cert = "{ca}"
cert = "{cert}"
key = "{key}"
route_ttl_secs = 4
route_refresh_secs = 1
peer_failure_cooldown_secs = 1
{peer_entries}"#,
        ca = pki.join("ca.pem").display(),
        cert = pki.join(format!("{edge_id}.pem")).display(),
        key = pki.join(format!("{edge_id}.key")).display(),
    )
}

struct MeshCluster {
    /// Unique per test: hostname ownership is global, so tests must not share one
    host: String,
    ingress: helpers::EdgeTestConfig,
    ingress_tcp_port: u16,
    ingress_udp_port: u16,
    _ingress_process: helpers::ProcessGuard,
    connector_edge: helpers::EdgeTestConfig,
    connector_edge_process: Option<helpers::ProcessGuard>,
    _connector: helpers::ProcessGuard,
    _backend_port: u16,
}

/// Ingress Edge "edge-a" without a Connector, and "edge-b" with one.
async fn start_cluster(secret: &str, mode: &str) -> Option<MeshCluster> {
    let valkey = valkey_url()?;
    let host = format!("mesh-{}.test", helpers::unique_id());
    let pki = mesh_pki(&["edge-a", "edge-b"]);
    let (backend_port, _) = helpers::start_backend().await;
    let echo_port = helpers::start_tcp_echo_server().await;
    let udp_echo_port = helpers::start_udp_echo_server().await;

    let mut ingress = helpers::EdgeTestConfig::new(secret);
    let ingress_tcp_port = helpers::find_free_port();
    let ingress_udp_port = helpers::find_free_port();
    ingress.tcp_listeners = vec![(ingress_tcp_port, host.clone())];
    ingress.udp_listeners = vec![(ingress_udp_port, host.clone())];
    ingress.extra = mesh_section(
        &pki,
        "edge-a",
        helpers::find_free_port(),
        &["edge-b"],
        &valkey,
        mode,
    );

    let mut connector_edge = helpers::EdgeTestConfig::new(secret);
    connector_edge.extra = mesh_section(
        &pki,
        "edge-b",
        helpers::find_free_port(),
        &["edge-a"],
        &valkey,
        "mesh",
    );

    let ingress_cfg = ingress.write();
    let connector_edge_cfg = connector_edge.write();
    let ingress_process = helpers::start_edge(&ingress_cfg).await;
    let connector_edge_process = helpers::start_edge(&connector_edge_cfg).await;
    helpers::wait_for_health(ingress.health_port).await;
    helpers::wait_for_health(connector_edge.health_port).await;

    // The Connector attaches only to edge-b.
    let jwt = helpers::make_jwt(secret, &format!("tenant-{secret}"), &[host.as_str()]);
    let conn_cfg = helpers::write_connector_config(
        &jwt,
        &connector_edge.quic_addr(),
        &[
            (host.as_str(), "http", &format!("127.0.0.1:{backend_port}")),
            (host.as_str(), "tcp", &format!("127.0.0.1:{echo_port}")),
            (host.as_str(), "udp", &format!("127.0.0.1:{udp_echo_port}")),
        ],
    );
    let connector = helpers::start_connector(&conn_cfg).await;
    helpers::wait_for_connectors(connector_edge.health_port, 1).await;

    Some(MeshCluster {
        host,
        ingress,
        ingress_tcp_port,
        ingress_udp_port,
        _ingress_process: ingress_process,
        connector_edge,
        connector_edge_process: Some(connector_edge_process),
        _connector: connector,
        _backend_port: backend_port,
    })
}

/// Wait until the ingress Edge has learned the remote route and forwards.
async fn wait_for_forwarding(port: u16, host: &str) -> Option<String> {
    helpers::eventually(Duration::from_secs(20), || async {
        let response = helpers::http_get(port, host, "/mesh").await.ok()?;
        response.contains("200 OK").then_some(response)
    })
    .await
}

#[tokio::test]
async fn http_tcp_and_udp_reach_a_connector_on_another_edge() {
    let Some(cluster) = start_cluster("secret-mesh", "mesh").await else {
        eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
        return;
    };

    // HTTP: edge-a has no Connector for the hostname and forwards to edge-b.
    let response = wait_for_forwarding(cluster.ingress.http_port, &cluster.host).await;
    let response = response.expect("request was not forwarded over the mesh");
    assert!(response.contains("hello from backend /mesh"), "{response}");

    // TCP.
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", cluster.ingress_tcp_port))
        .await
        .unwrap();
    stream.write_all(b"mesh tcp payload").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"mesh tcp payload");

    // UDP, including the reply finding its way back through the ingress Edge.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .connect(format!("127.0.0.1:{}", cluster.ingress_udp_port))
        .await
        .unwrap();
    let received = helpers::eventually(Duration::from_secs(10), || async {
        socket.send(b"mesh udp payload").await.ok()?;
        let mut buf = [0u8; 64];
        let n = timeout(Duration::from_millis(700), socket.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some(buf[..n].to_vec())
    })
    .await;
    assert_eq!(received.as_deref(), Some(&b"mesh udp payload"[..]));

    // The forwarding shows up in the ingress Edge's metrics, and the Connector
    // Edge counts the accepted requests.
    let ingress_metrics = helpers::metrics(cluster.ingress.health_port).await;
    assert!(
        ingress_metrics
            .lines()
            .any(|l| l.starts_with("sievetube_mesh_forwarded_total")
                && l.contains("stage=\"opened\"")),
        "{ingress_metrics}"
    );
    let peer_metrics = helpers::metrics(cluster.connector_edge.health_port).await;
    assert!(
        peer_metrics
            .lines()
            .any(|l| l.starts_with("sievetube_mesh_forwarded_total")
                && l.contains("stage=\"accepted\"")),
        "{peer_metrics}"
    );
}

#[tokio::test]
async fn routes_disappear_when_the_connector_edge_stops() {
    let Some(mut cluster) = start_cluster("secret-mesh-stop", "mesh").await else {
        eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
        return;
    };
    assert!(
        wait_for_forwarding(cluster.ingress.http_port, &cluster.host)
            .await
            .is_some()
    );

    // Killing edge-b lets its advertisements expire; edge-a must answer 502
    // instead of hanging or forwarding in a loop.
    drop(cluster.connector_edge_process.take());
    let failed = helpers::eventually(Duration::from_secs(20), || async {
        let response = helpers::http_get(cluster.ingress.http_port, &cluster.host, "/gone")
            .await
            .ok()?;
        response.contains(" 502 ").then_some(())
    })
    .await;
    assert!(failed.is_some(), "expired routes must stop being used");
}

#[tokio::test]
async fn direct_mode_does_not_forward_between_edges() {
    let Some(cluster) = start_cluster("secret-mesh-direct", "direct").await else {
        eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
        return;
    };
    // edge-a is configured with a mesh section but routing.mode = "direct".
    tokio::time::sleep(Duration::from_secs(3)).await;
    let response = helpers::http_get(cluster.ingress.http_port, &cluster.host, "/")
        .await
        .unwrap();
    assert!(
        response.contains(" 502 "),
        "direct mode must not forward: {response}"
    );

    // The Connector's own Edge still serves it.
    let direct = helpers::http_get(cluster.connector_edge.http_port, &cluster.host, "/local")
        .await
        .unwrap();
    assert!(direct.contains("hello from backend /local"), "{direct}");
}

//! The Connector verifies the Edge's QUIC certificate (mesh-related improvement).

mod helpers;

use std::time::Duration;

const HOST: &str = "verified.test";

fn fingerprint(cert_pem: &str) -> String {
    let der = helpers::pem_to_der(cert_pem).expect("certificate PEM");
    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Start an Edge with a real QUIC certificate and a Connector with the given
/// `[network]` verification settings. Returns whether the tunnel came up.
async fn tunnel_established(
    secret: &str,
    network_extra: impl Fn(&helpers::TestCa, &str) -> String,
) -> bool {
    let ca = helpers::TestCa::new();
    let (cert_pem, key_pem) = ca.issue(&["localhost"]);
    let dir = helpers::temp_dir("quic-cert");
    let (cert_path, key_path) = (dir.join("edge.crt"), dir.join("edge.key"));
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    let (backend_port, _) = helpers::start_backend().await;
    let mut edge = helpers::EdgeTestConfig::new(secret);
    edge.quic_cert = Some((cert_path, key_path));
    let edge_cfg = edge.write();

    let jwt = helpers::make_jwt(secret, &format!("tenant-{secret}"), &[HOST]);
    let conn_cfg = helpers::write_connector_config_with_network(
        &jwt,
        // Connect by name so the certificate's SAN is checked.
        &[&format!("localhost:{}", edge.quic_port)],
        &[(HOST, "http", &format!("127.0.0.1:{backend_port}"))],
        &network_extra(&ca, &cert_pem),
    );

    let _edge = helpers::start_edge(&edge_cfg).await;
    helpers::wait_for_health(edge.health_port).await;
    let _connector = helpers::start_connector(&conn_cfg).await;

    let connected = helpers::eventually(Duration::from_secs(6), || async {
        (helpers::connector_count(edge.health_port)
            .await
            .unwrap_or(0)
            >= 1)
            .then_some(())
    })
    .await
    .is_some();
    if connected {
        let response = helpers::http_get(edge.http_port, HOST, "/verified")
            .await
            .unwrap();
        assert!(
            response.contains("hello from backend /verified"),
            "{response}"
        );
    }
    connected
}

#[tokio::test]
async fn connector_accepts_an_edge_certificate_from_its_ca() {
    let established = tunnel_established("secret-edge-ca", |ca, _| {
        let dir = helpers::temp_dir("edge-ca");
        let path = dir.join("ca.pem");
        std::fs::write(&path, &ca.pem).unwrap();
        format!("edge_ca_cert = \"{}\"", path.display())
    })
    .await;
    assert!(
        established,
        "a certificate issued by the configured CA must be accepted"
    );
}

#[tokio::test]
async fn connector_rejects_an_edge_certificate_from_another_ca() {
    let established = tunnel_established("secret-edge-wrong-ca", |_, _| {
        let other = helpers::TestCa::new();
        let dir = helpers::temp_dir("other-ca");
        let path = dir.join("ca.pem");
        std::fs::write(&path, &other.pem).unwrap();
        format!("edge_ca_cert = \"{}\"", path.display())
    })
    .await;
    assert!(
        !established,
        "a certificate from an unknown CA must be rejected"
    );
}

#[tokio::test]
async fn connector_pins_the_edge_certificate() {
    let established = tunnel_established("secret-edge-pin", |_, cert_pem| {
        format!("edge_cert_sha256 = [\"{}\"]", fingerprint(cert_pem))
    })
    .await;
    assert!(established, "the pinned certificate must be accepted");

    let established = tunnel_established("secret-edge-badpin", |_, _| {
        format!("edge_cert_sha256 = [\"{}\"]", "11".repeat(32))
    })
    .await;
    assert!(
        !established,
        "a certificate that does not match the pin must be rejected"
    );
}

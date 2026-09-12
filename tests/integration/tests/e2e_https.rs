//! HTTPS termination (A1/B1): SNI routing, certificate hot reload and SNI/Host checks.

mod helpers;

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};

const HOST: &str = "secure.test";
const OTHER: &str = "other.test";

#[tokio::test]
async fn https_listener_starts_without_certificates_and_picks_up_new_ones() {
    let cert_dir = helpers::temp_dir("certs-reload");
    let ca = helpers::TestCa::new();
    let dir = cert_dir.clone();
    let env =
        helpers::start_http_tunnel("secret-https-reload", "tenant-https", &[HOST], move |cfg| {
            cfg.cert_dir = dir.display().to_string();
        })
        .await;
    let port = env.edge.https_port;

    // No certificate yet: the handshake fails, but the listener is up.
    assert!(helpers::tls_connect(port, HOST, &ca.pem, &[b"http/1.1"])
        .await
        .is_err());

    // Add a certificate without restarting the edge.
    ca.write_pair(&cert_dir, HOST, &[HOST]);
    let tls = helpers::eventually(Duration::from_secs(10), || async {
        helpers::tls_connect(port, HOST, &ca.pem, &[b"http/1.1"])
            .await
            .ok()
    })
    .await
    .expect("certificate was not loaded by periodic reload");

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("/tls")
        .header("host", HOST)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let (status, body) = helpers::read_response(sender.send_request(req).await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello from backend /tls");
}

#[tokio::test]
async fn http2_over_tls_is_negotiated_with_alpn() {
    let cert_dir = helpers::temp_dir("certs-h2");
    let ca = helpers::TestCa::new();
    ca.write_pair(&cert_dir, HOST, &[HOST]);
    let dir = cert_dir.clone();
    let env =
        helpers::start_http_tunnel("secret-https-h2", "tenant-https-h2", &[HOST], move |cfg| {
            cfg.cert_dir = dir.display().to_string();
        })
        .await;

    let tls = helpers::tls_connect(env.edge.https_port, HOST, &ca.pem, &[b"h2", b"http/1.1"])
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(format!("https://{HOST}/h2-headers"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let (status, body) = helpers::read_response(sender.send_request(req).await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello from backend /h2-headers");
}

#[tokio::test]
async fn host_not_matching_sni_is_misdirected() {
    let cert_dir = helpers::temp_dir("certs-sni");
    let ca = helpers::TestCa::new();
    // One certificate covering both names, so the only protection is the SNI/Host check.
    ca.write_pair(&cert_dir, HOST, &[HOST, OTHER]);
    ca.write_pair(&cert_dir, OTHER, &[HOST, OTHER]);
    let dir = cert_dir.clone();
    let env = helpers::start_http_tunnel(
        "secret-https-sni",
        "tenant-sni",
        &[HOST, OTHER],
        move |cfg| {
            cfg.cert_dir = dir.display().to_string();
        },
    )
    .await;

    let tls = helpers::tls_connect(env.edge.https_port, HOST, &ca.pem, &[b"http/1.1"])
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);

    let req = Request::builder()
        .uri("/")
        .header("host", OTHER)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let (status, _) = helpers::read_response(sender.send_request(req).await.unwrap()).await;
    assert_eq!(status, 421);

    sender.ready().await.unwrap();
    let req = Request::builder()
        .uri("/ok")
        .header("host", HOST)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let (status, body) = helpers::read_response(sender.send_request(req).await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello from backend /ok");
}

#[tokio::test]
async fn unknown_sni_fails_handshake_and_invalid_update_keeps_certificate() {
    let cert_dir = helpers::temp_dir("certs-invalid");
    let ca = helpers::TestCa::new();
    ca.write_pair(&cert_dir, HOST, &[HOST]);
    let dir = cert_dir.clone();
    let env = helpers::start_http_tunnel(
        "secret-https-invalid",
        "tenant-invalid-cert",
        &[HOST],
        move |cfg| {
            cfg.cert_dir = dir.display().to_string();
        },
    )
    .await;
    let port = env.edge.https_port;

    assert!(
        helpers::tls_connect(port, "unknown.test", &ca.pem, &[b"http/1.1"])
            .await
            .is_err()
    );
    assert!(helpers::tls_connect(port, HOST, &ca.pem, &[b"http/1.1"])
        .await
        .is_ok());

    // Corrupt the key; after several reload intervals the old certificate must still be served.
    std::fs::write(cert_dir.join(format!("{HOST}.key")), "not a key").unwrap();
    env.edge_process.signal("HUP");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(helpers::tls_connect(port, HOST, &ca.pem, &[b"http/1.1"])
        .await
        .is_ok());
}

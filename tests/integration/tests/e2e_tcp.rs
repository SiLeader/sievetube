mod helpers;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use std::time::Duration;

/// End-to-end: data sent through a raw TCP tunnel is echoed back correctly.
#[tokio::test]
async fn tcp_echo_tunnel() {
    let secret = "secret-e2e-tcp-echo";
    let hostname = "echo.test";

    let echo_port = helpers::start_tcp_echo_server().await;

    let quic_port = helpers::find_free_port();
    let http_port = helpers::find_free_port();
    let health_port = helpers::find_free_port();
    let tcp_listen_port = helpers::find_free_port();

    let edge_cfg = helpers::write_edge_config(
        quic_port,
        http_port,
        health_port,
        secret,
        &[(tcp_listen_port, hostname)],
    );
    let jwt = helpers::make_jwt(secret, "tenant-tcp", &[hostname]);
    let conn_cfg = helpers::write_connector_config(
        &jwt,
        &format!("127.0.0.1:{quic_port}"),
        &[(hostname, "tcp", &format!("127.0.0.1:{echo_port}"))],
    );

    let _edge = helpers::start_edge(&edge_cfg).await;
    helpers::wait_for_health(health_port).await;

    let _connector = helpers::start_connector(&conn_cfg).await;
    helpers::wait_for_connectors(health_port, 1).await;

    // Connect to the edge's raw TCP listener
    let mut stream = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{tcp_listen_port}")),
    )
    .await
    .expect("timeout connecting to TCP listener")
    .expect("failed to connect to TCP listener");

    let message = b"sievetube tcp echo test";
    stream.write_all(message).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut buf = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("timeout reading TCP echo")
        .expect("read error");

    assert_eq!(buf.as_slice(), message, "TCP echo payload mismatch");
}

/// Two tenants connected to the same edge are routed independently.
#[tokio::test]
async fn multi_tenant_coexistence() {
    let secret = "secret-e2e-multi-tenant";

    let backend_a = helpers::start_mock_http_server("tenant-A response").await;
    let backend_b = helpers::start_mock_http_server("tenant-B response").await;

    let quic_port = helpers::find_free_port();
    let http_port = helpers::find_free_port();
    let health_port = helpers::find_free_port();

    let edge_cfg =
        helpers::write_edge_config(quic_port, http_port, health_port, secret, &[]);

    let jwt_a = helpers::make_jwt(secret, "tenant-a", &["host-a.test"]);
    let cfg_a = helpers::write_connector_config(
        &jwt_a,
        &format!("127.0.0.1:{quic_port}"),
        &[("host-a.test", "http", &format!("127.0.0.1:{backend_a}"))],
    );

    let jwt_b = helpers::make_jwt(secret, "tenant-b", &["host-b.test"]);
    let cfg_b = helpers::write_connector_config(
        &jwt_b,
        &format!("127.0.0.1:{quic_port}"),
        &[("host-b.test", "http", &format!("127.0.0.1:{backend_b}"))],
    );

    let _edge = helpers::start_edge(&edge_cfg).await;
    helpers::wait_for_health(health_port).await;

    let _conn_a = helpers::start_connector(&cfg_a).await;
    let _conn_b = helpers::start_connector(&cfg_b).await;
    helpers::wait_for_connectors(health_port, 2).await;

    let resp_a = helpers::http_get(http_port, "host-a.test", "/").await.unwrap();
    assert!(
        resp_a.contains("tenant-A response"),
        "expected tenant-A backend, got:\n{resp_a}"
    );

    let resp_b = helpers::http_get(http_port, "host-b.test", "/").await.unwrap();
    assert!(
        resp_b.contains("tenant-B response"),
        "expected tenant-B backend, got:\n{resp_b}"
    );
}

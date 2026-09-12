mod helpers;

/// End-to-end: HTTP request is forwarded through the tunnel to the backend.
#[tokio::test]
async fn http_tunnel_basic() {
    let secret = "secret-e2e-http-basic";
    let hostname = "backend.test";

    let backend_port = helpers::start_mock_http_server("hello from backend").await;

    let quic_port = helpers::find_free_port();
    let http_port = helpers::find_free_port();
    let health_port = helpers::find_free_port();

    let edge_cfg = helpers::write_edge_config(quic_port, http_port, health_port, secret, &[]);
    let jwt = helpers::make_jwt(secret, "tenant-http", &[hostname]);
    let conn_cfg = helpers::write_connector_config(
        &jwt,
        &format!("127.0.0.1:{quic_port}"),
        &[(hostname, "http", &format!("127.0.0.1:{backend_port}"))],
    );

    let _edge = helpers::start_edge(&edge_cfg).await;
    helpers::wait_for_health(health_port).await;

    let _connector = helpers::start_connector(&conn_cfg).await;
    helpers::wait_for_connectors(health_port, 1).await;

    let response = helpers::http_get(http_port, hostname, "/").await.unwrap();

    assert!(
        response.contains("200 OK"),
        "expected 200 OK, got:\n{response}"
    );
    assert!(
        response.contains("hello from backend"),
        "expected backend body, got:\n{response}"
    );
}

/// A connector with a JWT signed by a different secret is rejected by the edge.
/// Requests for that hostname return 502 (no connector registered).
#[tokio::test]
async fn auth_rejection_returns_502() {
    let edge_secret = "edge-secret-auth-test";
    let wrong_secret = "wrong-secret-auth-test";
    let hostname = "auth-rejected.test";

    let quic_port = helpers::find_free_port();
    let http_port = helpers::find_free_port();
    let health_port = helpers::find_free_port();

    let edge_cfg = helpers::write_edge_config(quic_port, http_port, health_port, edge_secret, &[]);
    let bad_jwt = helpers::make_jwt(wrong_secret, "bad-tenant", &[hostname]);
    let conn_cfg = helpers::write_connector_config(
        &bad_jwt,
        &format!("127.0.0.1:{quic_port}"),
        &[(hostname, "http", "127.0.0.1:9")],
    );

    let _edge = helpers::start_edge(&edge_cfg).await;
    helpers::wait_for_health(health_port).await;

    // Connector with wrong secret should be rejected — connector count stays 0
    let _connector = helpers::start_connector(&conn_cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let response = helpers::http_get(http_port, hostname, "/").await.unwrap();
    assert!(
        response.contains("502"),
        "expected 502 for rejected connector, got:\n{response}"
    );
}

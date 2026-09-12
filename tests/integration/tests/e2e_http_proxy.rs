//! Request-level HTTP proxying (B1): keep-alive, HTTP/2, streaming, upgrades and validation.

mod helpers;

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HOST: &str = "proxy.test";

#[tokio::test]
async fn keep_alive_connection_serves_multiple_requests() {
    let env = helpers::start_http_tunnel("secret-keepalive", "tenant-ka", &[HOST], |_| {}).await;
    let mut sender = helpers::h1_connect::<Empty<Bytes>>(env.edge.http_port).await;

    for i in 0..3 {
        sender.ready().await.unwrap();
        let req = Request::builder()
            .uri(format!("/req-{i}"))
            .header("host", HOST)
            .body(Empty::new())
            .unwrap();
        let (status, body) = helpers::read_response(sender.send_request(req).await.unwrap()).await;
        assert_eq!(status, 200);
        assert_eq!(body, format!("hello from backend /req-{i}"));
    }
}

#[tokio::test]
async fn http2_concurrent_requests_are_independent() {
    let env = helpers::start_http_tunnel("secret-h2", "tenant-h2", &[HOST], |_| {}).await;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", env.edge.http_port))
        .await
        .unwrap();
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);

    let mut tasks = Vec::new();
    for i in 0..20 {
        let mut sender = sender.clone();
        tasks.push(tokio::spawn(async move {
            let req = Request::builder()
                .uri(format!("http://{HOST}/item-{i}"))
                .body(Empty::<Bytes>::new())
                .unwrap();
            let response = sender.send_request(req).await.unwrap();
            let (status, body) = helpers::read_response(response).await;
            (i, status, body)
        }));
    }
    for task in tasks {
        let (i, status, body) = task.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, format!("hello from backend /item-{i}"));
    }
}

#[tokio::test]
async fn split_request_headers_are_reassembled() {
    let env = helpers::start_http_tunnel("secret-split", "tenant-split", &[HOST], |_| {}).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", env.edge.http_port))
        .await
        .unwrap();
    for part in [
        "GET /split HTTP/1.1\r\nHo",
        "st: proxy.te",
        "st\r\nConnection: cl",
        "ose\r\n\r\n",
    ] {
        stream.write_all(part.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("hello from backend /split"), "{response}");
}

#[tokio::test]
async fn large_request_body_is_streamed_to_backend_and_back() {
    let env = helpers::start_http_tunnel("secret-stream", "tenant-stream", &[HOST], |_| {}).await;
    let mut sender = helpers::h1_connect::<helpers::PatternBody>(env.edge.http_port).await;

    const CHUNKS: usize = 512; // 8 MiB, sent with chunked encoding
    let req = Request::builder()
        .method("POST")
        .uri("/echo")
        .header("host", HOST)
        .body(helpers::PatternBody::new(CHUNKS))
        .unwrap();
    let response = sender.send_request(req).await.unwrap();
    assert_eq!(response.status(), 200);

    let mut body = response.into_body();
    let mut received = 0usize;
    let mut checksum = 0u64;
    while let Some(frame) = timeout(Duration::from_secs(10), body.frame())
        .await
        .unwrap()
    {
        if let Ok(data) = frame.unwrap().into_data() {
            for (offset, byte) in data.iter().enumerate() {
                // PatternBody repeats `i % 251` within each 16 KiB chunk.
                let expected = ((received + offset) % (16 * 1024)) % 251;
                checksum = checksum.wrapping_add(expected as u64 ^ *byte as u64);
            }
            received += data.len();
        }
    }
    assert_eq!(received, helpers::PatternBody::expected_len(CHUNKS));
    assert_eq!(checksum, 0, "echoed body content differs");
}

#[tokio::test]
async fn websocket_upgrade_is_tunneled() {
    let env = helpers::start_http_tunnel("secret-ws", "tenant-ws", &[HOST], |_| {}).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", env.edge.http_port))
        .await
        .unwrap();
    stream
        .write_all(b"GET /ws HTTP/1.1\r\nHost: proxy.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .await
        .unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        timeout(Duration::from_secs(5), stream.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_lowercase();
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert!(head.contains("upgrade: websocket"), "{head}");

    for message in [&b"first frame"[..], b"second frame"] {
        stream.write_all(message).await.unwrap();
        let mut echoed = vec![0u8; message.len()];
        timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, message);
    }
}

#[tokio::test]
async fn invalid_requests_are_rejected_before_the_backend() {
    let env = helpers::start_http_tunnel("secret-invalid", "tenant-invalid", &[HOST], |_| {}).await;
    let port = env.edge.http_port;

    let connect = helpers::raw_request(
        port,
        b"CONNECT proxy.test:443 HTTP/1.1\r\nHost: proxy.test:443\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(connect.starts_with("HTTP/1.1 405"), "{connect}");

    let duplicate = helpers::raw_request(
        port,
        b"GET / HTTP/1.1\r\nHost: proxy.test\r\nHost: other.test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(duplicate.starts_with("HTTP/1.1 400"), "{duplicate}");

    let mismatch = helpers::raw_request(
        port,
        b"GET http://proxy.test/ HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(mismatch.starts_with("HTTP/1.1 400"), "{mismatch}");

    let unknown = helpers::http_get(port, "unknown.test", "/").await.unwrap();
    assert!(unknown.contains(" 502 "), "{unknown}");

    // None of the rejected requests reached the backend.
    let count = helpers::http_get(port, HOST, "/count").await.unwrap();
    assert!(count.ends_with("\r\n\r\n1"), "{count}");
}

#[tokio::test]
async fn hostname_is_normalized_and_forwarding_headers_are_set() {
    let env = helpers::start_http_tunnel("secret-norm", "tenant-norm", &[HOST], |_| {}).await;
    let response = helpers::raw_request(
        env.edge.http_port,
        b"GET /headers HTTP/1.1\r\nHost: PROXY.Test.:80\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    // The body lists the headers the backend received.
    let received = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert!(received.contains("host: PROXY.Test.:80"), "{received}");
    assert!(
        received.contains("x-forwarded-for: 127.0.0.1\n"),
        "client-supplied XFF must be replaced: {received}"
    );
    assert!(received.contains("x-forwarded-proto: http\n"), "{received}");
    assert!(
        !received.contains("connection:"),
        "hop-by-hop header forwarded: {received}"
    );
}

#[tokio::test]
async fn http10_client_gets_complete_response() {
    let env = helpers::start_http_tunnel("secret-h10", "tenant-h10", &[HOST], |_| {}).await;
    let response = helpers::http_get(env.edge.http_port, HOST, "/legacy")
        .await
        .unwrap();
    assert!(response.contains("200 OK"), "{response}");
    assert!(
        response.contains("hello from backend /legacy"),
        "{response}"
    );
    // body must be complete and connection closed (read_to_end returned)
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert_eq!(body, "hello from backend /legacy");
    let _ = Empty::<Bytes>::new().collect().await;
}

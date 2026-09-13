use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

use sievetube_common::config::{Protocol, Target};
use sievetube_common::metrics;

/// Forward traffic between a QUIC bidirectional stream and a local TCP target.
///
/// Returns (bytes_from_client, bytes_to_client).
pub async fn forward_tcp(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    target_addr: SocketAddr,
    tunnel_id: &str,
    hostname: &str,
    protocol: Protocol,
    connect_timeout: Duration,
) -> anyhow::Result<(u64, u64)> {
    let mut local = tokio::time::timeout(connect_timeout, TcpStream::connect(target_addr))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "timed out connecting to local target {target_addr} after {}s",
                connect_timeout.as_secs_f64()
            )
        })?
        .map_err(|e| anyhow::anyhow!("failed to connect to local target {}: {}", target_addr, e))?;

    let (mut local_read, mut local_write) = local.split();

    use tokio::io::AsyncWriteExt;

    // Bidirectional copy with half-close: when one direction ends,
    // shut down the corresponding write side to propagate EOF.
    let quic_to_local = async {
        let n = tokio::io::copy(&mut recv, &mut local_write)
            .await
            .unwrap_or(0);
        let _ = local_write.shutdown().await;
        n
    };
    let local_to_quic = async {
        let n = tokio::io::copy(&mut local_read, &mut send)
            .await
            .unwrap_or(0);
        let _ = send.shutdown().await;
        n
    };

    let (bytes_in, bytes_out) = tokio::join!(quic_to_local, local_to_quic);

    let m = metrics::global();
    m.bytes_transferred_total
        .with_label_values(&["in", &protocol.to_string()])
        .inc_by(bytes_in as f64);
    m.bytes_transferred_total
        .with_label_values(&["out", &protocol.to_string()])
        .inc_by(bytes_out as f64);

    tracing::debug!(
        tunnel_id,
        hostname,
        %protocol,
        bytes_in,
        bytes_out,
        "stream tunnel closed"
    );

    Ok((bytes_in, bytes_out))
}

/// Send an HTTP status response over the QUIC send stream (for http_status targets).
pub async fn respond_http_status(mut send: quinn::SendStream, status: u16) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    send.write_all(response.as_bytes()).await?;
    send.finish()?;
    Ok(())
}

/// Forward a single UDP datagram to the local target and return any reply.
pub async fn forward_udp_datagram(
    payload: &[u8],
    target_addr: SocketAddr,
) -> anyhow::Result<Option<Vec<u8>>> {
    let bind: SocketAddr = match target_addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind).await?;
    // A connected socket only receives datagrams from the target, so no other
    // host can slip its payload in as the reply.
    socket.connect(target_addr).await?;
    socket.send(payload).await?;
    metrics::global()
        .bytes_transferred_total
        .with_label_values(&["in", "udp"])
        .inc_by(payload.len() as f64);

    // Wait for a reply with a short timeout
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            metrics::global()
                .bytes_transferred_total
                .with_label_values(&["out", "udp"])
                .inc_by(n as f64);
            Ok(Some(buf))
        }
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Ok(None), // timeout — no reply
    }
}

/// Dispatch an incoming QUIC bidi stream to the appropriate forwarder.
pub async fn handle_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    target: Target,
    tunnel_id: String,
    hostname: String,
    protocol: Protocol,
    connect_timeout: Duration,
) {
    let started = Instant::now();
    match target {
        Target::Address(addr) => {
            if let Err(e) = forward_tcp(
                send,
                recv,
                addr,
                &tunnel_id,
                &hostname,
                protocol,
                connect_timeout,
            )
            .await
            {
                tracing::warn!(tunnel_id, hostname, %protocol, error = %e, "stream forward error");
            }
        }
        Target::HttpStatus(status) => {
            if let Err(e) = respond_http_status(send, status).await {
                tracing::warn!(tunnel_id, hostname, error = %e, "http status response error");
            }
        }
    }
    metrics::global()
        .tunnel_duration_seconds
        .with_label_values(&[&protocol.to_string()])
        .observe(started.elapsed().as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_replies_come_only_from_the_target() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let forward = tokio::spawn(async move { forward_udp_datagram(b"ping", target_addr).await });

        let mut buf = [0u8; 16];
        let (len, forwarder) = target.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
        // Another host answers first, from an address that is not the target.
        let spoofer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        spoofer.send_to(b"spoofed", forwarder).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        target.send_to(b"pong", forwarder).await.unwrap();

        let reply = forward.await.unwrap().unwrap();
        assert_eq!(reply.as_deref(), Some(&b"pong"[..]));
    }

    #[tokio::test]
    async fn udp_targets_can_be_ipv6() {
        let Ok(target) = UdpSocket::bind("[::1]:0").await else {
            eprintln!("skipping: no IPv6 loopback");
            return;
        };
        let target_addr = target.local_addr().unwrap();
        let forward = tokio::spawn(async move { forward_udp_datagram(b"ping", target_addr).await });
        let mut buf = [0u8; 16];
        let (_, forwarder) = target.recv_from(&mut buf).await.unwrap();
        target.send_to(b"pong", forwarder).await.unwrap();
        let reply = forward.await.unwrap().unwrap();
        assert_eq!(reply.as_deref(), Some(&b"pong"[..]));
    }
}

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;

use sievetube_common::config::Protocol;
use sievetube_common::metrics;
use sievetube_common::protocol::{self, ConnectRequest, Message};

use crate::connector_registry::ConnectorHandle;

/// Maps request_id → (client_addr, public_socket, created_at) for routing UDP replies back.
pub type UdpReplyMap = Arc<RwLock<HashMap<u64, (SocketAddr, Arc<tokio::net::UdpSocket>, Instant)>>>;

pub fn new_udp_reply_map() -> UdpReplyMap {
    Arc::new(RwLock::new(HashMap::new()))
}

static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Forward a public inbound stream through the QUIC tunnel to the Connector.
///
/// Works with any `AsyncRead + AsyncWrite` split pair (TcpStream, TlsStream, …).
pub async fn forward_tcp<R, W>(
    mut public_recv: R,
    mut public_send: W,
    connector: Arc<ConnectorHandle>,
    hostname: String,
    protocol: Protocol,
    client_addr: SocketAddr,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let request_id = next_request_id();
    let start = Instant::now();

    // Open a QUIC bidi stream to the Connector
    let (mut quic_send, mut quic_recv) = connector
        .connection
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("failed to open QUIC stream: {e}"))?;

    // Send ConnectRequest
    protocol::write_message(
        &mut quic_send,
        &Message::ConnectRequest(ConnectRequest {
            request_id,
            hostname: hostname.clone(),
            protocol,
            client_addr,
        }),
    )
    .await?;

    tracing::debug!(
        tunnel_id = %connector.tenant_id,
        hostname = %hostname,
        protocol = ?protocol,
        client_addr = %client_addr,
        request_id,
        "tunnel opened"
    );

    // Bidirectional copy with half-close: when one direction ends,
    // shut down the corresponding write side to propagate EOF.
    let quic_to_public = async {
        let n = tokio::io::copy(&mut quic_recv, &mut public_send)
            .await
            .unwrap_or(0);
        let _ = public_send.shutdown().await;
        n
    };
    let public_to_quic = async {
        let n = tokio::io::copy(&mut public_recv, &mut quic_send)
            .await
            .unwrap_or(0);
        let _ = quic_send.shutdown().await;
        n
    };

    let (bytes_out, bytes_in) = tokio::join!(quic_to_public, public_to_quic);
    let elapsed = start.elapsed().as_secs_f64();

    let m = metrics::global();
    m.bytes_transferred_total
        .with_label_values(&["in", &protocol.to_string()])
        .inc_by(bytes_in as f64);
    m.bytes_transferred_total
        .with_label_values(&["out", &protocol.to_string()])
        .inc_by(bytes_out as f64);
    m.tunnel_latency_seconds
        .with_label_values(&[&protocol.to_string()])
        .observe(elapsed);

    tracing::debug!(
        tunnel_id = %connector.tenant_id,
        hostname = %hostname,
        bytes_in,
        bytes_out,
        elapsed_secs = elapsed,
        "tunnel closed"
    );

    Ok(())
}

/// Forward a UDP datagram from the public interface through the QUIC tunnel.
/// The reply map is populated so that `udp_reply_loop` can route replies back.
pub async fn forward_udp_datagram(
    payload: bytes::Bytes,
    connector: Arc<ConnectorHandle>,
    hostname: String,
    client_addr: SocketAddr,
    public_socket: Arc<tokio::net::UdpSocket>,
    udp_reply_map: UdpReplyMap,
) -> anyhow::Result<()> {
    use sievetube_common::protocol::DatagramHeader;

    let request_id = next_request_id();
    let header = DatagramHeader {
        request_id,
        hostname,
    };
    let datagram = header.encode(&payload);

    // Register the mapping before sending so the reply loop can find it
    {
        let mut map = udp_reply_map.write().await;
        map.insert(request_id, (client_addr, public_socket, Instant::now()));
    }

    connector
        .connection
        .send_datagram(datagram)
        .map_err(|e| anyhow::anyhow!("failed to send datagram: {e}"))?;

    Ok(())
}

/// Receive QUIC datagrams from a Connector and route UDP replies back to clients.
/// Spawned once per authenticated Connector connection.
pub async fn udp_reply_loop(
    connection: quinn::Connection,
    udp_reply_map: UdpReplyMap,
) {
    use sievetube_common::protocol::DatagramHeader;

    loop {
        let datagram = match connection.read_datagram().await {
            Ok(d) => d,
            Err(_) => return, // connection closed
        };

        let Some((header, payload)) = DatagramHeader::decode(&datagram) else {
            tracing::warn!("received malformed UDP reply datagram from connector");
            continue;
        };

        let entry = {
            let map = udp_reply_map.read().await;
            map.get(&header.request_id).cloned()
        };

        match entry {
            Some((client_addr, socket, _)) => {
                if let Err(e) = socket.send_to(payload, client_addr).await {
                    tracing::debug!(
                        request_id = header.request_id,
                        client_addr = %client_addr,
                        error = %e,
                        "failed to send UDP reply to client"
                    );
                }
                // Remove after first reply (one reply per request for MVP)
                let mut map = udp_reply_map.write().await;
                map.remove(&header.request_id);
            }
            None => {
                tracing::debug!(
                    request_id = header.request_id,
                    "no client mapping for UDP reply (expired or unknown)"
                );
            }
        }
    }
}

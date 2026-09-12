use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::OwnedSemaphorePermit;

use sievetube_common::config::Protocol;
use sievetube_common::mesh_protocol::{MeshDatagramHeader, MeshDatagramKind};
use sievetube_common::metrics;
use sievetube_common::protocol::{self, ConnectRequest, DatagramHeader, Message};

use crate::connector_registry::ConnectorHandle;
use crate::edge_metrics;

/// QUIC stream error code used when a tunnel stream is abandoned before completion.
const STREAM_CANCELLED: u32 = 0x10;

/// Where a UDP reply for a request should be delivered.
#[derive(Clone)]
pub enum UdpReplyDestination {
    /// To the client that sent the datagram to this Edge
    Client {
        addr: SocketAddr,
        socket: Arc<tokio::net::UdpSocket>,
    },
    /// Back to the ingress Edge that forwarded the request over the mesh
    Peer {
        connection: quinn::Connection,
        ingress_edge_id: String,
        /// The ingress Edge's request id, which it uses to find its client
        request_id: u64,
        hostname: String,
    },
}

#[derive(Clone)]
pub struct UdpReplyEntry {
    pub destination: UdpReplyDestination,
    /// Mesh peer the request was sent to; only that peer may answer it
    pub expect_peer: Option<String>,
    pub created: Instant,
}

impl UdpReplyEntry {
    pub fn client(addr: SocketAddr, socket: Arc<tokio::net::UdpSocket>) -> Self {
        UdpReplyEntry {
            destination: UdpReplyDestination::Client { addr, socket },
            expect_peer: None,
            created: Instant::now(),
        }
    }

    /// A request forwarded over the mesh: the reply is accepted only from `peer`.
    pub fn client_via_peer(
        addr: SocketAddr,
        socket: Arc<tokio::net::UdpSocket>,
        peer: String,
    ) -> Self {
        UdpReplyEntry {
            destination: UdpReplyDestination::Client { addr, socket },
            expect_peer: Some(peer),
            created: Instant::now(),
        }
    }

    pub fn peer(
        connection: quinn::Connection,
        ingress_edge_id: String,
        request_id: u64,
        hostname: String,
    ) -> Self {
        UdpReplyEntry {
            destination: UdpReplyDestination::Peer {
                connection,
                ingress_edge_id,
                request_id,
                hostname,
            },
            expect_peer: None,
            created: Instant::now(),
        }
    }
}

/// Pending UDP requests awaiting a reply, bounded in size and age so that
/// requests without replies cannot accumulate state.
pub struct UdpReplyTable {
    entries: Mutex<HashMap<u64, UdpReplyEntry>>,
    max_entries: usize,
    ttl: Duration,
}

impl std::fmt::Debug for UdpReplyTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpReplyTable")
            .field("pending", &self.len())
            .field("max_entries", &self.max_entries)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl UdpReplyTable {
    pub fn new(max_entries: usize, ttl: Duration) -> Arc<Self> {
        Arc::new(UdpReplyTable {
            entries: Mutex::new(HashMap::new()),
            max_entries,
            ttl,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, UdpReplyEntry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns `false` if the table is full even after removing expired entries.
    pub fn insert(&self, request_id: u64, entry: UdpReplyEntry) -> bool {
        let mut entries = self.lock();
        if entries.len() >= self.max_entries {
            let ttl = self.ttl;
            entries.retain(|_, e| e.created.elapsed() < ttl);
            if entries.len() >= self.max_entries {
                return false;
            }
        }
        entries.insert(request_id, entry);
        true
    }

    /// Remove and return a pending entry that has not expired.
    pub fn take(&self, request_id: u64) -> Option<UdpReplyEntry> {
        self.lock()
            .remove(&request_id)
            .filter(|e| e.created.elapsed() < self.ttl)
    }

    /// Like [`UdpReplyTable::take`], but the entry is left in place when
    /// `accept` rejects it, so that the genuine reply can still claim it.
    pub fn take_if(
        &self,
        request_id: u64,
        accept: impl FnOnce(&UdpReplyEntry) -> bool,
    ) -> Option<UdpReplyEntry> {
        let mut entries = self.lock();
        if !entries.get(&request_id).is_some_and(accept) {
            return None;
        }
        entries
            .remove(&request_id)
            .filter(|e| e.created.elapsed() < self.ttl)
    }

    pub fn remove(&self, request_id: u64) {
        self.lock().remove(&request_id);
    }

    /// Whether a request id is still pending. Tells a reply for an unknown
    /// request apart from one sent by a peer the request never went to.
    pub fn contains(&self, request_id: u64) -> bool {
        self.lock().contains_key(&request_id)
    }

    /// Drop expired entries; returns how many were removed.
    pub fn purge_expired(&self) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        let ttl = self.ttl;
        entries.retain(|_, e| e.created.elapsed() < ttl);
        before - entries.len()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

pub type UdpReplyMap = Arc<UdpReplyTable>;

#[cfg(test)]
pub fn new_udp_reply_map() -> UdpReplyMap {
    UdpReplyTable::new(4096, Duration::from_secs(10))
}

static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A bidirectional QUIC stream to a Connector after the ConnectRequest was sent.
///
/// Records transfer metrics when dropped and resets the send side if it was not
/// finished, so that cancellation propagates to the Connector.
pub struct TunnelStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    protocol: Protocol,
    opened_at: Instant,
    bytes_in: u64,
    bytes_out: u64,
    send_finished: bool,
    /// Counted once per request, at the ingress Edge
    record_metrics: bool,
    /// Concurrency slots held for the lifetime of the stream
    permits: Vec<OwnedSemaphorePermit>,
}

impl TunnelStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream, protocol: Protocol) -> Self {
        TunnelStream {
            send,
            recv,
            protocol,
            opened_at: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            send_finished: false,
            record_metrics: true,
            permits: Vec::new(),
        }
    }

    /// A stream whose bytes are already accounted for elsewhere (mesh peer side).
    pub fn untracked(send: quinn::SendStream, recv: quinn::RecvStream, protocol: Protocol) -> Self {
        let mut stream = TunnelStream::new(send, recv, protocol);
        stream.record_metrics = false;
        stream
    }

    /// Hold concurrency permits until the stream is dropped.
    pub fn with_permits(mut self, permits: Vec<OwnedSemaphorePermit>) -> Self {
        self.permits = permits;
        self
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.recv).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            this.bytes_out += (buf.filled().len() - before) as u64;
        }
        poll
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = AsyncWrite::poll_write(Pin::new(&mut this.send), cx, data);
        if let Poll::Ready(Ok(n)) = poll {
            this.bytes_in += n as u64;
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.send).poll_shutdown(cx);
        if let Poll::Ready(Ok(())) = poll {
            this.send_finished = true;
        }
        poll
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        if !self.send_finished {
            let _ = self.send.reset(quinn::VarInt::from_u32(STREAM_CANCELLED));
        }
        if !self.record_metrics {
            return;
        }
        let m = metrics::global();
        let protocol = self.protocol.to_string();
        m.bytes_transferred_total
            .with_label_values(&["in", &protocol])
            .inc_by(self.bytes_in as f64);
        m.bytes_transferred_total
            .with_label_values(&["out", &protocol])
            .inc_by(self.bytes_out as f64);
        m.tunnel_latency_seconds
            .with_label_values(&[&protocol])
            .observe(self.opened_at.elapsed().as_secs_f64());
    }
}

/// Open a stream to a locally connected Connector and send the ConnectRequest.
pub async fn open_local_stream(
    connector: &ConnectorHandle,
    hostname: &str,
    protocol: Protocol,
    client_addr: SocketAddr,
) -> anyhow::Result<TunnelStream> {
    let request_id = next_request_id();
    let (mut send, recv) = connector
        .connection
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("failed to open QUIC stream: {e}"))?;

    protocol::write_message(
        &mut send,
        &Message::ConnectRequest(ConnectRequest {
            request_id,
            hostname: hostname.to_string(),
            protocol,
            client_addr,
        }),
    )
    .await?;

    tracing::debug!(
        tunnel_id = %connector.tenant_id,
        hostname,
        protocol = ?protocol,
        client_addr = %client_addr,
        request_id,
        "tunnel opened"
    );
    Ok(TunnelStream::new(send, recv, protocol))
}

/// Copy bytes in both directions with half-close: when one direction ends,
/// the corresponding write side is shut down to propagate EOF.
pub async fn pipe<S>(public: S, tunnel: TunnelStream)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut public_recv, mut public_send) = tokio::io::split(public);
    let (mut tunnel_recv, mut tunnel_send) = tokio::io::split(tunnel);

    let tunnel_to_public = async {
        let _ = tokio::io::copy(&mut tunnel_recv, &mut public_send).await;
        let _ = public_send.shutdown().await;
    };
    let public_to_tunnel = async {
        let _ = tokio::io::copy(&mut public_recv, &mut tunnel_send).await;
        let _ = tunnel_send.shutdown().await;
    };
    tokio::join!(tunnel_to_public, public_to_tunnel);
}

/// Forward a UDP datagram from the public interface through the QUIC tunnel.
/// The reply map is populated so that `udp_reply_loop` can route replies back.
pub async fn forward_udp_datagram(
    payload: bytes::Bytes,
    connector: &ConnectorHandle,
    hostname: &str,
    client_addr: SocketAddr,
    public_socket: Arc<tokio::net::UdpSocket>,
) -> anyhow::Result<()> {
    let request_id = next_request_id();
    let header = DatagramHeader {
        request_id,
        hostname: hostname.to_string(),
    };
    let datagram = header.encode(&payload);
    if connector
        .connection
        .max_datagram_size()
        .is_some_and(|max| datagram.len() > max)
    {
        edge_metrics::get()
            .udp_dropped_total
            .with_label_values(&["oversize"])
            .inc();
        anyhow::bail!(
            "datagram of {} bytes exceeds the tunnel datagram limit",
            datagram.len()
        );
    }

    // Register the mapping before sending so the reply loop can find it
    if !connector.udp_reply_map.insert(
        request_id,
        UdpReplyEntry::client(client_addr, public_socket),
    ) {
        edge_metrics::get()
            .udp_dropped_total
            .with_label_values(&["reply_table_full"])
            .inc();
        anyhow::bail!("too many UDP requests awaiting replies");
    }

    if let Err(e) = connector.connection.send_datagram(datagram) {
        connector.udp_reply_map.remove(request_id);
        edge_metrics::get()
            .udp_dropped_total
            .with_label_values(&["send_failed"])
            .inc();
        anyhow::bail!("failed to send datagram: {e}");
    }
    Ok(())
}

/// Receive QUIC datagrams from a Connector and route UDP replies back to clients.
/// Spawned once per authenticated Connector connection; also expires stale requests.
pub async fn udp_reply_loop(connection: quinn::Connection, udp_reply_map: UdpReplyMap) {
    let mut purge =
        tokio::time::interval((udp_reply_map.ttl() / 2).max(Duration::from_millis(500)));
    purge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let datagram = tokio::select! {
            _ = purge.tick() => {
                let expired = udp_reply_map.purge_expired();
                if expired > 0 {
                    edge_metrics::get().udp_dropped_total.with_label_values(&["reply_timeout"]).inc_by(expired as u64);
                }
                continue;
            }
            datagram = connection.read_datagram() => match datagram {
                Ok(d) => d,
                Err(_) => return, // connection closed
            },
        };

        let Some((header, payload)) = DatagramHeader::decode(&datagram) else {
            tracing::warn!("received malformed UDP reply datagram from connector");
            continue;
        };

        // Remove on first reply (one reply per request)
        match udp_reply_map.take(header.request_id) {
            Some(entry) => match entry.destination {
                UdpReplyDestination::Client { addr, socket } => {
                    if let Err(e) = socket.send_to(payload, addr).await {
                        tracing::debug!(
                            request_id = header.request_id,
                            client_addr = %addr,
                            error = %e,
                            "failed to send UDP reply to client"
                        );
                    }
                }
                UdpReplyDestination::Peer {
                    connection,
                    ingress_edge_id,
                    request_id,
                    hostname,
                } => {
                    let reply = match (MeshDatagramHeader {
                        kind: MeshDatagramKind::Reply,
                        request_id,
                        connection_generation: 0,
                        ingress_edge_id,
                        tenant_id: String::new(),
                        hostname,
                    })
                    .encode(payload)
                    {
                        Ok(reply) => reply,
                        Err(e) => {
                            tracing::debug!(request_id, error = %e, "cannot encode mesh UDP reply");
                            edge_metrics::get()
                                .udp_dropped_total
                                .with_label_values(&["encode_failed"])
                                .inc();
                            continue;
                        }
                    };
                    let too_large = connection
                        .max_datagram_size()
                        .is_some_and(|max| reply.len() > max);
                    if too_large {
                        edge_metrics::get()
                            .udp_dropped_total
                            .with_label_values(&["oversize"])
                            .inc();
                    } else if connection.send_datagram(reply).is_err() {
                        edge_metrics::get()
                            .udp_dropped_total
                            .with_label_values(&["send_failed"])
                            .inc();
                    }
                }
            },
            None => {
                tracing::debug!(
                    request_id = header.request_id,
                    "no client mapping for UDP reply (expired or unknown)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn entry(created: Instant) -> UdpReplyEntry {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        UdpReplyEntry {
            destination: UdpReplyDestination::Client {
                addr: "127.0.0.1:9".parse().unwrap(),
                socket,
            },
            expect_peer: None,
            created,
        }
    }

    #[tokio::test]
    async fn reply_table_is_bounded_and_expires() {
        let table = UdpReplyTable::new(2, Duration::from_millis(50));
        assert!(table.insert(1, entry(Instant::now()).await));
        assert!(table.insert(2, entry(Instant::now()).await));
        assert!(!table.insert(3, entry(Instant::now()).await), "table full");

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(table.take(1).is_none(), "expired entries are not returned");
        assert!(table.insert(3, entry(Instant::now()).await));
        assert!(
            table.insert(4, entry(Instant::now()).await),
            "expired entries are reclaimed when full"
        );
        assert_eq!(table.len(), 2);
        assert!(table.take(3).is_some());
        assert_eq!(table.purge_expired(), 0);
    }

    #[tokio::test]
    async fn take_if_keeps_entries_it_rejects() {
        let table = UdpReplyTable::new(4, Duration::from_secs(5));
        let mut pending = entry(Instant::now()).await;
        pending.expect_peer = Some("edge-b".to_string());
        assert!(table.insert(7, pending));

        // Another peer guessing the request id must not consume the entry.
        assert!(table
            .take_if(7, |e| e.expect_peer.as_deref() == Some("edge-c"))
            .is_none());
        assert_eq!(table.len(), 1);
        assert!(table
            .take_if(7, |e| e.expect_peer.as_deref() == Some("edge-b"))
            .is_some());
        assert_eq!(table.len(), 0);
    }
}

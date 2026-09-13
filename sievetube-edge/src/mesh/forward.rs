//! One-hop forwarding between Edges.
//!
//! The ingress Edge applies the traffic policy once, then opens a stream to a peer
//! that has the Connector. The receiving Edge verifies that the hostname belongs to
//! the claimed tenant and delivers only to its own Connectors: a forwarded request
//! is never forwarded again.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use sievetube_common::config::Protocol;
use sievetube_common::mesh_protocol::{
    read_forward_request, read_forward_response, write_forward_request, write_forward_response,
    ForwardRequest, ForwardResponse, MeshDatagramHeader, MeshDatagramKind, RejectReason,
    MESH_VERSION,
};
use sievetube_common::protocol::DatagramHeader;

use super::routes::{RemoteRoute, RouteTable};
use super::transport::PeerPool;
use crate::connector_registry::ConnectorRegistry;
use crate::edge_metrics;
use crate::tunnel::{self, TunnelStream, UdpReplyDestination, UdpReplyEntry, UdpReplyMap};

/// Limits that keep one peer or tenant from exhausting this Edge.
#[derive(Debug, Clone, Copy)]
pub struct MeshLimits {
    pub max_streams_per_peer: usize,
    pub max_streams_per_tenant: usize,
    /// How long to wait for a stream slot before giving up
    pub stream_wait: Duration,
    /// How long to wait for the peer to accept a forwarded request
    pub accept_timeout: Duration,
}

/// Why a forwarding attempt failed, and whether another peer may be tried.
#[derive(Debug)]
pub struct ForwardError {
    pub message: String,
    /// Nothing was forwarded yet, so another candidate is safe to try
    pub retryable: bool,
    pub timed_out: bool,
}

impl ForwardError {
    fn retryable(message: impl Into<String>) -> Self {
        ForwardError {
            message: message.into(),
            retryable: true,
            timed_out: false,
        }
    }

    fn timeout(message: impl Into<String>) -> Self {
        ForwardError {
            message: message.into(),
            retryable: true,
            timed_out: true,
        }
    }

    fn rejected(reason: Option<RejectReason>) -> Self {
        let reason = reason.unwrap_or(RejectReason::Invalid);
        ForwardError {
            message: format!("peer rejected the request: {}", reason.as_str()),
            retryable: reason.retryable(),
            timed_out: false,
        }
    }
}

/// Per-peer and per-tenant stream budgets for one direction.
///
/// Entries are created on demand and removed again by [`PermitTable::sweep`]
/// once nothing holds a permit, so that ids seen once do not accumulate for the
/// lifetime of the process.
#[derive(Default)]
struct PermitTable {
    peers: DashMap<String, Arc<Semaphore>>,
    tenants: DashMap<String, Arc<Semaphore>>,
}

impl PermitTable {
    async fn acquire(
        map: &DashMap<String, Arc<Semaphore>>,
        key: &str,
        limit: usize,
        wait: Duration,
    ) -> Option<OwnedSemaphorePermit> {
        let semaphore = map
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(limit)))
            .clone();
        tokio::time::timeout(wait, semaphore.acquire_owned())
            .await
            .ok()?
            .ok()
    }

    async fn peer(&self, peer: &str, limits: &MeshLimits) -> Option<OwnedSemaphorePermit> {
        Self::acquire(
            &self.peers,
            peer,
            limits.max_streams_per_peer,
            limits.stream_wait,
        )
        .await
    }

    async fn tenant(&self, tenant: &str, limits: &MeshLimits) -> Option<OwnedSemaphorePermit> {
        Self::acquire(
            &self.tenants,
            tenant,
            limits.max_streams_per_tenant,
            limits.stream_wait,
        )
        .await
    }

    /// Drop idle entries. Whether an entry is idle is decided while the shard is
    /// locked, which is also what acquiring needs, so an entry is never removed
    /// while a task holds or is about to hold one of its permits.
    fn sweep(&self, limits: &MeshLimits) {
        for (map, limit) in [
            (&self.peers, limits.max_streams_per_peer),
            (&self.tenants, limits.max_streams_per_tenant),
        ] {
            map.retain(|_, semaphore| {
                Arc::strong_count(semaphore) > 1 || semaphore.available_permits() < limit
            });
        }
    }
}

pub struct MeshService {
    edge_id: String,
    pool: Arc<PeerPool>,
    routes: Arc<RouteTable>,
    registry: ConnectorRegistry,
    limits: MeshLimits,
    /// Budgets for streams this Edge opens to peers
    outbound: PermitTable,
    /// Budgets for streams peers open to this Edge; kept apart from `outbound`
    /// so that the two directions do not share one tenant's budget
    inbound: PermitTable,
    /// Ingress side: UDP requests forwarded to peers, awaiting a reply.
    /// Forwarded datagrams take no stream permit; this bounded table is what
    /// limits the state a peer's UDP traffic can occupy.
    udp_replies: UdpReplyMap,
}

impl MeshService {
    pub fn new(
        edge_id: String,
        pool: Arc<PeerPool>,
        routes: Arc<RouteTable>,
        registry: ConnectorRegistry,
        limits: MeshLimits,
        udp_replies: UdpReplyMap,
    ) -> Arc<Self> {
        Arc::new(MeshService {
            edge_id,
            pool,
            routes,
            registry,
            limits,
            outbound: PermitTable::default(),
            inbound: PermitTable::default(),
            udp_replies,
        })
    }

    pub fn routes(&self) -> &Arc<RouteTable> {
        &self.routes
    }

    pub fn pool(&self) -> &Arc<PeerPool> {
        &self.pool
    }

    /// Release the budget entries of peers and tenants that are currently idle.
    pub fn sweep_permits(&self) {
        self.outbound.sweep(&self.limits);
        self.inbound.sweep(&self.limits);
    }

    /// Ingress: open a forwarding stream to the peer that has the Connector.
    pub async fn open_remote_stream(
        &self,
        route: &RemoteRoute,
        hostname: &str,
        protocol: Protocol,
        client_addr: SocketAddr,
    ) -> Result<TunnelStream, ForwardError> {
        let peer_permit = self
            .outbound
            .peer(&route.edge_id, &self.limits)
            .await
            .ok_or_else(|| {
                ForwardError::timeout(format!("no stream slot for edge {}", route.edge_id))
            })?;
        let tenant_permit = self
            .outbound
            .tenant(&route.tenant_id, &self.limits)
            .await
            .ok_or_else(|| ForwardError::timeout("no stream slot for tenant"))?;

        let connection = self
            .pool
            .connection(&route.edge_id, route.addr)
            .await
            .map_err(|e| {
                self.pool.mark_failed(&route.edge_id);
                ForwardError::retryable(format!("{e:#}"))
            })?;
        let request = ForwardRequest {
            version: MESH_VERSION,
            ingress_edge_id: self.edge_id.clone(),
            tenant_id: route.tenant_id.clone(),
            hostname: hostname.to_string(),
            protocol,
            client_addr,
            request_id: tunnel::next_request_id(),
            // One hop only: the receiving Edge must deliver locally.
            hops_remaining: 1,
            connection_generation: route.generation,
        };
        let ((send, recv), response) = tokio::time::timeout(self.limits.accept_timeout, async {
            let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
                self.pool.mark_failed(&route.edge_id);
                ForwardError::retryable(format!("cannot open mesh stream: {e}"))
            })?;
            write_forward_request(&mut send, &request)
                .await
                .map_err(|e| {
                    self.pool.mark_failed(&route.edge_id);
                    ForwardError::retryable(format!("cannot send forward request: {e}"))
                })?;
            let response = read_forward_response(&mut recv).await.map_err(|e| {
                self.pool.mark_failed(&route.edge_id);
                ForwardError::retryable(format!("invalid forward response: {e}"))
            })?;
            Ok::<_, ForwardError>(((send, recv), response))
        })
        .await
        .map_err(|_| {
            self.pool.mark_failed(&route.edge_id);
            ForwardError::timeout("peer did not answer the forward request")
        })??;
        if !response.accepted {
            return Err(ForwardError::rejected(response.reject));
        }

        edge_metrics::get()
            .mesh_forwarded_total
            .with_label_values(&[&protocol.to_string(), "opened"])
            .inc();
        Ok(TunnelStream::new(send, recv, protocol).with_permits(vec![peer_permit, tenant_permit]))
    }

    /// Receiving side: serve streams and datagrams of one authenticated peer.
    pub async fn serve_peer(
        self: Arc<Self>,
        connection: quinn::Connection,
        peer_id: String,
        shutdown: CancellationToken,
        tracker: TaskTracker,
    ) {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = connection.accept_bi() => match accepted {
                    Ok((send, recv)) => {
                        let service = self.clone();
                        let peer_id = peer_id.clone();
                        tracker.spawn(async move { service.handle_forward(send, recv, peer_id).await });
                    }
                    Err(_) => return,
                },
                datagram = connection.read_datagram() => match datagram {
                    Ok(datagram) => self.handle_datagram(datagram, &peer_id, &connection).await,
                    Err(_) => return,
                },
            }
        }
    }

    async fn handle_forward(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        peer_id: String,
    ) {
        let request =
            match tokio::time::timeout(self.limits.accept_timeout, read_forward_request(&mut recv))
                .await
            {
                Ok(Ok(request)) => request,
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer_id, error = %e, "invalid forward request");
                    let _ = write_forward_response(
                        &mut send,
                        &ForwardResponse::reject(RejectReason::Invalid),
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    let _ = write_forward_response(
                        &mut send,
                        &ForwardResponse::reject(RejectReason::Invalid),
                    )
                    .await;
                    return;
                }
            };

        let reject = |reason: RejectReason| {
            edge_metrics::get()
                .mesh_rejected_total
                .with_label_values(&[reason.as_str()])
                .inc();
            reason
        };
        if let Err(reason) = request.validate() {
            let _ =
                write_forward_response(&mut send, &ForwardResponse::reject(reject(reason))).await;
            return;
        }
        // The metadata must match the authenticated peer identity.
        if request.ingress_edge_id != peer_id {
            let _ = write_forward_response(
                &mut send,
                &ForwardResponse::reject(reject(RejectReason::NotAuthorized)),
            )
            .await;
            return;
        }
        let Some(connector) = self.registry.get_by_hostname(&request.hostname) else {
            let _ = write_forward_response(
                &mut send,
                &ForwardResponse::reject(reject(RejectReason::NoRoute)),
            )
            .await;
            return;
        };
        // Peer authentication alone does not authorize a tenant's hostname.
        if connector.tenant_id != request.tenant_id {
            tracing::warn!(peer = %peer_id, hostname = %request.hostname, "peer claimed a hostname of another tenant");
            let _ = write_forward_response(
                &mut send,
                &ForwardResponse::reject(reject(RejectReason::NotAuthorized)),
            )
            .await;
            return;
        }
        if !connector.supports(&request.hostname, request.protocol) {
            let _ = write_forward_response(
                &mut send,
                &ForwardResponse::reject(reject(RejectReason::NoRoute)),
            )
            .await;
            return;
        }

        let (Some(_peer_permit), Some(_tenant_permit)) = (
            self.inbound.peer(&peer_id, &self.limits).await,
            self.inbound.tenant(&request.tenant_id, &self.limits).await,
        ) else {
            let _ = write_forward_response(
                &mut send,
                &ForwardResponse::reject(reject(RejectReason::Overloaded)),
            )
            .await;
            return;
        };

        // The ingress Edge gives up after the same timeout, so waiting longer
        // would only hold this peer's and tenant's stream slots for nothing.
        let open = tunnel::open_local_stream(
            &connector,
            &request.hostname,
            request.protocol,
            request.client_addr,
        );
        let local = match tokio::time::timeout(self.limits.accept_timeout, open).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                tracing::debug!(hostname = %request.hostname, error = %e, "cannot open local tunnel for forwarded request");
                let _ = write_forward_response(
                    &mut send,
                    &ForwardResponse::reject(reject(RejectReason::NoRoute)),
                )
                .await;
                return;
            }
            Err(_) => {
                tracing::debug!(hostname = %request.hostname, "opening the local tunnel for a forwarded request timed out");
                let _ = write_forward_response(
                    &mut send,
                    &ForwardResponse::reject(reject(RejectReason::Overloaded)),
                )
                .await;
                return;
            }
        };
        if write_forward_response(&mut send, &ForwardResponse::accept())
            .await
            .is_err()
        {
            return;
        }
        edge_metrics::get()
            .mesh_forwarded_total
            .with_label_values(&[&request.protocol.to_string(), "accepted"])
            .inc();

        // The peer side is already accounted for by the ingress Edge's metrics.
        let peer_stream = TunnelStream::untracked(send, recv, request.protocol);
        tunnel::pipe(peer_stream, local).await;
    }

    /// Ingress: send a UDP datagram to a peer and remember where the reply goes.
    pub async fn forward_udp(
        &self,
        route: &RemoteRoute,
        hostname: &str,
        payload: Bytes,
        client_addr: SocketAddr,
        socket: Arc<tokio::net::UdpSocket>,
    ) -> anyhow::Result<()> {
        let connection = self
            .pool
            .connection(&route.edge_id, route.addr)
            .await
            .inspect_err(|_| {
                self.pool.mark_failed(&route.edge_id);
            })?;
        let request_id = tunnel::next_request_id();
        let header = MeshDatagramHeader {
            kind: MeshDatagramKind::Request,
            request_id,
            connection_generation: route.generation,
            ingress_edge_id: self.edge_id.clone(),
            tenant_id: route.tenant_id.clone(),
            hostname: hostname.to_string(),
        };
        let datagram = header.encode(&payload).inspect_err(|_| {
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["encode_failed"])
                .inc();
        })?;
        if connection
            .max_datagram_size()
            .is_some_and(|max| datagram.len() > max)
        {
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["oversize"])
                .inc();
            anyhow::bail!(
                "datagram of {} bytes exceeds the mesh datagram limit",
                datagram.len()
            );
        }
        if !self.udp_replies.insert(
            request_id,
            UdpReplyEntry::client_via_peer(client_addr, socket, route.edge_id.clone()),
        ) {
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["reply_table_full"])
                .inc();
            anyhow::bail!("too many UDP requests awaiting replies");
        }
        if let Err(e) = connection.send_datagram(datagram) {
            self.udp_replies.remove(request_id);
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["send_failed"])
                .inc();
            anyhow::bail!("cannot send mesh datagram: {e}");
        }
        Ok(())
    }

    /// Expire UDP requests whose reply never arrived.
    pub fn purge_udp(&self) {
        let expired = self.udp_replies.purge_expired();
        if expired > 0 {
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["reply_timeout"])
                .inc_by(expired as u64);
        }
    }

    async fn handle_datagram(
        &self,
        datagram: Bytes,
        peer_id: &str,
        connection: &quinn::Connection,
    ) {
        let Ok((header, payload)) = MeshDatagramHeader::decode(&datagram) else {
            tracing::debug!(peer = %peer_id, "malformed mesh datagram");
            return;
        };
        match header.kind {
            MeshDatagramKind::Request => {
                if header.ingress_edge_id != peer_id {
                    return;
                }
                let Some(connector) = self.registry.get_by_hostname(&header.hostname) else {
                    return;
                };
                if connector.tenant_id != header.tenant_id
                    || !connector.supports(&header.hostname, Protocol::Udp)
                {
                    return;
                }
                // A local request id keeps replies of different ingress Edges apart.
                let local_id = tunnel::next_request_id();
                let entry = UdpReplyEntry::peer(
                    connection.clone(),
                    header.ingress_edge_id.clone(),
                    header.request_id,
                    header.hostname.clone(),
                );
                if !connector.udp_reply_map.insert(local_id, entry) {
                    edge_metrics::get()
                        .udp_dropped_total
                        .with_label_values(&["reply_table_full"])
                        .inc();
                    return;
                }
                let to_connector = DatagramHeader {
                    request_id: local_id,
                    hostname: header.hostname,
                }
                .encode(payload);
                if connector
                    .connection
                    .max_datagram_size()
                    .is_some_and(|max| to_connector.len() > max)
                {
                    connector.udp_reply_map.remove(local_id);
                    edge_metrics::get()
                        .udp_dropped_total
                        .with_label_values(&["oversize"])
                        .inc();
                    return;
                }
                if connector.connection.send_datagram(to_connector).is_err() {
                    connector.udp_reply_map.remove(local_id);
                    edge_metrics::get()
                        .udp_dropped_total
                        .with_label_values(&["send_failed"])
                        .inc();
                }
            }
            MeshDatagramKind::Reply => {
                // Replies are only valid for requests this Edge sent.
                if header.ingress_edge_id != self.edge_id {
                    return;
                }
                // Request ids are sequential, so matching on the id alone would let
                // any authorized peer claim another peer's pending reply. The entry
                // stays in place unless the peer it was sent to is the sender.
                let claimed = self.udp_replies.take_if(header.request_id, |entry| {
                    entry.expect_peer.as_deref() == Some(peer_id)
                });
                let Some(entry) = claimed else {
                    let reason = if self.udp_replies.contains(header.request_id) {
                        tracing::warn!(peer = %peer_id, request_id = header.request_id, "peer answered a request forwarded to another peer");
                        "reply_peer_mismatch"
                    } else {
                        "unknown_reply"
                    };
                    edge_metrics::get()
                        .udp_dropped_total
                        .with_label_values(&[reason])
                        .inc();
                    return;
                };
                if let UdpReplyDestination::Client { addr, socket } = entry.destination {
                    if let Err(e) = socket.send_to(payload, addr).await {
                        tracing::debug!(client_addr = %addr, error = %e, "cannot deliver mesh UDP reply");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use sievetube_common::mesh_protocol::MESH_VERSION;

    use crate::connector_registry::Registration;
    use crate::mesh::certs::test_pki::TestPki;
    use crate::mesh::routes::RouteTable;
    use crate::mesh::transport::{build_endpoint, peer_edge_id, PeerPool};
    use crate::test_support::quic_pair;
    use crate::tunnel::UdpReplyTable;

    fn limits() -> MeshLimits {
        MeshLimits {
            max_streams_per_peer: 4,
            max_streams_per_tenant: 4,
            stream_wait: Duration::from_millis(200),
            accept_timeout: Duration::from_secs(2),
        }
    }

    fn service(
        pki: &TestPki,
        edge_id: &str,
        allowed: &[&str],
        registry: ConnectorRegistry,
    ) -> (Arc<MeshService>, quinn::Endpoint) {
        crate::test_support::install_crypto();
        let identity = pki.identity(edge_id);
        let endpoint = build_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let pool = PeerPool::new(
            endpoint.clone(),
            allowed
                .iter()
                .map(|s| s.to_string())
                .collect::<HashSet<_>>(),
            Duration::from_millis(50),
            Duration::from_secs(5),
            None,
        );
        let service = MeshService::new(
            edge_id.to_string(),
            pool,
            RouteTable::new(),
            registry,
            limits(),
            UdpReplyTable::new(64, Duration::from_secs(5)),
        );
        (service, endpoint)
    }

    fn request(hostname: &str, tenant: &str) -> ForwardRequest {
        ForwardRequest {
            version: MESH_VERSION,
            ingress_edge_id: "edge-a".to_string(),
            tenant_id: tenant.to_string(),
            hostname: hostname.to_string(),
            protocol: Protocol::Http,
            client_addr: "203.0.113.9:1234".parse().unwrap(),
            request_id: 1,
            hops_remaining: 1,
            connection_generation: 1,
        }
    }

    /// Send one forward request from edge-a to edge-b and return the response.
    async fn forward(
        pool: &Arc<PeerPool>,
        addr: SocketAddr,
        request: &ForwardRequest,
    ) -> ForwardResponse {
        let connection = pool
            .connection("edge-b", addr)
            .await
            .expect("mesh connection");
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_forward_request(&mut send, request).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), read_forward_response(&mut recv))
            .await
            .expect("peer answered")
            .expect("valid response")
    }

    #[tokio::test]
    async fn idle_stream_budgets_are_released() {
        let limits = limits();
        let table = PermitTable::default();
        let peer_permit = table.peer("edge-b", &limits).await.expect("peer permit");
        let tenant_permit = table
            .tenant("tenant-1", &limits)
            .await
            .expect("tenant permit");

        table.sweep(&limits);
        assert_eq!(table.peers.len(), 1, "a held permit keeps its entry");
        assert_eq!(table.tenants.len(), 1);

        drop((peer_permit, tenant_permit));
        table.sweep(&limits);
        assert!(table.peers.is_empty(), "ids seen once must not accumulate");
        assert!(table.tenants.is_empty());
    }

    #[tokio::test]
    async fn udp_replies_are_accepted_only_from_the_peer_they_went_to() {
        let pki = TestPki::new();
        let (service, _endpoint) = service(
            &pki,
            "edge-a",
            &["edge-b", "edge-c"],
            ConnectorRegistry::new(),
        );
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request_id = 4242;
        assert!(service.udp_replies.insert(
            request_id,
            UdpReplyEntry::client_via_peer(
                client.local_addr().unwrap(),
                socket,
                "edge-b".to_string(),
            ),
        ));
        let reply = |payload: &[u8]| {
            MeshDatagramHeader {
                kind: MeshDatagramKind::Reply,
                request_id,
                connection_generation: 0,
                ingress_edge_id: "edge-a".to_string(),
                tenant_id: String::new(),
                hostname: "game.test".to_string(),
            }
            .encode(payload)
            .expect("encoded")
        };

        let pair = quic_pair().await;
        // edge-c is an authorized peer, but this request went to edge-b.
        service
            .handle_datagram(reply(b"spoofed"), "edge-c", &pair.server)
            .await;
        service
            .handle_datagram(reply(b"genuine"), "edge-b", &pair.server)
            .await;

        let mut buf = [0u8; 64];
        let received = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("the genuine reply is delivered")
            .unwrap();
        assert_eq!(&buf[..received], b"genuine");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv(&mut buf))
                .await
                .is_err(),
            "a request is answered once"
        );
    }

    #[tokio::test]
    async fn receiving_edge_checks_ownership_hops_and_version() {
        let pki = TestPki::new();
        let registry = ConnectorRegistry::new();
        let connector = quic_pair().await;
        let _registered = registry
            .register(Registration {
                tenant_id: "tenant-1".to_string(),
                hostnames: vec!["web.test".to_string()],
                services: None,
                connection: connector.server.clone(),
                udp_reply_map: crate::tunnel::new_udp_reply_map(),
            })
            .unwrap();

        let (service_b, endpoint_b) = service(&pki, "edge-b", &["edge-a"], registry);
        let addr_b = endpoint_b.local_addr().unwrap();
        let (service_a, _endpoint_a) =
            service(&pki, "edge-a", &["edge-b"], ConnectorRegistry::new());

        let served = service_b.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint_b.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                let Some(peer) = peer_edge_id(&connection) else {
                    continue;
                };
                let service = served.clone();
                tokio::spawn(async move {
                    service
                        .serve_peer(
                            connection,
                            peer,
                            CancellationToken::new(),
                            TaskTracker::new(),
                        )
                        .await
                });
            }
        });

        let pool = service_a.pool().clone();
        // A hostname of another tenant is refused even though the peer is authenticated.
        let response = forward(&pool, addr_b, &request("web.test", "tenant-2")).await;
        assert_eq!(response.reject, Some(RejectReason::NotAuthorized));

        // Unknown hostname.
        let response = forward(&pool, addr_b, &request("other.test", "tenant-1")).await;
        assert_eq!(response.reject, Some(RejectReason::NoRoute));

        // A forwarded request must not be forwarded again.
        let mut no_hops = request("web.test", "tenant-1");
        no_hops.hops_remaining = 0;
        assert_eq!(
            forward(&pool, addr_b, &no_hops).await.reject,
            Some(RejectReason::HopLimit)
        );

        // Unknown protocol version.
        let mut future_version = request("web.test", "tenant-1");
        future_version.version = MESH_VERSION + 1;
        assert_eq!(
            forward(&pool, addr_b, &future_version).await.reject,
            Some(RejectReason::UnsupportedVersion)
        );

        // Metadata must match the authenticated peer identity.
        let mut impostor = request("web.test", "tenant-1");
        impostor.ingress_edge_id = "edge-c".to_string();
        assert_eq!(
            forward(&pool, addr_b, &impostor).await.reject,
            Some(RejectReason::NotAuthorized)
        );

        // A valid request is accepted and reaches the Connector.
        let response = forward(&pool, addr_b, &request("web.test", "tenant-1")).await;
        assert!(response.accepted, "{response:?}");
    }
}

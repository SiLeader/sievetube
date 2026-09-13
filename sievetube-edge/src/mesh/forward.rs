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
use tokio::time::Instant;
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

/// Part of a forward request's response budget the receiving Edge leaves
/// unused on top of the round trip, for scheduling delays on either side.
const ANSWER_MARGIN: Duration = Duration::from_millis(100);

/// Shortest silence after sending a request that marks a peer as gone. A live
/// peer acknowledges the request's packets within a round trip, even when it
/// is too busy to answer the request itself.
const MIN_SILENCE: Duration = Duration::from_secs(1);

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Whether `connection` received nothing at all since a request was sent on it
/// at `sent_at`, when `received` datagrams had arrived, for long enough that
/// even lost acknowledgements would have been repeated.
fn went_silent(connection: &quinn::Connection, sent_at: Instant, received: u64) -> bool {
    sent_at.elapsed() >= (connection.rtt() * 4).max(MIN_SILENCE)
        && connection.stats().udp_rx.datagrams == received
}

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

    async fn peer(
        &self,
        peer: &str,
        limits: &MeshLimits,
        wait: Duration,
    ) -> Option<OwnedSemaphorePermit> {
        Self::acquire(&self.peers, peer, limits.max_streams_per_peer, wait).await
    }

    async fn tenant(
        &self,
        tenant: &str,
        limits: &MeshLimits,
        wait: Duration,
    ) -> Option<OwnedSemaphorePermit> {
        Self::acquire(&self.tenants, tenant, limits.max_streams_per_tenant, wait).await
    }

    /// A tenant slot and then a peer slot. The tenant budget is the narrower
    /// one: a tenant that used up its own budget must not wait while holding
    /// slots of the peer budget that every other tenant shares.
    async fn tenant_and_peer(
        &self,
        tenant: &str,
        peer: &str,
        limits: &MeshLimits,
        deadline: Instant,
    ) -> Result<[OwnedSemaphorePermit; 2], &'static str> {
        let wait = |deadline: Instant| {
            limits
                .stream_wait
                .min(deadline.saturating_duration_since(Instant::now()))
        };
        let tenant_permit = self
            .tenant(tenant, limits, wait(deadline))
            .await
            .ok_or("no stream slot for tenant")?;
        let peer_permit = self
            .peer(peer, limits, wait(deadline))
            .await
            .ok_or("no stream slot for edge")?;
        Ok([tenant_permit, peer_permit])
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
        // Connecting comes first: an attempt can take the whole connect timeout,
        // and must not hold stream slots meanwhile that requests to other peers
        // could use.
        let connection = self
            .pool
            .connection(&route.edge_id, route.addr)
            .await
            .map_err(|e| ForwardError::retryable(format!("{e:#}")))?;
        let permits = self
            .outbound
            .tenant_and_peer(
                &route.tenant_id,
                &route.edge_id,
                &self.limits,
                Instant::now() + self.limits.stream_wait * 2,
            )
            .await
            .map_err(|message| {
                ForwardError::timeout(format!("{message} (edge {})", route.edge_id))
            })?;

        let mut request = ForwardRequest {
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
            response_budget_ms: None,
        };
        // A stream error cools the peer down only if it closed the shared connection.
        let failed = |message: String| {
            self.pool.connection_failed(&route.edge_id, &connection);
            ForwardError::retryable(message)
        };
        let deadline = Instant::now() + self.limits.accept_timeout;
        // When the request went out, and how many datagrams had arrived by then.
        let mut sent = None;
        let exchange = async {
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|e| failed(format!("cannot open mesh stream: {e}")))?;
            // The receiving Edge answers within the time left, so that even a
            // rejection arrives before this Edge gives up.
            request.response_budget_ms =
                Some(millis(deadline.saturating_duration_since(Instant::now())));
            write_forward_request(&mut send, &request)
                .await
                .map_err(|e| failed(format!("cannot send forward request: {e}")))?;
            sent = Some((Instant::now(), connection.stats().udp_rx.datagrams));
            let response = read_forward_response(&mut recv)
                .await
                .map_err(|e| failed(format!("invalid forward response: {e}")))?;
            Ok::<_, ForwardError>(((send, recv), response))
        };
        let outcome = tokio::time::timeout_at(deadline, exchange).await;
        let ((send, recv), response) = match outcome {
            Ok(result) => result?,
            Err(_) => {
                // A receiving Edge that is merely busy still rejects in time,
                // and dropping this stream tells it to stop waiting. Silence on
                // the whole connection is different: the peer is gone.
                if sent
                    .is_some_and(|(sent_at, received)| went_silent(&connection, sent_at, received))
                {
                    tracing::warn!(peer = %route.edge_id, "mesh peer stopped responding; closing its connection");
                    self.pool
                        .connection_unresponsive(&route.edge_id, &connection);
                }
                return Err(ForwardError::timeout(
                    "peer did not answer the forward request",
                ));
            }
        };
        if !response.accepted {
            return Err(ForwardError::rejected(response.reject));
        }

        edge_metrics::get()
            .mesh_forwarded_total
            .with_label_values(&[&protocol.to_string(), "opened"])
            .inc();
        Ok(TunnelStream::new(send, recv, protocol).with_permits(permits.into()))
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
                _ = shutdown.cancelled() => break,
                accepted = connection.accept_bi() => match accepted {
                    Ok((send, recv)) => {
                        let service = self.clone();
                        let peer_id = peer_id.clone();
                        let rtt = connection.rtt();
                        tracker.spawn(async move { service.handle_forward(send, recv, peer_id, rtt).await });
                    }
                    Err(_) => return,
                },
                datagram = connection.read_datagram() => match datagram {
                    Ok(datagram) => self.handle_datagram(datagram, &peer_id, &connection).await,
                    Err(_) => return,
                },
            }
        }

        // The connection stays open while this Edge drains, for the streams in
        // flight. New requests are refused at once, so that the peer tries
        // another Edge instead of waiting for its accept timeout.
        while let Ok((mut send, recv)) = connection.accept_bi().await {
            tokio::spawn(async move {
                edge_metrics::get()
                    .mesh_rejected_total
                    .with_label_values(&[RejectReason::Overloaded.as_str()])
                    .inc();
                let _ = write_forward_response(
                    &mut send,
                    &ForwardResponse::reject(RejectReason::Overloaded),
                )
                .await;
                // Dropped only after the response, so that the peer's request
                // is not stopped before the rejection is on its way.
                drop(recv);
            });
        }
    }

    /// When the receiving Edge must have answered a request accepted at
    /// `accepted_at`: the response still has to travel back, and the ingress
    /// Edge started its clock before the request travelled here.
    fn answer_deadline(
        &self,
        accepted_at: Instant,
        budget_ms: Option<u64>,
        rtt: Duration,
    ) -> Instant {
        // An ingress Edge that predates the budget waits for its own accept
        // timeout, which is expected to match this Edge's.
        let budget = budget_ms
            .map(Duration::from_millis)
            .unwrap_or(self.limits.accept_timeout)
            .min(self.limits.accept_timeout);
        accepted_at + budget.saturating_sub(rtt + ANSWER_MARGIN)
    }

    async fn handle_forward(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        peer_id: String,
        rtt: Duration,
    ) {
        let accepted_at = Instant::now();
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

        // A rejection that arrives after the ingress Edge gave up turns into a
        // timeout there, which cannot be told apart from a peer that is gone.
        // Waiting past the deadline would also only hold stream slots for nothing.
        let deadline = self.answer_deadline(accepted_at, request.response_budget_ms, rtt);
        let prepare = async {
            let permits = self
                .inbound
                .tenant_and_peer(&request.tenant_id, &peer_id, &self.limits, deadline)
                .await
                .map_err(|_| RejectReason::Overloaded)?;
            let open = tunnel::open_local_stream(
                &connector,
                &request.hostname,
                request.protocol,
                request.client_addr,
            );
            match tokio::time::timeout_at(deadline, open).await {
                Ok(Ok(local)) => Ok((local, permits)),
                Ok(Err(e)) => {
                    tracing::debug!(hostname = %request.hostname, error = %e, "cannot open local tunnel for forwarded request");
                    Err(RejectReason::NoRoute)
                }
                Err(_) => {
                    tracing::debug!(hostname = %request.hostname, "opening the local tunnel for a forwarded request timed out");
                    Err(RejectReason::Overloaded)
                }
            }
        };
        // An ingress Edge that gives up drops the stream, which stops this
        // sending side; nobody would read the answer any more.
        let prepared = tokio::select! {
            prepared = prepare => prepared,
            _ = send.stopped() => {
                tracing::debug!(peer = %peer_id, hostname = %request.hostname, "ingress edge abandoned the forwarded request");
                return;
            }
        };
        let (local, _permits) = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => {
                let _ = write_forward_response(&mut send, &ForwardResponse::reject(reject(reason)))
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
        let connection = self.pool.connection(&route.edge_id, route.addr).await?;
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
    use std::sync::atomic::{AtomicBool, Ordering};

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
        service_with(pki, edge_id, allowed, registry, limits())
    }

    fn service_with(
        pki: &TestPki,
        edge_id: &str,
        allowed: &[&str],
        registry: ConnectorRegistry,
        limits: MeshLimits,
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
            limits,
            UdpReplyTable::new(64, Duration::from_secs(5)),
        );
        (service, endpoint)
    }

    /// Serve every peer that connects to `endpoint`, as the mesh accept loop does.
    fn serve_peers(
        service: Arc<MeshService>,
        endpoint: quinn::Endpoint,
        shutdown: CancellationToken,
    ) {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                let Some(peer) = peer_edge_id(&connection) else {
                    continue;
                };
                let service = service.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    service
                        .serve_peer(connection, peer, shutdown, TaskTracker::new())
                        .await
                });
            }
        });
    }

    /// A registry with a Connector of tenant-1 serving web.test.
    async fn registry_with_connector() -> (ConnectorRegistry, crate::test_support::QuicPair) {
        let registry = ConnectorRegistry::new();
        let connector = quic_pair().await;
        registry
            .register(Registration {
                tenant_id: "tenant-1".to_string(),
                hostnames: vec!["web.test".to_string()],
                services: None,
                connection: connector.server.clone(),
                udp_reply_map: crate::tunnel::new_udp_reply_map(),
            })
            .unwrap();
        (registry, connector)
    }

    /// A UDP relay in front of `server` for a single client, which can go dark
    /// and drop everything like a network path that stopped working.
    async fn relay(server: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let dark = Arc::new(AtomicBool::new(false));
        let dropping = dark.clone();
        tokio::spawn(async move {
            let mut client = None;
            let mut buf = vec![0u8; 65536];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                if dropping.load(Ordering::Relaxed) {
                    continue;
                }
                let to = if from == server {
                    let Some(client) = client else { continue };
                    client
                } else {
                    client = Some(from);
                    server
                };
                let _ = socket.send_to(&buf[..len], to).await;
            }
        });
        (addr, dark)
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
            response_budget_ms: None,
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
        let permits = table
            .tenant_and_peer(
                "tenant-1",
                "edge-b",
                &limits,
                Instant::now() + limits.stream_wait,
            )
            .await
            .expect("permits");

        table.sweep(&limits);
        assert_eq!(table.peers.len(), 1, "a held permit keeps its entry");
        assert_eq!(table.tenants.len(), 1);

        drop(permits);
        table.sweep(&limits);
        assert!(table.peers.is_empty(), "ids seen once must not accumulate");
        assert!(table.tenants.is_empty());
    }

    #[tokio::test]
    async fn a_saturated_tenant_does_not_hold_the_budget_of_a_shared_peer() {
        let limits = MeshLimits {
            max_streams_per_peer: 2,
            max_streams_per_tenant: 1,
            stream_wait: Duration::from_millis(500),
            accept_timeout: Duration::from_secs(2),
        };
        let table = Arc::new(PermitTable::default());
        let deadline = || Instant::now() + limits.stream_wait;
        let _busy = table
            .tenant_and_peer("tenant-1", "edge-b", &limits, deadline())
            .await
            .expect("first request of tenant-1");

        // More requests of tenant-1 queue for its own budget ...
        let queued: Vec<_> = (0..4)
            .map(|_| {
                let table = table.clone();
                tokio::spawn(async move {
                    table
                        .tenant_and_peer(
                            "tenant-1",
                            "edge-b",
                            &limits,
                            Instant::now() + limits.stream_wait,
                        )
                        .await
                        .is_ok()
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // ... without taking the peer slot another tenant needs.
        let started = Instant::now();
        assert!(table
            .tenant_and_peer("tenant-2", "edge-b", &limits, deadline())
            .await
            .is_ok());
        assert!(started.elapsed() < Duration::from_millis(250));
        for request in queued {
            assert!(!request.await.unwrap(), "tenant-1 stays at its limit");
        }
    }

    #[tokio::test]
    async fn waiting_for_slots_ends_at_the_deadline() {
        let limits = MeshLimits {
            max_streams_per_peer: 1,
            max_streams_per_tenant: 1,
            stream_wait: Duration::from_secs(5),
            accept_timeout: Duration::from_secs(5),
        };
        let table = PermitTable::default();
        let _busy = table
            .tenant_and_peer("tenant-1", "edge-b", &limits, Instant::now())
            .await
            .expect("free slots are taken even at the deadline");
        let started = Instant::now();
        let result = table
            .tenant_and_peer(
                "tenant-1",
                "edge-b",
                &limits,
                Instant::now() + Duration::from_millis(100),
            )
            .await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn forward_timeout_does_not_fail_the_shared_connection() {
        let pki = TestPki::new();
        crate::test_support::install_crypto();
        let endpoint_a =
            build_endpoint(&pki.identity("edge-a"), "127.0.0.1:0".parse().unwrap()).unwrap();
        let pool = PeerPool::new(
            endpoint_a,
            HashSet::from(["edge-b".to_string()]),
            Duration::from_secs(5),
            Duration::from_secs(5),
            None,
        );
        let mut short_limits = limits();
        // Short enough to keep the test quick, long enough for the second
        // request to complete on a loaded machine.
        short_limits.accept_timeout = Duration::from_millis(500);
        let service = MeshService::new(
            "edge-a".to_string(),
            pool.clone(),
            RouteTable::new(),
            ConnectorRegistry::new(),
            short_limits,
            UdpReplyTable::new(64, Duration::from_secs(5)),
        );

        let endpoint_b =
            build_endpoint(&pki.identity("edge-b"), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr_b = endpoint_b.local_addr().unwrap();
        let (release_first, wait_for_release) = tokio::sync::oneshot::channel();
        let (finish_peer, wait_for_finish) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = endpoint_b.accept().await.unwrap().await.unwrap();

            let (_send, mut recv) = connection.accept_bi().await.unwrap();
            read_forward_request(&mut recv).await.unwrap();
            // Model a healthy Edge whose Connector has no stream slot yet.
            let _ = wait_for_release.await;

            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            read_forward_request(&mut recv).await.unwrap();
            write_forward_response(&mut send, &ForwardResponse::accept())
                .await
                .unwrap();
            let _ = wait_for_finish.await;
        });

        let route = RemoteRoute {
            edge_id: "edge-b".to_string(),
            tenant_id: "tenant-1".to_string(),
            generation: 1,
            addr: addr_b,
            expires_at: std::time::Instant::now() + Duration::from_secs(5),
        };
        let connection = pool.connection("edge-b", addr_b).await.unwrap();
        let stable_id = connection.stable_id();

        let result = service
            .open_remote_stream(
                &route,
                "web.test",
                Protocol::Http,
                "203.0.113.9:1234".parse().unwrap(),
            )
            .await;
        let Err(error) = result else {
            panic!("the first request should time out");
        };
        assert!(error.timed_out, "{error:?}");
        assert!(
            !pool.cooling_down("edge-b"),
            "one timed-out request must not put the peer in cooldown"
        );
        assert_eq!(
            pool.connection("edge-b", addr_b).await.unwrap().stable_id(),
            stable_id,
            "the shared connection must remain reusable"
        );

        release_first.send(()).unwrap();
        let stream = service
            .open_remote_stream(
                &route,
                "other.test",
                Protocol::Http,
                "203.0.113.10:5678".parse().unwrap(),
            )
            .await
            .expect("an unrelated request still uses the shared connection");
        drop(stream);
        finish_peer.send(()).unwrap();
        peer.await.unwrap();
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
    async fn a_peer_that_goes_silent_is_given_up() {
        let pki = TestPki::new();
        let mut ingress_limits = limits();
        // Long enough for the silence to count, see `MIN_SILENCE`.
        ingress_limits.accept_timeout = MIN_SILENCE + Duration::from_millis(500);
        let (service_a, _endpoint_a) = service_with(
            &pki,
            "edge-a",
            &["edge-b"],
            ConnectorRegistry::new(),
            ingress_limits,
        );
        let pool = service_a.pool().clone();

        let endpoint_b =
            build_endpoint(&pki.identity("edge-b"), "127.0.0.1:0".parse().unwrap()).unwrap();
        let (addr, dark) = relay(endpoint_b.local_addr().unwrap()).await;
        let peer = tokio::spawn(async move {
            let connection = endpoint_b.accept().await.unwrap().await.unwrap();
            connection.closed().await
        });
        let connection = pool.connection("edge-b", addr).await.unwrap();

        // The path goes dark: not even acknowledgements come back.
        dark.store(true, Ordering::Relaxed);
        let route = RemoteRoute {
            edge_id: "edge-b".to_string(),
            tenant_id: "tenant-1".to_string(),
            generation: 1,
            addr,
            expires_at: std::time::Instant::now() + Duration::from_secs(5),
        };
        let Err(error) = service_a
            .open_remote_stream(
                &route,
                "web.test",
                Protocol::Http,
                "203.0.113.9:1234".parse().unwrap(),
            )
            .await
        else {
            panic!("a silent peer cannot accept the request");
        };
        assert!(error.timed_out, "{error:?}");
        assert!(
            connection.close_reason().is_some(),
            "the dead connection is not kept until the idle timeout"
        );
        assert!(pool.cooling_down("edge-b"));
        peer.abort();
    }

    #[tokio::test]
    async fn receiving_edge_answers_within_the_response_budget() {
        let pki = TestPki::new();
        let (registry, _connector) = registry_with_connector().await;
        // Waiting for a slot as configured would take far longer than the
        // ingress Edge is prepared to wait.
        let receiving_limits = MeshLimits {
            max_streams_per_peer: 4,
            max_streams_per_tenant: 1,
            stream_wait: Duration::from_secs(10),
            accept_timeout: Duration::from_secs(10),
        };
        let (service_b, endpoint_b) =
            service_with(&pki, "edge-b", &["edge-a"], registry, receiving_limits);
        let addr_b = endpoint_b.local_addr().unwrap();
        let _busy = service_b
            .inbound
            .tenant("tenant-1", &receiving_limits, Duration::ZERO)
            .await
            .expect("the only slot of tenant-1");
        serve_peers(service_b, endpoint_b, CancellationToken::new());
        let (service_a, _endpoint_a) =
            service(&pki, "edge-a", &["edge-b"], ConnectorRegistry::new());

        let budget = Duration::from_millis(800);
        let mut budgeted = request("web.test", "tenant-1");
        budgeted.response_budget_ms = Some(millis(budget));
        let started = Instant::now();
        let response = forward(service_a.pool(), addr_b, &budgeted).await;
        assert_eq!(response.reject, Some(RejectReason::Overloaded));
        assert!(
            started.elapsed() < budget,
            "the rejection must arrive while the ingress Edge still waits: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_draining_edge_refuses_new_requests_at_once() {
        let pki = TestPki::new();
        let (registry, _connector) = registry_with_connector().await;
        let (service_b, endpoint_b) = service(&pki, "edge-b", &["edge-a"], registry);
        let addr_b = endpoint_b.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        serve_peers(service_b, endpoint_b, shutdown.clone());
        let (service_a, _endpoint_a) =
            service(&pki, "edge-a", &["edge-b"], ConnectorRegistry::new());
        let pool = service_a.pool().clone();
        let response = forward(&pool, addr_b, &request("web.test", "tenant-1")).await;
        assert!(response.accepted, "{response:?}");

        shutdown.cancel();
        // Let the peer's serving task see the shutdown first.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        let response = forward(&pool, addr_b, &request("web.test", "tenant-1")).await;
        assert_eq!(response.reject, Some(RejectReason::Overloaded));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn receiving_edge_checks_ownership_hops_and_version() {
        let pki = TestPki::new();
        let (registry, _connector) = registry_with_connector().await;
        let (service_b, endpoint_b) = service(&pki, "edge-b", &["edge-a"], registry);
        let addr_b = endpoint_b.local_addr().unwrap();
        let (service_a, _endpoint_a) =
            service(&pki, "edge-a", &["edge-b"], ConnectorRegistry::new());
        serve_peers(service_b, endpoint_b, CancellationToken::new());

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

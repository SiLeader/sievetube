use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use sievetube_common::config::Protocol;

use crate::edge_metrics;
use crate::policy::Policy;
use crate::router::{RouteDecision, Router};
use crate::tunnel;

/// Forwarded datagrams in flight per UDP listener. Forwarding is done off the
/// receive loop, and this bounds how much that can accumulate.
const MAX_INFLIGHT_FORWARDS: usize = 1024;

/// Accept raw TCP connections (non-HTTP) on a dedicated port.
///
/// Since there is no protocol-level hostname signal in raw TCP, routing is
/// done by a configured hostname associated with this listen port.
pub async fn serve_raw_tcp(
    listener: TcpListener,
    listen_addr: String,
    hostname: String,
    router: Router,
    policy: Arc<Policy>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) {
    loop {
        let (stream, client_addr) = tokio::select! {
            _ = shutdown.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "raw TCP accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };

        // Policy is checked before any routing work; the permit holds a
        // concurrency slot until the connection task ends.
        let (verdict, permit) = policy.admit_tcp(&listen_addr, client_addr.ip());
        if verdict.rejects() {
            drop(stream);
            continue;
        }

        let router = router.clone();
        let hostname = hostname.clone();
        tracker.spawn(async move {
            let _permit = permit;
            let decision = router.route(&hostname, Protocol::Tcp);
            if !decision.is_available() {
                tracing::debug!(client_addr = %client_addr, hostname, "no route for TCP");
                return;
            }
            match router
                .open(&decision, &hostname, Protocol::Tcp, client_addr)
                .await
            {
                Ok(tunnel) => tunnel::pipe(stream, tunnel).await,
                Err(e) => tracing::debug!(hostname, error = %e.message, "TCP tunnel error"),
            }
        });
    }
}

/// Receive UDP datagrams and forward them via QUIC datagrams, locally or over the mesh.
pub async fn serve_udp(
    socket: Arc<UdpSocket>,
    listen_addr: String,
    hostname: String,
    router: Router,
    policy: Arc<Policy>,
    shutdown: CancellationToken,
) {
    let mut buf = vec![0u8; 65535];
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_FORWARDS));
    loop {
        let (n, client_addr) = tokio::select! {
            _ = shutdown.cancelled() => return,
            received = socket.recv_from(&mut buf) => match received {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "UDP receive failed");
                    continue;
                }
            },
        };

        // Limits are applied before routing and before any reply state is allocated.
        if policy
            .admit_udp(&listen_addr, client_addr.ip(), n)
            .rejects()
        {
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["policy"])
                .inc();
            continue;
        }

        let payload = Bytes::copy_from_slice(&buf[..n]);
        let decision = router.route(&hostname, Protocol::Udp);
        if !decision.is_available() {
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["no_route"])
                .inc();
            continue;
        }

        // Forwarding to a peer can wait for a QUIC handshake, so it must not run
        // in the receive loop: the kernel buffer would overflow and datagrams of
        // every listener served by this task would be lost.
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["forward_backlog"])
                .inc();
            continue;
        };
        let router = router.clone();
        let hostname = hostname.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let _permit = permit;
            forward_datagram(&router, decision, payload, &hostname, client_addr, socket).await;
        });
    }
}

/// Deliver one datagram to a local Connector or, over the mesh, to a peer Edge.
async fn forward_datagram(
    router: &Router,
    decision: RouteDecision,
    payload: Bytes,
    hostname: &str,
    client_addr: SocketAddr,
    socket: Arc<UdpSocket>,
) {
    match decision {
        RouteDecision::Local(connector) => {
            if let Err(e) =
                tunnel::forward_udp_datagram(payload, &connector, hostname, client_addr, socket)
                    .await
            {
                tracing::debug!(error = %e, "UDP tunnel error");
            }
        }
        RouteDecision::Remote(routes) => {
            let Some(mesh) = router.mesh() else {
                return;
            };
            for route in &routes {
                match mesh
                    .forward_udp(
                        route,
                        hostname,
                        payload.clone(),
                        client_addr,
                        socket.clone(),
                    )
                    .await
                {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::debug!(peer = %route.edge_id, error = %e, "mesh UDP forward failed")
                    }
                }
            }
            edge_metrics::get()
                .udp_dropped_total
                .with_label_values(&["no_route"])
                .inc();
        }
        // Checked before spawning, so there is nothing left to deliver.
        RouteDecision::Unavailable => {}
    }
}

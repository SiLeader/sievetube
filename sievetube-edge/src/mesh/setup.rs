//! Starting the mesh: identity, endpoint, peers, routes and background tasks.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use anyhow::Context;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use sievetube_common::error::app_error;

use super::certs::MeshIdentity;
use super::forward::{MeshLimits, MeshService};
use super::routes::{EdgeInfo, RouteAdvertiser, RouteSync, RouteTable};
use super::transport::{self, PeerPool};
use crate::config::MeshConfig;
use crate::connector_registry::ConnectorRegistry;
use crate::edge_metrics;
use crate::tunnel::UdpReplyTable;
use crate::valkey::ValkeyHandle;

/// A running mesh.
pub struct MeshRuntime {
    pub service: Arc<MeshService>,
    pub advertiser: Option<Arc<RouteAdvertiser>>,
    endpoint: quinn::Endpoint,
}

impl MeshRuntime {
    /// Stop accepting and close peer connections after in-flight streams drained.
    pub fn close(&self) {
        self.service.pool().close_all(b"edge shutting down");
        self.endpoint.close(
            quinn::VarInt::from_u32(app_error::GOING_AWAY),
            b"edge shutting down",
        );
    }
}

/// Build the mesh and start its background tasks.
pub async fn start(
    cfg: &MeshConfig,
    registry: ConnectorRegistry,
    valkey: Option<ValkeyHandle>,
    udp_reply_timeout: Duration,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) -> anyhow::Result<MeshRuntime> {
    let identity = MeshIdentity::load(
        &cfg.edge_id,
        Path::new(&cfg.ca_cert),
        Path::new(&cfg.cert),
        Path::new(&cfg.key),
    )?;
    let listen: SocketAddr = cfg.listen.parse().context("mesh.listen")?;
    let endpoint = transport::build_endpoint(&identity, listen)?;
    let allowed: HashSet<String> = cfg.peers.iter().map(|peer| peer.edge_id.clone()).collect();
    let routes = RouteTable::new();

    // Connections this Edge opens are served too: peers send replies and may open
    // streams back over the same connection. The hook is owned by the pool, which
    // the service owns, so it must hold a weak reference: an `Arc` here would make
    // the mesh runtime and every pooled connection unreclaimable.
    let service_slot: Arc<OnceLock<Weak<MeshService>>> = Arc::new(OnceLock::new());
    let hook_slot = service_slot.clone();
    let hook_shutdown = shutdown.clone();
    let hook_tracker = tracker.clone();
    let pool = PeerPool::new(
        endpoint.clone(),
        allowed.clone(),
        Duration::from_secs(cfg.peer_failure_cooldown_secs),
        cfg.connect_timeout(),
        Some(Arc::new(
            move |edge_id: &str, connection: &quinn::Connection| {
                let Some(service) = hook_slot.get().and_then(Weak::upgrade) else {
                    return;
                };
                let (connection, peer) = (connection.clone(), edge_id.to_string());
                let (shutdown, tracker) = (hook_shutdown.clone(), hook_tracker.clone());
                tokio::spawn(async move {
                    service
                        .serve_peer(connection, peer, shutdown, tracker)
                        .await
                });
            },
        )),
    );

    let service = MeshService::new(
        cfg.edge_id.clone(),
        pool,
        routes.clone(),
        registry.clone(),
        MeshLimits {
            max_streams_per_peer: cfg.max_streams_per_peer,
            max_streams_per_tenant: cfg.max_streams_per_tenant,
            stream_wait: cfg.stream_wait(),
            accept_timeout: cfg.accept_timeout(),
        },
        UdpReplyTable::new(cfg.max_pending_udp_replies, udp_reply_timeout),
    );
    let _ = service_slot.set(Arc::downgrade(&service));

    tokio::spawn(accept_loop(
        endpoint.clone(),
        service.clone(),
        shutdown.clone(),
        tracker.clone(),
    ));
    tokio::spawn(maintenance_loop(
        service.clone(),
        udp_reply_timeout,
        shutdown.clone(),
    ));

    let advertiser = valkey.clone().map(|valkey| {
        RouteAdvertiser::new(
            valkey,
            registry,
            cfg.edge_id.clone(),
            EdgeInfo {
                advertise: cfg.advertise.clone(),
                udp: cfg.udp,
            },
            cfg.route_ttl(),
            cfg.route_refresh(),
        )
    });
    if let Some(advertiser) = advertiser.clone() {
        tokio::spawn(advertiser.run(shutdown.clone()));
    }
    if let Some(valkey) = valkey {
        let static_addrs: HashMap<String, SocketAddr> = cfg
            .peers
            .iter()
            .filter_map(|peer| Some((peer.edge_id.clone(), peer.addr.as_ref()?.parse().ok()?)))
            .collect();
        let sync = RouteSync::new(
            valkey,
            routes,
            cfg.edge_id.clone(),
            allowed,
            static_addrs,
            cfg.route_refresh(),
        );
        tokio::spawn(sync.run(shutdown.clone()));
    }

    tracing::info!(
        edge_id = %identity.edge_id,
        listen = %cfg.listen,
        advertise = %cfg.advertise,
        peers = cfg.peers.len(),
        "mesh forwarding enabled"
    );
    Ok(MeshRuntime {
        service,
        advertiser,
        endpoint,
    })
}

/// Accept peer connections and serve their forwarded streams and datagrams.
async fn accept_loop(
    endpoint: quinn::Endpoint,
    service: Arc<MeshService>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) {
    loop {
        let incoming = tokio::select! {
            _ = shutdown.cancelled() => return,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => return,
            },
        };
        let service = service.clone();
        let shutdown = shutdown.clone();
        let tracker = tracker.clone();
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            let Ok(connection) = incoming.await else {
                return;
            };
            let Some(peer) = transport::peer_edge_id(&connection) else {
                tracing::warn!(remote_addr = %remote, "mesh peer without a usable edge identity");
                connection.close(app_error::AUTH_FAILED.into(), b"unknown peer identity");
                return;
            };
            if !service.pool().is_allowed(&peer) {
                tracing::warn!(remote_addr = %remote, peer = %peer, "mesh peer is not in the configured peer list");
                connection.close(app_error::AUTH_FAILED.into(), b"peer not allowed");
                return;
            }
            tracing::info!(peer = %peer, remote_addr = %remote, "mesh peer connected");
            edge_metrics::get().mesh_peers.inc();
            service
                .serve_peer(connection, peer.clone(), shutdown, tracker)
                .await;
            edge_metrics::get().mesh_peers.dec();
            tracing::info!(peer = %peer, "mesh peer disconnected");
        });
    }
}

/// Expire forwarded UDP requests whose reply never came back and release the
/// stream budgets of peers and tenants that are no longer forwarding.
async fn maintenance_loop(service: Arc<MeshService>, ttl: Duration, shutdown: CancellationToken) {
    let mut ticker = tokio::time::interval((ttl / 2).max(Duration::from_millis(500)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {
                service.purge_udp();
                service.sweep_permits();
            }
        }
    }
}

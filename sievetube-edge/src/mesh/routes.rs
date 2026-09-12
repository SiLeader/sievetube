//! Route advertisement and lookup for the mesh.
//!
//! Each Edge advertises the hostnames its authenticated Connectors serve, with the
//! Connector's registration generation, into Valkey with a TTL. Other Edges keep a
//! local cache and use an entry only while it is unexpired, so routes of a crashed
//! Edge disappear on their own, a reconnecting Connector's newer generation is not
//! removed by the old one's disconnect, and a control-plane outage never stops
//! forwarding to local Connectors.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use sievetube_common::config::Protocol;

use crate::connector_registry::ConnectorRegistry;
use crate::valkey::ValkeyHandle;

/// One advertised route. Serialized as the Valkey sorted-set member, so the
/// field names are short and the encoding must stay stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAd {
    #[serde(rename = "h")]
    pub hostname: String,
    #[serde(rename = "p")]
    pub protocol: Protocol,
    #[serde(rename = "t")]
    pub tenant_id: String,
    #[serde(rename = "e")]
    pub edge_id: String,
    #[serde(rename = "g")]
    pub generation: u64,
}

/// What this Edge publishes about itself for peers to reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeInfo {
    pub advertise: String,
    /// Whether this Edge can forward UDP datagrams
    #[serde(default)]
    pub udp: bool,
}

/// A usable remote route with the peer's reachable address.
#[derive(Debug, Clone)]
pub struct RemoteRoute {
    pub edge_id: String,
    pub tenant_id: String,
    pub generation: u64,
    pub addr: SocketAddr,
    pub expires_at: Instant,
}

/// Deterministic order so that every Edge prefers the same peer for a hostname.
fn rank(hostname: &str, edge_id: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in hostname
        .bytes()
        .chain(b"|".iter().copied())
        .chain(edge_id.bytes())
    {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Remote routes learned from the control plane.
#[derive(Default)]
pub struct RouteTable {
    routes: ArcSwap<HashMap<(String, Protocol), Vec<RemoteRoute>>>,
}

impl RouteTable {
    pub fn new() -> Arc<Self> {
        Arc::new(RouteTable::default())
    }

    pub fn replace(&self, routes: HashMap<(String, Protocol), Vec<RemoteRoute>>) {
        self.routes.store(Arc::new(routes));
    }

    /// Unexpired candidates in a stable order.
    pub fn candidates(&self, hostname: &str, protocol: Protocol, now: Instant) -> Vec<RemoteRoute> {
        let routes = self.routes.load();
        let mut candidates: Vec<RemoteRoute> = routes
            .get(&(hostname.to_string(), protocol))
            .map(|routes| {
                routes
                    .iter()
                    .filter(|r| r.expires_at > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        candidates.sort_by_key(|route| (rank(hostname, &route.edge_id), route.edge_id.clone()));
        candidates
    }
}

/// The routes this Edge currently serves locally.
pub fn local_ads(registry: &ConnectorRegistry, edge_id: &str) -> Vec<RouteAd> {
    let mut ads = Vec::new();
    for handle in registry.snapshot() {
        for hostname in &handle.hostnames {
            for protocol in [Protocol::Http, Protocol::Tcp, Protocol::Udp] {
                if handle.supports(hostname, protocol) {
                    ads.push(RouteAd {
                        hostname: hostname.clone(),
                        protocol,
                        tenant_id: handle.tenant_id.clone(),
                        edge_id: edge_id.to_string(),
                        generation: handle.generation,
                    });
                }
            }
        }
    }
    ads
}

/// Routes a single Connector registration contributes (used when it disconnects).
pub fn ads_for(
    hostnames: &[String],
    supports: impl Fn(&str, Protocol) -> bool,
    tenant_id: &str,
    edge_id: &str,
    generation: u64,
) -> Vec<RouteAd> {
    let mut ads = Vec::new();
    for hostname in hostnames {
        for protocol in [Protocol::Http, Protocol::Tcp, Protocol::Udp] {
            if supports(hostname, protocol) {
                ads.push(RouteAd {
                    hostname: hostname.clone(),
                    protocol,
                    tenant_id: tenant_id.to_string(),
                    edge_id: edge_id.to_string(),
                    generation,
                });
            }
        }
    }
    ads
}

/// Publishes this Edge's presence and routes while it is running.
pub struct RouteAdvertiser {
    valkey: ValkeyHandle,
    registry: ConnectorRegistry,
    edge_id: String,
    info: EdgeInfo,
    ttl: Duration,
    refresh: Duration,
}

impl RouteAdvertiser {
    pub fn new(
        valkey: ValkeyHandle,
        registry: ConnectorRegistry,
        edge_id: String,
        info: EdgeInfo,
        ttl: Duration,
        refresh: Duration,
    ) -> Arc<Self> {
        Arc::new(RouteAdvertiser {
            valkey,
            registry,
            edge_id,
            info,
            ttl,
            refresh,
        })
    }

    /// Advertise the current routes once.
    pub async fn advertise_now(&self) {
        if let Err(e) = self.valkey.publish_edge_info(&self.info, self.ttl).await {
            tracing::debug!(error = %e, "cannot publish edge info");
            return;
        }
        let ads = local_ads(&self.registry, &self.edge_id);
        if let Err(e) = self.valkey.publish_routes(&ads, self.ttl).await {
            tracing::debug!(error = %e, "cannot advertise routes");
        }
    }

    /// Withdraw the routes of a disconnected registration. The generation is part
    /// of each advertisement, so a newer registration's routes are left in place.
    pub async fn withdraw_registration(&self, handle: &crate::connector_registry::ConnectorHandle) {
        let ads = ads_for(
            &handle.hostnames,
            |hostname, protocol| handle.supports(hostname, protocol),
            &handle.tenant_id,
            &self.edge_id,
            handle.generation,
        );
        self.withdraw(&ads).await;
    }

    /// Withdraw the routes of one registration; only the matching generation is removed.
    pub async fn withdraw(&self, ads: &[RouteAd]) {
        if let Err(e) = self.valkey.withdraw_routes(ads).await {
            tracing::debug!(error = %e, "cannot withdraw routes");
        }
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(self.refresh);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let ads = local_ads(&self.registry, &self.edge_id);
                    self.withdraw(&ads).await;
                    let _ = self.valkey.remove_edge_info().await;
                    return;
                }
                _ = ticker.tick() => self.advertise_now().await,
            }
        }
    }
}

/// Keeps the local route cache in sync with the control plane.
pub struct RouteSync {
    valkey: ValkeyHandle,
    table: Arc<RouteTable>,
    edge_id: String,
    allowed_peers: HashSet<String>,
    /// Addresses from the configuration, preferred over advertised ones
    static_addrs: HashMap<String, SocketAddr>,
    refresh: Duration,
}

impl RouteSync {
    pub fn new(
        valkey: ValkeyHandle,
        table: Arc<RouteTable>,
        edge_id: String,
        allowed_peers: HashSet<String>,
        static_addrs: HashMap<String, SocketAddr>,
        refresh: Duration,
    ) -> Arc<Self> {
        Arc::new(RouteSync {
            valkey,
            table,
            edge_id,
            allowed_peers,
            static_addrs,
            refresh,
        })
    }

    /// Read all advertised routes and rebuild the cache.
    pub async fn sync(&self) -> anyhow::Result<()> {
        let ads = self.valkey.fetch_routes().await?;
        let live: HashSet<String> = self.valkey.live_edges().await?.into_iter().collect();
        let peers: HashSet<String> = ads
            .iter()
            .map(|(ad, _)| ad.edge_id.clone())
            .filter(|edge| {
                edge != &self.edge_id && self.allowed_peers.contains(edge) && live.contains(edge)
            })
            .collect();
        let infos = self.valkey.fetch_edge_infos(&peers).await?;

        let now = Instant::now();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut routes: HashMap<(String, Protocol), Vec<RemoteRoute>> = HashMap::new();
        for (ad, expiry_ms) in ads {
            if !peers.contains(&ad.edge_id) {
                continue;
            }
            let Some(info) = infos.get(&ad.edge_id) else {
                continue;
            };
            // A peer that cannot forward UDP must not be offered UDP traffic.
            if ad.protocol == Protocol::Udp && !info.udp {
                continue;
            }
            let addr = match self.static_addrs.get(&ad.edge_id) {
                Some(addr) => *addr,
                None => match info.advertise.parse::<SocketAddr>() {
                    Ok(addr) => addr,
                    Err(_) => {
                        tracing::debug!(edge = %ad.edge_id, advertise = %info.advertise, "ignoring peer with an unusable advertised address");
                        continue;
                    }
                },
            };
            let remaining = Duration::from_millis(expiry_ms.saturating_sub(now_ms));
            routes
                .entry((ad.hostname.clone(), ad.protocol))
                .or_default()
                .push(RemoteRoute {
                    edge_id: ad.edge_id,
                    tenant_id: ad.tenant_id,
                    generation: ad.generation,
                    addr,
                    expires_at: now + remaining,
                });
        }
        let count = routes.values().map(Vec::len).sum::<usize>();
        self.table.replace(routes);
        crate::edge_metrics::get().mesh_routes.set(count as i64);
        Ok(())
    }

    /// Sync periodically, waking early when a peer announces a change.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        use futures_util::StreamExt;

        let mut subscriber = self.valkey.route_change_subscriber().await.ok();
        loop {
            if let Err(e) = self.sync().await {
                tracing::debug!(error = %e, "route sync failed; keeping cached routes until they expire");
            }
            // `false` means the subscription ended, which resolves immediately
            // from then on: without dropping it the loop would spin.
            let notified = async {
                match subscriber.as_mut() {
                    Some(pubsub) => pubsub.on_message().next().await.is_some(),
                    // Without notifications the periodic sync is the only trigger.
                    None => std::future::pending::<bool>().await,
                }
            };
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(self.refresh) => {
                    if subscriber.is_none() {
                        subscriber = self.valkey.route_change_subscriber().await.ok();
                    }
                }
                received = notified => {
                    if !received {
                        tracing::debug!("route change subscription ended; resubscribing on the next refresh");
                        subscriber = None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(edge: &str, expires_in: Duration) -> RemoteRoute {
        RemoteRoute {
            edge_id: edge.to_string(),
            tenant_id: "tenant".to_string(),
            generation: 1,
            addr: "127.0.0.1:4434".parse().unwrap(),
            expires_at: Instant::now() + expires_in,
        }
    }

    #[test]
    fn candidates_are_stable_and_expire() {
        let table = RouteTable::new();
        let key = ("web.example.com".to_string(), Protocol::Http);
        table.replace(HashMap::from([(
            key.clone(),
            vec![
                route("edge-b", Duration::from_secs(30)),
                route("edge-c", Duration::from_secs(30)),
                route("edge-d", Duration::from_millis(0)),
            ],
        )]));

        let now = Instant::now();
        let first = table.candidates("web.example.com", Protocol::Http, now);
        assert_eq!(first.len(), 2, "expired routes are not returned");
        let again = table.candidates("web.example.com", Protocol::Http, now);
        assert_eq!(
            first.iter().map(|r| &r.edge_id).collect::<Vec<_>>(),
            again.iter().map(|r| &r.edge_id).collect::<Vec<_>>()
        );
        assert!(table
            .candidates("web.example.com", Protocol::Tcp, now)
            .is_empty());
        assert!(table
            .candidates("other.example.com", Protocol::Http, now)
            .is_empty());
    }

    #[test]
    fn different_hostnames_spread_over_peers() {
        let edges = ["edge-b", "edge-c", "edge-d"];
        let preferred: HashSet<&str> = ["a.test", "b.test", "c.test", "d.test", "e.test"]
            .iter()
            .map(|hostname| {
                *edges
                    .iter()
                    .min_by_key(|edge| rank(hostname, edge))
                    .expect("edges")
            })
            .collect();
        assert!(
            preferred.len() > 1,
            "one peer must not absorb every hostname"
        );
    }

    #[test]
    fn ads_cover_supported_protocols_only() {
        let ads = ads_for(
            &["web.example.com".to_string()],
            |_, protocol| protocol != Protocol::Udp,
            "tenant-1",
            "edge-a",
            7,
        );
        assert_eq!(ads.len(), 2);
        assert!(ads
            .iter()
            .all(|ad| ad.generation == 7 && ad.edge_id == "edge-a"));
        assert!(!ads.iter().any(|ad| ad.protocol == Protocol::Udp));
    }

    #[test]
    fn route_ads_serialize_compactly() {
        let ad = RouteAd {
            hostname: "web.example.com".into(),
            protocol: Protocol::Http,
            tenant_id: "tenant-1".into(),
            edge_id: "edge-a".into(),
            generation: 3,
        };
        let encoded = serde_json::to_string(&ad).unwrap();
        assert_eq!(
            encoded,
            r#"{"h":"web.example.com","p":"http","t":"tenant-1","e":"edge-a","g":3}"#
        );
        assert_eq!(serde_json::from_str::<RouteAd>(&encoded).unwrap(), ad);
    }
}

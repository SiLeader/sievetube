use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

use sievetube_common::auth::TunnelClaims;

use crate::tunnel::UdpReplyMap;

#[derive(Debug)]
pub struct ConnectorHandle {
    pub tenant_id: String,
    pub hostnames: Vec<String>,
    pub connection: quinn::Connection,
    pub connected_at: Instant,
    pub udp_reply_map: UdpReplyMap,
}

/// Thread-safe registry of active Connector QUIC connections.
///
/// Keyed by hostname → ConnectorHandle so that routing is O(1).
/// A single tenant may only hold one connection per Edge per hostname.
#[derive(Default, Clone)]
pub struct ConnectorRegistry {
    /// hostname (lowercase) → connector
    by_hostname: Arc<DashMap<String, Arc<ConnectorHandle>>>,
    /// tenant_id → list of owned hostnames (for cleanup on disconnect)
    by_tenant: Arc<DashMap<String, Vec<String>>>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        claims: &TunnelClaims,
        connection: quinn::Connection,
        udp_reply_map: UdpReplyMap,
    ) -> Result<(), String> {
        let tenant_id = &claims.sub;

        // Check for hostname conflicts with other tenants
        for hostname in &claims.hostnames {
            let key = hostname.to_lowercase();
            if let Some(existing) = self.by_hostname.get(&key) {
                if existing.tenant_id != *tenant_id {
                    return Err(format!(
                        "hostname {hostname} is already owned by tenant {}",
                        existing.tenant_id
                    ));
                }
            }
        }

        // Disconnect any existing connection for this tenant
        self.remove_tenant(tenant_id);

        let handle = Arc::new(ConnectorHandle {
            tenant_id: tenant_id.clone(),
            hostnames: claims.hostnames.clone(),
            connection,
            connected_at: Instant::now(),
            udp_reply_map,
        });

        for hostname in &claims.hostnames {
            self.by_hostname
                .insert(hostname.to_lowercase(), handle.clone());
        }
        self.by_tenant
            .insert(tenant_id.clone(), claims.hostnames.iter().map(|h| h.to_lowercase()).collect());

        sievetube_common::metrics::global()
            .active_quic_connections
            .inc();

        tracing::info!(
            tenant_id,
            hostnames = ?claims.hostnames,
            "connector registered"
        );
        Ok(())
    }

    pub fn remove_tenant(&self, tenant_id: &str) {
        if let Some((_, hostnames)) = self.by_tenant.remove(tenant_id) {
            for h in &hostnames {
                self.by_hostname.remove(h);
            }
            sievetube_common::metrics::global()
                .active_quic_connections
                .dec();
            tracing::info!(tenant_id, "connector deregistered");
        }
    }

    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<ConnectorHandle>> {
        self.by_hostname
            .get(&hostname.to_lowercase())
            .map(|r| r.clone())
    }

    pub fn len(&self) -> usize {
        self.by_tenant.len()
    }
}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use dashmap::DashMap;

use sievetube_common::config::Protocol;

use crate::tunnel::UdpReplyMap;

#[derive(Debug)]
pub struct ConnectorHandle {
    pub tenant_id: String,
    /// Normalized hostnames authorized by the Connector's JWT
    pub hostnames: Vec<String>,
    /// Protocols served per hostname; `None` for Connectors that do not advertise them
    pub services: Option<HashMap<String, Vec<Protocol>>>,
    pub connection: quinn::Connection,
    pub connected_at: Instant,
    pub udp_reply_map: UdpReplyMap,
    /// Unique per registration so that a stale disconnect cannot remove a newer connection
    pub generation: u64,
}

impl ConnectorHandle {
    pub fn supports(&self, hostname: &str, protocol: Protocol) -> bool {
        match &self.services {
            None => self.hostnames.iter().any(|h| h == hostname),
            Some(services) => services
                .get(hostname)
                .is_some_and(|protocols| protocols.contains(&protocol)),
        }
    }
}

/// The outcome of a registration.
#[derive(Debug)]
pub struct Registered {
    pub handle: Arc<ConnectorHandle>,
    /// The registration this one replaced. Its QUIC connection is still open and
    /// the caller closes it, since it no longer receives any traffic.
    pub replaced: Option<Arc<ConnectorHandle>>,
}

/// Everything needed to register an authenticated Connector connection.
pub struct Registration {
    pub tenant_id: String,
    pub hostnames: Vec<String>,
    pub services: Option<HashMap<String, Vec<Protocol>>>,
    pub connection: quinn::Connection,
    pub udp_reply_map: UdpReplyMap,
}

/// Thread-safe registry of active Connector QUIC connections.
///
/// Lookups are lock-free; registration and removal are serialized so that the
/// hostname and tenant indexes always change together.
#[derive(Default, Clone)]
pub struct ConnectorRegistry {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// normalized hostname → connector
    by_hostname: DashMap<String, Arc<ConnectorHandle>>,
    /// tenant_id → current connector
    by_tenant: DashMap<String, Arc<ConnectorHandle>>,
    write_lock: Mutex<()>,
    next_generation: AtomicU64,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a connection. A newer connection of the same tenant replaces the
    /// previous one; hostnames served by another tenant are rejected.
    pub fn register(&self, registration: Registration) -> Result<Registered, String> {
        let _guard = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        for hostname in &registration.hostnames {
            if let Some(existing) = self.inner.by_hostname.get(hostname) {
                if existing.tenant_id != registration.tenant_id {
                    return Err(format!(
                        "hostname {hostname} is already served by another tenant on this edge"
                    ));
                }
            }
        }

        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        let handle = Arc::new(ConnectorHandle {
            tenant_id: registration.tenant_id,
            hostnames: registration.hostnames,
            services: registration.services,
            connection: registration.connection,
            connected_at: Instant::now(),
            udp_reply_map: registration.udp_reply_map,
            generation,
        });

        let replaced = self
            .inner
            .by_tenant
            .insert(handle.tenant_id.clone(), handle.clone());
        match &replaced {
            Some(previous) => {
                for hostname in &previous.hostnames {
                    self.inner
                        .by_hostname
                        .remove_if(hostname, |_, h| h.generation == previous.generation);
                }
                tracing::info!(
                    tenant_id = %handle.tenant_id,
                    previous_generation = previous.generation,
                    generation,
                    "connector replaced by a newer connection"
                );
            }
            None => sievetube_common::metrics::global()
                .active_quic_connections
                .inc(),
        }

        for hostname in &handle.hostnames {
            self.inner
                .by_hostname
                .insert(hostname.clone(), handle.clone());
        }

        tracing::info!(
            tenant_id = %handle.tenant_id,
            hostnames = ?handle.hostnames,
            generation,
            "connector registered"
        );
        Ok(Registered { handle, replaced })
    }

    /// Remove the tenant's connection only if it is still the given generation.
    /// Returns `true` when the registration was removed.
    pub fn remove(&self, tenant_id: &str, generation: u64) -> bool {
        let _guard = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        let Some((_, handle)) = self
            .inner
            .by_tenant
            .remove_if(tenant_id, |_, h| h.generation == generation)
        else {
            return false;
        };
        for hostname in &handle.hostnames {
            self.inner
                .by_hostname
                .remove_if(hostname, |_, h| h.generation == generation);
        }
        sievetube_common::metrics::global()
            .active_quic_connections
            .dec();
        tracing::info!(
            tenant_id,
            generation,
            connected_secs = handle.connected_at.elapsed().as_secs(),
            "connector deregistered"
        );
        true
    }

    /// Look up by a normalized hostname.
    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<ConnectorHandle>> {
        self.inner.by_hostname.get(hostname).map(|r| r.clone())
    }

    pub fn len(&self) -> usize {
        self.inner.by_tenant.len()
    }

    /// All current registrations, e.g. to advertise their routes.
    pub fn snapshot(&self) -> Vec<Arc<ConnectorHandle>> {
        self.inner
            .by_tenant
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::quic_pair;
    use crate::tunnel::new_udp_reply_map;

    fn registration(
        tenant: &str,
        hostnames: &[&str],
        connection: quinn::Connection,
    ) -> Registration {
        Registration {
            tenant_id: tenant.to_string(),
            hostnames: hostnames.iter().map(|h| h.to_string()).collect(),
            services: None,
            connection,
            udp_reply_map: new_udp_reply_map(),
        }
    }

    #[tokio::test]
    async fn stale_generation_does_not_remove_newer_connection() {
        let first = quic_pair().await;
        let second = quic_pair().await;
        let registry = ConnectorRegistry::new();

        let old = registry
            .register(registration("t1", &["a.test"], first.server.clone()))
            .unwrap()
            .handle;
        let replacement = registry
            .register(registration("t1", &["a.test"], second.server.clone()))
            .unwrap();
        let new = replacement.handle;
        assert!(new.generation > old.generation);
        assert_eq!(
            replacement.replaced.map(|previous| previous.generation),
            Some(old.generation),
            "the caller has to close the replaced connection"
        );

        // The old connection closing must not deregister the new one.
        assert!(!registry.remove("t1", old.generation));
        assert_eq!(
            registry.get_by_hostname("a.test").unwrap().generation,
            new.generation
        );
        assert_eq!(registry.len(), 1);

        assert!(registry.remove("t1", new.generation));
        assert!(registry.get_by_hostname("a.test").is_none());
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn replacement_drops_hostnames_no_longer_claimed() {
        let pair = quic_pair().await;
        let registry = ConnectorRegistry::new();
        registry
            .register(registration(
                "t1",
                &["a.test", "b.test"],
                pair.server.clone(),
            ))
            .unwrap();
        registry
            .register(registration("t1", &["a.test"], pair.server.clone()))
            .unwrap();
        assert!(registry.get_by_hostname("a.test").is_some());
        assert!(registry.get_by_hostname("b.test").is_none());
    }

    #[tokio::test]
    async fn rejects_hostname_of_other_tenant() {
        let pair = quic_pair().await;
        let registry = ConnectorRegistry::new();
        registry
            .register(registration("t1", &["a.test"], pair.server.clone()))
            .unwrap();
        let err = registry
            .register(registration("t2", &["a.test"], pair.server.clone()))
            .unwrap_err();
        assert!(
            !err.contains("t1"),
            "error must not leak the other tenant id: {err}"
        );
    }

    #[tokio::test]
    async fn protocol_support() {
        let pair = quic_pair().await;
        let registry = ConnectorRegistry::new();
        let mut reg = registration("t1", &["a.test"], pair.server.clone());
        reg.services = Some(HashMap::from([(
            "a.test".to_string(),
            vec![Protocol::Http],
        )]));
        let handle = registry.register(reg).unwrap().handle;
        assert!(handle.supports("a.test", Protocol::Http));
        assert!(!handle.supports("a.test", Protocol::Tcp));
        assert!(!handle.supports("b.test", Protocol::Http));
    }
}

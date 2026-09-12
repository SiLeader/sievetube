//! Mutually authenticated QUIC between Edges.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use dashmap::DashMap;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;

use sievetube_common::mesh_protocol::MESH_ALPN;

use super::certs::{edge_ids_from_cert, server_name, MeshIdentity};

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(10_000u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(60)
            .try_into()
            .expect("valid idle timeout"),
    ));
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    Arc::new(transport)
}

/// A QUIC endpoint that accepts only peers with a certificate from the mesh CA
/// and presents this Edge's certificate when connecting.
pub fn build_endpoint(
    identity: &MeshIdentity,
    listen: SocketAddr,
) -> anyhow::Result<quinn::Endpoint> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(identity.roots.clone(), provider.clone())
            .build()
            .context("mesh client verifier")?;
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(identity.cert_chain.clone(), identity.key.clone_key())
        .context("mesh server certificate")?;
    server_crypto.alpn_protocols = vec![MESH_ALPN.to_vec()];

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(identity.roots.clone())
        .with_client_auth_cert(identity.cert_chain.clone(), identity.key.clone_key())
        .context("mesh client certificate")?;
    client_crypto.alpn_protocols = vec![MESH_ALPN.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto)
            .map_err(|e| anyhow!("mesh QUIC server config: {e}"))?,
    ));
    server_config.transport_config(transport_config());
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto)
            .map_err(|e| anyhow!("mesh QUIC client config: {e}"))?,
    ));
    client_config.transport_config(transport_config());

    let mut endpoint = quinn::Endpoint::server(server_config, listen)
        .with_context(|| format!("cannot bind mesh listener {listen}"))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// The authenticated Edge ID of a mesh connection.
pub fn peer_edge_id(connection: &quinn::Connection) -> Option<String> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let mut ids = edge_ids_from_cert(certs.first()?.as_ref());
    (ids.len() == 1).then(|| ids.remove(0))
}

pub type ConnectHook = Arc<dyn Fn(&str, &quinn::Connection) + Send + Sync>;

/// Outgoing connections to authorized peers, reused across requests.
pub struct PeerPool {
    endpoint: quinn::Endpoint,
    allowed: HashSet<String>,
    connections: DashMap<String, quinn::Connection>,
    connect_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    cooldown: DashMap<String, Instant>,
    cooldown_period: Duration,
    connect_timeout: Duration,
    on_connect: Option<ConnectHook>,
}

impl PeerPool {
    pub fn new(
        endpoint: quinn::Endpoint,
        allowed: HashSet<String>,
        cooldown_period: Duration,
        connect_timeout: Duration,
        on_connect: Option<ConnectHook>,
    ) -> Arc<Self> {
        Arc::new(PeerPool {
            endpoint,
            allowed,
            connections: DashMap::new(),
            connect_locks: DashMap::new(),
            cooldown: DashMap::new(),
            cooldown_period,
            connect_timeout,
            on_connect,
        })
    }

    pub fn is_allowed(&self, edge_id: &str) -> bool {
        self.allowed.contains(edge_id)
    }

    /// Whether a peer recently failed and should not be used as a candidate.
    pub fn cooling_down(&self, edge_id: &str) -> bool {
        self.cooldown
            .get(edge_id)
            .is_some_and(|until| *until > Instant::now())
    }

    pub fn mark_failed(&self, edge_id: &str) {
        self.cooldown
            .insert(edge_id.to_string(), Instant::now() + self.cooldown_period);
        if let Some((_, connection)) = self.connections.remove(edge_id) {
            connection.close(0u32.into(), b"peer marked failed");
        }
    }

    /// An open connection to `edge_id` at `addr`, connecting if needed.
    pub async fn connection(
        &self,
        edge_id: &str,
        addr: SocketAddr,
    ) -> anyhow::Result<quinn::Connection> {
        if !self.is_allowed(edge_id) {
            bail!("edge {edge_id} is not an allowed mesh peer");
        }
        if let Some(existing) = self.usable(edge_id) {
            return Ok(existing);
        }
        let lock = self
            .connect_locks
            .entry(edge_id.to_string())
            .or_default()
            .clone();
        let _guard = lock.lock().await;
        if let Some(existing) = self.usable(edge_id) {
            return Ok(existing);
        }

        let connecting = self
            .endpoint
            .connect(addr, &server_name(edge_id))
            .map_err(|e| anyhow!("cannot connect to edge {edge_id} at {addr}: {e}"))?;
        let connection = tokio::time::timeout(self.connect_timeout, connecting)
            .await
            .map_err(|_| anyhow!("connecting to edge {edge_id} at {addr} timed out"))?
            .map_err(|e| anyhow!("mesh handshake with edge {edge_id} failed: {e}"))?;
        // The server name check already binds the certificate; double-check the URI identity.
        if peer_edge_id(&connection).as_deref() != Some(edge_id) {
            connection.close(0u32.into(), b"unexpected peer identity");
            bail!("peer at {addr} did not authenticate as {edge_id}");
        }
        self.cooldown.remove(edge_id);
        self.connections
            .insert(edge_id.to_string(), connection.clone());
        if let Some(hook) = &self.on_connect {
            hook(edge_id, &connection);
        }
        Ok(connection)
    }

    fn usable(&self, edge_id: &str) -> Option<quinn::Connection> {
        let connection = self.connections.get(edge_id)?;
        connection
            .close_reason()
            .is_none()
            .then(|| connection.clone())
    }

    pub fn close_all(&self, reason: &[u8]) {
        for entry in self.connections.iter() {
            entry.value().close(0u32.into(), reason);
        }
        self.connections.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::super::certs::test_pki::TestPki;
    use super::*;

    fn pool(pki: &TestPki, edge_id: &str, allowed: &[&str]) -> (Arc<PeerPool>, quinn::Endpoint) {
        crate::test_support::install_crypto();
        let endpoint =
            build_endpoint(&pki.identity(edge_id), "127.0.0.1:0".parse().unwrap()).unwrap();
        let pool = PeerPool::new(
            endpoint.clone(),
            allowed.iter().map(|s| s.to_string()).collect(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            None,
        );
        (pool, endpoint)
    }

    async fn accept_one(endpoint: quinn::Endpoint) -> Option<String> {
        let incoming = endpoint.accept().await?;
        let connection = incoming.await.ok()?;
        peer_edge_id(&connection)
    }

    #[tokio::test]
    async fn peers_authenticate_each_other() {
        let pki = TestPki::new();
        let (pool_a, _endpoint_a) = pool(&pki, "edge-a", &["edge-b"]);
        let (_pool_b, endpoint_b) = pool(&pki, "edge-b", &["edge-a"]);
        let addr_b = endpoint_b.local_addr().unwrap();

        let accepted = tokio::spawn(accept_one(endpoint_b.clone()));
        let connection = pool_a.connection("edge-b", addr_b).await.unwrap();
        assert_eq!(peer_edge_id(&connection).as_deref(), Some("edge-b"));
        assert_eq!(accepted.await.unwrap().as_deref(), Some("edge-a"));

        // Reused while open.
        let again = pool_a.connection("edge-b", addr_b).await.unwrap();
        assert_eq!(again.stable_id(), connection.stable_id());
    }

    #[tokio::test]
    async fn unauthorized_or_impostor_peers_are_rejected() {
        let pki = TestPki::new();
        let (pool_a, _endpoint_a) = pool(&pki, "edge-a", &["edge-b"]);
        let (_pool_c, endpoint_c) = pool(&pki, "edge-c", &[]);
        let addr_c = endpoint_c.local_addr().unwrap();
        tokio::spawn(accept_one(endpoint_c.clone()));

        // Not in the allowed list.
        assert!(pool_a.connection("edge-c", addr_c).await.is_err());
        // edge-c pretending to be edge-b: its certificate does not match the server name.
        let err = pool_a.connection("edge-b", addr_c).await.unwrap_err();
        assert!(format!("{err:#}").contains("failed"), "{err:#}");

        // A certificate from another CA is rejected by the server.
        let other_pki = TestPki::new();
        let (pool_x, _endpoint_x) = pool(&other_pki, "edge-a", &["edge-b"]);
        let (_pool_b, endpoint_b) = pool(&pki, "edge-b", &["edge-a"]);
        let addr_b = endpoint_b.local_addr().unwrap();
        tokio::spawn(accept_one(endpoint_b.clone()));
        assert!(pool_x.connection("edge-b", addr_b).await.is_err());
    }

    #[tokio::test]
    async fn connector_alpn_is_rejected_by_mesh_endpoint() {
        let pki = TestPki::new();
        let (_pool, endpoint) = pool(&pki, "edge-b", &[]);
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(accept_one(endpoint.clone()));

        // A client with a valid mesh certificate but the Connector ALPN.
        let identity = pki.identity("edge-a");
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(identity.roots.clone())
            .with_client_auth_cert(identity.cert_chain.clone(), identity.key.clone_key())
            .unwrap();
        crypto.alpn_protocols = vec![sievetube_common::protocol::ALPN_PROTOCOL.to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).unwrap(),
        )));
        let result = client.connect(addr, &server_name("edge-b")).unwrap().await;
        assert!(result.is_err(), "ALPN mismatch must fail the handshake");
    }

    #[tokio::test]
    async fn failed_peers_cool_down() {
        let pki = TestPki::new();
        let (pool_a, _endpoint) = pool(&pki, "edge-a", &["edge-b"]);
        assert!(!pool_a.cooling_down("edge-b"));
        pool_a.mark_failed("edge-b");
        assert!(pool_a.cooling_down("edge-b"));
    }
}

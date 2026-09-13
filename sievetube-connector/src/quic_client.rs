use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls;
use sievetube_common::config::{Protocol, Target};
use sievetube_common::hostname;
use sievetube_common::protocol::{
    self, AuthRequest, DatagramHeader, Message, ServiceAdvertisement, ALPN_PROTOCOL,
};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::task::TaskTracker;

use crate::health::ConnectorHealth;
use crate::ingress::IngressMatcher;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// An authenticated session that lasted this long proves the Edge usable, so
/// the next reconnect starts over from the initial backoff. Sessions that end
/// sooner keep backing off, so that an Edge or middlebox dropping Connectors
/// right after authentication is not reconnected to every second.
const STABLE_SESSION: Duration = Duration::from_secs(60);
/// Wait after another Connector with the same token took over this Edge
/// connection. Reconnecting sooner would take it back and cut its streams.
const REPLACED_RETRY_DELAY: Duration = Duration::from_secs(60);
/// Streams the Edge may open at once; it opens one per HTTP request and tunnel.
pub(crate) const MAX_INCOMING_STREAMS: u32 = 10_000;
/// Data the Edge may send on a connection beyond what was passed on to local
/// targets, over all streams together. Each stream buffers up to its own
/// window, so without this bound thousands of streams to a target that reads
/// slowly could buffer gigabytes. It matches the memory the default limit of
/// 100 streams allowed before.
const RECEIVE_WINDOW: u32 = 128 * 1024 * 1024;
/// How long connecting to one address of an Edge may take before the next one
/// is tried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long sending the going-away notice may take during shutdown.
const GOING_AWAY_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum time for the Edge to deliver a stream's ConnectRequest.
const CONNECT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// UDP datagrams forwarded to local targets at once; each holds a socket while
/// it waits for a reply, so datagrams beyond this are dropped.
const MAX_PENDING_UDP_FORWARDS: usize = 1024;

/// How the Edge's QUIC certificate is checked.
pub enum EdgeVerification {
    /// Verify against a CA bundle (recommended)
    Ca(rustls::RootCertStore),
    /// Accept only these certificate fingerprints
    Pinned(Vec<String>),
    /// No verification; only for migrating existing deployments
    Skip,
}

impl EdgeVerification {
    /// Build from the `[network]` settings, reading the CA bundle if configured.
    pub fn from_config(ca_cert: Option<&str>, pins: &[String]) -> anyhow::Result<Self> {
        if let Some(path) = ca_cert {
            let pem =
                std::fs::read(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                roots.add(cert?)?;
            }
            if roots.is_empty() {
                anyhow::bail!("no certificate found in {path}");
            }
            return Ok(EdgeVerification::Ca(roots));
        }
        if !pins.is_empty() {
            return Ok(EdgeVerification::Pinned(
                pins.iter()
                    .map(|pin| pin.trim().to_ascii_lowercase())
                    .collect(),
            ));
        }
        Ok(EdgeVerification::Skip)
    }
}

/// Client endpoints for connecting to Edges, one per address family and bound
/// on first use. Edges are reachable over IPv4 and IPv6 alike, without relying
/// on the platform's support for dual-stack sockets.
struct EdgeEndpoints {
    config: quinn::ClientConfig,
    v4: Option<quinn::Endpoint>,
    v6: Option<quinn::Endpoint>,
}

impl EdgeEndpoints {
    fn new(verification: EdgeVerification) -> anyhow::Result<Self> {
        Ok(EdgeEndpoints {
            config: client_config(verification)?,
            v4: None,
            v6: None,
        })
    }

    fn for_addr(&mut self, addr: SocketAddr) -> std::io::Result<&quinn::Endpoint> {
        let (slot, bind) = match addr {
            SocketAddr::V4(_) => (&mut self.v4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
            SocketAddr::V6(_) => (&mut self.v6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))),
        };
        if slot.is_none() {
            let mut endpoint = quinn::Endpoint::client(bind)?;
            endpoint.set_default_client_config(self.config.clone());
            *slot = Some(endpoint);
        }
        Ok(slot.as_ref().expect("endpoint bound above"))
    }
}

/// Build the QUIC client configuration for connecting to Edges.
fn client_config(verification: EdgeVerification) -> anyhow::Result<quinn::ClientConfig> {
    let builder = rustls::ClientConfig::builder();
    let mut crypto = match verification {
        EdgeVerification::Ca(roots) => builder.with_root_certificates(roots).with_no_client_auth(),
        EdgeVerification::Pinned(pins) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerification::new(pins)))
            .with_no_client_auth(),
        EdgeVerification::Skip => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth(),
    };
    crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| anyhow::anyhow!("QuicClientConfig error: {e}"))?;

    let mut transport = quinn::TransportConfig::default();
    // The limit applies to streams the peer opens, and only the Edge opens them.
    transport.max_concurrent_bidi_streams(MAX_INCOMING_STREAMS.into());
    transport.receive_window(RECEIVE_WINDOW.into());
    transport.datagram_receive_buffer_size(Some(65535));

    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    client_cfg.transport_config(Arc::new(transport));
    Ok(client_cfg)
}

/// Resolves once shutdown was requested, or the sender is gone.
async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

/// `backoff` shortened by a random part of up to half, so that Connectors that
/// lost their Edge at the same moment do not all reconnect at the same moment.
fn jittered(backoff: Duration) -> Duration {
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let half = backoff / 2;
    half + half.mul_f64((random % 1024) as f64 / 1024.0)
}

/// Connect to a single Edge server, authenticate with JWT, and serve streams.
///
/// This function runs a reconnect loop with exponential backoff.
#[allow(clippy::too_many_arguments)]
pub async fn run_connection(
    server_addr_str: String,
    jwt: String,
    services: Option<Arc<Vec<ServiceAdvertisement>>>,
    matcher: Arc<IngressMatcher>,
    tunnel_id: String,
    verification: EdgeVerification,
    configured_server_name: Option<String>,
    drain_timeout: Duration,
    target_connect_timeout: Duration,
    stream_permits: Arc<tokio::sync::Semaphore>,
    health: ConnectorHealth,
    mut shutdown: watch::Receiver<bool>,
) {
    let server_name = match tls_server_name(&server_addr_str, configured_server_name.as_deref()) {
        Ok(name) => name,
        Err(e) => {
            health.disconnected(&server_addr_str, &e);
            tracing::error!(error = %e, "cannot determine the TLS server name of the edge");
            return;
        }
    };
    if matches!(verification, EdgeVerification::Ca(_))
        && server_name.parse::<std::net::IpAddr>().is_ok()
    {
        tracing::warn!(
            server = %server_addr_str,
            "the edge address is an IP literal, so its certificate needs a matching IP SAN; set [network] edge_server_name to verify against a hostname instead"
        );
    }
    let mut endpoints = match EdgeEndpoints::new(verification) {
        Ok(endpoints) => endpoints,
        Err(e) => {
            health.disconnected(&server_addr_str, &e);
            tracing::error!(error = %e, "failed to build QUIC client configuration");
            return;
        }
    };

    let mut backoff = INITIAL_BACKOFF;

    loop {
        if *shutdown.borrow() {
            return;
        }
        // Waiting after a replacement is not shortened: reconnecting early would
        // take the connection back from the other Connector.
        let mut exact_delay = None;
        health.connecting(&server_addr_str);

        let connect = connect_and_authenticate(
            &mut endpoints,
            &server_addr_str,
            &server_name,
            &jwt,
            services.as_deref(),
            &tunnel_id,
        );
        let connected = tokio::select! {
            connected = connect => connected,
            () = shutdown_requested(&mut shutdown) => return,
        };
        let result = match connected {
            Ok(connection) => {
                health.connected(&server_addr_str);
                let authenticated_at = Instant::now();
                sievetube_common::metrics::init()
                    .active_quic_connections
                    .inc();
                let result = serve_streams(
                    connection.clone(),
                    matcher.clone(),
                    &tunnel_id,
                    shutdown.clone(),
                    drain_timeout,
                    target_connect_timeout,
                    stream_permits.clone(),
                )
                .await;
                sievetube_common::metrics::global()
                    .active_quic_connections
                    .dec();
                if authenticated_at.elapsed() >= STABLE_SESSION {
                    backoff = INITIAL_BACKOFF;
                }
                if replaced_by_another_connector(&connection) {
                    tracing::warn!(
                        server = %server_addr_str,
                        retry_secs = REPLACED_RETRY_DELAY.as_secs(),
                        "another connector with the same token took over this edge; connectors sharing a token must connect to different edges"
                    );
                    exact_delay = Some(REPLACED_RETRY_DELAY);
                    Err(anyhow::anyhow!("connection replaced by another connector"))
                } else {
                    result
                }
            }
            Err(e) => Err(e),
        };

        let health_error = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_else(|| "connection closed".to_string());
        health.disconnected(&server_addr_str, health_error);

        let delay = exact_delay.unwrap_or_else(|| jittered(backoff));
        match result {
            Ok(()) => {
                tracing::info!(server = %server_addr_str, "connection closed gracefully");
            }
            Err(e) => {
                tracing::warn!(
                    server = %server_addr_str,
                    error = %e,
                    retry_after_ms = delay.as_millis() as u64,
                    "connection failed, retrying"
                );
            }
        }

        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = shutdown_requested(&mut shutdown) => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Whether the Edge closed the connection because a newer connection of the same
/// tenant replaced it. A Connector's own reconnect abandons the old connection
/// first, so a live Connector only sees this when another one shares its token.
fn replaced_by_another_connector(connection: &quinn::Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(quinn::ConnectionError::ApplicationClosed(close))
            if close.error_code == quinn::VarInt::from_u32(sievetube_common::error::app_error::REPLACED)
    )
}

/// TLS server name for an Edge address: the configured override, otherwise the
/// host part of the address. Splitting on `:` would mangle every IPv6 literal.
fn tls_server_name(server_addr_str: &str, configured: Option<&str>) -> anyhow::Result<String> {
    if let Some(name) = configured {
        return Ok(name.to_string());
    }
    let (host, _port) = hostname::split_authority(server_addr_str)
        .map_err(|e| anyhow::anyhow!("invalid server address {server_addr_str}: {e}"))?;
    Ok(host.to_string())
}

/// Connect to the Edge and authenticate; returns the connection ready to serve.
async fn connect_and_authenticate(
    endpoints: &mut EdgeEndpoints,
    server_addr_str: &str,
    server_name: &str,
    jwt: &str,
    services: Option<&Vec<ServiceAdvertisement>>,
    tunnel_id: &str,
) -> anyhow::Result<quinn::Connection> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(server_addr_str)
        .await
        .map_err(|e| anyhow::anyhow!("DNS lookup failed for {server_addr_str}: {e}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("no addresses for {server_addr_str}");
    }

    tracing::info!(server = %server_addr_str, server_name, "connecting to edge");

    let connection = connect_any(endpoints, &addrs, server_name).await?;

    tracing::info!(server = %server_addr_str, remote_addr = %connection.remote_address(), "connected, authenticating");

    // Send AuthRequest on a unidirectional stream
    let mut auth_send = connection.open_uni().await?;
    protocol::write_message(
        &mut auth_send,
        &Message::AuthRequest(AuthRequest {
            jwt: jwt.to_string(),
            services: services.cloned(),
        }),
    )
    .await?;
    auth_send.finish()?;

    // Read AuthResponse from a unidirectional stream opened by the Edge
    let mut auth_recv = connection.accept_uni().await?;
    let auth_resp = match protocol::read_message(&mut auth_recv).await? {
        Message::AuthResponse(r) => r,
        _ => anyhow::bail!("expected AuthResponse"),
    };

    if !auth_resp.ok {
        anyhow::bail!(
            "authentication rejected: {}",
            auth_resp.reason.unwrap_or_default()
        );
    }

    tracing::info!(server = %server_addr_str, tunnel_id, "authenticated, serving streams");
    Ok(connection)
}

/// Connect to the first of `addrs` that answers, in the resolver's order of
/// preference. A host name with both IPv6 and IPv4 addresses stays reachable
/// when only one of the address families works.
async fn connect_any(
    endpoints: &mut EdgeEndpoints,
    addrs: &[SocketAddr],
    server_name: &str,
) -> anyhow::Result<quinn::Connection> {
    let mut failures = Vec::new();
    for &addr in addrs {
        let attempt = async {
            let connecting = endpoints.for_addr(addr)?.connect(addr, server_name)?;
            match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
                Ok(connected) => Ok(connected?),
                Err(_) => anyhow::bail!("timed out"),
            }
        };
        match attempt.await {
            Ok(connection) => return Ok(connection),
            Err(e) => {
                tracing::debug!(%addr, error = %e, "cannot connect to edge address");
                failures.push(format!("{addr}: {e}"));
            }
        }
    }
    anyhow::bail!("QUIC connect failed: {}", failures.join("; "))
}

/// Resolves at `deadline`, or never without one.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Ask the Edge to route no new traffic to this connection.
async fn send_going_away(connection: &quinn::Connection) -> anyhow::Result<()> {
    let mut send = connection.open_uni().await?;
    protocol::write_message(&mut send, &Message::GoingAway).await?;
    send.finish()?;
    Ok(())
}

fn close_going_away(connection: &quinn::Connection) {
    connection.close(
        quinn::VarInt::from_u32(sievetube_common::error::app_error::GOING_AWAY),
        b"connector shutting down",
    );
}

async fn serve_streams(
    connection: quinn::Connection,
    matcher: Arc<IngressMatcher>,
    tunnel_id: &str,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
    target_connect_timeout: Duration,
    stream_permits: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<()> {
    let udp_forwards = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_UDP_FORWARDS));
    // Streams and UDP forwards in flight, which a shutdown lets finish.
    let in_flight = TaskTracker::new();
    let mut drain_deadline = None;
    loop {
        tokio::select! {
            () = shutdown_requested(&mut shutdown), if drain_deadline.is_none() => {
                // Edges that know the notice stop routing new traffic here, so
                // the streams in flight can finish before the connection closes.
                // Older Edges keep routing until the connection closes.
                match tokio::time::timeout(GOING_AWAY_TIMEOUT, send_going_away(&connection)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::debug!(tunnel_id, error = %e, "cannot send going-away notice"),
                    Err(_) => tracing::debug!(tunnel_id, "sending the going-away notice timed out"),
                }
                in_flight.close();
                drain_deadline = Some(Instant::now() + drain_timeout);
                tracing::info!(tunnel_id, in_flight = in_flight.len(), "draining connection");
            }

            () = in_flight.wait(), if drain_deadline.is_some() => {
                close_going_away(&connection);
                return Ok(());
            }

            () = sleep_until(drain_deadline) => {
                tracing::warn!(tunnel_id, remaining = in_flight.len(), "drain timeout reached; closing the connection");
                close_going_away(&connection);
                return Ok(());
            }

            result = connection.accept_bi() => {
                let (send, recv) = match result {
                    Ok(s) => s,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };

                // The QUIC stream limit is deliberately high enough for busy
                // Edges, but accepted streams consume a task and usually a local
                // TCP socket. Bound those resources across all Edge connections.
                let Ok(permit) = stream_permits.clone().try_acquire_owned() else {
                    tracing::debug!(tunnel_id, "too many active streams, rejecting stream");
                    continue;
                };

                // The request is read in the stream's own task, so one slow or
                // broken stream affects neither the other streams nor the connection.
                let matcher = matcher.clone();
                let tid = tunnel_id.to_string();
                in_flight.spawn(async move {
                    let _permit = permit;
                    serve_stream(send, recv, matcher, tid, target_connect_timeout).await;
                });
            }

            result = connection.read_datagram() => {
                let datagram = match result {
                    Ok(d) => d,
                    Err(_) => return Ok(()), // connection closed
                };

                let Some((header, payload)) = DatagramHeader::decode(&datagram) else {
                    tracing::warn!(tunnel_id, "received malformed datagram from edge");
                    continue;
                };

                let hostname = header.hostname.clone();
                let request_id = header.request_id;

                let target_addr = match matcher.match_request(&hostname, Protocol::Udp) {
                    Ok(Target::Address(addr)) => addr,
                    _ => {
                        tracing::warn!(tunnel_id, hostname = %hostname, "no UDP ingress match for datagram");
                        continue;
                    }
                };

                let Ok(permit) = udp_forwards.clone().try_acquire_owned() else {
                    tracing::debug!(tunnel_id, hostname = %hostname, "too many pending UDP forwards, dropping datagram");
                    continue;
                };
                let payload = payload.to_vec();
                let conn = connection.clone();
                in_flight.spawn(async move {
                    let _permit = permit;
                    match crate::forwarder::forward_udp_datagram(&payload, target_addr).await {
                        Ok(Some(reply)) => {
                            let reply_header = DatagramHeader { request_id, hostname };
                            let reply_datagram = reply_header.encode(&reply);
                            if let Err(e) = conn.send_datagram(reply_datagram) {
                                tracing::debug!(error = %e, "failed to send UDP reply datagram");
                            }
                        }
                        Ok(None) => {} // timeout — no reply from local target
                        Err(e) => {
                            tracing::debug!(error = %e, "UDP forward error");
                        }
                    }
                });
            }
        }
    }
}

/// Read one stream's ConnectRequest and forward the stream to its target.
async fn serve_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    matcher: Arc<IngressMatcher>,
    tunnel_id: String,
    target_connect_timeout: Duration,
) {
    let connect_req = match tokio::time::timeout(
        CONNECT_REQUEST_TIMEOUT,
        protocol::read_message(&mut recv),
    )
    .await
    {
        Ok(Ok(Message::ConnectRequest(r))) => r,
        Ok(Ok(_)) => {
            tracing::warn!(tunnel_id, "expected ConnectRequest, got something else");
            return;
        }
        // The Edge resets streams whose client went away before the request
        // was complete, so this is routine.
        Ok(Err(e)) => {
            tracing::debug!(tunnel_id, error = %e, "cannot read ConnectRequest");
            return;
        }
        Err(_) => {
            tracing::debug!(tunnel_id, "timed out waiting for ConnectRequest");
            return;
        }
    };

    let hostname = connect_req.hostname;
    let protocol = connect_req.protocol;

    tracing::debug!(
        tunnel_id,
        hostname = %hostname,
        protocol = ?protocol,
        client_addr = %connect_req.client_addr,
        "new stream"
    );

    let target = match matcher.match_request(&hostname, protocol) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(tunnel_id, hostname = %hostname, error = %e, "no ingress match");
            return;
        }
    };

    crate::forwarder::handle_stream(
        send,
        recv,
        target,
        tunnel_id,
        hostname,
        protocol,
        target_connect_timeout,
    )
    .await;
}

/// Accepts only certificates whose SHA-256 fingerprint is pinned. Useful when the
/// Edge presents a self-signed certificate.
#[derive(Debug)]
struct PinnedServerVerification {
    pins: Vec<String>,
}

impl PinnedServerVerification {
    fn new(pins: Vec<String>) -> Self {
        PinnedServerVerification { pins }
    }
}

pub fn certificate_sha256(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fingerprint = certificate_sha256(end_entity.as_ref());
        if self.pins.iter().any(|pin| pin == &fingerprint) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "edge certificate {fingerprint} is not pinned"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A rustls certificate verifier that accepts any server certificate.
/// Security note: The tunnel is authenticated by JWT, not by server TLS cert.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dh_params: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dhs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_mode_follows_the_configuration() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(matches!(
            EdgeVerification::from_config(None, &[]).unwrap(),
            EdgeVerification::Skip
        ));
        assert!(matches!(
            EdgeVerification::from_config(None, &["ab".repeat(32)]).unwrap(),
            EdgeVerification::Pinned(_)
        ));
        assert!(EdgeVerification::from_config(Some("/nonexistent/ca.pem"), &[]).is_err());
    }

    #[test]
    fn server_name_handles_literals_and_overrides() {
        assert_eq!(
            tls_server_name("edge.example.com:4433", None).unwrap(),
            "edge.example.com"
        );
        assert_eq!(
            tls_server_name("203.0.113.5:4433", None).unwrap(),
            "203.0.113.5"
        );
        // An IPv6 literal must not be cut at its first colon.
        assert_eq!(
            tls_server_name("[2001:db8::1]:4433", None).unwrap(),
            "2001:db8::1"
        );
        assert_eq!(
            tls_server_name("[2001:db8::1]:4433", Some("edge.example.com")).unwrap(),
            "edge.example.com"
        );
        assert!(tls_server_name("2001:db8::1:4433", None).is_err());
    }

    /// A loopback Edge endpoint with a self-signed certificate for `edge.test`.
    fn test_server(bind: &str) -> Option<quinn::Endpoint> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["edge.test".to_string()]).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        tls.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        quinn::Endpoint::server(server_cfg, bind.parse().unwrap()).ok()
    }

    /// A Connector-side connection and the Edge side of it.
    async fn connected_pair() -> (
        quinn::Connection,
        quinn::Connection,
        EdgeEndpoints,
        quinn::Endpoint,
    ) {
        let server = test_server("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut endpoints = EdgeEndpoints::new(EdgeVerification::Skip).unwrap();
        let client = endpoints.for_addr(server_addr).unwrap().clone();
        let (edge, connector) = tokio::join!(
            async { server.accept().await.unwrap().await.unwrap() },
            async {
                client
                    .connect(server_addr, "edge.test")
                    .unwrap()
                    .await
                    .unwrap()
            }
        );
        (connector, edge, endpoints, server)
    }

    /// Connect to a loopback server that closes the connection with `code`.
    async fn closed_by_server_with(code: u32) -> quinn::Connection {
        let (connection, edge, _endpoints, _server) = connected_pair().await;
        edge.close(quinn::VarInt::from_u32(code), b"test");
        connection.closed().await;
        connection
    }

    #[tokio::test]
    async fn edges_are_reached_over_ipv6_and_past_unusable_addresses() {
        let Some(server) = test_server("[::1]:0") else {
            eprintln!("skipping: no IPv6 loopback");
            return;
        };
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            connection.closed().await
        });
        let mut endpoints = EdgeEndpoints::new(EdgeVerification::Skip).unwrap();
        // The first address cannot be connected to at all.
        let unusable: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let connection = connect_any(&mut endpoints, &[unusable, server_addr], "edge.test")
            .await
            .unwrap();
        assert_eq!(connection.remote_address(), server_addr);
        assert!(endpoints.v4.is_some() && endpoints.v6.is_some());
    }

    /// Serve `connector` with one ingress rule for web.test to `target`.
    fn serve(
        connector: quinn::Connection,
        target: SocketAddr,
        drain_timeout: Duration,
    ) -> (
        watch::Sender<bool>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        serve_with_permits(
            connector,
            target,
            drain_timeout,
            Arc::new(tokio::sync::Semaphore::new(256)),
        )
    }

    fn serve_with_permits(
        connector: quinn::Connection,
        target: SocketAddr,
        drain_timeout: Duration,
        stream_permits: Arc<tokio::sync::Semaphore>,
    ) -> (
        watch::Sender<bool>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let matcher = Arc::new(IngressMatcher::new(vec![
            sievetube_common::config::IngressRule {
                hostname: Some("web.test".to_string()),
                protocol: None,
                target: target.to_string(),
            },
        ]));
        let (stop, shutdown) = watch::channel(false);
        let serving = tokio::spawn(async move {
            serve_streams(
                connector,
                matcher,
                "tenant",
                shutdown,
                drain_timeout,
                Duration::from_secs(10),
                stream_permits,
            )
            .await
        });
        (stop, serving)
    }

    /// Open a tunnel stream from the Edge side as the Edge does for a request.
    async fn open_tunnel(edge: &quinn::Connection) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut send, recv) = edge.open_bi().await.unwrap();
        protocol::write_message(
            &mut send,
            &Message::ConnectRequest(protocol::ConnectRequest {
                request_id: 1,
                hostname: "web.test".to_string(),
                protocol: Protocol::Tcp,
                client_addr: "203.0.113.9:1234".parse().unwrap(),
            }),
        )
        .await
        .unwrap();
        (send, recv)
    }

    #[tokio::test]
    async fn shutdown_announces_going_away_and_waits_for_streams_in_flight() {
        use tokio::io::AsyncWriteExt;

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (connector, edge, _endpoints, _server) = connected_pair().await;
        let (stop, serving) = serve(
            connector,
            backend.local_addr().unwrap(),
            Duration::from_secs(30),
        );
        let (mut send, _recv) = open_tunnel(&edge).await;
        let (mut target, _) = backend.accept().await.unwrap();

        stop.send(true).unwrap();
        let mut notice = tokio::time::timeout(Duration::from_secs(5), edge.accept_uni())
            .await
            .expect("the edge is told before anything closes")
            .unwrap();
        assert!(matches!(
            protocol::read_message(&mut notice).await.unwrap(),
            Message::GoingAway
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !serving.is_finished(),
            "the stream in flight is still served"
        );
        assert!(edge.close_reason().is_none());

        // The request completes on both sides.
        send.finish().unwrap();
        target.shutdown().await.unwrap();
        drop(target);
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("the connection closes once its streams are done")
            .unwrap()
            .unwrap();
        assert!(matches!(
            edge.closed().await,
            quinn::ConnectionError::ApplicationClosed(close)
                if close.error_code == quinn::VarInt::from_u32(sievetube_common::error::app_error::GOING_AWAY)
        ));
    }

    #[tokio::test]
    async fn excess_streams_do_not_consume_local_connections() {
        use tokio::io::AsyncWriteExt;

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (connector, edge, _endpoints, _server) = connected_pair().await;
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let (stop, serving) = serve_with_permits(
            connector,
            backend.local_addr().unwrap(),
            Duration::from_secs(5),
            permits.clone(),
        );

        let (mut first_send, _first_recv) = open_tunnel(&edge).await;
        let (mut first_target, _) = backend.accept().await.unwrap();
        assert_eq!(permits.available_permits(), 0);

        let excess = open_tunnel(&edge).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), backend.accept())
                .await
                .is_err(),
            "a stream beyond the limit reached the local target"
        );
        drop(excess);

        first_send.finish().unwrap();
        first_target.shutdown().await.unwrap();
        drop(first_target);
        tokio::time::timeout(Duration::from_secs(5), async {
            while permits.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the stream permit is returned when forwarding ends");

        let (mut next_send, _next_recv) = open_tunnel(&edge).await;
        let (mut next_target, _) = tokio::time::timeout(Duration::from_secs(5), backend.accept())
            .await
            .expect("a later stream can use the returned permit")
            .unwrap();
        next_send.finish().unwrap();
        next_target.shutdown().await.unwrap();
        drop(next_target);

        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn draining_ends_at_the_drain_timeout() {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (connector, edge, _endpoints, _server) = connected_pair().await;
        let (stop, serving) = serve(
            connector,
            backend.local_addr().unwrap(),
            Duration::from_millis(300),
        );
        let (_send, _recv) = open_tunnel(&edge).await;
        let (_target, _) = backend.accept().await.unwrap();

        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), serving)
            .await
            .expect("a stream that never ends does not hold up shutdown")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn jitter_stays_within_half_of_the_backoff() {
        let backoff = Duration::from_secs(8);
        for _ in 0..100 {
            let delay = jittered(backoff);
            assert!(delay >= backoff / 2 && delay <= backoff, "{delay:?}");
        }
    }

    #[tokio::test]
    async fn replacement_is_told_apart_from_other_closes() {
        use sievetube_common::error::app_error;
        assert!(replaced_by_another_connector(
            &closed_by_server_with(app_error::REPLACED).await
        ));
        assert!(!replaced_by_another_connector(
            &closed_by_server_with(app_error::GOING_AWAY).await
        ));
    }

    #[test]
    fn pinning_accepts_only_listed_fingerprints() {
        use rustls::client::danger::ServerCertVerifier;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["edge.test".to_string()]).unwrap();
        let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let fingerprint = certificate_sha256(der.as_ref());

        let verify = |pins: Vec<String>| {
            PinnedServerVerification::new(pins).verify_server_cert(
                &der,
                &[],
                &rustls::pki_types::ServerName::try_from("edge.test").unwrap(),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
        };
        assert!(verify(vec![fingerprint.clone()]).is_ok());
        assert!(verify(vec!["00".repeat(32)]).is_err());
    }
}

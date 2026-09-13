use std::sync::Arc;
use std::time::Duration;

use quinn::rustls;
use sievetube_common::config::{Protocol, Target};
use sievetube_common::hostname;
use sievetube_common::protocol::{
    self, AuthRequest, DatagramHeader, Message, ServiceAdvertisement, ALPN_PROTOCOL,
};

use crate::ingress::IngressMatcher;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Wait after another Connector with the same token took over this Edge
/// connection. Reconnecting sooner would take it back and cut its streams.
const REPLACED_RETRY_DELAY: Duration = Duration::from_secs(60);
/// Streams the Edge may open at once; it opens one per HTTP request and tunnel.
const MAX_INCOMING_STREAMS: u32 = 10_000;
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

/// Build a QUIC client endpoint for connecting to Edges.
fn build_endpoint(verification: EdgeVerification) -> anyhow::Result<quinn::Endpoint> {
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
    transport.datagram_receive_buffer_size(Some(65535));

    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    client_cfg.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
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
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let server_name = match tls_server_name(&server_addr_str, configured_server_name.as_deref()) {
        Ok(name) => name,
        Err(e) => {
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
    let endpoint = match build_endpoint(verification) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "failed to build QUIC endpoint");
            return;
        }
    };

    let mut backoff = INITIAL_BACKOFF;

    loop {
        if *shutdown.borrow() {
            return;
        }

        let result = match connect_and_authenticate(
            &endpoint,
            &server_addr_str,
            &server_name,
            &jwt,
            services.as_deref(),
            &tunnel_id,
        )
        .await
        {
            Ok(connection) => {
                // An authenticated session proves the Edge is reachable, so a
                // later disconnect, graceful or not, starts over from a short wait.
                backoff = INITIAL_BACKOFF;
                sievetube_common::metrics::init()
                    .active_quic_connections
                    .inc();
                let result = serve_streams(
                    connection.clone(),
                    matcher.clone(),
                    &tunnel_id,
                    shutdown.clone(),
                )
                .await;
                sievetube_common::metrics::global()
                    .active_quic_connections
                    .dec();
                if replaced_by_another_connector(&connection) {
                    tracing::warn!(
                        server = %server_addr_str,
                        retry_secs = REPLACED_RETRY_DELAY.as_secs(),
                        "another connector with the same token took over this edge; connectors sharing a token must connect to different edges"
                    );
                    backoff = REPLACED_RETRY_DELAY;
                    Err(anyhow::anyhow!("connection replaced by another connector"))
                } else {
                    result
                }
            }
            Err(e) => Err(e),
        };

        match result {
            Ok(()) => {
                tracing::info!(server = %server_addr_str, "connection closed gracefully");
            }
            Err(e) => {
                tracing::warn!(
                    server = %server_addr_str,
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "connection failed, retrying"
                );
            }
        }

        if *shutdown.borrow() {
            return;
        }

        tokio::time::sleep(backoff).await;
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
    endpoint: &quinn::Endpoint,
    server_addr_str: &str,
    server_name: &str,
    jwt: &str,
    services: Option<&Vec<ServiceAdvertisement>>,
    tunnel_id: &str,
) -> anyhow::Result<quinn::Connection> {
    // Resolve address
    let server_addr: std::net::SocketAddr = tokio::net::lookup_host(server_addr_str)
        .await
        .map_err(|e| anyhow::anyhow!("DNS lookup failed for {server_addr_str}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {server_addr_str}"))?;

    tracing::info!(server = %server_addr_str, server_name, "connecting to edge");

    let connection = endpoint
        .connect(server_addr, server_name)?
        .await
        .map_err(|e| anyhow::anyhow!("QUIC connect failed: {e}"))?;

    tracing::info!(server = %server_addr_str, "connected, authenticating");

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

async fn serve_streams(
    connection: quinn::Connection,
    matcher: Arc<IngressMatcher>,
    tunnel_id: &str,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let udp_forwards = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_UDP_FORWARDS));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                connection.close(
                    quinn::VarInt::from_u32(sievetube_common::error::app_error::GOING_AWAY),
                    b"connector shutting down",
                );
                return Ok(());
            }

            result = connection.accept_bi() => {
                let (send, recv) = match result {
                    Ok(s) => s,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };

                // The request is read in the stream's own task, so one slow or
                // broken stream affects neither the other streams nor the connection.
                let matcher = matcher.clone();
                let tid = tunnel_id.to_string();
                tokio::spawn(async move {
                    serve_stream(send, recv, matcher, tid).await;
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
                tokio::spawn(async move {
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

    crate::forwarder::handle_stream(send, recv, target, tunnel_id, hostname).await;
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

    /// Connect to a loopback server that closes the connection with `code`.
    async fn closed_by_server_with(code: u32) -> quinn::Connection {
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
        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = build_endpoint(EdgeVerification::Skip).unwrap();
        let (_, connection) = tokio::join!(
            async {
                let conn = server.accept().await.unwrap().await.unwrap();
                conn.close(quinn::VarInt::from_u32(code), b"test");
            },
            async {
                client
                    .connect(server_addr, "edge.test")
                    .unwrap()
                    .await
                    .unwrap()
            }
        );
        connection.closed().await;
        connection
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

use std::sync::Arc;
use std::time::Duration;

use quinn::rustls;
use sievetube_common::config::{Protocol, Target};
use sievetube_common::protocol::{
    self, AuthRequest, DatagramHeader, Message, ALPN_PROTOCOL,
};

use crate::ingress::IngressMatcher;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Build a QUIC client endpoint that skips server certificate verification.
/// This is acceptable for the internal tunnel — the JWT provides auth.
fn build_endpoint() -> anyhow::Result<quinn::Endpoint> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut crypto = crypto;
    crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let quic_cfg =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| anyhow::anyhow!("QuicClientConfig error: {e}"))?;

    let mut transport = quinn::TransportConfig::default();
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
pub async fn run_connection(
    server_addr_str: String,
    jwt: String,
    matcher: Arc<IngressMatcher>,
    tunnel_id: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let endpoint = match build_endpoint() {
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

        match try_connect_and_serve(
            &endpoint,
            &server_addr_str,
            &jwt,
            matcher.clone(),
            &tunnel_id,
            shutdown.clone(),
        )
        .await
        {
            Ok(()) => {
                tracing::info!(server = %server_addr_str, "connection closed gracefully");
                backoff = INITIAL_BACKOFF;
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

async fn try_connect_and_serve(
    endpoint: &quinn::Endpoint,
    server_addr_str: &str,
    jwt: &str,
    matcher: Arc<IngressMatcher>,
    tunnel_id: &str,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    // Resolve address
    let server_addr: std::net::SocketAddr = tokio::net::lookup_host(server_addr_str)
        .await
        .map_err(|e| anyhow::anyhow!("DNS lookup failed for {server_addr_str}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {server_addr_str}"))?;

    let server_name = server_addr_str
        .split(':')
        .next()
        .unwrap_or(server_addr_str)
        .to_string();

    tracing::info!(server = %server_addr_str, "connecting to edge");

    let connection = endpoint
        .connect(server_addr, &server_name)?
        .await
        .map_err(|e| anyhow::anyhow!("QUIC connect failed: {e}"))?;

    tracing::info!(server = %server_addr_str, "connected, authenticating");

    // Send AuthRequest on a unidirectional stream
    let mut auth_send = connection.open_uni().await?;
    protocol::write_message(
        &mut auth_send,
        &Message::AuthRequest(AuthRequest {
            jwt: jwt.to_string(),
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

    sievetube_common::metrics::init()
        .active_quic_connections
        .inc();

    let result = serve_streams(connection, matcher, tunnel_id, shutdown).await;

    sievetube_common::metrics::global()
        .active_quic_connections
        .dec();

    result
}

async fn serve_streams(
    connection: quinn::Connection,
    matcher: Arc<IngressMatcher>,
    tunnel_id: &str,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
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
                let (send, mut recv) = match result {
                    Ok(s) => s,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };

                let connect_req = match protocol::read_message(&mut recv).await? {
                    Message::ConnectRequest(r) => r,
                    _ => {
                        tracing::warn!(tunnel_id, "expected ConnectRequest, got something else");
                        continue;
                    }
                };

                let hostname = connect_req.hostname.clone();
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
                        continue;
                    }
                };

                let tid = tunnel_id.to_string();
                tokio::spawn(async move {
                    crate::forwarder::handle_stream(send, recv, target, tid, hostname).await;
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

                let payload = payload.to_vec();
                let conn = connection.clone();
                tokio::spawn(async move {
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

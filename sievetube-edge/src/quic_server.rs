use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use sievetube_common::auth::verify_jwt;
use sievetube_common::config::Protocol;
use sievetube_common::error::app_error;
use sievetube_common::hostname::{self, HostnameError};
use sievetube_common::protocol::{
    self, AuthRequest, AuthResponse, Message, ServiceAdvertisement, ALPN_PROTOCOL,
};

use crate::connector_registry::{ConnectorRegistry, Registration};
use crate::mesh::routes::RouteAdvertiser;
use crate::tls::generate_self_signed;
use crate::tunnel;
use crate::valkey::{ClaimOutcome, ValkeyHandle};

/// Maximum time for a Connector to complete authentication after connecting.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared state for Connector connection handling.
pub struct QuicContext {
    pub registry: ConnectorRegistry,
    pub jwt_secret: Vec<u8>,
    pub valkey: Option<ValkeyHandle>,
    /// Advertises this Edge's routes to mesh peers
    pub advertiser: Option<Arc<RouteAdvertiser>>,
    pub udp_reply_timeout: Duration,
    pub udp_max_pending_replies: usize,
}

/// Build a QUIC server endpoint for incoming Connector connections.
///
/// With `cert`/`key` the Edge presents a certificate Connectors can verify against
/// their configured CA; otherwise a self-signed certificate is generated and
/// Connectors have to pin it or skip verification.
pub fn build_endpoint(
    listen_addr: &str,
    cert: Option<&str>,
    key: Option<&str>,
) -> anyhow::Result<quinn::Endpoint> {
    let (certs, key) = match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)
                .map_err(|e| anyhow::anyhow!("cannot read {cert_path}: {e}"))?;
            let key_pem = std::fs::read(key_path)
                .map_err(|e| anyhow::anyhow!("cannot read {key_path}: {e}"))?;
            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<_, _>>()?;
            if certs.is_empty() {
                anyhow::bail!("no certificate found in {cert_path}");
            }
            let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
                .ok_or_else(|| anyhow::anyhow!("no private key found in {key_path}"))?;
            (certs, key)
        }
        _ => {
            tracing::warn!(
                "no server.quic_cert configured; using a self-signed certificate that Connectors cannot verify against a CA"
            );
            generate_self_signed()?
        }
    };

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;
    tls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("QuicServerConfig error: {e}"))?;

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(10_000u32.into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport.datagram_receive_buffer_size(Some(65535));

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport));

    let addr: std::net::SocketAddr = listen_addr
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid QUIC listen address: {listen_addr}"))?;

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    Ok(endpoint)
}

/// Accept incoming Connector QUIC connections and authenticate them.
pub async fn accept_loop(
    endpoint: quinn::Endpoint,
    ctx: Arc<QuicContext>,
    shutdown: CancellationToken,
) {
    if let Ok(addr) = endpoint.local_addr() {
        tracing::info!(addr = %addr, "QUIC server listening for connectors");
    }

    loop {
        let incoming = tokio::select! {
            _ = shutdown.cancelled() => return,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => return,
            },
        };
        let ctx = ctx.clone();

        tokio::spawn(async move {
            let remote_addr = incoming.remote_address();
            match incoming.await {
                Ok(conn) => {
                    tracing::debug!(remote_addr = %remote_addr, "new connector connection");
                    handle_connector(conn, ctx).await;
                }
                Err(e) => {
                    tracing::warn!(remote_addr = %remote_addr, error = %e, "connector handshake failed");
                }
            }
        });
    }
}

async fn read_auth_request(connection: &quinn::Connection) -> anyhow::Result<AuthRequest> {
    let mut auth_recv = connection.accept_uni().await?;
    match protocol::read_message(&mut auth_recv).await? {
        Message::AuthRequest(request) => Ok(request),
        _ => anyhow::bail!("expected AuthRequest"),
    }
}

async fn handle_connector(connection: quinn::Connection, ctx: Arc<QuicContext>) {
    let remote = connection.remote_address();

    // Wait for the Connector to open a unidirectional stream and send AuthRequest
    let auth_req = match tokio::time::timeout(AUTH_TIMEOUT, read_auth_request(&connection)).await {
        Ok(Ok(request)) => request,
        Ok(Err(e)) => {
            tracing::warn!(remote_addr = %remote, error = %e, "failed to read AuthRequest");
            connection.close(app_error::AUTH_FAILED.into(), b"invalid auth request");
            return;
        }
        Err(_) => {
            tracing::warn!(remote_addr = %remote, "authentication timed out");
            connection.close(app_error::AUTH_FAILED.into(), b"auth timeout");
            return;
        }
    };

    // Verify JWT
    let claims = match verify_jwt(&auth_req.jwt, &ctx.jwt_secret) {
        Ok(data) => data.claims,
        Err(e) => {
            tracing::warn!(remote_addr = %remote, error = %e, "JWT verification failed");
            reject(&connection, e.to_string(), b"auth failed").await;
            return;
        }
    };

    let tenant_id = claims.sub.clone();
    let hostnames = match normalize_claimed_hostnames(&claims.hostnames) {
        Ok(hostnames) => hostnames,
        Err(e) => {
            tracing::warn!(remote_addr = %remote, tenant_id, error = %e, "invalid hostname in token");
            reject(
                &connection,
                format!("invalid hostname in token: {e}"),
                b"auth failed",
            )
            .await;
            return;
        }
    };
    let services = auth_req
        .services
        .map(|advertised| services_for(&hostnames, advertised));

    // Claim hostname ownership atomically. When the control plane cannot be
    // reached, only ownership confirmed earlier in this process is accepted.
    if let Some(valkey) = &ctx.valkey {
        match valkey.claim_hostnames(&tenant_id, &hostnames).await {
            Ok(ClaimOutcome::Claimed) => {}
            Ok(ClaimOutcome::Conflict { hostname }) => {
                tracing::warn!(remote_addr = %remote, tenant_id, hostname, "hostname owned by another tenant");
                reject(
                    &connection,
                    format!("hostname '{hostname}' is already claimed by another tenant"),
                    b"hostname conflict",
                )
                .await;
                return;
            }
            Err(e) if valkey.previously_confirmed(&tenant_id, &hostnames) => {
                tracing::warn!(tenant_id, error = %e, "valkey unavailable; accepting ownership confirmed earlier");
            }
            Err(e) => {
                tracing::warn!(remote_addr = %remote, tenant_id, error = %e, "cannot verify hostname ownership");
                reject(
                    &connection,
                    "control plane unavailable; hostname ownership cannot be verified".to_string(),
                    b"control plane unavailable",
                )
                .await;
                return;
            }
        }
    }

    let udp_reply_map =
        tunnel::UdpReplyTable::new(ctx.udp_max_pending_replies, ctx.udp_reply_timeout);
    let registration = Registration {
        tenant_id: tenant_id.clone(),
        hostnames,
        services,
        connection: connection.clone(),
        udp_reply_map: udp_reply_map.clone(),
    };
    let registered = match ctx.registry.register(registration) {
        Ok(registered) => registered,
        Err(e) => {
            tracing::warn!(remote_addr = %remote, tenant_id, error = %e, "registration failed");
            reject(&connection, e, b"registration failed").await;
            return;
        }
    };
    let handle = registered.handle;
    // The replaced connection receives no traffic any more; without closing it,
    // its Connector would keep believing it is serving and the connection would
    // stay open, since both sides keep it alive.
    if let Some(previous) = registered
        .replaced
        .filter(|previous| previous.connection.stable_id() != connection.stable_id())
    {
        previous.connection.close(
            app_error::GOING_AWAY.into(),
            b"replaced by a newer connection",
        );
    }

    if let Some(valkey) = &ctx.valkey {
        if let Err(e) = valkey.register_presence(&tenant_id).await {
            tracing::warn!(tenant_id, error = %e, "valkey presence registration failed (non-fatal)");
        }
    }

    send_auth_response(&connection, true, None).await;
    tracing::info!(tenant_id, remote_addr = %remote, generation = handle.generation, "connector authenticated");

    // Routes are advertised only after the Connector is authenticated and registered.
    if let Some(advertiser) = &ctx.advertiser {
        advertiser.advertise_now().await;
    }

    // Spawn UDP reply loop for this connector connection
    {
        let conn = connection.clone();
        tokio::spawn(async move {
            tunnel::udp_reply_loop(conn, udp_reply_map).await;
        });
    }

    // Wait for the connection to close
    let close_reason = connection.closed().await;
    tracing::info!(tenant_id, reason = ?close_reason, "connector disconnected");

    // Only the current generation may deregister; a newer connection keeps its routes.
    if ctx.registry.remove(&tenant_id, handle.generation) {
        if let Some(advertiser) = &ctx.advertiser {
            advertiser.withdraw_registration(&handle).await;
        }
        if let Some(valkey) = &ctx.valkey {
            if let Err(e) = valkey.deregister_presence(&tenant_id).await {
                tracing::warn!(tenant_id, error = %e, "valkey deregistration failed (non-fatal)");
            }
        }
    }
}

fn normalize_claimed_hostnames(raw: &[String]) -> Result<Vec<String>, HostnameError> {
    let mut hostnames = Vec::with_capacity(raw.len());
    for hostname in raw {
        let normalized = hostname::normalize_hostname(hostname)?;
        if !hostnames.contains(&normalized) {
            hostnames.push(normalized);
        }
    }
    Ok(hostnames)
}

/// Restrict advertised services to hostnames authorized by the token.
fn services_for(
    hostnames: &[String],
    advertised: Vec<ServiceAdvertisement>,
) -> HashMap<String, Vec<Protocol>> {
    let mut services: HashMap<String, Vec<Protocol>> = HashMap::new();
    for ad in advertised {
        let Ok(hostname) = hostname::normalize_hostname(&ad.hostname) else {
            continue;
        };
        if !hostnames.contains(&hostname) {
            continue;
        }
        let protocols = services.entry(hostname).or_default();
        for protocol in ad.protocols {
            if !protocols.contains(&protocol) {
                protocols.push(protocol);
            }
        }
    }
    services
}

async fn reject(connection: &quinn::Connection, reason: String, close_reason: &[u8]) {
    send_auth_response(connection, false, Some(reason)).await;
    connection.close(app_error::AUTH_FAILED.into(), close_reason);
}

async fn send_auth_response(connection: &quinn::Connection, ok: bool, reason: Option<String>) {
    let Ok(mut send) = connection.open_uni().await else {
        return;
    };
    let _ = protocol::write_message(
        &mut send,
        &Message::AuthResponse(AuthResponse { ok, reason }),
    )
    .await;
    let _ = send.finish();
    // Give the peer a chance to receive the response before a close.
    let _ = tokio::time::timeout(Duration::from_millis(200), send.stopped()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimed_hostnames_are_normalized_and_deduplicated() {
        let hostnames =
            normalize_claimed_hostnames(&["A.test".into(), "a.test.".into(), "b.test".into()])
                .unwrap();
        assert_eq!(hostnames, vec!["a.test", "b.test"]);
        assert!(normalize_claimed_hostnames(&["bad host".into()]).is_err());
    }

    #[test]
    fn services_are_limited_to_claimed_hostnames() {
        let services = services_for(
            &["a.test".to_string()],
            vec![
                ServiceAdvertisement {
                    hostname: "A.test".into(),
                    protocols: vec![Protocol::Http, Protocol::Http],
                },
                ServiceAdvertisement {
                    hostname: "evil.test".into(),
                    protocols: vec![Protocol::Tcp],
                },
            ],
        );
        assert_eq!(services.len(), 1);
        assert_eq!(services["a.test"], vec![Protocol::Http]);
    }
}

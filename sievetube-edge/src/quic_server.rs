use std::sync::Arc;

use sievetube_common::auth::verify_jwt;
use sievetube_common::error::app_error;
use sievetube_common::protocol::{self, AuthResponse, Message, ALPN_PROTOCOL};

use crate::connector_registry::ConnectorRegistry;
use crate::tls::generate_self_signed;
use crate::tunnel;
use crate::valkey::ValkeyHandle;

/// Build a QUIC server endpoint for incoming Connector connections.
pub fn build_endpoint(listen_addr: &str) -> anyhow::Result<quinn::Endpoint> {
    let (certs, key) = generate_self_signed()?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;
    tls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
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
    registry: ConnectorRegistry,
    jwt_secret: Arc<Vec<u8>>,
    valkey: Option<ValkeyHandle>,
) {
    tracing::info!(addr = %endpoint.local_addr().unwrap(), "QUIC server listening for connectors");

    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        let jwt_secret = jwt_secret.clone();
        let valkey = valkey.clone();

        tokio::spawn(async move {
            let remote_addr = incoming.remote_address();
            match incoming.await {
                Ok(conn) => {
                    tracing::debug!(remote_addr = %remote_addr, "new connector connection");
                    handle_connector(conn, registry, jwt_secret, valkey).await;
                }
                Err(e) => {
                    tracing::warn!(remote_addr = %remote_addr, error = %e, "connector handshake failed");
                }
            }
        });
    }
}

async fn handle_connector(
    connection: quinn::Connection,
    registry: ConnectorRegistry,
    jwt_secret: Arc<Vec<u8>>,
    valkey: Option<ValkeyHandle>,
) {
    let remote = connection.remote_address();

    // Wait for the Connector to open a unidirectional stream and send AuthRequest
    let mut auth_recv = match connection.accept_uni().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(remote_addr = %remote, error = %e, "failed to accept auth stream");
            return;
        }
    };

    let auth_req = match protocol::read_message(&mut auth_recv).await {
        Ok(Message::AuthRequest(r)) => r,
        Ok(_) => {
            tracing::warn!(remote_addr = %remote, "expected AuthRequest");
            connection.close(app_error::AUTH_FAILED.into(), b"expected AuthRequest");
            return;
        }
        Err(e) => {
            tracing::warn!(remote_addr = %remote, error = %e, "failed to read AuthRequest");
            connection.close(app_error::AUTH_FAILED.into(), b"read error");
            return;
        }
    };

    // Verify JWT
    let claims = match verify_jwt(&auth_req.jwt, &jwt_secret) {
        Ok(data) => data.claims,
        Err(e) => {
            tracing::warn!(remote_addr = %remote, error = %e, "JWT verification failed");
            send_auth_response(&connection, false, Some(e.to_string())).await;
            connection.close(app_error::AUTH_FAILED.into(), b"auth failed");
            return;
        }
    };

    let tenant_id = claims.sub.clone();

    // Check hostname ownership in Valkey to prevent cross-tenant conflicts
    if let Some(ref v) = valkey {
        for hostname in &claims.hostnames {
            match v.check_hostname_owner(hostname).await {
                Ok(Some(ref owner)) if owner != &tenant_id => {
                    tracing::warn!(
                        remote_addr = %remote,
                        tenant_id,
                        hostname,
                        existing_owner = %owner,
                        "hostname owned by another tenant"
                    );
                    send_auth_response(
                        &connection,
                        false,
                        Some(format!("hostname '{hostname}' is already claimed by another tenant")),
                    ).await;
                    connection.close(app_error::AUTH_FAILED.into(), b"hostname conflict");
                    return;
                }
                Ok(_) => {} // unclaimed or owned by same tenant
                Err(e) => {
                    tracing::warn!(hostname, error = %e, "valkey hostname check failed (allowing registration)");
                }
            }
        }
    }

    // Create UDP reply map for this connector
    let udp_reply_map = tunnel::new_udp_reply_map();

    // Register in ConnectorRegistry
    if let Err(e) = registry.register(&claims, connection.clone(), udp_reply_map.clone()) {
        tracing::warn!(remote_addr = %remote, tenant_id, error = %e, "registration failed");
        send_auth_response(&connection, false, Some(e)).await;
        connection.close(app_error::AUTH_FAILED.into(), b"registration failed");
        return;
    }

    // Publish to Valkey
    if let Some(ref v) = valkey {
        if let Err(e) = v.register_connector(&tenant_id, &claims.hostnames).await {
            tracing::warn!(tenant_id, error = %e, "valkey registration failed (non-fatal)");
        }
    }

    // Send AuthResponse (success)
    send_auth_response(&connection, true, None).await;

    tracing::info!(tenant_id, remote_addr = %remote, "connector authenticated");

    // Spawn UDP reply loop for this connector connection
    {
        let conn = connection.clone();
        let reply_map = udp_reply_map;
        tokio::spawn(async move {
            tunnel::udp_reply_loop(conn, reply_map).await;
        });
    }

    // Wait for the connection to close
    let close_reason = connection.closed().await;
    tracing::info!(tenant_id, reason = ?close_reason, "connector disconnected");

    registry.remove_tenant(&tenant_id);

    if let Some(ref v) = valkey {
        if let Err(e) = v.deregister_connector(&tenant_id).await {
            tracing::warn!(tenant_id, error = %e, "valkey deregistration failed (non-fatal)");
        }
    }
}

async fn send_auth_response(
    connection: &quinn::Connection,
    ok: bool,
    reason: Option<String>,
) {
    let Ok(mut send) = connection.open_uni().await else {
        return;
    };
    let _ = protocol::write_message(
        &mut send,
        &Message::AuthResponse(AuthResponse { ok, reason }),
    )
    .await;
    let _ = send.finish();
}

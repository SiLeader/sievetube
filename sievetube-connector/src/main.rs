mod config;
mod forwarder;
mod health;
mod ingress;
mod quic_client;
mod valkey;

use std::path::PathBuf;
use std::sync::Arc;

use ingress::IngressMatcher;
use sievetube_common::observability;

fn parse_config_path() -> PathBuf {
    std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the ring CryptoProvider for rustls (required by quinn 0.11 + rustls 0.23)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    observability::init_tracing("sievetube-connector");
    sievetube_common::metrics::init();

    let config_path = parse_config_path();
    tracing::info!(config = ?config_path, "loading configuration");

    let cfg = config::ConnectorConfig::from_file(&config_path)?;

    // Extract claims from JWT for display and service advertisement
    // (no signature verification; the Edge verifies the token)
    let claims = extract_jwt_claims(&cfg.auth.token);
    let tunnel_id = claims
        .as_ref()
        .and_then(|c| c["sub"].as_str())
        .unwrap_or("unknown")
        .to_string();

    tracing::info!(tunnel_id, "connector starting");

    let matcher = Arc::new(IngressMatcher::new(cfg.ingress.clone()));
    let services = claims
        .as_ref()
        .and_then(|c| c["hostnames"].as_array())
        .map(|hostnames| {
            let hostnames: Vec<String> = hostnames
                .iter()
                .filter_map(|h| h.as_str().map(str::to_string))
                .collect();
            Arc::new(matcher.services(&hostnames))
        });

    // Connect to Valkey and start heartbeat (optional)
    if let Some(ref valkey_cfg) = cfg.valkey {
        let tunnel_id_clone = tunnel_id.clone();
        let url = valkey_cfg.url.clone();
        let interval = std::time::Duration::from_secs(valkey_cfg.heartbeat_interval_secs);
        let edge_id = cfg
            .network
            .public_servers
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        match valkey::connect(&url).await {
            Ok(conn) => {
                tracing::info!(url = %url, "connected to valkey");
                tokio::spawn(async move {
                    valkey::heartbeat_loop(conn, tunnel_id_clone, edge_id, interval).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to connect to valkey (continuing without heartbeat)");
            }
        }
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let drain_timeout = std::time::Duration::from_secs(cfg.network.drain_timeout_secs);

    // How the Edge's certificate is checked (CA, pinning, or not at all).
    let verification = || {
        quic_client::EdgeVerification::from_config(
            cfg.network.edge_ca_cert.as_deref(),
            &cfg.network.edge_cert_sha256,
        )
    };

    // Spawn a connection task for each public server (full-mesh topology)
    let connections = tokio_util::task::TaskTracker::new();
    for server in &cfg.network.public_servers {
        let server = server.clone();
        let jwt = cfg.auth.token.clone();
        let matcher = matcher.clone();
        let services = services.clone();
        let tid = tunnel_id.clone();
        let shutdown = shutdown_rx.clone();

        let edge_verification = verification()?;
        let server_name = cfg.network.edge_server_name.clone();
        connections.spawn(async move {
            quic_client::run_connection(
                server,
                jwt,
                services,
                matcher,
                tid,
                edge_verification,
                server_name,
                drain_timeout,
                shutdown,
            )
            .await;
        });
    }
    connections.close();

    // Health/metrics server
    let health_addr =
        std::env::var("SIEVETUBE_HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:9091".to_string());
    tokio::spawn(async move {
        if let Err(e) = health::serve(&health_addr).await {
            tracing::error!(error = %e, "health server failed");
        }
    });

    wait_for_shutdown_signal().await;
    tracing::info!("shutdown signal received, draining connections...");
    let _ = shutdown_tx.send(true);

    // Each connection tells its Edge to stop sending new traffic and closes once
    // its streams finished or its drain timeout passed.
    let grace = drain_timeout + std::time::Duration::from_secs(5);
    if tokio::time::timeout(grace, connections.wait())
        .await
        .is_err()
    {
        tracing::warn!("connections did not close in time");
    }
    tracing::info!("exiting");
    Ok(())
}

/// SIGTERM (service managers, container runtimes) or Ctrl-C.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot listen for SIGTERM; only Ctrl-C stops the connector gracefully");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Decode the claims from a JWT payload without verifying the signature.
/// Used only for logging and advertisement — not a security boundary.
fn extract_jwt_claims(token: &str) -> Option<serde_json::Value> {
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64url_decode(payload_b64)?;
    serde_json::from_slice(&bytes).ok()
}

/// Minimal URL-safe base64 decode (no padding required).
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let lookup: [u8; 256] = {
        let mut t = [0xffu8; 256];
        for (i, &c) in TABLE.iter().enumerate() {
            t[c as usize] = i as u8;
        }
        t
    };

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut i = 0;
    while i < bytes.len() {
        let a = lookup[bytes[i] as usize];
        if a == 0xff {
            return None;
        }
        if i + 1 >= bytes.len() {
            break;
        }
        let b = lookup[bytes[i + 1] as usize];
        if b == 0xff {
            return None;
        }
        out.push((a << 2) | (b >> 4));

        if i + 2 < bytes.len() {
            let c = lookup[bytes[i + 2] as usize];
            if c == 0xff {
                return None;
            }
            out.push(((b & 0x0f) << 4) | (c >> 2));

            if i + 3 < bytes.len() {
                let d = lookup[bytes[i + 3] as usize];
                if d == 0xff {
                    return None;
                }
                out.push(((c & 0x03) << 6) | d);
            }
        }
        i += 4;
    }
    Some(out)
}

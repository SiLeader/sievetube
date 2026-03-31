mod config;
mod connector_registry;
mod health;
mod listener;
mod quic_server;
mod router;
mod tls;
mod tunnel;
mod valkey;

use std::path::PathBuf;
use std::sync::Arc;

use connector_registry::ConnectorRegistry;
use sievetube_common::observability;

fn issue_token_command(args: &[String]) -> anyhow::Result<()> {
    use sievetube_common::auth::{sign_jwt, TunnelClaims};

    let mut secret: Option<String> = None;
    let mut sub: Option<String> = None;
    let mut hostnames: Vec<String> = Vec::new();
    let mut exp_hours: u64 = 8760; // default: 1 year

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret" => {
                i += 1;
                secret = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--secret requires a value"))?
                        .clone(),
                );
            }
            "--sub" => {
                i += 1;
                sub = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--sub requires a value"))?
                        .clone(),
                );
            }
            "--hostname" => {
                i += 1;
                hostnames.push(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--hostname requires a value"))?
                        .clone(),
                );
            }
            "--exp-hours" => {
                i += 1;
                exp_hours = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--exp-hours requires a value"))?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--exp-hours must be a positive integer"))?;
            }
            other => anyhow::bail!("unknown flag: {other}\nUsage: sievetube-edge issue-token --secret <secret> --sub <tenant_id> --hostname <hostname> [--exp-hours <hours>]"),
        }
        i += 1;
    }

    let secret = secret.ok_or_else(|| anyhow::anyhow!("--secret is required"))?;
    let sub = sub.ok_or_else(|| anyhow::anyhow!("--sub is required"))?;
    if hostnames.is_empty() {
        anyhow::bail!("at least one --hostname is required");
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = TunnelClaims {
        sub,
        hostnames,
        exp: now + exp_hours * 3600,
        iat: now,
    };

    let token = sign_jwt(&claims, secret.as_bytes())?;
    println!("{token}");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("issue-token") {
        return issue_token_command(&args[2..]);
    }

    // Install the ring CryptoProvider for rustls (required by quinn 0.11 + rustls 0.23)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    observability::init_tracing("sievetube-edge");
    sievetube_common::metrics::init();

    let config_path = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("edge.toml"));
    tracing::info!(config = ?config_path, "loading configuration");

    let cfg = config::EdgeConfig::from_file(&config_path)?;
    let edge_id = uuid::Uuid::new_v4().to_string();

    tracing::info!(edge_id, "edge starting");

    let registry = ConnectorRegistry::new();

    // Connect to Valkey (optional; non-fatal if unavailable or not configured)
    let valkey = if let Some(ref vcfg) = cfg.valkey {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            valkey::ValkeyHandle::connect(&vcfg.url, &edge_id),
        )
        .await
        {
            Ok(Ok(v)) => {
                tracing::info!(url = %vcfg.url, "connected to valkey");
                Some(v)
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "failed to connect to valkey (running without state management)");
                None
            }
            Err(_) => {
                tracing::warn!(url = %vcfg.url, "valkey connection timed out (running without state management)");
                None
            }
        }
    } else {
        tracing::debug!("valkey not configured");
        None
    };

    // Load BYOC TLS certificates
    let cert_dir = std::path::Path::new(&cfg.tls.cert_dir);
    let tls_resolver = if cert_dir.exists() {
        match tls::BYOCCertResolver::load_from_dir(cert_dir) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error = %e, "failed to load TLS certs, HTTPS disabled");
                None
            }
        }
    } else {
        tracing::warn!(cert_dir = %cfg.tls.cert_dir, "cert_dir does not exist, HTTPS disabled");
        None
    };

    let jwt_secret = Arc::new(cfg.auth.jwt_secret.as_bytes().to_vec());

    // Spawn QUIC server for Connectors (keep handle for graceful shutdown)
    let quic_endpoint = quic_server::build_endpoint(&cfg.server.quic_listen)?;
    {
        let endpoint = quic_endpoint.clone();
        let registry = registry.clone();
        let jwt_secret = jwt_secret.clone();
        let valkey = valkey.clone();
        tokio::spawn(async move {
            quic_server::accept_loop(endpoint, registry, jwt_secret, valkey).await;
        });
    }

    // Spawn HTTP listener
    {
        let registry = registry.clone();
        let addr = cfg.server.http_listen.clone();
        tokio::spawn(async move {
            if let Err(e) = listener::serve_http(&addr, registry).await {
                tracing::error!(error = %e, "HTTP listener failed");
            }
        });
    }

    // Spawn HTTPS listener (if certs available)
    if let Some(resolver) = tls_resolver {
        let registry = registry.clone();
        let addr = cfg.server.https_listen.clone();
        tokio::spawn(async move {
            if let Err(e) = listener::serve_https(&addr, registry, resolver).await {
                tracing::error!(error = %e, "HTTPS listener failed");
            }
        });
    }

    // Spawn raw TCP listeners
    for entry in &cfg.server.tcp_listen {
        let registry = registry.clone();
        let addr = entry.addr.clone();
        let hostname = entry.hostname.clone();
        tokio::spawn(async move {
            if let Err(e) = listener::serve_raw_tcp(&addr, hostname, registry).await {
                tracing::error!(addr, error = %e, "raw TCP listener failed");
            }
        });
    }

    // Spawn UDP listeners
    for entry in &cfg.server.udp_listen {
        let registry = registry.clone();
        let addr = entry.addr.clone();
        let hostname = entry.hostname.clone();
        tokio::spawn(async move {
            if let Err(e) = listener::serve_udp(&addr, hostname, registry).await {
                tracing::error!(addr, error = %e, "UDP listener failed");
            }
        });
    }

    // Spawn health/metrics server
    {
        let addr = cfg.server.health_listen.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = health::serve(&addr, registry).await {
                tracing::error!(error = %e, "health server failed");
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received, draining connections...");

    quic_endpoint.close(
        quinn::VarInt::from_u32(sievetube_common::error::app_error::GOING_AWAY),
        b"server shutting down",
    );
    quic_endpoint.wait_idle().await;

    tracing::info!("all connections drained, exiting");
    Ok(())
}

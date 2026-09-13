mod acme;
mod certificate_store;
mod config;
mod connector_registry;
mod dns;
mod edge_metrics;
mod health;
mod http_proxy;
mod listener;
mod mesh;
mod plugins;
mod policy;
mod quic_server;
mod router;
#[cfg(test)]
mod test_support;
mod tls;
mod tunnel;
mod valkey;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use certificate_store::now_unix;
use connector_registry::ConnectorRegistry;
use sievetube_common::observability;

/// How often the control-plane connection is verified with a round trip.
const VALKEY_LIVENESS_INTERVAL: Duration = Duration::from_secs(5);

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
    // Mesh messages carry the tenant id and are limited to this length.
    if sub.is_empty() || sub.len() > sievetube_common::mesh_protocol::MAX_ID_LEN {
        anyhow::bail!(
            "--sub must be between 1 and {} bytes",
            sievetube_common::mesh_protocol::MAX_ID_LEN
        );
    }
    if hostnames.is_empty() {
        anyhow::bail!("at least one --hostname is required");
    }
    for hostname in &mut hostnames {
        *hostname = sievetube_common::hostname::normalize_hostname(hostname)
            .map_err(|e| anyhow::anyhow!("invalid --hostname {hostname:?}: {e}"))?;
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

    match args.get(1).map(String::as_str) {
        Some("mesh-ca") => return mesh_ca_command(&args[2..]),
        Some("mesh-cert") => return mesh_cert_command(&args[2..]),
        _ => {}
    }

    if args.get(1).map(String::as_str) == Some("dns-plan") {
        return dns_plan_command(&args[2..]).await;
    }

    observability::init_tracing("sievetube-edge");
    sievetube_common::metrics::init();

    let config_path = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("edge.toml"));
    tracing::info!(config = ?config_path, "loading configuration");

    let cfg = config::EdgeConfig::from_file(&config_path)?;
    // A mesh needs a stable identity; without one a random id per start is fine.
    let edge_id = cfg
        .mesh
        .as_ref()
        .map(|mesh| mesh.edge_id.clone())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    tracing::info!(edge_id, "edge starting");

    let shutdown = CancellationToken::new();
    let tracker = TaskTracker::new();
    let (reload_tx, reload_rx) = watch::channel(0u64);
    spawn_reload_signal(reload_tx);

    let registry = ConnectorRegistry::new();

    // Traffic policy: validated at load; SIGHUP re-validates the whole config file
    // and swaps the policy only if it is valid.
    let policy = policy::Policy::new(&cfg.policy)?;
    tokio::spawn(policy_maintenance_loop(policy.clone(), shutdown.clone()));
    tokio::spawn(config_reload_loop(
        config_path.clone(),
        policy.clone(),
        reload_rx.clone(),
        shutdown.clone(),
    ));

    // Valkey is optional. When configured, it is required for new hostname claims:
    // the edge starts without it and keeps retrying in the background.
    let valkey = match &cfg.valkey {
        Some(vcfg) => {
            let handle = valkey::ValkeyHandle::new(&vcfg.url, &edge_id)?;
            match tokio::time::timeout(Duration::from_secs(5), handle.try_connect()).await {
                Ok(Ok(())) => tracing::info!("connected to valkey"),
                _ => {
                    tracing::warn!("valkey unavailable at startup; new hostname claims are paused until it connects");
                    tokio::spawn(handle.clone().connect_loop(shutdown.clone()));
                }
            }
            Some(handle)
        }
        None => {
            tracing::debug!("valkey not configured");
            None
        }
    };
    if let Some(handle) = valkey.clone() {
        tokio::spawn(presence_loop(handle.clone(), shutdown.clone()));
        // Keeps readiness and the ACME coordination honest: the client
        // reconnects silently, so reachability has to be checked.
        tokio::spawn(handle.liveness_loop(VALKEY_LIVENESS_INTERVAL, shutdown.clone()));
    }

    // DNS providers are shared by record management and ACME dns-01.
    let acme_dns01 = cfg
        .tls
        .acme
        .as_ref()
        .is_some_and(|a| a.enabled && a.challenge == config::AcmeChallenge::Dns01);
    let dns_setup = if cfg.dns.enabled || acme_dns01 {
        let compiled = dns::plan::compile(&cfg.dns)?;
        let providers = dns::build_providers(&compiled).await?;
        Some((compiled, providers))
    } else {
        None
    };

    // Public TLS certificates: loaded now and re-read periodically / on SIGHUP.
    let cert_resolver = tls::CertResolver::new();
    let cert_dir = PathBuf::from(&cfg.tls.cert_dir);

    // ACME-managed names are declared before BYOC files are read. A BYOC file for
    // a managed name is a configuration error rather than a silent override.
    let acme_manager = match cfg.tls.acme.as_ref().filter(|a| a.enabled) {
        Some(acme_cfg) => {
            if let Some(domain) = acme_cfg
                .domains
                .iter()
                .find(|d| cert_dir.join(format!("{d}.crt")).exists())
            {
                anyhow::bail!(
                    "{domain} is listed in tls.acme.domains but {}/{domain}.crt also exists; remove one of them",
                    cert_dir.display()
                );
            }
            let coordination = match acme_cfg.coordination {
                config::AcmeCoordination::Valkey => {
                    acme::Coordination::Valkey(valkey.clone().ok_or_else(|| {
                        anyhow::anyhow!("tls.acme.coordination = \"valkey\" requires [valkey]")
                    })?)
                }
                config::AcmeCoordination::None => acme::Coordination::Local,
            };
            let dns01 = match (&dns_setup, acme_cfg.challenge) {
                (Some((compiled, providers)), config::AcmeChallenge::Dns01) => {
                    let zone_providers = compiled
                        .providers
                        .iter()
                        .filter_map(|spec| {
                            providers
                                .get(&spec.name)
                                .map(|p| (spec.zone.clone(), p.clone()))
                        })
                        .collect();
                    let resolvers = acme_cfg
                        .dns_resolvers
                        .iter()
                        .map(|r| config::parse_resolver_addr(r))
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    Some(Arc::new(dns::txt::TxtChallengeSolver::new(
                        zone_providers,
                        compiled.allowed_zones.clone(),
                        dns::txt::TxtLookup::dns(&resolvers)?,
                        dns::txt::TxtSettings {
                            ttl: acme_cfg.dns_txt_ttl,
                            propagation_timeout: Duration::from_secs(
                                acme_cfg.dns_propagation_timeout_secs,
                            ),
                            poll_interval: Duration::from_secs(acme_cfg.dns_propagation_poll_secs),
                        },
                        acme::AcmeManager::dns01_journal_path(acme_cfg),
                    )))
                }
                _ => None,
            };
            let manager = acme::AcmeManager::new(
                acme_cfg.clone(),
                cert_resolver.clone(),
                Arc::new(acme::SystemClock),
                coordination,
                dns01,
            )?;
            manager.load_existing();
            tokio::spawn(manager.clone().run(shutdown.clone()));
            tracing::info!(domains = ?acme_cfg.domains, directory = %acme_cfg.directory_url, "ACME certificate management enabled");
            Some(manager)
        }
        None => None,
    };
    let report = cert_resolver.reload_byoc(&cert_dir, now_unix());
    tracing::info!(cert_dir = %cert_dir.display(), loaded = report.loaded, failed = report.failed, "loaded TLS certificates");
    edge_metrics::update_certificates(&cert_resolver, now_unix());
    tokio::spawn(certificate_reload_loop(
        cert_resolver.clone(),
        cert_dir,
        Duration::from_secs(cfg.tls.reload_interval_secs),
        reload_rx.clone(),
        shutdown.clone(),
    ));

    // DNS record management (explicitly listed records only)
    if let Some((compiled, providers)) = dns_setup.clone().filter(|_| cfg.dns.enabled) {
        let writer = match &valkey {
            Some(handle) if !cfg.dns.single_writer => {
                dns::reconciler::WriterMode::Valkey(handle.clone())
            }
            _ => dns::reconciler::WriterMode::SingleWriter,
        };
        let reconciler = dns::reconciler::DnsReconciler::new(
            dns_settings(&cfg.dns),
            compiled,
            providers,
            writer,
        );
        tracing::info!(
            records = cfg.dns.records.len(),
            dry_run = cfg.dns.dry_run,
            "DNS record management enabled"
        );
        tokio::spawn(reconciler.run(shutdown.clone()));
    }

    // Edge-to-Edge forwarding
    let mesh_runtime = match (cfg.routing.mode, cfg.mesh.as_ref()) {
        (Some(config::RoutingMode::Mesh), Some(mesh_cfg)) => Some(
            mesh::setup::start(
                mesh_cfg,
                registry.clone(),
                valkey.clone(),
                Duration::from_secs(cfg.server.udp_reply_timeout_secs),
                shutdown.clone(),
                tracker.clone(),
            )
            .await?,
        ),
        _ => {
            if cfg.mesh.is_some() {
                tracing::info!(
                    "[mesh] is configured but routing.mode is \"direct\"; traffic is not forwarded between edges"
                );
            }
            None
        }
    };
    let router = {
        let router = router::Router::new(registry.clone())
            .with_open_timeout(cfg.http.backend_open_timeout());
        match &mesh_runtime {
            Some(runtime) => router.with_mesh(runtime.service.clone()),
            None => router,
        }
    };

    // QUIC server for Connectors (keep handle for graceful shutdown)
    let quic_endpoint = quic_server::build_endpoint(
        &cfg.server.quic_listen,
        cfg.server.quic_cert.as_deref(),
        cfg.server.quic_key.as_deref(),
    )?;
    let quic_ctx = Arc::new(quic_server::QuicContext {
        registry: registry.clone(),
        jwt_secret: cfg.auth.jwt_secret.as_bytes().to_vec(),
        valkey: valkey.clone(),
        advertiser: mesh_runtime
            .as_ref()
            .and_then(|runtime| runtime.advertiser.clone()),
        udp_reply_timeout: Duration::from_secs(cfg.server.udp_reply_timeout_secs),
        udp_max_pending_replies: cfg.server.udp_max_pending_replies,
    });
    tokio::spawn(quic_server::accept_loop(
        quic_endpoint.clone(),
        quic_ctx,
        shutdown.clone(),
    ));

    let proxy = Arc::new(http_proxy::HttpProxy::new(
        router.clone(),
        cfg.http.clone(),
        policy.clone(),
        acme_manager.as_ref().map(|m| m.challenges()),
        tracker.clone(),
    ));

    // HTTP listener
    let http_listener = TcpListener::bind(&cfg.server.http_listen).await?;
    tracing::info!(addr = %cfg.server.http_listen, "HTTP listener started");
    tokio::spawn(proxy.clone().serve_http(http_listener, shutdown.clone()));

    // HTTPS listener: always started; names without a certificate fail the handshake
    // and become available as soon as a certificate is loaded.
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver.clone());
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let https_listener = TcpListener::bind(&cfg.server.https_listen).await?;
    tracing::info!(addr = %cfg.server.https_listen, "HTTPS listener started");
    tokio::spawn(
        proxy
            .clone()
            .serve_https(https_listener, acceptor, shutdown.clone()),
    );

    // Raw TCP listeners
    for entry in &cfg.server.tcp_listen {
        let listener = TcpListener::bind(&entry.addr).await?;
        tracing::info!(addr = %entry.addr, hostname = %entry.hostname, "raw TCP listener started");
        tokio::spawn(listener::serve_raw_tcp(
            listener,
            entry.addr.clone(),
            entry.hostname.clone(),
            router.clone(),
            policy.clone(),
            shutdown.clone(),
            tracker.clone(),
        ));
    }

    // UDP listeners
    for entry in &cfg.server.udp_listen {
        let socket = Arc::new(UdpSocket::bind(&entry.addr).await?);
        tracing::info!(addr = %entry.addr, hostname = %entry.hostname, "UDP listener started");
        tokio::spawn(listener::serve_udp(
            socket,
            entry.addr.clone(),
            entry.hostname.clone(),
            router.clone(),
            policy.clone(),
            shutdown.clone(),
        ));
    }

    // Health/metrics server
    let mut probes: Vec<health::ReadinessProbe> = Vec::new();
    {
        let resolver = cert_resolver.clone();
        probes.push(Box::new(move || resolver.readiness_issues(now_unix())));
    }
    if let Some(manager) = acme_manager.clone() {
        probes.push(Box::new(move || manager.readiness_issues(now_unix())));
    }
    if let Some(handle) = valkey.clone() {
        probes.push(Box::new(move || {
            if handle.is_connected() {
                Vec::new()
            } else {
                vec!["valkey not connected".to_string()]
            }
        }));
    }
    let health_state = Arc::new(health::HealthState {
        registry: registry.clone(),
        probes,
    });
    let health_listener = TcpListener::bind(&cfg.server.health_listen).await?;
    tokio::spawn(health::serve(
        health_listener,
        health_state,
        shutdown.clone(),
    ));

    wait_for_shutdown_signal().await;
    tracing::info!("shutdown signal received, draining connections...");

    // Stop accepting, let in-flight public connections finish, then close tunnels.
    shutdown.cancel();
    tracker.close();
    let drain = Duration::from_secs(cfg.server.drain_timeout_secs);
    if tokio::time::timeout(drain, tracker.wait()).await.is_err() {
        tracing::warn!(
            remaining = tracker.len(),
            "drain timeout reached; closing remaining connections"
        );
    }

    if let Some(runtime) = &mesh_runtime {
        runtime.close();
    }
    quic_endpoint.close(
        quinn::VarInt::from_u32(sievetube_common::error::app_error::GOING_AWAY),
        b"server shutting down",
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), quic_endpoint.wait_idle()).await;

    tracing::info!("all connections drained, exiting");
    Ok(())
}

async fn certificate_reload_loop(
    resolver: Arc<tls::CertResolver>,
    cert_dir: PathBuf,
    interval: Duration,
    mut reload: watch::Receiver<u64>,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {}
            changed = reload.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        let now = now_unix();
        let report = resolver.reload_byoc(&cert_dir, now);
        if report.changed() || report.failed > 0 {
            tracing::info!(?report, "BYOC certificates reloaded");
        }
        edge_metrics::update_certificates(&resolver, now);
    }
}

fn dns_settings(cfg: &config::DnsConfig) -> dns::reconciler::ReconcilerSettings {
    dns::reconciler::ReconcilerSettings {
        state_dir: PathBuf::from(&cfg.state_dir),
        interval: Duration::from_secs(cfg.reconcile_interval_secs),
        settle_secs: cfg.settle_secs as i64,
        lease_ttl: Duration::from_secs(cfg.lease_ttl_secs),
        dry_run: cfg.dry_run,
    }
}

/// Write `data` to `path`, restricting private material to the owner.
///
/// Private keys are written through the certificate store's atomic write, which
/// creates the file with the restricted mode instead of widening it afterwards:
/// a `write` followed by `chmod` leaves the key readable in between.
fn write_pem(path: &std::path::Path, data: &str, private: bool) -> anyhow::Result<()> {
    if private {
        return certificate_store::write_atomic(path, data.as_bytes());
    }
    std::fs::write(path, data)?;
    Ok(())
}

/// `sievetube-edge mesh-ca <dir>`: create the mesh CA (ca.pem, ca.key).
fn mesh_ca_command(args: &[String]) -> anyhow::Result<()> {
    let dir = args
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("Usage: sievetube-edge mesh-ca <dir>"))?;
    std::fs::create_dir_all(&dir)?;
    let (cert, key) = mesh::certs::generate_ca("sievetube mesh CA")?;
    write_pem(&dir.join("ca.pem"), &cert, false)?;
    write_pem(&dir.join("ca.key"), &key, true)?;
    println!("wrote {}", dir.join("ca.pem").display());
    println!("wrote {} (keep this private)", dir.join("ca.key").display());
    Ok(())
}

/// `sievetube-edge mesh-cert <ca-dir> <edge-id> [out-dir] [days]`: issue an Edge certificate.
fn mesh_cert_command(args: &[String]) -> anyhow::Result<()> {
    let usage = "Usage: sievetube-edge mesh-cert <ca-dir> <edge-id> [out-dir] [validity-days]";
    let ca_dir = args
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("{usage}"))?;
    let edge_id = args.get(1).ok_or_else(|| anyhow::anyhow!("{usage}"))?;
    let out_dir = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| ca_dir.clone());
    let days: u32 = match args.get(3) {
        Some(value) => value.parse().map_err(|_| anyhow::anyhow!("{usage}"))?,
        None => 365,
    };
    let ca_cert = std::fs::read_to_string(ca_dir.join("ca.pem"))
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", ca_dir.join("ca.pem").display()))?;
    let ca_key = std::fs::read_to_string(ca_dir.join("ca.key"))
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", ca_dir.join("ca.key").display()))?;
    let (cert, key) = mesh::certs::issue_edge_cert(&ca_cert, &ca_key, edge_id, days)?;
    std::fs::create_dir_all(&out_dir)?;
    write_pem(&out_dir.join(format!("{edge_id}.pem")), &cert, false)?;
    write_pem(&out_dir.join(format!("{edge_id}.key")), &key, true)?;
    println!("wrote {}", out_dir.join(format!("{edge_id}.pem")).display());
    println!(
        "wrote {} (keep this private)",
        out_dir.join(format!("{edge_id}.key")).display()
    );
    Ok(())
}

/// `sievetube-edge dns-plan <config>`: print the DNS changes that would be made.
/// Reads providers and state only; never writes.
async fn dns_plan_command(args: &[String]) -> anyhow::Result<()> {
    let path = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("Usage: sievetube-edge dns-plan <edge.toml>"))?;
    let cfg = config::EdgeConfig::from_file(std::path::Path::new(path))?;
    let compiled = dns::plan::compile(&cfg.dns)?;
    let providers = dns::build_providers(&compiled).await?;
    let mut settings = dns_settings(&cfg.dns);
    settings.dry_run = true;
    let reconciler = dns::reconciler::DnsReconciler::new(
        settings,
        compiled,
        providers,
        dns::reconciler::WriterMode::SingleWriter,
    );
    let mut failed = false;
    for outcome in reconciler.plan().await {
        match &outcome.error {
            Some(error) => {
                failed = true;
                println!("{} {}: error: {error}", outcome.provider, outcome.key);
            }
            None => println!(
                "{} {}: {}",
                outcome.provider,
                outcome.key,
                outcome.action.describe()
            ),
        }
    }
    if failed {
        anyhow::bail!("some records could not be planned");
    }
    Ok(())
}

/// Announce this Edge in Valkey so that coordinated features know the live Edges.
async fn presence_loop(valkey: valkey::ValkeyHandle, shutdown: CancellationToken) {
    const PRESENCE_TTL: Duration = Duration::from_secs(30);
    let mut ticker = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                let _ = valkey.remove_presence().await;
                return;
            }
            _ = ticker.tick() => {
                if let Err(e) = valkey.heartbeat_presence(PRESENCE_TTL).await {
                    tracing::debug!(error = %e, "presence heartbeat failed");
                }
            }
        }
    }
}

/// Periodically reclaim idle policy buckets.
async fn policy_maintenance_loop(policy: Arc<policy::Policy>, shutdown: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => policy.sweep(),
        }
    }
}

/// Re-read the configuration on SIGHUP and apply reloadable sections. The whole
/// file is validated first; any error keeps the running configuration.
async fn config_reload_loop(
    path: PathBuf,
    policy: Arc<policy::Policy>,
    mut reload: watch::Receiver<u64>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            changed = reload.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        match config::EdgeConfig::from_file(&path) {
            Ok(new_cfg) => match policy.reload(&new_cfg.policy) {
                Ok(()) => tracing::info!("policy configuration reloaded"),
                Err(e) => {
                    tracing::error!(error = %e, "policy reload failed; keeping current policy")
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "configuration reload failed; keeping current configuration")
            }
        }
    }
}

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
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Bump the reload counter on SIGHUP.
fn spawn_reload_signal(reload: watch::Sender<u64>) {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let Ok(mut hangup) = signal(SignalKind::hangup()) else {
            return;
        };
        while hangup.recv().await.is_some() {
            tracing::info!("SIGHUP received, reloading");
            reload.send_modify(|generation| *generation += 1);
        }
    });
    #[cfg(not(unix))]
    drop(reload);
}

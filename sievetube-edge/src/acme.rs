//! Automatic certificate issuance and renewal with ACME (RFC 8555).
//!
//! Only domains listed by the administrator are managed; unknown SNI or
//! Connector registrations never trigger an order. Certificates are persisted in
//! the generation store and installed into the resolver without a restart.
//!
//! With `coordination = "valkey"` several Edges share one state directory: a
//! per-domain lease with a fencing generation selects the Edge that orders,
//! HTTP-01 responses are confirmed by every live Edge before validation, and the
//! other Edges install new generations from the shared store.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::certificate_store::{write_atomic, CertEntry, CertSource, CertStore};
use crate::config::{AcmeChallenge, AcmeConfig};
use crate::dns::txt::{TxtChallengeSolver, TxtHandle};
use crate::edge_metrics;
use crate::tls::CertResolver;
use crate::valkey::ValkeyHandle;

pub const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";
/// Upper bound for how long the scheduler sleeps between checks.
const MAX_SLEEP_SECS: i64 = 300;
const MAX_TOKEN_LEN: usize = 256;
const CHALLENGE_SYNC_INTERVAL: Duration = Duration::from_millis(500);
/// How often an Edge announces that it answers published HTTP-01 challenges,
/// and how long that announcement is trusted.
const RESPONDER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const RESPONDER_TTL: Duration = Duration::from_secs(30);

/// Wall-clock source (unix seconds), injectable for tests.
pub trait WallClock: Send + Sync {
    fn now_unix(&self) -> i64;
}

pub struct SystemClock;

impl WallClock for SystemClock {
    fn now_unix(&self) -> i64 {
        crate::certificate_store::now_unix()
    }
}

/// HTTP-01 responses currently served by this Edge.
pub struct Http01Challenges {
    domains: HashSet<String>,
    responses: DashMap<(String, String), String>,
    in_flight: Arc<Semaphore>,
}

impl Http01Challenges {
    pub fn new(domains: HashSet<String>, max_concurrent: usize) -> Arc<Self> {
        Arc::new(Http01Challenges {
            domains,
            responses: DashMap::new(),
            in_flight: Arc::new(Semaphore::new(max_concurrent)),
        })
    }

    /// Whether this Edge manages the certificate for `hostname` itself.
    pub fn is_managed(&self, hostname: &str) -> bool {
        self.domains.contains(hostname)
    }

    /// Whether challenge requests for this hostname are answered by the Edge.
    ///
    /// Besides its own domains this includes a hostname a peer published a
    /// response for: in a cluster the CA may reach any Edge, so every Edge has
    /// to answer for the domain being validated. Without a published response
    /// the request belongs to the tenant as usual.
    pub fn serves(&self, hostname: &str) -> bool {
        self.is_managed(hostname) || self.responses.iter().any(|entry| entry.key().0 == hostname)
    }

    /// Extract a syntactically valid token from a challenge path.
    pub fn token_from_path(path: &str) -> Option<&str> {
        let token = path.strip_prefix(CHALLENGE_PATH_PREFIX)?;
        let valid = !token.is_empty()
            && token.len() <= MAX_TOKEN_LEN
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        valid.then_some(token)
    }

    pub fn insert(&self, hostname: &str, token: &str, key_authorization: &str) {
        self.responses.insert(
            (hostname.to_string(), token.to_string()),
            key_authorization.to_string(),
        );
    }

    pub fn remove(&self, hostname: &str, token: &str) {
        self.responses
            .remove(&(hostname.to_string(), token.to_string()));
    }

    pub fn lookup(&self, hostname: &str, token: &str) -> Option<String> {
        self.responses
            .get(&(hostname.to_string(), token.to_string()))
            .map(|v| v.clone())
    }

    /// Challenge responses have their own concurrency budget; the permit should be
    /// held until the response body has been sent.
    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.in_flight.clone().try_acquire_owned().ok()
    }
}

/// Unix time at which a certificate should be renewed: when `renew_before_fraction`
/// of its validity period remains. Works for any certificate lifetime.
pub fn renewal_due_at(entry: &CertEntry, renew_before_fraction: f64) -> i64 {
    let remaining_at_renewal =
        (entry.lifetime_secs() as f64 * renew_before_fraction).round() as i64;
    entry.not_after - remaining_at_renewal
}

/// Exponential backoff after `failures` consecutive failures, capped at `max`,
/// with ±20% jitter (`jitter` in [0, 1]).
pub fn retry_delay(failures: u32, initial: Duration, max: Duration, jitter: f64) -> Duration {
    let exponent = failures.saturating_sub(1).min(32) as i32;
    let base = (initial.as_secs_f64() * 2f64.powi(exponent)).min(max.as_secs_f64());
    Duration::from_secs_f64(base * (0.8 + 0.4 * jitter.clamp(0.0, 1.0)))
}

fn random_unit() -> f64 {
    (uuid::Uuid::new_v4().as_u128() >> 64) as f64 / u64::MAX as f64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DomainState {
    failures: u32,
    /// Unix time before which no new order is attempted
    next_attempt: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    domains: HashMap<String, DomainState>,
}

/// How Edges agree on which one orders a certificate.
pub enum Coordination {
    /// This Edge is the only one managing the domains
    Local,
    /// Per-domain Valkey leases; challenges are distributed to all live Edges
    Valkey(ValkeyHandle),
}

/// Challenge material published during one order, removed afterwards.
#[derive(Default)]
struct Published {
    http01: Vec<String>,
    txt: Vec<TxtHandle>,
}

/// Issues and renews certificates for the configured domains.
pub struct AcmeManager {
    settings: AcmeConfig,
    domains: Vec<String>,
    state_dir: PathBuf,
    store: CertStore,
    resolver: Arc<CertResolver>,
    challenges: Arc<Http01Challenges>,
    account: OnceCell<Account>,
    state: Mutex<HashMap<String, DomainState>>,
    clock: Arc<dyn WallClock>,
    coordination: Coordination,
    dns01: Option<Arc<TxtChallengeSolver>>,
}

impl AcmeManager {
    /// `settings` must have been validated by the configuration loader.
    pub fn new(
        settings: AcmeConfig,
        resolver: Arc<CertResolver>,
        clock: Arc<dyn WallClock>,
        coordination: Coordination,
        dns01: Option<Arc<TxtChallengeSolver>>,
    ) -> anyhow::Result<Arc<Self>> {
        if settings.challenge == AcmeChallenge::Dns01 && dns01.is_none() {
            bail!("dns-01 requires DNS providers");
        }
        let state_dir =
            PathBuf::from(&settings.state_dir).join(directory_label(&settings.directory_url));
        let store = CertStore::open(&state_dir.join("certs"))?;
        let domains = settings.domains.clone();
        let challenges = Http01Challenges::new(
            domains.iter().cloned().collect(),
            settings.challenge_max_concurrent,
        );
        let persisted: PersistedState = std::fs::read(state_dir.join("status.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        resolver.set_managed_names(domains.iter().cloned().collect());

        Ok(Arc::new(AcmeManager {
            settings,
            domains,
            state_dir,
            store,
            resolver,
            challenges,
            account: OnceCell::new(),
            state: Mutex::new(persisted.domains),
            clock,
            coordination,
            dns01,
        }))
    }

    /// Where the DNS-01 solver keeps its journal for this directory.
    pub fn dns01_journal_path(settings: &AcmeConfig) -> PathBuf {
        PathBuf::from(&settings.state_dir)
            .join(directory_label(&settings.directory_url))
            .join("dns01-journal.json")
    }

    pub fn challenges(&self) -> Arc<Http01Challenges> {
        self.challenges.clone()
    }

    /// Install certificates already in the store (e.g. after a restart).
    pub fn load_existing(&self) {
        let now = self.clock.now_unix();
        for domain in &self.domains {
            self.refresh_from_store(domain, now);
        }
    }

    fn control_plane_ready(&self) -> bool {
        match &self.coordination {
            Coordination::Local => true,
            Coordination::Valkey(valkey) => valkey.is_connected(),
        }
    }

    /// Install a newer stored generation, e.g. one written by another Edge.
    fn refresh_from_store(&self, domain: &str, now: i64) {
        let installed = self
            .resolver
            .get(domain)
            .filter(|e| e.source == CertSource::Acme)
            .and_then(|e| e.generation);
        match self.store.current_generation(domain) {
            Ok(Some(current)) if Some(current) != installed => {}
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(domain, error = %e, "cannot read certificate store");
                return;
            }
        }
        match self.store.load_current(domain, now) {
            Ok(Some(entry)) if entry.generation != installed => {
                tracing::info!(domain, generation = ?entry.generation, not_after = entry.not_after, "installed stored certificate");
                self.resolver.install(entry);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(domain, error = %e, "cannot load stored certificate"),
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HashMap<String, DomainState>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// When the next order for `domain` may be attempted.
    pub fn due_at(&self, domain: &str, now: i64) -> i64 {
        let certificate_due = self
            .resolver
            .get(domain)
            .filter(|e| e.source == CertSource::Acme && !e.is_expired(now))
            .map(|e| renewal_due_at(&e, self.settings.renew_before_fraction))
            .unwrap_or(now);
        let not_before = self
            .lock_state()
            .get(domain)
            .map(|s| s.next_attempt)
            .unwrap_or(0);
        certificate_due.max(not_before)
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        if let Some(solver) = self.dns01.clone() {
            self.cleanup_dns01(&solver).await;
        }
        if let Coordination::Valkey(valkey) = &self.coordination {
            tokio::spawn(
                self.clone()
                    .sync_http01_challenges(valkey.clone(), shutdown.clone()),
            );
        }
        self.load_existing();
        let poll = self.settings.store_poll_interval_secs as i64;
        loop {
            let mut wake_at = self.clock.now_unix() + MAX_SLEEP_SECS;
            for domain in &self.domains {
                let now = self.clock.now_unix();
                // Without the control plane, neither order nor switch certificates.
                if !self.control_plane_ready() {
                    wake_at = wake_at.min(now + poll);
                    continue;
                }
                self.refresh_from_store(domain, now);
                if self.due_at(domain, now) <= now {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = self.coordinated_attempt(domain) => {}
                    }
                }
                let now = self.clock.now_unix();
                wake_at = wake_at.min(self.due_at(domain, now));
                if matches!(self.coordination, Coordination::Valkey(_)) {
                    wake_at = wake_at.min(now + poll);
                }
            }
            self.publish_metrics();

            let sleep_secs = (wake_at - self.clock.now_unix()).clamp(1, MAX_SLEEP_SECS) as u64;
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {}
            }
        }
    }

    async fn coordinated_attempt(&self, domain: &str) {
        match &self.coordination {
            Coordination::Local => self.attempt(domain, None).await,
            Coordination::Valkey(valkey) => {
                let resource = lease_resource(domain);
                let min_generation = match self.store.next_generation(domain) {
                    Ok(generation) => generation,
                    Err(e) => {
                        tracing::warn!(domain, error = %e, "cannot read certificate store");
                        return;
                    }
                };
                let ttl = Duration::from_secs(self.settings.order_timeout_secs + 120);
                match valkey.acquire_lease(&resource, ttl, min_generation).await {
                    Ok(Some(generation)) => {
                        // Another Edge may have finished while we waited for the lease.
                        self.refresh_from_store(domain, self.clock.now_unix());
                        if self.due_at(domain, self.clock.now_unix()) <= self.clock.now_unix() {
                            self.attempt(domain, Some(generation)).await;
                        }
                        if let Err(e) = valkey.release_lease(&resource, generation).await {
                            tracing::debug!(domain, error = %e, "cannot release ACME lease");
                        }
                    }
                    Ok(None) => tracing::debug!(domain, "another edge holds the ACME lease"),
                    Err(e) => {
                        tracing::warn!(domain, error = %e, "cannot acquire ACME lease; ordering paused")
                    }
                }
            }
        }
    }

    async fn attempt(&self, domain: &str, generation: Option<u64>) {
        let result = self.issue(domain, generation).await;
        let now = self.clock.now_unix();
        let metrics = edge_metrics::get();
        match result {
            Ok(entry) => {
                tracing::info!(
                    domain,
                    generation = ?entry.generation,
                    not_after = entry.not_after,
                    "ACME certificate issued"
                );
                self.resolver.install(entry);
                self.lock_state().remove(domain);
                metrics
                    .acme_orders_total
                    .with_label_values(&["success"])
                    .inc();
            }
            Err(e) => {
                let mut state = self.lock_state();
                let entry = state.entry(domain.to_string()).or_default();
                entry.failures += 1;
                let delay = retry_delay(
                    entry.failures,
                    Duration::from_secs(self.settings.retry_initial_secs),
                    Duration::from_secs(self.settings.retry_max_secs),
                    random_unit(),
                );
                entry.next_attempt = now + delay.as_secs().max(1) as i64;
                tracing::warn!(
                    domain,
                    error = %format!("{e:#}"),
                    failures = entry.failures,
                    retry_in_secs = delay.as_secs(),
                    "ACME order failed"
                );
                metrics
                    .acme_orders_total
                    .with_label_values(&["failure"])
                    .inc();
            }
        }
        self.persist_state();
    }

    fn persist_state(&self) {
        let snapshot = PersistedState {
            domains: self.lock_state().clone(),
        };
        let written = serde_json::to_vec_pretty(&snapshot)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| write_atomic(&self.state_dir.join("status.json"), &bytes));
        if let Err(e) = written {
            tracing::warn!(error = %e, "cannot persist ACME state");
        }
    }

    fn publish_metrics(&self) {
        let now = self.clock.now_unix();
        let metrics = edge_metrics::get();
        if let Some(next) = self.domains.iter().map(|d| self.due_at(d, now)).min() {
            metrics.acme_next_attempt_timestamp_seconds.set(next as f64);
        }
        edge_metrics::update_certificates(&self.resolver, now);
    }

    /// Domains that have no usable certificate.
    pub fn readiness_issues(&self, now: i64) -> Vec<String> {
        self.domains
            .iter()
            .filter(|d| {
                !self
                    .resolver
                    .get(d)
                    .is_some_and(|e| e.source == CertSource::Acme && !e.is_expired(now))
            })
            .map(|d| format!("no valid ACME certificate for {d}"))
            .collect()
    }

    async fn account(&self) -> anyhow::Result<Account> {
        let account = self
            .account
            .get_or_try_init(|| async {
                let path = self.state_dir.join("account.json");
                let builder = || match &self.settings.ca_root_pem {
                    Some(root) => Account::builder_with_root(root),
                    None => Account::builder(),
                };
                if let Ok(bytes) = std::fs::read(&path) {
                    let credentials: AccountCredentials =
                        serde_json::from_slice(&bytes).context("corrupt ACME account file")?;
                    let account = builder()?.from_credentials(credentials).await?;
                    return Ok::<_, anyhow::Error>(account);
                }
                let contact = self
                    .settings
                    .contact_email
                    .as_ref()
                    .map(|email| format!("mailto:{email}"));
                let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
                let (account, credentials) = builder()?
                    .create(
                        &NewAccount {
                            contact: &contacts,
                            terms_of_service_agreed: self.settings.terms_of_service_agreed,
                            only_return_existing: false,
                        },
                        self.settings.directory_url.clone(),
                        None,
                    )
                    .await?;
                write_atomic(&path, &serde_json::to_vec(&credentials)?)?;
                tracing::info!(directory = %self.settings.directory_url, "created ACME account");
                Ok(account)
            })
            .await?;
        Ok(account.clone())
    }

    async fn issue(&self, domain: &str, generation: Option<u64>) -> anyhow::Result<CertEntry> {
        let account = self.account().await?;
        let identifiers = [Identifier::Dns(domain.to_string())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("new order")?;

        let mut published = Published::default();
        let outcome = tokio::time::timeout(
            Duration::from_secs(self.settings.order_timeout_secs),
            self.complete_order(&mut order, domain, &mut published),
        )
        .await;
        self.cleanup(domain, &published).await;
        let (chain_pem, key_pem) = outcome.map_err(|_| anyhow!("order timed out"))??;

        let generation = match (generation, &self.coordination) {
            (Some(generation), Coordination::Valkey(valkey)) => {
                // Fencing: a holder whose lease expired must not overwrite a newer writer.
                if !valkey
                    .check_lease(&lease_resource(domain), generation)
                    .await
                    .unwrap_or(false)
                {
                    bail!("lost the ACME lease before storing the certificate");
                }
                generation
            }
            (Some(generation), Coordination::Local) => generation,
            (None, _) => self.store.next_generation(domain)?,
        };
        let now = self.clock.now_unix();
        self.store.store(
            domain,
            generation,
            chain_pem.as_bytes(),
            key_pem.as_bytes(),
            now,
        )
    }

    async fn cleanup(&self, domain: &str, published: &Published) {
        for token in &published.http01 {
            self.challenges.remove(domain, token);
            if let Coordination::Valkey(valkey) = &self.coordination {
                if let Err(e) = valkey.unpublish_http01(domain, token).await {
                    tracing::debug!(domain, error = %e, "cannot unpublish HTTP-01 challenge");
                }
            }
        }
        if let Some(solver) = &self.dns01 {
            for handle in &published.txt {
                if let Err(e) = solver.remove(handle).await {
                    tracing::warn!(domain, name = %handle.name, error = %format!("{e:#}"), "cannot remove DNS-01 TXT value; it stays in the journal");
                }
            }
        }
    }

    async fn complete_order(
        &self,
        order: &mut instant_acme::Order,
        domain: &str,
        published: &mut Published,
    ) -> anyhow::Result<(String, String)> {
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result?;
                match authz.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    status => bail!("authorization is {status:?}"),
                }
                match self.settings.challenge {
                    AcmeChallenge::Http01 => {
                        let mut challenge = authz
                            .challenge(ChallengeType::Http01)
                            .ok_or_else(|| anyhow!("CA did not offer an http-01 challenge"))?;
                        let key_authorization = challenge.key_authorization();
                        let token = challenge.token.clone();
                        self.challenges
                            .insert(domain, &token, key_authorization.as_str());
                        published.http01.push(token.clone());
                        if let Coordination::Valkey(valkey) = &self.coordination {
                            self.distribute_http01(
                                valkey,
                                domain,
                                &token,
                                key_authorization.as_str(),
                            )
                            .await?;
                        }
                        challenge.set_ready().await.context("set challenge ready")?;
                    }
                    AcmeChallenge::Dns01 => {
                        let solver = self
                            .dns01
                            .as_ref()
                            .ok_or_else(|| anyhow!("dns-01 requires DNS providers"))?;
                        let base = match authz.identifier().identifier {
                            Identifier::Dns(name) => name.clone(),
                            other => bail!("unsupported identifier {other:?}"),
                        };
                        let mut challenge = authz
                            .challenge(ChallengeType::Dns01)
                            .ok_or_else(|| anyhow!("CA did not offer a dns-01 challenge"))?;
                        let value = challenge.key_authorization().dns_value();
                        let handle = solver.add(&base, &value).await?;
                        published.txt.push(handle.clone());
                        solver.wait_propagated(&handle).await?;
                        challenge.set_ready().await.context("set challenge ready")?;
                    }
                }
            }
        }

        let retry = RetryPolicy::new()
            .initial_delay(Duration::from_millis(500))
            .backoff(1.5)
            .timeout(Duration::from_secs(self.settings.order_timeout_secs));
        match order.poll_ready(&retry).await.context("wait for order")? {
            OrderStatus::Ready => {}
            status => bail!("order became {status:?}"),
        }

        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key)?;
        order
            .finalize_csr(csr.der())
            .await
            .context("finalize order")?;
        let chain = order
            .poll_certificate(&retry)
            .await
            .context("download certificate")?;
        Ok((chain, key.serialize_pem()))
    }

    /// Remove TXT values left behind by an interrupted order.
    ///
    /// With `coordination = "valkey"` the journal is shared between the Edges of
    /// a cluster, so an entry whose domain is currently leased by another Edge
    /// belongs to an order that is still running: removing its TXT value would
    /// fail that authorization.
    async fn cleanup_dns01(&self, solver: &TxtChallengeSolver) {
        let Coordination::Valkey(valkey) = &self.coordination else {
            solver.cleanup_journal().await;
            return;
        };
        for handle in solver.journal_entries() {
            let Some(domain) = handle.domain() else {
                tracing::warn!(name = %handle.name, "keeping a journaled DNS-01 value whose domain is unknown");
                continue;
            };
            // A wildcard order authorizes the base name, so both leases have to
            // be free before its value may be removed.
            let mut removable = true;
            for resource in [domain.to_string(), format!("*.{domain}")] {
                match valkey.lease_owner(&lease_resource(&resource)).await {
                    Ok(None) => {}
                    Ok(Some(owner)) if owner == valkey.edge_id() => {}
                    Ok(Some(owner)) => {
                        tracing::info!(domain = %resource, owner = %owner, "keeping a journaled DNS-01 value; another edge is ordering for this domain");
                        removable = false;
                    }
                    Err(e) => {
                        tracing::warn!(domain = %resource, error = %e, "cannot check the ACME lease; keeping the journaled DNS-01 value");
                        removable = false;
                    }
                }
            }
            if removable {
                solver.cleanup_entry(&handle).await;
            }
        }
    }

    /// Publish an HTTP-01 response and wait until every Edge that serves
    /// challenges confirms it, since the CA may reach any of them.
    async fn distribute_http01(
        &self,
        valkey: &ValkeyHandle,
        domain: &str,
        token: &str,
        key_authorization: &str,
    ) -> anyhow::Result<()> {
        let ttl = Duration::from_secs(self.settings.order_timeout_secs + 60);
        valkey
            .publish_http01(domain, token, key_authorization, ttl)
            .await?;
        let deadline =
            Instant::now() + Duration::from_secs(self.settings.challenge_distribution_timeout_secs);
        let mut warned = false;
        loop {
            let live: HashSet<String> = valkey.live_edges().await?.into_iter().collect();
            // An Edge that does not serve challenges never confirms one, so
            // waiting for every live Edge would fail every order in a cluster
            // whose Edges are configured differently.
            let responders: HashSet<String> =
                valkey.http01_responders().await?.into_iter().collect();
            let acks = valkey.http01_acks(domain, token).await?;
            if !warned {
                let silent: Vec<&str> = live.difference(&responders).map(String::as_str).collect();
                if !silent.is_empty() {
                    tracing::warn!(domain, edges = ?silent, "live edges do not serve HTTP-01 challenges; validation fails if the CA reaches one of them, so use dns-01 in this cluster");
                    warned = true;
                }
            }
            let missing = live
                .intersection(&responders)
                .filter(|edge| !acks.contains(edge))
                .count();
            if missing == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("{missing} edge(s) did not confirm the HTTP-01 response; use dns-01 when not every edge can serve challenges");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Serve challenges published by other Edges and confirm them.
    async fn sync_http01_challenges(
        self: Arc<Self>,
        valkey: ValkeyHandle,
        shutdown: CancellationToken,
    ) {
        let mut synced: HashSet<(String, String)> = HashSet::new();
        let mut announce = tokio::time::interval(RESPONDER_HEARTBEAT_INTERVAL);
        announce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = valkey.remove_http01_responder().await;
                    return;
                }
                _ = announce.tick() => {
                    if let Err(e) = valkey.heartbeat_http01_responder(RESPONDER_TTL).await {
                        tracing::debug!(error = %e, "cannot announce HTTP-01 challenge responder");
                    }
                    continue;
                }
                _ = tokio::time::sleep(CHALLENGE_SYNC_INTERVAL) => {}
            }
            let pending = match valkey.pending_http01().await {
                Ok(pending) => pending,
                Err(e) => {
                    tracing::debug!(error = %e, "cannot read published HTTP-01 challenges");
                    continue;
                }
            };
            let mut current = HashSet::new();
            // Responses are served for whatever domain a peer is validating,
            // not only for this Edge's own domains.
            for (domain, token, key_authorization) in pending {
                let key = (domain.clone(), token.clone());
                if self.challenges.lookup(&domain, &token).is_none() {
                    self.challenges.insert(&domain, &token, &key_authorization);
                    synced.insert(key.clone());
                }
                if let Err(e) = valkey.ack_http01(&domain, &token).await {
                    tracing::debug!(domain, error = %e, "cannot confirm HTTP-01 challenge");
                }
                current.insert(key);
            }
            synced.retain(|(domain, token)| {
                let keep = current.contains(&(domain.clone(), token.clone()));
                if !keep {
                    self.challenges.remove(domain, token);
                }
                keep
            });
        }
    }
}

fn lease_resource(domain: &str) -> String {
    format!("acme:{domain}")
}

/// A stable, filesystem-safe name for an ACME directory, so that accounts and
/// certificates from different CAs (e.g. staging and production) never mix.
pub fn directory_label(url: &str) -> String {
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("acme");
    let host: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let digest = ring::digest::digest(&ring::digest::SHA256, url.as_bytes());
    let suffix: String = digest.as_ref()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{host}-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_store::{parse_and_validate, test_certs::generate};
    use crate::config::AcmeCoordination;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct FakeClock(AtomicI64);

    impl WallClock for FakeClock {
        fn now_unix(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    const NOW: i64 = 1_800_000_000;

    fn entry(not_before: i64, not_after: i64) -> CertEntry {
        let (cert, key) = generate(&["a.test"], not_before, not_after);
        parse_and_validate(
            cert.as_bytes(),
            key.as_bytes(),
            "a.test",
            CertSource::Acme,
            not_before + 1,
        )
        .unwrap()
    }

    #[test]
    fn challenge_paths_are_served_while_a_peer_publishes_a_response() {
        let challenges = Http01Challenges::new(HashSet::from(["a.test".to_string()]), 2);
        assert!(challenges.serves("a.test"), "own managed domain");
        assert!(!challenges.serves("b.test"));

        // A peer validating b.test publishes its response to every Edge.
        challenges.insert("b.test", "token", "key-authorization");
        assert!(challenges.serves("b.test"));
        challenges.remove("b.test", "token");
        assert!(
            !challenges.serves("b.test"),
            "without a response the path belongs to the tenant again"
        );
    }

    #[test]
    fn renewal_is_scheduled_by_lifetime_fraction() {
        // 90-day certificate renews with 30 days left.
        let e = entry(NOW, NOW + 90 * 86400);
        assert_eq!(renewal_due_at(&e, 1.0 / 3.0), NOW + 60 * 86400);
        // 6-day certificate renews with 2 days left.
        let e = entry(NOW, NOW + 6 * 86400);
        assert_eq!(renewal_due_at(&e, 1.0 / 3.0), NOW + 4 * 86400);
    }

    #[test]
    fn retry_delay_grows_and_is_capped() {
        let initial = Duration::from_secs(60);
        let max = Duration::from_secs(3600);
        assert_eq!(retry_delay(1, initial, max, 0.5), Duration::from_secs(60));
        assert_eq!(retry_delay(3, initial, max, 0.5), Duration::from_secs(240));
        assert_eq!(retry_delay(30, initial, max, 0.5), max);
        assert!(retry_delay(1, initial, max, 0.0) >= Duration::from_secs(48));
        assert!(retry_delay(1, initial, max, 1.0) <= Duration::from_secs(72));
    }

    #[test]
    fn challenge_tokens_are_validated() {
        assert_eq!(
            Http01Challenges::token_from_path("/.well-known/acme-challenge/abc_DEF-123"),
            Some("abc_DEF-123")
        );
        assert_eq!(
            Http01Challenges::token_from_path("/.well-known/acme-challenge/"),
            None
        );
        assert_eq!(
            Http01Challenges::token_from_path("/.well-known/acme-challenge/../etc"),
            None
        );
        assert_eq!(
            Http01Challenges::token_from_path("/.well-known/acme-challenge/a/b"),
            None
        );
        assert_eq!(Http01Challenges::token_from_path("/other"), None);

        let challenges = Http01Challenges::new(HashSet::from(["a.test".to_string()]), 1);
        challenges.insert("a.test", "tok", "tok.thumb");
        assert_eq!(
            challenges.lookup("a.test", "tok").as_deref(),
            Some("tok.thumb")
        );
        assert!(challenges.lookup("b.test", "tok").is_none());
        let permit = challenges.try_acquire();
        assert!(permit.is_some());
        assert!(challenges.try_acquire().is_none());
    }

    #[test]
    fn directory_labels_differ_per_ca() {
        let staging = directory_label("https://acme-staging-v02.api.letsencrypt.org/directory");
        let production = directory_label("https://acme-v02.api.letsencrypt.org/directory");
        assert!(staging.starts_with("acme-staging-v02.api.letsencrypt.org-"));
        assert_ne!(staging, production);
    }

    fn settings(state_dir: &std::path::Path) -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            directory_url: "https://127.0.0.1:1/dir".to_string(),
            contact_email: None,
            terms_of_service_agreed: true,
            domains: vec!["a.test".to_string()],
            challenge: AcmeChallenge::Http01,
            state_dir: state_dir.display().to_string(),
            ca_root_pem: None,
            renew_before_fraction: 0.5,
            retry_initial_secs: 60,
            retry_max_secs: 3600,
            order_timeout_secs: 5,
            challenge_max_concurrent: 8,
            coordination: AcmeCoordination::None,
            store_poll_interval_secs: 30,
            challenge_distribution_timeout_secs: 5,
            dns_resolvers: Vec::new(),
            dns_propagation_timeout_secs: 30,
            dns_propagation_poll_secs: 1,
            dns_txt_ttl: 60,
        }
    }

    fn tempdir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sievetube-{prefix}-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn scheduling_uses_stored_certificate_and_persisted_backoff() {
        let dir = tempdir("acme");
        let clock = Arc::new(FakeClock(AtomicI64::new(NOW)));
        let resolver = CertResolver::new();
        let manager = AcmeManager::new(
            settings(&dir),
            resolver.clone(),
            clock.clone(),
            Coordination::Local,
            None,
        )
        .unwrap();

        // No certificate: due immediately.
        assert_eq!(manager.due_at("a.test", NOW), NOW);
        assert_eq!(manager.readiness_issues(NOW).len(), 1);

        // A stored certificate (e.g. from before a restart) is installed and not re-ordered.
        let (cert, key) = generate(&["a.test"], NOW - 100, NOW + 900);
        manager
            .store
            .store("a.test", 1, cert.as_bytes(), key.as_bytes(), NOW)
            .unwrap();
        manager.load_existing();
        assert!(manager.readiness_issues(NOW).is_empty());
        assert_eq!(manager.due_at("a.test", NOW), NOW + 400);

        // A failed attempt (unreachable CA) backs off and the backoff survives a restart.
        clock.0.store(NOW + 400, Ordering::SeqCst);
        manager.attempt("a.test", None).await;
        let next = manager.due_at("a.test", NOW + 400);
        assert!(next >= NOW + 400 + 48, "retry was not delayed: {next}");
        drop(manager);

        let restarted = AcmeManager::new(
            settings(&dir),
            CertResolver::new(),
            clock.clone(),
            Coordination::Local,
            None,
        )
        .unwrap();
        restarted.load_existing();
        assert_eq!(restarted.due_at("a.test", NOW + 400), next);
    }

    #[tokio::test]
    async fn certificates_written_by_another_edge_are_installed_from_shared_storage() {
        let dir = tempdir("acme-shared");
        let clock = Arc::new(FakeClock(AtomicI64::new(NOW)));
        let writer = AcmeManager::new(
            settings(&dir),
            CertResolver::new(),
            clock.clone(),
            Coordination::Local,
            None,
        )
        .unwrap();
        let reader_resolver = CertResolver::new();
        let reader = AcmeManager::new(
            settings(&dir),
            reader_resolver.clone(),
            clock.clone(),
            Coordination::Local,
            None,
        )
        .unwrap();

        let (c1, k1) = generate(&["a.test"], NOW - 10, NOW + 1000);
        writer
            .store
            .store("a.test", 1, c1.as_bytes(), k1.as_bytes(), NOW)
            .unwrap();
        reader.refresh_from_store("a.test", NOW);
        assert_eq!(reader_resolver.get("a.test").unwrap().generation, Some(1));

        let (c2, k2) = generate(&["a.test"], NOW - 10, NOW + 2000);
        writer
            .store
            .store("a.test", 7, c2.as_bytes(), k2.as_bytes(), NOW)
            .unwrap();
        reader.refresh_from_store("a.test", NOW);
        assert_eq!(reader_resolver.get("a.test").unwrap().generation, Some(7));
        // A stale lease holder cannot roll back.
        assert!(writer
            .store
            .store("a.test", 5, c1.as_bytes(), k1.as_bytes(), NOW)
            .is_err());
    }

    #[tokio::test]
    async fn http01_responses_are_confirmed_by_the_edges_that_serve_them() {
        let Ok(url) = std::env::var("SIEVETUBE_TEST_VALKEY_URL") else {
            eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let domain = format!("dist-{suffix}.test");
        let edge_a = ValkeyHandle::new(&url, &format!("edge-a-{suffix}")).unwrap();
        let edge_b = ValkeyHandle::new(&url, &format!("edge-b-{suffix}")).unwrap();
        edge_a.try_connect().await.unwrap();
        edge_b.try_connect().await.unwrap();
        edge_a
            .heartbeat_presence(Duration::from_secs(30))
            .await
            .unwrap();
        edge_b
            .heartbeat_presence(Duration::from_secs(30))
            .await
            .unwrap();

        let make = |valkey: ValkeyHandle| {
            let mut cfg = settings(&tempdir("acme-dist"));
            cfg.domains = vec![domain.clone()];
            cfg.coordination = AcmeCoordination::Valkey;
            AcmeManager::new(
                cfg,
                CertResolver::new(),
                Arc::new(SystemClock),
                Coordination::Valkey(valkey),
                None,
            )
            .unwrap()
        };
        let manager_a = make(edge_a.clone());
        let manager_b = make(edge_b.clone());

        // Edge B is live but has not announced that it answers challenges (e.g.
        // ACME is disabled there). It never confirms one, so waiting for it
        // would fail every order: distribution completes without it.
        manager_a
            .distribute_http01(&edge_a, &domain, "tok-silent", "tok-silent.thumb")
            .await
            .unwrap();
        edge_a
            .unpublish_http01(&domain, "tok-silent")
            .await
            .unwrap();

        // Once it announces itself as a responder it has to confirm.
        edge_b
            .heartbeat_http01_responder(Duration::from_secs(30))
            .await
            .unwrap();
        let err = manager_a
            .distribute_http01(&edge_a, &domain, "tok-early", "tok-early.thumb")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not confirm"));
        edge_a.unpublish_http01(&domain, "tok-early").await.unwrap();

        let shutdown = CancellationToken::new();
        tokio::spawn(
            manager_b
                .clone()
                .sync_http01_challenges(edge_b.clone(), shutdown.clone()),
        );
        manager_a
            .distribute_http01(&edge_a, &domain, "tok", "tok.thumb")
            .await
            .unwrap();
        assert_eq!(
            manager_b.challenges.lookup(&domain, "tok").as_deref(),
            Some("tok.thumb")
        );

        // Unpublishing removes the response from the other edge.
        edge_a.unpublish_http01(&domain, "tok").await.unwrap();
        tokio::time::sleep(CHALLENGE_SYNC_INTERVAL * 3).await;
        assert!(manager_b.challenges.lookup(&domain, "tok").is_none());
        shutdown.cancel();
        let _ = edge_a.remove_presence().await;
        let _ = edge_b.remove_presence().await;
        let _ = edge_b.remove_http01_responder().await;
    }

    mod dns01_with_pebble {
        //! Real DNS-01 validation against Pebble through both provider adapters.
        //! Requires SIEVETUBE_PEBBLE_BIN, SIEVETUBE_CHALLTESTSRV_BIN and SIEVETUBE_PEBBLE_DIR.

        use super::*;
        use crate::dns::contract_tests::{CloudflareMock, MOCK_TOKEN};
        use crate::dns::route53::mock::Route53Mock;
        use crate::dns::txt::{TxtLookup, TxtSettings};
        use crate::dns::{ChangeObserver, Provider, RecordType};
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpListener, TcpStream};
        use std::process::{Child, Command, Stdio};

        struct KillOnDrop(Child);

        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn free_port() -> u16 {
            TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }

        fn post_json(port: u16, path: &str, body: &str) {
            let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
                return;
            };
            let request = format!(
                "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(request.as_bytes());
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response);
        }

        /// Mirror TXT record sets from the mock APIs into challtestsrv's DNS server.
        fn mirror_to_challtestsrv(management_port: u16) -> ChangeObserver {
            Arc::new(move |name: &str, record_type: &str, values: Vec<String>| {
                if record_type != "TXT" {
                    return;
                }
                let host = format!("{name}.");
                post_json(
                    management_port,
                    "/clear-txt",
                    &serde_json::json!({ "host": host }).to_string(),
                );
                for value in values {
                    post_json(
                        management_port,
                        "/set-txt",
                        &serde_json::json!({ "host": host, "value": value }).to_string(),
                    );
                }
            })
        }

        struct Pebble {
            _processes: Vec<KillOnDrop>,
            directory_url: String,
            minica: String,
            dns: SocketAddr,
            management_port: u16,
        }

        fn start_pebble() -> Option<Pebble> {
            let pebble = std::env::var("SIEVETUBE_PEBBLE_BIN").ok()?;
            let challtestsrv = std::env::var("SIEVETUBE_CHALLTESTSRV_BIN").ok()?;
            let dir = PathBuf::from(std::env::var("SIEVETUBE_PEBBLE_DIR").ok()?);
            let (dns_port, management_port, acme_port, pebble_mgmt) =
                (free_port(), free_port(), free_port(), free_port());
            let challtestsrv = KillOnDrop(
                Command::new(challtestsrv)
                    .args([
                        "-defaultIPv4",
                        "127.0.0.1",
                        "-defaultIPv6",
                        "",
                        "-http01",
                        "",
                        "-https01",
                        "",
                        "-tlsalpn01",
                        "",
                        "-doh",
                        "",
                    ])
                    .args([
                        "-dnsserver",
                        &format!("127.0.0.1:{dns_port}"),
                        "-management",
                        &format!("127.0.0.1:{management_port}"),
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let certs = dir.join("test/certs");
            let config = serde_json::json!({"pebble": {
                "listenAddress": format!("127.0.0.1:{acme_port}"),
                "managementListenAddress": format!("127.0.0.1:{pebble_mgmt}"),
                "certificate": certs.join("localhost/cert.pem"),
                "privateKey": certs.join("localhost/key.pem"),
                "httpPort": free_port(), "tlsPort": free_port(),
                "ocspResponderURL": "", "externalAccountBindingRequired": false,
                "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
            }});
            let config_path = tempdir("pebble-dns01").join("pebble.json");
            std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
            std::fs::write(&config_path, config.to_string()).unwrap();
            let pebble = KillOnDrop(
                Command::new(pebble)
                    .arg("-config")
                    .arg(&config_path)
                    .args(["-dnsserver", &format!("127.0.0.1:{dns_port}")])
                    .env("PEBBLE_VA_NOSLEEP", "1")
                    .env("PEBBLE_WFE_NONCEREJECT", "0")
                    .env("PEBBLE_AUTHZREUSE", "0")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            for _ in 0..100 {
                if TcpStream::connect(("127.0.0.1", acme_port)).is_ok()
                    && TcpStream::connect(("127.0.0.1", management_port)).is_ok()
                {
                    return Some(Pebble {
                        _processes: vec![challtestsrv, pebble],
                        directory_url: format!("https://localhost:{acme_port}/dir"),
                        minica: certs.join("pebble.minica.pem").display().to_string(),
                        dns: format!("127.0.0.1:{dns_port}").parse().unwrap(),
                        management_port,
                    });
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            panic!("pebble did not start");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn dns01_issues_wildcards_through_cloudflare_and_route53() {
            crate::test_support::install_crypto();
            let Some(pebble) = start_pebble() else {
                eprintln!("skipping: Pebble environment variables not set");
                return;
            };
            let cloudflare = CloudflareMock::start_with_observer(Some(mirror_to_challtestsrv(
                pebble.management_port,
            )))
            .await;
            let route53 = Route53Mock::start_with_observer(Some(mirror_to_challtestsrv(
                pebble.management_port,
            )))
            .await;
            let route53_provider = crate::dns::route53::Route53Provider::with_client(
                crate::dns::route53::tests_support::client(&route53.endpoint),
                "Z123".into(),
                Duration::from_secs(10),
            );
            let providers: Vec<(String, Arc<Provider>)> = vec![
                (
                    "cf.test".to_string(),
                    Arc::new(cloudflare.provider(MOCK_TOKEN)),
                ),
                (
                    "r53.test".to_string(),
                    Arc::new(Provider::Route53(Box::new(route53_provider))),
                ),
            ];
            let dir = tempdir("acme-dns01");
            let mut cfg = settings(&dir);
            cfg.challenge = AcmeChallenge::Dns01;
            cfg.directory_url = pebble.directory_url.clone();
            cfg.ca_root_pem = Some(pebble.minica.clone());
            cfg.order_timeout_secs = 60;
            cfg.domains = vec!["*.cf.test".into(), "cf.test".into(), "*.r53.test".into()];
            let solver = Arc::new(TxtChallengeSolver::new(
                providers.clone(),
                vec!["cf.test".into(), "r53.test".into()],
                TxtLookup::dns(&[pebble.dns]).unwrap(),
                TxtSettings {
                    ttl: 60,
                    propagation_timeout: Duration::from_secs(20),
                    poll_interval: Duration::from_millis(200),
                },
                AcmeManager::dns01_journal_path(&cfg),
            ));
            let resolver = CertResolver::new();
            let manager = AcmeManager::new(
                cfg.clone(),
                resolver.clone(),
                Arc::new(SystemClock),
                Coordination::Local,
                Some(solver),
            )
            .unwrap();

            for domain in &cfg.domains {
                manager.attempt(domain, None).await;
                let installed = resolver.get(domain);
                assert!(
                    installed.is_some(),
                    "no certificate for {domain}: {:?}",
                    manager.lock_state().get(domain)
                );
            }
            assert!(
                resolver.lookup("www.cf.test").is_some(),
                "wildcard certificate serves subdomains"
            );

            // Only the order's own TXT values existed, and they were removed.
            for (zone, provider) in &providers {
                let name = format!("_acme-challenge.{zone}");
                assert!(
                    provider
                        .get(&name, RecordType::Txt)
                        .await
                        .unwrap()
                        .is_none(),
                    "{name} was not cleaned up"
                );
            }
        }
    }
}

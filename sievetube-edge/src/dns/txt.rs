//! TXT records for ACME DNS-01 validation.
//!
//! Challenge values are added to and removed from `_acme-challenge` record sets
//! one value at a time, so concurrent orders (e.g. a wildcard and its base name)
//! and values managed by operators are never removed. Every added value is
//! journaled first so that leftovers are cleaned up after a restart.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType as DnsRecordType};
use hickory_resolver::{Resolver, TokioResolver};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use sievetube_common::hostname;

use super::{ChangeTicket, DnsError, Provider, RecordSet, RecordType};
use crate::certificate_store::{open_lock_file, write_atomic};

const MAX_ATTEMPTS: u32 = 6;

/// How the solver confirms that a TXT value is served.
pub enum TxtLookup {
    /// Query DNS through these resolvers (system configuration if built without servers)
    Dns(Box<TokioResolver>),
    /// Read back through the provider API only (tests)
    #[cfg(test)]
    ProviderApi,
}

impl TxtLookup {
    pub fn dns(resolvers: &[SocketAddr]) -> anyhow::Result<Self> {
        let mut builder = if resolvers.is_empty() {
            TokioResolver::builder_tokio().context("cannot read system resolver configuration")?
        } else {
            let servers = resolvers
                .iter()
                .map(|addr| {
                    let mut server = NameServerConfig::udp_and_tcp(addr.ip());
                    for connection in &mut server.connections {
                        connection.port = addr.port();
                    }
                    server
                })
                .collect();
            Resolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            )
        };
        // Propagation checks must not be answered from a cache.
        builder.options_mut().cache_size = 0;
        Ok(TxtLookup::Dns(Box::new(
            builder.build().context("cannot build DNS resolver")?,
        )))
    }
}

/// A TXT value published for one authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxtHandle {
    pub zone: String,
    pub name: String,
    pub value: String,
    /// Domain the value authorizes. Journaled so that a shared journal can be
    /// cleaned up per domain.
    #[serde(default)]
    pub domain: String,
}

impl TxtHandle {
    /// The domain this value authorizes, recovered from the challenge name for
    /// journals written before the field existed.
    pub fn domain(&self) -> Option<&str> {
        if !self.domain.is_empty() {
            return Some(&self.domain);
        }
        self.name.strip_prefix("_acme-challenge.")
    }
}

pub struct TxtChallengeSolver {
    /// (zone, provider), most specific zone first
    providers: Vec<(String, Arc<Provider>)>,
    allowed_zones: Vec<String>,
    lookup: TxtLookup,
    ttl: u32,
    propagation_timeout: Duration,
    poll_interval: Duration,
    journal_path: PathBuf,
    journal_lock: Mutex<()>,
}

#[derive(Debug, Clone, Copy)]
pub struct TxtSettings {
    pub ttl: u32,
    pub propagation_timeout: Duration,
    pub poll_interval: Duration,
}

impl TxtChallengeSolver {
    pub fn new(
        mut providers: Vec<(String, Arc<Provider>)>,
        allowed_zones: Vec<String>,
        lookup: TxtLookup,
        settings: TxtSettings,
        journal_path: PathBuf,
    ) -> Self {
        providers.sort_by_key(|(zone, _)| std::cmp::Reverse(zone.len()));
        TxtChallengeSolver {
            providers,
            allowed_zones,
            lookup,
            ttl: settings.ttl,
            propagation_timeout: settings.propagation_timeout,
            poll_interval: settings.poll_interval,
            journal_path,
            journal_lock: Mutex::new(()),
        }
    }

    fn provider_for(&self, name: &str) -> Option<(&str, &Arc<Provider>)> {
        self.providers
            .iter()
            .find(|(zone, _)| hostname::is_within_zone(name, zone))
            .map(|(zone, provider)| (zone.as_str(), provider))
    }

    fn zone_provider(&self, zone: &str) -> anyhow::Result<&Arc<Provider>> {
        self.providers
            .iter()
            .find(|(z, _)| z == zone)
            .map(|(_, p)| p)
            .ok_or_else(|| anyhow!("no DNS provider for zone {zone}"))
    }

    /// The name to publish for `domain`, following a CNAME delegation of
    /// `_acme-challenge` only into allowed zones.
    async fn challenge_name(&self, domain: &str) -> anyhow::Result<String> {
        let name = format!("_acme-challenge.{domain}");
        #[allow(irrefutable_let_patterns)] // only tests add another lookup mode
        if let TxtLookup::Dns(resolver) = &self.lookup {
            if let Ok(lookup) = resolver.lookup(name.as_str(), DnsRecordType::CNAME).await {
                for record in lookup.answers() {
                    if let RData::CNAME(target) = &record.data {
                        let target = hostname::normalize_dns_name(&target.0.to_ascii())
                            .map_err(|e| anyhow!("invalid CNAME target for {name}: {e}"))?;
                        if !delegation_allowed(&target, &self.allowed_zones) {
                            bail!("{name} is delegated to {target}, which is outside dns.allowed_zones");
                        }
                        return Ok(target);
                    }
                }
            }
        }
        Ok(name)
    }

    /// Add `value` to the challenge TXT record set for `domain` and wait for the
    /// provider to apply it.
    pub async fn add(&self, domain: &str, value: &str) -> anyhow::Result<TxtHandle> {
        let name = self.challenge_name(domain).await?;
        let (zone, provider) = self
            .provider_for(&name)
            .ok_or_else(|| anyhow!("no DNS provider zone covers {name}"))?;
        let handle = TxtHandle {
            zone: zone.to_string(),
            name: name.clone(),
            value: value.to_string(),
            domain: domain.to_string(),
        };
        self.journal_update(|entries| {
            if !entries.contains(&handle) {
                entries.push(handle.clone());
            }
        })
        .await?;

        for attempt in 1..=MAX_ATTEMPTS {
            let current = observed_set(provider, &name).await?;
            if current.as_ref().is_some_and(|c| c.values.contains(value)) {
                return Ok(handle);
            }
            let mut desired = current.clone().unwrap_or(RecordSet {
                name: name.clone(),
                record_type: RecordType::Txt,
                ttl: self.ttl,
                values: Default::default(),
                proxied: None,
            });
            desired.values.insert(value.to_string());
            match provider
                .replace(&name, RecordType::Txt, current.as_ref(), Some(&desired))
                .await
            {
                Ok(ticket) => {
                    wait_synced(provider, &ticket, self.propagation_timeout).await?;
                    return Ok(handle);
                }
                Err(e) => retry_or_fail(e, attempt).await?,
            }
        }
        bail!("could not add TXT value to {name}: too many concurrent changes")
    }

    /// Wait until the value is visible through DNS (or the provider API in tests).
    pub async fn wait_propagated(&self, handle: &TxtHandle) -> anyhow::Result<()> {
        let deadline = Instant::now() + self.propagation_timeout;
        loop {
            if self.visible(handle).await {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "TXT record {} was not visible within {}s",
                    handle.name,
                    self.propagation_timeout.as_secs()
                );
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    async fn visible(&self, handle: &TxtHandle) -> bool {
        match &self.lookup {
            TxtLookup::Dns(resolver) => match resolver
                .lookup(handle.name.as_str(), DnsRecordType::TXT)
                .await
            {
                Ok(lookup) => lookup.answers().iter().any(|record| match &record.data {
                    RData::TXT(txt) => {
                        let joined: Vec<u8> = txt
                            .txt_data
                            .iter()
                            .flat_map(|chunk| chunk.iter().copied())
                            .collect();
                        String::from_utf8_lossy(&joined) == handle.value
                    }
                    _ => false,
                }),
                Err(_) => false,
            },
            #[cfg(test)]
            TxtLookup::ProviderApi => match self.zone_provider(&handle.zone) {
                Ok(provider) => observed_set(provider, &handle.name)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|set| set.values.contains(&handle.value)),
                Err(_) => false,
            },
        }
    }

    /// Remove only this value; other values in the record set are kept.
    pub async fn remove(&self, handle: &TxtHandle) -> anyhow::Result<()> {
        let provider = self.zone_provider(&handle.zone)?;
        let mut removed = false;
        for attempt in 1..=MAX_ATTEMPTS {
            let current = observed_set(provider, &handle.name).await?;
            let Some(current) = current.filter(|c| c.values.contains(&handle.value)) else {
                removed = true;
                break;
            };
            let mut remaining = current.clone();
            remaining.values.remove(&handle.value);
            let desired = (!remaining.values.is_empty()).then_some(remaining);
            match provider
                .replace(
                    &handle.name,
                    RecordType::Txt,
                    Some(&current),
                    desired.as_ref(),
                )
                .await
            {
                Ok(ticket) => {
                    wait_synced(provider, &ticket, self.propagation_timeout).await?;
                    removed = true;
                    break;
                }
                Err(e) => retry_or_fail(e, attempt).await?,
            }
        }
        if !removed {
            bail!(
                "could not remove TXT value from {}: too many concurrent changes",
                handle.name
            );
        }
        self.journal_update(|entries| entries.retain(|e| e != handle))
            .await
    }

    /// Remove every value left behind by an interrupted order. Only safe when
    /// the journal belongs to this Edge alone; with a shared journal the caller
    /// decides per entry and uses [`TxtChallengeSolver::cleanup_entry`].
    pub async fn cleanup_journal(&self) {
        for handle in self.journal_entries() {
            self.cleanup_entry(&handle).await;
        }
    }

    /// Values that were published and not removed again, e.g. by an order that
    /// was interrupted.
    pub fn journal_entries(&self) -> Vec<TxtHandle> {
        match self.read_journal() {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(error = %e, "cannot read DNS-01 journal");
                Vec::new()
            }
        }
    }

    /// Remove one journaled value.
    pub async fn cleanup_entry(&self, handle: &TxtHandle) {
        match self.remove(handle).await {
            Ok(()) => tracing::info!(name = %handle.name, "removed leftover DNS-01 TXT value"),
            Err(e) => {
                tracing::warn!(name = %handle.name, error = %e, "cannot remove leftover DNS-01 TXT value")
            }
        }
    }

    fn read_journal(&self) -> anyhow::Result<Vec<TxtHandle>> {
        match std::fs::read(&self.journal_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("corrupt DNS-01 journal"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn journal_update(&self, update: impl FnOnce(&mut Vec<TxtHandle>)) -> anyhow::Result<()> {
        let _guard = self.journal_lock.lock().await;
        if let Some(parent) = self.journal_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Different Edge processes have different Tokio mutexes.  Serialize the
        // complete read-modify-write transaction with a shared filesystem lock.
        let lock_path = self.journal_path.with_extension("json.lock");
        let lock = open_lock_file(&lock_path)?;
        lock.lock()
            .with_context(|| format!("cannot lock DNS-01 journal {lock_path:?}"))?;
        let mut entries = self.read_journal()?;
        update(&mut entries);
        write_atomic(&self.journal_path, &serde_json::to_vec_pretty(&entries)?)
    }
}

/// A delegated challenge name must stay inside the zones Sieve Tube may modify.
pub fn delegation_allowed(target: &str, allowed_zones: &[String]) -> bool {
    allowed_zones
        .iter()
        .any(|zone| hostname::is_within_zone(target, zone))
}

async fn observed_set(provider: &Provider, name: &str) -> anyhow::Result<Option<RecordSet>> {
    match provider.get(name, RecordType::Txt).await? {
        Some(observed) => match observed.unsupported {
            Some(reason) => bail!("TXT record set {name} cannot be managed: {reason}"),
            None => Ok(Some(observed.set)),
        },
        None => Ok(None),
    }
}

async fn wait_synced(
    provider: &Provider,
    ticket: &ChangeTicket,
    limit: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + limit;
    let mut delay = Duration::from_millis(200);
    while !provider.change_synced(ticket).await? {
        if Instant::now() >= deadline {
            bail!("DNS provider did not apply the change in time");
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(5));
    }
    Ok(())
}

async fn retry_or_fail(error: DnsError, attempt: u32) -> anyhow::Result<()> {
    match error {
        DnsError::Conflict(_) => {
            tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
            Ok(())
        }
        DnsError::RateLimited { retry_after } => {
            tokio::time::sleep(
                retry_after
                    .unwrap_or(Duration::from_secs(2))
                    .min(Duration::from_secs(30)),
            )
            .await;
            Ok(())
        }
        other => Err(other.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::contract_tests::CloudflareMock;
    use crate::dns::memory::MemoryProvider;

    fn settings() -> TxtSettings {
        TxtSettings {
            ttl: 60,
            propagation_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(20),
        }
    }

    fn journal() -> PathBuf {
        std::env::temp_dir().join(format!(
            "sievetube-txt-{}/journal.json",
            uuid::Uuid::new_v4()
        ))
    }

    fn solver(provider: Provider, journal: PathBuf) -> TxtChallengeSolver {
        TxtChallengeSolver::new(
            vec![("example.com".to_string(), Arc::new(provider))],
            vec!["example.com".to_string()],
            TxtLookup::ProviderApi,
            settings(),
            journal,
        )
    }

    async fn values(solver: &TxtChallengeSolver, name: &str) -> Vec<String> {
        let provider = solver.zone_provider("example.com").unwrap();
        observed_set(provider, name)
            .await
            .unwrap()
            .map(|s| s.values.into_iter().collect())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn concurrent_values_and_operator_values_are_kept() {
        let memory = MemoryProvider::with_tracked_changes();
        memory.set_external(RecordSet {
            name: "_acme-challenge.example.com".into(),
            record_type: RecordType::Txt,
            ttl: 300,
            values: ["operator-value".to_string()].into(),
            proxied: None,
        });
        let solver = solver(Provider::Memory(memory), journal());

        // Wildcard and base name orders validate at the same time.
        let (wildcard, base) = tokio::join!(
            solver.add("example.com", "wildcard-token"),
            solver.add("example.com", "base-token")
        );
        let (wildcard, base) = (wildcard.unwrap(), base.unwrap());
        solver.wait_propagated(&wildcard).await.unwrap();
        solver.wait_propagated(&base).await.unwrap();
        assert_eq!(
            values(&solver, "_acme-challenge.example.com").await.len(),
            3
        );

        solver.remove(&wildcard).await.unwrap();
        assert_eq!(
            values(&solver, "_acme-challenge.example.com").await,
            ["base-token", "operator-value"]
        );
        solver.remove(&base).await.unwrap();
        assert_eq!(
            values(&solver, "_acme-challenge.example.com").await,
            ["operator-value"]
        );
        // Removing again is a no-op.
        solver.remove(&base).await.unwrap();
    }

    #[tokio::test]
    async fn journal_cleans_up_after_restart() {
        let memory = MemoryProvider::new();
        let path = journal();
        let first = solver(Provider::Memory(memory.clone()), path.clone());
        first.add("example.com", "left-behind").await.unwrap();
        drop(first);

        let restarted = solver(Provider::Memory(memory), path.clone());
        assert_eq!(
            values(&restarted, "_acme-challenge.example.com").await,
            ["left-behind"]
        );
        restarted.cleanup_journal().await;
        assert!(values(&restarted, "_acme-challenge.example.com")
            .await
            .is_empty());
        assert!(restarted.read_journal().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn separate_solvers_serialize_shared_journal_updates() {
        let path = journal();
        let mut tasks = Vec::new();
        for i in 0..40 {
            let solver = solver(Provider::Memory(MemoryProvider::new()), path.clone());
            tasks.push(tokio::spawn(async move {
                solver
                    .journal_update(|entries| {
                        entries.push(TxtHandle {
                            zone: "example.com".into(),
                            name: "_acme-challenge.example.com".into(),
                            value: format!("token-{i}"),
                            domain: "example.com".into(),
                        });
                    })
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let restarted = solver(Provider::Memory(MemoryProvider::new()), path);
        let entries = restarted.read_journal().unwrap();
        assert_eq!(entries.len(), 40);
        assert_eq!(
            entries
                .iter()
                .map(|entry| &entry.value)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            40
        );
    }

    #[tokio::test]
    async fn works_through_the_cloudflare_adapter() {
        let mock = CloudflareMock::start().await;
        let solver = solver(
            mock.provider(crate::dns::contract_tests::MOCK_TOKEN),
            journal(),
        );
        let handle = solver.add("www.example.com", "cf-token").await.unwrap();
        assert_eq!(handle.name, "_acme-challenge.www.example.com");
        solver.wait_propagated(&handle).await.unwrap();
        solver.remove(&handle).await.unwrap();
        assert!(values(&solver, "_acme-challenge.www.example.com")
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn journal_entries_carry_their_domain() {
        let solver = solver(Provider::Memory(MemoryProvider::new()), journal());
        solver.add("www.example.com", "token").await.unwrap();
        let entries = solver.journal_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain(), Some("www.example.com"));

        // A journal written before the field existed still resolves a domain.
        let legacy = TxtHandle {
            zone: "example.com".into(),
            name: "_acme-challenge.example.com".into(),
            value: "v".into(),
            domain: String::new(),
        };
        assert_eq!(legacy.domain(), Some("example.com"));
    }

    #[tokio::test]
    async fn names_outside_provider_zones_are_rejected() {
        let solver = solver(Provider::Memory(MemoryProvider::new()), journal());
        assert!(solver.add("example.net", "x").await.is_err());
        assert!(delegation_allowed(
            "_acme-challenge.example.com",
            &["example.com".to_string()]
        ));
        assert!(!delegation_allowed(
            "evil.example.net",
            &["example.com".to_string()]
        ));
    }

    #[tokio::test]
    async fn propagation_timeout_fails_the_wait() {
        let solver = solver(Provider::Memory(MemoryProvider::new()), journal());
        let handle = TxtHandle {
            zone: "example.com".into(),
            name: "_acme-challenge.example.com".into(),
            value: "never".into(),
            domain: "example.com".into(),
        };
        let mut short = settings();
        short.propagation_timeout = Duration::from_millis(100);
        let solver = TxtChallengeSolver {
            propagation_timeout: short.propagation_timeout,
            ..solver
        };
        assert!(solver.wait_propagated(&handle).await.is_err());
    }
}

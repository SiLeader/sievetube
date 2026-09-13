//! Periodic reconciliation of desired DNS records with the providers.
//!
//! Each provider (zone) has a single writer: either the holder of a Valkey lease
//! or an Edge explicitly configured as the single writer. Every change is first
//! recorded as a pending intent, so an interrupted change is resumed or reported
//! as a conflict instead of being mistaken for an external edit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::plan::{
    decide, Action, CompiledDns, DesiredRecord, ManagedRecord, PendingChange, ProviderState,
};
use super::{ChangeTicket, DnsError, Provider, RecordSet};
use crate::certificate_store::{now_unix, write_atomic};
use crate::edge_metrics;
use crate::valkey::ValkeyHandle;

/// How this Edge becomes the writer for a provider.
pub enum WriterMode {
    /// Configured as the only writer (no Valkey)
    SingleWriter,
    /// Coordinated through per-provider Valkey leases
    Valkey(ValkeyHandle),
}

#[derive(Debug, Clone)]
pub struct ReconcilerSettings {
    pub state_dir: PathBuf,
    pub interval: Duration,
    pub settle_secs: i64,
    pub lease_ttl: Duration,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordOutcome {
    pub provider: String,
    pub key: String,
    pub action: Action,
    /// `None` for planned or unexecuted actions
    pub error: Option<String>,
}

pub struct DnsReconciler {
    settings: ReconcilerSettings,
    compiled: CompiledDns,
    providers: HashMap<String, Arc<Provider>>,
    writer: WriterMode,
    /// Generation used in single-writer mode, fixed per process and provider
    single_writer_generations: Mutex<HashMap<String, u64>>,
}

impl DnsReconciler {
    pub fn new(
        settings: ReconcilerSettings,
        compiled: CompiledDns,
        providers: HashMap<String, Arc<Provider>>,
        writer: WriterMode,
    ) -> Arc<Self> {
        Arc::new(DnsReconciler {
            settings,
            compiled,
            providers,
            writer,
            single_writer_generations: Mutex::new(HashMap::new()),
        })
    }

    fn state_path(&self, provider: &str) -> PathBuf {
        self.settings.state_dir.join(format!("{provider}.json"))
    }

    fn load_state(&self, provider: &str) -> anyhow::Result<ProviderState> {
        load_state(&self.state_path(provider))
    }

    fn save_state(&self, provider: &str, state: &ProviderState) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.settings.state_dir)
            .with_context(|| format!("cannot create {:?}", self.settings.state_dir))?;
        write_atomic(
            &self.state_path(provider),
            &serde_json::to_vec_pretty(state)?,
        )
    }

    fn records_for<'a>(
        &'a self,
        provider: &'a str,
    ) -> impl Iterator<Item = &'a DesiredRecord> + 'a {
        self.compiled
            .records
            .iter()
            .filter(move |r| r.provider == provider)
    }

    /// Compute the actions for every record without changing anything.
    pub async fn plan(&self) -> Vec<RecordOutcome> {
        let mut outcomes = Vec::new();
        let now = now_unix();
        for spec in &self.compiled.providers {
            let Some(provider) = self.providers.get(&spec.name) else {
                continue;
            };
            let state = match self.load_state(&spec.name) {
                Ok(state) => state,
                Err(e) => {
                    outcomes.push(provider_error(
                        &spec.name,
                        format!("cannot read state: {e:#}"),
                    ));
                    continue;
                }
            };
            for desired in self.records_for(&spec.name) {
                let key = desired.key();
                let observed = provider
                    .get(&desired.set.name, desired.set.record_type)
                    .await;
                let outcome = match observed {
                    Ok(observed) => RecordOutcome {
                        provider: spec.name.clone(),
                        key: key.clone(),
                        action: decide(
                            desired,
                            observed.as_ref(),
                            state.records.get(&key),
                            now,
                            self.settings.settle_secs,
                        ),
                        error: None,
                    },
                    Err(e) => RecordOutcome {
                        provider: spec.name.clone(),
                        key,
                        action: Action::Wait {
                            reason: "provider read failed".to_string(),
                        },
                        error: Some(e.to_string()),
                    },
                };
                outcomes.push(outcome);
            }
        }
        outcomes
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let outcomes = if self.settings.dry_run {
                let plan = self.plan().await;
                for outcome in plan.iter().filter(|o| o.action != Action::NoChange) {
                    tracing::info!(provider = %outcome.provider, record = %outcome.key, plan = %outcome.action.describe(), error = ?outcome.error, "DNS dry-run");
                }
                plan
            } else {
                self.reconcile_once().await
            };
            publish_metrics(&outcomes, self.settings.dry_run);

            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(self.settings.interval) => {}
            }
        }
    }

    /// Reconcile every provider this Edge may write to.
    pub async fn reconcile_once(&self) -> Vec<RecordOutcome> {
        let mut outcomes = Vec::new();
        for spec in &self.compiled.providers {
            outcomes.extend(self.reconcile_provider(&spec.name).await);
        }
        outcomes
    }

    async fn acquire_writer(
        &self,
        provider: &str,
        state: &ProviderState,
    ) -> Result<Option<u64>, String> {
        match &self.writer {
            WriterMode::SingleWriter => {
                let mut generations = self.single_writer_generations.lock().await;
                let generation = *generations
                    .entry(provider.to_string())
                    .or_insert(state.writer_generation + 1);
                Ok(Some(generation))
            }
            WriterMode::Valkey(valkey) => valkey
                .acquire_lease(
                    &lease_resource(provider),
                    self.settings.lease_ttl,
                    state.writer_generation + 1,
                )
                .await
                .map_err(|e| e.to_string()),
        }
    }

    /// Extend the writer lease and verify that its fencing generation did not
    /// change.  A bounded renewal leaves enough TTL to stop an in-flight change
    /// if the control plane cannot confirm ownership.
    async fn renew_writer(&self, provider: &str, generation: u64) -> bool {
        match &self.writer {
            WriterMode::SingleWriter => true,
            WriterMode::Valkey(valkey) => {
                let resource = lease_resource(provider);
                let renewal = valkey.acquire_lease(&resource, self.settings.lease_ttl, generation);
                matches!(
                    tokio::time::timeout(self.settings.lease_ttl / 2, renewal).await,
                    Ok(Ok(Some(renewed))) if renewed == generation
                )
            }
        }
    }

    /// Run a provider mutation while periodically extending the writer lease.
    /// Dropping the provider future on renewal failure prevents a stale writer
    /// from continuing an HTTP exchange after another Edge can take over.
    async fn replace_while_writer(
        &self,
        provider: &Provider,
        provider_name: &str,
        generation: u64,
        record: &DesiredRecord,
        expected: Option<&RecordSet>,
        target: Option<&RecordSet>,
    ) -> Result<Result<ChangeTicket, DnsError>, ()> {
        if !self.renew_writer(provider_name, generation).await {
            return Err(());
        }
        let replace = provider.replace(&record.set.name, record.set.record_type, expected, target);
        tokio::pin!(replace);
        let renew_every = (self.settings.lease_ttl / 3).max(Duration::from_millis(1));
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep(renew_every) => {
                    if !self.renew_writer(provider_name, generation).await {
                        return Err(());
                    }
                }
                result = &mut replace => {
                    if !self.renew_writer(provider_name, generation).await {
                        return Err(());
                    }
                    return Ok(result);
                }
            }
        }
    }

    async fn reconcile_provider(&self, provider_name: &str) -> Vec<RecordOutcome> {
        let Some(provider) = self.providers.get(provider_name).cloned() else {
            return Vec::new();
        };
        let mut state = match self.load_state(provider_name) {
            Ok(state) => state,
            Err(e) => {
                return vec![provider_error(
                    provider_name,
                    format!("cannot read state; not changing records: {e:#}"),
                )]
            }
        };
        let generation = match self.acquire_writer(provider_name, &state).await {
            Ok(Some(generation)) => generation,
            Ok(None) => {
                tracing::debug!(
                    provider = provider_name,
                    "another edge holds the DNS writer lease"
                );
                return Vec::new();
            }
            Err(e) => {
                return vec![provider_error(
                    provider_name,
                    format!("control plane unavailable; DNS changes paused: {e}"),
                )];
            }
        };
        if state.writer_generation > generation {
            return vec![provider_error(
                provider_name,
                "a newer writer updated this zone; stopping".to_string(),
            )];
        }
        state.writer_generation = generation;

        let mut outcomes = Vec::new();
        let desired_records: Vec<DesiredRecord> =
            self.records_for(provider_name).cloned().collect();
        let mut lost_writer = false;
        for desired in &desired_records {
            let outcome = self
                .reconcile_record(&provider, provider_name, desired, &mut state, generation)
                .await;
            let stop = matches!(outcome.error.as_deref(), Some(e) if e.starts_with("stop:"));
            if let Some(error) = &outcome.error {
                tracing::warn!(provider = provider_name, record = %outcome.key, action = outcome.action.label(), error = %error, "DNS reconcile issue");
            } else if !matches!(outcome.action, Action::NoChange) {
                tracing::info!(provider = provider_name, record = %outcome.key, action = %outcome.action.describe(), "DNS reconcile");
            }
            outcomes.push(outcome);
            if stop {
                lost_writer = outcomes.last().is_some_and(|outcome| {
                    outcome.error.as_deref() == Some("stop: lost the DNS writer lease")
                });
                break;
            }
        }

        for key in state.records.keys() {
            if !desired_records.iter().any(|d| &d.key() == key) {
                tracing::warn!(provider = provider_name, record = %key, "managed record is no longer configured; it is left unchanged (use state = \"absent\" to delete)");
            }
        }
        // Do not let a stale in-memory snapshot overwrite state saved by the
        // successor.  Renew immediately before the final shared-state write.
        if !lost_writer && !self.renew_writer(provider_name, generation).await {
            lost_writer = true;
            outcomes.push(provider_error(
                provider_name,
                "stop: lost the DNS writer lease before persisting state".to_string(),
            ));
        }
        if !lost_writer {
            if let Err(e) = self.save_state(provider_name, &state) {
                outcomes.push(provider_error(
                    provider_name,
                    format!("cannot persist state: {e:#}"),
                ));
            }
        }
        outcomes
    }

    async fn reconcile_record(
        &self,
        provider: &Provider,
        provider_name: &str,
        desired: &DesiredRecord,
        state: &mut ProviderState,
        generation: u64,
    ) -> RecordOutcome {
        let key = desired.key();
        let now = now_unix();
        let outcome = |action: Action, error: Option<String>| RecordOutcome {
            provider: provider_name.to_string(),
            key: key.clone(),
            action,
            error,
        };

        // Finish tracked changes first (Route 53 PENDING → INSYNC).
        if let Some(pending) = state.records.get(&key).and_then(|m| m.pending.clone()) {
            if let Some(ticket @ ChangeTicket::Route53 { .. }) = &pending.ticket {
                match provider.change_synced(ticket).await {
                    Ok(true) => finish_pending(state, &key, generation, now),
                    Ok(false) => {
                        return outcome(
                            Action::Wait {
                                reason: "provider change is still pending".to_string(),
                            },
                            None,
                        )
                    }
                    Err(e) => {
                        return outcome(
                            Action::Wait {
                                reason: "cannot read change status".to_string(),
                            },
                            Some(e.to_string()),
                        )
                    }
                }
            }
        }

        let observed = match provider
            .get(&desired.set.name, desired.set.record_type)
            .await
        {
            Ok(observed) => observed,
            Err(e) => {
                return outcome(
                    Action::Wait {
                        reason: "provider read failed".to_string(),
                    },
                    Some(error_text(&e)),
                )
            }
        };

        // An interrupted immediate change that actually completed.
        if let Some(pending) = state.records.get(&key).and_then(|m| m.pending.clone()) {
            if pending.ticket.is_none()
                && super::same_optional(observed.as_ref().map(|o| &o.set), pending.desired.as_ref())
            {
                finish_pending(state, &key, generation, now);
            }
        }

        let action = decide(
            desired,
            observed.as_ref(),
            state.records.get(&key),
            now,
            self.settings.settle_secs,
        );
        match &action {
            Action::NoChange => {
                // Record what the provider has if it converged by other means.
                if let Some(entry) = state.records.get_mut(&key) {
                    let observed_set = observed.as_ref().map(|o| o.set.clone());
                    if entry.pending.is_some()
                        || !super::same_optional(observed_set.as_ref(), entry.applied.as_ref())
                    {
                        entry.applied = observed_set;
                        entry.pending = None;
                        entry.updated_at = now;
                    }
                }
                outcome(action, None)
            }
            Action::Wait { .. } | Action::Conflict { .. } => outcome(action, None),
            Action::Adopt { current } => {
                state.records.insert(
                    key.clone(),
                    ManagedRecord {
                        name: desired.set.name.clone(),
                        record_type: desired.set.record_type,
                        applied: Some(current.clone()),
                        previous: None,
                        generation,
                        pending: None,
                        updated_at: now,
                    },
                );
                outcome(action, None)
            }
            Action::Forget => {
                state.records.remove(&key);
                outcome(action, None)
            }
            Action::Apply {
                expected,
                desired: target,
            } => {
                if !self.renew_writer(provider_name, generation).await {
                    return outcome(action, Some("stop: lost the DNS writer lease".to_string()));
                }
                let entry = state
                    .records
                    .entry(key.clone())
                    .or_insert_with(|| ManagedRecord {
                        name: desired.set.name.clone(),
                        record_type: desired.set.record_type,
                        applied: None,
                        previous: None,
                        generation,
                        pending: None,
                        updated_at: now,
                    });
                entry.pending = Some(PendingChange {
                    expected: expected.clone(),
                    desired: target.clone(),
                    ticket: None,
                    started_at: now,
                });
                // Persist the intent before touching the provider.
                if let Err(e) = self.save_state(provider_name, state) {
                    return outcome(action, Some(format!("stop: cannot persist state: {e:#}")));
                }

                let result = match self
                    .replace_while_writer(
                        provider,
                        provider_name,
                        generation,
                        desired,
                        expected.as_ref(),
                        target.as_ref(),
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(()) => {
                        return outcome(action, Some("stop: lost the DNS writer lease".to_string()))
                    }
                };
                let changes = edge_metrics::get();
                let kind = provider.kind();
                match result {
                    Ok(ChangeTicket::Immediate) => {
                        complete_change(
                            state,
                            &key,
                            expected.clone(),
                            target.clone(),
                            generation,
                            now,
                        );
                        changes
                            .dns_changes_total
                            .with_label_values(&[kind, "success"])
                            .inc();
                        outcome(action, None)
                    }
                    Ok(ticket @ ChangeTicket::Route53 { .. }) => {
                        if let Some(entry) = state.records.get_mut(&key) {
                            if let Some(pending) = entry.pending.as_mut() {
                                pending.ticket = Some(ticket);
                            }
                        }
                        changes
                            .dns_changes_total
                            .with_label_values(&[kind, "submitted"])
                            .inc();
                        outcome(action, None)
                    }
                    Err(DnsError::Conflict(reason)) => {
                        // Conditional change rejected: nothing was modified.
                        if let Some(entry) = state.records.get_mut(&key) {
                            entry.pending = None;
                            if entry.applied.is_none() && entry.previous.is_none() {
                                state.records.remove(&key);
                            }
                        }
                        changes
                            .dns_changes_total
                            .with_label_values(&[kind, "conflict"])
                            .inc();
                        outcome(Action::Conflict { reason }, None)
                    }
                    Err(e) => {
                        // May be partially applied; the pending intent lets the next run resume.
                        changes
                            .dns_changes_total
                            .with_label_values(&[kind, e.label()])
                            .inc();
                        let stop = matches!(e, DnsError::RateLimited { .. } | DnsError::Auth(_));
                        let text = error_text(&e);
                        outcome(
                            action,
                            Some(if stop { format!("stop: {text}") } else { text }),
                        )
                    }
                }
            }
        }
    }
}

fn load_state(path: &Path) -> anyhow::Result<ProviderState> {
    match std::fs::read(path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("corrupt DNS state {path:?}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProviderState::default()),
        Err(e) => Err(e).with_context(|| format!("cannot read {path:?}")),
    }
}

fn finish_pending(state: &mut ProviderState, key: &str, generation: u64, now: i64) {
    if let Some(pending) = state.records.get(key).and_then(|m| m.pending.clone()) {
        complete_change(
            state,
            key,
            pending.expected,
            pending.desired,
            generation,
            now,
        );
    }
}

fn complete_change(
    state: &mut ProviderState,
    key: &str,
    expected: Option<RecordSet>,
    desired: Option<RecordSet>,
    generation: u64,
    now: i64,
) {
    if let Some(entry) = state.records.get_mut(key) {
        entry.previous = expected;
        entry.applied = desired;
        entry.pending = None;
        entry.generation = generation;
        entry.updated_at = now;
    }
}

fn lease_resource(provider: &str) -> String {
    format!("dns:{provider}")
}

fn provider_error(provider: &str, error: String) -> RecordOutcome {
    RecordOutcome {
        provider: provider.to_string(),
        key: "*".to_string(),
        action: Action::Wait {
            reason: "provider unavailable".to_string(),
        },
        error: Some(error),
    }
}

fn error_text(error: &DnsError) -> String {
    error.to_string()
}

fn publish_metrics(outcomes: &[RecordOutcome], dry_run: bool) {
    let m = edge_metrics::get();
    let mut counts: HashMap<&'static str, i64> = HashMap::new();
    for outcome in outcomes.iter().filter(|o| o.key != "*") {
        let status = if outcome.error.is_some() {
            "error"
        } else if dry_run
            && matches!(
                outcome.action,
                Action::Apply { .. } | Action::Adopt { .. } | Action::Forget
            )
        {
            "planned"
        } else {
            outcome.action.label()
        };
        *counts.entry(status).or_default() += 1;
    }
    for status in [
        "in_sync", "change", "adopt", "forget", "pending", "conflict", "error", "planned",
    ] {
        m.dns_records
            .with_label_values(&[status])
            .set(counts.get(status).copied().unwrap_or(0));
    }
    if !outcomes.iter().any(|o| o.key == "*") {
        m.dns_last_reconcile_timestamp_seconds
            .set(now_unix() as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::super::memory::MemoryProvider;
    use super::super::plan::compile;
    use super::super::RecordType;
    use super::*;
    use crate::config::{
        DnsConfig, DnsProviderConfig, DnsProviderType, DnsRecordConfig, RecordState,
    };

    fn provider_config() -> DnsProviderConfig {
        DnsProviderConfig {
            name: "mem".into(),
            kind: DnsProviderType::Cloudflare,
            zone: "example.com".into(),
            zone_id: Some("z".into()),
            api_token_env: Some("UNUSED".into()),
            api_token_file: None,
            api_base_url: None,
            hosted_zone_id: None,
            endpoint_url: None,
            region: None,
            request_timeout_secs: 5,
        }
    }

    fn record(values: &[&str], state: RecordState, import: bool) -> DnsRecordConfig {
        DnsRecordConfig {
            provider: "mem".into(),
            name: "www.example.com".into(),
            record_type: RecordType::A,
            values: values.iter().map(|v| v.to_string()).collect(),
            ttl: 300,
            proxied: None,
            import,
            state,
        }
    }

    fn reconciler(
        dir: &Path,
        provider: &MemoryProvider,
        records: Vec<DnsRecordConfig>,
    ) -> Arc<DnsReconciler> {
        let cfg = DnsConfig {
            enabled: true,
            allowed_zones: vec!["example.com".into()],
            providers: vec![provider_config()],
            records,
            ..DnsConfig::default()
        };
        let compiled = compile(&cfg).unwrap();
        DnsReconciler::new(
            ReconcilerSettings {
                state_dir: dir.to_path_buf(),
                interval: Duration::from_secs(60),
                settle_secs: 0,
                lease_ttl: Duration::from_secs(30),
                dry_run: false,
            },
            compiled,
            HashMap::from([(
                "mem".to_string(),
                Arc::new(Provider::Memory(provider.clone())),
            )]),
            WriterMode::SingleWriter,
        )
    }

    fn tempdir() -> crate::test_support::TempPath {
        crate::test_support::TempPath::new("dns")
    }

    fn values(set: Option<RecordSet>) -> Vec<String> {
        set.map(|s| s.values.into_iter().collect())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn create_change_rerun_and_delete() {
        crate::test_support::install_crypto();
        let dir = tempdir();
        let provider = MemoryProvider::new();

        let r = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.1"], RecordState::Present, false)],
        );
        r.reconcile_once().await;
        assert_eq!(
            values(provider.snapshot("www.example.com", RecordType::A)),
            ["192.0.2.1"]
        );

        // Re-running converges without writes.
        let writes = provider.writes();
        let outcomes = r.reconcile_once().await;
        assert_eq!(provider.writes(), writes);
        assert_eq!(outcomes[0].action, Action::NoChange);

        let r = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.2"], RecordState::Present, false)],
        );
        r.reconcile_once().await;
        assert_eq!(
            values(provider.snapshot("www.example.com", RecordType::A)),
            ["192.0.2.2"]
        );
        let state = load_state(&dir.join("mem.json")).unwrap();
        let managed = &state.records["www.example.com/A"];
        assert_eq!(
            values(managed.previous.clone()),
            ["192.0.2.1"],
            "previous value kept for rollback"
        );

        // Removing the record from the configuration does not delete it.
        let r = reconciler(&dir, &provider, vec![]);
        r.reconcile_once().await;
        assert!(provider
            .snapshot("www.example.com", RecordType::A)
            .is_some());

        // Explicit deletion does.
        let r = reconciler(
            &dir,
            &provider,
            vec![record(&[], RecordState::Absent, false)],
        );
        r.reconcile_once().await;
        assert!(provider
            .snapshot("www.example.com", RecordType::A)
            .is_none());
        r.reconcile_once().await;
        assert!(load_state(&dir.join("mem.json"))
            .unwrap()
            .records
            .is_empty());
    }

    #[tokio::test]
    async fn unmanaged_and_externally_changed_records_are_left_alone() {
        let dir = tempdir();
        let provider = MemoryProvider::new();
        let foreign = RecordSet {
            name: "www.example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            values: ["198.51.100.1".to_string()].into(),
            proxied: Some(true),
        };
        provider.set_external(foreign.clone());

        let r = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.1"], RecordState::Present, false)],
        );
        let outcomes = r.reconcile_once().await;
        assert!(matches!(outcomes[0].action, Action::Conflict { .. }));
        assert_eq!(
            provider.snapshot("www.example.com", RecordType::A),
            Some(foreign.clone())
        );
        assert_eq!(provider.writes(), 0);

        // Explicit import takes it over and keeps the proxy setting.
        let r = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.1"], RecordState::Present, true)],
        );
        r.reconcile_once().await;
        let imported = provider.snapshot("www.example.com", RecordType::A).unwrap();
        assert_eq!(values(Some(imported.clone())), ["192.0.2.1"]);
        assert_eq!(imported.proxied, Some(true));

        // Someone edits it by hand: the reconciler stops and does not revert.
        let mut edited = imported.clone();
        edited.values = ["203.0.113.5".to_string()].into();
        provider.set_external(edited.clone());
        let outcomes = r.reconcile_once().await;
        assert!(matches!(outcomes[0].action, Action::Conflict { .. }));
        assert_eq!(
            provider.snapshot("www.example.com", RecordType::A),
            Some(edited)
        );
    }

    #[tokio::test]
    async fn provider_failures_and_pending_changes_recover() {
        let dir = tempdir();
        let provider = MemoryProvider::with_tracked_changes();
        let r = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.1"], RecordState::Present, false)],
        );

        provider.fail_next(DnsError::Timeout);
        let outcomes = r.reconcile_once().await;
        assert!(outcomes[0].error.is_some());
        assert!(provider
            .snapshot("www.example.com", RecordType::A)
            .is_none());

        // Submitted but not yet in sync: wait, don't resubmit.
        r.reconcile_once().await;
        assert_eq!(provider.writes(), 1);
        let outcomes = r.reconcile_once().await;
        assert!(matches!(outcomes[0].action, Action::Wait { .. }));
        assert_eq!(provider.writes(), 1);

        // After a restart the pending change is still tracked and completes.
        provider.sync_all();
        let restarted = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.1"], RecordState::Present, false)],
        );
        let outcomes = restarted.reconcile_once().await;
        assert_eq!(outcomes[0].action, Action::NoChange);
        let state = load_state(&dir.join("mem.json")).unwrap();
        assert!(state.records["www.example.com/A"].pending.is_none());

        // Rate limiting stops the pass without marking records as conflicts.
        let r = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.9"], RecordState::Present, false)],
        );
        provider.fail_next(DnsError::RateLimited {
            retry_after: Some(Duration::from_secs(5)),
        });
        let outcomes = r.reconcile_once().await;
        assert!(outcomes[0]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("rate limited")));
    }

    #[tokio::test]
    async fn corrupt_state_stops_changes() {
        let dir = tempdir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mem.json"), b"{broken").unwrap();
        let provider = MemoryProvider::new();
        let r = reconciler(
            &dir,
            &provider,
            vec![record(&["192.0.2.1"], RecordState::Present, false)],
        );
        let outcomes = r.reconcile_once().await;
        assert!(outcomes[0].error.is_some());
        assert_eq!(provider.writes(), 0);
    }

    #[tokio::test]
    async fn valkey_lease_allows_a_single_writer() {
        let Ok(url) = std::env::var("SIEVETUBE_TEST_VALKEY_URL") else {
            eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
            return;
        };
        let provider = MemoryProvider::new();
        let dir = tempdir();
        let valkey_a = ValkeyHandle::new(&url, "a-edge").unwrap();
        let valkey_b = ValkeyHandle::new(&url, "b-edge").unwrap();
        valkey_a.try_connect().await.unwrap();
        valkey_b.try_connect().await.unwrap();

        let provider_name = format!("mem-{}", uuid::Uuid::new_v4().simple());
        let build = |valkey: ValkeyHandle| {
            let cfg = DnsConfig {
                enabled: true,
                allowed_zones: vec!["example.com".into()],
                providers: vec![DnsProviderConfig {
                    name: provider_name.clone(),
                    ..provider_config()
                }],
                records: vec![DnsRecordConfig {
                    provider: provider_name.clone(),
                    ..record(&["192.0.2.1"], RecordState::Present, false)
                }],
                ..DnsConfig::default()
            };
            DnsReconciler::new(
                ReconcilerSettings {
                    state_dir: dir.to_path_buf(),
                    interval: Duration::from_secs(60),
                    settle_secs: 0,
                    lease_ttl: Duration::from_secs(30),
                    dry_run: false,
                },
                compile(&cfg).unwrap(),
                HashMap::from([(
                    provider_name.clone(),
                    Arc::new(Provider::Memory(provider.clone())),
                )]),
                WriterMode::Valkey(valkey),
            )
        };
        let a = build(valkey_a);
        let b = build(valkey_b);
        assert_eq!(a.reconcile_once().await.len(), 1);
        assert!(
            b.reconcile_once().await.is_empty(),
            "second edge must not write while the lease is held"
        );
        assert_eq!(provider.writes(), 1);
    }
}

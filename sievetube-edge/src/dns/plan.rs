//! Desired DNS state from configuration, persisted management state, and the
//! decision logic that compares them with what a provider reports.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};

use sievetube_common::hostname;

use super::{same_optional, ChangeTicket, Observed, RecordSet, RecordType};
use crate::config::{DnsConfig, DnsProviderConfig, DnsProviderType, RecordState};

/// Label reserved for ACME DNS-01 challenge records managed separately.
pub const ACME_CHALLENGE_LABEL: &str = "_acme-challenge";

#[derive(Debug, Clone)]
pub struct ProviderSpec {
    pub name: String,
    pub kind: DnsProviderType,
    pub zone: String,
    pub config: DnsProviderConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DesiredRecord {
    pub provider: String,
    pub set: RecordSet,
    pub import: bool,
    pub absent: bool,
}

impl DesiredRecord {
    pub fn key(&self) -> String {
        record_key(&self.set.name, self.set.record_type)
    }
}

pub fn record_key(name: &str, record_type: RecordType) -> String {
    format!("{name}/{}", record_type.as_str())
}

#[derive(Debug, Clone)]
pub struct CompiledDns {
    pub allowed_zones: Vec<String>,
    pub providers: Vec<ProviderSpec>,
    pub records: Vec<DesiredRecord>,
}

/// Validate the DNS section against the allowed zones and provider constraints.
pub fn compile(cfg: &DnsConfig) -> anyhow::Result<CompiledDns> {
    let allowed_zones = cfg
        .allowed_zones
        .iter()
        .map(|zone| {
            hostname::normalize_hostname(zone)
                .map_err(|e| anyhow!("dns.allowed_zones: invalid zone {zone:?}: {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if allowed_zones.is_empty() {
        bail!("dns.allowed_zones must list the zones Sieve Tube may modify");
    }

    let mut providers = Vec::new();
    for provider in &cfg.providers {
        let name = provider.name.trim().to_string();
        let valid_name = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !valid_name {
            bail!("dns.providers: name {name:?} must be lowercase letters, digits, '-' or '_'");
        }
        if providers.iter().any(|p: &ProviderSpec| p.name == name) {
            bail!("dns.providers: duplicate provider name {name}");
        }
        let zone = hostname::normalize_hostname(&provider.zone)
            .map_err(|e| anyhow!("dns.providers[{name}]: invalid zone: {e}"))?;
        if !allowed_zones
            .iter()
            .any(|allowed| hostname::is_within_zone(&zone, allowed))
        {
            bail!("dns.providers[{name}]: zone {zone} is not inside dns.allowed_zones");
        }
        let field_set =
            |value: &Option<String>| value.as_deref().is_some_and(|v| !v.trim().is_empty());
        match provider.kind {
            DnsProviderType::Cloudflare => {
                if !field_set(&provider.zone_id) {
                    bail!("dns.providers[{name}]: cloudflare requires zone_id");
                }
                if field_set(&provider.api_token_env) == field_set(&provider.api_token_file) {
                    bail!(
                        "dns.providers[{name}]: set exactly one of api_token_env or api_token_file"
                    );
                }
                if provider.hosted_zone_id.is_some()
                    || provider.endpoint_url.is_some()
                    || provider.region.is_some()
                {
                    bail!("dns.providers[{name}]: hosted_zone_id/endpoint_url/region are Route 53 settings");
                }
            }
            DnsProviderType::Route53 => {
                if !field_set(&provider.hosted_zone_id) {
                    bail!("dns.providers[{name}]: route53 requires hosted_zone_id");
                }
                if provider.zone_id.is_some()
                    || provider.api_token_env.is_some()
                    || provider.api_token_file.is_some()
                    || provider.api_base_url.is_some()
                {
                    bail!("dns.providers[{name}]: zone_id/api_token_*/api_base_url are Cloudflare settings; Route 53 uses the AWS credential chain");
                }
            }
        }
        if provider.request_timeout_secs == 0 {
            bail!("dns.providers[{name}]: request_timeout_secs must be greater than 0");
        }
        providers.push(ProviderSpec {
            name,
            kind: provider.kind,
            zone,
            config: provider.clone(),
        });
    }

    let mut records = Vec::new();
    let mut keys = HashSet::new();
    let mut present_types: HashMap<(String, String), Vec<RecordType>> = HashMap::new();
    for record in &cfg.records {
        let spec = providers
            .iter()
            .find(|p| p.name == record.provider)
            .ok_or_else(|| anyhow!("dns.records: unknown provider {:?}", record.provider))?;
        let name = hostname::normalize_dns_name(&record.name)
            .map_err(|e| anyhow!("dns.records: invalid name {:?}: {e}", record.name))?;
        let field = format!("dns.records[{name} {}]", record.record_type.as_str());
        if !hostname::is_within_zone(&name, &spec.zone) {
            bail!(
                "{field}: name is outside zone {} of provider {}",
                spec.zone,
                spec.name
            );
        }
        if name.split('.').next() == Some(ACME_CHALLENGE_LABEL) {
            bail!("{field}: {ACME_CHALLENGE_LABEL} records are reserved for ACME DNS-01");
        }
        let absent = record.state == RecordState::Absent;
        let values = record
            .values
            .iter()
            .map(|v| {
                record
                    .record_type
                    .normalize_value(v)
                    .map_err(|e| anyhow!("{field}: {e}"))
            })
            .collect::<anyhow::Result<std::collections::BTreeSet<_>>>()?;
        if !absent && values.is_empty() {
            bail!("{field}: at least one value is required");
        }
        if record.record_type == RecordType::Cname && values.len() > 1 {
            bail!("{field}: CNAME must have exactly one value");
        }
        if record.record_type == RecordType::Cname
            && name == spec.zone
            && spec.kind == DnsProviderType::Route53
        {
            bail!("{field}: Route 53 does not allow a CNAME at the zone apex");
        }
        match spec.kind {
            DnsProviderType::Cloudflare
                if !(record.ttl == 1 || (60..=86400).contains(&record.ttl)) =>
            {
                bail!("{field}: Cloudflare TTL must be 1 (automatic) or between 60 and 86400");
            }
            DnsProviderType::Route53 if !(1..=604_800).contains(&record.ttl) => {
                bail!("{field}: TTL must be between 1 and 604800");
            }
            _ => {}
        }
        if let Some(proxied) = record.proxied {
            if spec.kind != DnsProviderType::Cloudflare {
                bail!("{field}: proxied is only supported by Cloudflare");
            }
            if proxied && record.record_type == RecordType::Txt {
                bail!("{field}: TXT records cannot be proxied");
            }
            if proxied && record.ttl != 1 {
                bail!("{field}: proxied records must use ttl = 1");
            }
        }
        if !keys.insert((spec.name.clone(), name.clone(), record.record_type)) {
            bail!("{field}: duplicate record");
        }
        if !absent {
            present_types
                .entry((spec.name.clone(), name.clone()))
                .or_default()
                .push(record.record_type);
        }
        records.push(DesiredRecord {
            provider: spec.name.clone(),
            set: RecordSet {
                name,
                record_type: record.record_type,
                ttl: record.ttl,
                values,
                proxied: record.proxied,
            },
            import: record.import,
            absent,
        });
    }
    for ((_, name), types) in present_types {
        if types.contains(&RecordType::Cname) && types.len() > 1 {
            bail!("dns.records: {name} has a CNAME and other record types");
        }
    }

    Ok(CompiledDns {
        allowed_zones,
        providers,
        records,
    })
}

/// Management state for one provider, persisted to `<state_dir>/<provider>.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderState {
    /// Fencing generation of the last writer
    #[serde(default)]
    pub writer_generation: u64,
    #[serde(default)]
    pub records: BTreeMap<String, ManagedRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManagedRecord {
    pub name: String,
    pub record_type: RecordType,
    /// What Sieve Tube last applied (what the provider should report)
    pub applied: Option<RecordSet>,
    /// The value before the last change, kept for rollback
    pub previous: Option<RecordSet>,
    /// Writer generation of the last change
    pub generation: u64,
    /// A change that was started but not confirmed
    pub pending: Option<PendingChange>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingChange {
    pub expected: Option<RecordSet>,
    pub desired: Option<RecordSet>,
    pub ticket: Option<ChangeTicket>,
    pub started_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    NoChange,
    /// Conditionally change `expected` into `desired` (create, update or delete)
    Apply {
        expected: Option<RecordSet>,
        desired: Option<RecordSet>,
    },
    /// Start managing an existing record that already has the desired data
    Adopt {
        current: RecordSet,
    },
    /// The managed record is gone as requested; drop it from the state
    Forget,
    Wait {
        reason: String,
    },
    Conflict {
        reason: String,
    },
}

impl Action {
    pub fn label(&self) -> &'static str {
        match self {
            Action::NoChange => "in_sync",
            Action::Apply { .. } => "change",
            Action::Adopt { .. } => "adopt",
            Action::Forget => "forget",
            Action::Wait { .. } => "pending",
            Action::Conflict { .. } => "conflict",
        }
    }

    /// Human-readable summary without secrets (used for dry-run output).
    pub fn describe(&self) -> String {
        let show = |set: &Option<RecordSet>| match set {
            Some(set) => format!(
                "ttl={} values={:?}{}",
                set.ttl,
                set.values,
                set.proxied
                    .map(|p| format!(" proxied={p}"))
                    .unwrap_or_default()
            ),
            None => "(none)".to_string(),
        };
        match self {
            Action::NoChange => "in sync".to_string(),
            Action::Apply {
                expected: None,
                desired,
            } => format!("create {}", show(desired)),
            Action::Apply {
                expected,
                desired: None,
            } => format!("delete {}", show(expected)),
            Action::Apply { expected, desired } => {
                format!("update {} -> {}", show(expected), show(desired))
            }
            Action::Adopt { current } => format!("adopt existing {}", show(&Some(current.clone()))),
            Action::Forget => "already deleted; forget".to_string(),
            Action::Wait { reason } => format!("wait: {reason}"),
            Action::Conflict { reason } => format!("conflict: {reason}"),
        }
    }
}

/// Keep the provider's proxy setting when the configuration does not specify one.
fn with_current_proxied(desired: &RecordSet, current: Option<&RecordSet>) -> RecordSet {
    let mut target = desired.clone();
    if target.proxied.is_none() {
        target.proxied = current.and_then(|c| c.proxied);
    }
    target
}

/// Whether `actual` could be an intermediate state of a change from `from` to `to`.
fn is_between(
    actual: Option<&RecordSet>,
    from: Option<&RecordSet>,
    to: Option<&RecordSet>,
) -> bool {
    fn values<'a>(
        set: Option<&'a RecordSet>,
        empty: &'a std::collections::BTreeSet<String>,
    ) -> &'a std::collections::BTreeSet<String> {
        set.map(|s| &s.values).unwrap_or(empty)
    }
    let empty = std::collections::BTreeSet::new();
    let (actual_values, from_values, to_values) = (
        values(actual, &empty),
        values(from, &empty),
        values(to, &empty),
    );
    let union: std::collections::BTreeSet<_> = from_values.union(to_values).collect();
    let within = actual_values.iter().all(|v| union.contains(v));
    let keeps_common = from_values
        .intersection(to_values)
        .all(|v| actual_values.contains(v));
    let ttl_ok = actual
        .is_none_or(|a| from.is_some_and(|f| f.ttl == a.ttl) || to.is_some_and(|t| t.ttl == a.ttl));
    within && keeps_common && ttl_ok
}

/// Decide what to do for one desired record.
pub fn decide(
    desired: &DesiredRecord,
    observed: Option<&Observed>,
    managed: Option<&ManagedRecord>,
    now: i64,
    settle_secs: i64,
) -> Action {
    if let Some(reason) = observed.and_then(|o| o.unsupported.as_ref()) {
        return Action::Conflict {
            reason: format!("provider record cannot be managed: {reason}"),
        };
    }
    let actual = observed.map(|o| &o.set);
    // The provider already has what the configuration asks for.
    let reached = if desired.absent {
        actual.is_none()
    } else {
        actual.is_some_and(|a| a.same_data(&with_current_proxied(&desired.set, Some(a))))
    };

    match managed {
        Some(_) if reached => {}
        Some(record) => match &record.pending {
            Some(pending) => {
                if !is_between(actual, pending.expected.as_ref(), pending.desired.as_ref()) {
                    if now - pending.started_at < settle_secs {
                        return Action::Wait {
                            reason: "waiting for the provider to reflect the last change"
                                .to_string(),
                        };
                    }
                    return Action::Conflict {
                        reason: "record changed outside Sieve Tube during an unfinished change"
                            .to_string(),
                    };
                }
            }
            None => {
                if !same_optional(actual, record.applied.as_ref()) {
                    if now - record.updated_at < settle_secs {
                        return Action::Wait {
                            reason: "waiting for the provider to reflect the last change"
                                .to_string(),
                        };
                    }
                    return Action::Conflict {
                        reason: "record was changed outside Sieve Tube".to_string(),
                    };
                }
            }
        },
        None => {
            if let Some(current) = actual {
                if desired.absent {
                    return Action::Conflict {
                        reason: "record is not managed by Sieve Tube; refusing to delete it"
                            .to_string(),
                    };
                }
                if !desired.import {
                    return Action::Conflict {
                        reason:
                            "an unmanaged record already exists; set import = true to take it over"
                                .to_string(),
                    };
                }
                let target = with_current_proxied(&desired.set, Some(current));
                return if current.same_data(&target) {
                    Action::Adopt {
                        current: current.clone(),
                    }
                } else {
                    Action::Apply {
                        expected: Some(current.clone()),
                        desired: Some(target),
                    }
                };
            }
        }
    }

    match (actual, desired.absent) {
        (None, true) if managed.is_some() => Action::Forget,
        (None, true) => Action::NoChange,
        (Some(current), true) => Action::Apply {
            expected: Some(current.clone()),
            desired: None,
        },
        (None, false) => Action::Apply {
            expected: None,
            desired: Some(desired.set.clone()),
        },
        (Some(current), false) => {
            let target = with_current_proxied(&desired.set, Some(current));
            if current.same_data(&target) {
                Action::NoChange
            } else {
                Action::Apply {
                    expected: Some(current.clone()),
                    desired: Some(target),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsProviderConfig, DnsRecordConfig};

    const NOW: i64 = 1_800_000_000;

    fn set(values: &[&str], ttl: u32) -> RecordSet {
        RecordSet {
            name: "www.example.com".into(),
            record_type: RecordType::A,
            ttl,
            values: values.iter().map(|v| v.to_string()).collect(),
            proxied: None,
        }
    }

    fn desired(values: &[&str]) -> DesiredRecord {
        DesiredRecord {
            provider: "cf".into(),
            set: set(values, 300),
            import: false,
            absent: false,
        }
    }

    fn observed(set: RecordSet) -> Observed {
        Observed {
            set,
            unsupported: None,
        }
    }

    fn managed(applied: Option<RecordSet>) -> ManagedRecord {
        ManagedRecord {
            name: "www.example.com".into(),
            record_type: RecordType::A,
            applied,
            previous: None,
            generation: 1,
            pending: None,
            updated_at: NOW - 3600,
        }
    }

    #[test]
    fn creates_updates_and_stays_idempotent() {
        let want = desired(&["192.0.2.1"]);
        assert_eq!(
            decide(&want, None, None, NOW, 30),
            Action::Apply {
                expected: None,
                desired: Some(set(&["192.0.2.1"], 300))
            }
        );

        let applied = set(&["192.0.2.1"], 300);
        let state = managed(Some(applied.clone()));
        assert_eq!(
            decide(
                &want,
                Some(&observed(applied.clone())),
                Some(&state),
                NOW,
                30
            ),
            Action::NoChange
        );

        let changed = desired(&["192.0.2.2"]);
        assert_eq!(
            decide(
                &changed,
                Some(&observed(applied.clone())),
                Some(&state),
                NOW,
                30
            ),
            Action::Apply {
                expected: Some(applied),
                desired: Some(set(&["192.0.2.2"], 300))
            }
        );
    }

    #[test]
    fn unmanaged_records_are_never_overwritten_or_deleted_without_import() {
        let existing = observed(set(&["198.51.100.1"], 300));
        assert!(matches!(
            decide(&desired(&["192.0.2.1"]), Some(&existing), None, NOW, 30),
            Action::Conflict { .. }
        ));

        let mut delete = desired(&[]);
        delete.absent = true;
        delete.import = true;
        assert!(matches!(
            decide(&delete, Some(&existing), None, NOW, 30),
            Action::Conflict { .. }
        ));

        let mut import = desired(&["198.51.100.1"]);
        import.import = true;
        assert_eq!(
            decide(&import, Some(&existing), None, NOW, 30),
            Action::Adopt {
                current: existing.set.clone()
            }
        );
    }

    #[test]
    fn import_keeps_proxy_setting() {
        let mut current = set(&["198.51.100.1"], 1);
        current.proxied = Some(true);
        let mut import = desired(&["192.0.2.1"]);
        import.import = true;
        import.set.ttl = 1;
        match decide(&import, Some(&observed(current)), None, NOW, 30) {
            Action::Apply {
                desired: Some(target),
                ..
            } => assert_eq!(target.proxied, Some(true)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn external_changes_stop_management_after_settle_window() {
        let applied = set(&["192.0.2.1"], 300);
        let mut state = managed(Some(applied));
        let tampered = observed(set(&["203.0.113.9"], 300));
        assert!(matches!(
            decide(
                &desired(&["192.0.2.1"]),
                Some(&tampered),
                Some(&state),
                NOW,
                30
            ),
            Action::Conflict { .. }
        ));
        // Deleted externally is also a conflict, not a silent re-create.
        assert!(matches!(
            decide(&desired(&["192.0.2.1"]), None, Some(&state), NOW, 30),
            Action::Conflict { .. }
        ));

        state.updated_at = NOW - 5;
        assert!(matches!(
            decide(
                &desired(&["192.0.2.1"]),
                Some(&tampered),
                Some(&state),
                NOW,
                30
            ),
            Action::Wait { .. }
        ));
    }

    #[test]
    fn deletion_requires_explicit_absent_and_matching_value() {
        let applied = set(&["192.0.2.1"], 300);
        let state = managed(Some(applied.clone()));
        let mut absent = desired(&[]);
        absent.absent = true;
        assert_eq!(
            decide(
                &absent,
                Some(&observed(applied.clone())),
                Some(&state),
                NOW,
                30
            ),
            Action::Apply {
                expected: Some(applied),
                desired: None
            }
        );
        assert_eq!(decide(&absent, None, Some(&state), NOW, 30), Action::Forget);
    }

    #[test]
    fn interrupted_change_resumes_from_intermediate_state() {
        let from = set(&["192.0.2.1", "192.0.2.2"], 300);
        let to = set(&["192.0.2.2", "192.0.2.3"], 300);
        let mut state = managed(Some(from.clone()));
        state.pending = Some(PendingChange {
            expected: Some(from),
            desired: Some(to.clone()),
            ticket: None,
            started_at: NOW - 3600,
        });

        // Half applied: the new value was added, the old one not yet removed.
        let partial = set(&["192.0.2.1", "192.0.2.2", "192.0.2.3"], 300);
        let want = DesiredRecord {
            set: to.clone(),
            ..desired(&[])
        };
        assert_eq!(
            decide(
                &want,
                Some(&observed(partial.clone())),
                Some(&state),
                NOW,
                30
            ),
            Action::Apply {
                expected: Some(partial),
                desired: Some(to)
            }
        );

        // Something unrelated to the change is a conflict.
        let foreign = set(&["198.51.100.7"], 300);
        assert!(matches!(
            decide(&want, Some(&observed(foreign)), Some(&state), NOW, 30),
            Action::Conflict { .. }
        ));
    }

    #[test]
    fn unsupported_provider_configuration_is_a_conflict() {
        let o = Observed {
            set: set(&["192.0.2.1"], 300),
            unsupported: Some("alias record".into()),
        };
        let mut import = desired(&["192.0.2.1"]);
        import.import = true;
        assert!(matches!(
            decide(&import, Some(&o), None, NOW, 30),
            Action::Conflict { .. }
        ));
    }

    fn provider(name: &str, kind: DnsProviderType, zone: &str) -> DnsProviderConfig {
        DnsProviderConfig {
            name: name.into(),
            kind,
            zone: zone.into(),
            zone_id: (kind == DnsProviderType::Cloudflare).then(|| "zone123".into()),
            api_token_env: (kind == DnsProviderType::Cloudflare).then(|| "CF_TOKEN".into()),
            api_token_file: None,
            api_base_url: None,
            hosted_zone_id: (kind == DnsProviderType::Route53).then(|| "Z123".into()),
            endpoint_url: None,
            region: None,
            request_timeout_secs: 10,
        }
    }

    fn record(
        provider: &str,
        name: &str,
        record_type: RecordType,
        values: &[&str],
    ) -> DnsRecordConfig {
        DnsRecordConfig {
            provider: provider.into(),
            name: name.into(),
            record_type,
            values: values.iter().map(|v| v.to_string()).collect(),
            ttl: 300,
            proxied: None,
            import: false,
            state: RecordState::Present,
        }
    }

    fn config(records: Vec<DnsRecordConfig>) -> DnsConfig {
        DnsConfig {
            enabled: true,
            allowed_zones: vec!["example.com".into(), "example.org".into()],
            providers: vec![
                provider("cf", DnsProviderType::Cloudflare, "example.com"),
                provider("r53", DnsProviderType::Route53, "example.org"),
            ],
            records,
            ..DnsConfig::default()
        }
    }

    #[test]
    fn compiles_both_providers_in_one_process() {
        let compiled = compile(&config(vec![
            record(
                "cf",
                "WWW.example.com.",
                RecordType::A,
                &["192.0.2.1", "192.0.2.1"],
            ),
            record("r53", "api.example.org", RecordType::Aaaa, &["2001:db8::1"]),
        ]))
        .unwrap();
        assert_eq!(compiled.providers.len(), 2);
        assert_eq!(compiled.records[0].set.name, "www.example.com");
        assert_eq!(compiled.records[0].set.values.len(), 1);
    }

    #[test]
    fn rejects_invalid_record_configurations() {
        let cases = vec![
            vec![record("cf", "www.other.net", RecordType::A, &["192.0.2.1"])],
            vec![record(
                "nope",
                "www.example.com",
                RecordType::A,
                &["192.0.2.1"],
            )],
            vec![record(
                "cf",
                "www.example.com",
                RecordType::A,
                &["not-an-ip"],
            )],
            vec![record("cf", "www.example.com", RecordType::A, &[])],
            vec![record(
                "cf",
                "x.example.com",
                RecordType::Cname,
                &["a.example.net", "b.example.net"],
            )],
            vec![record(
                "r53",
                "example.org",
                RecordType::Cname,
                &["a.example.net"],
            )],
            vec![
                record("cf", "x.example.com", RecordType::Cname, &["a.example.net"]),
                record("cf", "x.example.com", RecordType::Txt, &["hello"]),
            ],
            vec![
                record("cf", "www.example.com", RecordType::A, &["192.0.2.1"]),
                record("cf", "WWW.example.com", RecordType::A, &["192.0.2.2"]),
            ],
            vec![record(
                "cf",
                "_acme-challenge.example.com",
                RecordType::Txt,
                &["x"],
            )],
            vec![DnsRecordConfig {
                proxied: Some(true),
                ..record("r53", "www.example.org", RecordType::A, &["192.0.2.1"])
            }],
            vec![DnsRecordConfig {
                proxied: Some(true),
                ..record("cf", "www.example.com", RecordType::A, &["192.0.2.1"])
            }],
            vec![DnsRecordConfig {
                ttl: 30,
                ..record("cf", "www.example.com", RecordType::A, &["192.0.2.1"])
            }],
        ];
        for records in cases {
            let description = format!(
                "{:?}",
                records
                    .iter()
                    .map(|r| (&r.provider, &r.name, r.record_type))
                    .collect::<Vec<_>>()
            );
            assert!(
                compile(&config(records)).is_err(),
                "should reject {description}"
            );
        }

        let mut outside = config(vec![]);
        outside.providers[0].zone = "example.net".into();
        assert!(
            compile(&outside).is_err(),
            "provider zone outside allowed zones"
        );

        let mut both_tokens = config(vec![]);
        both_tokens.providers[0].api_token_file = Some("/run/secrets/cf".into());
        assert!(compile(&both_tokens).is_err());

        let mut no_allowed = config(vec![]);
        no_allowed.allowed_zones.clear();
        assert!(compile(&no_allowed).is_err());
    }
}

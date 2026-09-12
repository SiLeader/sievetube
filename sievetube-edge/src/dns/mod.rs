//! DNS record management through provider APIs.
//!
//! Authoritative DNS stays with the provider. Sieve Tube only manages records an
//! administrator lists explicitly, never deletes records merely because they left
//! the configuration, and stops on any sign of an external change.

pub mod cloudflare;
#[cfg(test)]
pub(crate) mod contract_tests;
#[cfg(test)]
pub mod memory;
pub mod plan;
pub mod reconciler;
pub mod route53;
pub mod txt;

/// Test hook called with (name, type, all current values) after a mock API change.
#[cfg(test)]
pub(crate) type ChangeObserver = Arc<dyn Fn(&str, &str, Vec<String>) + Send + Sync>;

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use sievetube_common::hostname;

use crate::config::DnsProviderType;

/// Construct provider clients for a validated configuration.
pub async fn build_providers(
    compiled: &plan::CompiledDns,
) -> anyhow::Result<HashMap<String, Arc<Provider>>> {
    let mut providers = HashMap::new();
    for spec in &compiled.providers {
        let cfg = &spec.config;
        let timeout = Duration::from_secs(cfg.request_timeout_secs);
        let provider = match spec.kind {
            DnsProviderType::Cloudflare => {
                let token = cloudflare::load_token(
                    cfg.api_token_env.as_deref(),
                    cfg.api_token_file.as_deref(),
                )
                .map_err(|e| anyhow!("dns provider {}: {e}", spec.name))?;
                Provider::Cloudflare(Box::new(cloudflare::CloudflareProvider::new(
                    cfg.zone_id.clone().unwrap_or_default(),
                    cfg.api_base_url.clone(),
                    token,
                    timeout,
                )?))
            }
            DnsProviderType::Route53 => Provider::Route53(Box::new(
                route53::Route53Provider::new(
                    cfg.hosted_zone_id.clone().unwrap_or_default(),
                    cfg.endpoint_url.clone(),
                    cfg.region.clone(),
                    timeout,
                )
                .await,
            )),
        };
        providers.insert(spec.name.clone(), Arc::new(provider));
    }
    Ok(providers)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecordType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "CNAME")]
    Cname,
    #[serde(rename = "TXT")]
    Txt,
}

impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Cname => "CNAME",
            RecordType::Txt => "TXT",
        }
    }

    /// Canonical form of a record value, used for comparisons.
    pub fn normalize_value(self, value: &str) -> Result<String, String> {
        let value = value.trim();
        match self {
            RecordType::A => value
                .parse::<Ipv4Addr>()
                .map(|ip| ip.to_string())
                .map_err(|_| format!("invalid IPv4 address {value:?}")),
            RecordType::Aaaa => value
                .parse::<Ipv6Addr>()
                .map(|ip| ip.to_string())
                .map_err(|_| format!("invalid IPv6 address {value:?}")),
            RecordType::Cname => hostname::normalize_dns_name(value)
                .map_err(|e| format!("invalid CNAME target {value:?}: {e}")),
            RecordType::Txt => {
                let text = unquote_txt(value);
                if text.len() > 4000 || text.chars().any(|c| c.is_control()) {
                    return Err("TXT value must be printable and at most 4000 bytes".to_string());
                }
                Ok(text)
            }
        }
    }
}

/// Decode a TXT value that may be written as one or more quoted strings
/// (`"abc" "def"` → `abcdef`). Unquoted values are returned unchanged.
pub fn unquote_txt(raw: &str) -> String {
    let raw = raw.trim();
    if !raw.starts_with('"') {
        return raw.to_string();
    }
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        out.push(escaped);
                    }
                }
                '"' => break,
                other => out.push(other),
            }
        }
    }
    out
}

/// Encode a TXT value as quoted character strings of at most 255 bytes each.
pub fn quote_txt(value: &str) -> String {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for c in value.chars() {
        if current.len() + c.len_utf8() > 255 {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(c);
    }
    if !current.is_empty() || chunks.is_empty() {
        chunks.push(current);
    }
    chunks
        .iter()
        .map(|chunk| format!("\"{}\"", chunk.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// All values for one (name, type), normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSet {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub values: BTreeSet<String>,
    /// Cloudflare proxy flag; `None` means "not specified"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
}

impl RecordSet {
    /// Same DNS data. `proxied` is compared only when both sides specify it.
    pub fn same_data(&self, other: &RecordSet) -> bool {
        self.name == other.name
            && self.record_type == other.record_type
            && self.ttl == other.ttl
            && self.values == other.values
            && match (self.proxied, other.proxied) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

pub fn same_optional(a: Option<&RecordSet>, b: Option<&RecordSet>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.same_data(b),
        _ => false,
    }
}

/// A record set as read from a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub set: RecordSet,
    /// Set when the provider-side configuration cannot be managed (e.g. alias records)
    pub unsupported: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("rate limited by provider")]
    RateLimited { retry_after: Option<Duration> },
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("provider request timed out")]
    Timeout,
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("provider error: {0}")]
    Provider(String),
}

impl DnsError {
    pub fn label(&self) -> &'static str {
        match self {
            DnsError::Conflict(_) => "conflict",
            DnsError::RateLimited { .. } => "rate_limited",
            DnsError::Auth(_) => "auth",
            DnsError::Timeout => "timeout",
            DnsError::Unsupported(_) => "unsupported",
            DnsError::Provider(_) => "provider",
        }
    }
}

/// Identifies a submitted change whose propagation inside the provider can be tracked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChangeTicket {
    /// Applied synchronously (Cloudflare)
    Immediate,
    /// Route 53 change id, pending until INSYNC
    Route53 { change_id: String },
}

pub enum Provider {
    Cloudflare(Box<cloudflare::CloudflareProvider>),
    Route53(Box<route53::Route53Provider>),
    #[cfg(test)]
    Memory(memory::MemoryProvider),
}

impl Provider {
    pub fn kind(&self) -> &'static str {
        match self {
            Provider::Cloudflare(_) => "cloudflare",
            Provider::Route53(_) => "route53",
            #[cfg(test)]
            Provider::Memory(_) => "memory",
        }
    }

    pub async fn get(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Option<Observed>, DnsError> {
        match self {
            Provider::Cloudflare(p) => p.get(name, record_type).await,
            Provider::Route53(p) => p.get(name, record_type).await,
            #[cfg(test)]
            Provider::Memory(p) => p.get(name, record_type),
        }
    }

    /// Conditionally replace the record set: fails with [`DnsError::Conflict`] when the
    /// provider's current state differs from `expected` (`None` = must not exist).
    /// `desired = None` deletes the set.
    pub async fn replace(
        &self,
        name: &str,
        record_type: RecordType,
        expected: Option<&RecordSet>,
        desired: Option<&RecordSet>,
    ) -> Result<ChangeTicket, DnsError> {
        match self {
            Provider::Cloudflare(p) => p.replace(name, record_type, expected, desired).await,
            Provider::Route53(p) => p.replace(name, record_type, expected, desired).await,
            #[cfg(test)]
            Provider::Memory(p) => p.replace(name, record_type, expected, desired),
        }
    }

    /// Whether a submitted change is applied inside the provider. This does not mean
    /// recursive resolvers have picked it up.
    pub async fn change_synced(&self, ticket: &ChangeTicket) -> Result<bool, DnsError> {
        match (self, ticket) {
            (_, ChangeTicket::Immediate) => Ok(true),
            (Provider::Route53(p), ChangeTicket::Route53 { change_id }) => {
                p.change_synced(change_id).await
            }
            #[cfg(test)]
            (Provider::Memory(p), ChangeTicket::Route53 { change_id }) => {
                Ok(p.change_synced(change_id))
            }
            (_, ChangeTicket::Route53 { .. }) => Err(DnsError::Unsupported(
                "change ticket does not belong to this provider".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_values() {
        assert_eq!(
            RecordType::A.normalize_value(" 192.0.2.1 ").unwrap(),
            "192.0.2.1"
        );
        assert_eq!(
            RecordType::Aaaa.normalize_value("2001:DB8:0::1").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(
            RecordType::Cname
                .normalize_value("Edge.Example.com.")
                .unwrap(),
            "edge.example.com"
        );
        assert_eq!(
            RecordType::Txt
                .normalize_value("\"v=spf1\" \" -all\"")
                .unwrap(),
            "v=spf1 -all"
        );
        assert!(RecordType::A.normalize_value("2001:db8::1").is_err());
        assert!(RecordType::Txt.normalize_value("a\nb").is_err());
    }

    #[test]
    fn txt_quoting_round_trips() {
        let long = "x".repeat(600);
        let quoted = quote_txt(&long);
        assert_eq!(quoted.matches('"').count(), 6);
        assert_eq!(unquote_txt(&quoted), long);
        assert_eq!(
            unquote_txt(&quote_txt(r#"say "hi" \o/"#)),
            r#"say "hi" \o/"#
        );
        assert_eq!(quote_txt(""), "\"\"");
    }

    #[test]
    fn proxied_is_compared_only_when_specified() {
        let mut a = RecordSet {
            name: "www.example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            values: ["192.0.2.1".to_string()].into(),
            proxied: None,
        };
        let mut b = a.clone();
        b.proxied = Some(true);
        assert!(a.same_data(&b));
        a.proxied = Some(false);
        assert!(!a.same_data(&b));
    }
}

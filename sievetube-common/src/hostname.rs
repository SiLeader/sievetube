//! Hostname normalization shared by routing, ownership checks, TLS and DNS.
//!
//! Every hostname that is used as a lookup key (registry, Valkey, certificate
//! store, policy) must go through [`normalize_hostname`] first so that
//! `Web.Example.com.` and `web.example.com` resolve to the same entry.

use std::fmt;

const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameError(String);

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostnameError {}

fn err(msg: impl Into<String>) -> HostnameError {
    HostnameError(msg.into())
}

/// Normalize a hostname: trim, drop one trailing dot, ASCII-lowercase and
/// validate the label syntax. Non-ASCII names must be supplied as punycode.
pub fn normalize_hostname(input: &str) -> Result<String, HostnameError> {
    normalize(input, false, false)
}

/// Like [`normalize_hostname`] but additionally accepts a single leading `*`
/// label (e.g. `*.example.com`).
pub fn normalize_hostname_pattern(input: &str) -> Result<String, HostnameError> {
    normalize(input, true, false)
}

/// DNS owner names may contain underscores (e.g. `_acme-challenge.example.com`).
pub fn normalize_dns_name(input: &str) -> Result<String, HostnameError> {
    normalize(input, true, true)
}

fn normalize(
    input: &str,
    allow_wildcard: bool,
    allow_underscore: bool,
) -> Result<String, HostnameError> {
    let trimmed = input.trim();
    let name = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if name.is_empty() {
        return Err(err("empty hostname"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(err(format!("hostname longer than {MAX_NAME_LEN} bytes")));
    }
    if !name.is_ascii() {
        return Err(err("hostname must be ASCII (use punycode for IDN)"));
    }
    let lower = name.to_ascii_lowercase();
    let label_count = lower.split('.').count();
    for (index, label) in lower.split('.').enumerate() {
        if label.is_empty() {
            return Err(err(format!("empty label in {lower:?}")));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(err(format!("label longer than {MAX_LABEL_LEN} bytes")));
        }
        if label == "*" {
            if allow_wildcard && index == 0 && label_count > 1 {
                continue;
            }
            return Err(err(format!("wildcard not allowed in {lower:?}")));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(err(format!("label {label:?} starts or ends with '-'")));
        }
        let valid = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || (allow_underscore && b == b'_'));
        if !valid {
            return Err(err(format!("invalid character in label {label:?}")));
        }
    }
    Ok(lower)
}

/// Split an HTTP authority (`host`, `host:port`, `[v6]:port`) into its host and
/// optional port. User information (`user@host`) is rejected.
pub fn split_authority(authority: &str) -> Result<(&str, Option<u16>), HostnameError> {
    if authority.contains('@') {
        return Err(err("userinfo is not allowed in authority"));
    }
    let parse_port = |port: &str| -> Result<Option<u16>, HostnameError> {
        if port.is_empty() {
            return Ok(None);
        }
        port.parse::<u16>()
            .map(Some)
            .map_err(|_| err(format!("invalid port {port:?}")))
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| err("unterminated IPv6 literal"))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(port) => parse_port(port)?,
            None if after.is_empty() => None,
            None => return Err(err("unexpected data after IPv6 literal")),
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, _)) if host.contains(':') => Err(err("IPv6 literal must be bracketed")),
        Some((host, port)) => Ok((host, parse_port(port)?)),
        None => Ok((authority, None)),
    }
}

/// Whether a normalized `hostname` is covered by a normalized `pattern`
/// (exact match, or a single-label `*.` wildcard).
pub fn matches_pattern(pattern: &str, hostname: &str) -> bool {
    if pattern == hostname {
        return true;
    }
    match (pattern.strip_prefix("*."), hostname.split_once('.')) {
        (Some(suffix), Some((first, rest))) => !first.is_empty() && first != "*" && rest == suffix,
        _ => false,
    }
}

/// The wildcard pattern that would cover `hostname` (`a.example.com` → `*.example.com`).
pub fn wildcard_for(hostname: &str) -> Option<String> {
    let (_, rest) = hostname.split_once('.')?;
    if rest.contains('.') {
        Some(format!("*.{rest}"))
    } else {
        None
    }
}

/// Whether a normalized `name` equals `zone` or is inside it.
pub fn is_within_zone(name: &str, zone: &str) -> bool {
    let name = name.strip_prefix("*.").unwrap_or(name);
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(
            normalize_hostname("Web.Example.COM.").unwrap(),
            "web.example.com"
        );
        assert_eq!(
            normalize_hostname("  api.example.com ").unwrap(),
            "api.example.com"
        );
    }

    #[test]
    fn rejects_invalid_hostnames() {
        for bad in [
            "", ".", "a..b", "-a.com", "a-.com", "a_b.com", "*.a.com", "ü.com", "a b.com",
        ] {
            assert!(
                normalize_hostname(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(normalize_hostname(&"a".repeat(64)).is_err());
    }

    #[test]
    fn wildcard_patterns() {
        assert_eq!(
            normalize_hostname_pattern("*.Example.com").unwrap(),
            "*.example.com"
        );
        assert!(normalize_hostname_pattern("*").is_err());
        assert!(normalize_hostname_pattern("a.*.com").is_err());
        assert!(matches_pattern("*.example.com", "a.example.com"));
        assert!(!matches_pattern("*.example.com", "a.b.example.com"));
        assert!(!matches_pattern("*.example.com", "example.com"));
        assert_eq!(
            wildcard_for("a.example.com").as_deref(),
            Some("*.example.com")
        );
        assert_eq!(wildcard_for("example.com"), None);
    }

    #[test]
    fn dns_names_allow_underscore() {
        assert_eq!(
            normalize_dns_name("_acme-challenge.Example.com").unwrap(),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn splits_authority() {
        assert_eq!(
            split_authority("example.com").unwrap(),
            ("example.com", None)
        );
        assert_eq!(
            split_authority("example.com:8080").unwrap(),
            ("example.com", Some(8080))
        );
        assert_eq!(split_authority("[::1]:443").unwrap(), ("::1", Some(443)));
        assert_eq!(
            split_authority("example.com:").unwrap(),
            ("example.com", None)
        );
        assert!(split_authority("user@example.com").is_err());
        assert!(split_authority("::1").is_err());
        assert!(split_authority("example.com:99999").is_err());
    }

    #[test]
    fn zone_membership() {
        assert!(is_within_zone("example.com", "example.com"));
        assert!(is_within_zone("a.example.com", "example.com"));
        assert!(is_within_zone("*.example.com", "example.com"));
        assert!(!is_within_zone("badexample.com", "example.com"));
    }
}

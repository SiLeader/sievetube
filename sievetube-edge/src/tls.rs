use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;

use sievetube_common::hostname;

use crate::certificate_store::{parse_and_validate, CertEntry, CertSource};

/// SNI-based certificate resolver for public HTTPS.
///
/// Holds BYOC certificates loaded from `cert_dir` and managed (ACME) certificates
/// installed by the certificate manager. Each name has exactly one source; a
/// BYOC file for a managed name is rejected instead of overriding it.
pub struct CertResolver {
    entries: ArcSwap<HashMap<String, Arc<CertEntry>>>,
    managed: ArcSwap<HashSet<String>>,
    write_lock: Mutex<()>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = self.entries.load();
        f.debug_struct("CertResolver")
            .field("names", &map.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Outcome of a BYOC directory scan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    pub loaded: usize,
    pub unchanged: usize,
    pub kept_previous: usize,
    pub failed: usize,
    pub removed: usize,
}

impl ReloadReport {
    pub fn changed(&self) -> bool {
        self.loaded > 0 || self.removed > 0
    }
}

impl CertResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(CertResolver {
            entries: ArcSwap::from_pointee(HashMap::new()),
            managed: ArcSwap::from_pointee(HashSet::new()),
            write_lock: Mutex::new(()),
        })
    }

    /// Declare the names whose certificates are managed automatically.
    pub fn set_managed_names(&self, names: HashSet<String>) {
        self.managed.store(Arc::new(names));
    }

    /// Re-read `<name>.crt` / `<name>.key` pairs. A pair that fails validation keeps
    /// the previously loaded certificate for that name; other names are updated
    /// independently. An unreadable directory keeps all current BYOC certificates.
    pub fn reload_byoc(&self, cert_dir: &Path, now: i64) -> ReloadReport {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut report = ReloadReport::default();
        let current = self.entries.load_full();
        let managed = self.managed.load();

        let files = match list_cert_pairs(cert_dir) {
            Ok(files) => files,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound
                    || current.values().any(|c| c.source == CertSource::Byoc)
                {
                    tracing::warn!(
                        cert_dir = %cert_dir.display(),
                        error = %e,
                        "cannot read cert_dir; keeping loaded certificates"
                    );
                    report.failed += 1;
                }
                return report;
            }
        };

        let mut next: HashMap<String, Arc<CertEntry>> = current
            .iter()
            .filter(|(_, e)| e.source != CertSource::Byoc)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut seen = HashSet::new();

        for (stem, cert_path, key_path) in files {
            let name = match hostname::normalize_hostname_pattern(&stem) {
                Ok(name) => name,
                Err(e) => {
                    tracing::warn!(file = %cert_path.display(), error = %e, "invalid certificate file name");
                    report.failed += 1;
                    continue;
                }
            };
            seen.insert(name.clone());
            if managed.contains(&name) {
                tracing::error!(
                    name,
                    "BYOC certificate conflicts with a managed certificate name; ignoring file"
                );
                report.failed += 1;
                continue;
            }
            let previous = current
                .get(&name)
                .filter(|e| e.source == CertSource::Byoc)
                .cloned();

            let loaded = std::fs::read(&cert_path)
                .and_then(|cert| std::fs::read(&key_path).map(|key| (cert, key)))
                .map_err(anyhow::Error::from)
                .and_then(|(cert, key)| {
                    parse_and_validate(&cert, &key, &name, CertSource::Byoc, now)
                });

            match loaded {
                Ok(entry) => match previous {
                    Some(prev) if prev.fingerprint == entry.fingerprint => {
                        report.unchanged += 1;
                        next.insert(name, prev);
                    }
                    _ => {
                        tracing::info!(name, not_after = entry.not_after, "loaded TLS certificate");
                        report.loaded += 1;
                        next.insert(name, Arc::new(entry));
                    }
                },
                Err(e) => {
                    report.failed += 1;
                    match previous {
                        Some(prev) => {
                            tracing::warn!(name, error = %e, "invalid certificate update; keeping previous certificate");
                            report.kept_previous += 1;
                            next.insert(name, prev);
                        }
                        None => {
                            tracing::warn!(name, error = %e, "failed to load certificate, skipping")
                        }
                    }
                }
            }
        }

        for (name, entry) in current.iter() {
            if entry.source == CertSource::Byoc && !seen.contains(name) {
                tracing::info!(name, "BYOC certificate removed");
                report.removed += 1;
            }
        }

        self.entries.store(Arc::new(next));
        report
    }

    /// Install or replace a managed certificate. Returns `true` if it changed.
    pub fn install(&self, entry: CertEntry) -> bool {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current = self.entries.load_full();
        if current
            .get(&entry.name)
            .is_some_and(|e| e.fingerprint == entry.fingerprint)
        {
            return false;
        }
        let mut next = (*current).clone();
        next.insert(entry.name.clone(), Arc::new(entry));
        self.entries.store(Arc::new(next));
        true
    }

    /// Exact-name lookup.
    pub fn get(&self, name: &str) -> Option<Arc<CertEntry>> {
        self.entries.load().get(name).cloned()
    }

    /// SNI lookup: exact name first, then a covering wildcard.
    pub fn lookup(&self, sni: &str) -> Option<Arc<CertEntry>> {
        let entries = self.entries.load();
        if let Some(entry) = entries.get(sni) {
            return Some(entry.clone());
        }
        hostname::wildcard_for(sni).and_then(|pattern| entries.get(&pattern).cloned())
    }

    pub fn entries(&self) -> Vec<Arc<CertEntry>> {
        self.entries.load().values().cloned().collect()
    }

    /// Reasons why HTTPS readiness is degraded (expired certificates).
    pub fn readiness_issues(&self, now: i64) -> Vec<String> {
        let mut issues: Vec<String> = self
            .entries
            .load()
            .values()
            .filter(|e| e.is_expired(now))
            .map(|e| format!("certificate for {} ({}) expired", e.name, e.source.as_str()))
            .collect();
        issues.sort();
        issues
    }
}

fn list_cert_pairs(cert_dir: &Path) -> std::io::Result<Vec<(String, PathBuf, PathBuf)>> {
    let mut pairs = Vec::new();
    for entry in std::fs::read_dir(cert_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("crt") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let key_path = path.with_extension("key");
        pairs.push((stem.to_string(), path.clone(), key_path));
    }
    pairs.sort();
    Ok(pairs)
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let name = hostname::normalize_hostname(sni).ok()?;
        self.lookup(&name).map(|e| e.certified_key.clone())
    }
}

/// Generate a self-signed certificate for the QUIC tunnel endpoint.
/// This cert is used for Connector→Edge QUIC connections, not for public HTTPS.
pub fn generate_self_signed(
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["sievetube-edge".to_string()])
        .map_err(|e| anyhow::anyhow!("rcgen error: {}", e))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.key_pair.serialize_der(),
    ));
    Ok((vec![cert_der], key_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_store::test_certs::generate;

    const NOW: i64 = 1_800_000_000;

    fn cert_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sievetube-byoc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_pair(dir: &Path, name: &str, not_after: i64) {
        let (cert, key) = generate(&[name], NOW - 10, not_after);
        std::fs::write(dir.join(format!("{name}.crt")), cert).unwrap();
        std::fs::write(dir.join(format!("{name}.key")), key).unwrap();
    }

    #[test]
    fn reload_updates_each_name_independently() {
        let dir = cert_dir();
        write_pair(&dir, "a.test", NOW + 100);
        write_pair(&dir, "b.test", NOW + 100);
        let resolver = CertResolver::new();
        let report = resolver.reload_byoc(&dir, NOW);
        assert_eq!(report.loaded, 2);
        let a_before = resolver.get("a.test").unwrap().fingerprint.clone();

        // Break a.test and renew b.test: a keeps the old cert, b is updated.
        std::fs::write(dir.join("a.test.key"), b"broken").unwrap();
        write_pair(&dir, "b.test", NOW + 500);
        let report = resolver.reload_byoc(&dir, NOW);
        assert_eq!(report.kept_previous, 1);
        assert_eq!(report.loaded, 1);
        assert_eq!(resolver.get("a.test").unwrap().fingerprint, a_before);
        assert_eq!(resolver.get("b.test").unwrap().not_after, NOW + 500);

        // Unchanged files are not reported as changes.
        std::fs::remove_file(dir.join("a.test.crt")).unwrap();
        std::fs::remove_file(dir.join("a.test.key")).unwrap();
        let report = resolver.reload_byoc(&dir, NOW);
        assert_eq!(report.removed, 1);
        assert_eq!(report.unchanged, 1);
        assert!(resolver.get("a.test").is_none());
    }

    #[test]
    fn missing_directory_keeps_certificates() {
        let dir = cert_dir();
        write_pair(&dir, "a.test", NOW + 100);
        let resolver = CertResolver::new();
        resolver.reload_byoc(&dir, NOW);
        std::fs::remove_dir_all(&dir).unwrap();
        resolver.reload_byoc(&dir, NOW);
        assert!(resolver.get("a.test").is_some());
    }

    #[test]
    fn managed_names_reject_byoc_and_wildcards_resolve() {
        let dir = cert_dir();
        write_pair(&dir, "a.test", NOW + 100);
        write_pair(&dir, "*.wild.test", NOW + 100);
        let resolver = CertResolver::new();
        resolver.set_managed_names(HashSet::from(["a.test".to_string()]));
        let report = resolver.reload_byoc(&dir, NOW);
        assert_eq!(report.failed, 1);
        assert!(resolver.get("a.test").is_none());
        assert_eq!(resolver.lookup("x.wild.test").unwrap().name, "*.wild.test");
        assert!(resolver.lookup("x.y.wild.test").is_none());
    }

    #[test]
    fn readiness_reports_expired_certificates() {
        let dir = cert_dir();
        write_pair(&dir, "a.test", NOW + 100);
        let resolver = CertResolver::new();
        resolver.reload_byoc(&dir, NOW);
        assert!(resolver.readiness_issues(NOW).is_empty());
        assert_eq!(resolver.readiness_issues(NOW + 200).len(), 1);
    }
}

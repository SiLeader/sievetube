//! Certificate validation and the on-disk generation store for managed certificates.
//!
//! Managed certificates are written to `<root>/<name>/gen-<N>/` and activated by
//! atomically replacing the `<root>/<name>/current` pointer, so a certificate and
//! its key are never observed half-updated and a failed update keeps the
//! previously active generation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use x509_parser::extensions::GeneralName;

use sievetube_common::hostname;

/// Tolerated clock skew when checking `notBefore`.
const NOT_BEFORE_LEEWAY_SECS: i64 = 300;
/// Number of generations kept on disk (including the active one).
const KEPT_GENERATIONS: usize = 3;
const CERT_FILE: &str = "fullchain.pem";
const KEY_FILE: &str = "privkey.pem";
const CURRENT_FILE: &str = "current";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSource {
    Byoc,
    Acme,
}

impl CertSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CertSource::Byoc => "byoc",
            CertSource::Acme => "acme",
        }
    }
}

/// A parsed and validated certificate chain with its signing key.
pub struct CertEntry {
    /// Hostname or wildcard pattern this entry serves
    pub name: String,
    pub source: CertSource,
    pub certified_key: Arc<CertifiedKey>,
    pub not_before: i64,
    pub not_after: i64,
    pub dns_names: Vec<String>,
    /// Hex SHA-256 of the leaf certificate
    pub fingerprint: String,
    pub generation: Option<u64>,
}

impl std::fmt::Debug for CertEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertEntry")
            .field("name", &self.name)
            .field("source", &self.source)
            .field("not_after", &self.not_after)
            .field("dns_names", &self.dns_names)
            .field("fingerprint", &self.fingerprint)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl CertEntry {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.not_after
    }

    pub fn remaining_secs(&self, now: i64) -> i64 {
        self.not_after - now
    }

    /// Total validity period in seconds.
    pub fn lifetime_secs(&self) -> i64 {
        (self.not_after - self.not_before).max(0)
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse a PEM chain and key and check that they form a usable certificate for `name`:
/// the key matches the leaf, the SANs cover the name and the certificate is valid at `now`.
pub fn parse_and_validate(
    cert_pem: &[u8],
    key_pem: &[u8],
    name: &str,
    source: CertSource,
    now: i64,
) -> anyhow::Result<CertEntry> {
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .context("failed to parse certificate PEM")?;
    let leaf = chain.first().cloned().context("no certificate found")?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &key_pem[..])
        .context("failed to parse private key PEM")?
        .context("no private key found")?;

    let provider = rustls::crypto::ring::default_provider();
    let certified_key = CertifiedKey::from_der(chain, key, &provider)
        .map_err(|e| anyhow!("unusable certificate/key pair: {e}"))?;

    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| anyhow!("invalid certificate: {e}"))?;
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let dns_names: Vec<String> = parsed
        .subject_alternative_name()
        .map_err(|e| anyhow!("invalid subjectAltName: {e}"))?
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    GeneralName::DNSName(n) => Some(n.trim_end_matches('.').to_ascii_lowercase()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let covered = dns_names.iter().any(|san| {
        san == name || (!name.starts_with("*.") && hostname::matches_pattern(san, name))
    });
    if !covered {
        bail!("certificate SANs {dns_names:?} do not cover {name}");
    }
    if now >= not_after {
        bail!("certificate for {name} expired at {not_after}");
    }
    if not_before > now + NOT_BEFORE_LEEWAY_SECS {
        bail!("certificate for {name} is not valid before {not_before}");
    }

    let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    Ok(CertEntry {
        name: name.to_string(),
        source,
        certified_key: Arc::new(certified_key),
        not_before,
        not_after,
        dns_names,
        fingerprint: hex(digest.as_ref()),
        generation: None,
    })
}

/// Generation-based certificate storage for managed (ACME) certificates.
#[derive(Debug, Clone)]
pub struct CertStore {
    root: PathBuf,
}

impl CertStore {
    pub fn open(root: &Path) -> anyhow::Result<Self> {
        create_private_dir(root)?;
        Ok(CertStore {
            root: root.to_path_buf(),
        })
    }

    fn name_dir(&self, name: &str) -> PathBuf {
        let dir = match name.strip_prefix("*.") {
            Some(rest) => format!("_wildcard.{rest}"),
            None => name.to_string(),
        };
        self.root.join(dir)
    }

    /// The generation the `current` pointer refers to, if any.
    pub fn current_generation(&self, name: &str) -> anyhow::Result<Option<u64>> {
        let path = self.name_dir(name).join(CURRENT_FILE);
        match fs::read_to_string(&path) {
            Ok(content) => content
                .trim()
                .parse::<u64>()
                .map(Some)
                .with_context(|| format!("corrupt generation pointer {path:?}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("cannot read {path:?}")),
        }
    }

    /// All complete generations on disk, newest first.
    pub fn generations(&self, name: &str) -> anyhow::Result<Vec<u64>> {
        let dir = self.name_dir(name);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("cannot read {dir:?}")),
        };
        let mut generations: Vec<u64> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.file_name()
                    .to_str()
                    .and_then(|n| n.strip_prefix("gen-"))
                    .and_then(|n| n.parse().ok())
            })
            .collect();
        generations.sort_unstable_by(|a, b| b.cmp(a));
        Ok(generations)
    }

    /// A generation number greater than anything stored so far.
    pub fn next_generation(&self, name: &str) -> anyhow::Result<u64> {
        let newest = self.generations(name)?.first().copied().unwrap_or(0);
        let current = self.current_generation(name)?.unwrap_or(0);
        Ok(newest.max(current) + 1)
    }

    /// Validate and persist a new generation, then switch the `current` pointer to it.
    /// Generations not newer than the active one are rejected so that a stale
    /// writer cannot roll the certificate back.
    pub fn store(
        &self,
        name: &str,
        generation: u64,
        cert_pem: &[u8],
        key_pem: &[u8],
        now: i64,
    ) -> anyhow::Result<CertEntry> {
        let mut entry = parse_and_validate(cert_pem, key_pem, name, CertSource::Acme, now)?;
        entry.generation = Some(generation);

        let dir = self.name_dir(name);
        create_private_dir(&dir)?;
        if let Some(current) = self.current_generation(name)? {
            if generation <= current {
                bail!("refusing to store generation {generation} for {name}: active generation is {current}");
            }
        }
        let final_dir = dir.join(format!("gen-{generation}"));
        if final_dir.exists() {
            bail!("generation {generation} for {name} already exists");
        }

        let tmp_dir = dir.join(format!(".gen-{generation}.{}.tmp", uuid::Uuid::new_v4()));
        create_private_dir(&tmp_dir)?;
        let written = write_file(&tmp_dir.join(CERT_FILE), cert_pem, 0o644)
            .and_then(|_| write_file(&tmp_dir.join(KEY_FILE), key_pem, 0o600))
            .and_then(|_| fs::rename(&tmp_dir, &final_dir).context("rename generation dir"));
        if let Err(e) = written {
            let _ = fs::remove_dir_all(&tmp_dir);
            return Err(e);
        }

        write_atomic(&dir.join(CURRENT_FILE), generation.to_string().as_bytes())?;
        sync_dir(&dir);
        self.prune(name, generation);
        Ok(entry)
    }

    /// Load the active generation. If it is unusable, fall back to the newest older
    /// generation that still validates.
    pub fn load_current(&self, name: &str, now: i64) -> anyhow::Result<Option<CertEntry>> {
        let Some(current) = self.current_generation(name)? else {
            return Ok(None);
        };
        for generation in self
            .generations(name)?
            .into_iter()
            .filter(|g| *g <= current)
        {
            match self.load_generation(name, generation, now) {
                Ok(entry) => {
                    if generation != current {
                        tracing::warn!(
                            name,
                            active = current,
                            fallback = generation,
                            "active certificate generation unusable; using previous generation"
                        );
                    }
                    return Ok(Some(entry));
                }
                Err(e) => {
                    tracing::warn!(name, generation, error = %e, "certificate generation unusable")
                }
            }
        }
        Ok(None)
    }

    fn load_generation(&self, name: &str, generation: u64, now: i64) -> anyhow::Result<CertEntry> {
        let dir = self.name_dir(name).join(format!("gen-{generation}"));
        let cert = fs::read(dir.join(CERT_FILE)).context("read certificate")?;
        let key = fs::read(dir.join(KEY_FILE)).context("read private key")?;
        let mut entry = parse_and_validate(&cert, &key, name, CertSource::Acme, now)?;
        entry.generation = Some(generation);
        Ok(entry)
    }

    fn prune(&self, name: &str, active: u64) {
        let dir = self.name_dir(name);
        if let Ok(generations) = self.generations(name) {
            for generation in generations
                .into_iter()
                .filter(|g| *g < active)
                .skip(KEPT_GENERATIONS - 1)
            {
                let _ = fs::remove_dir_all(dir.join(format!("gen-{generation}")));
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("cannot create directory {path:?}"))
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {path:?}"))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

/// Replace `path` atomically via a temporary file and rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        uuid::Uuid::new_v4()
    ));
    let result = write_file(&tmp, data, 0o600)
        .and_then(|_| fs::rename(&tmp, path).with_context(|| format!("cannot replace {path:?}")));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn sync_dir(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
pub mod test_certs {
    use rcgen::{CertificateParams, KeyPair};

    /// Self-signed certificate valid from `not_before` to `not_after` (unix seconds).
    pub fn generate(names: &[&str], not_before: i64, not_after: i64) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.not_before =
            rcgen::date_time_ymd(1970, 1, 1) + std::time::Duration::from_secs(not_before as u64);
        params.not_after =
            rcgen::date_time_ymd(1970, 1, 1) + std::time::Duration::from_secs(not_after as u64);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

#[cfg(test)]
mod tests {
    use super::test_certs::generate;
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn tempdir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sievetube-certstore-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validates_san_expiry_and_key() {
        let (cert, key) = generate(&["web.test"], NOW - 10, NOW + 1000);
        let entry = parse_and_validate(
            cert.as_bytes(),
            key.as_bytes(),
            "web.test",
            CertSource::Byoc,
            NOW,
        )
        .unwrap();
        assert_eq!(entry.dns_names, vec!["web.test"]);

        assert!(parse_and_validate(
            cert.as_bytes(),
            key.as_bytes(),
            "other.test",
            CertSource::Byoc,
            NOW
        )
        .is_err());
        assert!(parse_and_validate(
            cert.as_bytes(),
            key.as_bytes(),
            "web.test",
            CertSource::Byoc,
            NOW + 1000
        )
        .is_err());

        let (_, other_key) = generate(&["web.test"], NOW - 10, NOW + 1000);
        assert!(parse_and_validate(
            cert.as_bytes(),
            other_key.as_bytes(),
            "web.test",
            CertSource::Byoc,
            NOW
        )
        .is_err());
    }

    #[test]
    fn wildcard_san_covers_single_label() {
        let (cert, key) = generate(&["*.example.test"], NOW - 10, NOW + 1000);
        assert!(parse_and_validate(
            cert.as_bytes(),
            key.as_bytes(),
            "a.example.test",
            CertSource::Byoc,
            NOW
        )
        .is_ok());
        assert!(parse_and_validate(
            cert.as_bytes(),
            key.as_bytes(),
            "*.example.test",
            CertSource::Byoc,
            NOW
        )
        .is_ok());
        assert!(parse_and_validate(
            cert.as_bytes(),
            key.as_bytes(),
            "a.b.example.test",
            CertSource::Byoc,
            NOW
        )
        .is_err());
    }

    #[test]
    fn store_switches_generations_and_rejects_stale_writers() {
        let root = tempdir();
        let store = CertStore::open(&root).unwrap();
        let (c1, k1) = generate(&["web.test"], NOW - 10, NOW + 1000);
        let (c2, k2) = generate(&["web.test"], NOW - 10, NOW + 2000);

        assert_eq!(store.next_generation("web.test").unwrap(), 1);
        store
            .store("web.test", 1, c1.as_bytes(), k1.as_bytes(), NOW)
            .unwrap();
        store
            .store("web.test", 2, c2.as_bytes(), k2.as_bytes(), NOW)
            .unwrap();
        let loaded = store.load_current("web.test", NOW).unwrap().unwrap();
        assert_eq!(loaded.generation, Some(2));
        assert_eq!(loaded.not_after, NOW + 2000);

        // A stale writer (older generation) must not roll back.
        let err = store
            .store("web.test", 2, c1.as_bytes(), k1.as_bytes(), NOW)
            .unwrap_err();
        assert!(err.to_string().contains("refusing"));
        assert_eq!(store.current_generation("web.test").unwrap(), Some(2));
    }

    #[test]
    fn invalid_update_keeps_active_generation() {
        let root = tempdir();
        let store = CertStore::open(&root).unwrap();
        let (c1, k1) = generate(&["web.test"], NOW - 10, NOW + 1000);
        store
            .store("web.test", 1, c1.as_bytes(), k1.as_bytes(), NOW)
            .unwrap();

        let (_, wrong_key) = generate(&["web.test"], NOW - 10, NOW + 1000);
        assert!(store
            .store("web.test", 2, c1.as_bytes(), wrong_key.as_bytes(), NOW)
            .is_err());
        assert_eq!(store.current_generation("web.test").unwrap(), Some(1));
        assert!(store.load_current("web.test", NOW).unwrap().is_some());
    }

    #[test]
    fn corrupted_active_generation_falls_back() {
        let root = tempdir();
        let store = CertStore::open(&root).unwrap();
        let (c1, k1) = generate(&["web.test"], NOW - 10, NOW + 1000);
        let (c2, k2) = generate(&["web.test"], NOW - 10, NOW + 2000);
        store
            .store("web.test", 1, c1.as_bytes(), k1.as_bytes(), NOW)
            .unwrap();
        store
            .store("web.test", 2, c2.as_bytes(), k2.as_bytes(), NOW)
            .unwrap();

        // Simulate a torn write of the active generation.
        fs::write(root.join("web.test/gen-2").join(CERT_FILE), b"garbage").unwrap();
        let loaded = store.load_current("web.test", NOW).unwrap().unwrap();
        assert_eq!(loaded.generation, Some(1));
    }

    #[test]
    fn prunes_old_generations() {
        let root = tempdir();
        let store = CertStore::open(&root).unwrap();
        for generation in 1..=5 {
            let (c, k) = generate(&["web.test"], NOW - 10, NOW + 1000);
            store
                .store("web.test", generation, c.as_bytes(), k.as_bytes(), NOW)
                .unwrap();
        }
        assert_eq!(store.generations("web.test").unwrap(), vec![5, 4, 3]);
    }
}

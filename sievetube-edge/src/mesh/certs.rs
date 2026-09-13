//! Mesh PKI. A private CA issues one certificate per Edge; the Edge ID is bound
//! to the certificate as `URI:sievetube-edge://<id>` and
//! `DNS:<id>.mesh.sievetube.internal`, which peers verify on every connection.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use x509_parser::extensions::GeneralName;

pub const EDGE_URI_PREFIX: &str = "sievetube-edge://";
pub const MESH_DNS_SUFFIX: &str = "mesh.sievetube.internal";

/// TLS server name used when connecting to a peer.
pub fn server_name(edge_id: &str) -> String {
    format!("{edge_id}.{MESH_DNS_SUFFIX}")
}

/// Edge IDs are single DNS labels so they can appear in certificate names.
pub fn validate_edge_id(edge_id: &str) -> anyhow::Result<()> {
    let valid = (1..=63).contains(&edge_id.len())
        && edge_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !edge_id.starts_with('-')
        && !edge_id.ends_with('-');
    if !valid {
        bail!("edge id {edge_id:?} must be 1-63 lowercase letters, digits or '-'");
    }
    Ok(())
}

/// Generate a mesh CA; returns (certificate PEM, private key PEM).
pub fn generate_ca(common_name: &str) -> anyhow::Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2044, 1, 1);
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Issue an Edge certificate signed by the mesh CA; returns (certificate PEM, key PEM).
pub fn issue_edge_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    edge_id: &str,
    validity_days: u32,
) -> anyhow::Result<(String, String)> {
    validate_edge_id(edge_id)?;
    let ca_key = KeyPair::from_pem(ca_key_pem).context("invalid CA key")?;
    let ca_params =
        CertificateParams::from_ca_cert_pem(ca_cert_pem).context("invalid CA certificate")?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![server_name(edge_id)])?;
    params.subject_alt_names.push(SanType::URI(
        format!("{EDGE_URI_PREFIX}{edge_id}")
            .try_into()
            .map_err(|_| anyhow!("invalid URI SAN"))?,
    ));
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, format!("sievetube edge {edge_id}"));
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(validity_days as i64);
    let cert = params.signed_by(&key, &ca_cert, &ca_key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Edge IDs bound to a certificate through `sievetube-edge://` URI SANs.
pub fn edge_ids_from_cert(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => uri.strip_prefix(EDGE_URI_PREFIX).map(str::to_string),
            _ => None,
        })
        .collect()
}

/// This Edge's mesh credentials.
pub struct MeshIdentity {
    pub edge_id: String,
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub roots: Arc<RootCertStore>,
}

impl MeshIdentity {
    pub fn load(
        edge_id: &str,
        ca_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> anyhow::Result<Self> {
        validate_edge_id(edge_id)?;
        let read = |path: &Path| {
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
        };
        let ca_pem = read(ca_path)?;
        let cert_pem = read(cert_path)?;
        let key_pem = read(key_path)?;

        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
            roots.add(cert.context("invalid mesh CA certificate")?)?;
        }
        if roots.is_empty() {
            bail!("no CA certificate in {}", ca_path.display());
        }
        let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<_, _>>()
            .context("invalid mesh certificate")?;
        let leaf = cert_chain.first().context("no mesh certificate found")?;
        let ids = edge_ids_from_cert(leaf.as_ref());
        if ids != [edge_id] {
            bail!("mesh certificate identifies {ids:?}, expected exactly {edge_id:?}");
        }
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .context("invalid mesh private key")?
            .context("no mesh private key found")?;
        rustls::sign::CertifiedKey::from_der(
            cert_chain.clone(),
            key.clone_key(),
            &rustls::crypto::ring::default_provider(),
        )
        .map_err(|e| anyhow!("mesh certificate and key do not match: {e}"))?;
        Ok(MeshIdentity {
            edge_id: edge_id.to_string(),
            cert_chain,
            key,
            roots: Arc::new(roots),
        })
    }
}

#[cfg(test)]
pub mod test_pki {
    use super::*;

    /// A CA directory with certificates for the given edges, removed on drop.
    pub struct TestPki {
        pub dir: crate::test_support::TempPath,
        pub ca_cert: String,
        pub ca_key: String,
    }

    impl TestPki {
        pub fn new() -> Self {
            let dir = crate::test_support::TempPath::dir("mesh-pki");
            let (ca_cert, ca_key) = generate_ca("sievetube test mesh CA").unwrap();
            std::fs::write(dir.join("ca.pem"), &ca_cert).unwrap();
            TestPki {
                dir,
                ca_cert,
                ca_key,
            }
        }

        pub fn identity(&self, edge_id: &str) -> MeshIdentity {
            let (cert, key) = issue_edge_cert(&self.ca_cert, &self.ca_key, edge_id, 30).unwrap();
            let cert_path = self.dir.join(format!("{edge_id}.pem"));
            let key_path = self.dir.join(format!("{edge_id}.key"));
            std::fs::write(&cert_path, cert).unwrap();
            std::fs::write(&key_path, key).unwrap();
            MeshIdentity::load(edge_id, &self.dir.join("ca.pem"), &cert_path, &key_path).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_pki::TestPki;
    use super::*;

    #[test]
    fn edge_certificates_bind_the_edge_id() {
        let pki = TestPki::new();
        let identity = pki.identity("edge-a");
        assert_eq!(
            edge_ids_from_cert(identity.cert_chain[0].as_ref()),
            ["edge-a"]
        );
        assert_eq!(server_name("edge-a"), "edge-a.mesh.sievetube.internal");
    }

    #[test]
    fn identity_must_match_configured_edge_id() {
        let pki = TestPki::new();
        pki.identity("edge-a");
        let err = MeshIdentity::load(
            "edge-b",
            &pki.dir.join("ca.pem"),
            &pki.dir.join("edge-a.pem"),
            &pki.dir.join("edge-a.key"),
        )
        .err()
        .expect("mismatched identity must fail");
        assert!(format!("{err:#}").contains("expected exactly"), "{err:#}");
    }

    #[test]
    fn edge_ids_are_dns_labels() {
        assert!(validate_edge_id("edge-1").is_ok());
        for bad in ["", "Edge", "edge_1", "-edge", "edge.a", &"a".repeat(64)] {
            assert!(validate_edge_id(bad).is_err(), "{bad:?}");
        }
    }
}

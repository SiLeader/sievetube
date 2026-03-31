use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// BYOC (Bring Your Own Certificate) TLS resolver.
///
/// Implements `ResolvesServerCert` so rustls can select the correct
/// certificate based on the SNI hostname in each TLS ClientHello.
pub struct BYOCCertResolver {
    certs: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for BYOCCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = self.certs.load();
        f.debug_struct("BYOCCertResolver")
            .field("hostnames", &map.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BYOCCertResolver {
    /// Load all .crt/.key pairs from the given directory.
    /// Files must be named `<hostname>.crt` and `<hostname>.key`.
    pub fn load_from_dir(cert_dir: &Path) -> anyhow::Result<Arc<Self>> {
        let map = load_certs_from_dir(cert_dir)?;
        tracing::info!(count = map.len(), "loaded TLS certificates");
        Ok(Arc::new(BYOCCertResolver {
            certs: ArcSwap::from_pointee(map),
        }))
    }

    /// Hot-reload certificates from disk without dropping existing connections.
    pub fn reload(&self, cert_dir: &Path) -> anyhow::Result<()> {
        let map = load_certs_from_dir(cert_dir)?;
        self.certs.store(Arc::new(map));
        tracing::info!("TLS certificates reloaded");
        Ok(())
    }
}

fn load_certs_from_dir(cert_dir: &Path) -> anyhow::Result<HashMap<String, Arc<CertifiedKey>>> {
    let mut map = HashMap::new();

    let entries = std::fs::read_dir(cert_dir)
        .map_err(|e| anyhow::anyhow!("cannot read cert_dir {:?}: {}", cert_dir, e))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("crt") {
            continue;
        }

        let hostname = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid cert filename: {:?}", path))?
            .to_string();

        let key_path = path.with_extension("key");
        if !key_path.exists() {
            tracing::warn!(hostname, "missing .key file for cert, skipping");
            continue;
        }

        match load_cert_pair(&path, &key_path) {
            Ok(ck) => {
                tracing::debug!(hostname, "loaded TLS cert");
                map.insert(hostname, Arc::new(ck));
            }
            Err(e) => {
                tracing::warn!(hostname, error = %e, "failed to load cert, skipping");
            }
        }
    }

    Ok(map)
}

fn load_cert_pair(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertifiedKey> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("failed to parse cert PEM: {}", e))?;

    if certs.is_empty() {
        anyhow::bail!("no certificates found in {:?}", cert_path);
    }

    let key_der: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| anyhow::anyhow!("failed to parse key PEM: {}", e))?
            .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", key_path))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| anyhow::anyhow!("unsupported key type: {:?}", e))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

impl ResolvesServerCert for BYOCCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let map = self.certs.load();
        map.get(sni).cloned()
    }
}

/// Generate a self-signed certificate for the QUIC tunnel endpoint.
/// This cert is used for Connector→Edge QUIC connections, not for public HTTPS.
pub fn generate_self_signed() -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["sievetube-edge".to_string()])
        .map_err(|e| anyhow::anyhow!("rcgen error: {}", e))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    );
    Ok((vec![cert_der], key_der))
}

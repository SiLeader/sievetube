use quinn::rustls;
use serde::Deserialize;
use sievetube_common::config::IngressRule;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct ConnectorConfig {
    pub auth: AuthConfig,
    pub network: NetworkConfig,
    pub ingress: Vec<IngressRule>,
    #[serde(default)]
    pub valkey: Option<ValkeyConfig>,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    /// List of Edge server addresses (host:port)
    pub public_servers: Vec<String>,
    /// PEM CA bundle used to verify the Edge's QUIC certificate
    pub edge_ca_cert: Option<String>,
    /// TLS server name to verify the Edge's certificate against. Defaults to the
    /// host part of the `public_servers` entry, which is an IP address when the
    /// Edge is addressed by IP and then requires a matching IP SAN.
    pub edge_server_name: Option<String>,
    /// Hex SHA-256 fingerprints of accepted Edge certificates (pinning)
    #[serde(default)]
    pub edge_cert_sha256: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ValkeyConfig {
    pub url: String,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
}

fn default_heartbeat_interval() -> u64 {
    15
}

impl ConnectorConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {:?}: {}", path, e))?;
        let config: ConnectorConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.ingress.is_empty() {
            anyhow::bail!("at least one [[ingress]] rule is required");
        }
        if self.network.public_servers.is_empty() {
            anyhow::bail!("[network] public_servers must not be empty");
        }
        let pins = &self.network.edge_cert_sha256;
        if self.network.edge_ca_cert.is_some() && !pins.is_empty() {
            anyhow::bail!("[network] set either edge_ca_cert or edge_cert_sha256, not both");
        }
        for pin in pins {
            let pin = pin.trim();
            if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
                anyhow::bail!("[network] edge_cert_sha256 entries must be 64 hex characters");
            }
        }
        if let Some(path) = &self.network.edge_ca_cert {
            if !std::path::Path::new(path).exists() {
                anyhow::bail!("[network] edge_ca_cert: {path} does not exist");
            }
        }
        if let Some(name) = &self.network.edge_server_name {
            if name.trim().is_empty() {
                anyhow::bail!("[network] edge_server_name must not be empty");
            }
            if rustls::pki_types::ServerName::try_from(name.as_str()).is_err() {
                anyhow::bail!("[network] edge_server_name: {name} is not a valid server name");
            }
        }
        if self.network.edge_ca_cert.is_none() && pins.is_empty() {
            tracing::warn!(
                "no [network] edge_ca_cert or edge_cert_sha256 configured; the Edge's QUIC certificate is not verified"
            );
        }
        // Validate that the last rule is a catch-all if any non-catch-all rules exist
        let all_catch_all = self.ingress.iter().all(|r| r.hostname.is_none());
        if !all_catch_all {
            let last = self.ingress.last().unwrap();
            if last.hostname.is_some() {
                tracing::warn!(
                    "last ingress rule is not a catch-all; unmatched requests will return an error"
                );
            }
        }
        Ok(())
    }
}

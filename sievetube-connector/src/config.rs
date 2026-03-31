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
        // Validate that the last rule is a catch-all if any non-catch-all rules exist
        let all_catch_all = self.ingress.iter().all(|r| r.hostname.is_none());
        if !all_catch_all {
            let last = self.ingress.last().unwrap();
            if last.hostname.is_some() {
                tracing::warn!("last ingress rule is not a catch-all; unmatched requests will return an error");
            }
        }
        Ok(())
    }
}

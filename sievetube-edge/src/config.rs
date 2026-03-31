use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct EdgeConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub valkey: Option<ValkeyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortHostMapping {
    /// Listen address (e.g. "0.0.0.0:2222")
    pub addr: String,
    /// Hostname used for connector routing (since raw TCP/UDP has no Host header)
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Address where Connectors connect via QUIC (e.g. "0.0.0.0:4433")
    pub quic_listen: String,
    /// Public HTTP listen address
    pub http_listen: String,
    /// Public HTTPS listen address
    pub https_listen: String,
    /// Raw TCP listeners: each entry maps a listen address to a hostname
    #[serde(default)]
    pub tcp_listen: Vec<PortHostMapping>,
    /// UDP listeners: each entry maps a listen address to a hostname
    #[serde(default)]
    pub udp_listen: Vec<PortHostMapping>,
    /// Health and metrics server address
    #[serde(default = "default_health_listen")]
    pub health_listen: String,
}

fn default_health_listen() -> String {
    "127.0.0.1:9090".to_string()
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    /// HMAC-SHA256 secret used to verify Connector JWTs
    pub jwt_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Directory containing TLS certs for public HTTPS.
    /// Files should be named: <hostname>.crt and <hostname>.key
    pub cert_dir: String,
}

#[derive(Debug, Deserialize)]
pub struct ValkeyConfig {
    pub url: String,
}

impl EdgeConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {:?}: {}", path, e))?;
        let config: EdgeConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;
        Ok(config)
    }
}

use quinn::rustls;
use serde::Deserialize;
use sievetube_common::config::{IngressRule, Protocol, Target};
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    pub auth: AuthConfig,
    pub network: NetworkConfig,
    pub ingress: Vec<IngressRule>,
    #[serde(default)]
    pub valkey: Option<ValkeyConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// How long a shutdown waits for the streams in flight before closing
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
    /// Maximum number of tunnel streams that may consume Connector resources
    /// at once, shared by all Edge connections.
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
    /// Maximum time to establish a TCP connection to a local ingress target.
    #[serde(default = "default_target_connect_timeout")]
    pub target_connect_timeout_secs: u64,
}

fn default_drain_timeout() -> u64 {
    10
}

fn default_max_concurrent_streams() -> usize {
    256
}

fn default_target_connect_timeout() -> u64 {
    10
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
        if self.auth.token.trim().is_empty() {
            anyhow::bail!("[auth] token must not be empty");
        }
        if self.ingress.is_empty() {
            anyhow::bail!("at least one [[ingress]] rule is required");
        }
        if self.network.public_servers.is_empty() {
            anyhow::bail!("[network] public_servers must not be empty");
        }
        if !(1..=crate::quic_client::MAX_INCOMING_STREAMS as usize)
            .contains(&self.network.max_concurrent_streams)
        {
            anyhow::bail!(
                "[network] max_concurrent_streams must be between 1 and {}",
                crate::quic_client::MAX_INCOMING_STREAMS
            );
        }
        if self.network.target_connect_timeout_secs == 0 {
            anyhow::bail!("[network] target_connect_timeout_secs must be greater than 0");
        }
        if let Some(valkey) = &self.valkey {
            if valkey.url.trim().is_empty() {
                anyhow::bail!("[valkey] url must not be empty");
            }
            if valkey.heartbeat_interval_secs == 0 {
                anyhow::bail!("[valkey] heartbeat_interval_secs must be greater than 0");
            }
        }
        for (index, rule) in self.ingress.iter().enumerate() {
            validate_rule(rule)
                .map_err(|e| anyhow::anyhow!("[[ingress]] rule {}: {e}", index + 1))?;
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

/// A rule whose target cannot be used would otherwise only surface as a
/// hostname the Edge never routes to.
fn validate_rule(rule: &IngressRule) -> anyhow::Result<()> {
    match Target::parse(&rule.target).map_err(anyhow::Error::msg)? {
        Target::Address(_) => {}
        Target::HttpStatus(code) => {
            if !(100..=599).contains(&code) {
                anyhow::bail!("http_status:{code} is not an HTTP status code");
            }
            if let Some(protocol @ (Protocol::Tcp | Protocol::Udp)) = rule.protocol {
                anyhow::bail!("an http_status target cannot answer {protocol} traffic");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(ingress: &str) -> anyhow::Result<()> {
        let toml = format!(
            r#"
[auth]
token = "a.b.c"

[network]
public_servers = ["edge.test:4433"]
edge_cert_sha256 = ["{pin}"]

{ingress}
"#,
            pin = "ab".repeat(32),
        );
        toml::from_str::<ConnectorConfig>(&toml)?.validate()
    }

    #[test]
    fn ingress_targets_are_checked_at_startup() {
        let valid = r#"
[[ingress]]
hostname = "web.test"
target = "127.0.0.1:8080"

[[ingress]]
hostname = "game.test"
protocol = "udp"
target = "[::1]:19132"

[[ingress]]
target = "http_status:404"
"#;
        config(valid).unwrap();

        for (target, expected) in [
            ("localhost:8080", "invalid socket address"),
            ("http_status:abc", "invalid http status code"),
            ("http_status:42", "not an HTTP status code"),
        ] {
            let error = config(&format!("[[ingress]]\ntarget = \"{target}\"")).unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{target}: {error:#}"
            );
        }

        let status_for_udp = r#"
[[ingress]]
protocol = "udp"
target = "http_status:404"
"#;
        let error = config(status_for_udp).unwrap_err();
        assert!(format!("{error:#}").contains("rule 1"), "{error:#}");
    }

    #[test]
    fn drain_timeout_has_a_default() {
        let toml = r#"
[auth]
token = "a.b.c"

[network]
public_servers = ["edge.test:4433"]

[[ingress]]
target = "127.0.0.1:8080"
"#;
        let config: ConnectorConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.network.drain_timeout_secs, 10);
        assert_eq!(config.network.max_concurrent_streams, 256);
        assert_eq!(config.network.target_connect_timeout_secs, 10);
    }

    #[test]
    fn concurrent_stream_limit_is_validated() {
        for limit in [0, crate::quic_client::MAX_INCOMING_STREAMS as usize + 1] {
            let toml = format!(
                r#"
[auth]
token = "a.b.c"

[network]
public_servers = ["edge.test:4433"]
max_concurrent_streams = {limit}

[[ingress]]
target = "127.0.0.1:8080"
"#
            );
            let config: ConnectorConfig = toml::from_str(&toml).unwrap();
            let error = config.validate().unwrap_err();
            assert!(
                format!("{error:#}").contains("max_concurrent_streams"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let toml = r#"
[auth]
token = "a.b.c"

[network]
public_servers = ["edge.test:4433"]
connect_timout_secs = 10

[[ingress]]
target = "127.0.0.1:8080"
"#;
        let error = toml::from_str::<ConnectorConfig>(toml).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}

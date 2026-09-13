use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail};
use serde::Deserialize;

use sievetube_common::hostname;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// Configuration format version. Version 2 defaults to mesh routing; an
    /// absent value is treated as version 1 (direct routing) so that upgrading
    /// the binary never changes how traffic flows.
    #[serde(default)]
    pub config_version: Option<u32>,
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub valkey: Option<ValkeyConfig>,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub mesh: Option<MeshConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    /// Only Connectors attached to this Edge are used
    Direct,
    /// Requests without a local Connector are forwarded to a peer Edge
    Mesh,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    /// Defaults to mesh for config_version >= 2, otherwise direct
    pub mode: Option<RoutingMode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPeerConfig {
    pub edge_id: String,
    /// Static address; by default the peer's advertised address is used
    pub addr: Option<String>,
}

/// Edge-to-Edge forwarding. Peers authenticate with certificates from a mesh CA.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MeshConfig {
    /// Stable identifier of this Edge; must match its mesh certificate
    pub edge_id: String,
    pub listen: String,
    /// Address peers use to reach this Edge
    pub advertise: String,
    pub ca_cert: String,
    pub cert: String,
    pub key: String,
    pub peers: Vec<MeshPeerConfig>,
    /// Whether this Edge forwards UDP for peers
    pub udp: bool,
    pub max_streams_per_peer: usize,
    pub max_streams_per_tenant: usize,
    pub stream_wait_ms: u64,
    pub accept_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    /// Lifetime of an advertised route
    pub route_ttl_secs: u64,
    /// How often routes are re-advertised and the cache is refreshed
    pub route_refresh_secs: u64,
    pub peer_failure_cooldown_secs: u64,
    pub max_pending_udp_replies: usize,
}

impl Default for MeshConfig {
    fn default() -> Self {
        MeshConfig {
            edge_id: String::new(),
            listen: "0.0.0.0:4434".to_string(),
            advertise: String::new(),
            ca_cert: String::new(),
            cert: String::new(),
            key: String::new(),
            peers: Vec::new(),
            udp: true,
            max_streams_per_peer: 1024,
            max_streams_per_tenant: 256,
            stream_wait_ms: 2000,
            accept_timeout_ms: 3000,
            connect_timeout_ms: 5000,
            route_ttl_secs: 30,
            route_refresh_secs: 10,
            peer_failure_cooldown_secs: 15,
            max_pending_udp_replies: 4096,
        }
    }
}

impl MeshConfig {
    pub fn stream_wait(&self) -> Duration {
        Duration::from_millis(self.stream_wait_ms)
    }

    pub fn accept_timeout(&self) -> Duration {
        Duration::from_millis(self.accept_timeout_ms)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn route_ttl(&self) -> Duration {
        Duration::from_secs(self.route_ttl_secs)
    }

    pub fn route_refresh(&self) -> Duration {
        Duration::from_secs(self.route_refresh_secs)
    }

    fn validate(&self, has_valkey: bool) -> anyhow::Result<()> {
        crate::mesh::certs::validate_edge_id(&self.edge_id)
            .map_err(|e| anyhow!("mesh.edge_id: {e}"))?;
        self.listen
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("mesh.listen: invalid socket address {:?}", self.listen))?;
        let advertise: SocketAddr = self.advertise.parse().map_err(|_| {
            anyhow!(
                "mesh.advertise: invalid socket address {:?}",
                self.advertise
            )
        })?;
        if advertise.ip().is_unspecified() || advertise.port() == 0 {
            bail!("mesh.advertise must be an address peers can reach, not {advertise}");
        }
        for (field, path) in [
            ("ca_cert", &self.ca_cert),
            ("cert", &self.cert),
            ("key", &self.key),
        ] {
            if path.trim().is_empty() {
                bail!("mesh.{field} must be set");
            }
            if !Path::new(path).exists() {
                bail!("mesh.{field}: {path} does not exist");
            }
        }
        let mut seen = HashSet::new();
        for peer in &self.peers {
            crate::mesh::certs::validate_edge_id(&peer.edge_id)
                .map_err(|e| anyhow!("mesh.peers: {e}"))?;
            if peer.edge_id == self.edge_id {
                bail!(
                    "mesh.peers must not contain this edge's own id {}",
                    self.edge_id
                );
            }
            if !seen.insert(peer.edge_id.clone()) {
                bail!("mesh.peers: duplicate peer {}", peer.edge_id);
            }
            if let Some(addr) = &peer.addr {
                addr.parse::<SocketAddr>()
                    .map_err(|_| anyhow!("mesh.peers[{}]: invalid addr {addr:?}", peer.edge_id))?;
            }
        }
        // Several Edges need the control plane for routes, leases and presence.
        if !self.peers.is_empty() && !has_valkey {
            bail!(
                "a mesh with peers requires a [valkey] section for route advertisement and leases"
            );
        }
        if self.route_refresh_secs == 0 || self.route_ttl_secs <= self.route_refresh_secs {
            bail!("mesh.route_ttl_secs must be greater than mesh.route_refresh_secs");
        }
        for (field, value) in [
            ("max_streams_per_peer", self.max_streams_per_peer),
            ("max_streams_per_tenant", self.max_streams_per_tenant),
            ("max_pending_udp_replies", self.max_pending_udp_replies),
        ] {
            if value == 0 {
                bail!("mesh.{field} must be greater than 0");
            }
        }
        for (field, value) in [
            ("stream_wait_ms", self.stream_wait_ms),
            ("accept_timeout_ms", self.accept_timeout_ms),
            ("connect_timeout_ms", self.connect_timeout_ms),
            (
                "peer_failure_cooldown_secs",
                self.peer_failure_cooldown_secs,
            ),
        ] {
            if value == 0 {
                bail!("mesh.{field} must be greater than 0");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProviderType {
    Cloudflare,
    Route53,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordState {
    #[default]
    Present,
    /// Delete the record if it is managed by Sieve Tube and unchanged
    Absent,
}

/// DNS record management through provider APIs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub enabled: bool,
    /// Only log the planned changes
    pub dry_run: bool,
    /// Persistent directory for managed record state (share it between Edges)
    pub state_dir: String,
    pub reconcile_interval_secs: u64,
    /// Tolerated read-after-write delay before a mismatch counts as an external change
    pub settle_secs: u64,
    /// Zone writer lease duration when coordinating through Valkey
    pub lease_ttl_secs: u64,
    /// Explicit single-writer mode for deployments without Valkey
    pub single_writer: bool,
    /// Zones Sieve Tube may modify; providers and records must be inside them
    pub allowed_zones: Vec<String>,
    pub providers: Vec<DnsProviderConfig>,
    pub records: Vec<DnsRecordConfig>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            enabled: false,
            dry_run: false,
            state_dir: String::new(),
            reconcile_interval_secs: 300,
            settle_secs: 30,
            lease_ttl_secs: 60,
            single_writer: false,
            allowed_zones: Vec::new(),
            providers: Vec::new(),
            records: Vec::new(),
        }
    }
}

/// A named provider bound to one zone. Credentials are never inline: Cloudflare
/// tokens come from an environment variable or file, AWS credentials from the
/// SDK's standard provider chain.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsProviderConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: DnsProviderType,
    pub zone: String,
    /// Cloudflare zone id
    pub zone_id: Option<String>,
    pub api_token_env: Option<String>,
    pub api_token_file: Option<String>,
    /// Cloudflare API base URL override
    pub api_base_url: Option<String>,
    /// Route 53 public hosted zone id
    pub hosted_zone_id: Option<String>,
    /// Route 53 endpoint override
    pub endpoint_url: Option<String>,
    /// Route 53 signing region (defaults to us-east-1)
    pub region: Option<String>,
    #[serde(default = "default_dns_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

fn default_dns_request_timeout_secs() -> u64 {
    15
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRecordConfig {
    pub provider: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: crate::dns::RecordType,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default = "default_dns_ttl")]
    pub ttl: u32,
    /// Cloudflare proxy flag; unset keeps the current setting (new records are DNS-only)
    pub proxied: Option<bool>,
    /// Take over an existing record that Sieve Tube did not create
    #[serde(default)]
    pub import: bool,
    #[serde(default)]
    pub state: RecordState,
}

fn default_dns_ttl() -> u32 {
    300
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Reject traffic that violates the policy
    #[default]
    Enforce,
    /// Only record decisions (metrics and logs)
    Monitor,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    /// One bucket per tenant, hostname and client IP
    #[default]
    TenantHostnameIp,
    /// One bucket per client IP across all hostnames
    ClientIp,
}

/// Built-in traffic policy (local to each Edge).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub enabled: bool,
    pub mode: PolicyMode,
    /// Peers whose X-Forwarded-For is trusted (addresses or CIDRs)
    pub trusted_proxies: Vec<String>,
    /// Client addresses or CIDRs that are always rejected
    pub blocked_cidrs: Vec<String>,
    /// HTTP requests per second per key (unset = unlimited)
    pub requests_per_second: Option<f64>,
    /// Bucket size; defaults to ceil(requests_per_second)
    pub burst: Option<u32>,
    pub rate_limit_key: RateLimitKey,
    /// Maximum buckets per table; new keys beyond this are rejected
    pub max_entries: usize,
    /// Idle buckets older than this are reclaimed
    pub idle_ttl_secs: u64,
    pub domains: Vec<DomainPolicyConfig>,
    pub tcp: TcpPolicyConfig,
    pub udp: UdpPolicyConfig,
    /// WebAssembly plugins evaluated after the built-in HTTP rules
    pub plugins: Vec<PluginConfig>,
}

/// A WebAssembly policy plugin (ABI described in the `plugins` module).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    pub name: String,
    pub path: String,
    /// Hex SHA-256 of the module file; the module is loaded only if it matches
    pub sha256: String,
    /// Hostnames or `*.` patterns the plugin applies to (all when empty)
    #[serde(default)]
    pub applies_to: Vec<String>,
    #[serde(default = "default_plugin_max_memory_bytes")]
    pub max_memory_bytes: usize,
    /// Fuel per call (roughly proportional to executed instructions)
    #[serde(default = "default_plugin_fuel")]
    pub fuel: u64,
    /// Wall-clock limit per call
    #[serde(default = "default_plugin_timeout_ms")]
    pub timeout_ms: u64,
    /// Concurrent calls; further requests fail with 503
    #[serde(default = "default_plugin_max_concurrent")]
    pub max_concurrent: usize,
}

fn default_plugin_max_memory_bytes() -> usize {
    16 * 1024 * 1024
}

fn default_plugin_fuel() -> u64 {
    10_000_000
}

fn default_plugin_timeout_ms() -> u64 {
    20
}

fn default_plugin_max_concurrent() -> usize {
    64
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            enabled: false,
            mode: PolicyMode::Enforce,
            trusted_proxies: Vec::new(),
            blocked_cidrs: Vec::new(),
            requests_per_second: None,
            burst: None,
            rate_limit_key: RateLimitKey::TenantHostnameIp,
            max_entries: 100_000,
            idle_ttl_secs: 600,
            domains: Vec::new(),
            tcp: TcpPolicyConfig::default(),
            udp: UdpPolicyConfig::default(),
            plugins: Vec::new(),
        }
    }
}

/// Per-domain overrides. Blocked CIDRs add to the global list.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainPolicyConfig {
    /// Hostname or `*.` wildcard pattern
    pub hostname: String,
    pub mode: Option<PolicyMode>,
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,
    pub requests_per_second: Option<f64>,
    pub burst: Option<u32>,
}

/// Limits for raw TCP listeners, keyed by listener and client IP.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpPolicyConfig {
    pub connections_per_second: Option<f64>,
    pub connection_burst: Option<u32>,
    pub max_concurrent_per_ip: Option<usize>,
    pub max_concurrent_per_listener: Option<usize>,
}

/// Limits for UDP listeners, keyed by listener and source IP. Excess datagrams are dropped.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpPolicyConfig {
    pub packets_per_second: Option<f64>,
    pub packet_burst: Option<u32>,
    pub bytes_per_second: Option<f64>,
    pub byte_burst: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortHostMapping {
    /// Listen address (e.g. "0.0.0.0:2222")
    pub addr: String,
    /// Hostname used for connector routing (since raw TCP/UDP has no Host header)
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address where Connectors connect via QUIC (e.g. "0.0.0.0:4433")
    pub quic_listen: String,
    /// Certificate presented to Connectors. Without one a self-signed certificate
    /// is generated, which Connectors can only accept by skipping verification.
    pub quic_cert: Option<String>,
    pub quic_key: Option<String>,
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
    /// Seconds to wait for in-flight public connections to finish on shutdown
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
    /// How long a UDP request waits for its reply before its state is discarded
    #[serde(default = "default_udp_reply_timeout_secs")]
    pub udp_reply_timeout_secs: u64,
    /// Maximum UDP requests awaiting a reply per Connector connection
    #[serde(default = "default_udp_max_pending_replies")]
    pub udp_max_pending_replies: usize,
    /// Maximum authenticated or handshaking Connector QUIC connections.
    #[serde(default = "default_max_connector_connections")]
    pub max_connector_connections: usize,
}

fn default_udp_reply_timeout_secs() -> u64 {
    10
}

fn default_max_connector_connections() -> usize {
    4096
}

fn default_udp_max_pending_replies() -> usize {
    4096
}

fn default_health_listen() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_drain_timeout_secs() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// HMAC-SHA256 secret used to verify Connector JWTs
    pub jwt_secret: String,
    /// Older secrets accepted during a rolling rotation. New tokens must be
    /// signed with jwt_secret; remove old values after their tokens expire.
    #[serde(default)]
    pub jwt_previous_secrets: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Directory containing TLS certs for public HTTPS.
    /// Files should be named: <hostname>.crt and <hostname>.key
    pub cert_dir: String,
    /// How often the certificate directory is re-read (SIGHUP reloads immediately)
    #[serde(default = "default_cert_reload_interval_secs")]
    pub reload_interval_secs: u64,
    /// Automatic certificate management for explicitly listed domains
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

fn default_cert_reload_interval_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum AcmeChallenge {
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// TXT records through the providers in `[dns]`; required for wildcards
    #[serde(rename = "dns-01")]
    Dns01,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeCoordination {
    /// This Edge manages the certificates alone
    #[default]
    None,
    /// Edges sharing `state_dir` coordinate through Valkey leases
    Valkey,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    /// ACME directory; defaults to Let's Encrypt production
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    pub contact_email: Option<String>,
    /// Must be set to true to accept the CA's terms of service
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    /// Domains to manage (the allowlist; nothing else is ever ordered)
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub challenge: AcmeChallenge,
    /// Persistent directory for the account key and certificates (created 0700)
    pub state_dir: String,
    /// PEM root for a private or test ACME server's HTTPS endpoint
    pub ca_root_pem: Option<String>,
    /// Renew when this fraction of the certificate lifetime remains
    #[serde(default = "default_renew_before_fraction")]
    pub renew_before_fraction: f64,
    #[serde(default = "default_acme_retry_initial_secs")]
    pub retry_initial_secs: u64,
    #[serde(default = "default_acme_retry_max_secs")]
    pub retry_max_secs: u64,
    #[serde(default = "default_acme_order_timeout_secs")]
    pub order_timeout_secs: u64,
    /// Concurrent HTTP-01 challenge responses
    #[serde(default = "default_acme_challenge_max_concurrent")]
    pub challenge_max_concurrent: usize,
    #[serde(default)]
    pub coordination: AcmeCoordination,
    /// How often Edges look for certificates written by another Edge
    #[serde(default = "default_acme_store_poll_interval_secs")]
    pub store_poll_interval_secs: u64,
    /// Maximum wait for every live Edge to confirm an HTTP-01 response
    #[serde(default = "default_acme_distribution_timeout_secs")]
    pub challenge_distribution_timeout_secs: u64,
    /// Resolvers used to confirm DNS-01 TXT records (`ip` or `ip:port`); system resolvers if empty
    #[serde(default)]
    pub dns_resolvers: Vec<String>,
    #[serde(default = "default_acme_dns_propagation_timeout_secs")]
    pub dns_propagation_timeout_secs: u64,
    #[serde(default = "default_acme_dns_propagation_poll_secs")]
    pub dns_propagation_poll_secs: u64,
    #[serde(default = "default_acme_dns_txt_ttl")]
    pub dns_txt_ttl: u32,
}

fn default_acme_store_poll_interval_secs() -> u64 {
    30
}

fn default_acme_distribution_timeout_secs() -> u64 {
    30
}

fn default_acme_dns_propagation_timeout_secs() -> u64 {
    300
}

fn default_acme_dns_propagation_poll_secs() -> u64 {
    5
}

fn default_acme_dns_txt_ttl() -> u32 {
    60
}

/// Parse `ip` or `ip:port` (default port 53).
pub fn parse_resolver_addr(value: &str) -> anyhow::Result<SocketAddr> {
    let value = value.trim();
    value
        .parse::<SocketAddr>()
        .or_else(|_| {
            value
                .parse::<std::net::IpAddr>()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .map_err(|_| anyhow!("invalid resolver address {value:?}"))
}

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_renew_before_fraction() -> f64 {
    1.0 / 3.0
}

fn default_acme_retry_initial_secs() -> u64 {
    60
}

fn default_acme_retry_max_secs() -> u64 {
    6 * 3600
}

fn default_acme_order_timeout_secs() -> u64 {
    300
}

fn default_acme_challenge_max_concurrent() -> usize {
    64
}

impl AcmeConfig {
    fn validate(&mut self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !self.terms_of_service_agreed {
            bail!("tls.acme.terms_of_service_agreed must be true to use ACME");
        }
        if !self.directory_url.starts_with("https://") {
            bail!("tls.acme.directory_url must be an https:// URL");
        }
        if self.domains.is_empty() {
            bail!("tls.acme.domains must list at least one domain");
        }
        let mut seen = HashSet::new();
        for domain in self.domains.iter_mut() {
            let normalized = hostname::normalize_hostname_pattern(domain)
                .map_err(|e| anyhow!("tls.acme.domains: invalid domain {domain:?}: {e}"))?;
            if normalized.starts_with("*.") && self.challenge == AcmeChallenge::Http01 {
                bail!("tls.acme.domains: wildcard {normalized} requires the dns-01 challenge");
            }
            if !seen.insert(normalized.clone()) {
                bail!("tls.acme.domains: duplicate domain {normalized}");
            }
            *domain = normalized;
        }
        if self.state_dir.trim().is_empty() {
            bail!("tls.acme.state_dir must not be empty");
        }
        if let Some(email) = &self.contact_email {
            let valid =
                email.contains('@') && !email.contains(|c: char| c.is_whitespace() || c == ',');
            if !valid {
                bail!("tls.acme.contact_email is not a valid address");
            }
        }
        if !(self.renew_before_fraction > 0.0 && self.renew_before_fraction < 1.0) {
            bail!("tls.acme.renew_before_fraction must be between 0 and 1");
        }
        if self.retry_initial_secs == 0 || self.retry_max_secs < self.retry_initial_secs {
            bail!("tls.acme.retry_initial_secs must be > 0 and <= retry_max_secs");
        }
        if self.order_timeout_secs == 0 || self.challenge_max_concurrent == 0 {
            bail!(
                "tls.acme.order_timeout_secs and challenge_max_concurrent must be greater than 0"
            );
        }
        if self.store_poll_interval_secs == 0
            || self.challenge_distribution_timeout_secs == 0
            || self.dns_propagation_timeout_secs == 0
            || self.dns_propagation_poll_secs == 0
        {
            bail!("tls.acme intervals and timeouts must be greater than 0");
        }
        if !(60..=3600).contains(&self.dns_txt_ttl) {
            bail!("tls.acme.dns_txt_ttl must be between 60 and 3600");
        }
        for resolver in &self.dns_resolvers {
            parse_resolver_addr(resolver).map_err(|e| anyhow!("tls.acme.dns_resolvers: {e}"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValkeyConfig {
    pub url: String,
}

/// Limits and timeouts for request-level HTTP/HTTPS proxying.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// Maximum active client connections shared by HTTP and HTTPS listeners.
    pub max_connections: usize,
    /// Maximum time to receive a complete HTTP/1.x request head
    pub header_read_timeout_secs: u64,
    /// Maximum request/response header size in bytes (HTTP/1 buffer and HTTP/2 header list)
    pub max_header_bytes: usize,
    /// Maximum time for a TLS handshake on the HTTPS listener
    pub tls_handshake_timeout_secs: u64,
    /// Maximum time to open a tunnel stream to the Connector
    pub backend_open_timeout_secs: u64,
    /// Maximum time to wait for the backend response head
    pub response_header_timeout_secs: u64,
    /// Maximum concurrent streams per HTTP/2 client connection
    pub h2_max_concurrent_streams: u32,
    /// Set X-Forwarded-For / X-Forwarded-Proto on forwarded requests
    pub forwarded_headers: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            max_connections: 4096,
            header_read_timeout_secs: 30,
            max_header_bytes: 64 * 1024,
            tls_handshake_timeout_secs: 10,
            backend_open_timeout_secs: 10,
            response_header_timeout_secs: 60,
            h2_max_concurrent_streams: 256,
            forwarded_headers: true,
        }
    }
}

impl HttpConfig {
    pub fn header_read_timeout(&self) -> Duration {
        Duration::from_secs(self.header_read_timeout_secs)
    }

    pub fn tls_handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.tls_handshake_timeout_secs)
    }

    pub fn backend_open_timeout(&self) -> Duration {
        Duration::from_secs(self.backend_open_timeout_secs)
    }

    pub fn response_header_timeout(&self) -> Duration {
        Duration::from_secs(self.response_header_timeout_secs)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.max_connections == 0 {
            bail!("http.max_connections must be greater than 0");
        }
        // hyper requires HTTP/1 buffers of at least 8 KiB.
        if !(8192..=1024 * 1024).contains(&self.max_header_bytes) {
            bail!("http.max_header_bytes must be between 8192 and 1048576");
        }
        for (field, value) in [
            ("header_read_timeout_secs", self.header_read_timeout_secs),
            (
                "tls_handshake_timeout_secs",
                self.tls_handshake_timeout_secs,
            ),
            ("backend_open_timeout_secs", self.backend_open_timeout_secs),
            (
                "response_header_timeout_secs",
                self.response_header_timeout_secs,
            ),
        ] {
            if value == 0 {
                bail!("http.{field} must be greater than 0");
            }
        }
        if self.h2_max_concurrent_streams == 0 {
            bail!("http.h2_max_concurrent_streams must be greater than 0");
        }
        Ok(())
    }
}

impl EdgeConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read config {:?}: {}", path, e))?;
        Self::from_toml(&content)
    }

    pub fn from_toml(content: &str) -> anyhow::Result<Self> {
        let mut config: EdgeConfig =
            toml::from_str(content).map_err(|e| anyhow!("failed to parse config: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration and normalize hostnames in place.
    fn validate(&mut self) -> anyhow::Result<()> {
        self.server.quic_listen.parse::<SocketAddr>().map_err(|_| {
            anyhow!(
                "server.quic_listen: invalid socket address {:?}",
                self.server.quic_listen
            )
        })?;
        validate_listen_addr("server.http_listen", &self.server.http_listen)?;
        validate_listen_addr("server.https_listen", &self.server.https_listen)?;
        validate_listen_addr("server.health_listen", &self.server.health_listen)?;
        validate_port_mappings("server.tcp_listen", &mut self.server.tcp_listen)?;
        validate_port_mappings("server.udp_listen", &mut self.server.udp_listen)?;

        match (&self.server.quic_cert, &self.server.quic_key) {
            (Some(cert), Some(key)) => {
                for (field, path) in [("quic_cert", cert), ("quic_key", key)] {
                    if !Path::new(path).exists() {
                        bail!("server.{field}: {path} does not exist");
                    }
                }
            }
            (None, None) => {}
            _ => bail!("server.quic_cert and server.quic_key must be set together"),
        }
        if self.server.udp_reply_timeout_secs == 0
            || self.server.udp_max_pending_replies == 0
            || self.server.max_connector_connections == 0
        {
            bail!("server UDP limits and max_connector_connections must be greater than 0");
        }
        if self.auth.jwt_secret.is_empty() {
            bail!("auth.jwt_secret must not be empty");
        }
        if self
            .auth
            .jwt_previous_secrets
            .iter()
            .any(|secret| secret.is_empty())
        {
            bail!("auth.jwt_previous_secrets must not contain an empty secret");
        }
        let mut jwt_secrets = HashSet::new();
        if !jwt_secrets.insert(self.auth.jwt_secret.as_str())
            || self
                .auth
                .jwt_previous_secrets
                .iter()
                .any(|secret| !jwt_secrets.insert(secret.as_str()))
        {
            bail!("auth JWT secrets must not contain duplicates");
        }
        crate::policy::compile(&self.policy)?;
        if self.tls.reload_interval_secs == 0 {
            bail!("tls.reload_interval_secs must be greater than 0");
        }
        if let Some(acme) = &mut self.tls.acme {
            acme.validate()?;
        }
        if let Some(acme) = self.tls.acme.as_ref().filter(|a| a.enabled) {
            if acme.coordination == AcmeCoordination::Valkey && self.valkey.is_none() {
                bail!("tls.acme.coordination = \"valkey\" requires a [valkey] section");
            }
            if acme.challenge == AcmeChallenge::Dns01 {
                let dns = crate::dns::plan::compile(&self.dns)
                    .map_err(|e| anyhow!("tls.acme dns-01 needs valid [dns] providers: {e}"))?;
                for domain in &acme.domains {
                    let base = domain.strip_prefix("*.").unwrap_or(domain);
                    let challenge = format!("_acme-challenge.{base}");
                    let covered = dns
                        .providers
                        .iter()
                        .any(|p| hostname::is_within_zone(&challenge, &p.zone));
                    if !covered {
                        bail!("tls.acme: no [[dns.providers]] zone covers {challenge}");
                    }
                }
            }
        }
        if let Some(valkey) = &self.valkey {
            if valkey.url.trim().is_empty() {
                bail!("valkey.url must not be empty");
            }
        }
        self.http.validate()?;

        // Routing mode: version 2 defaults to mesh, version 1 keeps direct so that
        // upgrading a binary never silently changes the traffic path.
        let version = self.config_version.unwrap_or(1);
        if version == 0 || version > 2 {
            bail!("config_version {version} is not supported by this build");
        }
        let mode = self.routing.mode.unwrap_or(match version {
            2 => RoutingMode::Mesh,
            _ => RoutingMode::Direct,
        });
        self.routing.mode = Some(mode);
        match (mode, &self.mesh) {
            (RoutingMode::Mesh, None) => {
                bail!("routing.mode = \"mesh\" requires a [mesh] section")
            }
            (RoutingMode::Mesh, Some(mesh)) => mesh.validate(self.valkey.is_some())?,
            (RoutingMode::Direct, Some(mesh)) => {
                mesh.validate(self.valkey.is_some())?;
            }
            (RoutingMode::Direct, None) => {}
        }

        if self.dns.enabled {
            if self.dns.state_dir.trim().is_empty() {
                bail!("dns.state_dir must be set when dns.enabled = true");
            }
            if self.dns.reconcile_interval_secs == 0 || self.dns.lease_ttl_secs < 5 {
                bail!("dns.reconcile_interval_secs must be > 0 and dns.lease_ttl_secs >= 5");
            }
            if self.valkey.is_none() && !self.dns.single_writer {
                bail!("dns requires [valkey] for zone leases, or dns.single_writer = true for a single writing Edge");
            }
            crate::dns::plan::compile(&self.dns)?;
        }
        Ok(())
    }
}

fn validate_listen_addr(field: &str, addr: &str) -> anyhow::Result<()> {
    if addr.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => Ok(()),
        _ => bail!("{field}: invalid listen address {addr:?}"),
    }
}

fn validate_port_mappings(field: &str, mappings: &mut [PortHostMapping]) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for mapping in mappings.iter_mut() {
        validate_listen_addr(field, &mapping.addr)?;
        if !seen.insert(mapping.addr.clone()) {
            bail!("{field}: duplicate listen address {:?}", mapping.addr);
        }
        mapping.hostname = hostname::normalize_hostname(&mapping.hostname)
            .map_err(|e| anyhow!("{field}: invalid hostname {:?}: {e}", mapping.hostname))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[server]
quic_listen = "127.0.0.1:4433"
http_listen = "127.0.0.1:8080"
https_listen = "127.0.0.1:8443"

[auth]
jwt_secret = "secret"

[tls]
cert_dir = "/nonexistent"
"#;

    #[test]
    fn example_config_is_valid() {
        let cfg = EdgeConfig::from_toml(include_str!("../../config/edge.example.toml")).unwrap();
        assert_eq!(cfg.server.quic_listen, "0.0.0.0:4433");
        // The shipped example is a single-Edge deployment.
        assert_eq!(cfg.config_version, Some(2));
        assert_eq!(cfg.routing.mode, Some(RoutingMode::Direct));
    }

    #[test]
    fn routing_mode_follows_the_config_version() {
        // Version 1 (or an absent version) keeps direct routing on upgrade.
        let cfg = EdgeConfig::from_toml(MINIMAL).unwrap();
        assert_eq!(cfg.routing.mode, Some(RoutingMode::Direct));

        // Version 2 defaults to mesh, which needs a [mesh] section.
        let v2 = format!("config_version = 2\n{MINIMAL}");
        let err = EdgeConfig::from_toml(&v2).unwrap_err();
        assert!(format!("{err:#}").contains("[mesh]"), "{err:#}");

        // Mesh without reachable peers or certificates is a configuration error,
        // never a silent fallback to direct.
        let mesh = format!("{MINIMAL}\n[routing]\nmode = \"mesh\"\n\n[mesh]\nedge_id = \"edge-a\"\nlisten = \"0.0.0.0:4434\"\nadvertise = \"0.0.0.0:4434\"\nca_cert = \"/nonexistent/ca.pem\"\ncert = \"/nonexistent/edge.pem\"\nkey = \"/nonexistent/edge.key\"\n");
        assert!(EdgeConfig::from_toml(&mesh).is_err());
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = EdgeConfig::from_toml(MINIMAL).unwrap();
        assert_eq!(cfg.http.max_header_bytes, 64 * 1024);
        assert_eq!(cfg.http.max_connections, 4096);
        assert_eq!(cfg.server.drain_timeout_secs, 30);
        assert_eq!(cfg.server.max_connector_connections, 4096);
        assert!(cfg.valkey.is_none());
    }

    #[test]
    fn normalizes_listener_hostnames() {
        let toml = format!(
            "{MINIMAL}\n[[server.tcp_listen]]\naddr = \"127.0.0.1:2222\"\nhostname = \"SSH.Example.com.\"\n"
        );
        let cfg = EdgeConfig::from_toml(&toml).unwrap();
        assert_eq!(cfg.server.tcp_listen[0].hostname, "ssh.example.com");
    }

    #[test]
    fn rejects_invalid_values() {
        let bad_host = format!(
            "{MINIMAL}\n[[server.udp_listen]]\naddr = \"127.0.0.1:2222\"\nhostname = \"bad host\"\n"
        );
        assert!(EdgeConfig::from_toml(&bad_host).is_err());

        let small_headers = format!("{MINIMAL}\n[http]\nmax_header_bytes = 1024\n");
        assert!(EdgeConfig::from_toml(&small_headers).is_err());

        let bad_quic = MINIMAL.replace("127.0.0.1:4433", "localhost");
        assert!(EdgeConfig::from_toml(&bad_quic).is_err());

        let bad_policy =
            format!("{MINIMAL}\n[policy]\nenabled = true\nblocked_cidrs = [\"10.0.0.0/33\"]\n");
        assert!(EdgeConfig::from_toml(&bad_policy).is_err());

        let unknown_policy_field = format!("{MINIMAL}\n[policy]\nrequest_per_second = 5\n");
        assert!(EdgeConfig::from_toml(&unknown_policy_field).is_err());

        let unknown_server_field = MINIMAL.replace(
            "quic_listen = \"127.0.0.1:4433\"",
            "quic_listen = \"127.0.0.1:4433\"\nquic_lisen = \"127.0.0.1:4433\"",
        );
        assert!(EdgeConfig::from_toml(&unknown_server_field).is_err());
    }

    #[test]
    fn validates_acme_section() {
        let acme = |body: &str| {
            format!("{MINIMAL}\n[tls.acme]\nstate_dir = \"/var/lib/sievetube\"\n{body}\n")
        };

        let cfg = EdgeConfig::from_toml(&acme(
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"WWW.Example.com.\"]\ncontact_email = \"ops@example.com\"",
        ))
        .unwrap();
        let parsed = cfg.tls.acme.unwrap();
        assert_eq!(parsed.domains, vec!["www.example.com"]);
        assert_eq!(parsed.challenge, AcmeChallenge::Http01);

        // Disabled sections are not validated.
        assert!(EdgeConfig::from_toml(&acme("enabled = false")).is_ok());

        for bad in [
            "enabled = true\ndomains = [\"a.example.com\"]",
            "enabled = true\nterms_of_service_agreed = true\ndomains = []",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"*.example.com\"]",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"a.example.com\", \"A.example.com\"]",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"a.example.com\"]\ndirectory_url = \"http://ca.test/dir\"",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"a.example.com\"]\nrenew_before_fraction = 1.5",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"a.example.com\"]\nchallenge = \"tls-alpn-01\"",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"a.example.com\"]\ncoordination = \"valkey\"",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"*.example.com\"]\nchallenge = \"dns-01\"",
            "enabled = true\nterms_of_service_agreed = true\ndomains = [\"a.example.com\"]\ndns_resolvers = [\"not-an-ip\"]",
        ] {
            assert!(EdgeConfig::from_toml(&acme(bad)).is_err(), "should reject: {bad}");
        }

        // dns-01 with a provider covering the domain (wildcards allowed).
        let dns01 = format!(
            "{}\n[dns]\nallowed_zones = [\"example.com\"]\n[[dns.providers]]\nname = \"cf\"\ntype = \"cloudflare\"\nzone = \"example.com\"\nzone_id = \"z\"\napi_token_env = \"CF_TOKEN\"\n",
            acme("enabled = true\nterms_of_service_agreed = true\ndomains = [\"*.example.com\", \"example.com\"]\nchallenge = \"dns-01\"\ndns_resolvers = [\"127.0.0.1:8053\", \"1.1.1.1\"]")
        );
        let cfg = EdgeConfig::from_toml(&dns01).unwrap();
        assert_eq!(cfg.tls.acme.unwrap().challenge, AcmeChallenge::Dns01);
        assert!(EdgeConfig::from_toml(
            &dns01.replace("zone = \"example.com\"", "zone = \"other.example.com\"")
        )
        .is_err());
    }

    #[test]
    fn parses_policy_section() {
        let toml = format!(
            r#"{MINIMAL}
[policy]
enabled = true
mode = "monitor"
trusted_proxies = ["10.0.0.0/8"]
requests_per_second = 20
burst = 40

[[policy.domains]]
hostname = "*.api.example.com"
mode = "enforce"
requests_per_second = 5

[policy.tcp]
max_concurrent_per_ip = 10

[policy.udp]
packets_per_second = 100
"#
        );
        let cfg = EdgeConfig::from_toml(&toml).unwrap();
        assert_eq!(cfg.policy.mode, PolicyMode::Monitor);
        assert_eq!(cfg.policy.domains[0].mode, Some(PolicyMode::Enforce));
        assert_eq!(cfg.policy.tcp.max_concurrent_per_ip, Some(10));
    }
}

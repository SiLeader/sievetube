//! Built-in traffic policy: CIDR blocks and per-client token buckets for HTTP
//! requests, and connection/packet limits for raw TCP and UDP listeners.
//!
//! All limits are local to this Edge. Spreading traffic over several Edges
//! increases the effective allowance; this is not a cluster-wide quota.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use arc_swap::ArcSwap;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use http::HeaderMap;
use ipnet::IpNet;

use sievetube_common::config::Protocol;
use sievetube_common::hostname;

use crate::config::{PolicyConfig, PolicyMode, RateLimitKey};
use crate::edge_metrics;
use crate::plugins::{ModuleCache, PluginSet, PluginVerdict};

/// Monotonic time source, injectable for deterministic tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

pub struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        MonotonicClock {
            start: Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimit {
    pub per_second: f64,
    pub burst: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    BlockedCidr,
    RateLimit,
    Capacity,
    ConcurrencyLimit,
    Plugin,
    PluginFailure,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::BlockedCidr => "blocked_cidr",
            Reason::RateLimit => "rate_limit",
            Reason::Capacity => "capacity",
            Reason::ConcurrencyLimit => "concurrency_limit",
            Reason::Plugin => "plugin",
            Reason::PluginFailure => "plugin_failure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(Reason),
    RateLimited {
        reason: Reason,
        retry_after_secs: u64,
    },
    /// The request could not be evaluated (e.g. a plugin failed).
    Unavailable(Reason),
}

impl Decision {
    fn labels(&self) -> (&'static str, &'static str) {
        match self {
            Decision::Allow => ("allow", "none"),
            Decision::Deny(reason) => ("deny", reason.as_str()),
            Decision::RateLimited { reason, .. } => ("rate_limited", reason.as_str()),
            Decision::Unavailable(reason) => ("unavailable", reason.as_str()),
        }
    }
}

/// A decision and whether it is enforced (monitor mode only records it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub enforced: bool,
}

impl Verdict {
    fn allow() -> Self {
        Verdict {
            decision: Decision::Allow,
            enforced: true,
        }
    }

    pub fn rejects(&self) -> bool {
        self.enforced && self.decision != Decision::Allow
    }
}

/// Facts a request policy may depend on. Only authorized, normalized values.
#[derive(Debug, Clone, Copy)]
pub struct RequestContext<'a> {
    pub tenant_id: &'a str,
    pub hostname: &'a str,
    pub protocol: Protocol,
    pub client_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
}

struct Bucket {
    tokens: f64,
    updated: Duration,
    /// Time after which an idle bucket is indistinguishable from a new one
    full_after: Duration,
}

impl Bucket {
    fn take(&mut self, limit: RateLimit, amount: f64, now: Duration) -> Result<(), TakeError> {
        let elapsed = now.saturating_sub(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * limit.per_second).min(limit.burst);
        self.updated = now;
        self.full_after = Duration::from_secs_f64(limit.burst / limit.per_second);
        if self.tokens >= amount {
            self.tokens -= amount;
            Ok(())
        } else {
            Err(TakeError::Limited {
                wait_secs: (amount - self.tokens) / limit.per_second,
            })
        }
    }
}

enum TakeError {
    Limited { wait_secs: f64 },
    Capacity,
}

/// Token buckets keyed by a keyed hash of the limit key. Per-key updates are
/// atomic because they happen under the map's entry lock.
struct BucketTable {
    name: &'static str,
    buckets: DashMap<u64, Bucket>,
    hasher: RandomState,
}

impl BucketTable {
    fn new(name: &'static str) -> Self {
        BucketTable {
            name,
            buckets: DashMap::new(),
            hasher: RandomState::new(),
        }
    }

    fn key<T: Hash>(&self, value: T) -> u64 {
        self.hasher.hash_one(value)
    }

    fn take(
        &self,
        key: u64,
        limit: RateLimit,
        amount: f64,
        now: Duration,
        max_entries: usize,
        idle_ttl: Duration,
    ) -> Result<(), TakeError> {
        if let Some(mut bucket) = self.buckets.get_mut(&key) {
            return bucket.take(limit, amount, now);
        }
        if self.buckets.len() >= max_entries {
            self.sweep(now, idle_ttl);
            if self.buckets.len() >= max_entries {
                return Err(TakeError::Capacity);
            }
        }
        let mut bucket = self.buckets.entry(key).or_insert_with(|| Bucket {
            tokens: limit.burst,
            updated: now,
            full_after: Duration::ZERO,
        });
        bucket.take(limit, amount, now)
    }

    fn sweep(&self, now: Duration, idle_ttl: Duration) {
        self.buckets.retain(|_, bucket| {
            now.saturating_sub(bucket.updated) < bucket.full_after.max(idle_ttl)
        });
    }
}

#[derive(Debug, Clone)]
struct CompiledDomain {
    mode: Option<PolicyMode>,
    blocked: Vec<IpNet>,
    http_rate: Option<RateLimit>,
}

#[derive(Debug, Clone, Default)]
struct CompiledTcp {
    connection_rate: Option<RateLimit>,
    max_concurrent_per_ip: Option<usize>,
    max_concurrent_per_listener: Option<usize>,
}

#[derive(Debug, Clone, Default)]
struct CompiledUdp {
    packet_rate: Option<RateLimit>,
    byte_rate: Option<RateLimit>,
}

/// A validated policy configuration.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    enabled: bool,
    mode: PolicyMode,
    trusted_proxies: Vec<IpNet>,
    blocked: Vec<IpNet>,
    http_rate: Option<RateLimit>,
    key: RateLimitKey,
    domains: HashMap<String, CompiledDomain>,
    max_entries: usize,
    idle_ttl: Duration,
    tcp: CompiledTcp,
    udp: CompiledUdp,
}

impl CompiledPolicy {
    fn domain(&self, hostname: &str) -> Option<&CompiledDomain> {
        self.domains.get(hostname).or_else(|| {
            hostname::wildcard_for(hostname).and_then(|pattern| self.domains.get(&pattern))
        })
    }
}

/// Validate a policy section. Called when the configuration is loaded and on reload.
pub fn compile(cfg: &PolicyConfig) -> anyhow::Result<CompiledPolicy> {
    let mut domains = HashMap::new();
    for domain in &cfg.domains {
        let name = hostname::normalize_hostname_pattern(&domain.hostname).map_err(|e| {
            anyhow!(
                "policy.domains: invalid hostname {:?}: {e}",
                domain.hostname
            )
        })?;
        let field = format!("policy.domains[{name}]");
        let compiled = CompiledDomain {
            mode: domain.mode,
            blocked: parse_networks(&field, &domain.blocked_cidrs)?,
            http_rate: rate_limit(&field, domain.requests_per_second, domain.burst)?,
        };
        if domains.insert(name.clone(), compiled).is_some() {
            bail!("policy.domains: duplicate hostname {name}");
        }
    }
    if cfg.max_entries == 0 {
        bail!("policy.max_entries must be greater than 0");
    }

    let udp = CompiledUdp {
        packet_rate: rate_limit(
            "policy.udp packets",
            cfg.udp.packets_per_second,
            cfg.udp.packet_burst,
        )?,
        byte_rate: rate_limit(
            "policy.udp bytes",
            cfg.udp.bytes_per_second,
            cfg.udp.byte_burst,
        )?,
    };
    if udp.byte_rate.is_some_and(|r| r.burst < 65535.0) {
        bail!("policy.udp.byte_burst must be at least 65535 so that every datagram size can pass");
    }

    let mut plugin_names = std::collections::HashSet::new();
    for plugin in &cfg.plugins {
        let field = format!("policy.plugins[{}]", plugin.name);
        let valid_name = !plugin.name.is_empty()
            && plugin
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !valid_name {
            bail!("{field}: name must be lowercase letters, digits, '-' or '_'");
        }
        if !plugin_names.insert(plugin.name.as_str()) {
            bail!("{field}: duplicate plugin name");
        }
        if plugin.path.trim().is_empty() {
            bail!("{field}: path must be set");
        }
        let sha256 = plugin.sha256.trim();
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{field}: sha256 must be 64 hex characters");
        }
        for pattern in &plugin.applies_to {
            hostname::normalize_hostname_pattern(pattern)
                .map_err(|e| anyhow!("{field}: invalid applies_to {pattern:?}: {e}"))?;
        }
        if !(64 * 1024..=1024 * 1024 * 1024).contains(&plugin.max_memory_bytes) {
            bail!("{field}: max_memory_bytes must be between 65536 and 1073741824");
        }
        if plugin.fuel == 0
            || plugin.max_concurrent == 0
            || !(1..=10_000).contains(&plugin.timeout_ms)
        {
            bail!(
                "{field}: fuel and max_concurrent must be > 0 and timeout_ms between 1 and 10000"
            );
        }
    }

    Ok(CompiledPolicy {
        enabled: cfg.enabled,
        mode: cfg.mode,
        trusted_proxies: parse_networks("policy.trusted_proxies", &cfg.trusted_proxies)?,
        blocked: parse_networks("policy.blocked_cidrs", &cfg.blocked_cidrs)?,
        http_rate: rate_limit("policy", cfg.requests_per_second, cfg.burst)?,
        key: cfg.rate_limit_key,
        domains,
        max_entries: cfg.max_entries,
        idle_ttl: Duration::from_secs(cfg.idle_ttl_secs),
        tcp: CompiledTcp {
            connection_rate: rate_limit(
                "policy.tcp",
                cfg.tcp.connections_per_second,
                cfg.tcp.connection_burst,
            )?,
            max_concurrent_per_ip: positive(
                "policy.tcp.max_concurrent_per_ip",
                cfg.tcp.max_concurrent_per_ip,
            )?,
            max_concurrent_per_listener: positive(
                "policy.tcp.max_concurrent_per_listener",
                cfg.tcp.max_concurrent_per_listener,
            )?,
        },
        udp,
    })
}

fn rate_limit(
    field: &str,
    per_second: Option<f64>,
    burst: Option<u32>,
) -> anyhow::Result<Option<RateLimit>> {
    match (per_second, burst) {
        (None, None) => Ok(None),
        (None, Some(_)) => bail!("{field}: burst requires a rate"),
        (Some(rate), burst) => {
            if !rate.is_finite() || rate <= 0.0 {
                bail!("{field}: rate must be a positive number");
            }
            let burst = burst.unwrap_or_else(|| rate.ceil().max(1.0) as u32);
            if burst == 0 {
                bail!("{field}: burst must be at least 1");
            }
            Ok(Some(RateLimit {
                per_second: rate,
                burst: burst as f64,
            }))
        }
    }
}

fn positive(field: &str, value: Option<usize>) -> anyhow::Result<Option<usize>> {
    match value {
        Some(0) => bail!("{field} must be greater than 0"),
        other => Ok(other),
    }
}

fn parse_networks(field: &str, values: &[String]) -> anyhow::Result<Vec<IpNet>> {
    values
        .iter()
        .map(|value| {
            let value = value.trim();
            value
                .parse::<IpNet>()
                .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
                .map(|net| net.trunc())
                .map_err(|_| anyhow!("{field}: invalid address or CIDR {value:?}"))
        })
        .collect()
}

fn contains(networks: &[IpNet], ip: IpAddr) -> bool {
    networks.iter().any(|net| net.contains(&ip))
}

/// Determine the client IP. Forwarding headers are only honored when the peer is a
/// trusted proxy; the chain is walked from the right and stops at the first
/// untrusted hop, so clients cannot choose the address used for limits.
pub fn resolve_client_ip(peer: IpAddr, forwarded_for: &[&str], trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    if !contains(trusted, peer) {
        return peer;
    }
    let mut client = peer;
    for hop in forwarded_for
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let Some(ip) = parse_forwarded_ip(hop) else {
            break;
        };
        client = ip;
        if !contains(trusted, ip) {
            break;
        }
    }
    client
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Some(rest) = value.strip_prefix('[') {
        return rest
            .split_once(']')?
            .0
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical());
    }
    let (host, port) = value.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Releases a TCP concurrency slot when dropped.
pub struct TcpPermit {
    policy: Arc<Policy>,
    ip_key: Option<u64>,
    listener_key: Option<u64>,
}

impl Drop for TcpPermit {
    fn drop(&mut self) {
        if let Some(key) = self.ip_key {
            release(&self.policy.tcp_ip_active, key);
        }
        if let Some(key) = self.listener_key {
            release(&self.policy.tcp_listener_active, key);
        }
    }
}

fn acquire(map: &DashMap<u64, usize>, key: u64, max: usize) -> bool {
    let mut count = map.entry(key).or_insert(0);
    if *count >= max {
        return false;
    }
    *count += 1;
    true
}

fn release(map: &DashMap<u64, usize>, key: u64) {
    if let Entry::Occupied(mut entry) = map.entry(key) {
        *entry.get_mut() = entry.get().saturating_sub(1);
        if *entry.get() == 0 {
            entry.remove();
        }
    }
}

pub struct Policy {
    compiled: ArcSwap<CompiledPolicy>,
    plugins: ArcSwap<PluginSet>,
    module_cache: ModuleCache,
    http_buckets: BucketTable,
    tcp_buckets: BucketTable,
    udp_packet_buckets: BucketTable,
    udp_byte_buckets: BucketTable,
    tcp_ip_active: DashMap<u64, usize>,
    tcp_listener_active: DashMap<u64, usize>,
    key_hasher: RandomState,
    clock: Arc<dyn Clock>,
}

impl Policy {
    pub fn new(cfg: &PolicyConfig) -> anyhow::Result<Arc<Self>> {
        Self::with_clock(cfg, Arc::new(MonotonicClock::new()))
    }

    pub fn with_clock(cfg: &PolicyConfig, clock: Arc<dyn Clock>) -> anyhow::Result<Arc<Self>> {
        let compiled = compile(cfg)?;
        let module_cache = ModuleCache::default();
        let plugins = load_plugins(cfg, &module_cache)?;
        Ok(Arc::new(Policy {
            compiled: ArcSwap::from_pointee(compiled),
            plugins: ArcSwap::from_pointee(plugins),
            module_cache,
            http_buckets: BucketTable::new("http"),
            tcp_buckets: BucketTable::new("tcp"),
            udp_packet_buckets: BucketTable::new("udp_packets"),
            udp_byte_buckets: BucketTable::new("udp_bytes"),
            tcp_ip_active: DashMap::new(),
            tcp_listener_active: DashMap::new(),
            key_hasher: RandomState::new(),
            clock,
        }))
    }

    /// Replace the configuration after validating it. Existing buckets and
    /// concurrency counts are kept; on error the current policy stays active.
    pub fn reload(&self, cfg: &PolicyConfig) -> anyhow::Result<()> {
        let compiled = compile(cfg)?;
        let plugins = load_plugins(cfg, &self.module_cache)?;
        self.plugins.store(Arc::new(plugins));
        self.compiled.store(Arc::new(compiled));
        Ok(())
    }

    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        contains(&self.compiled.load().trusted_proxies, ip.to_canonical())
    }

    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let values: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        resolve_client_ip(peer, &values, &self.compiled.load().trusted_proxies)
    }

    /// Evaluate the built-in rules and then the policy plugins.
    ///
    /// Plugins are WebAssembly modules with a CPU and wall-clock budget, so they
    /// run on a blocking thread: evaluating them on a runtime worker would stall
    /// every listener of this Edge for as long as a module runs.
    pub async fn evaluate_http(&self, ctx: &RequestContext<'_>) -> Verdict {
        let policy = self.compiled.load_full();
        if !policy.enabled {
            return Verdict::allow();
        }
        let started = Instant::now();
        let domain = policy.domain(ctx.hostname);
        let mode = domain.and_then(|d| d.mode).unwrap_or(policy.mode);
        let mut decision = self.decide_http(&policy, domain, ctx);
        if decision == Decision::Allow {
            decision = self.decide_plugins(ctx).await;
        }
        let verdict = Verdict {
            decision,
            enforced: mode == PolicyMode::Enforce,
        };
        observe(ctx.protocol, verdict, started);
        if decision != Decision::Allow {
            tracing::debug!(
                hostname = ctx.hostname,
                tenant_id = ctx.tenant_id,
                client_ip = %ctx.client_ip,
                method = ctx.method,
                path = ctx.path,
                decision = decision.labels().0,
                reason = decision.labels().1,
                enforced = verdict.enforced,
                "policy decision"
            );
        }
        verdict
    }

    fn decide_http(
        &self,
        policy: &CompiledPolicy,
        domain: Option<&CompiledDomain>,
        ctx: &RequestContext<'_>,
    ) -> Decision {
        if contains(&policy.blocked, ctx.client_ip)
            || domain.is_some_and(|d| contains(&d.blocked, ctx.client_ip))
        {
            return Decision::Deny(Reason::BlockedCidr);
        }
        if let Some(limit) = domain.and_then(|d| d.http_rate).or(policy.http_rate) {
            let key = match policy.key {
                RateLimitKey::TenantHostnameIp => {
                    self.http_buckets
                        .key((ctx.tenant_id, ctx.hostname, ctx.client_ip))
                }
                RateLimitKey::ClientIp => self.http_buckets.key(ctx.client_ip),
            };
            let taken = self.http_buckets.take(
                key,
                limit,
                1.0,
                self.clock.now(),
                policy.max_entries,
                policy.idle_ttl,
            );
            if let Err(e) = taken {
                return limited(e);
            }
        }

        Decision::Allow
    }

    /// Run the plugins that apply to the request on a blocking thread.
    async fn decide_plugins(&self, ctx: &RequestContext<'_>) -> Decision {
        let plugins = self.plugins.load_full();
        let Some(job) = plugins.prepare(ctx) else {
            return Decision::Allow;
        };
        let evaluated = tokio::task::spawn_blocking(move || plugins.evaluate_prepared(&job)).await;
        let verdict = match evaluated {
            Ok(verdict) => verdict,
            Err(e) => {
                tracing::warn!(error = %e, hostname = ctx.hostname, "policy plugin evaluation did not finish");
                return Decision::Unavailable(Reason::PluginFailure);
            }
        };
        match verdict {
            PluginVerdict::Allow => Decision::Allow,
            PluginVerdict::Deny { plugin } => {
                tracing::debug!(plugin, hostname = ctx.hostname, "request denied by plugin");
                Decision::Deny(Reason::Plugin)
            }
            PluginVerdict::Failed { plugin, failure } => {
                edge_metrics::get()
                    .policy_plugin_failures_total
                    .with_label_values(&[&plugin, failure.as_str()])
                    .inc();
                tracing::warn!(
                    plugin,
                    failure = failure.as_str(),
                    hostname = ctx.hostname,
                    "policy plugin failed"
                );
                Decision::Unavailable(Reason::PluginFailure)
            }
        }
    }

    /// Admit a raw TCP connection. The permit must be held for the connection's lifetime.
    pub fn admit_tcp(
        self: &Arc<Self>,
        listener: &str,
        client_ip: IpAddr,
    ) -> (Verdict, Option<TcpPermit>) {
        let policy = self.compiled.load();
        if !policy.enabled {
            return (Verdict::allow(), None);
        }
        let started = Instant::now();
        let client_ip = client_ip.to_canonical();
        let mut permit = None;
        let mut decision = if contains(&policy.blocked, client_ip) {
            Decision::Deny(Reason::BlockedCidr)
        } else if let Some(limit) = policy.tcp.connection_rate {
            let key = self.tcp_buckets.key((listener, client_ip));
            match self.tcp_buckets.take(
                key,
                limit,
                1.0,
                self.clock.now(),
                policy.max_entries,
                policy.idle_ttl,
            ) {
                Ok(()) => Decision::Allow,
                Err(e) => limited(e),
            }
        } else {
            Decision::Allow
        };

        if decision == Decision::Allow {
            match self.acquire_tcp(&policy.tcp, listener, client_ip) {
                Some(acquired) => permit = Some(acquired),
                None => decision = Decision::Deny(Reason::ConcurrencyLimit),
            }
        }
        let verdict = Verdict {
            decision,
            enforced: policy.mode == PolicyMode::Enforce,
        };
        observe(Protocol::Tcp, verdict, started);
        if decision != Decision::Allow {
            tracing::debug!(listener, client_ip = %client_ip, reason = decision.labels().1, enforced = verdict.enforced, "TCP connection policy decision");
        }
        (verdict, permit)
    }

    fn acquire_tcp(
        self: &Arc<Self>,
        limits: &CompiledTcp,
        listener: &str,
        client_ip: IpAddr,
    ) -> Option<TcpPermit> {
        let listener_key = self.key_hasher.hash_one(listener);
        let ip_key = self.key_hasher.hash_one((listener, client_ip));
        let mut permit = TcpPermit {
            policy: self.clone(),
            ip_key: None,
            listener_key: None,
        };
        if let Some(max) = limits.max_concurrent_per_listener {
            if !acquire(&self.tcp_listener_active, listener_key, max) {
                return None;
            }
            permit.listener_key = Some(listener_key);
        }
        if let Some(max) = limits.max_concurrent_per_ip {
            // Dropping `permit` releases the listener slot acquired above.
            if !acquire(&self.tcp_ip_active, ip_key, max) {
                return None;
            }
            permit.ip_key = Some(ip_key);
        }
        Some(permit)
    }

    /// Admit a UDP datagram before any routing work or state allocation.
    pub fn admit_udp(&self, listener: &str, client_ip: IpAddr, size: usize) -> Verdict {
        let policy = self.compiled.load();
        if !policy.enabled {
            return Verdict::allow();
        }
        let started = Instant::now();
        let client_ip = client_ip.to_canonical();
        let now = self.clock.now();
        let decision = if contains(&policy.blocked, client_ip) {
            Decision::Deny(Reason::BlockedCidr)
        } else {
            let packets = policy.udp.packet_rate.map(|limit| {
                let key = self.udp_packet_buckets.key((listener, client_ip));
                self.udp_packet_buckets.take(
                    key,
                    limit,
                    1.0,
                    now,
                    policy.max_entries,
                    policy.idle_ttl,
                )
            });
            let bytes = match packets {
                Some(Err(_)) => None,
                _ => policy.udp.byte_rate.map(|limit| {
                    let key = self.udp_byte_buckets.key((listener, client_ip));
                    self.udp_byte_buckets.take(
                        key,
                        limit,
                        size as f64,
                        now,
                        policy.max_entries,
                        policy.idle_ttl,
                    )
                }),
            };
            match (packets, bytes) {
                (Some(Err(e)), _) | (_, Some(Err(e))) => limited(e),
                _ => Decision::Allow,
            }
        };
        let verdict = Verdict {
            decision,
            enforced: policy.mode == PolicyMode::Enforce,
        };
        observe(Protocol::Udp, verdict, started);
        verdict
    }

    /// Drop idle buckets and publish table sizes.
    pub fn sweep(&self) {
        let policy = self.compiled.load();
        let now = self.clock.now();
        let m = edge_metrics::get();
        for table in [
            &self.http_buckets,
            &self.tcp_buckets,
            &self.udp_packet_buckets,
            &self.udp_byte_buckets,
        ] {
            table.sweep(now, policy.idle_ttl);
            m.policy_buckets
                .with_label_values(&[table.name])
                .set(table.buckets.len() as i64);
        }
    }
}

/// Plugins are compiled only for an enabled policy.
fn load_plugins(cfg: &PolicyConfig, cache: &ModuleCache) -> anyhow::Result<PluginSet> {
    if cfg.enabled {
        PluginSet::load(&cfg.plugins, cache)
    } else {
        Ok(PluginSet::default())
    }
}

fn limited(error: TakeError) -> Decision {
    match error {
        TakeError::Limited { wait_secs } => Decision::RateLimited {
            reason: Reason::RateLimit,
            retry_after_secs: wait_secs.ceil().max(1.0) as u64,
        },
        TakeError::Capacity => Decision::RateLimited {
            reason: Reason::Capacity,
            retry_after_secs: 1,
        },
    }
}

fn observe(protocol: Protocol, verdict: Verdict, started: Instant) {
    let m = edge_metrics::get();
    let (decision, reason) = verdict.decision.labels();
    let mode = if verdict.enforced {
        "enforce"
    } else {
        "monitor"
    };
    let protocol = protocol.to_string();
    m.policy_decisions_total
        .with_label_values(&[&protocol, decision, reason, mode])
        .inc();
    m.policy_evaluation_seconds
        .with_label_values(&[&protocol])
        .observe(started.elapsed().as_secs_f64());
}

#[cfg(test)]
pub mod test_clock {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::Clock;

    #[derive(Default)]
    pub struct ManualClock {
        nanos: AtomicU64,
    }

    impl ManualClock {
        pub fn advance(&self, by: Duration) {
            self.nanos.fetch_add(by.as_nanos() as u64, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.nanos.load(Ordering::SeqCst))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_clock::ManualClock;
    use super::*;
    use crate::config::{DomainPolicyConfig, TcpPolicyConfig, UdpPolicyConfig};

    fn config() -> PolicyConfig {
        PolicyConfig {
            enabled: true,
            ..PolicyConfig::default()
        }
    }

    fn ctx<'a>(tenant: &'a str, hostname: &'a str, ip: &str) -> RequestContext<'a> {
        RequestContext {
            tenant_id: tenant,
            hostname,
            protocol: Protocol::Http,
            client_ip: ip.parse().unwrap(),
            method: "GET",
            path: "/",
        }
    }

    fn policy(cfg: PolicyConfig) -> (Arc<Policy>, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        (Policy::with_clock(&cfg, clock.clone()).unwrap(), clock)
    }

    #[tokio::test]
    async fn burst_boundary_and_refill() {
        let mut cfg = config();
        cfg.requests_per_second = Some(2.0);
        cfg.burst = Some(3);
        let (policy, clock) = policy(cfg);
        let c = ctx("t", "a.test", "192.0.2.1");

        for _ in 0..3 {
            assert_eq!(policy.evaluate_http(&c).await.decision, Decision::Allow);
        }
        assert_eq!(
            policy.evaluate_http(&c).await.decision,
            Decision::RateLimited {
                reason: Reason::RateLimit,
                retry_after_secs: 1
            }
        );

        // 0.5s at 2 rps refills exactly one token.
        clock.advance(Duration::from_millis(500));
        assert_eq!(policy.evaluate_http(&c).await.decision, Decision::Allow);
        assert!(policy.evaluate_http(&c).await.rejects());

        // Refill never exceeds the burst.
        clock.advance(Duration::from_secs(60));
        let mut allowed = 0;
        for _ in 0..10 {
            if policy.evaluate_http(&c).await.decision == Decision::Allow {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_consume_atomically() {
        let mut cfg = config();
        cfg.requests_per_second = Some(0.001);
        cfg.burst = Some(50);
        let (policy, _clock) = policy(cfg);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let policy = policy.clone();
            tasks.push(tokio::spawn(async move {
                let mut allowed = 0;
                for _ in 0..100 {
                    if policy
                        .evaluate_http(&ctx("t", "a.test", "192.0.2.1"))
                        .await
                        .decision
                        == Decision::Allow
                    {
                        allowed += 1;
                    }
                }
                allowed
            }));
        }
        let mut allowed = 0;
        for task in tasks {
            allowed += task.await.unwrap();
        }
        assert_eq!(allowed, 50);
    }

    #[tokio::test]
    async fn keys_isolate_tenants_hostnames_and_clients() {
        let mut cfg = config();
        cfg.requests_per_second = Some(1.0);
        cfg.burst = Some(1);
        let (policy, _clock) = policy(cfg);
        assert!(!policy
            .evaluate_http(&ctx("t1", "a.test", "192.0.2.1"))
            .await
            .rejects());
        assert!(policy
            .evaluate_http(&ctx("t1", "a.test", "192.0.2.1"))
            .await
            .rejects());
        assert!(!policy
            .evaluate_http(&ctx("t2", "a.test", "192.0.2.1"))
            .await
            .rejects());
        assert!(!policy
            .evaluate_http(&ctx("t1", "b.test", "192.0.2.1"))
            .await
            .rejects());
        assert!(!policy
            .evaluate_http(&ctx("t1", "a.test", "192.0.2.2"))
            .await
            .rejects());
    }

    #[tokio::test]
    async fn blocks_ipv4_and_ipv6_cidrs_including_mapped_addresses() {
        let mut cfg = config();
        cfg.blocked_cidrs = vec![
            "192.0.2.0/24".into(),
            "2001:db8::/32".into(),
            "198.51.100.7".into(),
        ];
        let (policy, _clock) = policy(cfg);
        let denied = Decision::Deny(Reason::BlockedCidr);
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "192.0.2.200"))
                .await
                .decision,
            denied
        );
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "2001:db8::1"))
                .await
                .decision,
            denied
        );
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "198.51.100.7"))
                .await
                .decision,
            denied
        );
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "198.51.100.8"))
                .await
                .decision,
            Decision::Allow
        );

        let (verdict, _) = policy.admit_tcp("0.0.0.0:22", "::ffff:192.0.2.9".parse().unwrap());
        assert_eq!(verdict.decision, denied);
    }

    #[tokio::test]
    async fn domain_overrides_and_monitor_mode() {
        let mut cfg = config();
        cfg.requests_per_second = Some(100.0);
        cfg.domains = vec![
            DomainPolicyConfig {
                hostname: "*.strict.test".into(),
                mode: None,
                blocked_cidrs: vec!["203.0.113.0/24".into()],
                requests_per_second: Some(1.0),
                burst: Some(1),
            },
            DomainPolicyConfig {
                hostname: "watch.test".into(),
                mode: Some(PolicyMode::Monitor),
                blocked_cidrs: vec!["192.0.2.0/24".into()],
                requests_per_second: None,
                burst: None,
            },
        ];
        let (policy, _clock) = policy(cfg);
        assert!(policy
            .evaluate_http(&ctx("t", "api.strict.test", "203.0.113.1"))
            .await
            .rejects());
        assert!(!policy
            .evaluate_http(&ctx("t", "api.strict.test", "192.0.2.1"))
            .await
            .rejects());
        assert!(policy
            .evaluate_http(&ctx("t", "api.strict.test", "192.0.2.1"))
            .await
            .rejects());
        assert!(!policy
            .evaluate_http(&ctx("t", "other.test", "203.0.113.1"))
            .await
            .rejects());

        let verdict = policy
            .evaluate_http(&ctx("t", "watch.test", "192.0.2.1"))
            .await;
        assert_eq!(verdict.decision, Decision::Deny(Reason::BlockedCidr));
        assert!(!verdict.enforced);
        assert!(!verdict.rejects());
    }

    #[test]
    fn trusted_proxy_chain_is_walked_from_the_right() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let untrusted_peer: IpAddr = "198.51.100.1".parse().unwrap();

        // Untrusted peers cannot choose the client IP.
        assert_eq!(
            resolve_client_ip(untrusted_peer, &["192.0.2.1"], &trusted),
            untrusted_peer
        );
        // The rightmost untrusted hop is the client; earlier (spoofable) entries are ignored.
        assert_eq!(
            resolve_client_ip(peer, &["6.6.6.6, 192.0.2.1", "10.0.0.2"], &trusted),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            resolve_client_ip(peer, &["[2001:db8::1]:443"], &trusted),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        // Garbage stops the walk at the last trusted hop.
        assert_eq!(
            resolve_client_ip(peer, &["192.0.2.1, garbage"], &trusted),
            peer
        );
        assert_eq!(resolve_client_ip(peer, &[], &trusted), peer);
    }

    #[tokio::test]
    async fn bucket_capacity_rejects_new_keys_instead_of_allowing() {
        let mut cfg = config();
        cfg.requests_per_second = Some(1.0);
        cfg.burst = Some(5);
        cfg.max_entries = 2;
        cfg.idle_ttl_secs = 1;
        let (policy, clock) = policy(cfg);
        assert!(!policy
            .evaluate_http(&ctx("t", "a.test", "192.0.2.1"))
            .await
            .rejects());
        assert!(!policy
            .evaluate_http(&ctx("t", "a.test", "192.0.2.2"))
            .await
            .rejects());
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "192.0.2.3"))
                .await
                .decision,
            Decision::RateLimited {
                reason: Reason::Capacity,
                retry_after_secs: 1
            }
        );
        // Once existing buckets are idle long enough to be full again, they are reclaimed.
        clock.advance(Duration::from_secs(6));
        assert!(!policy
            .evaluate_http(&ctx("t", "a.test", "192.0.2.3"))
            .await
            .rejects());
    }

    #[tokio::test]
    async fn reload_validates_before_switching_and_keeps_buckets() {
        let mut cfg = config();
        cfg.requests_per_second = Some(1.0);
        cfg.burst = Some(2);
        let (policy, _clock) = policy(cfg.clone());
        let c = ctx("t", "a.test", "192.0.2.1");
        assert!(!policy.evaluate_http(&c).await.rejects());
        assert!(!policy.evaluate_http(&c).await.rejects());

        let mut invalid = cfg.clone();
        invalid.blocked_cidrs = vec!["not-a-cidr".into()];
        assert!(policy.reload(&invalid).is_err());
        assert!(
            policy.evaluate_http(&c).await.rejects(),
            "previous policy must stay active"
        );

        let mut monitor = cfg;
        monitor.mode = PolicyMode::Monitor;
        policy.reload(&monitor).unwrap();
        let verdict = policy.evaluate_http(&c).await;
        assert!(
            matches!(verdict.decision, Decision::RateLimited { .. }),
            "bucket state was reset"
        );
        assert!(!verdict.rejects());
    }

    #[test]
    fn tcp_concurrency_slots_are_released() {
        let mut cfg = config();
        cfg.tcp = TcpPolicyConfig {
            connections_per_second: None,
            connection_burst: None,
            max_concurrent_per_ip: Some(2),
            max_concurrent_per_listener: Some(3),
        };
        let (policy, _clock) = policy(cfg);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();

        let (_, p1) = policy.admit_tcp("l", ip);
        let (_, p2) = policy.admit_tcp("l", ip);
        let (v3, p3) = policy.admit_tcp("l", ip);
        assert_eq!(v3.decision, Decision::Deny(Reason::ConcurrencyLimit));
        assert!(p3.is_none());

        let (_, p4) = policy.admit_tcp("l", other);
        let (v5, _) = policy.admit_tcp("l", other);
        assert_eq!(
            v5.decision,
            Decision::Deny(Reason::ConcurrencyLimit),
            "listener limit"
        );

        drop(p1);
        let (v6, p6) = policy.admit_tcp("l", ip);
        assert_eq!(v6.decision, Decision::Allow);
        drop((p2, p4, p6));
        assert!(policy.tcp_ip_active.is_empty());
        assert!(policy.tcp_listener_active.is_empty());
    }

    #[test]
    fn udp_packet_and_byte_limits() {
        let mut cfg = config();
        cfg.udp = UdpPolicyConfig {
            packets_per_second: Some(1.0),
            packet_burst: Some(3),
            bytes_per_second: Some(1000.0),
            byte_burst: Some(70_000),
        };
        let (policy, clock) = policy(cfg);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(!policy.admit_udp("u", ip, 60_000).rejects());
        assert!(
            policy.admit_udp("u", ip, 20_000).rejects(),
            "byte budget exhausted"
        );
        assert!(!policy.admit_udp("u", ip, 5_000).rejects());
        assert!(
            policy.admit_udp("u", ip, 1).rejects(),
            "packet budget exhausted"
        );
        clock.advance(Duration::from_secs(1));
        assert!(!policy.admit_udp("u", ip, 100).rejects());
    }

    fn plugin_config(name: &str, source: &str) -> crate::config::PluginConfig {
        let path = std::env::temp_dir().join(format!(
            "sievetube-policy-plugin-{}.wat",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, source).unwrap();
        crate::config::PluginConfig {
            name: name.to_string(),
            path: path.display().to_string(),
            sha256: crate::plugins::sha256_hex(source.as_bytes()),
            applies_to: Vec::new(),
            max_memory_bytes: 1024 * 1024,
            fuel: 1_000_000,
            timeout_ms: 1000,
            max_concurrent: 4,
        }
    }

    #[tokio::test]
    async fn a_spinning_plugin_does_not_block_the_runtime() {
        use crate::plugins::test_modules;
        let mut cfg = config();
        // Spins until the wall-clock deadline instead of running out of fuel.
        let mut spin = plugin_config(
            "spin",
            &test_modules::module(1, "(loop (br 0)) (i32.const 0)", ""),
        );
        spin.timeout_ms = 400;
        spin.fuel = 10_000_000_000;
        cfg.plugins = vec![spin];
        let (policy, _clock) = policy(cfg);

        // This single-threaded runtime has nothing else to run the timer on, so
        // the tick can only be observed early if the plugin runs elsewhere.
        let started = Instant::now();
        let tick = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            started.elapsed()
        });
        let verdict = policy.evaluate_http(&ctx("t", "a.test", "192.0.2.1")).await;
        assert_eq!(
            verdict.decision,
            Decision::Unavailable(Reason::PluginFailure),
            "the deadline fails the request"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "the plugin ran to its deadline"
        );
        let ticked_after = tick.await.unwrap();
        assert!(
            ticked_after < Duration::from_millis(200),
            "the runtime kept making progress while the plugin ran, but the timer              fired only after {ticked_after:?}"
        );
    }

    #[tokio::test]
    async fn plugins_run_after_builtin_rules_and_reload_keeps_previous_set() {
        use crate::plugins::test_modules;
        let mut cfg = config();
        cfg.blocked_cidrs = vec!["203.0.113.0/24".into()];
        cfg.plugins = vec![plugin_config("admin", &test_modules::deny_admin_paths())];
        let (policy, _clock) = policy(cfg.clone());

        let mut admin = ctx("t", "a.test", "192.0.2.1");
        admin.path = "/admin";
        assert_eq!(
            policy.evaluate_http(&admin).await.decision,
            Decision::Deny(Reason::Plugin)
        );
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "192.0.2.1"))
                .await
                .decision,
            Decision::Allow
        );
        // Built-in rules decide first.
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "203.0.113.1"))
                .await
                .decision,
            Decision::Deny(Reason::BlockedCidr)
        );

        // A plugin that traps fails the request instead of allowing it.
        let mut failing = cfg.clone();
        failing.plugins = vec![plugin_config(
            "crash",
            &test_modules::module(1, "(unreachable)", ""),
        )];
        policy.reload(&failing).unwrap();
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "192.0.2.1"))
                .await
                .decision,
            Decision::Unavailable(Reason::PluginFailure)
        );

        // An invalid plugin is rejected and the running set stays.
        let mut broken = cfg;
        broken.plugins = vec![plugin_config(
            "v9",
            &test_modules::module(9, "(i32.const 0)", ""),
        )];
        assert!(policy.reload(&broken).is_err());
        assert_eq!(
            policy
                .evaluate_http(&ctx("t", "a.test", "192.0.2.1"))
                .await
                .decision,
            Decision::Unavailable(Reason::PluginFailure)
        );
    }

    #[test]
    fn validation_errors() {
        let mut cfg = config();
        cfg.burst = Some(5);
        assert!(compile(&cfg).is_err(), "burst without rate");

        let mut cfg = config();
        cfg.requests_per_second = Some(-1.0);
        assert!(compile(&cfg).is_err());

        let mut cfg = config();
        cfg.udp.bytes_per_second = Some(10.0);
        cfg.udp.byte_burst = Some(100);
        assert!(compile(&cfg).is_err());

        let mut cfg = config();
        cfg.domains = vec![
            DomainPolicyConfig {
                hostname: "a.test".into(),
                mode: None,
                blocked_cidrs: vec![],
                requests_per_second: None,
                burst: None,
            },
            DomainPolicyConfig {
                hostname: "A.test.".into(),
                mode: None,
                blocked_cidrs: vec![],
                requests_per_second: None,
                burst: None,
            },
        ];
        assert!(compile(&cfg).is_err(), "duplicate normalized domain");
    }
}

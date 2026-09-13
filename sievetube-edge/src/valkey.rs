use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::AsyncCommands;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use crate::mesh::routes::{EdgeInfo, RouteAd};

/// Atomically claim every hostname for a tenant, or none of them.
///
/// KEYS: owner keys, ARGV[1]: tenant id.
/// Returns `{0, ""}` on success or `{index, owner}` for the first conflicting key.
static CLAIM_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
for i, key in ipairs(KEYS) do
  local owner = redis.call('GET', key)
  if owner and owner ~= ARGV[1] then
    return {i, owner}
  end
end
for _, key in ipairs(KEYS) do
  redis.call('SET', key, ARGV[1], 'NX')
end
return {0, ''}
"#,
    )
});

/// Administrative ownership changes are compare-and-set operations: a typo or
/// stale operator view cannot release or overwrite another tenant's hostname.
static OWNER_RELEASE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0",
    )
});

static OWNER_TRANSFER_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('SET', KEYS[1], ARGV[2]); return 1 end return 0",
    )
});

/// Acquire or extend a lease. The value is `<owner>|<generation>`; a new holder gets
/// a generation greater than any previous one (and at least `min_generation`), which
/// callers use as a fencing token.
///
/// KEYS: lease key, generation counter. ARGV: owner, ttl ms, min generation.
/// Returns the generation, or -1 if another owner holds the lease.
static LEASE_ACQUIRE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
local current = redis.call('GET', KEYS[1])
if current then
  local owner, generation = string.match(current, '^(.*)|(%d+)$')
  if owner == ARGV[1] then
    redis.call('PEXPIRE', KEYS[1], ARGV[2])
    return tonumber(generation)
  end
  return -1
end
local generation = redis.call('INCR', KEYS[2])
if generation < tonumber(ARGV[3]) then
  generation = tonumber(ARGV[3])
  redis.call('SET', KEYS[2], generation)
end
redis.call('SET', KEYS[1], ARGV[1] .. '|' .. generation, 'PX', ARGV[2])
return generation
"#,
    )
});

static LEASE_CHECK_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new("if redis.call('GET', KEYS[1]) == ARGV[1] then return 1 end return 0")
});

static LEASE_RELEASE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0",
    )
});

/// Replace every route belonging to one Edge and refresh the desired set.
///
/// Replaces this Edge's advertised routes.
///
/// Each Edge keeps the members it advertised in a set of its own, so replacing
/// its routes touches only those instead of decoding every route of every Edge
/// on each refresh. The set expires with the routes, so that of a crashed Edge
/// disappears on its own.
///
/// KEYS: routes zset, this Edge's member set.
/// ARGV: notification channel, now ms, expiry ms, ttl ms, locally-changed flag,
/// serialized ads...
static ROUTES_REPLACE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
local desired = {}
for i = 6, #ARGV do
  desired[ARGV[i]] = true
end
local removed = 0
for _, member in ipairs(redis.call('SMEMBERS', KEYS[2])) do
  if not desired[member] then
    removed = removed + redis.call('ZREM', KEYS[1], member)
    redis.call('SREM', KEYS[2], member)
  end
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
for i = 6, #ARGV do
  redis.call('ZADD', KEYS[1], ARGV[3], ARGV[i])
  redis.call('SADD', KEYS[2], ARGV[i])
end
if #ARGV >= 6 then
  redis.call('PEXPIRE', KEYS[2], ARGV[4])
end
if removed > 0 or ARGV[5] == '1' then
  redis.call('PUBLISH', ARGV[1], 'routes')
end
return removed
"#,
    )
});

#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    #[error("control plane unavailable: {0}")]
    Unavailable(String),
}

impl From<redis::RedisError> for ControlPlaneError {
    fn from(e: redis::RedisError) -> Self {
        ControlPlaneError::Unavailable(e.to_string())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Claimed,
    Conflict { hostname: String },
}

/// Handle to the Valkey control plane. The connection is established lazily and
/// retried in the background; operations fail with [`ControlPlaneError`] until
/// it is available so that callers can stop making new changes.
#[derive(Clone)]
pub struct ValkeyHandle {
    inner: Arc<Inner>,
}

struct Inner {
    client: redis::Client,
    conn: OnceCell<ConnectionManager>,
    /// Whether the last round trip succeeded. The connection manager reconnects
    /// silently, so having connected once says nothing about reachability now.
    healthy: AtomicBool,
    edge_id: String,
    /// hostname → tenant ownership confirmed by Valkey during this process lifetime
    confirmed: Mutex<HashMap<String, ConfirmedOwner>>,
    /// Digest of the last published route set, so that the change notification
    /// is sent when routes change instead of on every refresh
    published_routes: Mutex<Option<u64>>,
}

struct ConfirmedOwner {
    tenant_id: String,
    confirmed_at: std::time::Instant,
}

/// Valkey outages may briefly use a prior ownership result so existing tunnels
/// can reconnect, but never indefinitely after an administrative transfer.
const OWNERSHIP_CACHE_TTL: Duration = Duration::from_secs(60);

impl ValkeyHandle {
    pub fn new(url: &str, edge_id: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(ValkeyHandle {
            inner: Arc::new(Inner {
                client,
                conn: OnceCell::new(),
                healthy: AtomicBool::new(false),
                edge_id: edge_id.to_string(),
                confirmed: Mutex::new(HashMap::new()),
                published_routes: Mutex::new(None),
            }),
        })
    }

    pub fn edge_id(&self) -> &str {
        &self.inner.edge_id
    }

    /// Whether the control plane is reachable right now, as of the last round
    /// trip. Callers use it to stop making changes they cannot coordinate.
    pub fn is_connected(&self) -> bool {
        self.inner.conn.initialized() && self.inner.healthy.load(Ordering::Relaxed)
    }

    pub async fn try_connect(&self) -> Result<(), ControlPlaneError> {
        if self.inner.conn.initialized() {
            // The manager reconnects on its own; only a round trip confirms it.
            return self.ping().await;
        }
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_secs(5))
            .set_response_timeout(Duration::from_secs(5))
            .set_number_of_retries(1);
        let manager = ConnectionManager::new_with_config(self.inner.client.clone(), config).await?;
        let _ = self.inner.conn.set(manager);
        self.inner.healthy.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// One round trip, which is also what [`ValkeyHandle::is_connected`] reports.
    pub async fn ping(&self) -> Result<(), ControlPlaneError> {
        let result = async {
            let mut conn = self.connection()?;
            redis::cmd("PING").query_async::<()>(&mut conn).await?;
            Ok(())
        }
        .await;
        self.inner.healthy.store(result.is_ok(), Ordering::Relaxed);
        result
    }

    /// Keep the reachability answer current for as long as the process runs.
    pub async fn liveness_loop(self, interval: Duration, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            let was_connected = self.is_connected();
            match tokio::time::timeout(interval, self.ping()).await {
                Ok(Ok(())) => {
                    if !was_connected {
                        tracing::info!("valkey is reachable");
                    }
                }
                Ok(Err(e)) => {
                    if was_connected {
                        tracing::warn!(error = %e, "valkey is not reachable; coordinated changes are paused");
                    }
                }
                Err(_) => {
                    self.inner.healthy.store(false, Ordering::Relaxed);
                    if was_connected {
                        tracing::warn!(
                            "valkey did not answer in time; coordinated changes are paused"
                        );
                    }
                }
            }
        }
    }

    /// Retry the initial connection until it succeeds or shutdown is requested.
    pub async fn connect_loop(self, shutdown: CancellationToken) {
        let mut backoff = Duration::from_millis(500);
        loop {
            match self.try_connect().await {
                Ok(()) => {
                    tracing::info!("connected to valkey");
                    return;
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    retry_in_ms = backoff.as_millis() as u64,
                    "valkey unavailable; new hostname claims are paused"
                ),
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    pub fn connection(&self) -> Result<ConnectionManager, ControlPlaneError> {
        self.inner
            .conn
            .get()
            .cloned()
            .ok_or_else(|| ControlPlaneError::Unavailable("not connected".to_string()))
    }

    /// Atomically claim normalized hostnames for a tenant.
    pub async fn claim_hostnames(
        &self,
        tenant_id: &str,
        hostnames: &[String],
    ) -> Result<ClaimOutcome, ControlPlaneError> {
        if hostnames.is_empty() {
            return Ok(ClaimOutcome::Claimed);
        }
        let mut conn = self.connection()?;
        let mut invocation = CLAIM_SCRIPT.prepare_invoke();
        for hostname in hostnames {
            invocation.key(owner_key(hostname));
        }
        invocation.arg(tenant_id);
        let (index, _owner): (i64, String) = invocation.invoke_async(&mut conn).await?;
        if index > 0 {
            let hostname = hostnames
                .get(index as usize - 1)
                .cloned()
                .unwrap_or_default();
            return Ok(ClaimOutcome::Conflict { hostname });
        }

        let mut confirmed = self
            .inner
            .confirmed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for hostname in hostnames {
            confirmed.insert(
                hostname.clone(),
                ConfirmedOwner {
                    tenant_id: tenant_id.to_string(),
                    confirmed_at: std::time::Instant::now(),
                },
            );
        }
        Ok(ClaimOutcome::Claimed)
    }

    /// Whether Valkey confirmed these hostnames for the tenant earlier in this
    /// process. Used to let existing tenants reconnect while Valkey is down.
    pub fn previously_confirmed(&self, tenant_id: &str, hostnames: &[String]) -> bool {
        let mut confirmed = self
            .inner
            .confirmed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        confirmed.retain(|_, owner| owner.confirmed_at.elapsed() <= OWNERSHIP_CACHE_TTL);
        hostnames.iter().all(|h| {
            confirmed
                .get(h)
                .is_some_and(|owner| owner.tenant_id == tenant_id)
        })
    }

    /// Return the current owner of a normalized hostname.
    pub async fn hostname_owner(
        &self,
        hostname: &str,
    ) -> Result<Option<String>, ControlPlaneError> {
        let mut conn = self.connection()?;
        Ok(conn.get(owner_key(hostname)).await?)
    }

    /// Release only if `expected_tenant` is still the owner.
    pub async fn release_hostname_owner(
        &self,
        hostname: &str,
        expected_tenant: &str,
    ) -> Result<bool, ControlPlaneError> {
        let mut conn = self.connection()?;
        let changed: i64 = OWNER_RELEASE_SCRIPT
            .key(owner_key(hostname))
            .arg(expected_tenant)
            .invoke_async(&mut conn)
            .await?;
        self.inner
            .confirmed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(hostname);
        Ok(changed == 1)
    }

    /// Transfer only if `expected_tenant` is still the owner.
    pub async fn transfer_hostname_owner(
        &self,
        hostname: &str,
        expected_tenant: &str,
        new_tenant: &str,
    ) -> Result<bool, ControlPlaneError> {
        let mut conn = self.connection()?;
        let changed: i64 = OWNER_TRANSFER_SCRIPT
            .key(owner_key(hostname))
            .arg(expected_tenant)
            .arg(new_tenant)
            .invoke_async(&mut conn)
            .await?;
        self.inner
            .confirmed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(hostname);
        Ok(changed == 1)
    }

    /// Record that the tenant has a Connector on this Edge (visibility only).
    ///
    /// Key: `sievetube:tenant:<tenant_id>:edges` → SET of edge_ids
    pub async fn register_presence(&self, tenant_id: &str) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        conn.sadd::<_, _, ()>(edges_key(tenant_id), &self.inner.edge_id)
            .await?;
        Ok(())
    }

    pub async fn deregister_presence(&self, tenant_id: &str) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        conn.srem::<_, _, ()>(edges_key(tenant_id), &self.inner.edge_id)
            .await?;
        Ok(())
    }

    /// Acquire or extend the lease on `resource`. Returns the fencing generation,
    /// or `None` when another Edge holds it.
    pub async fn acquire_lease(
        &self,
        resource: &str,
        ttl: Duration,
        min_generation: u64,
    ) -> Result<Option<u64>, ControlPlaneError> {
        let mut conn = self.connection()?;
        let generation: i64 = LEASE_ACQUIRE_SCRIPT
            .key(lease_key(resource))
            .key(lease_generation_key(resource))
            .arg(&self.inner.edge_id)
            .arg(ttl.as_millis() as u64)
            .arg(min_generation)
            .invoke_async(&mut conn)
            .await?;
        Ok(u64::try_from(generation).ok())
    }

    /// Whether this Edge still holds `resource` with `generation`.
    pub async fn check_lease(
        &self,
        resource: &str,
        generation: u64,
    ) -> Result<bool, ControlPlaneError> {
        let mut conn = self.connection()?;
        let held: i64 = LEASE_CHECK_SCRIPT
            .key(lease_key(resource))
            .arg(format!("{}|{generation}", self.inner.edge_id))
            .invoke_async(&mut conn)
            .await?;
        Ok(held == 1)
    }

    /// Which Edge currently holds the lease on `resource`, if any.
    pub async fn lease_owner(&self, resource: &str) -> Result<Option<String>, ControlPlaneError> {
        let mut conn = self.connection()?;
        let value: Option<String> = conn.get(lease_key(resource)).await?;
        Ok(value.and_then(|value| {
            value
                .rsplit_once('|')
                .map(|(owner, _generation)| owner.to_string())
        }))
    }

    pub async fn release_lease(
        &self,
        resource: &str,
        generation: u64,
    ) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        let _: i64 = LEASE_RELEASE_SCRIPT
            .key(lease_key(resource))
            .arg(format!("{}|{generation}", self.inner.edge_id))
            .invoke_async(&mut conn)
            .await?;
        Ok(())
    }
}

/// Live Edges: ZSET of edge ids scored by presence expiry (unix ms).
const EDGES_KEY: &str = "sievetube:edges";
/// Published HTTP-01 challenges: ZSET of "<domain> <token>" scored by expiry (unix ms).
const HTTP01_KEY: &str = "sievetube:acme:http01";
/// Edges that answer published HTTP-01 challenges: ZSET scored by expiry (unix ms).
const HTTP01_RESPONDERS_KEY: &str = "sievetube:acme:http01:responders";

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn http01_value_key(domain: &str, token: &str) -> String {
    format!("{HTTP01_KEY}:{domain}:{token}")
}

fn http01_acks_key(domain: &str, token: &str) -> String {
    format!("{HTTP01_KEY}:{domain}:{token}:acks")
}

impl ValkeyHandle {
    /// Announce that this Edge is alive for `ttl`.
    pub async fn heartbeat_presence(&self, ttl: Duration) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        let now = unix_ms();
        redis::pipe()
            .atomic()
            .zadd(EDGES_KEY, &self.inner.edge_id, now + ttl.as_millis() as u64)
            .zrembyscore(EDGES_KEY, "-inf", now)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn remove_presence(&self) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        conn.zrem::<_, _, ()>(EDGES_KEY, &self.inner.edge_id)
            .await?;
        Ok(())
    }

    /// Edge ids whose presence has not expired.
    pub async fn live_edges(&self) -> Result<Vec<String>, ControlPlaneError> {
        let mut conn = self.connection()?;
        let edges: Vec<String> = conn.zrangebyscore(EDGES_KEY, unix_ms(), "+inf").await?;
        Ok(edges)
    }

    /// Publish an HTTP-01 response for every Edge; the publisher acknowledges it itself.
    pub async fn publish_http01(
        &self,
        domain: &str,
        token: &str,
        key_authorization: &str,
        ttl: Duration,
    ) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        let ttl_ms = ttl.as_millis() as u64;
        let acks = http01_acks_key(domain, token);
        redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(http01_value_key(domain, token))
            .arg(key_authorization)
            .arg("PX")
            .arg(ttl_ms)
            .del(&acks)
            .sadd(&acks, &self.inner.edge_id)
            .pexpire(&acks, ttl_ms as i64)
            .zadd(HTTP01_KEY, format!("{domain} {token}"), unix_ms() + ttl_ms)
            .zrembyscore(HTTP01_KEY, "-inf", unix_ms())
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn unpublish_http01(
        &self,
        domain: &str,
        token: &str,
    ) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        redis::pipe()
            .atomic()
            .del(http01_value_key(domain, token))
            .del(http01_acks_key(domain, token))
            .zrem(HTTP01_KEY, format!("{domain} {token}"))
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Currently published challenges as (domain, token, key authorization).
    pub async fn pending_http01(&self) -> Result<Vec<(String, String, String)>, ControlPlaneError> {
        let mut conn = self.connection()?;
        let members: Vec<String> = conn.zrangebyscore(HTTP01_KEY, unix_ms(), "+inf").await?;
        let mut pending = Vec::new();
        for member in members {
            let Some((domain, token)) = member.split_once(' ') else {
                continue;
            };
            let value: Option<String> = conn.get(http01_value_key(domain, token)).await?;
            if let Some(value) = value {
                pending.push((domain.to_string(), token.to_string(), value));
            }
        }
        Ok(pending)
    }

    /// Confirm that this Edge serves the challenge response.
    pub async fn ack_http01(&self, domain: &str, token: &str) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        let acks = http01_acks_key(domain, token);
        redis::pipe()
            .sadd(&acks, &self.inner.edge_id)
            .pexpire(&acks, 600_000)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn http01_acks(
        &self,
        domain: &str,
        token: &str,
    ) -> Result<Vec<String>, ControlPlaneError> {
        let mut conn = self.connection()?;
        let acks: Vec<String> = conn.smembers(http01_acks_key(domain, token)).await?;
        Ok(acks)
    }

    /// Announce that this Edge answers published HTTP-01 challenges. Only these
    /// Edges are expected to confirm a challenge, since an Edge without ACME
    /// never serves one.
    pub async fn heartbeat_http01_responder(&self, ttl: Duration) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        let now = unix_ms();
        redis::pipe()
            .atomic()
            .zadd(
                HTTP01_RESPONDERS_KEY,
                &self.inner.edge_id,
                now + ttl.as_millis() as u64,
            )
            .zrembyscore(HTTP01_RESPONDERS_KEY, "-inf", now)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn remove_http01_responder(&self) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        conn.zrem::<_, _, ()>(HTTP01_RESPONDERS_KEY, &self.inner.edge_id)
            .await?;
        Ok(())
    }

    /// Edges whose HTTP-01 responder announcement has not expired.
    pub async fn http01_responders(&self) -> Result<Vec<String>, ControlPlaneError> {
        let mut conn = self.connection()?;
        let edges: Vec<String> = conn
            .zrangebyscore(HTTP01_RESPONDERS_KEY, unix_ms(), "+inf")
            .await?;
        Ok(edges)
    }
}

/// Advertised mesh routes: ZSET of serialized [`RouteAd`] scored by expiry (unix ms).
const MESH_ROUTES_KEY: &str = "sievetube:mesh:routes";
/// Peers publish here when routes change, so others can sync earlier than their timer.
const MESH_ROUTES_CHANNEL: &str = "sievetube:mesh:routes:changed";

fn mesh_edge_key(edge_id: &str) -> String {
    format!("sievetube:mesh:edge:{edge_id}")
}

/// Members of [`MESH_ROUTES_KEY`] advertised by one Edge.
fn mesh_edge_routes_key(edge_id: &str) -> String {
    format!("sievetube:mesh:edge:{edge_id}:routes")
}

impl ValkeyHandle {
    /// Publish how peers can reach this Edge. Expires unless refreshed.
    pub async fn publish_edge_info(
        &self,
        info: &EdgeInfo,
        ttl: Duration,
    ) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        let payload = serde_json::to_string(info)
            .map_err(|e| ControlPlaneError::Unavailable(e.to_string()))?;
        redis::cmd("SET")
            .arg(mesh_edge_key(&self.inner.edge_id))
            .arg(payload)
            .arg("PX")
            .arg(ttl.as_millis() as u64)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn remove_edge_info(&self) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        conn.del::<_, ()>(mesh_edge_key(&self.inner.edge_id))
            .await?;
        Ok(())
    }

    pub async fn fetch_edge_infos(
        &self,
        edges: &HashSet<String>,
    ) -> Result<HashMap<String, EdgeInfo>, ControlPlaneError> {
        if edges.is_empty() {
            return Ok(HashMap::new());
        }
        let mut conn = self.connection()?;
        let ids: Vec<&String> = edges.iter().collect();
        let keys: Vec<String> = ids.iter().map(|id| mesh_edge_key(id)).collect();
        let payloads: Vec<Option<String>> = conn.mget(keys).await?;
        Ok(ids
            .into_iter()
            .zip(payloads)
            .filter_map(|(id, payload)| {
                let info = serde_json::from_str::<EdgeInfo>(payload.as_deref()?).ok()?;
                Some((id.clone(), info))
            })
            .collect())
    }

    /// Advertise routes with an expiry; re-advertising refreshes them.
    ///
    /// The change notification is sent only when the advertised set differs from
    /// the last published one. Notifying on every refresh would wake all peers
    /// into a full resync, so control-plane work would grow with the square of
    /// the number of Edges instead of with actual topology changes.
    pub async fn publish_routes(
        &self,
        ads: &[RouteAd],
        ttl: Duration,
    ) -> Result<(), ControlPlaneError> {
        let mut conn = self.connection()?;
        let now = unix_ms();
        let mut members = Vec::with_capacity(ads.len());
        for ad in ads {
            members.push(
                serde_json::to_string(ad)
                    .map_err(|e| ControlPlaneError::Unavailable(e.to_string()))?,
            );
        }
        let digest = digest_members(&members);
        let changed = *self.published_routes() != Some(digest);

        let ttl_ms = ttl.as_millis() as u64;
        let mut invocation = ROUTES_REPLACE_SCRIPT.prepare_invoke();
        invocation
            .key(MESH_ROUTES_KEY)
            .key(mesh_edge_routes_key(&self.inner.edge_id))
            .arg(MESH_ROUTES_CHANNEL)
            .arg(now)
            .arg(now + ttl_ms)
            .arg(ttl_ms)
            .arg(if changed && !ads.is_empty() { 1 } else { 0 });
        for member in &members {
            invocation.arg(member);
        }
        let _: i64 = invocation.invoke_async(&mut conn).await?;
        *self.published_routes() = Some(digest);
        Ok(())
    }

    fn published_routes(&self) -> std::sync::MutexGuard<'_, Option<u64>> {
        self.inner
            .published_routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Withdraw exactly these advertisements (same generation), leaving newer ones.
    pub async fn withdraw_routes(&self, ads: &[RouteAd]) -> Result<(), ControlPlaneError> {
        if ads.is_empty() {
            return Ok(());
        }
        let mut conn = self.connection()?;
        let mut pipe = redis::pipe();
        pipe.atomic();
        let own = mesh_edge_routes_key(&self.inner.edge_id);
        for ad in ads {
            let member = serde_json::to_string(ad)
                .map_err(|e| ControlPlaneError::Unavailable(e.to_string()))?;
            pipe.zrem(MESH_ROUTES_KEY, &member);
            pipe.srem(&own, member);
        }
        pipe.publish(MESH_ROUTES_CHANNEL, "routes");
        pipe.query_async::<()>(&mut conn).await?;
        // The advertised set changed, so the next refresh notifies again.
        *self.published_routes() = None;
        Ok(())
    }

    /// All unexpired advertisements with their expiry (unix ms).
    pub async fn fetch_routes(&self) -> Result<Vec<(RouteAd, u64)>, ControlPlaneError> {
        let mut conn = self.connection()?;
        let entries: Vec<(String, u64)> = redis::cmd("ZRANGEBYSCORE")
            .arg(MESH_ROUTES_KEY)
            .arg(unix_ms())
            .arg("+inf")
            .arg("WITHSCORES")
            .query_async(&mut conn)
            .await?;
        Ok(entries
            .into_iter()
            .filter_map(|(member, expiry)| {
                Some((serde_json::from_str::<RouteAd>(&member).ok()?, expiry))
            })
            .collect())
    }

    /// Subscription that yields a message whenever a peer changes its routes.
    pub async fn route_change_subscriber(&self) -> Result<redis::aio::PubSub, ControlPlaneError> {
        let mut pubsub = self.inner.client.get_async_pubsub().await?;
        pubsub.subscribe(MESH_ROUTES_CHANNEL).await?;
        Ok(pubsub)
    }
}

/// Order-independent digest of an advertised route set.
fn digest_members(members: &[String]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut sorted: Vec<&String> = members.iter().collect();
    sorted.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for member in sorted {
        member.hash(&mut hasher);
    }
    hasher.finish()
}

fn lease_key(resource: &str) -> String {
    format!("sievetube:lease:{resource}")
}

fn lease_generation_key(resource: &str) -> String {
    format!("sievetube:lease:{resource}:generation")
}

/// Key: `sievetube:hostname:<hostname>:owner` → tenant_id
pub fn owner_key(hostname: &str) -> String {
    format!("sievetube:hostname:{hostname}:owner")
}

fn edges_key(tenant_id: &str) -> String {
    format!("sievetube:tenant:{tenant_id}:edges")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against a real Valkey when `SIEVETUBE_TEST_VALKEY_URL` is set.
    async fn test_handle() -> Option<ValkeyHandle> {
        let url = std::env::var("SIEVETUBE_TEST_VALKEY_URL").ok()?;
        let handle = ValkeyHandle::new(&url, "edge-test").unwrap();
        handle.try_connect().await.unwrap();
        Some(handle)
    }

    #[tokio::test]
    async fn unavailable_until_connected() {
        let handle = ValkeyHandle::new("redis://127.0.0.1:1", "edge").unwrap();
        let err = handle
            .claim_hostnames("t1", &["a.test".to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, ControlPlaneError::Unavailable(_)));
        assert!(!handle.previously_confirmed("t1", &["a.test".to_string()]));
    }

    #[test]
    fn route_digest_ignores_order() {
        let ads = ["a".to_string(), "b".to_string()];
        let reordered = ["b".to_string(), "a".to_string()];
        assert_eq!(
            digest_members(&ads),
            digest_members(&reordered),
            "the same routes must not look like a change"
        );
        assert_ne!(digest_members(&ads), digest_members(&ads[..1]));
    }

    #[tokio::test]
    async fn claim_is_all_or_nothing() {
        let Some(handle) = test_handle().await else {
            eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let a = format!("a-{suffix}.test");
        let b = format!("b-{suffix}.test");

        assert_eq!(
            handle
                .claim_hostnames("t1", std::slice::from_ref(&a))
                .await
                .unwrap(),
            ClaimOutcome::Claimed
        );
        // t2 conflicts on `a`, so `b` must not be claimed either.
        assert_eq!(
            handle
                .claim_hostnames("t2", &[b.clone(), a.clone()])
                .await
                .unwrap(),
            ClaimOutcome::Conflict {
                hostname: a.clone()
            }
        );
        assert_eq!(
            handle
                .claim_hostnames("t3", std::slice::from_ref(&b))
                .await
                .unwrap(),
            ClaimOutcome::Claimed
        );
        assert!(handle.previously_confirmed("t1", &[a]));
    }

    #[tokio::test]
    async fn leases_are_exclusive_and_fenced() {
        let Some(edge_a) = test_handle().await else {
            eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
            return;
        };
        let url = std::env::var("SIEVETUBE_TEST_VALKEY_URL").unwrap();
        let edge_b = ValkeyHandle::new(&url, "edge-b").unwrap();
        edge_b.try_connect().await.unwrap();
        let resource = format!("test:{}", uuid::Uuid::new_v4());
        let ttl = Duration::from_secs(30);

        let first = edge_a
            .acquire_lease(&resource, ttl, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(edge_b.acquire_lease(&resource, ttl, 0).await.unwrap(), None);
        // Extending keeps the generation.
        assert_eq!(
            edge_a.acquire_lease(&resource, ttl, 0).await.unwrap(),
            Some(first)
        );
        assert!(edge_a.check_lease(&resource, first).await.unwrap());
        assert!(!edge_b.check_lease(&resource, first).await.unwrap());

        // A new holder always gets a larger generation, honoring the minimum.
        edge_b.release_lease(&resource, first).await.unwrap();
        assert!(
            edge_a.check_lease(&resource, first).await.unwrap(),
            "only the holder can release"
        );
        edge_a.release_lease(&resource, first).await.unwrap();
        let second = edge_b
            .acquire_lease(&resource, ttl, first + 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second, first + 10);
        assert!(!edge_a.check_lease(&resource, first).await.unwrap());

        // Expired leases can be taken over.
        edge_b.release_lease(&resource, second).await.unwrap();
        let short = edge_a
            .acquire_lease(&resource, Duration::from_millis(100), 0)
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let third = edge_b
            .acquire_lease(&resource, ttl, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(third > short);
    }

    #[tokio::test]
    async fn publishing_routes_replaces_stale_routes_for_the_edge() {
        let Some(base) = test_handle().await else {
            eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
            return;
        };
        let url = std::env::var("SIEVETUBE_TEST_VALKEY_URL").unwrap();
        let edge_id = format!("route-edge-{}", uuid::Uuid::new_v4());
        let edge = ValkeyHandle::new(&url, &edge_id).unwrap();
        edge.try_connect().await.unwrap();
        let make_ad = |hostname: &str, generation| RouteAd {
            hostname: hostname.to_string(),
            protocol: sievetube_common::config::Protocol::Http,
            tenant_id: "tenant".to_string(),
            edge_id: edge_id.clone(),
            generation,
        };
        let keep = make_ad("keep.test", 2);
        // Another Edge's route must survive this Edge replacing its own.
        let other_id = format!("route-other-{}", uuid::Uuid::new_v4());
        let other = ValkeyHandle::new(&url, &other_id).unwrap();
        other.try_connect().await.unwrap();
        let foreign = RouteAd {
            edge_id: other_id.clone(),
            ..make_ad("keep.test", 1)
        };
        other
            .publish_routes(std::slice::from_ref(&foreign), Duration::from_secs(30))
            .await
            .unwrap();

        edge.publish_routes(
            &[make_ad("keep.test", 1), make_ad("stale.test", 1)],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        edge.publish_routes(std::slice::from_ref(&keep), Duration::from_secs(30))
            .await
            .unwrap();

        let routes_of = |routes: Vec<(RouteAd, u64)>, id: &str| -> Vec<RouteAd> {
            routes
                .into_iter()
                .map(|(ad, _)| ad)
                .filter(|ad| ad.edge_id == id)
                .collect()
        };
        let routes = edge.fetch_routes().await.unwrap();
        assert_eq!(routes_of(routes.clone(), &edge_id), vec![keep.clone()]);
        assert_eq!(routes_of(routes, &other_id), vec![foreign.clone()]);

        // A withdrawn route stays withdrawn when the rest is published again.
        let extra = make_ad("extra.test", 2);
        edge.publish_routes(&[keep.clone(), extra.clone()], Duration::from_secs(30))
            .await
            .unwrap();
        edge.withdraw_routes(std::slice::from_ref(&extra))
            .await
            .unwrap();
        edge.publish_routes(std::slice::from_ref(&keep), Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(
            routes_of(edge.fetch_routes().await.unwrap(), &edge_id),
            vec![keep]
        );

        edge.publish_routes(&[], Duration::from_secs(30))
            .await
            .unwrap();
        let routes = edge.fetch_routes().await.unwrap();
        assert!(routes_of(routes.clone(), &edge_id).is_empty());
        assert_eq!(routes_of(routes, &other_id), vec![foreign]);
        other
            .publish_routes(&[], Duration::from_secs(30))
            .await
            .unwrap();
        drop(base);
    }

    #[tokio::test]
    async fn concurrent_claims_have_single_winner() {
        let Some(handle) = test_handle().await else {
            eprintln!("skipping: SIEVETUBE_TEST_VALKEY_URL not set");
            return;
        };
        let hostname = format!("race-{}.test", uuid::Uuid::new_v4());
        let mut tasks = Vec::new();
        for i in 0..16 {
            let handle = handle.clone();
            let hostname = hostname.clone();
            tasks.push(tokio::spawn(async move {
                handle
                    .claim_hostnames(&format!("tenant-{i}"), &[hostname])
                    .await
                    .unwrap()
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() == ClaimOutcome::Claimed {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }
}

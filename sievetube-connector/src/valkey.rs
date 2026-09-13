use redis::AsyncCommands;
use std::time::Duration;
use tokio::sync::watch;

use crate::health::ConnectorHealth;

/// Publish connection-aware heartbeats. The key is absent while no Edge is
/// authenticated, so control-plane users do not mistake a running but isolated
/// Connector for a usable one. ConnectionManager reconnects after transient
/// failures; constructing it is retried as well.
pub async fn heartbeat_loop(
    url: String,
    tunnel_id: String,
    health: ConnectorHealth,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let key = format!("sievetube:connector:{tunnel_id}:last_seen");
    let ttl = interval.as_secs().saturating_mul(4).max(60);
    loop {
        let mut conn = match connect(&url).await {
            Ok(conn) => {
                tracing::info!("connected to valkey for heartbeat");
                conn
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to connect to valkey; retrying heartbeat");
                tokio::select! {
                    _ = tokio::time::sleep(interval) => continue,
                    _ = shutdown.wait_for(|stop| *stop) => return,
                }
            }
        };

        loop {
            let edges = health.connected_edges();
            let result = if edges.is_empty() {
                conn.del::<_, ()>(&key).await
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let value = serde_json::json!({"last_seen": now, "edges": edges}).to_string();
                conn.set_ex::<_, _, ()>(&key, value, ttl).await
            };

            if let Err(e) = result {
                tracing::warn!(tunnel_id, error = %e, "valkey heartbeat failed; reconnecting");
                break;
            }

            let stopping = tokio::select! {
                _ = tokio::time::sleep(interval) => false,
                result = shutdown.changed() => result.is_err() || *shutdown.borrow(),
            };
            if stopping {
                let _ = conn.del::<_, ()>(&key).await;
                return;
            }
        }
    }
}

async fn connect(url: &str) -> anyhow::Result<redis::aio::ConnectionManager> {
    let client = redis::Client::open(url)?;
    let conn = redis::aio::ConnectionManager::new(client).await?;
    Ok(conn)
}

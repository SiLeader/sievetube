use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::time::Duration;

/// Publishes a heartbeat to Valkey indicating this Connector is alive.
pub async fn heartbeat_loop(
    mut conn: ConnectionManager,
    tunnel_id: String,
    edge_id: String,
    interval: Duration,
) {
    let key = format!("sievetube:connector:{tunnel_id}:last_seen");
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Err(e) = conn
            .set_ex::<_, _, ()>(&key, format!("{now}:{edge_id}"), 60)
            .await
        {
            tracing::warn!(tunnel_id, error = %e, "valkey heartbeat failed");
        }

        tokio::time::sleep(interval).await;
    }
}

pub async fn connect(url: &str) -> anyhow::Result<ConnectionManager> {
    let client = redis::Client::open(url)?;
    let conn = ConnectionManager::new(client).await?;
    Ok(conn)
}

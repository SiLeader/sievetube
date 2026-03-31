use redis::aio::ConnectionManager;
use redis::AsyncCommands;

#[derive(Clone)]
pub struct ValkeyHandle {
    conn: ConnectionManager,
    edge_id: String,
}

impl ValkeyHandle {
    pub async fn connect(url: &str, edge_id: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(ValkeyHandle {
            conn,
            edge_id: edge_id.to_string(),
        })
    }

    /// Register a connector's hostnames in Valkey.
    ///
    /// Key: `sievetube:hostname:<hostname>:owner` → tenant_id
    /// Key: `sievetube:tenant:<tenant_id>:edges` → SET of edge_ids
    pub async fn register_connector(
        &self,
        tenant_id: &str,
        hostnames: &[String],
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.clone();
        for hostname in hostnames {
            let owner_key = format!("sievetube:hostname:{hostname}:owner");
            conn.set::<_, _, ()>(&owner_key, tenant_id).await?;
        }
        let edge_key = format!("sievetube:tenant:{tenant_id}:edges");
        conn.sadd::<_, _, ()>(&edge_key, &self.edge_id).await?;
        Ok(())
    }

    pub async fn deregister_connector(&self, tenant_id: &str) -> anyhow::Result<()> {
        let mut conn = self.conn.clone();
        let edge_key = format!("sievetube:tenant:{tenant_id}:edges");
        conn.srem::<_, _, ()>(&edge_key, &self.edge_id).await?;
        Ok(())
    }

    /// Check whether a hostname is already claimed by a different tenant.
    pub async fn check_hostname_owner(
        &self,
        hostname: &str,
    ) -> anyhow::Result<Option<String>> {
        let mut conn = self.conn.clone();
        let owner_key = format!("sievetube:hostname:{hostname}:owner");
        let owner: Option<String> = conn.get(&owner_key).await?;
        Ok(owner)
    }
}

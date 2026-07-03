use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::fs;
use std::path::PathBuf;

pub mod queries;
pub mod schema;

#[derive(Clone)]
pub struct Database {
    pub pool: SqlitePool,
}

impl Database {
    pub async fn new(db_path: &PathBuf, pool_size: u32) -> Result<Self, sqlx::Error> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Get absolute path for file connections
        let abs_path = if db_path.is_absolute() {
            db_path.clone()
        } else {
            std::env::current_dir().unwrap_or_default().join(db_path)
        };

        // Use sqlx's SqliteConnectOptions for proper connection string parsing
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&abs_path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(pool_size)
            .connect_with(options)
            .await?;

        let db = Database { pool };
        db.migrate().await?;

        Ok(db)
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;
    use tokio::task;

    async fn setup_test_db_pool() -> SqlitePool {
        let conn_str = "sqlite::memory:";

        SqlitePoolOptions::new()
            .max_connections(5)
            .connect(conn_str)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_database_initialization() {
        let pool = setup_test_db_pool().await;
        assert!(pool.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_schema_creation() {
        let pool = setup_test_db_pool().await;

        // Create tables
        sqlx::query(schema::ALLOWLIST_IPS_TABLE)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(schema::INCIDENTS_TABLE)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(schema::ACTIONS_TABLE)
            .execute(&pool)
            .await
            .unwrap();

        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('allowlist_ips', 'incidents', 'actions')"
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert!(tables.contains(&"allowlist_ips".to_string()));
        assert!(tables.contains(&"incidents".to_string()));
        assert!(tables.contains(&"actions".to_string()));
    }

    #[tokio::test]
    async fn test_connection_pooling() {
        let pool = setup_test_db_pool().await;

        let mut connections = Vec::new();
        for _ in 0..5 {
            let conn = pool.acquire().await.unwrap();
            connections.push(conn);
        }

        assert_eq!(connections.len(), 5);
    }

    #[tokio::test]
    async fn test_allowlist_crud_operations() {
        let pool = setup_test_db_pool().await;

        sqlx::query(schema::ALLOWLIST_IPS_TABLE)
            .execute(&pool)
            .await
            .unwrap();

        let ip = "192.168.1.100";

        let is_allowlisted = queries::is_ip_allowlisted(&pool, ip).await.unwrap();
        assert!(!is_allowlisted);

        queries::add_allowlist_ip(&pool, ip, Some("Test IP"))
            .await
            .unwrap();

        let is_allowlisted = queries::is_ip_allowlisted(&pool, ip).await.unwrap();
        assert!(is_allowlisted);

        let ips = queries::get_allowlist_ips(&pool).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].ip, ip);
        assert_eq!(ips[0].description, Some("Test IP".to_string()));
    }

    #[tokio::test]
    async fn test_incident_crud_operations() {
        let pool = setup_test_db_pool().await;

        sqlx::query(schema::INCIDENTS_TABLE)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE incidents ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0; ALTER TABLE incidents ADD COLUMN details TEXT;").execute(&pool).await.unwrap();

        let incident_id = "inc-test-001";
        let source_ip = "10.0.0.1";
        let detected_at = "2026-07-01T12:00:00Z";

        queries::create_incident(&pool, incident_id, source_ip, detected_at, 12, "{}")
            .await
            .unwrap();

        let incident = queries::get_incident(&pool, incident_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(incident.id, incident_id);
        assert_eq!(incident.source_ip, source_ip);
        assert_eq!(incident.detected_at, detected_at);
        assert_eq!(incident.status, "detected");

        queries::update_incident_status(&pool, incident_id, "resolved")
            .await
            .unwrap();

        let incident = queries::get_incident(&pool, incident_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(incident.status, "resolved");

        let all_incidents = queries::get_all_incidents(&pool).await.unwrap();
        assert_eq!(all_incidents.len(), 1);
    }

    #[tokio::test]
    async fn test_action_crud_operations() {
        let pool = setup_test_db_pool().await;

        sqlx::query(schema::INCIDENTS_TABLE)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE incidents ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0; ALTER TABLE incidents ADD COLUMN details TEXT;").execute(&pool).await.unwrap();
        sqlx::query(schema::ACTIONS_TABLE)
            .execute(&pool)
            .await
            .unwrap();

        let incident_id = "inc-test-002";
        let action_id = "act-test-001";
        let source_ip = "10.0.0.2";
        let detected_at = "2026-07-01T13:00:00Z";

        queries::create_incident(&pool, incident_id, source_ip, detected_at, 12, "{}")
            .await
            .unwrap();
        queries::create_action(&pool, action_id, incident_id, "block_ip")
            .await
            .unwrap();

        let actions = queries::get_actions_by_incident(&pool, incident_id)
            .await
            .unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].id, action_id);
        assert_eq!(actions[0].incident_id, incident_id);
        assert_eq!(actions[0].action_type, "block_ip");
        assert_eq!(actions[0].status, "pending");

        queries::update_action_status(&pool, action_id, "completed")
            .await
            .unwrap();

        let actions = queries::get_actions_by_incident(&pool, incident_id)
            .await
            .unwrap();
        assert_eq!(actions[0].status, "completed");
    }

    #[tokio::test]
    async fn test_concurrent_database_access() {
        let pool = setup_test_db_pool().await;

        sqlx::query(schema::INCIDENTS_TABLE)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE incidents ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0; ALTER TABLE incidents ADD COLUMN details TEXT;").execute(&pool).await.unwrap();
        sqlx::query(schema::ALLOWLIST_IPS_TABLE)
            .execute(&pool)
            .await
            .unwrap();

        let incident_id_base = "inc-concurrent-";

        let mut handles = Vec::new();
        for i in 0..10 {
            let pool_clone = pool.clone();
            let incident_id = format!("{}{}", incident_id_base, i);
            let source_ip = format!("10.0.0.{}", i);
            let detected_at = "2026-07-01T14:00:00Z";

            let handle = task::spawn(async move {
                queries::create_incident(
                    &pool_clone,
                    &incident_id,
                    &source_ip,
                    detected_at,
                    12,
                    "{}",
                )
                .await
                .unwrap();
                queries::is_ip_allowlisted(&pool_clone, &source_ip)
                    .await
                    .unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let all_incidents = queries::get_all_incidents(&pool).await.unwrap();
        assert_eq!(all_incidents.len(), 10);
    }
}

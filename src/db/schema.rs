#![allow(dead_code)]

#[allow(dead_code)]
pub const ALLOWLIST_IPS_TABLE: &str = "CREATE TABLE IF NOT EXISTS allowlist_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);";

#[allow(dead_code)]
pub const INCIDENTS_TABLE: &str = "CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, detected_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'detected', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);";

#[allow(dead_code)]
pub const ACTIONS_TABLE: &str = "CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, action_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE);";

#[allow(dead_code)]
pub const MIGRATION_001_CREATE_TABLES: &str = "CREATE TABLE IF NOT EXISTS allowlist_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, detected_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'detected', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, action_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE); CREATE INDEX IF NOT EXISTS idx_allowlist_ips_ip ON allowlist_ips(ip); CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip); CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status); CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON actions(incident_id); CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);";

#[allow(dead_code)]
pub async fn create_tables(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(ALLOWLIST_IPS_TABLE).execute(pool).await?;
    sqlx::query(INCIDENTS_TABLE).execute(pool).await?;
    sqlx::query(ACTIONS_TABLE).execute(pool).await?;
    Ok(())
}

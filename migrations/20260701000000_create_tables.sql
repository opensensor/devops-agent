-- Create tables and indexes
--
-- NOTE: sqlx's `migrate!()` runs each .sql file as a single migration in full.
-- Do NOT add a "-- Down" section with DROP statements here: they would execute
-- immediately after the CREATEs and drop every table. Reversible migrations
-- require separate `<version>_<name>.up.sql` / `.down.sql` files.

CREATE TABLE IF NOT EXISTS allowlist_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    detected_at DATETIME NOT NULL,
    status TEXT NOT NULL DEFAULT 'detected',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_allowlist_ips_ip ON allowlist_ips(ip);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);

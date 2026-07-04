#![allow(unused_imports)]

use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub struct AllowlistIp {
    pub id: i64,
    pub ip: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub struct IncidentDb {
    pub id: String,
    pub source_ip: String,
    pub detected_at: String,
    pub status: String,
    pub failure_count: i64,
    pub details: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ActionDb {
    pub id: String,
    pub incident_id: String,
    pub action_type: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub enum ActionClaimResult {
    Claimed(ActionDb),
    AlreadyCompleted(ActionDb),
    AlreadyInProgress(ActionDb),
}

pub async fn is_ip_allowlisted(pool: &sqlx::SqlitePool, ip: &str) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM allowlist_ips WHERE ip = ?")
        .bind(ip)
        .fetch_one(pool)
        .await?;
    Ok(count > 0)
}

pub async fn add_allowlist_ip(
    pool: &sqlx::SqlitePool,
    ip: &str,
    description: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO allowlist_ips (ip, description) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET description = excluded.description, updated_at = CURRENT_TIMESTAMP",
    )
    .bind(ip)
    .bind(description)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

pub async fn get_allowlist_ips(pool: &sqlx::SqlitePool) -> Result<Vec<AllowlistIp>, sqlx::Error> {
    sqlx::query_as::<_, AllowlistIp>("SELECT id, ip, description, created_at, updated_at FROM allowlist_ips ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
}

pub async fn create_incident(
    pool: &sqlx::SqlitePool,
    id: &str,
    source_ip: &str,
    detected_at: &str,
    failure_count: i64,
    details: &str,
) -> Result<(), sqlx::Error> {
    // Upsert on the stable per-IP id: a re-detected attacker refreshes the
    // last-seen time and metrics but keeps its original created_at and,
    // crucially, any status the operator already set (e.g. approved/rejected via
    // the SPA) so re-detection never silently reopens a triaged incident.
    sqlx::query(
        "INSERT INTO incidents (id, source_ip, detected_at, status, failure_count, details, created_at, updated_at) \
         VALUES (?, ?, ?, 'detected', ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) \
         ON CONFLICT(id) DO UPDATE SET \
             detected_at = excluded.detected_at, \
             failure_count = excluded.failure_count, \
             details = excluded.details, \
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(id)
    .bind(source_ip)
    .bind(detected_at)
    .bind(failure_count)
    .bind(details)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_incident(
    pool: &sqlx::SqlitePool,
    id: &str,
) -> Result<Option<IncidentDb>, sqlx::Error> {
    sqlx::query_as::<_, IncidentDb>(
        "SELECT id, source_ip, detected_at, status, failure_count, details, created_at, updated_at FROM incidents WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

#[allow(dead_code)]
pub async fn get_incidents_by_status(
    pool: &sqlx::SqlitePool,
    status: &str,
) -> Result<Vec<IncidentDb>, sqlx::Error> {
    sqlx::query_as::<_, IncidentDb>(
        "SELECT id, source_ip, detected_at, status, failure_count, details, created_at, updated_at FROM incidents WHERE status = ? ORDER BY detected_at DESC",
    )
    .bind(status)
    .fetch_all(pool)
    .await
}

pub async fn get_all_incidents(pool: &sqlx::SqlitePool) -> Result<Vec<IncidentDb>, sqlx::Error> {
    sqlx::query_as::<_, IncidentDb>(
        "SELECT id, source_ip, detected_at, status, failure_count, details, created_at, updated_at FROM incidents ORDER BY detected_at DESC",
    )
    .fetch_all(pool)
    .await
}

#[allow(dead_code)]
pub async fn update_incident_status(
    pool: &sqlx::SqlitePool,
    id: &str,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_incident_status_from(
    pool: &sqlx::SqlitePool,
    id: &str,
    status: &str,
    allowed_current_statuses: &[&str],
) -> Result<Option<IncidentDb>, sqlx::Error> {
    if allowed_current_statuses.is_empty() {
        return Ok(None);
    }

    let placeholders = std::iter::repeat("?")
        .take(allowed_current_statuses.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE incidents \
         SET status = ?, updated_at = CURRENT_TIMESTAMP \
         WHERE id = ? AND status IN ({})",
        placeholders
    );

    let mut tx = pool.begin().await?;
    let mut query = sqlx::query(&sql).bind(status).bind(id);
    for current_status in allowed_current_statuses {
        query = query.bind(*current_status);
    }

    let result = query.execute(&mut *tx).await?;
    if result.rows_affected() == 0 {
        tx.commit().await?;
        return Ok(None);
    }

    let incident = sqlx::query_as::<_, IncidentDb>(
        "SELECT id, source_ip, detected_at, status, failure_count, details, created_at, updated_at FROM incidents WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(incident))
}

pub async fn create_action(
    pool: &sqlx::SqlitePool,
    id: &str,
    incident_id: &str,
    action_type: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO actions (id, incident_id, action_type, status, created_at, updated_at) \
         VALUES (?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) \
         ON CONFLICT(id) DO UPDATE SET \
             incident_id = excluded.incident_id, \
             action_type = excluded.action_type, \
             status = CASE \
                 WHEN actions.status = 'completed' AND excluded.action_type = 'block_ip' THEN actions.status \
                 ELSE 'pending' \
             END, \
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(id)
    .bind(incident_id)
    .bind(action_type)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn claim_action(
    pool: &sqlx::SqlitePool,
    id: &str,
    incident_id: &str,
    action_type: &str,
    force_completed: bool,
) -> Result<ActionClaimResult, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO actions (id, incident_id, action_type, status, created_at, updated_at) \
         VALUES (?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) \
         ON CONFLICT(id) DO UPDATE SET \
             incident_id = excluded.incident_id, \
             action_type = excluded.action_type, \
             status = 'pending', \
             updated_at = CURRENT_TIMESTAMP \
         WHERE actions.status = 'failed' OR (? AND actions.status = 'completed')",
    )
    .bind(id)
    .bind(incident_id)
    .bind(action_type)
    .bind(force_completed)
    .execute(pool)
    .await?;

    let action = get_action(pool, id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;

    if result.rows_affected() > 0 {
        return Ok(ActionClaimResult::Claimed(action));
    }

    if action.status == "completed" {
        Ok(ActionClaimResult::AlreadyCompleted(action))
    } else {
        Ok(ActionClaimResult::AlreadyInProgress(action))
    }
}

pub async fn get_action(
    pool: &sqlx::SqlitePool,
    id: &str,
) -> Result<Option<ActionDb>, sqlx::Error> {
    sqlx::query_as::<_, ActionDb>(
        "SELECT id, incident_id, action_type, status, created_at, updated_at FROM actions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

#[allow(dead_code)]
pub async fn get_actions_by_incident(
    pool: &sqlx::SqlitePool,
    incident_id: &str,
) -> Result<Vec<ActionDb>, sqlx::Error> {
    sqlx::query_as::<_, ActionDb>(
        "SELECT id, incident_id, action_type, status, created_at, updated_at FROM actions WHERE incident_id = ? ORDER BY created_at DESC",
    )
    .bind(incident_id)
    .fetch_all(pool)
        .await
}

#[allow(dead_code)]
pub async fn get_latest_action_by_incident(
    pool: &sqlx::SqlitePool,
    incident_id: &str,
) -> Result<Option<ActionDb>, sqlx::Error> {
    sqlx::query_as::<_, ActionDb>(
        "SELECT id, incident_id, action_type, status, created_at, updated_at FROM actions WHERE incident_id = ? ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(incident_id)
    .fetch_optional(pool)
    .await
}

pub async fn get_latest_action_by_incident_and_type(
    pool: &sqlx::SqlitePool,
    incident_id: &str,
    action_type: &str,
) -> Result<Option<ActionDb>, sqlx::Error> {
    sqlx::query_as::<_, ActionDb>(
        "SELECT id, incident_id, action_type, status, created_at, updated_at FROM actions WHERE incident_id = ? AND action_type = ? ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(incident_id)
    .bind(action_type)
    .fetch_optional(pool)
    .await
}

pub async fn get_latest_action_by_incident_type_and_status(
    pool: &sqlx::SqlitePool,
    incident_id: &str,
    action_type: &str,
    status: &str,
) -> Result<Option<ActionDb>, sqlx::Error> {
    sqlx::query_as::<_, ActionDb>(
        "SELECT id, incident_id, action_type, status, created_at, updated_at FROM actions WHERE incident_id = ? AND action_type = ? AND status = ? ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(incident_id)
    .bind(action_type)
    .bind(status)
    .fetch_optional(pool)
    .await
}

pub async fn get_actions_for_incidents(
    pool: &sqlx::SqlitePool,
    incident_ids: &[String],
) -> Result<Vec<ActionDb>, sqlx::Error> {
    if incident_ids.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders = std::iter::repeat("?")
        .take(incident_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT id, incident_id, action_type, status, created_at, updated_at \
         FROM actions \
         WHERE incident_id IN ({}) AND action_type IN ('block_ip', 'report_abuse') \
         ORDER BY updated_at DESC, created_at DESC",
        placeholders
    );

    let mut query = sqlx::query_as::<_, ActionDb>(&sql);
    for incident_id in incident_ids {
        query = query.bind(incident_id);
    }

    query.fetch_all(pool).await
}

#[allow(dead_code)]
pub async fn get_all_actions(pool: &sqlx::SqlitePool) -> Result<Vec<ActionDb>, sqlx::Error> {
    sqlx::query_as::<_, ActionDb>(
        "SELECT id, incident_id, action_type, status, created_at, updated_at FROM actions ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

pub async fn update_action_status(
    pool: &sqlx::SqlitePool,
    id: &str,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE actions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn get_incidents_by_source_ip(
    pool: &sqlx::SqlitePool,
    source_ip: &str,
) -> Result<Vec<IncidentDb>, sqlx::Error> {
    sqlx::query_as::<_, IncidentDb>(
        "SELECT id, source_ip, detected_at, status, failure_count, details, created_at, updated_at FROM incidents WHERE source_ip = ? ORDER BY detected_at DESC",
    )
    .bind(source_ip)
    .fetch_all(pool)
    .await
}

pub async fn delete_allowlist_ip(pool: &sqlx::SqlitePool, ip: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM allowlist_ips WHERE ip = ?")
        .bind(ip)
        .execute(pool)
        .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn cleanup_incidents(
    pool: &sqlx::SqlitePool,
    older_than: &str,
) -> Result<usize, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM incidents WHERE detected_at < ? AND status IN ('approved', 'rejected')",
    )
    .bind(older_than)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() as usize)
}

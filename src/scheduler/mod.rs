use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::interval;

use crate::config::models::SchedulerConfig;
use crate::db::queries::create_incident;
use crate::elasticsearch::EsClient;

#[derive(Debug)]
pub struct Scheduler {
    pub config: SchedulerConfig,
    pub es_client: Arc<EsClient>,
    pub db_pool: sqlx::SqlitePool,
    pub index_pattern: String,
}

impl Scheduler {
    pub fn new(
        config: SchedulerConfig,
        es_client: Arc<EsClient>,
        db_pool: sqlx::SqlitePool,
        index_pattern: String,
    ) -> Self {
        Self {
            config,
            es_client,
            db_pool,
            index_pattern,
        }
    }

    pub async fn run(&self) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            match signal::ctrl_c().await {
                Ok(()) => {
                    let _ = shutdown_tx.send(true);
                }
                Err(e) => {
                    tracing::error!("Failed to listen for shutdown signal: {}", e);
                    let _ = shutdown_tx.send(true);
                }
            }
        });

        self.run_until_shutdown(shutdown_rx).await;
    }

    pub async fn run_until_shutdown(&self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(
            "Starting incident scheduler with interval of {} seconds",
            self.config.interval_seconds
        );
        tracing::info!(
            "Incident detection query target: index_pattern={}, time_field={}, status_field={}, client_host_field={}, lookback_minutes={}, failure_threshold={}",
            self.index_pattern,
            self.config.time_field,
            self.config.status_field,
            self.config.client_host_field,
            self.config.lookback_minutes,
            self.config.failure_threshold
        );

        let mut ticker = interval(Duration::from_secs(self.config.interval_seconds));

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("Shutdown signal received, stopping scheduler...");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    tracing::info!("Running scheduled threat detection...");

                    match self.detect_threats_and_create_incidents().await {
                        Ok(count) => {
                            tracing::info!("Scheduled threat detection completed. Processed {} incidents", count);
                        }
                        Err(e) => {
                            tracing::error!("Error in scheduled threat detection: {}", e);
                        }
                    }
                }
            }
        }
    }

    async fn detect_threats_and_create_incidents(&self) -> Result<usize, SchedulerError> {
        let gte = format!("now-{}m", self.config.lookback_minutes);
        let dsl_query = serde_json::json!({
            "query": {
                "bool": {
                    "must": [
                        { "range": { self.config.time_field.clone(): { "gte": gte } } }
                    ],
                    "should": [
                        { "term": { self.config.status_field.clone(): 401 } },
                        { "term": { self.config.status_field.clone(): 403 } }
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 0,
            "aggs": {
                "source_ips": {
                    "terms": { "field": self.config.client_host_field.clone(), "size": 50 },
                    "aggs": {
                        "by_status": { "terms": { "field": self.config.status_field.clone() } },
                        "methods": { "terms": { "field": self.config.request_method_field.clone(), "size": 5 } },
                        "top_paths": { "terms": { "field": self.config.request_path_field.clone(), "size": 8 } },
                        "top_hosts": { "terms": { "field": self.config.request_host_field.clone(), "size": 5 } },
                        "last_seen": { "max": { "field": self.config.time_field.clone(), "format": "strict_date_optional_time" } }
                    }
                }
            }
        })
        .to_string();

        match self
            .es_client
            .execute_raw_dsl(&self.index_pattern, &dsl_query)
            .await
        {
            Ok(response) => {
                let response_json = serde_json::to_value(response)?;
                let incidents_created = self.process_aggregation_results(response_json).await?;
                Ok(incidents_created)
            }
            Err(e) => {
                tracing::error!("Failed to execute ES query for threat detection: {}", e);
                Err(SchedulerError::Es(e))
            }
        }
    }

    async fn process_aggregation_results(
        &self,
        response_json: serde_json::Value,
    ) -> Result<usize, SchedulerError> {
        let mut incidents_created = 0;

        let buckets = response_json
            .pointer("/aggregations/source_ips/buckets")
            .and_then(|b| b.as_array());

        let Some(buckets) = buckets else {
            return Ok(0);
        };

        for bucket in buckets {
            let (Some(ip), Some(doc_count)) = (
                bucket.get("key").and_then(|k| k.as_str()),
                bucket.get("doc_count").and_then(|d| d.as_u64()),
            ) else {
                continue;
            };

            if doc_count < self.config.failure_threshold {
                continue;
            }

            // Stable per-IP id so a persistent attacker maps to a single incident
            // that is refreshed on each run, rather than a new row every interval.
            let incident_id = format!("incident-{}", ip);
            let detected_at = chrono::Utc::now().to_rfc3339();
            let details = self.build_incident_details(bucket, doc_count);
            let details_str = match serde_json::to_string(&details) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to serialize incident details for IP {}: {}", ip, e);
                    String::new()
                }
            };

            match create_incident(
                &self.db_pool,
                &incident_id,
                ip,
                &detected_at,
                doc_count as i64,
                &details_str,
            )
            .await
            {
                Ok(_) => {
                    tracing::info!(
                        "Incident {} for IP {} recorded with {} auth failures",
                        incident_id,
                        ip,
                        doc_count
                    );
                    incidents_created += 1;
                }
                Err(e) => {
                    tracing::error!("Failed to record incident for IP {}: {}", ip, e);
                }
            }
        }

        Ok(incidents_created)
    }

    /// Turn one source-IP aggregation bucket into a structured metrics payload
    /// that explains why the IP was flagged (shown on the incident card).
    fn build_incident_details(
        &self,
        bucket: &serde_json::Value,
        failure_count: u64,
    ) -> serde_json::Value {
        // Convert a sub-aggregation's buckets into an ordered [key, count] list.
        let terms = |name: &str| -> Vec<serde_json::Value> {
            bucket
                .pointer(&format!("/{}/buckets", name))
                .and_then(|b| b.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|b| {
                            let key = b.get("key")?;
                            let count = b.get("doc_count")?;
                            // key may be a string (paths/methods) or number (status)
                            let key_str = key
                                .as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| key.to_string());
                            Some(serde_json::json!([key_str, count]))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        serde_json::json!({
            "window_minutes": self.config.lookback_minutes,
            "failure_count": failure_count,
            "status_breakdown": terms("by_status"),
            "methods": terms("methods"),
            "top_paths": terms("top_paths"),
            "target_hosts": terms("top_hosts"),
            "last_seen": bucket.pointer("/last_seen/value_as_string").and_then(|v| v.as_str()),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("Elasticsearch error: {0}")]
    Es(#[from] crate::elasticsearch::EsError),
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::SchedulerConfig as ConfigModel;

    #[test]
    fn test_scheduler_config_default() {
        let config = ConfigModel::default();
        assert_eq!(config.interval_seconds, 300);
    }

    #[test]
    fn test_scheduler_config_custom_interval() {
        let config = ConfigModel {
            interval_seconds: 60,
            lookback_minutes: 60,
            failure_threshold: 10,
            time_field: "StartLocal".to_string(),
            status_field: "DownstreamStatus".to_string(),
            client_host_field: "ClientHost.keyword".to_string(),
            request_method_field: "RequestMethod.keyword".to_string(),
            request_path_field: "RequestPath.keyword".to_string(),
            request_host_field: "RequestHost.keyword".to_string(),
        };
        assert_eq!(config.interval_seconds, 60);
    }

    #[test]
    fn test_scheduler_error_from_es_error() {
        let es_error = crate::elasticsearch::EsError::InvalidDsl("invalid dsl".to_string());
        let scheduler_error: SchedulerError = es_error.into();
        assert!(matches!(scheduler_error, SchedulerError::Es(_)));
    }

    #[test]
    fn test_scheduler_error_from_db_error() {
        let db_error = sqlx::Error::PoolTimedOut;
        let scheduler_error: SchedulerError = db_error.into();
        assert!(matches!(scheduler_error, SchedulerError::Db(_)));
    }
}

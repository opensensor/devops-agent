use autoagents::async_trait;
use autoagents::core::tool::ToolCallError;
use autoagents::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::{Arc, Mutex};

#[derive(ToolInput, Serialize, Deserialize)]
pub struct CheckAllowlistInput {
    #[input(description = "IP address to check against the allowlist")]
    pub ip: String,
}

#[tool(
    name = "check_allowlist",
    description = "Check if an IP address is in the allowlist database",
    input = CheckAllowlistInput
)]
pub struct CheckAllowlistTool {
    pub db_pool: Arc<Mutex<Option<SqlitePool>>>,
}

impl Default for CheckAllowlistTool {
    fn default() -> Self {
        Self {
            db_pool: Arc::new(Mutex::new(None)),
        }
    }
}

impl Clone for CheckAllowlistTool {
    fn clone(&self) -> Self {
        Self {
            db_pool: self.db_pool.clone(),
        }
    }
}

#[async_trait]
impl ToolRuntime for CheckAllowlistTool {
    async fn execute(&self, args: serde_json::Value) -> Result<serde_json::Value, ToolCallError> {
        let input: CheckAllowlistInput = serde_json::from_value(args)?;

        let pool = self
            .db_pool
            .lock()
            .unwrap()
            .as_ref()
            .ok_or_else(|| ToolCallError::RuntimeError("Database pool not configured".into()))?
            .clone();

        match crate::db::queries::is_ip_allowlisted(&pool, &input.ip).await {
            Ok(is_allowlisted) => {
                let result_json = serde_json::json!({
                    "ip": input.ip,
                    "is_allowlisted": is_allowlisted,
                    "success": true
                });
                Ok(result_json)
            }
            Err(e) => {
                let error_json = serde_json::json!({
                    "error": e.to_string(),
                    "ip": input.ip,
                    "success": false
                });
                Ok(error_json)
            }
        }
    }
}

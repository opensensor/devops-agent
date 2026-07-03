use autoagents::async_trait;
use autoagents::core::tool::ToolCallError;
use autoagents::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::elasticsearch::EsClient;

#[derive(ToolInput, Serialize, Deserialize)]
pub struct QueryLogsInput {
    #[input(description = "Elasticsearch index to query (e.g., 'traefik-*')")]
    pub index: String,
    #[input(description = "DSL query string or search parameters")]
    pub dsl_query: String,
}

#[tool(
    name = "query_logs",
    description = "Query logs from Elasticsearch using DSL queries",
    input = QueryLogsInput
)]
#[derive(Default, Clone)]
pub struct QueryLogsTool {
    pub es_client: Option<Arc<EsClient>>,
}

#[async_trait]
impl ToolRuntime for QueryLogsTool {
    async fn execute(&self, args: serde_json::Value) -> Result<serde_json::Value, ToolCallError> {
        let input: QueryLogsInput = serde_json::from_value(args)?;

        let es_client = self
            .es_client
            .as_ref()
            .ok_or_else(|| {
                ToolCallError::RuntimeError("Elasticsearch client not configured".into())
            })?
            .clone();

        match es_client
            .execute_raw_dsl(&input.index, &input.dsl_query)
            .await
        {
            Ok(response) => {
                let response_json = serde_json::to_value(response)?;
                Ok(response_json)
            }
            Err(e) => {
                let error_json = serde_json::json!({
                    "error": e.to_string(),
                    "success": false
                });
                Ok(error_json)
            }
        }
    }
}

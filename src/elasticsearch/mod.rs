use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

pub mod dsl_validator;
pub mod queries;

pub use dsl_validator::DslValidator;
pub use queries::{EsQueryResponse, EsSearchRequest};

/// Elasticsearch client configuration
#[derive(Debug, Clone)]
pub struct EsClientConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
    pub tls_insecure_skip_verify: bool,
}

impl Default for EsClientConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:9200".to_string(),
            username: None,
            password: None,
            api_key: None,
            timeout_seconds: 30,
            tls_insecure_skip_verify: false,
        }
    }
}

/// Elasticsearch client
#[derive(Debug, Clone)]
pub struct EsClient {
    pub config: EsClientConfig,
    pub http_client: Client,
    pub dsl_validator: DslValidator,
}

#[derive(Debug, thiserror::Error)]
pub enum EsError {
    #[error("HTTP error: {status} - {message}")]
    HttpError {
        status: u16,
        message: String,
        details: Option<Value>,
    },
    #[allow(dead_code)]
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[allow(dead_code)]
    #[error("Timeout error: query exceeded {timeout_ms}ms")]
    TimeoutError { timeout_ms: u64 },
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Invalid DSL: {0}")]
    InvalidDsl(String),
}

impl EsClient {
    /// Create a new Elasticsearch client
    pub fn new(config: EsClientConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_seconds);
        let mut client_builder = Client::builder().timeout(timeout);

        if config.tls_insecure_skip_verify {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let http_client = client_builder.build().expect("Failed to build HTTP client");

        Self {
            config,
            http_client,
            dsl_validator: DslValidator::new(),
        }
    }

    /// Execute an LLM-generated DSL query
    pub async fn execute_dsl_query(
        &self,
        index: &str,
        dsl_query: &str,
    ) -> Result<EsQueryResponse, EsError> {
        // Validate the DSL query first (operates on the raw JSON structure)
        self.dsl_validator.validate(dsl_query)?;

        // Parse the DSL query as free-form JSON. We intentionally do NOT round-trip
        // through the typed EsSearchRequest/QueryType model here: that model uses a
        // simplified shape (e.g. {"range":{"field":..,"gte":..}}) that neither parses
        // nor serializes as native Elasticsearch DSL. Callers (scheduler, query_logs
        // tool, ReAct executor) all produce native ES DSL, so we pass it through and
        // only clamp resource-bounding fields.
        let mut body: Value = serde_json::from_str(dsl_query)?;
        self.dsl_validator.sanitize_value(&mut body);

        // Execute the query
        self.execute_search_value(index, &body).await
    }

    /// Execute a search query against Elasticsearch
    #[allow(dead_code)]
    async fn execute_search(
        &self,
        index: &str,
        request: &EsSearchRequest,
    ) -> Result<EsQueryResponse, EsError> {
        let body = serde_json::to_value(request)?;
        self.execute_search_value(index, &body).await
    }

    /// Execute a search using a raw JSON request body (native Elasticsearch DSL).
    async fn execute_search_value(
        &self,
        index: &str,
        body: &Value,
    ) -> Result<EsQueryResponse, EsError> {
        let url = format!("{}/{}/_search", self.config.url, index);

        let mut request_builder = self.http_client.post(&url).json(body);

        // Add authentication if configured
        if let Some(ref api_key) = self.config.api_key {
            request_builder = request_builder.bearer_auth(api_key);
        } else if let (Some(username), Some(password)) =
            (&self.config.username, &self.config.password)
        {
            request_builder = request_builder.basic_auth(username, Some(password));
        }

        let response = request_builder.send().await?;

        let status = response.status().as_u16();

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            let details = serde_json::from_str(&error_text).ok();

            return Err(EsError::HttpError {
                status,
                message: error_text,
                details,
            });
        }

        let response_body: Value = response.json().await?;

        // Parse the response into EsQueryResponse
        let es_response: EsQueryResponse = serde_json::from_value(response_body)?;

        Ok(es_response)
    }

    /// Execute a raw DSL query string (for LLM-generated queries)
    pub async fn execute_raw_dsl(
        &self,
        index: &str,
        dsl_query: &str,
    ) -> Result<EsQueryResponse, EsError> {
        self.execute_dsl_query(index, dsl_query).await
    }

    /// Fallback to structured tool calls when LLM query fails
    #[allow(dead_code)]
    pub async fn fallback_to_structured_search(
        &self,
        index: &str,
        _query_type: &str,
        field: &str,
        value: &str,
        size: usize,
    ) -> Result<EsQueryResponse, EsError> {
        let structured_request = EsSearchRequest {
            query: Some(queries::QueryType::Match {
                field: field.to_string(),
                value: value.to_string(),
            }),
            size: Some(std::cmp::min(size, 100)), // Limit fallback size to 100
            ..Default::default()
        };

        self.execute_search(index, &structured_request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_es_client_config_default() {
        let config = EsClientConfig::default();
        assert_eq!(config.url, "http://localhost:9200");
        assert_eq!(config.timeout_seconds, 30);
        assert!(!config.tls_insecure_skip_verify);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
        assert!(config.api_key.is_none());
    }

    #[test]
    fn test_es_error_display() {
        let error = EsError::ValidationError("invalid query".to_string());
        let error_str = error.to_string();
        assert!(error_str.contains("Validation error"));
        assert!(error_str.contains("invalid query"));
    }
}

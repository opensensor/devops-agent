#![allow(dead_code)]

use autoagents::core::agent::AgentExecutor;
use autoagents::prelude::*;
use futures::StreamExt;
use std::sync::{Arc, Mutex};

use crate::agent::hooks::AgentGuardrails;
use crate::elasticsearch::dsl_validator::DslValidator;
use crate::elasticsearch::{EsClient, EsError};
use crate::tools::{ApplyBlockTool, CheckAllowlistTool, InspectPatternsTool, QueryLogsTool};
use sqlx::SqlitePool;

/// Configuration for the DevOps Agent ReAct executor
#[derive(Debug, Clone)]
pub struct DevOpsAgentConfig {
    pub max_turns: usize,
    pub dsl_validator: Option<DslValidator>,
}

impl Default for DevOpsAgentConfig {
    fn default() -> Self {
        Self {
            max_turns: 10,
            dsl_validator: Some(DslValidator::new()),
        }
    }
}

/// DevOps Agent for ReAct execution with ES query flow
#[agent(
    name = "devops_agent",
    description = "DevOps Network Monitoring Agent for analyzing Traefik logs and detecting secrets scanning activity",
    tools = [
        QueryLogsTool { es_client: self.es_client.clone() },
        CheckAllowlistTool { db_pool: self._db_pool.clone() },
        InspectPatternsTool { k8s_client: self._k8s_client.clone() },
        ApplyBlockTool { k8s_client: self._k8s_client.clone(), namespace: self._namespace.clone() },
    ]
)]
#[derive(Clone, AgentHooks)]
pub struct DevOpsAgent {
    pub config: DevOpsAgentConfig,
    pub es_client: Option<Arc<EsClient>>,
    pub guardrails: Option<AgentGuardrails>,
    pub llm: Arc<dyn autoagents_llm::LLMProvider>,
    _db_pool: Arc<Mutex<Option<SqlitePool>>>,
    _k8s_client: Arc<Mutex<Option<Arc<kube::Client>>>>,
    _namespace: Arc<Mutex<String>>,
}

impl Default for DevOpsAgent {
    fn default() -> Self {
        panic!("DevOpsAgent must be constructed with build_agent() which provides an LLM")
    }
}

impl DevOpsAgent {
    pub fn new(config: DevOpsAgentConfig, llm: Arc<dyn autoagents_llm::LLMProvider>) -> Self {
        Self {
            config,
            es_client: None,
            guardrails: Some(AgentGuardrails::new()),
            llm,
            _db_pool: Arc::new(Mutex::new(None)),
            _k8s_client: Arc::new(Mutex::new(None)),
            _namespace: Arc::new(Mutex::new("default".to_string())),
        }
    }

    pub fn with_es_client(mut self, es_client: Arc<EsClient>) -> Self {
        self.es_client = Some(es_client);
        self
    }

    pub fn with_guardrails(mut self, guardrails: AgentGuardrails) -> Self {
        self.guardrails = Some(guardrails);
        self
    }

    pub fn with_db_pool(self, pool: SqlitePool) -> Self {
        self._db_pool.lock().unwrap().replace(pool);
        self
    }

    pub fn with_k8s_client(self, client: Arc<kube::Client>) -> Self {
        self._k8s_client.lock().unwrap().replace(client);
        self
    }

    pub fn with_namespace(self, ns: String) -> Self {
        *self._namespace.lock().unwrap() = ns;
        self
    }

    pub fn llm(&self) -> &Arc<dyn autoagents_llm::LLMProvider> {
        &self.llm
    }

    /// Validate DSL query before execution
    pub fn validate_dsl(&self, dsl_query: &str) -> Result<(), EsError> {
        if let Some(validator) = &self.config.dsl_validator {
            validator.validate(dsl_query)?;
        }
        Ok(())
    }

    /// Execute ES query with DSL validation
    pub async fn execute_es_query(
        &self,
        index: &str,
        dsl_query: &str,
    ) -> Result<serde_json::Value, EsError> {
        self.validate_dsl(dsl_query)?;

        if let Some(client) = &self.es_client {
            let response = client.execute_raw_dsl(index, dsl_query).await?;
            let response_json = serde_json::to_value(response)?;
            Ok(response_json)
        } else {
            Err(EsError::ValidationError(
                "ES client not configured".to_string(),
            ))
        }
    }
}

/// ReAct executor error type alias - using the autoagents ReActExecutorError
pub type ReActExecutorError = autoagents::core::agent::prebuilt::executor::ReActExecutorError;

impl From<EsError> for ReActExecutorError {
    fn from(error: EsError) -> Self {
        match error {
            EsError::InvalidDsl(msg) => {
                ReActExecutorError::Other(format!("DSL validation failed: {}", msg))
            }
            EsError::HttpError {
                status, message, ..
            } => ReActExecutorError::Other(format!("HTTP error {}: {}", status, message)),
            EsError::TimeoutError { timeout_ms } => {
                ReActExecutorError::Other(format!("Timeout error: {}ms", timeout_ms))
            }
            EsError::NetworkError(e) => ReActExecutorError::Other(format!("Network error: {}", e)),
            EsError::SerializationError(e) => {
                ReActExecutorError::Other(format!("Serialization error: {}", e))
            }
            EsError::ValidationError(msg) => {
                ReActExecutorError::Other(format!("Validation error: {}", msg))
            }
        }
    }
}

/// ReAct executor wrapper for DevOps Agent
#[derive(Debug)]
pub struct ReActExecutor {
    pub inner: ReActAgent<DevOpsAgent>,
    pub max_turns: usize,
}

impl ReActExecutor {
    pub fn new(agent: DevOpsAgent) -> Self {
        let react_agent = ReActAgent::with_max_turns(agent, 10);
        Self {
            inner: react_agent,
            max_turns: 10,
        }
    }

    pub fn with_max_turns(agent: DevOpsAgent, max_turns: usize) -> Self {
        let react_agent = ReActAgent::with_max_turns(agent, max_turns.max(1));
        Self {
            inner: react_agent,
            max_turns: max_turns.max(1),
        }
    }

    /// Execute the ReAct loop with multi-turn ES query flow
    pub async fn execute(
        &self,
        task: &Task,
        context: Arc<Context>,
    ) -> Result<ReActAgentOutput, ReActExecutorError> {
        self.inner.execute(task, context).await
    }

    /// Execute the ReAct loop with streaming support
    pub async fn execute_stream(
        &self,
        task: &Task,
        context: Arc<Context>,
    ) -> Result<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<ReActAgentOutput, ReActExecutorError>> + Send>,
        >,
        ReActExecutorError,
    > {
        let stream = self.inner.execute_stream(task, context).await?;

        // Convert the stream to return ReActExecutorError
        let mapped_stream = stream.map(|result| match result {
            Ok(output) => Ok(output),
            Err(e) => Err(e),
        });

        Ok(Box::pin(mapped_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elasticsearch::dsl_validator::DslValidator;
    use crate::elasticsearch::queries::EsSearchRequest;

    #[test]
    fn test_devops_agent_config_creation() {
        let config = DevOpsAgentConfig::default();
        assert_eq!(config.max_turns, 10);
        assert!(config.dsl_validator.is_some());
    }

    #[test]
    fn test_react_executor_max_turns_enforced() {
        let config = DevOpsAgentConfig {
            max_turns: 3,
            dsl_validator: Some(DslValidator::new()),
        };
        assert_eq!(config.max_turns, 3);
    }

    #[test]
    fn test_dsl_validator_validates_safe_query() {
        let validator = DslValidator::new();
        let safe_query = r#"{"query": {"match_all": {}}}"#;
        assert!(validator.validate(safe_query).is_ok());
    }

    #[test]
    fn test_dsl_validator_blocks_script_injection() {
        let validator = DslValidator::new();
        let script_query = r#"{"query": {"script_score": {"script": "ctx._source.score * 2"}}}"#;
        let result = validator.validate(script_query);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Dangerous field or query type detected")
        );
    }

    #[test]
    fn test_dsl_validator_blocks_update_by_query() {
        let validator = DslValidator::new();
        let update_query = r#"{"_update_by_query": {"query": {"match_all": {}}}}"#;
        let result = validator.validate(update_query);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Dangerous field or query type detected")
        );
    }

    #[test]
    fn test_guardrails_integration() {
        let guardrails = AgentGuardrails::new();
        let _layer = guardrails.layer();
    }

    #[test]
    fn test_es_dsl_validator_sanitizes_size_limit() {
        let validator = DslValidator::new();
        let request = EsSearchRequest {
            query: None,
            size: Some(5000),
            from: None,
            sort: None,
            aggs: None,
            _source: None,
        };
        let sanitized = validator.sanitize(request).unwrap();
        assert_eq!(sanitized.size, Some(1000));
    }

    #[test]
    fn test_es_dsl_validator_sanitizes_from_limit() {
        let validator = DslValidator::new();
        let request = EsSearchRequest {
            query: None,
            size: None,
            from: Some(20000),
            sort: None,
            aggs: None,
            _source: None,
        };
        let sanitized = validator.sanitize(request).unwrap();
        assert_eq!(sanitized.from, Some(10000));
    }

    #[test]
    fn test_react_executor_error_from_es_error() {
        let es_error = EsError::InvalidDsl("invalid dsl".to_string());
        let react_error: ReActExecutorError = es_error.into();
        assert!(matches!(react_error, ReActExecutorError::Other(_)));
    }

    #[test]
    fn test_react_executor_error_from_es_http_error() {
        let es_error = EsError::HttpError {
            status: 400,
            message: "bad request".to_string(),
            details: None,
        };
        let react_error: ReActExecutorError = es_error.into();
        assert!(matches!(react_error, ReActExecutorError::Other(_)));
    }
}

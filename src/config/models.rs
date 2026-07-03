use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,

    #[serde(default)]
    pub llm: LlmConfig,

    #[serde(default)]
    pub email: EmailConfig,

    /// Legacy Mailjet-only email configuration. New configs should use
    /// `email`, but this remains so existing local config files keep working.
    #[serde(default)]
    pub mailjet: MailjetConfig,

    #[serde(default)]
    pub elasticsearch: ElasticsearchConfig,

    #[serde(default)]
    pub kubernetes: KubernetesConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    #[serde(default)]
    pub web: WebConfig,

    #[serde(default)]
    pub scheduler: SchedulerConfig,

    #[serde(default)]
    pub enforcement: EnforcementConfig,
}

/// Controls whether approving an incident actually enforces a block in the
/// cluster or is a no-op dry run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    /// When true (default), approving an incident updates the configured
    /// Traefik deny route. Set false for local dry-run review only.
    #[serde(default = "default_enforcement_enabled")]
    pub enabled: bool,

    /// Namespace containing the Traefik edge deny IngressRoute.
    #[serde(default = "default_enforcement_namespace")]
    pub namespace: String,

    /// IngressRoute updated when applying IP blocks.
    #[serde(default = "default_edge_ingressroute_name")]
    pub edge_ingressroute_name: String,

    /// Service that the edge deny route sends blocked traffic to.
    #[serde(default = "default_edge_deny_service_name")]
    pub edge_deny_service_name: String,

    /// Service port that the edge deny route sends blocked traffic to.
    #[serde(default = "default_edge_deny_service_port")]
    pub edge_deny_service_port: u16,
}

fn default_enforcement_enabled() -> bool {
    true
}

fn default_enforcement_namespace() -> String {
    "traefik".to_string()
}

fn default_edge_ingressroute_name() -> String {
    "edge-ip-deny".to_string()
}

fn default_edge_deny_service_name() -> String {
    "edge-deny".to_string()
}

fn default_edge_deny_service_port() -> u16 {
    80
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: default_enforcement_enabled(),
            namespace: default_enforcement_namespace(),
            edge_ingressroute_name: default_edge_ingressroute_name(),
            edge_deny_service_name: default_edge_deny_service_name(),
            edge_deny_service_port: default_edge_deny_service_port(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    #[clap(name = "analyze")]
    Analyze,
    #[clap(name = "serve-spa")]
    ServeSpa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    #[serde(default)]
    pub provider: String,

    #[serde(default)]
    pub url: String,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default)]
    pub model: String,

    #[serde(default)]
    pub temperature: f32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: "openai".to_string(),
            url: "http://127.0.0.1:8080/v1".to_string(),
            api_key: Some("local".to_string()),
            model: "local-model".to_string(),
            temperature: 0.1,
        }
    }
}

impl LlmConfig {
    pub fn create_provider(&self) -> Result<Arc<dyn autoagents_llm::LLMProvider>, String> {
        use crate::llm::provider::{LLMProviderFactory, LLMProviderType};
        let provider_type = LLMProviderType::from_str(&self.provider).map_err(|e| e.to_string())?;
        let factory = LLMProviderFactory::create(
            provider_type,
            if self.url.is_empty() {
                None
            } else {
                Some(self.url.clone())
            },
            self.api_key.clone(),
            if self.model.is_empty() {
                None
            } else {
                Some(self.model.clone())
            },
            self.temperature,
        )
        .map_err(|e| e.to_string())?;
        Ok(match factory {
            crate::llm::provider::LLMProviderImpl::Ollama(p) => {
                p.inner().clone() as Arc<dyn autoagents_llm::LLMProvider>
            }
            crate::llm::provider::LLMProviderImpl::OpenAI(p) => {
                p.inner().clone() as Arc<dyn autoagents_llm::LLMProvider>
            }
            crate::llm::provider::LLMProviderImpl::Anthropic(p) => {
                p.inner().clone() as Arc<dyn autoagents_llm::LLMProvider>
            }
            crate::llm::provider::LLMProviderImpl::DeepSeek(p) => {
                p.inner().clone() as Arc<dyn autoagents_llm::LLMProvider>
            }
            crate::llm::provider::LLMProviderImpl::Groq(p) => {
                p.inner().clone() as Arc<dyn autoagents_llm::LLMProvider>
            }
            crate::llm::provider::LLMProviderImpl::OpenRouter(p) => {
                p.inner().clone() as Arc<dyn autoagents_llm::LLMProvider>
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailjetConfig {
    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default)]
    pub api_secret: Option<String>,

    #[serde(default = "default_mailjet_from_email")]
    pub from_email: String,

    #[serde(default = "default_mailjet_from_name")]
    pub from_name: String,

    #[serde(default = "default_mailjet_endpoint")]
    pub endpoint: String,

    /// When true, Mailjet validates the request but does not deliver mail.
    #[serde(default)]
    pub sandbox_mode: bool,
}

fn default_mailjet_from_email() -> String {
    "abuse@example.com".to_string()
}

fn default_mailjet_from_name() -> String {
    "DevOps Agent Abuse Reports".to_string()
}

fn default_mailjet_endpoint() -> String {
    "https://api.mailjet.com/v3.1/send".to_string()
}

impl Default for MailjetConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            api_secret: None,
            from_email: default_mailjet_from_email(),
            from_name: default_mailjet_from_name(),
            endpoint: default_mailjet_endpoint(),
            sandbox_mode: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// Email provider used for abuse reports: `mailjet` or `postmark`.
    #[serde(default = "default_email_provider")]
    pub provider: String,

    #[serde(default = "default_mailjet_from_email")]
    pub from_email: String,

    #[serde(default = "default_mailjet_from_name")]
    pub from_name: String,

    /// When true, validate provider requests without delivering mail where the
    /// provider supports it. Postmark uses POSTMARK_API_TEST in this mode.
    #[serde(default)]
    pub sandbox_mode: bool,

    #[serde(default)]
    pub mailjet: MailjetEmailConfig,

    #[serde(default)]
    pub postmark: PostmarkEmailConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailjetEmailConfig {
    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default)]
    pub api_secret: Option<String>,

    #[serde(default = "default_mailjet_endpoint")]
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmarkEmailConfig {
    #[serde(default)]
    pub server_token: Option<String>,

    #[serde(default = "default_postmark_endpoint")]
    pub endpoint: String,

    #[serde(default = "default_postmark_message_stream")]
    pub message_stream: String,
}

fn default_email_provider() -> String {
    "mailjet".to_string()
}

fn default_postmark_endpoint() -> String {
    "https://api.postmarkapp.com/email".to_string()
}

fn default_postmark_message_stream() -> String {
    "outbound".to_string()
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            provider: default_email_provider(),
            from_email: default_mailjet_from_email(),
            from_name: default_mailjet_from_name(),
            sandbox_mode: false,
            mailjet: MailjetEmailConfig::default(),
            postmark: PostmarkEmailConfig::default(),
        }
    }
}

impl EmailConfig {
    pub fn normalized_provider(&self) -> String {
        self.provider.trim().to_ascii_lowercase()
    }
}

impl Default for MailjetEmailConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            api_secret: None,
            endpoint: default_mailjet_endpoint(),
        }
    }
}

impl Default for PostmarkEmailConfig {
    fn default() -> Self {
        Self {
            server_token: None,
            endpoint: default_postmark_endpoint(),
            message_stream: default_postmark_message_stream(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticsearchConfig {
    #[serde(default)]
    pub url: String,

    #[serde(default)]
    pub username: Option<String>,

    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default)]
    pub index_prefix: String,

    /// Index or data stream pattern used by scheduled threat detection.
    /// If unset, the legacy `index_prefix` is used as `<prefix>*`.
    #[serde(default)]
    pub index_pattern: Option<String>,

    #[serde(default = "default_es_timeout")]
    pub timeout_seconds: u64,

    /// Accept invalid/self-signed TLS certificates. Intended for local
    /// port-forwarding to ECK-managed Elasticsearch only.
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
}

fn default_es_timeout() -> u64 {
    30
}

impl Default for ElasticsearchConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:9200".to_string(),
            username: None,
            password: None,
            api_key: None,
            index_prefix: "traefik-".to_string(),
            index_pattern: None,
            timeout_seconds: 30,
            tls_insecure_skip_verify: false,
        }
    }
}

impl ElasticsearchConfig {
    pub fn effective_index_pattern(&self) -> String {
        self.index_pattern
            .as_ref()
            .filter(|pattern| !pattern.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| format!("{}*", self.index_prefix))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Optional kube context for this config/profile. The startup harness uses
    /// this before auto-discovering cluster services.
    #[serde(default)]
    pub context: Option<String>,

    #[serde(default)]
    pub kubeconfig: Option<String>,

    #[serde(default)]
    pub namespace: String,

    #[serde(default)]
    pub service_account_token: Option<String>,

    #[serde(default = "default_k8s_timeout")]
    pub timeout_seconds: u64,
}

fn default_k8s_timeout() -> u64 {
    30
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            context: None,
            kubeconfig: None,
            namespace: "traefik".to_string(),
            service_account_token: None,
            timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: PathBuf,

    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

fn default_db_path() -> PathBuf {
    PathBuf::from("data/devops-agent.db")
}

fn default_pool_size() -> u32 {
    5
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            pool_size: default_pool_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_web_host")]
    pub host: String,

    #[serde(default = "default_web_port")]
    pub port: u16,

    #[serde(default = "default_static_dir")]
    pub static_dir: PathBuf,
}

fn default_web_host() -> String {
    "127.0.0.1".to_string()
}

fn default_web_port() -> u16 {
    8080
}

fn default_static_dir() -> PathBuf {
    PathBuf::from("src/web/static")
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            host: default_web_host(),
            port: default_web_port(),
            static_dir: default_static_dir(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    #[serde(default = "default_schedule_interval")]
    pub interval_seconds: u64,

    /// How far back each detection run looks for suspicious activity, in minutes.
    #[serde(default = "default_lookback_minutes")]
    pub lookback_minutes: u64,

    /// Minimum number of 401/403 responses from one source before creating an incident.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u64,

    /// Date field used for the lookback window.
    #[serde(default = "default_scheduler_time_field")]
    pub time_field: String,

    /// HTTP status field in the Traefik access log mapping.
    #[serde(default = "default_scheduler_status_field")]
    pub status_field: String,

    /// Client source IP field in the Traefik access log mapping.
    #[serde(default = "default_scheduler_client_host_field")]
    pub client_host_field: String,

    /// Request method field used for incident details.
    #[serde(default = "default_scheduler_request_method_field")]
    pub request_method_field: String,

    /// Request path field used for incident details.
    #[serde(default = "default_scheduler_request_path_field")]
    pub request_path_field: String,

    /// Request host field used for incident details.
    #[serde(default = "default_scheduler_request_host_field")]
    pub request_host_field: String,
}

fn default_schedule_interval() -> u64 {
    300
}

fn default_lookback_minutes() -> u64 {
    60
}

fn default_failure_threshold() -> u64 {
    10
}

fn default_scheduler_time_field() -> String {
    "StartLocal".to_string()
}

fn default_scheduler_status_field() -> String {
    "DownstreamStatus".to_string()
}

fn default_scheduler_client_host_field() -> String {
    "ClientHost.keyword".to_string()
}

fn default_scheduler_request_method_field() -> String {
    "RequestMethod.keyword".to_string()
}

fn default_scheduler_request_path_field() -> String {
    "RequestPath.keyword".to_string()
}

fn default_scheduler_request_host_field() -> String {
    "RequestHost.keyword".to_string()
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            interval_seconds: default_schedule_interval(),
            lookback_minutes: default_lookback_minutes(),
            failure_threshold: default_failure_threshold(),
            time_field: default_scheduler_time_field(),
            status_field: default_scheduler_status_field(),
            client_host_field: default_scheduler_client_host_field(),
            request_method_field: default_scheduler_request_method_field(),
            request_path_field: default_scheduler_request_path_field(),
            request_host_field: default_scheduler_request_host_field(),
        }
    }
}

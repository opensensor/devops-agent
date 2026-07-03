#![allow(dead_code)]

use autoagents::async_trait;
use autoagents::llm::backends::anthropic::Anthropic;
use autoagents::llm::backends::deepseek::DeepSeek;
use autoagents::llm::backends::groq::Groq;
use autoagents::llm::backends::ollama::Ollama;
use autoagents::llm::backends::openai::OpenAI;
use autoagents::llm::backends::openrouter::OpenRouter;
use autoagents::llm::builder::LLMBuilder;
use autoagents::llm::chat::{ChatMessage, ChatProvider, StructuredOutputFormat};
use autoagents::llm::error::LLMError;
use std::sync::Arc;

fn optional_base_url(base_url: Option<String>) -> Option<String> {
    base_url
        .map(|url| url.trim().trim_end_matches('/').to_string())
        .filter(|url| !url.is_empty())
}

fn normalize_openai_compatible_base_url(
    base_url: Option<String>,
) -> Result<Option<String>, LLMError> {
    optional_base_url(base_url)
        .map(|mut url| {
            const CHAT_COMPLETIONS_SUFFIX: &str = "/chat/completions";
            if url.ends_with(CHAT_COMPLETIONS_SUFFIX) {
                let new_len = url.len() - CHAT_COMPLETIONS_SUFFIX.len();
                url.truncate(new_len);
                url = url.trim_end_matches('/').to_string();
            }
            reqwest::Url::parse(&format!("{}/", url.trim_end_matches('/'))).map_err(|e| {
                LLMError::InvalidRequest(format!("Invalid OpenAI-compatible base URL: {}", e))
            })?;
            Ok(url)
        })
        .transpose()
}

/// Supported LLM provider types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LLMProviderType {
    /// URL-based provider (Ollama/local models)
    Ollama,
    /// API key-based provider (OpenAI)
    OpenAI,
    /// API key-based provider (Anthropic)
    Anthropic,
    /// API key-based provider (DeepSeek)
    DeepSeek,
    /// API key-based provider (Groq)
    Groq,
    /// API key-based provider (OpenRouter)
    OpenRouter,
}

impl std::str::FromStr for LLMProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ollama" => Ok(LLMProviderType::Ollama),
            "openai" => Ok(LLMProviderType::OpenAI),
            "anthropic" => Ok(LLMProviderType::Anthropic),
            "deepseek" => Ok(LLMProviderType::DeepSeek),
            "groq" => Ok(LLMProviderType::Groq),
            "openrouter" => Ok(LLMProviderType::OpenRouter),
            _ => Err(format!("Unknown LLM provider type: {s}")),
        }
    }
}

impl std::fmt::Display for LLMProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LLMProviderType::Ollama => "ollama",
            LLMProviderType::OpenAI => "openai",
            LLMProviderType::Anthropic => "anthropic",
            LLMProviderType::DeepSeek => "deepseek",
            LLMProviderType::Groq => "groq",
            LLMProviderType::OpenRouter => "openrouter",
        };
        f.write_str(s)
    }
}

/// LLM provider implementations
pub enum LLMProviderImpl {
    Ollama(OllamaProvider),
    OpenAI(OpenAIProvider),
    Anthropic(AnthropicProvider),
    DeepSeek(DeepSeekProvider),
    Groq(GroqProvider),
    OpenRouter(OpenRouterProvider),
}

/// Unified LLM provider trait that wraps autoagents LLM backend
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Generate text from a prompt or messages
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError>;

    /// Generate text with structured output format
    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError>;
}

/// LLM provider implementation for Ollama (URL-based)
pub struct OllamaProvider {
    inner: Arc<Ollama>,
}

impl OllamaProvider {
    pub fn new(
        base_url: String,
        model: Option<String>,
        temperature: f32,
    ) -> Result<Self, LLMError> {
        let ollama = LLMBuilder::<Ollama>::new()
            .base_url(base_url)
            .model(model.unwrap_or_else(|| "llama3.1".to_string()))
            .temperature(temperature)
            .build()?;
        Ok(OllamaProvider { inner: ollama })
    }

    pub fn inner(&self) -> &Arc<Ollama> {
        &self.inner
    }
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, None).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }

    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, json_schema).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }
}

/// LLM provider implementation for OpenAI (API key-based)
pub struct OpenAIProvider {
    inner: Arc<OpenAI>,
}

impl OpenAIProvider {
    pub fn new(
        api_key: String,
        base_url: Option<String>,
        model: Option<String>,
        temperature: f32,
    ) -> Result<Self, LLMError> {
        let mut builder = LLMBuilder::<OpenAI>::new()
            .api_key(api_key)
            .model(model.unwrap_or_else(|| "gpt-4.1-nano".to_string()))
            .temperature(temperature);

        if let Some(url) = normalize_openai_compatible_base_url(base_url)? {
            builder = builder.base_url(url);
        }

        let openai = builder.build()?;
        Ok(OpenAIProvider { inner: openai })
    }

    pub fn inner(&self) -> &Arc<OpenAI> {
        &self.inner
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, None).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }

    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, json_schema).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }
}

/// LLM provider implementation for Anthropic (API key-based)
pub struct AnthropicProvider {
    inner: Arc<Anthropic>,
}

impl AnthropicProvider {
    pub fn new(api_key: String, model: Option<String>, temperature: f32) -> Result<Self, LLMError> {
        let anthropic = LLMBuilder::<Anthropic>::new()
            .api_key(api_key)
            .model(model.unwrap_or_else(|| "claude-sonnet-4-20250514".to_string()))
            .temperature(temperature)
            .build()?;
        Ok(AnthropicProvider { inner: anthropic })
    }

    pub fn inner(&self) -> &Arc<Anthropic> {
        &self.inner
    }
}

#[async_trait]
impl LLMProvider for AnthropicProvider {
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, None).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }

    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, json_schema).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }
}

/// LLM provider implementation for DeepSeek (API key-based)
pub struct DeepSeekProvider {
    inner: Arc<DeepSeek>,
}

impl DeepSeekProvider {
    pub fn new(
        api_key: String,
        base_url: Option<String>,
        model: Option<String>,
        temperature: f32,
    ) -> Result<Self, LLMError> {
        let deepseek = DeepSeek::new_with_options(
            api_key,
            normalize_openai_compatible_base_url(base_url)?,
            model.or_else(|| Some("deepseek-chat".to_string())),
            None,
            Some(temperature),
            None,
            None,
            None,
        );
        Ok(DeepSeekProvider {
            inner: Arc::new(deepseek),
        })
    }

    pub fn inner(&self) -> &Arc<DeepSeek> {
        &self.inner
    }
}

#[async_trait]
impl LLMProvider for DeepSeekProvider {
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, None).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }

    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, json_schema).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }
}

/// LLM provider implementation for Groq (API key-based)
pub struct GroqProvider {
    inner: Arc<Groq>,
}

impl GroqProvider {
    pub fn new(
        api_key: String,
        base_url: Option<String>,
        model: Option<String>,
        temperature: f32,
    ) -> Result<Self, LLMError> {
        let mut builder = LLMBuilder::<Groq>::new()
            .api_key(api_key)
            .model(model.unwrap_or_else(|| "llama-3.3-70b-versatile".to_string()))
            .temperature(temperature);

        if let Some(url) = normalize_openai_compatible_base_url(base_url)? {
            builder = builder.base_url(url);
        }

        let groq = builder.build()?;
        Ok(GroqProvider { inner: groq })
    }

    pub fn inner(&self) -> &Arc<Groq> {
        &self.inner
    }
}

#[async_trait]
impl LLMProvider for GroqProvider {
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, None).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }

    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, json_schema).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }
}

/// LLM provider implementation for OpenRouter (API key-based)
pub struct OpenRouterProvider {
    inner: Arc<OpenRouter>,
}

impl OpenRouterProvider {
    pub fn new(
        api_key: String,
        base_url: Option<String>,
        model: Option<String>,
        temperature: f32,
    ) -> Result<Self, LLMError> {
        let mut builder = LLMBuilder::<OpenRouter>::new()
            .api_key(api_key)
            .model(model.unwrap_or_else(|| "anthropic/claude-sonnet-4-20250514".to_string()))
            .temperature(temperature);

        if let Some(url) = normalize_openai_compatible_base_url(base_url)? {
            builder = builder.base_url(url);
        }

        let openrouter = builder.build()?;
        Ok(OpenRouterProvider { inner: openrouter })
    }

    pub fn inner(&self) -> &Arc<OpenRouter> {
        &self.inner
    }
}

#[async_trait]
impl LLMProvider for OpenRouterProvider {
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, None).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }

    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError> {
        let response = self.inner.chat(&messages, json_schema).await?;
        response
            .text()
            .ok_or_else(|| LLMError::ProviderError("No text in response".to_string()))
    }
}

/// LLM Provider Factory
#[derive(Debug, Clone)]
pub struct LLMProviderFactory;

impl LLMProviderFactory {
    /// Create an LLM provider from configuration
    ///
    /// # Arguments
    ///
    /// * `provider_type` - The type of LLM provider (Ollama, OpenAI, etc.)
    /// * `base_url` - Base URL for the provider (used for Ollama/local models)
    /// * `api_key` - API key for the provider (used for OpenAI, Anthropic, etc.)
    /// * `model` - Model name to use
    pub fn create(
        provider_type: LLMProviderType,
        base_url: Option<String>,
        api_key: Option<String>,
        model: Option<String>,
        temperature: f32,
    ) -> Result<LLMProviderImpl, LLMError> {
        match provider_type {
            LLMProviderType::Ollama => {
                let url = optional_base_url(base_url).ok_or_else(|| {
                    LLMError::InvalidRequest("Base URL is required for Ollama provider".to_string())
                })?;
                let provider = OllamaProvider::new(url, model, temperature)?;
                Ok(LLMProviderImpl::Ollama(provider))
            }
            LLMProviderType::OpenAI => {
                let key = api_key.ok_or_else(|| {
                    LLMError::InvalidRequest("API key is required for OpenAI provider".to_string())
                })?;
                let provider = OpenAIProvider::new(key, base_url, model, temperature)?;
                Ok(LLMProviderImpl::OpenAI(provider))
            }
            LLMProviderType::Anthropic => {
                let key = api_key.ok_or_else(|| {
                    LLMError::InvalidRequest(
                        "API key is required for Anthropic provider".to_string(),
                    )
                })?;
                let provider = AnthropicProvider::new(key, model, temperature)?;
                Ok(LLMProviderImpl::Anthropic(provider))
            }
            LLMProviderType::DeepSeek => {
                let key = api_key.ok_or_else(|| {
                    LLMError::InvalidRequest(
                        "API key is required for DeepSeek provider".to_string(),
                    )
                })?;
                let provider = DeepSeekProvider::new(key, base_url, model, temperature)?;
                Ok(LLMProviderImpl::DeepSeek(provider))
            }
            LLMProviderType::Groq => {
                let key = api_key.ok_or_else(|| {
                    LLMError::InvalidRequest("API key is required for Groq provider".to_string())
                })?;
                let provider = GroqProvider::new(key, base_url, model, temperature)?;
                Ok(LLMProviderImpl::Groq(provider))
            }
            LLMProviderType::OpenRouter => {
                let key = api_key.ok_or_else(|| {
                    LLMError::InvalidRequest(
                        "API key is required for OpenRouter provider".to_string(),
                    )
                })?;
                let provider = OpenRouterProvider::new(key, base_url, model, temperature)?;
                Ok(LLMProviderImpl::OpenRouter(provider))
            }
        }
    }

    /// Create an Ollama provider (URL-based)
    pub fn create_ollama(
        base_url: String,
        model: Option<String>,
    ) -> Result<LLMProviderImpl, LLMError> {
        let provider = OllamaProvider::new(base_url, model, 0.1)?;
        Ok(LLMProviderImpl::Ollama(provider))
    }

    /// Create an OpenAI provider (API key-based)
    pub fn create_openai(
        api_key: String,
        model: Option<String>,
    ) -> Result<LLMProviderImpl, LLMError> {
        let provider = OpenAIProvider::new(api_key, None, model, 0.1)?;
        Ok(LLMProviderImpl::OpenAI(provider))
    }
}

#[async_trait]
impl LLMProvider for LLMProviderImpl {
    async fn generate(&self, messages: Vec<ChatMessage>) -> Result<String, LLMError> {
        match self {
            LLMProviderImpl::Ollama(provider) => provider.generate(messages).await,
            LLMProviderImpl::OpenAI(provider) => provider.generate(messages).await,
            LLMProviderImpl::Anthropic(provider) => provider.generate(messages).await,
            LLMProviderImpl::DeepSeek(provider) => provider.generate(messages).await,
            LLMProviderImpl::Groq(provider) => provider.generate(messages).await,
            LLMProviderImpl::OpenRouter(provider) => provider.generate(messages).await,
        }
    }

    async fn generate_structured(
        &self,
        messages: Vec<ChatMessage>,
        json_schema: Option<StructuredOutputFormat>,
    ) -> Result<String, LLMError> {
        match self {
            LLMProviderImpl::Ollama(provider) => {
                provider.generate_structured(messages, json_schema).await
            }
            LLMProviderImpl::OpenAI(provider) => {
                provider.generate_structured(messages, json_schema).await
            }
            LLMProviderImpl::Anthropic(provider) => {
                provider.generate_structured(messages, json_schema).await
            }
            LLMProviderImpl::DeepSeek(provider) => {
                provider.generate_structured(messages, json_schema).await
            }
            LLMProviderImpl::Groq(provider) => {
                provider.generate_structured(messages, json_schema).await
            }
            LLMProviderImpl::OpenRouter(provider) => {
                provider.generate_structured(messages, json_schema).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_llm_provider_type_from_str() {
        assert_eq!(
            LLMProviderType::from_str("ollama").unwrap(),
            LLMProviderType::Ollama
        );
        assert_eq!(
            LLMProviderType::from_str("Ollama").unwrap(),
            LLMProviderType::Ollama
        );
        assert_eq!(
            LLMProviderType::from_str("openai").unwrap(),
            LLMProviderType::OpenAI
        );
        assert_eq!(
            LLMProviderType::from_str("anthropic").unwrap(),
            LLMProviderType::Anthropic
        );
        assert_eq!(
            LLMProviderType::from_str("deepseek").unwrap(),
            LLMProviderType::DeepSeek
        );
        assert_eq!(
            LLMProviderType::from_str("groq").unwrap(),
            LLMProviderType::Groq
        );
        assert_eq!(
            LLMProviderType::from_str("openrouter").unwrap(),
            LLMProviderType::OpenRouter
        );
    }

    #[test]
    fn test_llm_provider_type_from_str_invalid() {
        assert!(LLMProviderType::from_str("invalid_provider").is_err());
    }

    #[test]
    fn test_llm_provider_type_display() {
        assert_eq!(LLMProviderType::Ollama.to_string(), "ollama");
        assert_eq!(LLMProviderType::OpenAI.to_string(), "openai");
        assert_eq!(LLMProviderType::Anthropic.to_string(), "anthropic");
        assert_eq!(LLMProviderType::DeepSeek.to_string(), "deepseek");
        assert_eq!(LLMProviderType::Groq.to_string(), "groq");
        assert_eq!(LLMProviderType::OpenRouter.to_string(), "openrouter");
    }

    #[test]
    fn test_normalize_openai_compatible_base_url() {
        assert_eq!(
            normalize_openai_compatible_base_url(Some(
                "http://127.0.0.1:8080/v1/chat/completions".to_string()
            ))
            .unwrap(),
            Some("http://127.0.0.1:8080/v1".to_string())
        );
        assert_eq!(
            normalize_openai_compatible_base_url(Some("http://127.0.0.1:8080/v1/".to_string()))
                .unwrap(),
            Some("http://127.0.0.1:8080/v1".to_string())
        );
    }

    #[test]
    fn test_normalize_openai_compatible_base_url_rejects_invalid_url() {
        assert!(normalize_openai_compatible_base_url(Some("not a url".to_string())).is_err());
    }
}

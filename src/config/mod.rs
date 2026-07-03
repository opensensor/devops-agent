use crate::config::models::{Config, Mode};
use clap::Parser;
use std::env;
use std::fs;
use std::path::PathBuf;

pub mod models;

#[derive(Parser, Debug)]
#[command(name = "devops-agent")]
#[command(about = "DevOps Network Monitoring Agent", long_about = None)]
pub struct CliArgs {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Operation mode: analyze or serve-spa
    #[arg(short, long, value_name = "MODE")]
    pub mode: Option<Mode>,

    /// Serve SPA web server
    #[arg(long)]
    pub serve_spa: bool,

    /// LLM provider URL
    #[arg(long, value_name = "URL")]
    pub llm_url: Option<String>,

    /// LLM provider type (openai, anthropic, ollama, etc.)
    #[arg(long, value_name = "PROVIDER")]
    pub llm_provider: Option<String>,

    /// LLM API key
    #[arg(long, value_name = "KEY")]
    pub llm_api_key: Option<String>,

    /// Apply approved blocks to the cluster
    #[arg(long, conflicts_with = "dry_run")]
    pub enforce: bool,

    /// Approvals are recorded only; no cluster block is applied
    #[arg(long, conflicts_with = "enforce")]
    pub dry_run: bool,
}

pub fn load_config(cli_args: &CliArgs) -> Result<Config, String> {
    let mut config = Config::default();

    // Load from config file if specified
    let config_path = cli_args
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("config/default.yaml"));

    if config_path.exists() {
        let config_str = fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config file {:?}: {}", config_path, e))?;

        let mut file_config: Config = serde_yaml::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config file {:?}: {}", config_path, e))?;

        // Apply environment variable substitutions for sensitive credentials
        file_config.elasticsearch.username =
            substitute_env_var(&file_config.elasticsearch.username);
        file_config.elasticsearch.password =
            substitute_env_var(&file_config.elasticsearch.password);
        file_config.elasticsearch.api_key = substitute_env_var(&file_config.elasticsearch.api_key);

        file_config.kubernetes.kubeconfig = substitute_env_var(&file_config.kubernetes.kubeconfig);
        file_config.kubernetes.context = substitute_env_var(&file_config.kubernetes.context);
        file_config.kubernetes.service_account_token =
            substitute_env_var(&file_config.kubernetes.service_account_token);

        file_config.llm.api_key = substitute_env_var(&file_config.llm.api_key);

        file_config.email.provider = substitute_env_string(&file_config.email.provider);
        file_config.email.from_email = substitute_env_string(&file_config.email.from_email);
        file_config.email.from_name = substitute_env_string(&file_config.email.from_name);
        file_config.email.mailjet.api_key = substitute_env_var(&file_config.email.mailjet.api_key);
        file_config.email.mailjet.api_secret =
            substitute_env_var(&file_config.email.mailjet.api_secret);
        file_config.email.mailjet.endpoint =
            substitute_env_string(&file_config.email.mailjet.endpoint);
        file_config.email.postmark.server_token =
            substitute_env_var(&file_config.email.postmark.server_token);
        file_config.email.postmark.endpoint =
            substitute_env_string(&file_config.email.postmark.endpoint);
        file_config.email.postmark.message_stream =
            substitute_env_string(&file_config.email.postmark.message_stream);

        file_config.mailjet.api_key = substitute_env_var(&file_config.mailjet.api_key);
        file_config.mailjet.api_secret = substitute_env_var(&file_config.mailjet.api_secret);
        file_config.mailjet.from_email = substitute_env_string(&file_config.mailjet.from_email);
        file_config.mailjet.from_name = substitute_env_string(&file_config.mailjet.from_name);
        file_config.mailjet.endpoint = substitute_env_string(&file_config.mailjet.endpoint);

        apply_legacy_mailjet_config(&mut file_config);

        config = file_config;
    }

    // Override with CLI arguments if provided
    if let Some(mode) = &cli_args.mode {
        config.mode = mode.clone();
    }

    if cli_args.serve_spa {
        config.mode = Mode::ServeSpa;
    }

    if let Some(llm_url) = &cli_args.llm_url {
        config.llm.url = llm_url.clone();
    }

    if let Some(llm_provider) = &cli_args.llm_provider {
        config.llm.provider = llm_provider.clone();
    }

    if let Some(llm_api_key) = &cli_args.llm_api_key {
        config.llm.api_key = Some(llm_api_key.clone());
    }

    if cli_args.enforce {
        config.enforcement.enabled = true;
    }

    if cli_args.dry_run {
        config.enforcement.enabled = false;
    }

    // Override ES credentials with environment variables if set
    if let Ok(es_username) = env::var("ES_USERNAME") {
        config.elasticsearch.username = Some(es_username);
    }

    if let Ok(es_password) = env::var("ES_PASSWORD") {
        config.elasticsearch.password = Some(es_password);
    }

    if let Ok(es_api_key) = env::var("ES_API_KEY") {
        config.elasticsearch.api_key = Some(es_api_key);
    }

    // Override K8s credentials with environment variables if set
    if let Ok(k8s_kubeconfig) = env::var("K8S_KUBECONFIG") {
        config.kubernetes.kubeconfig = Some(k8s_kubeconfig);
    }

    if let Ok(k8s_context) = env::var("K8S_CONTEXT") {
        config.kubernetes.context = Some(k8s_context);
    }

    if let Ok(k8s_service_account_token) = env::var("K8S_SERVICE_ACCOUNT_TOKEN") {
        config.kubernetes.service_account_token = Some(k8s_service_account_token);
    }

    // Override LLM API key with environment variable if set
    if let Ok(llm_api_key) = env::var("LLM_API_KEY") {
        config.llm.api_key = Some(llm_api_key);
    }

    // Override email settings with environment variables if set. Mailjet env
    // names remain supported for backward compatibility.
    if let Ok(mailjet_api_key) = env::var("MAILJET_API_KEY") {
        config.email.mailjet.api_key = Some(mailjet_api_key.clone());
        config.mailjet.api_key = Some(mailjet_api_key);
    }

    if let Ok(mailjet_api_secret) = env::var("MAILJET_API_SECRET") {
        config.email.mailjet.api_secret = Some(mailjet_api_secret.clone());
        config.mailjet.api_secret = Some(mailjet_api_secret);
    }

    if let Ok(email_provider) = env::var("EMAIL_PROVIDER") {
        config.email.provider = email_provider;
    }

    let mailjet_is_active_provider = config.email.normalized_provider() == "mailjet";

    if let Ok(mailjet_from_email) = env::var("MAILJET_FROM_EMAIL") {
        if mailjet_is_active_provider {
            config.email.from_email = mailjet_from_email.clone();
        }
        config.mailjet.from_email = mailjet_from_email;
    }

    if let Ok(mailjet_from_name) = env::var("MAILJET_FROM_NAME") {
        if mailjet_is_active_provider {
            config.email.from_name = mailjet_from_name.clone();
        }
        config.mailjet.from_name = mailjet_from_name;
    }

    if let Ok(mailjet_endpoint) = env::var("MAILJET_ENDPOINT") {
        config.email.mailjet.endpoint = mailjet_endpoint.clone();
        config.mailjet.endpoint = mailjet_endpoint;
    }

    if let Ok(mailjet_sandbox_mode) = env::var("MAILJET_SANDBOX_MODE") {
        let sandbox_mode = parse_bool_env("MAILJET_SANDBOX_MODE", &mailjet_sandbox_mode)?;
        if mailjet_is_active_provider {
            config.email.sandbox_mode = sandbox_mode;
        }
        config.mailjet.sandbox_mode = sandbox_mode;
    }

    if let Ok(email_from_email) = env::var("EMAIL_FROM_EMAIL") {
        config.email.from_email = email_from_email;
    }

    if let Ok(email_from_name) = env::var("EMAIL_FROM_NAME") {
        config.email.from_name = email_from_name;
    }

    if let Ok(email_sandbox_mode) = env::var("EMAIL_SANDBOX_MODE") {
        config.email.sandbox_mode = parse_bool_env("EMAIL_SANDBOX_MODE", &email_sandbox_mode)?;
    }

    if let Ok(postmark_server_token) = env::var("POSTMARK_SERVER_TOKEN") {
        config.email.postmark.server_token = Some(postmark_server_token);
    }

    if let Ok(postmark_endpoint) = env::var("POSTMARK_ENDPOINT") {
        config.email.postmark.endpoint = postmark_endpoint;
    }

    if let Ok(postmark_message_stream) = env::var("POSTMARK_MESSAGE_STREAM") {
        config.email.postmark.message_stream = postmark_message_stream;
    }

    Ok(config)
}

fn substitute_env_var(value: &Option<String>) -> Option<String> {
    match value {
        Some(v) if v.starts_with("${") && v.ends_with("}") => {
            let env_var_name = &v[2..v.len() - 1];
            env::var(env_var_name).ok()
        }
        Some(v) => Some(v.clone()),
        None => None,
    }
}

fn substitute_env_string(value: &str) -> String {
    if value.starts_with("${") && value.ends_with("}") {
        let env_var_name = &value[2..value.len() - 1];
        return env::var(env_var_name).unwrap_or_default();
    }

    value.to_string()
}

fn apply_legacy_mailjet_config(config: &mut Config) {
    if config.mailjet.api_key.is_none() && config.mailjet.api_secret.is_none() {
        return;
    }

    config.email.provider = "mailjet".to_string();
    config.email.from_email = config.mailjet.from_email.clone();
    config.email.from_name = config.mailjet.from_name.clone();
    config.email.sandbox_mode = config.mailjet.sandbox_mode;
    config.email.mailjet.api_key = config.mailjet.api_key.clone();
    config.email.mailjet.api_secret = config.mailjet.api_secret.clone();
    config.email.mailjet.endpoint = config.mailjet.endpoint.clone();
}

fn parse_bool_env(name: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!(
            "{} must be one of true/false, yes/no, on/off, or 1/0",
            name
        )),
    }
}

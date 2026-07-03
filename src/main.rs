mod agent;
mod config;
mod db;
mod elasticsearch;
mod email;
mod k8s;
mod llm;
mod models;
mod scheduler;
mod tools;
mod web;
mod whois;

use agent::DevOpsAgent;
use agent::DevOpsAgentConfig;
use clap::Parser;
use std::sync::Arc;

use crate::config::models::{Mode, SchedulerConfig};
use crate::config::{CliArgs, load_config};
use crate::elasticsearch::{EsClient, EsClientConfig};
use crate::scheduler::Scheduler;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    match dotenvy::dotenv() {
        Ok(path) => tracing::debug!("Loaded environment from {}", path.display()),
        Err(e) if e.not_found() => {}
        Err(e) => eprintln!("Warning: failed to load .env: {}", e),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli_args = CliArgs::parse();

    match load_config(&cli_args) {
        Ok(config) => {
            tracing::info!("Configuration loaded successfully");
            tracing::info!("Mode: {:?}", config.mode);

            match config.mode {
                Mode::Analyze => {
                    tracing::info!("Running in analyze mode");

                    let db =
                        match db::Database::new(&config.database.path, config.database.pool_size)
                            .await
                        {
                            Ok(db) => db,
                            Err(e) => {
                                eprintln!("Error initializing database: {}", e);
                                std::process::exit(1);
                            }
                        };

                    let es_config = EsClientConfig {
                        url: config.elasticsearch.url.clone(),
                        username: config.elasticsearch.username.clone(),
                        password: config.elasticsearch.password.clone(),
                        api_key: config.elasticsearch.api_key.clone(),
                        timeout_seconds: config.elasticsearch.timeout_seconds,
                        tls_insecure_skip_verify: config.elasticsearch.tls_insecure_skip_verify,
                    };

                    let es_client = Arc::new(EsClient::new(es_config));

                    let scheduler_config = SchedulerConfig {
                        interval_seconds: config.scheduler.interval_seconds,
                        lookback_minutes: config.scheduler.lookback_minutes,
                        failure_threshold: config.scheduler.failure_threshold,
                        time_field: config.scheduler.time_field.clone(),
                        status_field: config.scheduler.status_field.clone(),
                        client_host_field: config.scheduler.client_host_field.clone(),
                        request_method_field: config.scheduler.request_method_field.clone(),
                        request_path_field: config.scheduler.request_path_field.clone(),
                        request_host_field: config.scheduler.request_host_field.clone(),
                    };

                    let scheduler = Scheduler::new(
                        scheduler_config,
                        es_client,
                        db.pool.clone(),
                        config.elasticsearch.effective_index_pattern(),
                    );

                    tracing::info!("Starting incident scheduler...");
                    scheduler.run().await;
                }
                Mode::ServeSpa => {
                    tracing::info!("Running in serve-spa mode");

                    let db =
                        match db::Database::new(&config.database.path, config.database.pool_size)
                            .await
                        {
                            Ok(db) => db,
                            Err(e) => {
                                eprintln!("Error initializing database: {}", e);
                                std::process::exit(1);
                            }
                        };

                    let es_config = EsClientConfig {
                        url: config.elasticsearch.url.clone(),
                        username: config.elasticsearch.username.clone(),
                        password: config.elasticsearch.password.clone(),
                        api_key: config.elasticsearch.api_key.clone(),
                        timeout_seconds: config.elasticsearch.timeout_seconds,
                        tls_insecure_skip_verify: config.elasticsearch.tls_insecure_skip_verify,
                    };
                    let es_client = Arc::new(EsClient::new(es_config));
                    let es_client_for_agent = es_client.clone();
                    let es_client_for_web = es_client.clone();
                    let evidence_index_pattern = config.elasticsearch.effective_index_pattern();
                    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                    let scheduler = Scheduler::new(
                        SchedulerConfig {
                            interval_seconds: config.scheduler.interval_seconds,
                            lookback_minutes: config.scheduler.lookback_minutes,
                            failure_threshold: config.scheduler.failure_threshold,
                            time_field: config.scheduler.time_field.clone(),
                            status_field: config.scheduler.status_field.clone(),
                            client_host_field: config.scheduler.client_host_field.clone(),
                            request_method_field: config.scheduler.request_method_field.clone(),
                            request_path_field: config.scheduler.request_path_field.clone(),
                            request_host_field: config.scheduler.request_host_field.clone(),
                        },
                        es_client,
                        db.pool.clone(),
                        evidence_index_pattern.clone(),
                    );
                    tracing::info!("Starting incident scheduler in background...");
                    let scheduler_shutdown = shutdown_rx.clone();
                    let scheduler_handle = tokio::spawn(async move {
                        scheduler.run_until_shutdown(scheduler_shutdown).await;
                    });

                    let signal_shutdown = shutdown_tx.clone();
                    tokio::spawn(async move {
                        match tokio::signal::ctrl_c().await {
                            Ok(()) => {
                                tracing::info!(
                                    "Shutdown signal received, stopping server and scheduler..."
                                );
                                let _ = signal_shutdown.send(true);
                            }
                            Err(e) => {
                                tracing::error!("Failed to listen for shutdown signal: {}", e);
                                let _ = signal_shutdown.send(true);
                            }
                        }
                    });

                    let k8s_client = match create_k8s_client(&config.kubernetes).await {
                        Ok(c) => Some(Arc::new(c)),
                        Err(e) => {
                            if config.enforcement.enabled {
                                tracing::error!(
                                    "Enforcement enabled but Kubernetes client init failed: {}. Blocks will not be applied.",
                                    e
                                );
                            } else {
                                tracing::warn!(
                                    "Kubernetes client init failed: {}. Dry-run override blocks will not be available.",
                                    e
                                );
                            }
                            None
                        }
                    };

                    if config.enforcement.enabled {
                        tracing::info!(
                            "Enforcement ENABLED — approving an incident will update {}/{}",
                            config.enforcement.namespace,
                            config.enforcement.edge_ingressroute_name
                        );
                    } else {
                        tracing::info!(
                            "Enforcement disabled — approvals are dry-run; Apply Block can still override when Kubernetes is available"
                        );
                    }
                    let k8s_for_agent = k8s_client.clone();

                    let (agent, agent_error) = match config.llm.create_provider() {
                        Ok(llm) => (
                            Some(Arc::new(build_agent(
                                &db.pool,
                                es_client_for_agent,
                                k8s_for_agent,
                                config.enforcement.namespace.clone(),
                                llm,
                            ))),
                            None,
                        ),
                        Err(e) => {
                            tracing::warn!(
                                "LLM provider is not available; AI inspection and /api/agent/chat will return 503: {}",
                                e
                            );
                            (
                                None,
                                Some(format!(
                                    "{}. Check llm.provider, llm.url, llm.api_key, or LLM_API_KEY.",
                                    e
                                )),
                            )
                        }
                    };

                    let app_state = web::api::AppState {
                        db_pool: db.pool.clone(),
                        enforce: config.enforcement.enabled,
                        block_namespace: config.enforcement.namespace.clone(),
                        edge_ingressroute_name: config.enforcement.edge_ingressroute_name.clone(),
                        edge_deny_service_name: config.enforcement.edge_deny_service_name.clone(),
                        edge_deny_service_port: config.enforcement.edge_deny_service_port,
                        es_client: es_client_for_web,
                        evidence_index_pattern,
                        scheduler_config: config.scheduler.clone(),
                        k8s_client,
                        whois_client: whois::WhoisClient::new(),
                        email_client: email::EmailClient::new(config.email.clone()),
                        agent,
                        agent_error,
                    };

                    tracing::info!(
                        "Serving SPA on http://{}:{}",
                        config.web.host,
                        config.web.port
                    );
                    let server_shutdown = shutdown_rx.clone();
                    let server_result = web::start_server_with_shutdown(
                        config.web.host.clone(),
                        config.web.port,
                        app_state,
                        config.web.static_dir.clone(),
                        async move {
                            let mut server_shutdown = server_shutdown;
                            let _ = server_shutdown.changed().await;
                        },
                    )
                    .await;

                    let _ = shutdown_tx.send(true);
                    if let Err(e) = scheduler_handle.await {
                        tracing::warn!("Scheduler task did not shut down cleanly: {}", e);
                    }

                    match server_result {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Error starting server: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            std::process::exit(1);
        }
    }
}

fn build_agent(
    db_pool: &sqlx::SqlitePool,
    es_client: Arc<EsClient>,
    k8s_client: Option<Arc<kube::Client>>,
    namespace: String,
    llm: Arc<dyn autoagents_llm::LLMProvider>,
) -> DevOpsAgent {
    let agent = DevOpsAgent::new(DevOpsAgentConfig::default(), llm)
        .with_es_client(es_client)
        .with_db_pool(db_pool.clone())
        .with_namespace(namespace);

    if let Some(k8s_client) = k8s_client {
        agent.with_k8s_client(k8s_client)
    } else {
        agent
    }
}

async fn create_k8s_client(
    config: &crate::config::models::KubernetesConfig,
) -> Result<kube::Client, String> {
    let Some(context) = config
        .context
        .as_deref()
        .map(str::trim)
        .filter(|context| !context.is_empty())
    else {
        return kube::Client::try_default().await.map_err(|e| e.to_string());
    };

    let kubeconfig_options = kube::config::KubeConfigOptions {
        context: Some(context.to_string()),
        ..Default::default()
    };
    let kube_config = kube::Config::from_kubeconfig(&kubeconfig_options)
        .await
        .map_err(|e| e.to_string())?;
    kube::Client::try_from(kube_config).map_err(|e| e.to_string())
}

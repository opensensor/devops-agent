use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
};
use rust_xlsxwriter::Workbook;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use crate::agent::DevOpsAgent;
use autoagents::core::agent::AgentExecutor;
use autoagents::core::agent::Context;
use autoagents::core::agent::prebuilt::executor::ReActAgent;
use autoagents::core::agent::task::Task;

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentResponse {
    pub id: String,
    pub source_ip: String,
    pub detected_at: String,
    pub status: String,
    pub failure_count: i64,
    pub action_type: Option<String>,
    pub action_status: Option<String>,
    pub report_status: Option<String>,
    pub report_sent_at: Option<String>,
    pub report_last_attempt_at: Option<String>,
    pub cluster_blocked: Option<bool>,
    pub block_applied: bool,
    /// Structured detection metrics (status breakdown, methods, top paths,
    /// targeted hosts, window, last-seen). `null` for legacy rows.
    pub details: Option<serde_json::Value>,
}

impl IncidentResponse {
    fn from_incident_and_action(
        incident: crate::db::queries::IncidentDb,
        block_action: Option<crate::db::queries::ActionDb>,
        report_action: Option<crate::db::queries::ActionDb>,
        sent_report_action: Option<crate::db::queries::ActionDb>,
        cluster_blocked: Option<bool>,
    ) -> Self {
        let details = incident
            .details
            .as_deref()
            .and_then(|d| serde_json::from_str(d).ok());
        let action_type = block_action.as_ref().map(|a| a.action_type.clone());
        let action_status = block_action.as_ref().map(|a| a.status.clone());
        let report_status = report_action.as_ref().map(|a| a.status.clone());
        let report_last_attempt_at = report_action.as_ref().map(|a| a.updated_at.clone());
        let report_sent_at = sent_report_action.as_ref().map(|a| a.updated_at.clone());
        let block_applied =
            cluster_blocked.unwrap_or_else(|| action_status.as_deref() == Some("completed"));
        Self {
            id: incident.id,
            source_ip: incident.source_ip,
            detected_at: incident.detected_at,
            status: incident.status,
            failure_count: incident.failure_count,
            action_type,
            action_status,
            report_status,
            report_sent_at,
            report_last_attempt_at,
            cluster_blocked,
            block_applied,
            details,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecommendationResponse {
    pub incident_id: String,
    pub recommendation: String,
    pub action_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AiInspectResponse {
    pub incident_id: String,
    pub source_ip: String,
    pub analysis: String,
    pub evidence_count: usize,
    pub tool_calls: serde_json::Value,
    pub done: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbuseReportResponse {
    pub incident_id: String,
    pub source_ip: String,
    pub provider: String,
    pub recipients: Vec<String>,
    pub sandbox_mode: bool,
    pub already_sent: bool,
    pub sent_at: Option<String>,
    pub evidence_count: usize,
    pub provider_response: serde_json::Value,
}

#[derive(Debug, Default, Deserialize)]
struct SendAbuseReportRequest {
    #[serde(default)]
    force: bool,
    #[serde(default)]
    ai_inspection: Option<AiInspectionReportContext>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct AiInspectionReportContext {
    #[serde(default)]
    analysis: String,
    #[serde(default)]
    evidence_count: Option<usize>,
    #[serde(default)]
    done: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllowlistIpResponse {
    pub id: i64,
    pub ip: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<crate::db::queries::AllowlistIp> for AllowlistIpResponse {
    fn from(ip: crate::db::queries::AllowlistIp) -> Self {
        Self {
            id: ip.id,
            ip: ip.ip,
            description: ip.description,
            created_at: ip.created_at,
            updated_at: ip.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AddAllowlistIpRequest {
    pub ip: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn new(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db_pool: SqlitePool,
    /// Enforcement settings; when `enforce` is true and `k8s_client` is present,
    /// approving an incident updates the configured Traefik edge deny route.
    pub enforce: bool,
    pub block_namespace: String,
    pub edge_ingressroute_name: String,
    pub edge_deny_service_name: String,
    pub edge_deny_service_port: u16,
    pub es_client: Arc<crate::elasticsearch::EsClient>,
    pub evidence_index_pattern: String,
    pub scheduler_config: crate::config::models::SchedulerConfig,
    pub k8s_client: Option<std::sync::Arc<kube::Client>>,
    pub whois_client: crate::whois::WhoisClient,
    pub email_client: crate::email::EmailClient,
    pub agent: Option<Arc<DevOpsAgent>>,
    pub agent_error: Option<String>,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/incidents", get(get_incidents))
        .route("/incidents/:id/recommendation", get(get_recommendation))
        .route("/incidents/:id/ai-inspect", post(ai_inspect_incident))
        .route("/incidents/:id/whois", get(get_incident_whois))
        .route("/incidents/:id/report-abuse", post(send_abuse_report))
        .route("/incidents/:id/approve", post(approve_incident))
        .route("/incidents/:id/apply-block", post(apply_block_override))
        .route("/incidents/:id/reject", post(reject_incident))
        .route("/blocks/export/:format", get(export_block_list))
        .route("/allowlist", get(get_allowlist))
        .route("/allowlist", post(add_allowlist_ip))
        .route("/allowlist/:ip", delete(delete_allowlist_ip))
        .route("/agent/chat", post(agent_chat))
        .with_state(state)
}

async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(ApiResponse::<()> {
            success: true,
            data: None,
            message: None,
        }),
    )
}

async fn get_incidents(State(state): State<AppState>) -> impl IntoResponse {
    match crate::db::queries::get_all_incidents(&state.db_pool).await {
        Ok(incidents) => {
            let mut responses = Vec::with_capacity(incidents.len());
            for incident in incidents {
                let block_action = match crate::db::queries::get_latest_action_by_incident_and_type(
                    &state.db_pool,
                    &incident.id,
                    "block_ip",
                )
                .await
                {
                    Ok(action) => action,
                    Err(e) => {
                        tracing::error!(
                            "Failed to get latest block action for incident {}: {}",
                            incident.id,
                            e
                        );
                        None
                    }
                };
                let report_action =
                    match crate::db::queries::get_latest_action_by_incident_and_type(
                        &state.db_pool,
                        &incident.id,
                        "report_abuse",
                    )
                    .await
                    {
                        Ok(action) => action,
                        Err(e) => {
                            tracing::error!(
                                "Failed to get latest abuse-report action for incident {}: {}",
                                incident.id,
                                e
                            );
                            None
                        }
                    };
                let sent_report_action =
                    match crate::db::queries::get_latest_action_by_incident_type_and_status(
                        &state.db_pool,
                        &incident.id,
                        "report_abuse",
                        "completed",
                    )
                    .await
                    {
                        Ok(action) => action,
                        Err(e) => {
                            tracing::error!(
                                "Failed to get completed abuse-report action for incident {}: {}",
                                incident.id,
                                e
                            );
                            None
                        }
                    };
                let cluster_blocked = check_cluster_block(&state, &incident.source_ip).await;
                responses.push(IncidentResponse::from_incident_and_action(
                    incident,
                    block_action,
                    report_action,
                    sent_report_action,
                    cluster_blocked,
                ));
            }
            (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    data: Some(responses),
                    message: None,
                }),
            )
        }
        Err(e) => {
            tracing::error!("Failed to get incidents: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<IncidentResponse>> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incidents: {}", e)),
                }),
            )
        }
    }
}

async fn check_cluster_block(state: &AppState, ip: &str) -> Option<bool> {
    let client = state.k8s_client.as_ref()?;
    let mut blocker =
        crate::k8s::TraefikBlocker::new((**client).clone(), state.block_namespace.clone());
    if let Err(e) = blocker.init_with_detection().await {
        tracing::warn!(
            "Could not initialize Traefik blocker for block check: {}",
            e
        );
        return None;
    }

    match blocker
        .is_ip_blocked_at_edge(ip, &state.edge_ingressroute_name)
        .await
    {
        Ok(blocked) => Some(blocked),
        Err(e) => {
            tracing::warn!("Could not verify cluster block for {}: {}", ip, e);
            None
        }
    }
}

#[derive(Debug, Clone)]
struct BlockListEntry {
    ip: String,
    cidr: String,
    source: String,
    cluster_blocked: Option<bool>,
    block_applied: bool,
    incident_id: Option<String>,
    incident_status: Option<String>,
    failure_count: Option<i64>,
    detected_at: Option<String>,
    block_action_status: Option<String>,
    report_sent_at: Option<String>,
    evidence_summary: String,
}

enum BlockListExportFormat {
    Csv,
    Markdown,
    Xlsx,
}

impl BlockListExportFormat {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "csv" => Some(Self::Csv),
            "md" | "markdown" => Some(Self::Markdown),
            "xlsx" => Some(Self::Xlsx),
            _ => None,
        }
    }

    fn extension(&self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Markdown => "md",
            Self::Xlsx => "xlsx",
        }
    }

    fn content_type(&self) -> &'static str {
        match self {
            Self::Csv => "text/csv; charset=utf-8",
            Self::Markdown => "text/markdown; charset=utf-8",
            Self::Xlsx => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }
    }
}

async fn export_block_list(State(state): State<AppState>, Path(format): Path<String>) -> Response {
    let Some(format) = BlockListExportFormat::parse(&format) else {
        return export_error_response(
            StatusCode::BAD_REQUEST,
            "Unsupported export format. Use csv, markdown, md, or xlsx.",
        );
    };

    let entries = match build_block_list_entries(&state).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!("Failed to build block-list export: {}", e);
            return export_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to build block-list export: {}", e),
            );
        }
    };

    let bytes = match format {
        BlockListExportFormat::Csv => render_block_list_csv(&entries).into_bytes(),
        BlockListExportFormat::Markdown => render_block_list_markdown(&entries).into_bytes(),
        BlockListExportFormat::Xlsx => match render_block_list_xlsx(&entries) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to render block-list XLSX: {}", e);
                return export_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to render block-list XLSX: {}", e),
                );
            }
        },
    };

    let filename = format!(
        "devops-agent-block-list-{}.{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        format.extension()
    );
    file_download_response(bytes, format.content_type(), &filename)
}

async fn build_block_list_entries(state: &AppState) -> Result<Vec<BlockListEntry>, String> {
    let incidents = crate::db::queries::get_all_incidents(&state.db_pool)
        .await
        .map_err(|e| e.to_string())?;
    let mut local_entries = Vec::new();

    for incident in incidents {
        let block_action = crate::db::queries::get_latest_action_by_incident_and_type(
            &state.db_pool,
            &incident.id,
            "block_ip",
        )
        .await
        .map_err(|e| e.to_string())?;
        let report_sent_action = crate::db::queries::get_latest_action_by_incident_type_and_status(
            &state.db_pool,
            &incident.id,
            "report_abuse",
            "completed",
        )
        .await
        .map_err(|e| e.to_string())?;

        if incident.status != "approved" && block_action.is_none() {
            continue;
        }

        let block_action_status = block_action.as_ref().map(|action| action.status.clone());
        local_entries.push(BlockListEntry {
            ip: incident.source_ip.clone(),
            cidr: cidr_for_export_ip(&incident.source_ip),
            source: "local_db".to_string(),
            cluster_blocked: None,
            block_applied: block_action_status.as_deref() == Some("completed"),
            incident_id: Some(incident.id.clone()),
            incident_status: Some(incident.status.clone()),
            failure_count: Some(incident.failure_count),
            detected_at: Some(incident.detected_at.clone()),
            block_action_status,
            report_sent_at: report_sent_action.map(|action| action.updated_at),
            evidence_summary: block_evidence_summary(&incident),
        });
    }

    if let Some(cluster_cidrs) = fetch_cluster_block_cidrs(state).await {
        let mut local_by_ip: BTreeMap<String, BlockListEntry> = local_entries
            .into_iter()
            .map(|entry| (entry.ip.clone(), entry))
            .collect();
        let mut cluster_entries = Vec::new();

        for cidr in cluster_cidrs {
            let ip = ip_from_cidr(&cidr);
            let mut entry = local_by_ip
                .remove(&ip)
                .unwrap_or_else(|| cluster_only_block_entry(&ip, &cidr));
            entry.ip = ip;
            entry.cidr = cidr;
            entry.source = "cluster".to_string();
            entry.cluster_blocked = Some(true);
            entry.block_applied = true;
            cluster_entries.push(entry);
        }

        cluster_entries.sort_by(|a, b| a.ip.cmp(&b.ip));
        return Ok(cluster_entries);
    }

    local_entries.sort_by(|a, b| a.ip.cmp(&b.ip));
    Ok(local_entries)
}

async fn fetch_cluster_block_cidrs(state: &AppState) -> Option<Vec<String>> {
    let client = state.k8s_client.as_ref()?;
    let mut blocker =
        crate::k8s::TraefikBlocker::new((**client).clone(), state.block_namespace.clone());
    if let Err(e) = blocker.init_with_detection().await {
        tracing::warn!(
            "Could not initialize Traefik blocker for block-list export: {}",
            e
        );
        return None;
    }

    match blocker
        .blocked_cidrs_at_edge(&state.edge_ingressroute_name)
        .await
    {
        Ok(cidrs) => Some(cidrs),
        Err(e) => {
            tracing::warn!("Could not read cluster block list: {}", e);
            None
        }
    }
}

fn cluster_only_block_entry(ip: &str, cidr: &str) -> BlockListEntry {
    BlockListEntry {
        ip: ip.to_string(),
        cidr: cidr.to_string(),
        source: "cluster".to_string(),
        cluster_blocked: Some(true),
        block_applied: true,
        incident_id: None,
        incident_status: None,
        failure_count: None,
        detected_at: None,
        block_action_status: None,
        report_sent_at: None,
        evidence_summary: String::new(),
    }
}

fn cidr_for_export_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => format!("{}/32", ip),
        Ok(IpAddr::V6(_)) => format!("{}/128", ip),
        Err(_) => ip.to_string(),
    }
}

fn ip_from_cidr(cidr: &str) -> String {
    cidr.strip_suffix("/32")
        .or_else(|| cidr.strip_suffix("/128"))
        .unwrap_or(cidr)
        .to_string()
}

fn block_evidence_summary(incident: &crate::db::queries::IncidentDb) -> String {
    let details: Option<serde_json::Value> = incident
        .details
        .as_deref()
        .and_then(|d| serde_json::from_str(d).ok());
    let Some(details) = details else {
        return String::new();
    };

    let hosts = compact_detail_pairs(&details, "target_hosts", 3);
    let paths = compact_detail_pairs(&details, "top_paths", 3);
    match (hosts.is_empty(), paths.is_empty()) {
        (false, false) => format!("hosts: {}; paths: {}", hosts, paths),
        (false, true) => format!("hosts: {}", hosts),
        (true, false) => format!("paths: {}", paths),
        (true, true) => String::new(),
    }
}

fn compact_detail_pairs(details: &serde_json::Value, key: &str, limit: usize) -> String {
    details
        .get(key)
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .take(limit)
                .filter_map(|item| {
                    let name = item
                        .get(0)
                        .and_then(|value| value.as_str())
                        .map(str::to_string)
                        .or_else(|| item.get(0).map(|value| value.to_string()))?;
                    let count = item.get(1).and_then(|value| value.as_i64()).unwrap_or(0);
                    Some(format!("{} ({})", name, count))
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn block_list_headers() -> [&'static str; 12] {
    [
        "ip",
        "cidr",
        "source",
        "cluster_blocked",
        "block_applied",
        "incident_id",
        "incident_status",
        "failure_count",
        "detected_at",
        "block_action_status",
        "report_sent_at",
        "evidence_summary",
    ]
}

fn block_list_row(entry: &BlockListEntry) -> [String; 12] {
    [
        entry.ip.clone(),
        entry.cidr.clone(),
        entry.source.clone(),
        optional_bool(entry.cluster_blocked),
        entry.block_applied.to_string(),
        entry.incident_id.clone().unwrap_or_default(),
        entry.incident_status.clone().unwrap_or_default(),
        entry
            .failure_count
            .map(|count| count.to_string())
            .unwrap_or_default(),
        entry.detected_at.clone().unwrap_or_default(),
        entry.block_action_status.clone().unwrap_or_default(),
        entry.report_sent_at.clone().unwrap_or_default(),
        entry.evidence_summary.clone(),
    ]
}

fn optional_bool(value: Option<bool>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn render_block_list_csv(entries: &[BlockListEntry]) -> String {
    let mut output = String::new();
    output.push_str(
        &block_list_headers()
            .into_iter()
            .map(csv_escape)
            .collect::<Vec<_>>()
            .join(","),
    );
    output.push('\n');

    for entry in entries {
        output.push_str(
            &block_list_row(entry)
                .into_iter()
                .map(csv_escape)
                .collect::<Vec<_>>()
                .join(","),
        );
        output.push('\n');
    }

    output
}

fn csv_escape(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn render_block_list_markdown(entries: &[BlockListEntry]) -> String {
    let headers = block_list_headers();
    let mut output = String::from("# DevOps Agent Block List\n\n");
    output.push_str(&format!(
        "Generated: {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));
    output.push('|');
    output.push_str(
        &headers
            .iter()
            .map(|header| markdown_escape(header))
            .collect::<Vec<_>>()
            .join("|"),
    );
    output.push_str("|\n|");
    output.push_str(&headers.iter().map(|_| "---").collect::<Vec<_>>().join("|"));
    output.push_str("|\n");

    for entry in entries {
        output.push('|');
        output.push_str(
            &block_list_row(entry)
                .iter()
                .map(|value| markdown_escape(value))
                .collect::<Vec<_>>()
                .join("|"),
        );
        output.push_str("|\n");
    }

    output
}

fn markdown_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "<br>")
        .replace('\r', "")
}

fn render_block_list_xlsx(
    entries: &[BlockListEntry],
) -> Result<Vec<u8>, rust_xlsxwriter::XlsxError> {
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    worksheet.set_name("Block list")?;

    for (col, header) in block_list_headers().iter().enumerate() {
        worksheet.write_string(0, col as u16, *header)?;
    }

    for (row_idx, entry) in entries.iter().enumerate() {
        let row = (row_idx + 1) as u32;
        for (col, value) in block_list_row(entry).iter().enumerate() {
            worksheet.write_string(row, col as u16, value)?;
        }
    }

    worksheet.autofit();
    workbook.save_to_buffer()
}

fn file_download_response(bytes: Vec<u8>, content_type: &'static str, filename: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    let disposition = format!("attachment; filename=\"{}\"", filename);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    (headers, bytes).into_response()
}

fn export_error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ApiResponse::<()> {
            success: false,
            data: None,
            message: Some(message.to_string()),
        }),
    )
        .into_response()
}

/// Derive a heuristic recommendation from an incident's captured metrics.
fn build_recommendation(incident: &crate::db::queries::IncidentDb) -> RecommendationResponse {
    let details: Option<serde_json::Value> = incident
        .details
        .as_deref()
        .and_then(|d| serde_json::from_str(d).ok());

    // Pull the top requested paths, if present, to spot scanner behaviour.
    let top_paths: Vec<String> = details
        .as_ref()
        .and_then(|d| d.get("top_paths"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get(0).and_then(|k| k.as_str()).map(str::to_string))
                .take(3)
                .collect()
        })
        .unwrap_or_default();

    // Paths that indicate secret/credential/config probing.
    let sensitive = top_paths.iter().any(|p| {
        let p = p.to_lowercase();
        p.contains(".env")
            || p.contains("credential")
            || p.contains(".aws")
            || p.contains(".git")
            || p.contains("phpinfo")
            || p.contains("wp-login")
    });

    let (action_type, recommendation) = if sensitive {
        (
            "block",
            format!(
                "{} sent {} auth-failed requests probing sensitive paths ({}). This is credential/secret scanning — recommend blocking the IP.",
                incident.source_ip,
                incident.failure_count,
                top_paths.join(", ")
            ),
        )
    } else if incident.failure_count >= 100 {
        (
            "block",
            format!(
                "{} generated {} authentication failures — high-volume brute force. Recommend blocking the IP.",
                incident.source_ip, incident.failure_count
            ),
        )
    } else {
        (
            "review",
            format!(
                "{} generated {} authentication failures in the detection window. Review activity before deciding.",
                incident.source_ip, incident.failure_count
            ),
        )
    };

    RecommendationResponse {
        incident_id: incident.id.clone(),
        recommendation,
        action_type: action_type.to_string(),
    }
}

async fn get_recommendation(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    match crate::db::queries::get_incident(&state.db_pool, &incident_id).await {
        Ok(Some(incident)) => {
            let recommendation = build_recommendation(&incident);
            (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    data: Some(recommendation),
                    message: None,
                }),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<RecommendationResponse> {
                success: false,
                data: None,
                message: Some("Incident not found".to_string()),
            }),
        ),
        Err(e) => {
            tracing::error!("Failed to get incident: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<RecommendationResponse> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incident: {}", e)),
                }),
            )
        }
    }
}

async fn ai_inspect_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let Some(agent) = state.agent.as_ref().map(|agent| (**agent).clone()) else {
        let message = state.agent_error.as_deref().map_or_else(
            || "AI inspection is unavailable because no LLM provider is configured".to_string(),
            |error| format!("AI inspection is unavailable: {}", error),
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<AiInspectResponse> {
                success: false,
                data: None,
                message: Some(message),
            }),
        );
    };

    let incident = match crate::db::queries::get_incident(&state.db_pool, &incident_id).await {
        Ok(Some(incident)) => incident,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<AiInspectResponse> {
                    success: false,
                    data: None,
                    message: Some("Incident not found".to_string()),
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get incident for AI inspection: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<AiInspectResponse> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incident: {}", e)),
                }),
            );
        }
    };

    let (log_evidence, evidence_note) =
        match fetch_abuse_report_log_evidence(&state, &incident).await {
            Ok(events) => (events, None),
            Err(e) => {
                tracing::warn!(
                    "Could not fetch raw log evidence for AI inspection {}: {}",
                    incident.source_ip,
                    e
                );
                (Vec::new(), Some(e.to_string()))
            }
        };

    let prompt = build_ai_inspection_prompt(
        &incident,
        &state.evidence_index_pattern,
        &state.scheduler_config,
        &log_evidence,
        evidence_note.as_deref(),
    );
    let task = Task::new(prompt);
    let context = Arc::new(Context::new(agent.llm().clone(), None));
    let react_agent = ReActAgent::with_max_turns(agent, 8);

    match react_agent.execute(&task, context).await {
        Ok(output) => {
            let tool_calls =
                serde_json::to_value(&output.tool_calls).unwrap_or_else(|_| serde_json::json!([]));
            let response = AiInspectResponse {
                incident_id: incident.id,
                source_ip: incident.source_ip,
                analysis: output.response,
                evidence_count: log_evidence.len(),
                tool_calls,
                done: output.done,
            };
            (StatusCode::OK, Json(ApiResponse::new(response)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<AiInspectResponse> {
                success: false,
                data: None,
                message: Some(format!("AI inspection failed: {}", e)),
            }),
        ),
    }
}

async fn get_incident_whois(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let incident = match crate::db::queries::get_incident(&state.db_pool, &incident_id).await {
        Ok(Some(incident)) => incident,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<crate::whois::WhoisInfo> {
                    success: false,
                    data: None,
                    message: Some("Incident not found".to_string()),
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get incident for WHOIS lookup: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<crate::whois::WhoisInfo> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incident: {}", e)),
                }),
            );
        }
    };

    match state.whois_client.lookup_ip(&incident.source_ip).await {
        Ok(info) => (StatusCode::OK, Json(ApiResponse::new(info))),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(ApiResponse::<crate::whois::WhoisInfo> {
                success: false,
                data: None,
                message: Some(e.to_string()),
            }),
        ),
    }
}

async fn send_abuse_report(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_send_abuse_report_request(&body) {
        Ok(request) => request,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<AbuseReportResponse> {
                    success: false,
                    data: None,
                    message: Some(message),
                }),
            );
        }
    };

    let incident = match crate::db::queries::get_incident(&state.db_pool, &incident_id).await {
        Ok(Some(incident)) => incident,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<AbuseReportResponse> {
                    success: false,
                    data: None,
                    message: Some("Incident not found".to_string()),
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get incident for abuse report: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<AbuseReportResponse> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incident: {}", e)),
                }),
            );
        }
    };

    let existing_sent_report =
        match crate::db::queries::get_latest_action_by_incident_type_and_status(
            &state.db_pool,
            &incident.id,
            "report_abuse",
            "completed",
        )
        .await
        {
            Ok(action) => action,
            Err(e) => {
                tracing::error!(
                    "Failed to check completed abuse-report action for {}: {}",
                    incident.source_ip,
                    e
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::<AbuseReportResponse> {
                        success: false,
                        data: None,
                        message: Some(format!("Failed to check prior abuse report: {}", e)),
                    }),
                );
            }
        };

    if let Some(sent_report) = existing_sent_report.as_ref().filter(|_| !request.force) {
        let sent_at = Some(sent_report.updated_at.clone());
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse {
                success: false,
                data: Some(AbuseReportResponse {
                    incident_id: incident.id,
                    source_ip: incident.source_ip,
                    provider: state.email_client.provider_name(),
                    recipients: Vec::new(),
                    sandbox_mode: false,
                    already_sent: true,
                    sent_at: sent_at.clone(),
                    evidence_count: 0,
                    provider_response: serde_json::json!({}),
                }),
                message: Some(format!(
                    "Abuse report was already sent for this incident at {}. Use Send Again to override.",
                    sent_at.unwrap_or_else(|| "an earlier time".to_string())
                )),
            }),
        );
    }

    let action_id = format!(
        "action-report-abuse-{}-{}",
        incident.source_ip,
        chrono::Utc::now().timestamp_millis()
    );
    if let Err(e) =
        crate::db::queries::create_action(&state.db_pool, &action_id, &incident.id, "report_abuse")
            .await
    {
        tracing::error!(
            "Failed to record abuse-report action for {}: {}",
            incident.source_ip,
            e
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<AbuseReportResponse> {
                success: false,
                data: None,
                message: Some(format!("Failed to record abuse-report action: {}", e)),
            }),
        );
    }

    let whois = match state.whois_client.lookup_ip(&incident.source_ip).await {
        Ok(info) => info,
        Err(e) => {
            let _ = crate::db::queries::update_action_status(&state.db_pool, &action_id, "failed")
                .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(ApiResponse::<AbuseReportResponse> {
                    success: false,
                    data: None,
                    message: Some(format!("WHOIS/RDAP lookup failed: {}", e)),
                }),
            );
        }
    };

    let recipients = abuse_report_recipients(&whois);
    if recipients.is_empty() {
        let _ =
            crate::db::queries::update_action_status(&state.db_pool, &action_id, "failed").await;
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<AbuseReportResponse> {
                success: false,
                data: None,
                message: Some("No abuse-report recipient found in WHOIS/RDAP data".to_string()),
            }),
        );
    }

    let log_evidence = match fetch_abuse_report_log_evidence(&state, &incident).await {
        Ok(events) => events,
        Err(e) => {
            tracing::warn!(
                "Could not fetch raw log evidence for abuse report {}: {}",
                incident.source_ip,
                e
            );
            Vec::new()
        }
    };

    let sender_name = state.email_client.sender_name();
    let report = build_abuse_report_email(
        &incident,
        &whois,
        recipients.clone(),
        &sender_name,
        &log_evidence,
        request.ai_inspection.as_ref(),
    );
    match state.email_client.send_abuse_report(&report).await {
        Ok(result) => {
            let _ =
                crate::db::queries::update_action_status(&state.db_pool, &action_id, "completed")
                    .await;
            let sent_at = crate::db::queries::get_latest_action_by_incident_type_and_status(
                &state.db_pool,
                &incident.id,
                "report_abuse",
                "completed",
            )
            .await
            .ok()
            .flatten()
            .map(|action| action.updated_at);
            let sandbox_mode = result.sandbox_mode;
            let response = AbuseReportResponse {
                incident_id: incident.id,
                source_ip: incident.source_ip,
                provider: result.provider.clone(),
                recipients: result.recipients,
                sandbox_mode,
                already_sent: false,
                sent_at,
                evidence_count: log_evidence.len(),
                provider_response: result.provider_response,
            };
            let provider_label = email_provider_label(&result.provider);
            (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    data: Some(response),
                    message: Some(if sandbox_mode {
                        format!(
                            "{} accepted abuse report in sandbox mode; no email was delivered.",
                            provider_label
                        )
                    } else {
                        format!("Abuse report sent via {}", provider_label)
                    }),
                }),
            )
        }
        Err(e) => {
            let _ = crate::db::queries::update_action_status(&state.db_pool, &action_id, "failed")
                .await;
            tracing::error!(
                "Failed to send abuse report for {} via {}: {}",
                incident.source_ip,
                state.email_client.provider_name(),
                e
            );
            (
                email_error_status(&e),
                Json(ApiResponse::<AbuseReportResponse> {
                    success: false,
                    data: None,
                    message: Some(e.to_string()),
                }),
            )
        }
    }
}

fn parse_send_abuse_report_request(body: &[u8]) -> Result<SendAbuseReportRequest, String> {
    if body.is_empty() {
        return Ok(SendAbuseReportRequest::default());
    }

    serde_json::from_slice(body).map_err(|e| format!("Invalid abuse-report request body: {}", e))
}

fn email_error_status(error: &crate::email::EmailError) -> StatusCode {
    match error {
        crate::email::EmailError::MissingCredentials(_) => StatusCode::SERVICE_UNAVAILABLE,
        crate::email::EmailError::InvalidSender(_)
        | crate::email::EmailError::NoRecipients
        | crate::email::EmailError::UnsupportedProvider(_) => StatusCode::BAD_REQUEST,
        crate::email::EmailError::Request { .. } | crate::email::EmailError::Http { .. } => {
            StatusCode::BAD_GATEWAY
        }
    }
}

fn email_provider_label(provider: &str) -> &'static str {
    match provider {
        "mailjet" => "Mailjet",
        "postmark" => "Postmark",
        _ => "email provider",
    }
}

fn abuse_report_recipients(whois: &crate::whois::WhoisInfo) -> Vec<String> {
    let mut seen = BTreeSet::new();
    whois
        .abuse_contacts
        .iter()
        .flat_map(|contact| contact.emails.iter())
        .map(|email| email.trim().to_ascii_lowercase())
        .filter(|email| email.contains('@'))
        .filter(|email| seen.insert(email.clone()))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogEvidenceEvent {
    timestamp: String,
    source_ip: String,
    status: String,
    method: String,
    host: String,
    path: String,
    user_agent: Option<String>,
    index: String,
}

async fn fetch_abuse_report_log_evidence(
    state: &AppState,
    incident: &crate::db::queries::IncidentDb,
) -> Result<Vec<LogEvidenceEvent>, crate::elasticsearch::EsError> {
    let details: Option<serde_json::Value> = incident
        .details
        .as_deref()
        .and_then(|d| serde_json::from_str(d).ok());
    let window = details
        .as_ref()
        .and_then(|d| d.get("window_minutes"))
        .and_then(|v| v.as_i64())
        .filter(|minutes| *minutes > 0)
        .unwrap_or(state.scheduler_config.lookback_minutes as i64);
    let (gte, lte) = evidence_time_range(incident, details.as_ref(), window);
    let cfg = &state.scheduler_config;
    let mut source_fields = vec![
        source_lookup_field(&cfg.time_field),
        source_lookup_field(&cfg.status_field),
        source_lookup_field(&cfg.client_host_field),
        source_lookup_field(&cfg.request_method_field),
        source_lookup_field(&cfg.request_host_field),
        source_lookup_field(&cfg.request_path_field),
        "RequestUserAgent".to_string(),
        "UserAgent".to_string(),
        "RequestAddr".to_string(),
        "OriginStatus".to_string(),
        "RouterName".to_string(),
        "ServiceName".to_string(),
    ];
    source_fields.sort();
    source_fields.dedup();

    let mut time_range = serde_json::Map::new();
    time_range.insert("gte".to_string(), serde_json::json!(gte));
    if let Some(lte) = lte {
        time_range.insert("lte".to_string(), serde_json::json!(lte));
    }

    let dsl_query = serde_json::json!({
        "query": {
            "bool": {
                "must": [
                    { "term": { cfg.client_host_field.clone(): incident.source_ip.clone() } },
                    { "range": { cfg.time_field.clone(): time_range } }
                ],
                "should": [
                    { "term": { cfg.status_field.clone(): 401 } },
                    { "term": { cfg.status_field.clone(): 403 } }
                ],
                "minimum_should_match": 1
            }
        },
        "size": 10,
        "sort": [
            { cfg.time_field.clone(): { "order": "desc" } }
        ],
        "_source": source_fields
    })
    .to_string();

    let response = state
        .es_client
        .execute_raw_dsl(&state.evidence_index_pattern, &dsl_query)
        .await?;

    Ok(response
        .hits
        .hits
        .iter()
        .map(|hit| log_evidence_event_from_hit(hit, cfg))
        .collect())
}

fn evidence_time_range(
    incident: &crate::db::queries::IncidentDb,
    details: Option<&serde_json::Value>,
    window_minutes: i64,
) -> (String, Option<String>) {
    let end = details
        .and_then(|d| d.get("last_seen"))
        .and_then(|v| v.as_str())
        .or(Some(incident.detected_at.as_str()));

    let Some(end) = end.and_then(parse_datetime) else {
        return (format!("now-{}m", window_minutes.max(1)), None);
    };

    let start = end - chrono::Duration::minutes(window_minutes.max(1) + 1);
    let padded_end = end + chrono::Duration::minutes(1);
    (start.to_rfc3339(), Some(padded_end.to_rfc3339()))
}

fn parse_datetime(value: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(value).ok()
}

fn log_evidence_event_from_hit(
    hit: &crate::elasticsearch::queries::Hit,
    cfg: &crate::config::models::SchedulerConfig,
) -> LogEvidenceEvent {
    let source = &hit.source;
    LogEvidenceEvent {
        timestamp: source_string(source, &cfg.time_field).unwrap_or_else(|| "unknown".to_string()),
        source_ip: source_string(source, &cfg.client_host_field)
            .unwrap_or_else(|| "unknown".to_string()),
        status: source_string(source, &cfg.status_field).unwrap_or_else(|| "unknown".to_string()),
        method: source_string(source, &cfg.request_method_field)
            .unwrap_or_else(|| "unknown".to_string()),
        host: source_string(source, &cfg.request_host_field)
            .unwrap_or_else(|| "unknown".to_string()),
        path: source_string(source, &cfg.request_path_field)
            .map(|path| sanitize_path(&path))
            .unwrap_or_else(|| "unknown".to_string()),
        user_agent: source_string(source, "RequestUserAgent")
            .or_else(|| source_string(source, "UserAgent"))
            .map(|value| compact_log_value(&value, 160)),
        index: hit.index.clone(),
    }
}

fn source_lookup_field(field: &str) -> String {
    field.strip_suffix(".keyword").unwrap_or(field).to_string()
}

fn source_string(source: &serde_json::Value, field: &str) -> Option<String> {
    let lookup = source_lookup_field(field);
    source
        .get(&lookup)
        .or_else(|| source.get(field))
        .or_else(|| dotted_value(source, &lookup))
        .and_then(json_value_to_string)
        .map(|value| compact_log_value(&value, 240))
}

fn dotted_value<'a>(source: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
    let mut current = source;
    for part in field.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn json_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn sanitize_path(path: &str) -> String {
    let without_query = path.split('?').next().unwrap_or(path);
    compact_log_value(without_query, 240)
}

fn compact_log_value(value: &str, max_chars: usize) -> String {
    let mut compact = value
        .replace(['\r', '\n', '\t'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if compact.chars().count() > max_chars {
        compact = compact.chars().take(max_chars).collect::<String>();
        compact.push_str("...");
    }
    compact
}

fn build_abuse_report_email(
    incident: &crate::db::queries::IncidentDb,
    whois: &crate::whois::WhoisInfo,
    recipients: Vec<String>,
    sender_name: &str,
    log_evidence: &[LogEvidenceEvent],
    ai_inspection: Option<&AiInspectionReportContext>,
) -> crate::email::AbuseReportEmail {
    let details: Option<serde_json::Value> = incident
        .details
        .as_deref()
        .and_then(|d| serde_json::from_str(d).ok());
    let window = details
        .as_ref()
        .and_then(|d| d.get("window_minutes"))
        .and_then(|v| v.as_i64())
        .unwrap_or(60);
    let status_lines = detail_pair_text(details.as_ref(), "status_breakdown", "Status breakdown");
    let method_lines = detail_pair_text(details.as_ref(), "methods", "Methods");
    let host_lines = detail_pair_text(details.as_ref(), "target_hosts", "Targeted hosts");
    let path_lines = detail_pair_text(details.as_ref(), "top_paths", "Top requested paths");
    let raw_log_lines = raw_log_evidence_text(log_evidence);
    let raw_log_html = raw_log_evidence_html(log_evidence);
    let ai_inspection_text = ai_inspection_report_text(ai_inspection);
    let ai_inspection_html = ai_inspection_report_html(ai_inspection);
    let sender_name = sender_name.trim();
    let sender_name = if sender_name.is_empty() {
        "DevOps Agent"
    } else {
        sender_name
    };

    let subject = format!(
        "Abuse report: suspicious traffic from {} toward monitored services",
        incident.source_ip
    );
    let range = address_range(whois);
    let text_body = format!(
        "{sender_name} observed suspicious authentication-failure traffic from {ip}.\n\n\
Source IP: {ip}\n\
Last seen: {detected_at}\n\
Failures: {failures} HTTP 401/403 responses in the last {window} minutes\n\
Network: {network}\n\
Organization: {organization}\n\
Country: {country}\n\
Address range: {range}\n\
RDAP source: {source}\n\n\
Evidence summary:\n{status_lines}{method_lines}{host_lines}{path_lines}\n\
{ai_inspection_text}\
Raw log sample:\n{raw_log_lines}\n\
Please investigate this source and take appropriate action.\n\n\
Regards,\n{sender_name}\n",
        sender_name = sender_name,
        ip = incident.source_ip,
        detected_at = incident.detected_at,
        failures = incident.failure_count,
        window = window,
        network = whois.network_name.as_deref().unwrap_or("unknown"),
        organization = whois.organization.as_deref().unwrap_or("unknown"),
        country = whois.country.as_deref().unwrap_or("unknown"),
        range = range,
        source = whois.registry_url.as_deref().unwrap_or("unavailable"),
        status_lines = status_lines,
        method_lines = method_lines,
        host_lines = host_lines,
        path_lines = path_lines,
        ai_inspection_text = ai_inspection_text,
        raw_log_lines = raw_log_lines,
    );

    let html_body = format!(
        "<p>{sender_name} observed suspicious authentication-failure traffic from <strong>{ip}</strong>.</p>\
<table>\
<tr><th align=\"left\">Source IP</th><td>{ip}</td></tr>\
<tr><th align=\"left\">Last seen</th><td>{detected_at}</td></tr>\
<tr><th align=\"left\">Failures</th><td>{failures} HTTP 401/403 responses in the last {window} minutes</td></tr>\
<tr><th align=\"left\">Network</th><td>{network}</td></tr>\
<tr><th align=\"left\">Organization</th><td>{organization}</td></tr>\
<tr><th align=\"left\">Country</th><td>{country}</td></tr>\
<tr><th align=\"left\">Address range</th><td>{range}</td></tr>\
<tr><th align=\"left\">RDAP source</th><td>{source}</td></tr>\
</table>\
<h3>Evidence summary</h3>{status_html}{method_html}{host_html}{path_html}\
{ai_inspection_html}\
<h3>Raw log sample</h3>{raw_log_html}\
<p>Please investigate this source and take appropriate action.</p>\
<p>Regards,<br>{sender_name}</p>",
        sender_name = html_escape(sender_name),
        ip = html_escape(&incident.source_ip),
        detected_at = html_escape(&incident.detected_at),
        failures = incident.failure_count,
        window = window,
        network = html_escape(whois.network_name.as_deref().unwrap_or("unknown")),
        organization = html_escape(whois.organization.as_deref().unwrap_or("unknown")),
        country = html_escape(whois.country.as_deref().unwrap_or("unknown")),
        range = html_escape(&range),
        source = html_escape(whois.registry_url.as_deref().unwrap_or("unavailable")),
        status_html = detail_pair_html(details.as_ref(), "status_breakdown", "Status breakdown"),
        method_html = detail_pair_html(details.as_ref(), "methods", "Methods"),
        host_html = detail_pair_html(details.as_ref(), "target_hosts", "Targeted hosts"),
        path_html = detail_pair_html(details.as_ref(), "top_paths", "Top requested paths"),
        ai_inspection_html = ai_inspection_html,
        raw_log_html = raw_log_html,
    );

    crate::email::AbuseReportEmail {
        recipients,
        subject,
        text_body,
        html_body,
        custom_id: Some(incident.id.clone()),
    }
}

fn ai_inspection_report_text(ai_inspection: Option<&AiInspectionReportContext>) -> String {
    let Some(ai_inspection) = ai_inspection else {
        return String::new();
    };
    let analysis = compact_multiline_value(&ai_inspection.analysis, 6000);
    if analysis.trim().is_empty() {
        return String::new();
    }

    let evidence_count = ai_inspection
        .evidence_count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let completion = match ai_inspection.done {
        Some(true) => "complete",
        Some(false) => "partial",
        None => "unknown",
    };

    format!(
        "AI inspection:\n- Evidence events reviewed: {}\n- Result status: {}\n{}\n\n",
        evidence_count, completion, analysis
    )
}

fn ai_inspection_report_html(ai_inspection: Option<&AiInspectionReportContext>) -> String {
    let Some(ai_inspection) = ai_inspection else {
        return String::new();
    };
    let analysis = compact_multiline_value(&ai_inspection.analysis, 6000);
    if analysis.trim().is_empty() {
        return String::new();
    }

    let evidence_count = ai_inspection
        .evidence_count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let completion = match ai_inspection.done {
        Some(true) => "complete",
        Some(false) => "partial",
        None => "unknown",
    };

    format!(
        "<h3>AI inspection</h3>\
<table>\
<tr><th align=\"left\">Evidence events reviewed</th><td>{}</td></tr>\
<tr><th align=\"left\">Result status</th><td>{}</td></tr>\
</table>\
<pre>{}</pre>",
        html_escape(&evidence_count),
        html_escape(completion),
        html_escape(&analysis)
    )
}

fn compact_multiline_value(value: &str, max_chars: usize) -> String {
    let normalized = value
        .replace('\r', "\n")
        .replace('\t', " ")
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");
    if normalized.chars().count() <= max_chars {
        return normalized;
    }

    let mut truncated = normalized.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn detail_pair_text(details: Option<&serde_json::Value>, key: &str, label: &str) -> String {
    let Some(items) = details
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_array())
        .filter(|items| !items.is_empty())
    else {
        return String::new();
    };

    let mut output = format!("{}:\n", label);
    for item in items.iter().take(10) {
        let name = item
            .get(0)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| item.get(0).map(|v| v.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        let count = item.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
        output.push_str(&format!("- {}: {}\n", name, count));
    }
    output
}

fn detail_pair_html(details: Option<&serde_json::Value>, key: &str, label: &str) -> String {
    let Some(items) = details
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_array())
        .filter(|items| !items.is_empty())
    else {
        return String::new();
    };

    let rows = items
        .iter()
        .take(10)
        .map(|item| {
            let name = item
                .get(0)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| item.get(0).map(|v| v.to_string()))
                .unwrap_or_else(|| "unknown".to_string());
            let count = item.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
            format!("<li>{}: {}</li>", html_escape(&name), count)
        })
        .collect::<String>();

    format!("<h4>{}</h4><ul>{}</ul>", html_escape(label), rows)
}

fn raw_log_evidence_text(events: &[LogEvidenceEvent]) -> String {
    if events.is_empty() {
        return "- No matching raw log events were available from Elasticsearch at send time.\n"
            .to_string();
    }

    let mut output = String::new();
    for event in events {
        let user_agent = event
            .user_agent
            .as_deref()
            .map(|ua| format!(" user_agent=\"{}\"", ua))
            .unwrap_or_default();
        output.push_str(&format!(
            "- {timestamp} status={status} method={method} source_ip={source_ip} host={host} path={path} index={index}{user_agent}\n",
            timestamp = event.timestamp,
            status = event.status,
            method = event.method,
            source_ip = event.source_ip,
            host = event.host,
            path = event.path,
            index = event.index,
            user_agent = user_agent,
        ));
    }
    output
}

fn raw_log_evidence_html(events: &[LogEvidenceEvent]) -> String {
    if events.is_empty() {
        return "<p>No matching raw log events were available from Elasticsearch at send time.</p>"
            .to_string();
    }

    let rows = events
        .iter()
        .map(|event| {
            format!(
                "<tr>\
<td>{timestamp}</td>\
<td>{status}</td>\
<td>{method}</td>\
<td>{host}</td>\
<td><code>{path}</code></td>\
<td>{user_agent}</td>\
</tr>",
                timestamp = html_escape(&event.timestamp),
                status = html_escape(&event.status),
                method = html_escape(&event.method),
                host = html_escape(&event.host),
                path = html_escape(&event.path),
                user_agent = html_escape(event.user_agent.as_deref().unwrap_or("")),
            )
        })
        .collect::<String>();

    format!(
        "<table>\
<tr><th align=\"left\">Time</th><th align=\"left\">Status</th><th align=\"left\">Method</th><th align=\"left\">Host</th><th align=\"left\">Path</th><th align=\"left\">User agent</th></tr>\
{}\
</table>",
        rows
    )
}

fn build_ai_inspection_prompt(
    incident: &crate::db::queries::IncidentDb,
    index_pattern: &str,
    cfg: &crate::config::models::SchedulerConfig,
    log_evidence: &[LogEvidenceEvent],
    evidence_error: Option<&str>,
) -> String {
    let details: Option<serde_json::Value> = incident
        .details
        .as_deref()
        .and_then(|d| serde_json::from_str(d).ok());
    let details_json = details
        .as_ref()
        .and_then(|details| serde_json::to_string_pretty(details).ok())
        .map(|details| compact_log_value(&details, 5000))
        .unwrap_or_else(|| "No structured detection details were recorded.".to_string());
    let evidence = compact_log_value(&raw_log_evidence_text(log_evidence), 7000);
    let evidence_note = evidence_error
        .map(|error| format!("Evidence fetch warning: {}\n", error))
        .unwrap_or_default();

    format!(
        "You are assisting a security operator reviewing a suspicious edge-traffic incident.\n\
Analyze the incident and available Elasticsearch log evidence. You may use the query_logs tool for read-only follow-up queries if the provided sample is not enough.\n\
Do not recommend irreversible actions without evidence. Keep the response concise and use these sections exactly: Assessment, Evidence, Recommended Action, Reporting Notes, Unknowns.\n\n\
Incident:\n\
- id: {incident_id}\n\
- source_ip: {source_ip}\n\
- detected_at: {detected_at}\n\
- status: {status}\n\
- failure_count: {failure_count}\n\n\
Elasticsearch context:\n\
- index_pattern: {index_pattern}\n\
- time_field: {time_field}\n\
- status_field: {status_field}\n\
- client_host_field: {client_host_field}\n\
- request_method_field: {request_method_field}\n\
- request_host_field: {request_host_field}\n\
- request_path_field: {request_path_field}\n\n\
Structured detection details:\n{details_json}\n\n\
{evidence_note}Raw log sample:\n{evidence}",
        incident_id = incident.id,
        source_ip = incident.source_ip,
        detected_at = incident.detected_at,
        status = incident.status,
        failure_count = incident.failure_count,
        index_pattern = index_pattern,
        time_field = cfg.time_field,
        status_field = cfg.status_field,
        client_host_field = cfg.client_host_field,
        request_method_field = cfg.request_method_field,
        request_host_field = cfg.request_host_field,
        request_path_field = cfg.request_path_field,
        details_json = details_json,
        evidence_note = evidence_note,
        evidence = evidence,
    )
}

fn address_range(whois: &crate::whois::WhoisInfo) -> String {
    match (whois.start_address.as_deref(), whois.end_address.as_deref()) {
        (Some(start), Some(end)) => format!("{} - {}", start, end),
        (Some(start), None) => start.to_string(),
        (None, Some(end)) => end.to_string(),
        (None, None) => "unknown".to_string(),
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Approving an incident confirms the recommended block for its source IP.
/// The incident is marked `approved` and, when enforcement is enabled, the
/// configured Traefik edge deny route is updated. The action is recorded either
/// way.
async fn approve_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let incident = match crate::db::queries::get_incident(&state.db_pool, &incident_id).await {
        Ok(Some(incident)) => incident,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    message: Some("Incident not found".to_string()),
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get incident: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incident: {}", e)),
                }),
            );
        }
    };

    if let Err(e) =
        crate::db::queries::update_incident_status(&state.db_pool, &incident_id, "approved").await
    {
        tracing::error!("Failed to update incident status: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some(format!("Failed to update incident status: {}", e)),
            }),
        );
    }

    let outcome = enforce_block(&state, &incident, state.enforce).await;
    (
        StatusCode::OK,
        Json(ApiResponse::<()> {
            success: outcome.applied || outcome.dry_run,
            data: None,
            message: Some(outcome.message),
        }),
    )
}

/// Force-apply the block for an already triaged incident. This bypasses
/// dry-run mode so an operator can turn a local approval into a cluster block.
async fn apply_block_override(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let incident = match crate::db::queries::get_incident(&state.db_pool, &incident_id).await {
        Ok(Some(incident)) => incident,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    message: Some("Incident not found".to_string()),
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get incident: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incident: {}", e)),
                }),
            );
        }
    };

    if let Err(e) =
        crate::db::queries::update_incident_status(&state.db_pool, &incident_id, "approved").await
    {
        tracing::error!("Failed to update incident status: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some(format!("Failed to update incident status: {}", e)),
            }),
        );
    }

    let outcome = enforce_block(&state, &incident, true).await;
    (
        StatusCode::OK,
        Json(ApiResponse::<()> {
            success: outcome.applied,
            data: None,
            message: Some(outcome.message),
        }),
    )
}

struct BlockOutcome {
    message: String,
    applied: bool,
    dry_run: bool,
}

/// Record and (if enabled) apply a block for the incident's IP. Returns a
/// human-readable status message. Never fails the request: a k8s error is
/// surfaced in the message and recorded on the action, but the incident stays
/// approved.
async fn enforce_block(
    state: &AppState,
    incident: &crate::db::queries::IncidentDb,
    apply_to_cluster: bool,
) -> BlockOutcome {
    let ip = &incident.source_ip;
    let action_id = format!("action-block-{}", ip);

    // Record the intended action (status starts 'pending').
    if let Err(e) =
        crate::db::queries::create_action(&state.db_pool, &action_id, &incident.id, "block_ip")
            .await
    {
        tracing::error!("Failed to record block action for {}: {}", ip, e);
    }

    if !apply_to_cluster {
        let _ =
            crate::db::queries::update_action_status(&state.db_pool, &action_id, "dry_run").await;
        return BlockOutcome {
            message: format!(
                "Block approved. Enforcement is disabled — no block applied to {} (dry-run).",
                ip
            ),
            applied: false,
            dry_run: true,
        };
    }

    let Some(client) = state.k8s_client.clone() else {
        let _ =
            crate::db::queries::update_action_status(&state.db_pool, &action_id, "failed").await;
        return BlockOutcome {
            message: format!(
                "Block approved, but no Kubernetes client is available — {} was not blocked.",
                ip
            ),
            applied: false,
            dry_run: false,
        };
    };

    match block_ip_in_cluster(
        &client,
        &state.block_namespace,
        &state.edge_ingressroute_name,
        &state.edge_deny_service_name,
        state.edge_deny_service_port,
        ip,
    )
    .await
    {
        Ok(route_name) => {
            let _ =
                crate::db::queries::update_action_status(&state.db_pool, &action_id, "completed")
                    .await;
            tracing::info!("Blocked {} via Traefik IngressRoute {}", ip, route_name);
            BlockOutcome {
                message: format!(
                    "Block approved and {} blocked via Traefik edge route '{}'.",
                    ip, route_name
                ),
                applied: true,
                dry_run: false,
            }
        }
        Err(e) => {
            let _ = crate::db::queries::update_action_status(&state.db_pool, &action_id, "failed")
                .await;
            tracing::error!("Failed to block {}: {}", ip, e);
            BlockOutcome {
                message: format!("Block approved, but blocking {} failed: {}", ip, e),
                applied: false,
                dry_run: false,
            }
        }
    }
}

/// Add `ip` to the configured Traefik edge deny route, returning the route name.
async fn block_ip_in_cluster(
    client: &kube::Client,
    namespace: &str,
    ingressroute_name: &str,
    service_name: &str,
    service_port: u16,
    ip: &str,
) -> Result<String, crate::k8s::BlockerError> {
    let mut blocker = crate::k8s::TraefikBlocker::new(client.clone(), namespace.to_string());
    blocker.init_with_detection().await?;
    blocker
        .block_ip_at_edge(ip, ingressroute_name, service_name, service_port)
        .await
}

async fn reject_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    match crate::db::queries::get_incident(&state.db_pool, &incident_id).await {
        Ok(Some(_)) => {
            match crate::db::queries::update_incident_status(
                &state.db_pool,
                &incident_id,
                "rejected",
            )
            .await
            {
                Ok(_) => (
                    StatusCode::OK,
                    Json(ApiResponse::<()> {
                        success: true,
                        data: None,
                        message: Some("Incident rejected".to_string()),
                    }),
                ),
                Err(e) => {
                    tracing::error!("Failed to update incident status: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::<()> {
                            success: false,
                            data: None,
                            message: Some(format!("Failed to update incident status: {}", e)),
                        }),
                    )
                }
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some("Incident not found".to_string()),
            }),
        ),
        Err(e) => {
            tracing::error!("Failed to get incident: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get incident: {}", e)),
                }),
            )
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentChatRequest {
    pub message: String,
}

async fn agent_chat(
    State(state): State<AppState>,
    Json(request): Json<AgentChatRequest>,
) -> impl IntoResponse {
    let Some(agent) = state.agent.as_ref().map(|agent| (**agent).clone()) else {
        let message = state.agent_error.as_deref().map_or_else(
            || "Agent chat is unavailable because no LLM provider is configured".to_string(),
            |error| format!("Agent chat is unavailable: {}", error),
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                message: Some(message),
            }),
        );
    };

    let task = Task::new(request.message);

    let context = Arc::new(Context::new(agent.llm().clone(), None));

    let react_agent = ReActAgent::with_max_turns(agent, 10);

    match react_agent.execute(&task, context).await {
        Ok(output) => {
            let response_json = serde_json::json!({
                "response": output.response,
                "tool_calls": output.tool_calls,
                "done": output.done,
                "success": true
            });
            (StatusCode::OK, Json(ApiResponse::new(response_json)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                message: Some(format!("Agent execution failed: {}", e)),
            }),
        ),
    }
}

async fn get_allowlist(State(state): State<AppState>) -> impl IntoResponse {
    match crate::db::queries::get_allowlist_ips(&state.db_pool).await {
        Ok(ips) => {
            let responses: Vec<AllowlistIpResponse> = ips.into_iter().map(|ip| ip.into()).collect();
            (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    data: Some(responses),
                    message: None,
                }),
            )
        }
        Err(e) => {
            tracing::error!("Failed to get allowlist: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<AllowlistIpResponse>> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to get allowlist: {}", e)),
                }),
            )
        }
    }
}

async fn add_allowlist_ip(
    State(state): State<AppState>,
    Json(request): Json<AddAllowlistIpRequest>,
) -> impl IntoResponse {
    if request.ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some("IP address is required".to_string()),
            }),
        );
    }

    if !is_valid_ip(&request.ip) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some("Invalid IP address format".to_string()),
            }),
        );
    }

    match crate::db::queries::add_allowlist_ip(
        &state.db_pool,
        &request.ip,
        request.description.as_deref(),
    )
    .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                data: None,
                message: Some(format!("IP {} added to allowlist", request.ip)),
            }),
        ),
        Err(e) => {
            tracing::error!("Failed to add allowlist IP: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to add allowlist IP: {}", e)),
                }),
            )
        }
    }
}

async fn delete_allowlist_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    if ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some("IP address is required".to_string()),
            }),
        );
    }

    if !is_valid_ip(&ip) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some("Invalid IP address format".to_string()),
            }),
        );
    }

    match crate::db::queries::is_ip_allowlisted(&state.db_pool, &ip).await {
        Ok(true) => match crate::db::queries::delete_allowlist_ip(&state.db_pool, &ip).await {
            Ok(_) => (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    data: None,
                    message: Some(format!("IP {} removed from allowlist", ip)),
                }),
            ),
            Err(e) => {
                tracing::error!("Failed to delete allowlist IP: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::<()> {
                        success: false,
                        data: None,
                        message: Some(format!("Failed to delete allowlist IP: {}", e)),
                    }),
                )
            }
        },
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                message: Some(format!("IP {} not found in allowlist", ip)),
            }),
        ),
        Err(e) => {
            tracing::error!("Failed to check allowlist: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    message: Some(format!("Failed to check allowlist: {}", e)),
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block_entry() -> BlockListEntry {
        BlockListEntry {
            ip: "203.0.113.10".to_string(),
            cidr: "203.0.113.10/32".to_string(),
            source: "cluster".to_string(),
            cluster_blocked: Some(true),
            block_applied: true,
            incident_id: Some("incident-203.0.113.10".to_string()),
            incident_status: Some("approved".to_string()),
            failure_count: Some(42),
            detected_at: Some("2026-07-03T12:00:00Z".to_string()),
            block_action_status: Some("completed".to_string()),
            report_sent_at: Some("2026-07-03T12:05:00Z".to_string()),
            evidence_summary: "hosts: example.com (40); paths: /admin|login (2), /env (1)"
                .to_string(),
        }
    }

    #[test]
    fn renders_block_list_csv_with_escaping() {
        let csv = render_block_list_csv(&[sample_block_entry()]);

        assert!(csv.starts_with("ip,cidr,source,cluster_blocked"));
        assert!(csv.contains("203.0.113.10,203.0.113.10/32,cluster,true,true"));
        assert!(csv.contains("\"hosts: example.com (40); paths: /admin|login (2), /env (1)\""));
    }

    #[test]
    fn renders_block_list_markdown_with_pipe_escaping() {
        let markdown = render_block_list_markdown(&[sample_block_entry()]);

        assert!(markdown.contains("# DevOps Agent Block List"));
        assert!(markdown.contains("/admin\\|login"));
    }

    #[test]
    fn renders_block_list_xlsx_workbook() {
        let bytes = render_block_list_xlsx(&[sample_block_entry()]).unwrap();

        assert!(bytes.starts_with(b"PK"));
        assert!(bytes.len() > 1024);
    }

    #[test]
    fn abuse_report_email_includes_ai_inspection_and_raw_logs() {
        let incident = crate::db::queries::IncidentDb {
            id: "incident-203.0.113.10".to_string(),
            source_ip: "203.0.113.10".to_string(),
            detected_at: "2026-07-03T12:00:00Z".to_string(),
            status: "detected".to_string(),
            failure_count: 42,
            details: Some(
                serde_json::json!({
                    "window_minutes": 60,
                    "status_breakdown": [["401", 42]],
                    "methods": [["GET", 42]],
                    "target_hosts": [["example.com", 42]],
                    "top_paths": [["/.env", 12]]
                })
                .to_string(),
            ),
            created_at: "2026-07-03T12:00:00Z".to_string(),
            updated_at: "2026-07-03T12:00:00Z".to_string(),
        };
        let whois = crate::whois::WhoisInfo {
            ip: "203.0.113.10".to_string(),
            registry_url: Some("https://rdap.example/ip/203.0.113.10".to_string()),
            network_name: Some("Example Net".to_string()),
            handle: None,
            country: Some("US".to_string()),
            start_address: Some("203.0.113.0".to_string()),
            end_address: Some("203.0.113.255".to_string()),
            organization: Some("Example Org".to_string()),
            abuse_contacts: Vec::new(),
        };
        let logs = vec![LogEvidenceEvent {
            timestamp: "2026-07-03T11:59:00Z".to_string(),
            source_ip: "203.0.113.10".to_string(),
            status: "401".to_string(),
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/.env".to_string(),
            user_agent: Some("scanner".to_string()),
            index: "filebeat-2026.07.03".to_string(),
        }];
        let ai_inspection = AiInspectionReportContext {
            analysis: "Assessment: credential probing.\nRecommended Action: block and report."
                .to_string(),
            evidence_count: Some(1),
            done: Some(true),
        };

        let email = build_abuse_report_email(
            &incident,
            &whois,
            vec!["abuse@example.net".to_string()],
            "DevOps Agent Abuse Reports",
            &logs,
            Some(&ai_inspection),
        );

        assert!(email.text_body.contains("AI inspection:"));
        assert!(email.text_body.contains("credential probing"));
        assert!(email.text_body.contains("Raw log sample:"));
        assert!(email.text_body.contains("path=/.env"));
        assert!(email.html_body.contains("<h3>AI inspection</h3>"));
        assert!(email.html_body.contains("credential probing"));
        assert!(email.html_body.contains("<h3>Raw log sample</h3>"));
    }
}

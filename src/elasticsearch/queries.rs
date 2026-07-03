use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Elasticsearch search request structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(dead_code)]
pub struct EsSearchRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<QueryType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<Vec<SortField>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggs: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub _source: Option<SourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum QueryType {
    Match {
        field: String,
        value: String,
    },
    Term {
        field: String,
        value: String,
    },
    Terms {
        field: String,
        values: Vec<String>,
    },
    Range {
        field: String,
        gt: Option<Value>,
        gte: Option<Value>,
        lt: Option<Value>,
        lte: Option<Value>,
    },
    Bool {
        #[serde(skip_serializing_if = "Option::is_none")]
        must: Option<Vec<QueryType>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        must_not: Option<Vec<QueryType>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        should: Option<Vec<QueryType>>,
    },
    Wildcard {
        field: String,
        value: String,
    },
    MatchAll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SortField {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SourceConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub includes: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub excludes: Option<Vec<String>>,
}

/// Elasticsearch query response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsQueryResponse {
    pub took: u64,
    pub timed_out: bool,
    #[serde(rename = "_shards")]
    pub shards: ShardsInfo,
    pub hits: HitsInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregations: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardsInfo {
    pub total: u64,
    pub successful: u64,
    pub skipped: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitsInfo {
    pub total: TotalHits,
    pub max_score: Option<f64>,
    pub hits: Vec<Hit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TotalHits {
    Exact { value: u64, relation: String },
    Relational { value: u64, relation: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    #[serde(rename = "_index")]
    pub index: String,
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_score")]
    pub score: Option<f64>,
    #[serde(rename = "_source")]
    pub source: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight: Option<Value>,
}

/// DSL query request for LLM-generated queries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct EsQueryRequest {
    pub query: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<usize>,
}

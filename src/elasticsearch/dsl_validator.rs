#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::manual_ok_err)]

use crate::elasticsearch::EsError;
use crate::elasticsearch::queries::{EsSearchRequest, QueryType, SourceConfig};
use serde_json::Value;

/// Maximum allowed size for search queries to prevent excessive resource usage
const MAX_QUERY_SIZE: usize = 1000;

/// Maximum allowed depth for nested query structures
const MAX_QUERY_DEPTH: usize = 10;

/// Maximum number of terms in a terms query
const MAX_TERMS_COUNT: usize = 100;

/// Maximum number of fields in a bool query
const MAX_BOOL_CLAUSES: usize = 32;

/// DSL Validator for Elasticsearch queries
#[derive(Debug, Clone, Default)]
pub struct DslValidator {
    max_size: usize,
    max_depth: usize,
    #[allow(dead_code)]
    max_terms_count: usize,
    #[allow(dead_code)]
    max_bool_clauses: usize,
}

impl DslValidator {
    /// Create a new DSL validator with default settings
    pub fn new() -> Self {
        Self {
            max_size: MAX_QUERY_SIZE,
            max_depth: MAX_QUERY_DEPTH,
            max_terms_count: MAX_TERMS_COUNT,
            max_bool_clauses: MAX_BOOL_CLAUSES,
        }
    }

    /// Create a new DSL validator with custom settings
    #[allow(dead_code)]
    pub fn with_settings(
        max_size: usize,
        max_depth: usize,
        max_terms_count: usize,
        max_bool_clauses: usize,
    ) -> Self {
        Self {
            max_size,
            max_depth,
            max_terms_count,
            max_bool_clauses,
        }
    }

    /// Validate a DSL query string
    pub fn validate(&self, dsl_query: &str) -> Result<(), EsError> {
        // Check query length
        if dsl_query.len() > self.max_size * 10 {
            // Rough estimate: 10 bytes per character max
            return Err(EsError::InvalidDsl(
                "Query exceeds maximum size limit".to_string(),
            ));
        }

        // Try to parse as JSON to validate basic structure
        let parsed: Value = serde_json::from_str(dsl_query)
            .map_err(|e| EsError::InvalidDsl(format!("Invalid JSON in DSL query: {}", e)))?;

        // Validate the parsed JSON structure
        self.validate_json_value(&parsed, 0)?;

        Ok(())
    }

    /// Validate a JSON value for dangerous or invalid ES query patterns
    fn validate_json_value(&self, value: &Value, depth: usize) -> Result<(), EsError> {
        if depth > self.max_depth {
            return Err(EsError::InvalidDsl(format!(
                "Query depth exceeds maximum limit of {}",
                self.max_depth
            )));
        }

        match value {
            Value::Object(map) => {
                // Check for dangerous ES query types or fields
                if let Some(dangerous_field) = self.detect_dangerous_fields(map) {
                    return Err(EsError::InvalidDsl(format!(
                        "Dangerous field or query type detected: {}",
                        dangerous_field
                    )));
                }

                // Recursively validate all values in the object
                for (key, val) in map {
                    // Skip _source includes/excludes validation for now
                    if key == "_source" {
                        if let Value::Object(source_obj) = val {
                            if let Some(includes) = source_obj.get("includes") {
                                if let Value::Array(arr) = includes {
                                    for item in arr {
                                        if let Value::String(s) = item {
                                            if s.contains('*') || s.contains('?') {
                                                // Wildcards in _source includes are allowed but should be limited
                                                if s.split('*').count() > 3 {
                                                    return Err(EsError::InvalidDsl(
                                                        "Too many wildcards in _source includes"
                                                            .to_string(),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    self.validate_json_value(val, depth + 1)?;
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.validate_json_value(item, depth + 1)?;
                }
            }
            Value::String(s) => {
                // Check for potential injection patterns in strings
                if self.is_dangerous_string(s) {
                    return Err(EsError::InvalidDsl(
                        "Potentially dangerous string pattern detected".to_string(),
                    ));
                }
            }
            Value::Number(_) | Value::Bool(_) | Value::Null => {
                // These are safe
            }
        }

        Ok(())
    }

    /// Detect dangerous fields or query types in an ES query
    fn detect_dangerous_fields(&self, map: &serde_json::Map<String, Value>) -> Option<String> {
        for key in map.keys() {
            let key_lower = key.to_lowercase();

            // Block script queries which can execute arbitrary code
            if key_lower == "script" || key_lower == "script_score" || key_lower == "scripted_score"
            {
                return Some(key.clone());
            }

            // Block _update_by_query, _delete_by_query, _reindex
            if key_lower == "_update_by_query"
                || key_lower == "_delete_by_query"
                || key_lower == "_reindex"
                || key_lower == "_msearch"
                || key_lower == "_mget"
            {
                return Some(key.clone());
            }

            // Block certain aggregations that can be resource-intensive
            if key_lower == "matrix_stats"
                || key_lower == "median_absolute_deviation"
                || key_lower == "geo_bounds"
            {
                return Some(key.clone());
            }

            // Check for nested dangerous fields
            if let Some(val) = map.get(key) {
                if let Value::Object(nested_map) = val {
                    if let Some(dangerous) = self.detect_dangerous_fields(nested_map) {
                        return Some(format!("{}.{}", key, dangerous));
                    }
                }
            }
        }
        None
    }

    /// Check if a string contains potentially dangerous patterns
    fn is_dangerous_string(&self, s: &str) -> bool {
        // Check for script injection patterns
        let dangerous_patterns = ["script(", "painless", "lang:", "ctx.", "_source", "params."];

        let s_lower = s.to_lowercase();
        for pattern in dangerous_patterns {
            if s_lower.contains(pattern) {
                // Allow _source in _source context, but not as a query pattern
                if pattern == "_source" && !s_lower.contains("script") {
                    continue;
                }
                return true;
            }
        }

        false
    }

    /// Sanitize a raw native-DSL request body in place.
    ///
    /// The full `validate()` pass has already rejected dangerous query types and
    /// strings; here we only clamp the resource-bounding top-level fields so a
    /// caller (or LLM) can't request an unbounded result set.
    pub fn sanitize_value(&self, body: &mut Value) {
        let Some(obj) = body.as_object_mut() else {
            return;
        };

        if let Some(size) = obj.get("size").and_then(Value::as_u64) {
            obj.insert("size".to_string(), Value::from(size.min(1000)));
        }

        if let Some(from) = obj.get("from").and_then(Value::as_u64) {
            obj.insert("from".to_string(), Value::from(from.min(10000)));
        }
    }

    /// Sanitize an ES search request
    #[allow(dead_code)]
    pub fn sanitize(&self, request: EsSearchRequest) -> Result<EsSearchRequest, EsError> {
        let mut sanitized = request;

        // Sanitize size
        if let Some(size) = sanitized.size {
            sanitized.size = Some(std::cmp::min(size, 1000)); // Max 1000 results
        }

        // Sanitize from (pagination offset)
        if let Some(from) = sanitized.from {
            sanitized.from = Some(std::cmp::min(from, 10000)); // Max 10000 offset
        }

        // Sanitize query
        if let Some(query) = sanitized.query {
            sanitized.query = Some(self.sanitize_query_type(query, 0)?);
        }

        // Sanitize source config
        if let Some(source) = sanitized._source {
            sanitized._source = Some(self.sanitize_source_config(source));
        }

        Ok(sanitized)
    }

    /// Sanitize a query type
    #[allow(dead_code)]
    fn sanitize_query_type(&self, query: QueryType, depth: usize) -> Result<QueryType, EsError> {
        if depth > self.max_depth {
            return Err(EsError::InvalidDsl(format!(
                "Query depth exceeds maximum limit of {}",
                self.max_depth
            )));
        }

        match query {
            QueryType::Match { field, value } => Ok(QueryType::Match {
                field: self.sanitize_field_name(&field)?,
                value,
            }),
            QueryType::Term { field, value } => Ok(QueryType::Term {
                field: self.sanitize_field_name(&field)?,
                value,
            }),
            QueryType::Terms { field, values } => {
                // Limit the number of terms
                let limited_values: Vec<String> =
                    values.into_iter().take(self.max_terms_count).collect();

                Ok(QueryType::Terms {
                    field: self.sanitize_field_name(&field)?,
                    values: limited_values,
                })
            }
            QueryType::Range {
                field,
                gt,
                gte,
                lt,
                lte,
            } => Ok(QueryType::Range {
                field: self.sanitize_field_name(&field)?,
                gt,
                gte,
                lt,
                lte,
            }),
            QueryType::Bool {
                must,
                must_not,
                should,
            } => {
                let mut must_clauses: Option<Vec<QueryType>> = None;
                let mut must_not_clauses: Option<Vec<QueryType>> = None;
                let mut should_clauses: Option<Vec<QueryType>> = None;

                if let Some(must_items) = must {
                    let limited_clauses: Vec<QueryType> = must_items
                        .into_iter()
                        .take(self.max_bool_clauses)
                        .filter_map(|q| match self.sanitize_query_type(q, depth + 1) {
                            Ok(sq) => Some(sq),
                            Err(_) => None, // Filter out invalid clauses
                        })
                        .collect();

                    if !limited_clauses.is_empty() {
                        must_clauses = Some(limited_clauses);
                    }
                }

                if let Some(must_not_items) = must_not {
                    let limited_clauses: Vec<QueryType> = must_not_items
                        .into_iter()
                        .take(self.max_bool_clauses)
                        .filter_map(|q| match self.sanitize_query_type(q, depth + 1) {
                            Ok(sq) => Some(sq),
                            Err(_) => None,
                        })
                        .collect();

                    if !limited_clauses.is_empty() {
                        must_not_clauses = Some(limited_clauses);
                    }
                }

                if let Some(should_items) = should {
                    let limited_clauses: Vec<QueryType> = should_items
                        .into_iter()
                        .take(self.max_bool_clauses)
                        .filter_map(|q| match self.sanitize_query_type(q, depth + 1) {
                            Ok(sq) => Some(sq),
                            Err(_) => None,
                        })
                        .collect();

                    if !limited_clauses.is_empty() {
                        should_clauses = Some(limited_clauses);
                    }
                }

                Ok(QueryType::Bool {
                    must: must_clauses,
                    must_not: must_not_clauses,
                    should: should_clauses,
                })
            }
            QueryType::Wildcard { field, value } => Ok(QueryType::Wildcard {
                field: self.sanitize_field_name(&field)?,
                value: self.sanitize_wildcard_value(&value)?,
            }),
            QueryType::MatchAll => Ok(QueryType::MatchAll),
        }
    }

    /// Sanitize a field name
    #[allow(dead_code)]
    fn sanitize_field_name(&self, field: &str) -> Result<String, EsError> {
        // Remove dangerous characters
        let sanitized: String = field
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
            .collect();

        if sanitized.is_empty() {
            return Err(EsError::InvalidDsl("Invalid field name".to_string()));
        }

        // Check for field name injection patterns
        if sanitized.contains("..") || sanitized.contains("*/") || sanitized.contains("*.") {
            return Err(EsError::InvalidDsl(
                "Invalid field name pattern".to_string(),
            ));
        }

        Ok(sanitized)
    }

    /// Sanitize a wildcard value
    #[allow(dead_code)]
    fn sanitize_wildcard_value(&self, value: &str) -> Result<String, EsError> {
        // Limit wildcard patterns to prevent excessive matching
        let asterisk_count = value.chars().filter(|c| *c == '*').count();
        let question_count = value.chars().filter(|c| *c == '?').count();

        if asterisk_count > 2 || question_count > 5 {
            return Err(EsError::InvalidDsl(
                "Wildcard pattern too complex".to_string(),
            ));
        }

        Ok(value.to_string())
    }

    /// Sanitize source configuration
    #[allow(dead_code)]
    fn sanitize_source_config(&self, source: SourceConfig) -> SourceConfig {
        let mut sanitized = source;

        if let Some(includes) = sanitized.includes {
            let limited_includes: Vec<String> = includes
                .into_iter()
                .take(50) // Max 50 include patterns
                .filter(|inc| !inc.contains("*/")) // Block recursive wildcards
                .collect();
            sanitized.includes = Some(limited_includes);
        }

        if let Some(excludes) = sanitized.excludes {
            let limited_excludes: Vec<String> = excludes
                .into_iter()
                .take(50) // Max 50 exclude patterns
                .filter(|exc| !exc.contains("*/")) // Block recursive wildcards
                .collect();
            sanitized.excludes = Some(limited_excludes);
        }

        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsl_validator_new() {
        let validator = DslValidator::new();
        assert_eq!(validator.max_size, MAX_QUERY_SIZE);
        assert_eq!(validator.max_depth, MAX_QUERY_DEPTH);
        assert_eq!(validator.max_terms_count, MAX_TERMS_COUNT);
        assert_eq!(validator.max_bool_clauses, MAX_BOOL_CLAUSES);
    }

    #[test]
    fn test_validate_valid_json() {
        let validator = DslValidator::new();
        let valid_query = r#"{"query": {"match_all": {}}}"#;
        assert!(validator.validate(valid_query).is_ok());
    }

    #[test]
    fn test_validate_invalid_json() {
        let validator = DslValidator::new();
        let invalid_query = r#"{"query": {"match_all": {}}"#; // Missing closing brace
        assert!(validator.validate(invalid_query).is_err());
    }

    #[test]
    fn test_validate_script_injection() {
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
    fn test_validate_update_by_query() {
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
    fn test_sanitize_size_limit() {
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
    fn test_sanitize_from_limit() {
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
    fn test_sanitize_terms_limit() {
        let validator = DslValidator::new();
        let mut values: Vec<String> = Vec::new();
        for i in 0..200 {
            values.push(format!("value_{}", i));
        }
        let request = EsSearchRequest {
            query: Some(QueryType::Terms {
                field: "status".to_string(),
                values,
            }),
            size: None,
            from: None,
            sort: None,
            aggs: None,
            _source: None,
        };
        let sanitized = validator.sanitize(request).unwrap();
        if let QueryType::Terms {
            values: sanitized_values,
            ..
        } = sanitized.query.unwrap()
        {
            assert_eq!(sanitized_values.len(), 100);
        } else {
            panic!("Expected Terms query");
        }
    }

    #[test]
    fn test_sanitize_field_name_invalid() {
        let validator = DslValidator::new();
        let invalid_field = "field..name";
        let result = validator.sanitize_field_name(invalid_field);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_wildcard_too_complex() {
        let validator = DslValidator::new();
        let complex_wildcard = "field*value*other*more";
        let result = validator.sanitize_wildcard_value(complex_wildcard);
        assert!(result.is_err());
    }
}

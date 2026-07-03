#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_match)]

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::Client;

use kube::api::{Api, ListParams, ObjectList};
use kube::core::ApiResource;
use kube::core::DynamicObject;
use kube::core::GroupVersionKind;

/// Traefik Middleware API group and version variants
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MiddlewareApiGroup {
    /// Prioritized: traefik.io/v1alpha1
    TraefikIoV1Alpha1,
    /// Fallback: traefik.containo.us/v1alpha1
    TraefikContainousV1Alpha1,
}

impl MiddlewareApiGroup {
    pub fn group(&self) -> &'static str {
        match self {
            MiddlewareApiGroup::TraefikIoV1Alpha1 => "traefik.io",
            MiddlewareApiGroup::TraefikContainousV1Alpha1 => "traefik.containo.us",
        }
    }

    pub fn version(&self) -> &'static str {
        "v1alpha1"
    }

    pub fn crd_name(&self) -> &'static str {
        match self {
            MiddlewareApiGroup::TraefikIoV1Alpha1 => "middlewares.traefik.io",
            MiddlewareApiGroup::TraefikContainousV1Alpha1 => "middlewares.traefik.containo.us",
        }
    }
}

/// Traefik IngressRoute API group and version variants
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum IngressRouteApiGroup {
    /// Prioritized: traefik.io/v1alpha1
    TraefikIoV1Alpha1,
    /// Fallback: traefik.containo.us/v1alpha1
    TraefikContainousV1Alpha1,
}

impl IngressRouteApiGroup {
    pub fn group(&self) -> &'static str {
        match self {
            IngressRouteApiGroup::TraefikIoV1Alpha1 => "traefik.io",
            IngressRouteApiGroup::TraefikContainousV1Alpha1 => "traefik.containo.us",
        }
    }

    pub fn version(&self) -> &'static str {
        "v1alpha1"
    }

    pub fn crd_name(&self) -> &'static str {
        match self {
            IngressRouteApiGroup::TraefikIoV1Alpha1 => "ingressroutes.traefik.io",
            IngressRouteApiGroup::TraefikContainousV1Alpha1 => "ingressroutes.traefik.containo.us",
        }
    }
}

/// K8s API error types
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum K8sError {
    /// K8s API connection failure
    ConnectionFailed(String),
    /// Missing CRD
    CrdNotFound(String),
    /// API version deprecated or not available
    ApiVersionDeprecated(String),
    /// Generic K8s error
    Generic(String),
}

impl std::fmt::Display for K8sError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            K8sError::ConnectionFailed(msg) => write!(f, "K8s API connection failed: {}", msg),
            K8sError::CrdNotFound(crd) => write!(f, "CRD not found: {}", crd),
            K8sError::ApiVersionDeprecated(msg) => {
                write!(f, "API version deprecated or not available: {}", msg)
            }
            K8sError::Generic(msg) => write!(f, "K8s error: {}", msg),
        }
    }
}

impl std::error::Error for K8sError {}

/// Middleware IP allowlist configuration
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub struct IpAllowListConfig {
    pub source_range: Vec<String>,
}

/// Middleware denyip plugin configuration
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub struct DenyIpConfig {
    pub source_range: Vec<String>,
}

/// Middleware configuration
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub struct MiddlewareConfig {
    pub ip_allowlist: Option<IpAllowListConfig>,
    pub denyip: Option<DenyIpConfig>,
}

/// Path regexp pattern for scanner detection
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub struct PathRegexpConfig {
    pub name: String,
    pub pattern: String,
}

/// IngressRoute path configuration
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub struct IngressRoutePathConfig {
    pub path: String,
    pub path_type: String,
    pub match_rule: Option<String>,
    pub path_regexp: Option<PathRegexpConfig>,
}

/// IngressRoute configuration
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub struct IngressRouteConfig {
    pub name: String,
    pub namespace: String,
    pub entry_points: Vec<String>,
    pub routes: Vec<IngressRoutePathConfig>,
}

/// Inspector result for discovered resources
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct InspectorResults {
    pub middlewares: Vec<MiddlewareDiscovery>,
    pub ingress_routes: Vec<IngressRouteDiscovery>,
    pub api_group_used: Option<String>,
}

/// Discovered Middleware resource
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct MiddlewareDiscovery {
    pub name: String,
    pub namespace: String,
    pub config: MiddlewareConfig,
}

/// Discovered IngressRoute resource
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct IngressRouteDiscovery {
    pub name: String,
    pub namespace: String,
    pub config: IngressRouteConfig,
}

/// K8s Traefik Inspector client
#[allow(dead_code)]
pub struct TraefikInspector {
    pub client: Client,
    pub namespace: Option<String>,
    pub middleware_api_group: MiddlewareApiGroup,
    pub ingressroute_api_group: IngressRouteApiGroup,
}

impl TraefikInspector {
    /// Create a new TraefikInspector with the given K8s client
    pub fn new(client: Client, namespace: Option<String>) -> Self {
        Self {
            client,
            namespace,
            middleware_api_group: MiddlewareApiGroup::TraefikIoV1Alpha1,
            ingressroute_api_group: IngressRouteApiGroup::TraefikIoV1Alpha1,
        }
    }

    /// Check if a CRD exists in the cluster
    pub async fn crd_exists(&self, crd_name: &str) -> Result<bool, K8sError> {
        let crds_api: Api<CustomResourceDefinition> = Api::all(self.client.clone());

        match crds_api.get(crd_name).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(err)) if err.code == 404 => Ok(false),
            Err(kube::Error::Api(err)) if err.code == 410 => Err(K8sError::ApiVersionDeprecated(
                format!("CRD {} is deprecated or version not available", crd_name),
            )),
            Err(e) => Err(K8sError::ConnectionFailed(format!(
                "Failed to check CRD {}: {}",
                crd_name, e
            ))),
        }
    }

    /// Detect available Traefik API groups by checking CRDs
    pub async fn detect_api_groups(
        &self,
    ) -> Result<(MiddlewareApiGroup, IngressRouteApiGroup), K8sError> {
        let middleware_crd_names = [
            MiddlewareApiGroup::TraefikIoV1Alpha1.crd_name(),
            MiddlewareApiGroup::TraefikContainousV1Alpha1.crd_name(),
        ];

        let mut middleware_found = None;
        for crd_name in &middleware_crd_names {
            if self.crd_exists(crd_name).await? {
                middleware_found = Some(match *crd_name {
                    "middlewares.traefik.io" => MiddlewareApiGroup::TraefikIoV1Alpha1,
                    "middlewares.traefik.containo.us" => {
                        MiddlewareApiGroup::TraefikContainousV1Alpha1
                    }
                    _ => unreachable!(),
                });
                break;
            }
        }

        let ingressroute_crd_names = [
            IngressRouteApiGroup::TraefikIoV1Alpha1.crd_name(),
            IngressRouteApiGroup::TraefikContainousV1Alpha1.crd_name(),
        ];

        let mut ingressroute_found = None;
        for crd_name in &ingressroute_crd_names {
            if self.crd_exists(crd_name).await? {
                ingressroute_found = Some(match *crd_name {
                    "ingressroutes.traefik.io" => IngressRouteApiGroup::TraefikIoV1Alpha1,
                    "ingressroutes.traefik.containo.us" => {
                        IngressRouteApiGroup::TraefikContainousV1Alpha1
                    }
                    _ => unreachable!(),
                });
                break;
            }
        }

        let middleware_group = middleware_found.unwrap_or(MiddlewareApiGroup::TraefikIoV1Alpha1);
        let ingressroute_group =
            ingressroute_found.unwrap_or(IngressRouteApiGroup::TraefikIoV1Alpha1);

        // Verify both CRDs exist with the detected groups
        if !self.crd_exists(middleware_group.crd_name()).await? {
            return Err(K8sError::CrdNotFound(
                middleware_group.crd_name().to_string(),
            ));
        }
        if !self.crd_exists(ingressroute_group.crd_name()).await? {
            return Err(K8sError::CrdNotFound(
                ingressroute_group.crd_name().to_string(),
            ));
        }

        Ok((middleware_group, ingressroute_group))
    }

    /// Initialize inspector with auto-detected API groups
    pub async fn init_with_detection(&mut self) -> Result<(), K8sError> {
        let (middleware_group, ingressroute_group) = self.detect_api_groups().await?;
        self.middleware_api_group = middleware_group;
        self.ingressroute_api_group = ingressroute_group;
        Ok(())
    }

    /// Inspect Middleware resources
    pub async fn inspect_middlewares(&self) -> Result<Vec<MiddlewareDiscovery>, K8sError> {
        let api_group = self.middleware_api_group.group();
        let version = self.middleware_api_group.version();
        let crd_name = self.middleware_api_group.crd_name();

        // Check if CRD exists
        if !self.crd_exists(crd_name).await? {
            return Err(K8sError::CrdNotFound(crd_name.to_string()));
        }

        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let params = ListParams::default();

        // Use dynamic API for custom resources
        let gvk = GroupVersionKind {
            group: api_group.to_string(),
            version: version.to_string(),
            kind: "Middleware".to_string(),
        };
        let api_resource = ApiResource::from_gvk_with_plural(&gvk, "middlewares");

        let apis: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &namespace, &api_resource);

        let middlewares: ObjectList<kube::core::DynamicObject> = match apis.list(&params).await {
            Ok(list) => list,
            Err(kube::Error::Api(err)) if err.code == 404 => {
                return Ok(vec![]);
            }
            Err(kube::Error::Api(err)) if err.code == 410 => {
                return Err(K8sError::ApiVersionDeprecated(format!(
                    "Middleware API {} in group {} is deprecated",
                    version, api_group
                )));
            }
            Err(kube::Error::Api(err)) => {
                return Err(K8sError::ConnectionFailed(format!(
                    "Failed to list middlewares: HTTP {}",
                    err.code
                )));
            }
            Err(e) => {
                return Err(K8sError::ConnectionFailed(format!(
                    "Failed to list middlewares: {}",
                    e
                )));
            }
        };

        let mut discoveries = Vec::new();
        for mw in middlewares.items {
            let discovery = self.parse_middleware(&mw);
            discoveries.push(discovery);
        }

        Ok(discoveries)
    }

    /// Parse Middleware dynamic object to extract IP allowlist and denyip configurations
    fn parse_middleware(&self, mw: &DynamicObject) -> MiddlewareDiscovery {
        let name = mw.metadata.name.clone().unwrap_or_default();
        let namespace = mw
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string());

        let mut config = MiddlewareConfig::default();

        // Try to extract spec from the dynamic object
        if let Some(spec) = mw.data.get("spec") {
            // Check for ipAllowList
            if let Some(ip_allowlist) = spec.get("ipAllowList") {
                if let Some(source_range) = ip_allowlist.get("sourceRange") {
                    if let Some(sr_vec) = source_range.as_array() {
                        let ranges: Vec<String> = sr_vec
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                        config.ip_allowlist = Some(IpAllowListConfig {
                            source_range: ranges,
                        });
                    }
                }
            }

            // Check for plugin denyip
            if let Some(plugin) = spec.get("plugin") {
                if let Some(denyip) = plugin.get("denyip") {
                    if let Some(source_range) = denyip.get("sourceRange") {
                        if let Some(sr_vec) = source_range.as_array() {
                            let ranges: Vec<String> = sr_vec
                                .iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect();
                            config.denyip = Some(DenyIpConfig {
                                source_range: ranges,
                            });
                        }
                    }
                }
            }
        }

        MiddlewareDiscovery {
            name,
            namespace,
            config,
        }
    }

    /// Inspect IngressRoute resources
    pub async fn inspect_ingress_routes(&self) -> Result<Vec<IngressRouteDiscovery>, K8sError> {
        let api_group = self.ingressroute_api_group.group();
        let version = self.ingressroute_api_group.version();
        let crd_name = self.ingressroute_api_group.crd_name();

        // Check if CRD exists
        if !self.crd_exists(crd_name).await? {
            return Err(K8sError::CrdNotFound(crd_name.to_string()));
        }

        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let params = ListParams::default();

        // Use dynamic API for custom resources
        let gvk = GroupVersionKind {
            group: api_group.to_string(),
            version: version.to_string(),
            kind: "IngressRoute".to_string(),
        };
        let api_resource = ApiResource::from_gvk_with_plural(&gvk, "ingressroutes");

        let apis: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &namespace, &api_resource);

        let ingress_routes: ObjectList<kube::core::DynamicObject> = match apis.list(&params).await {
            Ok(list) => list,
            Err(kube::Error::Api(err)) if err.code == 404 => {
                return Ok(vec![]);
            }
            Err(kube::Error::Api(err)) if err.code == 410 => {
                return Err(K8sError::ApiVersionDeprecated(format!(
                    "IngressRoute API {} in group {} is deprecated",
                    version, api_group
                )));
            }
            Err(kube::Error::Api(err)) => {
                return Err(K8sError::ConnectionFailed(format!(
                    "Failed to list ingressroutes: HTTP {}",
                    err.code
                )));
            }
            Err(e) => {
                return Err(K8sError::ConnectionFailed(format!(
                    "Failed to list ingressroutes: {}",
                    e
                )));
            }
        };

        let mut discoveries = Vec::new();
        for ir in ingress_routes.items {
            let discovery = self.parse_ingress_route(&ir);
            discoveries.push(discovery);
        }

        Ok(discoveries)
    }

    /// Parse IngressRoute dynamic object to extract path-based scanner detection rules
    fn parse_ingress_route(&self, ir: &DynamicObject) -> IngressRouteDiscovery {
        let name = ir.metadata.name.clone().unwrap_or_default();
        let namespace = ir
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string());

        let mut config = IngressRouteConfig {
            name: name.clone(),
            namespace: namespace.clone(),
            entry_points: vec![],
            routes: vec![],
        };

        // Try to extract spec from the dynamic object
        if let Some(spec) = ir.data.get("spec") {
            // Extract entryPoints
            if let Some(entry_points) = spec.get("entryPoints") {
                if let Some(ep_vec) = entry_points.as_array() {
                    config.entry_points = ep_vec
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                }
            }

            // Extract routes
            if let Some(routes) = spec.get("routes") {
                if let Some(routes_vec) = routes.as_array() {
                    for route in routes_vec {
                        let mut route_config = IngressRoutePathConfig::default();

                        if let Some(match_rule) = route.get("match") {
                            route_config.match_rule = match_rule.as_str().map(String::from);

                            // Extract path and pathType from match rule if it's a PathPrefix or PathRegexp
                            if let Some(match_str) = match_rule.as_str() {
                                if match_str.starts_with("PathPrefix(") {
                                    if let Some(path_start) = match_str.strip_prefix("PathPrefix(")
                                    {
                                        if let Some(path_end) = path_start.strip_suffix(")") {
                                            route_config.path = path_end.to_string();
                                            route_config.path_type = "PathPrefix".to_string();
                                        }
                                    }
                                } else if match_str.starts_with("PathRegexp(") {
                                    if let Some(path_start) = match_str.strip_prefix("PathRegexp(")
                                    {
                                        if let Some(path_end) = path_start.strip_suffix(")") {
                                            route_config.path = path_end.to_string();
                                            route_config.path_type = "PathRegexp".to_string();
                                        }
                                    }
                                } else if match_str.starts_with("Path(") {
                                    if let Some(path_start) = match_str.strip_prefix("Path(") {
                                        if let Some(path_end) = path_start.strip_suffix(")") {
                                            route_config.path = path_end.to_string();
                                            route_config.path_type = "Path".to_string();
                                        }
                                    }
                                }
                            }
                        }

                        // Extract pathRegexp from match rule
                        if let Some(match_rule_str) = route.get("match").and_then(|m| m.as_str()) {
                            if match_rule_str.contains("PathRegexp") {
                                // Extract the regexp name and pattern
                                if let Some(regexp_start) =
                                    match_rule_str.strip_prefix("PathRegexp(")
                                {
                                    if let Some(regexp_end) = regexp_start.strip_suffix(")") {
                                        // Split by comma to get name and pattern
                                        let parts: Vec<&str> = regexp_end.split(',').collect();
                                        if parts.len() >= 2 {
                                            let reg_name = parts[0].trim().to_string();
                                            let reg_pattern =
                                                parts[1..].join(",").trim().to_string();

                                            route_config.path_regexp = Some(PathRegexpConfig {
                                                name: reg_name,
                                                pattern: reg_pattern,
                                            });
                                        }
                                    }
                                }
                            }
                        }

                        config.routes.push(route_config);
                    }
                }
            }
        }

        IngressRouteDiscovery {
            name,
            namespace,
            config,
        }
    }

    /// Get all inspector results
    pub async fn inspect_all(&self) -> Result<InspectorResults, K8sError> {
        let mut results = InspectorResults::default();

        let middlewares = self.inspect_middlewares().await?;
        let ingress_routes = self.inspect_ingress_routes().await?;

        results.middlewares = middlewares;
        results.ingress_routes = ingress_routes;
        results.api_group_used = Some(format!(
            "{}/{}",
            self.middleware_api_group.group(),
            self.middleware_api_group.version()
        ));

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_api_group_names() {
        let traefik_io = MiddlewareApiGroup::TraefikIoV1Alpha1;
        assert_eq!(traefik_io.group(), "traefik.io");
        assert_eq!(traefik_io.version(), "v1alpha1");
        assert_eq!(traefik_io.crd_name(), "middlewares.traefik.io");

        let containous = MiddlewareApiGroup::TraefikContainousV1Alpha1;
        assert_eq!(containous.group(), "traefik.containo.us");
        assert_eq!(containous.version(), "v1alpha1");
        assert_eq!(containous.crd_name(), "middlewares.traefik.containo.us");
    }

    #[test]
    fn test_ingressroute_api_group_names() {
        let traefik_io = IngressRouteApiGroup::TraefikIoV1Alpha1;
        assert_eq!(traefik_io.group(), "traefik.io");
        assert_eq!(traefik_io.version(), "v1alpha1");
        assert_eq!(traefik_io.crd_name(), "ingressroutes.traefik.io");

        let containous = IngressRouteApiGroup::TraefikContainousV1Alpha1;
        assert_eq!(containous.group(), "traefik.containo.us");
        assert_eq!(containous.version(), "v1alpha1");
        assert_eq!(containous.crd_name(), "ingressroutes.traefik.containo.us");
    }

    #[test]
    fn test_k8s_error_display() {
        let conn_err = K8sError::ConnectionFailed("connection refused".to_string());
        assert!(conn_err.to_string().contains("connection refused"));

        let crd_err = K8sError::CrdNotFound("middlewares.traefik.io".to_string());
        assert!(
            crd_err
                .to_string()
                .contains("CRD not found: middlewares.traefik.io")
        );

        let deprec_err = K8sError::ApiVersionDeprecated("v1alpha1 deprecated".to_string());
        assert!(
            deprec_err
                .to_string()
                .contains("API version deprecated or not available")
        );

        let generic_err = K8sError::Generic("generic error".to_string());
        assert!(generic_err.to_string().contains("K8s error: generic error"));
    }

    #[test]
    fn test_middleware_config_defaults() {
        let config = MiddlewareConfig::default();
        assert!(config.ip_allowlist.is_none());
        assert!(config.denyip.is_none());
    }

    #[test]
    fn test_path_regexp_config() {
        let regexp = PathRegexpConfig {
            name: "scannerDetection".to_string(),
            pattern: "/(wp-login|xmlrpc|\\.env|\\.git)".to_string(),
        };
        assert_eq!(regexp.name, "scannerDetection");
        assert_eq!(regexp.pattern, "/(wp-login|xmlrpc|\\.env|\\.git)");
    }

    #[test]
    fn test_ip_allowlist_config() {
        let config = IpAllowListConfig {
            source_range: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
        };
        assert_eq!(config.source_range.len(), 2);
        assert_eq!(config.source_range[0], "192.168.1.0/24");
    }

    #[test]
    fn test_denyip_config() {
        let config = DenyIpConfig {
            source_range: vec!["0.0.0.0/0".to_string()],
        };
        assert_eq!(config.source_range.len(), 1);
        assert_eq!(config.source_range[0], "0.0.0.0/0");
    }

    #[test]
    fn test_extract_path_prefix() {
        let match_str = "PathPrefix(/api)";
        let mut path = String::new();
        let mut path_type = String::new();

        if match_str.starts_with("PathPrefix(") {
            if let Some(path_start) = match_str.strip_prefix("PathPrefix(") {
                if let Some(path_end) = path_start.strip_suffix(")") {
                    path = path_end.to_string();
                    path_type = "PathPrefix".to_string();
                }
            }
        }

        assert_eq!(path, "/api");
        assert_eq!(path_type, "PathPrefix");
    }

    #[test]
    fn test_extract_path_regexp() {
        let match_str = "PathRegexp(scanner,/(wp-login|xmlrpc|\\.env|\\.git))";
        let mut path_type = String::new();
        let mut path_regexp: Option<PathRegexpConfig> = None;

        if match_str.starts_with("PathRegexp(") {
            if let Some(path_start) = match_str.strip_prefix("PathRegexp(") {
                if let Some(path_end) = path_start.strip_suffix(")") {
                    assert_eq!(path_end, "scanner,/(wp-login|xmlrpc|\\.env|\\.git)");
                    path_type = "PathRegexp".to_string();
                }
            }
        }

        assert_eq!(path_type, "PathRegexp");
        assert!(match_str.contains("PathRegexp"));

        if let Some(regexp_start) = match_str.strip_prefix("PathRegexp(") {
            if let Some(regexp_end) = regexp_start.strip_suffix(")") {
                let parts: Vec<&str> = regexp_end.split(',').collect();
                if parts.len() >= 2 {
                    let reg_name = parts[0].trim().to_string();
                    let reg_pattern = parts[1..].join(",").trim().to_string();
                    path_regexp = Some(PathRegexpConfig {
                        name: reg_name,
                        pattern: reg_pattern,
                    });
                }
            }
        }

        assert!(path_regexp.is_some());
        let regexp = path_regexp.unwrap();
        assert_eq!(regexp.name, "scanner");
        assert_eq!(regexp.pattern, "/(wp-login|xmlrpc|\\.env|\\.git)");
    }
}

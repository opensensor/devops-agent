use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::Client;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::core::{ApiResource, DynamicObject, GroupVersionKind};

/// Traefik Middleware API group and version variants
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraefikMiddlewareApiGroup {
    /// Prioritized: traefik.io/v1alpha1
    TraefikIoV1Alpha1,
    /// Fallback: traefik.containo.us/v1alpha1
    TraefikContainousV1Alpha1,
}

impl TraefikMiddlewareApiGroup {
    pub fn group(&self) -> &'static str {
        match self {
            TraefikMiddlewareApiGroup::TraefikIoV1Alpha1 => "traefik.io",
            TraefikMiddlewareApiGroup::TraefikContainousV1Alpha1 => "traefik.containo.us",
        }
    }

    pub fn version(&self) -> &'static str {
        "v1alpha1"
    }

    pub fn crd_name(&self) -> &'static str {
        match self {
            TraefikMiddlewareApiGroup::TraefikIoV1Alpha1 => "middlewares.traefik.io",
            TraefikMiddlewareApiGroup::TraefikContainousV1Alpha1 => {
                "middlewares.traefik.containo.us"
            }
        }
    }

    pub fn ingressroute_crd_name(&self) -> &'static str {
        match self {
            TraefikMiddlewareApiGroup::TraefikIoV1Alpha1 => "ingressroutes.traefik.io",
            TraefikMiddlewareApiGroup::TraefikContainousV1Alpha1 => {
                "ingressroutes.traefik.containo.us"
            }
        }
    }
}

/// Blocker error types for structured error handling
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockerError {
    /// RBAC permission denied error
    RbacPermissionDenied(String),
    /// Resource conflict error (409 Conflict)
    ResourceConflict(String),
    /// CRD not found error
    CrdNotFound(String),
    /// API version deprecated or not available error
    ApiVersionDeprecated(String),
    /// K8s API connection failure
    ConnectionFailed(String),
    /// Generic blocker error
    Generic(String),
}

impl std::fmt::Display for BlockerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockerError::RbacPermissionDenied(msg) => write!(f, "RBAC permission denied: {}", msg),
            BlockerError::ResourceConflict(msg) => write!(f, "Resource conflict: {}", msg),
            BlockerError::CrdNotFound(crd) => write!(f, "CRD not found: {}", crd),
            BlockerError::ApiVersionDeprecated(msg) => {
                write!(f, "API version deprecated or not available: {}", msg)
            }
            BlockerError::ConnectionFailed(msg) => write!(f, "K8s API connection failed: {}", msg),
            BlockerError::Generic(msg) => write!(f, "Blocker error: {}", msg),
        }
    }
}

impl std::error::Error for BlockerError {}

impl BlockerError {
    /// Convert a kube Error to a BlockerError based on the error type and code
    pub fn from_kube_error(err: &kube::Error, operation: &str) -> Self {
        match err {
            kube::Error::Api(resp) => match resp.code {
                403 => BlockerError::RbacPermissionDenied(format!(
                    "{} failed: {}",
                    operation, resp.message
                )),
                404 => {
                    if resp.message.contains("customresourcedefinitions")
                        || resp.message.contains("middlewares.traefik")
                    {
                        BlockerError::CrdNotFound(resp.message.clone())
                    } else {
                        BlockerError::Generic(format!(
                            "{} failed: resource not found - {}",
                            operation, resp.message
                        ))
                    }
                }
                409 => BlockerError::ResourceConflict(format!(
                    "{} failed: {}",
                    operation, resp.message
                )),
                410 => BlockerError::ApiVersionDeprecated(format!(
                    "{} failed: {}",
                    operation, resp.message
                )),
                _ => BlockerError::Generic(format!(
                    "{} failed with HTTP {}: {}",
                    operation, resp.code, resp.message
                )),
            },
            _ => BlockerError::ConnectionFailed(format!("{} failed: {:?}", operation, err)),
        }
    }
}

/// IP deny list configuration
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct IpDenyListConfig {
    pub ips: Vec<String>,
}

/// DenyIP plugin block configuration
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DenyIpBlockConfig {
    #[serde(rename = "ipDenyList")]
    pub ip_deny_list: Option<IpDenyListConfig>,
}

/// Middleware block configuration
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct MiddlewareBlockConfig {
    #[serde(rename = "plugin")]
    pub plugin: Option<PluginBlockConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct PluginBlockConfig {
    #[serde(rename = "denyip")]
    pub denyip: Option<DenyIpBlockConfig>,
}

/// Traefik K8s Blocker client
pub struct TraefikBlocker {
    pub client: Client,
    pub namespace: String,
    pub middleware_api_group: TraefikMiddlewareApiGroup,
}

impl TraefikBlocker {
    /// Create a new TraefikBlocker with the given K8s client
    pub fn new(client: Client, namespace: String) -> Self {
        Self {
            client,
            namespace,
            middleware_api_group: TraefikMiddlewareApiGroup::TraefikIoV1Alpha1,
        }
    }

    /// Generate a middleware name for an IP block
    pub fn generate_middleware_name(ip: &str) -> String {
        let sanitized_ip = ip.replace('.', "-");
        format!("denyip-block-{}", sanitized_ip)
    }

    pub fn cidr_for_ip(ip: &str) -> Result<String, BlockerError> {
        match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => Ok(format!("{}/32", ip)),
            Ok(std::net::IpAddr::V6(_)) => Ok(format!("{}/128", ip)),
            Err(_) => Err(BlockerError::Generic(format!("Invalid IP address: {}", ip))),
        }
    }

    /// Check if a CRD exists in the cluster
    pub async fn crd_exists(&self, crd_name: &str) -> Result<bool, BlockerError> {
        let crds_api: Api<CustomResourceDefinition> = Api::all(self.client.clone());

        match crds_api.get(crd_name).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(err)) if err.code == 404 => Ok(false),
            Err(kube::Error::Api(err)) if err.code == 410 => {
                Err(BlockerError::ApiVersionDeprecated(format!(
                    "CRD {} is deprecated or version not available",
                    crd_name
                )))
            }
            Err(e) => Err(BlockerError::ConnectionFailed(format!(
                "Failed to check CRD {}: {}",
                crd_name, e
            ))),
        }
    }

    /// Detect available Traefik Middleware API group
    pub async fn detect_middleware_api_group(
        &self,
    ) -> Result<TraefikMiddlewareApiGroup, BlockerError> {
        let crd_names = [
            TraefikMiddlewareApiGroup::TraefikIoV1Alpha1.crd_name(),
            TraefikMiddlewareApiGroup::TraefikContainousV1Alpha1.crd_name(),
        ];

        for crd_name in &crd_names {
            if self.crd_exists(crd_name).await? {
                return Ok(match *crd_name {
                    "middlewares.traefik.io" => TraefikMiddlewareApiGroup::TraefikIoV1Alpha1,
                    "middlewares.traefik.containo.us" => {
                        TraefikMiddlewareApiGroup::TraefikContainousV1Alpha1
                    }
                    _ => unreachable!(),
                });
            }
        }

        Err(BlockerError::CrdNotFound(
            "middlewares.traefik.io or middlewares.traefik.containo.us".to_string(),
        ))
    }

    /// Initialize blocker with auto-detected API group
    pub async fn init_with_detection(&mut self) -> Result<(), BlockerError> {
        let api_group = self.detect_middleware_api_group().await?;
        self.middleware_api_group = api_group;
        Ok(())
    }

    /// Create or update a Traefik Middleware resource with denyip plugin for blocking IPs
    pub async fn block_ip(
        &self,
        ip: &str,
        middleware_name: Option<&str>,
    ) -> Result<String, BlockerError> {
        let name = middleware_name
            .map(|n| n.to_string())
            .unwrap_or_else(|| Self::generate_middleware_name(ip));

        let api_group = self.middleware_api_group.group();
        let version = self.middleware_api_group.version();

        // Check if CRD exists
        let crd_name = self.middleware_api_group.crd_name();
        if !self.crd_exists(crd_name).await? {
            return Err(BlockerError::CrdNotFound(crd_name.to_string()));
        }

        // Create the middleware spec with denyip plugin and ipDenyList
        let denyip_config = DenyIpBlockConfig {
            ip_deny_list: Some(IpDenyListConfig {
                ips: vec![ip.to_string()],
            }),
        };

        let plugin_config = PluginBlockConfig {
            denyip: Some(denyip_config),
        };

        let middleware_config = MiddlewareBlockConfig {
            plugin: Some(plugin_config),
        };

        let middleware_data = serde_json::json!({
            "apiVersion": format!("{}/{}", api_group, version),
            "kind": "Middleware",
            "metadata": {
                "name": name,
                "namespace": self.namespace.clone(),
            },
            "spec": middleware_config,
        });

        let gvk = GroupVersionKind {
            group: api_group.to_string(),
            version: version.to_string(),
            kind: "Middleware".to_string(),
        };
        let api_resource = ApiResource::from_gvk_with_plural(&gvk, "middlewares");

        let apis: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &api_resource);

        // Try to create or patch the middleware
        match self
            .create_or_patch_middleware(&apis, &name, &middleware_data)
            .await
        {
            Ok(_) => Ok(name),
            Err(e) => Err(e),
        }
    }

    /// Add an IP to a high-priority edge deny IngressRoute using Traefik's
    /// ClientIP matcher. This is the effective cluster-level block path for
    /// the local cluster because the route is attached to the public entrypoint.
    pub async fn block_ip_at_edge(
        &self,
        ip: &str,
        ingressroute_name: &str,
        service_name: &str,
        service_port: u16,
    ) -> Result<String, BlockerError> {
        let cidr = Self::cidr_for_ip(ip)?;
        let client_ip_rule = format!("ClientIP(`{}`)", cidr);

        let crd_name = self.middleware_api_group.ingressroute_crd_name();
        if !self.crd_exists(crd_name).await? {
            return Err(BlockerError::CrdNotFound(crd_name.to_string()));
        }

        let gvk = GroupVersionKind {
            group: self.middleware_api_group.group().to_string(),
            version: self.middleware_api_group.version().to_string(),
            kind: "IngressRoute".to_string(),
        };
        let api_resource = ApiResource::from_gvk_with_plural(&gvk, "ingressroutes");

        let apis: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &api_resource);

        const MAX_PATCH_ATTEMPTS: usize = 5;
        for attempt in 1..=MAX_PATCH_ATTEMPTS {
            let existing = match apis.get(ingressroute_name).await {
                Ok(route) => route,
                Err(e) => {
                    return Err(BlockerError::from_kube_error(
                        &e,
                        "get edge deny ingressroute",
                    ));
                }
            };

            let resource_version = existing.metadata.resource_version.clone();
            let mut spec = existing
                .data
                .get("spec")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));

            let entry_points = spec
                .get("entryPoints")
                .cloned()
                .unwrap_or_else(|| serde_json::json!(["websecure"]));

            let mut routes = spec
                .get_mut("routes")
                .and_then(|routes| routes.as_array_mut().map(std::mem::take))
                .unwrap_or_default();

            let mut changed = false;
            if routes.is_empty() {
                routes.push(serde_json::json!({
                    "kind": "Rule",
                    "match": client_ip_rule.clone(),
                    "priority": 100001,
                    "services": [{
                        "name": service_name,
                        "port": service_port
                    }]
                }));
                changed = true;
            } else {
                let route = &mut routes[0];
                let current_match = route.get("match").and_then(|m| m.as_str()).unwrap_or("");
                if !current_match.contains(&client_ip_rule) {
                    let next_match = if current_match.trim().is_empty() {
                        client_ip_rule.clone()
                    } else {
                        format!("{} || {}", current_match, client_ip_rule)
                    };
                    route["match"] = serde_json::Value::String(next_match);
                    changed = true;
                }

                if route.get("kind").is_none() {
                    route["kind"] = serde_json::Value::String("Rule".to_string());
                    changed = true;
                }
                if route.get("priority").is_none() {
                    route["priority"] = serde_json::json!(100001);
                    changed = true;
                }
                if route.get("services").is_none() {
                    route["services"] = serde_json::json!([{
                        "name": service_name,
                        "port": service_port
                    }]);
                    changed = true;
                }
            }

            if !changed {
                return Ok(ingressroute_name.to_string());
            }

            let mut patch_data = serde_json::json!({
                "spec": {
                    "entryPoints": entry_points,
                    "routes": routes
                }
            });
            if let Some(resource_version) = resource_version {
                patch_data["metadata"] = serde_json::json!({
                    "resourceVersion": resource_version
                });
            }

            let pp = PatchParams::default();
            let patch = Patch::Merge(&patch_data);

            match apis.patch(ingressroute_name, &pp, &patch).await {
                Ok(_) => return Ok(ingressroute_name.to_string()),
                Err(e) if is_kube_conflict(&e) && attempt < MAX_PATCH_ATTEMPTS => {
                    tracing::debug!(
                        "Retrying edge deny IngressRoute patch after resource conflict ({}/{})",
                        attempt,
                        MAX_PATCH_ATTEMPTS
                    );
                }
                Err(e) => {
                    return Err(BlockerError::from_kube_error(
                        &e,
                        "patch edge deny ingressroute",
                    ));
                }
            }
        }

        Err(BlockerError::ResourceConflict(format!(
            "patch edge deny ingressroute failed after {} attempts",
            MAX_PATCH_ATTEMPTS
        )))
    }

    #[allow(dead_code)]
    pub async fn is_ip_blocked_at_edge(
        &self,
        ip: &str,
        ingressroute_name: &str,
    ) -> Result<bool, BlockerError> {
        let cidr = Self::cidr_for_ip(ip)?;
        let client_ip_rule = format!("ClientIP(`{}`)", cidr);

        let crd_name = self.middleware_api_group.ingressroute_crd_name();
        if !self.crd_exists(crd_name).await? {
            return Err(BlockerError::CrdNotFound(crd_name.to_string()));
        }

        let gvk = GroupVersionKind {
            group: self.middleware_api_group.group().to_string(),
            version: self.middleware_api_group.version().to_string(),
            kind: "IngressRoute".to_string(),
        };
        let api_resource = ApiResource::from_gvk_with_plural(&gvk, "ingressroutes");

        let apis: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &api_resource);

        let existing = match apis.get(ingressroute_name).await {
            Ok(route) => route,
            Err(e) => {
                return Err(BlockerError::from_kube_error(
                    &e,
                    "get edge deny ingressroute",
                ));
            }
        };

        let blocked = existing
            .data
            .get("spec")
            .and_then(|spec| spec.get("routes"))
            .and_then(|routes| routes.as_array())
            .map(|routes| {
                routes.iter().any(|route| {
                    route
                        .get("match")
                        .and_then(|m| m.as_str())
                        .is_some_and(|m| m.contains(&client_ip_rule))
                })
            })
            .unwrap_or(false);

        Ok(blocked)
    }

    pub async fn blocked_cidrs_at_edge(
        &self,
        ingressroute_name: &str,
    ) -> Result<Vec<String>, BlockerError> {
        let crd_name = self.middleware_api_group.ingressroute_crd_name();
        if !self.crd_exists(crd_name).await? {
            return Err(BlockerError::CrdNotFound(crd_name.to_string()));
        }

        let gvk = GroupVersionKind {
            group: self.middleware_api_group.group().to_string(),
            version: self.middleware_api_group.version().to_string(),
            kind: "IngressRoute".to_string(),
        };
        let api_resource = ApiResource::from_gvk_with_plural(&gvk, "ingressroutes");

        let apis: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &api_resource);

        let existing = match apis.get(ingressroute_name).await {
            Ok(route) => route,
            Err(e) => {
                return Err(BlockerError::from_kube_error(
                    &e,
                    "get edge deny ingressroute",
                ));
            }
        };

        let mut cidrs: Vec<String> = existing
            .data
            .get("spec")
            .and_then(|spec| spec.get("routes"))
            .and_then(|routes| routes.as_array())
            .map(|routes| {
                routes
                    .iter()
                    .filter_map(|route| route.get("match").and_then(|m| m.as_str()))
                    .flat_map(extract_client_ip_match_values)
                    .collect()
            })
            .unwrap_or_default();
        cidrs.sort();
        cidrs.dedup();
        Ok(cidrs)
    }

    /// Create or patch a middleware resource
    async fn create_or_patch_middleware(
        &self,
        apis: &Api<DynamicObject>,
        name: &str,
        middleware_data: &serde_json::Value,
    ) -> Result<(), BlockerError> {
        // Try to get the existing middleware first
        let existing_mw = apis.get(name).await;

        match existing_mw {
            Ok(_) => {
                // Middleware exists, patch it
                self.patch_middleware(apis, name, middleware_data).await
            }
            Err(kube::Error::Api(err)) if err.code == 404 => {
                // Middleware doesn't exist, create it
                self.create_middleware(apis, name, middleware_data).await
            }
            Err(e) => {
                let blocker_err = BlockerError::from_kube_error(&e, "get middleware");
                Err(blocker_err)
            }
        }
    }

    /// Create a new middleware resource
    async fn create_middleware(
        &self,
        apis: &Api<DynamicObject>,
        _name: &str,
        middleware_data: &serde_json::Value,
    ) -> Result<(), BlockerError> {
        let dynamic_obj: DynamicObject = match serde_json::from_value(middleware_data.clone()) {
            Ok(obj) => obj,
            Err(e) => {
                return Err(BlockerError::Generic(format!(
                    "Failed to deserialize middleware data: {}",
                    e
                )));
            }
        };

        let pp = PostParams::default();
        match apis.create(&pp, &dynamic_obj).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let blocker_err = BlockerError::from_kube_error(&e, "create middleware");
                Err(blocker_err)
            }
        }
    }

    /// Patch an existing middleware resource
    async fn patch_middleware(
        &self,
        apis: &Api<DynamicObject>,
        name: &str,
        middleware_data: &serde_json::Value,
    ) -> Result<(), BlockerError> {
        let patch_data = serde_json::json!({
            "spec": middleware_data["spec"]
        });

        let pp = PatchParams::default().force();
        let patch = Patch::Merge(&patch_data);

        match apis.patch(name, &pp, &patch).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let blocker_err = BlockerError::from_kube_error(&e, "patch middleware");
                Err(blocker_err)
            }
        }
    }

    /// Remove a block for an IP by deleting the middleware
    #[allow(dead_code)]
    pub async fn unblock_ip(
        &self,
        ip: &str,
        middleware_name: Option<&str>,
    ) -> Result<(), BlockerError> {
        let name = middleware_name
            .map(|n| n.to_string())
            .unwrap_or_else(|| Self::generate_middleware_name(ip));

        let api_group = self.middleware_api_group.group();
        let version = self.middleware_api_group.version();

        let gvk = GroupVersionKind {
            group: api_group.to_string(),
            version: version.to_string(),
            kind: "Middleware".to_string(),
        };
        let api_resource = ApiResource::from_gvk_with_plural(&gvk, "middlewares");

        let apis: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &api_resource);

        let dp = DeleteParams::default();
        match apis.delete(&name, &dp).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(err)) if err.code == 404 => {
                // Middleware doesn't exist, which is fine for unblock
                Ok(())
            }
            Err(e) => {
                let blocker_err = BlockerError::from_kube_error(&e, "delete middleware");
                Err(blocker_err)
            }
        }
    }
}

fn is_kube_conflict(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(response) if response.code == 409)
}

fn extract_client_ip_match_values(rule: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut remaining = rule;

    while let Some(start) = remaining.find("ClientIP(") {
        remaining = &remaining[start + "ClientIP(".len()..];
        let Some(end) = remaining.find(')') else {
            break;
        };

        let args = &remaining[..end];
        values.extend(extract_quoted_match_args(args));
        remaining = &remaining[end + 1..];
    }

    values
}

fn extract_quoted_match_args(args: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for ch in args.chars() {
        match quote {
            Some(active_quote) if ch == active_quote => {
                let value = current.trim();
                if !value.is_empty() {
                    values.push(value.to_string());
                }
                current.clear();
                quote = None;
            }
            Some(_) => current.push(ch),
            None if ch == '`' || ch == '"' || ch == '\'' => quote = Some(ch),
            None => {}
        }
    }

    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocker_error_display() {
        let rbac_err =
            BlockerError::RbacPermissionDenied("no permissions to create middlewares".to_string());
        assert!(rbac_err.to_string().contains("RBAC permission denied"));
        assert!(
            rbac_err
                .to_string()
                .contains("no permissions to create middlewares")
        );

        let conflict_err = BlockerError::ResourceConflict("middleware already exists".to_string());
        assert!(conflict_err.to_string().contains("Resource conflict"));
        assert!(
            conflict_err
                .to_string()
                .contains("middleware already exists")
        );

        let not_found_err = BlockerError::CrdNotFound("middlewares.traefik.io".to_string());
        assert!(not_found_err.to_string().contains("CRD not found"));
        assert!(not_found_err.to_string().contains("middlewares.traefik.io"));

        let api_deprecated_err =
            BlockerError::ApiVersionDeprecated("v1alpha1 deprecated".to_string());
        assert!(
            api_deprecated_err
                .to_string()
                .contains("API version deprecated or not available")
        );

        let generic_err = BlockerError::Generic("generic error".to_string());
        assert!(
            generic_err
                .to_string()
                .contains("Blocker error: generic error")
        );
    }

    #[test]
    fn test_traefik_middleware_api_group_names() {
        let traefik_io = TraefikMiddlewareApiGroup::TraefikIoV1Alpha1;
        assert_eq!(traefik_io.group(), "traefik.io");
        assert_eq!(traefik_io.version(), "v1alpha1");
        assert_eq!(traefik_io.crd_name(), "middlewares.traefik.io");

        let containous = TraefikMiddlewareApiGroup::TraefikContainousV1Alpha1;
        assert_eq!(containous.group(), "traefik.containo.us");
        assert_eq!(containous.version(), "v1alpha1");
        assert_eq!(containous.crd_name(), "middlewares.traefik.containo.us");
    }

    #[test]
    fn test_extract_client_ip_match_values() {
        let values = extract_client_ip_match_values(
            "Host(`example.com`) || ClientIP(`203.0.113.10/32`) || ClientIP(\"2001:db8::1/128\")",
        );

        assert_eq!(values, vec!["203.0.113.10/32", "2001:db8::1/128"]);
    }

    #[test]
    fn test_ip_deny_list_config() {
        let config = IpDenyListConfig {
            ips: vec!["192.168.1.100".to_string(), "10.0.0.50".to_string()],
        };
        assert_eq!(config.ips.len(), 2);
        assert_eq!(config.ips[0], "192.168.1.100");
        assert_eq!(config.ips[1], "10.0.0.50");
    }

    #[test]
    fn test_deny_ip_block_config() {
        let ip_deny_list = IpDenyListConfig {
            ips: vec!["192.168.1.100".to_string()],
        };
        let config = DenyIpBlockConfig {
            ip_deny_list: Some(ip_deny_list),
        };
        assert!(config.ip_deny_list.is_some());
        assert_eq!(config.ip_deny_list.unwrap().ips.len(), 1);
    }

    #[test]
    fn test_middleware_block_config_defaults() {
        let config = MiddlewareBlockConfig::default();
        assert!(config.plugin.is_none());
    }

    #[test]
    fn test_generate_middleware_name() {
        let name = TraefikBlocker::generate_middleware_name("block-192.168.1.100");
        assert!(name.starts_with("denyip-block-"));
        assert!(name.contains("192-168-1-100"));
    }

    #[test]
    fn test_cidr_for_ip() {
        assert_eq!(
            TraefikBlocker::cidr_for_ip("192.168.1.100").unwrap(),
            "192.168.1.100/32"
        );
        assert_eq!(
            TraefikBlocker::cidr_for_ip("2001:db8::1").unwrap(),
            "2001:db8::1/128"
        );
        assert!(TraefikBlocker::cidr_for_ip("not-an-ip").is_err());
    }

    #[test]
    fn test_blocker_error_from_kube_error_rbac() {
        // Test that 403 errors are mapped to RbacPermissionDenied
        let kube_err = kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "middlewares.traefik.io is forbidden: User \"system:serviceaccount:default:devops-agent-sa\" cannot create resource \"middlewares\" in API group \"traefik.io\" in the namespace \"default\"".to_string(),
            reason: "Forbidden".to_string(),
            code: 403,
        });

        let blocker_err = BlockerError::from_kube_error(&kube_err, "create");
        assert!(matches!(blocker_err, BlockerError::RbacPermissionDenied(_)));
    }

    #[test]
    fn test_blocker_error_from_kube_error_conflict() {
        // Test that 409 errors are mapped to ResourceConflict
        let kube_err = kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "Operation cannot be fulfilled on middlewares.traefik.io \"denyip-block-192-168-1-100\": the object has been modified; please apply your changes to the latest version and try again".to_string(),
            reason: "Conflict".to_string(),
            code: 409,
        });

        let blocker_err = BlockerError::from_kube_error(&kube_err, "update");
        assert!(matches!(blocker_err, BlockerError::ResourceConflict(_)));
    }

    #[test]
    fn test_blocker_error_from_kube_error_not_found() {
        // Test that 404 errors for CRDs are mapped to CrdNotFound
        let kube_err = kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "customresourcedefinitions.apiextensions.k8s.io \"middlewares.traefik.io\" not found".to_string(),
            reason: "NotFound".to_string(),
            code: 404,
        });

        let blocker_err = BlockerError::from_kube_error(&kube_err, "create");
        assert!(matches!(blocker_err, BlockerError::CrdNotFound(_)));
    }

    #[test]
    fn test_blocker_error_from_kube_error_deprecated() {
        // Test that 410 errors are mapped to ApiVersionDeprecated
        let kube_err = kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message:
                "the server is currently unable to handle the request (get middlewares.traefik.io)"
                    .to_string(),
            reason: "Gone".to_string(),
            code: 410,
        });

        let blocker_err = BlockerError::from_kube_error(&kube_err, "create");
        assert!(matches!(blocker_err, BlockerError::ApiVersionDeprecated(_)));
    }
}

use autoagents::async_trait;
use autoagents::core::tool::ToolCallError;
use autoagents::prelude::*;
use kube::Client;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(ToolInput, Serialize, Deserialize)]
pub struct InspectPatternsInput {
    #[input(description = "Namespace to inspect (optional, defaults to all namespaces)")]
    pub namespace: Option<String>,
}

#[tool(
    name = "inspect_patterns",
    description = "Inspect Kubernetes Traefik patterns (Middleware IP allowlists/denylists and IngressRoute path patterns)",
    input = InspectPatternsInput
)]
pub struct InspectPatternsTool {
    pub k8s_client: Arc<Mutex<Option<Arc<Client>>>>,
}

impl Default for InspectPatternsTool {
    fn default() -> Self {
        Self {
            k8s_client: Arc::new(Mutex::new(None)),
        }
    }
}

impl Clone for InspectPatternsTool {
    fn clone(&self) -> Self {
        Self {
            k8s_client: self.k8s_client.clone(),
        }
    }
}

#[async_trait]
impl ToolRuntime for InspectPatternsTool {
    async fn execute(&self, args: serde_json::Value) -> Result<serde_json::Value, ToolCallError> {
        let input: InspectPatternsInput = serde_json::from_value(args)?;

        let client = self
            .k8s_client
            .lock()
            .unwrap()
            .as_ref()
            .ok_or_else(|| ToolCallError::RuntimeError("Kubernetes client not configured".into()))?
            .clone();

        let inspector_client = client.clone();
        let mut inspector_init = crate::k8s::TraefikInspector {
            client: (*inspector_client).clone(),
            namespace: input.namespace.clone(),
            middleware_api_group: crate::k8s::MiddlewareApiGroup::TraefikIoV1Alpha1,
            ingressroute_api_group: crate::k8s::IngressRouteApiGroup::TraefikIoV1Alpha1,
        };

        match inspector_init.init_with_detection().await {
            Ok(_) => match inspector_init.inspect_all().await {
                Ok(results) => {
                    let results_json = serde_json::json!({
                        "middlewares": results.middlewares.iter().map(|mw| {
                            serde_json::json!({
                                "name": mw.name,
                                "namespace": mw.namespace,
                                "ip_allowlist": mw.config.ip_allowlist.as_ref().map(|ial| {
                                    serde_json::json!({
                                        "source_range": ial.source_range
                                    })
                                }),
                                "denyip": mw.config.denyip.as_ref().map(|di| {
                                    serde_json::json!({
                                        "source_range": di.source_range
                                    })
                                })
                            })
                        }).collect::<Vec<_>>(),
                        "ingress_routes": results.ingress_routes.iter().map(|ir| {
                            serde_json::json!({
                                "name": ir.name,
                                "namespace": ir.namespace,
                                "entry_points": ir.config.entry_points,
                                "routes": ir.config.routes.iter().map(|route| {
                                    serde_json::json!({
                                        "path": route.path,
                                        "path_type": route.path_type,
                                        "match_rule": route.match_rule,
                                        "path_regexp": route.path_regexp.as_ref().map(|pr| {
                                            serde_json::json!({
                                                "name": pr.name,
                                                "pattern": pr.pattern
                                            })
                                        })
                                    })
                                }).collect::<Vec<_>>()
                            })
                        }).collect::<Vec<_>>(),
                        "api_group_used": results.api_group_used,
                        "success": true
                    });
                    Ok(results_json)
                }
                Err(e) => {
                    let error_json = serde_json::json!({
                        "error": e.to_string(),
                        "success": false
                    });
                    Ok(error_json)
                }
            },
            Err(e) => {
                let error_json = serde_json::json!({
                    "error": e.to_string(),
                    "success": false
                });
                Ok(error_json)
            }
        }
    }
}

use autoagents::async_trait;
use autoagents::core::tool::ToolCallError;
use autoagents::prelude::*;
use kube::Client;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(ToolInput, Serialize, Deserialize)]
pub struct ApplyBlockInput {
    #[input(description = "IP address to block")]
    pub ip: String,
    #[input(
        description = "Namespace for the Traefik Middleware (optional, defaults to 'default')"
    )]
    pub namespace: Option<String>,
    #[input(description = "Action to perform: 'block' or 'unblock'")]
    pub action: String,
}

#[tool(
    name = "apply_block",
    description = "Apply or remove IP blocks using Kubernetes Traefik Middleware resources",
    input = ApplyBlockInput
)]
pub struct ApplyBlockTool {
    pub k8s_client: Arc<Mutex<Option<Arc<Client>>>>,
    pub namespace: Arc<Mutex<String>>,
}

impl Default for ApplyBlockTool {
    fn default() -> Self {
        Self {
            k8s_client: Arc::new(Mutex::new(None)),
            namespace: Arc::new(Mutex::new("default".to_string())),
        }
    }
}

impl Clone for ApplyBlockTool {
    fn clone(&self) -> Self {
        Self {
            k8s_client: self.k8s_client.clone(),
            namespace: self.namespace.clone(),
        }
    }
}

#[async_trait]
impl ToolRuntime for ApplyBlockTool {
    async fn execute(&self, args: serde_json::Value) -> Result<serde_json::Value, ToolCallError> {
        let input: ApplyBlockInput = serde_json::from_value(args)?;

        let client = self
            .k8s_client
            .lock()
            .unwrap()
            .as_ref()
            .ok_or_else(|| ToolCallError::RuntimeError("Kubernetes client not configured".into()))?
            .clone();

        let namespace = input
            .namespace
            .clone()
            .unwrap_or_else(|| self.namespace.lock().unwrap().clone());

        if input.action == "block" {
            let blocker_client = client.clone();
            let mut blocker_init = crate::k8s::TraefikBlocker {
                client: (*blocker_client).clone(),
                namespace: namespace.clone(),
                middleware_api_group: crate::k8s::TraefikMiddlewareApiGroup::TraefikIoV1Alpha1,
            };

            match blocker_init.init_with_detection().await {
                Ok(_) => {
                    let blocker = crate::k8s::TraefikBlocker {
                        client: (*blocker_client).clone(),
                        namespace: namespace.clone(),
                        middleware_api_group: blocker_init.middleware_api_group,
                    };
                    match blocker.block_ip(&input.ip, None).await {
                        Ok(middleware_name) => {
                            let result_json = serde_json::json!({
                                "ip": input.ip,
                                "action": "block",
                                "middleware_name": middleware_name,
                                "success": true
                            });
                            Ok(result_json)
                        }
                        Err(e) => {
                            let error_json = serde_json::json!({
                                "error": e.to_string(),
                                "ip": input.ip,
                                "action": "block",
                                "success": false
                            });
                            Ok(error_json)
                        }
                    }
                }
                Err(e) => {
                    let error_json = serde_json::json!({
                        "error": e.to_string(),
                        "ip": input.ip,
                        "action": "block",
                        "success": false
                    });
                    Ok(error_json)
                }
            }
        } else if input.action == "unblock" {
            let blocker_client = client.clone();
            let mut blocker_init = crate::k8s::TraefikBlocker {
                client: (*blocker_client).clone(),
                namespace: namespace.clone(),
                middleware_api_group: crate::k8s::TraefikMiddlewareApiGroup::TraefikIoV1Alpha1,
            };

            match blocker_init.init_with_detection().await {
                Ok(_) => {
                    let blocker = crate::k8s::TraefikBlocker {
                        client: (*blocker_client).clone(),
                        namespace: namespace.clone(),
                        middleware_api_group: blocker_init.middleware_api_group,
                    };
                    match blocker.unblock_ip(&input.ip, None).await {
                        Ok(_) => {
                            let result_json = serde_json::json!({
                                "ip": input.ip,
                                "action": "unblock",
                                "success": true
                            });
                            Ok(result_json)
                        }
                        Err(e) => {
                            let error_json = serde_json::json!({
                                "error": e.to_string(),
                                "ip": input.ip,
                                "action": "unblock",
                                "success": false
                            });
                            Ok(error_json)
                        }
                    }
                }
                Err(e) => {
                    let error_json = serde_json::json!({
                        "error": e.to_string(),
                        "ip": input.ip,
                        "action": "unblock",
                        "success": false
                    });
                    Ok(error_json)
                }
            }
        } else {
            let error_json = serde_json::json!({
                "error": format!("Invalid action: {}. Must be 'block' or 'unblock'", input.action),
                "success": false
            });
            Ok(error_json)
        }
    }
}

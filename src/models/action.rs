use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Action {
    pub id: String,
    pub incident_id: String,
    pub action_type: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_json_serialize_deserialize() {
        let action = Action {
            id: "act-456".to_string(),
            incident_id: "inc-123".to_string(),
            action_type: "block_ip".to_string(),
            status: "pending".to_string(),
        };

        let json = serde_json::to_string(&action).unwrap();
        let deserialized: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(action.id, deserialized.id);
        assert_eq!(action.incident_id, deserialized.incident_id);
        assert_eq!(action.action_type, deserialized.action_type);
        assert_eq!(action.status, deserialized.status);
    }

    #[test]
    fn test_action_yaml_serialize_deserialize() {
        let action = Action {
            id: "act-456".to_string(),
            incident_id: "inc-123".to_string(),
            action_type: "block_ip".to_string(),
            status: "pending".to_string(),
        };

        let yaml = serde_yaml::to_string(&action).unwrap();
        let deserialized: Action = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(action.id, deserialized.id);
        assert_eq!(action.incident_id, deserialized.incident_id);
        assert_eq!(action.action_type, deserialized.action_type);
        assert_eq!(action.status, deserialized.status);
    }
}

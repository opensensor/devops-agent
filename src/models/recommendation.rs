use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Recommendation {
    pub incident_id: String,
    pub recommendation: String,
    pub action_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommendation_json_serialize_deserialize() {
        let rec = Recommendation {
            incident_id: "inc-123".to_string(),
            recommendation: "Block IP 192.168.1.100 due to secrets scanning activity".to_string(),
            action_type: "block".to_string(),
        };

        let json = serde_json::to_string(&rec).unwrap();
        let deserialized: Recommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(rec.incident_id, deserialized.incident_id);
        assert_eq!(rec.recommendation, deserialized.recommendation);
        assert_eq!(rec.action_type, deserialized.action_type);
    }

    #[test]
    fn test_recommendation_yaml_serialize_deserialize() {
        let rec = Recommendation {
            incident_id: "inc-123".to_string(),
            recommendation: "Block IP 192.168.1.100 due to secrets scanning activity".to_string(),
            action_type: "block".to_string(),
        };

        let yaml = serde_yaml::to_string(&rec).unwrap();
        let deserialized: Recommendation = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(rec.incident_id, deserialized.incident_id);
        assert_eq!(rec.recommendation, deserialized.recommendation);
        assert_eq!(rec.action_type, deserialized.action_type);
    }
}

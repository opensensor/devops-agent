use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Incident {
    pub id: String,
    pub source_ip: String,
    pub detected_at: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_json_serialize_deserialize() {
        let incident = Incident {
            id: "inc-123".to_string(),
            source_ip: "192.168.1.100".to_string(),
            detected_at: "2026-07-01T12:00:00Z".to_string(),
            status: "detected".to_string(),
        };

        let json = serde_json::to_string(&incident).unwrap();
        let deserialized: Incident = serde_json::from_str(&json).unwrap();
        assert_eq!(incident.id, deserialized.id);
        assert_eq!(incident.source_ip, deserialized.source_ip);
        assert_eq!(incident.detected_at, deserialized.detected_at);
        assert_eq!(incident.status, deserialized.status);
    }

    #[test]
    fn test_incident_yaml_serialize_deserialize() {
        let incident = Incident {
            id: "inc-123".to_string(),
            source_ip: "192.168.1.100".to_string(),
            detected_at: "2026-07-01T12:00:00Z".to_string(),
            status: "detected".to_string(),
        };

        let yaml = serde_yaml::to_string(&incident).unwrap();
        let deserialized: Incident = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(incident.id, deserialized.id);
        assert_eq!(incident.source_ip, deserialized.source_ip);
        assert_eq!(incident.detected_at, deserialized.detected_at);
        assert_eq!(incident.status, deserialized.status);
    }
}

use std::collections::HashMap;
use crate::types::internal::audit::EventType;

pub struct AuditIntent {
    pub event_type: EventType,
    pub data: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
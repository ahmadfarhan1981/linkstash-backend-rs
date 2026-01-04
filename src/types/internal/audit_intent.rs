use std::collections::HashMap;
use crate::types::internal::audit::EventType;

#[derive(Clone)]
pub struct AuditIntent {
    pub event_type: EventType,
    pub data: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl AuditIntent {
    /// Create a new AuditIntent with the specified event type
    pub fn new(event_type: EventType) -> Self {
        Self {
            event_type,
            data: HashMap::new(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Set the event type for this audit intent
    pub fn with_event_type(mut self, event_type: EventType) -> Self {
        self.event_type = event_type;
        self
    }

    /// Add a key-value pair to the data HashMap
    pub fn with_data<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Add multiple key-value pairs to the data HashMap
    pub fn with_data_map(mut self, data: HashMap<String, serde_json::Value>) -> Self {
        self.data.extend(data);
        self
    }

    /// Set a custom timestamp (useful for testing or backdated events)
    pub fn with_timestamp(mut self, timestamp: chrono::DateTime<chrono::Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }
}
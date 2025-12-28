use std::sync::Arc;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use crate::audit::AuditLogger;
use crate::errors::InternalError;
use crate::stores::AuditStore;
use crate::types::internal::audit::{AuditEvent, EventType};
use crate::types::internal::context::RequestContext;

pub struct AuditBuilder {
    event: AuditEvent,
    store: Arc<AuditStore>
}

impl AuditBuilder {
    /// Create a new AuditBuilder with the specified event type
    ///
    /// # Arguments
    /// * `store` - Arc reference to the AuditStore
    /// * `event_type` - Event type (can be EventType enum or string for custom events)
    pub fn new(store: Arc<AuditStore>, event_type: impl Into<EventType>) -> Self {
        Self {
            event: AuditEvent::new(event_type.into()),
            store,
        }
    }

    /// Set the user ID for this audit event
    ///
    /// # Arguments
    /// * `id` - User ID
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.event.user_id = Some(id.into());
        self
    }

    /// Set the IP address for this audit event
    ///
    /// # Arguments
    /// * `ip` - IP address as a string
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.event.ip_address = Some(ip.into());
        self
    }

    /// Set the JWT ID for this audit event
    ///
    /// # Arguments
    /// * `id` - JWT identifier (jti claim)
    pub fn jwt_id(mut self, id: impl Into<String>) -> Self {
        self.event.jwt_id = Some(id.into());
        self
    }

    /// Add an arbitrary field to the audit event
    ///
    /// The value will be serialized to JSON and stored in the event's data field.
    ///
    /// # Arguments
    /// * `key` - Field name
    /// * `value` - Field value (must implement Serialize)
    pub fn add_field(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        // Serialize the value to JSON
        if let Ok(json_value) = serde_json::to_value(value) {
            self.event.data.insert(key.into(), json_value);
        }
        self
    }

    /// Add a sensitive field to the audit event with SHA-256 hashing
    ///
    /// The value will be hashed using SHA-256 to prevent exposure while maintaining
    /// the ability to correlate events. Same input always produces the same hash,
    /// allowing pattern detection without revealing the original value.
    ///
    /// Use cases:
    /// - Email addresses (correlate password reset requests)
    /// - Phone numbers (track verification attempts)
    /// - Session identifiers (correlate related events)
    ///
    /// # Arguments
    /// * `key` - Field name
    /// * `value` - Field value (will be hashed)
    pub fn add_sensitive(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        // Serialize the value to a string representation for hashing
        if let Ok(json_value) = serde_json::to_value(&value) {
            let value_str = json_value.to_string();

            // Hash the value using SHA-256
            let mut hasher = Sha256::new();
            hasher.update(value_str.as_bytes());
            let hash_result = hasher.finalize();
            let hash_hex = format!("sha256:{:x}", hash_result);

            self.event.data.insert(key.into(), json!(hash_hex));
        }
        self
    }

    /// Write the audit event to the database
    ///
    /// Validates that user_id is present before writing. Returns an error if validation fails
    /// or if the database operation fails.
    ///
    /// # Errors
    /// Returns `AuditError::MissingUserId` if user_id was not set
    /// Returns `AuditError::DatabaseError` if the database operation fails
    pub async fn write(self) -> Result<(), InternalError> {
        // Validate that user_id is present
        if self.event.user_id.is_none() {
            return Err(InternalError::Audit(crate::errors::internal::AuditError::LogWriteFailed("Missing user_id".to_string())));
        }

        // Write the event to the database
        self.store.write_event(self.event).await
    }
}

#[cfg(test)]
mod tests {
    use linkstash_backend::test::utils::setup_test_stores;
    use crate::audit::AuditLogger;
    use super::*;
    use linkstash_backend::test::utils::setup_test_stores;
    use crate::types::internal::context::RequestContext;

    async fn create_test_audit_logger_provider() -> AuditLogger {
        let (_connections, _credential_store, audit_store) = setup_test_stores().await;
        AuditLogger::new(audit_store)
    }
    #[tokio::test]
    async fn test_audit_builder() {
        let provider = create_test_audit_logger_provider().await;

        let result = provider.builder("custom_event")
            .user_id("user123")
            .ip_address("192.168.1.1")
            .add_field("action", "test_action")
            .write()
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_builder_missing_user_id() {
        let provider = create_test_audit_logger_provider().await;

        let result = provider.builder("custom_event")
            .ip_address("192.168.1.1")
            .add_field("action", "test_action")
            .write()
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_audit_builder_sensitive_field() {
        let provider = create_test_audit_logger_provider().await;

        let result = provider.builder("custom_event")
            .user_id("user123")
            .add_sensitive("email", "test@example.com")
            .write()
            .await;

        assert!(result.is_ok());
    }
}

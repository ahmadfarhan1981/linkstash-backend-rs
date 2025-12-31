use std::sync::Arc;
use std::collections::HashMap;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use crate::errors::InternalError;
use crate::stores::AuditStore;
use crate::types::internal::audit::{AuditEvent, EventType};
use crate::types::internal::context::RequestContext;

/// Builder for creating custom audit events
///
/// Provides a fluent API for constructing audit events with type-safe field addition
/// and automatic sensitive data redaction.
///
/// # Example
/// ```
/// use std::sync::Arc;
/// use linkstash_backend::audit::AuditBuilder;
/// use linkstash_backend::stores::AuditStore;
///
/// async fn example(audit_store: Arc<AuditStore>, ctx: &RequestContext) {
///     AuditBuilder::new(audit_store.clone(), "password_reset_requested")
///         .with_context(ctx)
///         .add_field("reset_token_id", "abc123")
///         .add_sensitive("email", "user@example.com")
///         .write()
///         .await
///         .expect("Failed to write audit event");
/// }
/// ```
/// 
pub struct AuditBuilder {
    event_type: EventType,
    user_id: Option<String>,
    ip_address: Option<String>,
    jwt_id: Option<String>,
    data: HashMap<String, serde_json::Value>,
    store: Arc<AuditStore>,
}

impl AuditBuilder {
    /// Create a new AuditBuilder with the specified event type
    ///
    /// # Arguments
    /// * `store` - Arc reference to the AuditStore
    /// * `event_type` - Event type (can be EventType enum or string for custom events)
    pub fn new(store: Arc<AuditStore>, event_type: impl Into<EventType>) -> Self {
        Self {
            event_type: event_type.into(),
            user_id: None,
            ip_address: None,
            jwt_id: None,
            data: HashMap::new(),
            store,
        }
    }

    /// Populate builder fields from RequestContext
    /// 
    /// Maps RequestContext fields to AuditEvent fields:
    /// - `actor_id` -> `user_id` (actor who performed the action)
    /// - `ip_address` -> `ip_address` (or "unknown" if None)
    /// - `jwt_id` from claims -> `jwt_id` (or "none" if no JWT)
    /// - Other fields (request_id, source, authenticated) -> `data` JSON
    pub fn with_context(mut self, ctx: &RequestContext) -> Self {
        // Actor ID becomes user_id (who performed the action)
        self.user_id = Some(ctx.actor_id.clone());
        
        // IP address (use "unknown" if not available)
        self.ip_address = Some(ctx.ip_address.clone().unwrap_or_else(|| "unknown".to_string()));
        
        // Extract JWT ID from claims if available, otherwise use "none"
        self.jwt_id = Some(
            ctx.claims
                .as_ref()
                .map(|claims| claims.jti.clone())
                .unwrap_or_else(|| "none".to_string())
        );
        
        // Add other context fields to data JSON
        self.data.insert("request_id".to_string(), json!(ctx.request_id));
        self.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        self.data.insert("authenticated".to_string(), json!(ctx.authenticated));
        
        self
    }

    /// Set the user ID for this audit event
    ///
    /// # Arguments
    /// * `id` - User ID
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.user_id = Some(id.into());
        self
    }

    /// Set the IP address for this audit event
    ///
    /// # Arguments
    /// * `ip` - IP address as a string
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set the JWT ID for this audit event
    ///
    /// # Arguments
    /// * `id` - JWT identifier (jti claim)
    pub fn jwt_id(mut self, id: impl Into<String>) -> Self {
        self.jwt_id = Some(id.into());
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
            self.data.insert(key.into(), json_value);
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

            self.data.insert(key.into(), json!(hash_hex));
        }
        self
    }

    /// Build the audit event without writing to database
    /// 
    /// Returns the constructed AuditEvent. All required fields must be set
    /// (user_id, ip_address, jwt_id) or defaults will be used.
    /// 
    /// # Panics
    /// Panics if required fields are not set. Use `with_context()` or set fields manually.
    pub fn build(self) -> AuditEvent {
        let user_id = self.user_id.unwrap_or_else(|| "unknown".to_string());
        let ip_address = self.ip_address.unwrap_or_else(|| "unknown".to_string());
        let jwt_id = self.jwt_id.unwrap_or_else(|| "none".to_string());

        AuditEvent {
            event_type: self.event_type,
            user_id,
            ip_address,
            jwt_id,
            data: self.data,
        }
    }

    /// Write the audit event to the database
    ///
    /// Builds the event and writes it directly to storage.
    pub async fn write(self) -> Result<(), InternalError> {
        let store = self.store.clone();
        let event = self.build();
        store.write_event(event).await
    }
}


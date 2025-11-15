use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::stores::audit_store::AuditStore;
use crate::types::internal::audit::{AuditError, AuditEvent, EventType};

/// Log a successful login event
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `user_id` - ID of the user who logged in
/// * `ip_address` - Optional IP address of the client
pub async fn log_login_success(
    store: &AuditStore,
    user_id: String,
    ip_address: Option<String>,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::LoginSuccess);
    event.user_id = Some(user_id);
    event.ip_address = ip_address;
    
    store.write_event(event).await
}

/// Log a failed login attempt
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `user_id` - Optional ID of the user (if username was valid)
/// * `failure_reason` - Reason for the login failure
/// * `ip_address` - Optional IP address of the client
pub async fn log_login_failure(
    store: &AuditStore,
    user_id: Option<String>,
    failure_reason: String,
    ip_address: Option<String>,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::LoginFailure);
    event.user_id = user_id;
    event.ip_address = ip_address;
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    
    store.write_event(event).await
}

/// Log JWT issuance
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `user_id` - ID of the user for whom the JWT was issued
/// * `jwt_id` - JWT identifier (jti claim)
/// * `expiration` - Expiration timestamp of the JWT
/// * `ip_address` - Optional IP address of the client (if available)
pub async fn log_jwt_issued(
    store: &AuditStore,
    user_id: String,
    jwt_id: String,
    expiration: DateTime<Utc>,
    ip_address: Option<String>,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::JwtIssued);
    event.user_id = Some(user_id);
    event.jwt_id = Some(jwt_id);
    event.ip_address = ip_address;
    event.data.insert("expiration".to_string(), json!(expiration.to_rfc3339()));
    
    store.write_event(event).await
}

/// Log JWT validation failure
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `user_id` - ID of the user from the JWT claims
/// * `jwt_id` - Optional JWT identifier (jti claim)
/// * `failure_reason` - Reason for the validation failure
pub async fn log_jwt_validation_failure(
    store: &AuditStore,
    user_id: String,
    jwt_id: Option<String>,
    failure_reason: String,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::JwtValidationFailure);
    event.user_id = Some(user_id);
    event.jwt_id = jwt_id;
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    
    store.write_event(event).await
}

/// Log JWT tampering detection
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `user_id` - ID of the user from the JWT claims (if extractable)
/// * `jwt_id` - Optional JWT identifier (jti claim)
/// * `full_jwt` - Full JWT string for forensic analysis
/// * `failure_reason` - Reason for the tampering detection
pub async fn log_jwt_tampered(
    store: &AuditStore,
    user_id: String,
    jwt_id: Option<String>,
    full_jwt: String,
    failure_reason: String,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::JwtTampered);
    event.user_id = Some(user_id);
    event.jwt_id = jwt_id;
    event.data.insert("full_jwt".to_string(), json!(full_jwt));
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    
    store.write_event(event).await
}

/// Log refresh token issuance
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `user_id` - ID of the user for whom the refresh token was issued
/// * `jwt_id` - JWT identifier associated with this refresh token
/// * `token_id` - Unique identifier for the refresh token
/// * `ip_address` - Optional IP address of the client (if available)
pub async fn log_refresh_token_issued(
    store: &AuditStore,
    user_id: String,
    jwt_id: String,
    token_id: String,
    ip_address: Option<String>,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenIssued);
    event.user_id = Some(user_id);
    event.jwt_id = Some(jwt_id);
    event.ip_address = ip_address;
    event.data.insert("token_id".to_string(), json!(token_id));
    
    store.write_event(event).await
}

/// Log refresh token revocation
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `user_id` - ID of the user whose refresh token was revoked
/// * `jwt_id` - Optional JWT identifier associated with this refresh token
/// * `token_id` - Unique identifier for the refresh token
pub async fn log_refresh_token_revoked(
    store: &AuditStore,
    user_id: String,
    jwt_id: Option<String>,
    token_id: String,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenRevoked);
    event.user_id = Some(user_id);
    event.jwt_id = jwt_id;
    event.data.insert("token_id".to_string(), json!(token_id));
    
    store.write_event(event).await
}

/// Log refresh token validation failure
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `token_hash` - Hash of the refresh token that failed validation
/// * `failure_reason` - Reason for the validation failure (not_found, expired)
/// * `ip_address` - Optional IP address of the client
pub async fn log_refresh_token_validation_failure(
    store: &AuditStore,
    token_hash: String,
    failure_reason: String,
    ip_address: Option<String>,
) -> Result<(), AuditError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenValidationFailure);
    event.user_id = Some("unknown".to_string());
    event.ip_address = ip_address;
    event.data.insert("token_hash".to_string(), json!(token_hash));
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    
    store.write_event(event).await
}

/// Builder for creating custom audit events
///
/// Provides a fluent API for constructing audit events with type-safe field addition
/// and automatic sensitive data redaction.
///
/// # Example
/// ```
/// use std::sync::Arc;
/// use linkstash_backend::services::audit_logger::AuditBuilder;
/// use linkstash_backend::stores::audit_store::AuditStore;
///
/// async fn example(audit_store: Arc<AuditStore>) {
///     AuditBuilder::new(audit_store.clone(), "password_reset_requested")
///         .user_id(123.to_string())
///         .ip_address("192.168.1.1")
///         .add_field("reset_token_id", "abc123")
///         .add_sensitive("email", "user@example.com")
///         .write()
///         .await
///         .expect("Failed to write audit event");
/// }
/// ```
pub struct AuditBuilder {
    event: AuditEvent,
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
    pub async fn write(self) -> Result<(), AuditError> {
        // Validate that user_id is present
        if self.event.user_id.is_none() {
            return Err(AuditError::MissingUserId);
        }
        
        // Write the event to the database
        self.store.write_event(self.event).await
    }
}

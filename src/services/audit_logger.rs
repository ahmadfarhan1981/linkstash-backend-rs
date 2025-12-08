use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::stores::audit_store::AuditStore;
use crate::types::internal::audit::{AuditEvent, EventType};
use crate::types::internal::context::RequestContext;
use crate::errors::InternalError;

/// Log a successful login event
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `target_user_id` - ID of the user who logged in (target of the action)
pub async fn log_login_success(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::LoginSuccess);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

/// Log a failed login attempt
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `failure_reason` - Reason for the login failure
/// * `attempted_username` - Optional username that was attempted (for forensic analysis)
pub async fn log_login_failure(
    store: &AuditStore,
    ctx: &RequestContext,
    failure_reason: String,
    attempted_username: Option<String>,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::LoginFailure);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    if let Some(username) = attempted_username {
        event.data.insert("attempted_username".to_string(), json!(username));
    }
    
    store.write_event(event).await
}

/// Log JWT issuance
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `target_user_id` - ID of the user for whom the JWT was issued (JWT subject)
/// * `issued_jwt_id` - JWT identifier (jti claim) of the JWT being issued
/// * `expiration` - Expiration timestamp of the JWT
pub async fn log_jwt_issued(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: String,
    issued_jwt_id: String,
    expiration: DateTime<Utc>,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::JwtIssued);
    event.user_id = Some(ctx.actor_id.clone());
    // For JWT issuance, jwt_id field contains the JWT being issued (for easier querying)
    event.jwt_id = Some(issued_jwt_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("expiration".to_string(), json!(expiration.to_rfc3339()));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    // Also store actor's JWT ID if authenticated (for tracing who requested the issuance)
    if let Some(actor_jwt_id) = ctx.claims.as_ref().and_then(|c| c.jti.clone()) {
        event.data.insert("actor_jwt_id".to_string(), json!(actor_jwt_id));
    }
    
    store.write_event(event).await
}

/// Log JWT validation failure
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information (from JWT claims)
/// * `failure_reason` - Reason for the validation failure
pub async fn log_jwt_validation_failure(
    store: &AuditStore,
    ctx: &RequestContext,
    failure_reason: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::JwtValidationFailure);
    event.user_id = Some(ctx.actor_id.clone());
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

/// Log JWT tampering detection
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information (from unverified JWT claims)
/// * `full_jwt` - Full JWT string for forensic analysis
/// * `failure_reason` - Reason for the tampering detection
pub async fn log_jwt_tampered(
    store: &AuditStore,
    ctx: &RequestContext,
    full_jwt: String,
    failure_reason: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::JwtTampered);
    event.user_id = Some(ctx.actor_id.clone());
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("full_jwt".to_string(), json!(full_jwt));
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

/// Log refresh token issuance
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `target_user_id` - ID of the user for whom the refresh token was issued (token owner)
/// * `jwt_id` - JWT identifier associated with this refresh token
/// * `token_id` - Unique identifier for the refresh token
pub async fn log_refresh_token_issued(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: String,
    jwt_id: String,
    token_id: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenIssued);
    event.user_id = Some(ctx.actor_id.clone());
    event.jwt_id = Some(jwt_id);
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("token_id".to_string(), json!(token_id));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    // Store actor's JWT ID if authenticated (for tracing who requested the issuance)
    if let Some(actor_jwt_id) = ctx.claims.as_ref().and_then(|c| c.jti.clone()) {
        event.data.insert("actor_jwt_id".to_string(), json!(actor_jwt_id));
    }
    
    store.write_event(event).await
}

/// Log refresh token revocation
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `target_user_id` - ID of the user whose refresh token was revoked (token owner)
/// * `token_id` - Unique identifier for the refresh token
pub async fn log_refresh_token_revoked(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: String,
    token_id: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenRevoked);
    event.user_id = Some(ctx.actor_id.clone());
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("token_id".to_string(), json!(token_id));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

/// Log all refresh tokens invalidated event
///
/// Used when admin roles change and all tokens for a user need to be invalidated
/// to force re-authentication with updated JWT claims.
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context with actor information for audit logging
/// * `user_id` - The user whose tokens were invalidated
/// * `reason` - Reason for invalidation (e.g., "admin_role_changed")
pub async fn log_all_refresh_tokens_invalidated(
    store: &AuditStore,
    ctx: &RequestContext,
    user_id: String,
    reason: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenRevoked);
    event.user_id = Some(user_id);
    event.ip_address = ctx.ip_address.clone();
    // Extract JWT ID from claims if authenticated
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("action".to_string(), json!("all_tokens_invalidated"));
    event.data.insert("reason".to_string(), json!(reason));
    event.data.insert("actor_id".to_string(), json!(ctx.actor_id));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log token invalidation failure
///
/// Used when an attempt to invalidate all tokens for a user fails due to
/// database errors or other issues.
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context with actor information for audit logging
/// * `user_id` - The user whose tokens were being invalidated
/// * `reason` - Original reason for invalidation attempt
/// * `error_message` - Error message describing why invalidation failed
pub async fn log_token_invalidation_failure(
    store: &AuditStore,
    ctx: &RequestContext,
    user_id: String,
    reason: String,
    error_message: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenRevoked);
    event.user_id = Some(user_id);
    event.ip_address = ctx.ip_address.clone();
    // Extract JWT ID from claims if authenticated
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("action".to_string(), json!("all_tokens_invalidation_failed"));
    event.data.insert("reason".to_string(), json!(reason));
    event.data.insert("error_message".to_string(), json!(error_message));
    event.data.insert("actor_id".to_string(), json!(ctx.actor_id));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log refresh token validation failure
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `token_hash` - Hash of the refresh token that failed validation
/// * `failure_reason` - Reason for the validation failure (not_found, expired)
pub async fn log_refresh_token_validation_failure(
    store: &AuditStore,
    ctx: &RequestContext,
    token_hash: String,
    failure_reason: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::RefreshTokenValidationFailure);
    event.user_id = Some(ctx.actor_id.clone());
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("token_hash".to_string(), json!(token_hash));
    event.data.insert("failure_reason".to_string(), json!(failure_reason));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

/// Log bootstrap completion
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `actor_user_id` - ID of the user who performed the bootstrap (typically "system")
/// * `ip_address` - Optional IP address of the client
/// * `owner_username` - Username of the created owner account
/// * `system_admin_count` - Number of System Admin accounts created
/// * `role_admin_count` - Number of Role Admin accounts created
pub async fn log_bootstrap_completed(
    store: &AuditStore,
    actor_user_id: String,
    ip_address: Option<String>,
    owner_username: String,
    system_admin_count: u32,
    role_admin_count: u32,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::BootstrapCompleted);
    event.user_id = Some(actor_user_id);
    event.ip_address = ip_address;
    event.data.insert("activation_method".to_string(), json!("cli"));
    event.data.insert("owner_username".to_string(), json!(owner_username));
    event.data.insert("system_admin_count".to_string(), json!(system_admin_count));
    event.data.insert("role_admin_count".to_string(), json!(role_admin_count));
    
    store.write_event(event).await
}

/// Log owner activation
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `actor_user_id` - ID of the user who performed the activation
/// * `ip_address` - Optional IP address of the client
/// * `activation_method` - Method used for activation ("cli" or "api")
pub async fn log_owner_activated(
    store: &AuditStore,
    actor_user_id: String,
    ip_address: Option<String>,
    activation_method: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::OwnerActivated);
    event.user_id = Some(actor_user_id);
    event.ip_address = ip_address;
    event.data.insert("activation_method".to_string(), json!(activation_method));
    
    store.write_event(event).await
}

/// Log owner deactivation
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `actor_user_id` - ID of the user who performed the deactivation
/// * `ip_address` - Optional IP address of the client
/// * `activation_method` - Method used for deactivation ("cli" or "api")
pub async fn log_owner_deactivated(
    store: &AuditStore,
    actor_user_id: String,
    ip_address: Option<String>,
    activation_method: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::OwnerDeactivated);
    event.user_id = Some(actor_user_id);
    event.ip_address = ip_address;
    event.data.insert("activation_method".to_string(), json!(activation_method));
    
    store.write_event(event).await
}

/// Log admin role assignment
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `actor_user_id` - ID of the user who performed the assignment
/// * `target_user_id` - ID of the user who received the role
/// * `role_type` - Type of role assigned ("system_admin" or "role_admin")
/// * `ip_address` - Optional IP address of the client
pub async fn log_admin_role_assigned(
    store: &AuditStore,
    actor_user_id: String,
    target_user_id: String,
    role_type: String,
    ip_address: Option<String>,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::AdminRoleAssigned);
    event.user_id = Some(actor_user_id);
    event.ip_address = ip_address;
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("role_type".to_string(), json!(role_type));
    
    store.write_event(event).await
}

/// Log admin role removal
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `actor_user_id` - ID of the user who performed the removal
/// * `target_user_id` - ID of the user who lost the role
/// * `role_type` - Type of role removed ("system_admin" or "role_admin")
/// * `ip_address` - Optional IP address of the client
pub async fn log_admin_role_removed(
    store: &AuditStore,
    actor_user_id: String,
    target_user_id: String,
    role_type: String,
    ip_address: Option<String>,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::AdminRoleRemoved);
    event.user_id = Some(actor_user_id);
    event.ip_address = ip_address;
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("role_type".to_string(), json!(role_type));
    
    store.write_event(event).await
}

/// Log CLI session start
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing CLI source and actor information
/// * `command_name` - Name of the CLI command being executed
/// * `args` - Command arguments (sanitized, no sensitive data)
pub async fn log_cli_session_start(
    store: &AuditStore,
    ctx: &RequestContext,
    command_name: &str,
    args: Vec<String>,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::CliSessionStart);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("command_name".to_string(), json!(command_name));
    event.data.insert("args".to_string(), json!(args));
    event.data.insert("source".to_string(), json!("CLI"));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log CLI session end
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing CLI source and actor information
/// * `command_name` - Name of the CLI command that completed
/// * `success` - Whether the command completed successfully
/// * `error_message` - Optional error message if the command failed
pub async fn log_cli_session_end(
    store: &AuditStore,
    ctx: &RequestContext,
    command_name: &str,
    success: bool,
    error_message: Option<String>,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::CliSessionEnd);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("command_name".to_string(), json!(command_name));
    event.data.insert("success".to_string(), json!(success));
    event.data.insert("source".to_string(), json!("CLI"));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    if let Some(error) = error_message {
        event.data.insert("error_message".to_string(), json!(error));
    }
    
    store.write_event(event).await
}

/// Log user creation (primitive operation)
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing source and actor information
/// * `user_id` - ID of the created user
/// * `username` - Username of the created user
pub async fn log_user_created(
    store: &AuditStore,
    ctx: &RequestContext,
    user_id: &str,
    username: &str,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::UserCreated);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("target_user_id".to_string(), json!(user_id));
    event.data.insert("username".to_string(), json!(username));
    event.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log privilege change (assignment/removal)
///
/// Logs the before and after state of all privilege flags.
/// This provides a complete audit trail of what changed.
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing source and actor information
/// * `target_user_id` - ID of the user whose privileges changed
/// * `old_is_owner` - Previous owner flag value
/// * `new_is_owner` - New owner flag value
/// * `old_is_system_admin` - Previous system admin flag value
/// * `new_is_system_admin` - New system admin flag value
/// * `old_is_role_admin` - Previous role admin flag value
/// * `new_is_role_admin` - New role admin flag value
pub async fn log_privileges_changed(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: &str,
    old_is_owner: bool,
    new_is_owner: bool,
    old_is_system_admin: bool,
    new_is_system_admin: bool,
    old_is_role_admin: bool,
    new_is_role_admin: bool,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::PrivilegesChanged);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("old_is_owner".to_string(), json!(old_is_owner));
    event.data.insert("new_is_owner".to_string(), json!(new_is_owner));
    event.data.insert("old_is_system_admin".to_string(), json!(old_is_system_admin));
    event.data.insert("new_is_system_admin".to_string(), json!(new_is_system_admin));
    event.data.insert("old_is_role_admin".to_string(), json!(old_is_role_admin));
    event.data.insert("new_is_role_admin".to_string(), json!(new_is_role_admin));
    event.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log operation rollback
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing source and actor information
/// * `operation_type` - Type of operation that was rolled back (e.g., "user_creation_with_privileges")
/// * `reason` - Reason for rollback (e.g., "privilege_assignment_failed")
/// * `affected_user_id` - User ID involved in the rolled-back operation (if applicable)
pub async fn log_operation_rolled_back(
    store: &AuditStore,
    ctx: &RequestContext,
    operation_type: &str,
    reason: &str,
    affected_user_id: Option<&str>,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::OperationRolledBack);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("operation_type".to_string(), json!(operation_type));
    event.data.insert("reason".to_string(), json!(reason));
    event.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    if let Some(user_id) = affected_user_id {
        event.data.insert("affected_user_id".to_string(), json!(user_id));
    }
    
    store.write_event(event).await
}

/// Log successful password change
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `target_user_id` - ID of the user whose password was changed (target of the action)
pub async fn log_password_changed(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::PasswordChanged);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

/// Log failed password change attempt
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `reason` - Reason for the password change failure (e.g., "incorrect_old_password", "validation_failed")
pub async fn log_password_change_failed(
    store: &AuditStore,
    ctx: &RequestContext,
    reason: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::PasswordChangeFailed);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("reason".to_string(), json!(reason));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
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
    pub async fn write(self) -> Result<(), InternalError> {
        // Validate that user_id is present
        if self.event.user_id.is_none() {
            return Err(InternalError::Audit(crate::errors::internal::AuditError::LogWriteFailed("Missing user_id".to_string())));
        }
        
        // Write the event to the database
        self.store.write_event(self.event).await
    }
}


/// Log transaction started
///
/// # Arguments
/// * `store` - The audit store
/// * `ctx` - Request context containing actor information
/// * `operation_type` - Type of operation the transaction is for (e.g., "password_change")
pub async fn log_transaction_started(
    store: &AuditStore,
    ctx: &RequestContext,
    operation_type: &str,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::TransactionStarted);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("operation_type".to_string(), json!(operation_type));
    event.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log transaction committed
///
/// # Arguments
/// * `store` - The audit store
/// * `ctx` - Request context containing actor information
/// * `operation_type` - Type of operation the transaction was for (e.g., "password_change")
pub async fn log_transaction_committed(
    store: &AuditStore,
    ctx: &RequestContext,
    operation_type: &str,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::TransactionCommitted);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("operation_type".to_string(), json!(operation_type));
    event.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log transaction rolled back
///
/// # Arguments
/// * `store` - The audit store
/// * `ctx` - Request context containing actor information
/// * `operation_type` - Type of operation the transaction was for (e.g., "password_change")
/// * `reason` - Reason for rollback (e.g., "commit_failed", "operation_error")
pub async fn log_transaction_rolled_back(
    store: &AuditStore,
    ctx: &RequestContext,
    operation_type: &str,
    reason: &str,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::TransactionRolledBack);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("operation_type".to_string(), json!(operation_type));
    event.data.insert("reason".to_string(), json!(reason));
    event.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log common password list download
///
/// Records when a common password list is downloaded from a URL and loaded into the database.
/// This provides an audit trail of password policy updates.
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information (typically CLI source)
/// * `url` - URL from which the password list was downloaded
/// * `password_count` - Number of passwords successfully loaded into the database
pub async fn log_common_password_list_downloaded(
    store: &AuditStore,
    ctx: &RequestContext,
    url: &str,
    password_count: usize,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::CommonPasswordListDownloaded);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.data.insert("url".to_string(), json!(url));
    event.data.insert("password_count".to_string(), json!(password_count));
    event.data.insert("source".to_string(), json!(format!("{:?}", ctx.source)));
    event.data.insert("request_id".to_string(), json!(ctx.request_id));
    
    store.write_event(event).await
}

/// Log password validation failure
///
/// Records when a password fails validation during password change or user creation.
/// Never logs the actual password, only the validation failure reason.
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `validation_reason` - Reason for validation failure (e.g., "too_short", "common_password", "compromised")
pub async fn log_password_validation_failed(
    store: &AuditStore,
    ctx: &RequestContext,
    validation_reason: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::PasswordChangeFailed);
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("reason".to_string(), json!("validation_failed"));
    event.data.insert("validation_reason".to_string(), json!(validation_reason));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

/// Log password change requirement cleared
///
/// Records when the password_change_required flag is cleared for a user,
/// typically after a successful password change.
///
/// # Arguments
/// * `store` - Reference to the AuditStore
/// * `ctx` - Request context containing actor information
/// * `target_user_id` - ID of the user whose password change requirement was cleared
pub async fn log_password_change_requirement_cleared(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: String,
) -> Result<(), InternalError> {
    let mut event = AuditEvent::new(EventType::Custom("password_change_requirement_cleared".to_string()));
    event.user_id = Some(ctx.actor_id.clone());
    event.ip_address = ctx.ip_address.clone();
    event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
    event.data.insert("target_user_id".to_string(), json!(target_user_id));
    event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));
    
    store.write_event(event).await
}

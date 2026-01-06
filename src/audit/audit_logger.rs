use crate::audit::AuditBuilder;
use crate::errors::InternalError;
use crate::stores::audit_store::AuditStore;
use crate::types::internal::audit::{AuditEvent, EventType};
use crate::types::internal::context::RequestContext;
use serde_json::json;
use std::sync::Arc;

/// Trait for errors that can be converted to audit log data
///
/// This trait allows each error type to define its own audit representation,
/// eliminating the need for a large match statement in the audit logger.
pub trait AuditableError {
    /// Convert this error to audit event type and data
    ///
    /// Returns a tuple of (EventType, data_map) where:
    /// - EventType: The type of audit event this error should generate
    /// - data_map: Error-specific data to include in the audit event
    ///
    /// The audit logger will add common fields (user_id, ip_address, request_id, etc.)
    /// automatically, so implementations should only include error-specific data.
    fn to_audit_data(&self) -> (EventType, serde_json::Map<String, serde_json::Value>);
}

/// Audit logging provider that handles all audit event creation and logging
///
/// Migrated from audit_logger module as part of service layer refactor.
/// Maintains actor/target separation pattern and provides all audit logging
/// functionality including AuditBuilder for custom events.
pub struct AuditLogger {
    pub audit_store: Arc<AuditStore>,
}

impl AuditLogger {
    /// Create a new AuditLoggerProvider
    ///
    /// # Arguments
    /// * `audit_store` - Reference to the AuditStore for writing events
    pub fn new(audit_store: Arc<AuditStore>) -> Self {
        Self { audit_store }
    }

    /// Create an AuditBuilder for custom audit events
    ///
    /// # Arguments
    /// * `event_type` - Event type (can be EventType enum or string for custom events)
    pub fn builder(&self, event_type: impl Into<EventType>) -> AuditBuilder {
        AuditBuilder::new(self.audit_store.clone(), event_type)
    }

    // Additional methods continue below...
    /// Log CLI session start
    ///
    /// # Arguments
    /// * `ctx` - Request context containing CLI source and actor information
    /// * `command_name` - Name of the CLI command being executed
    /// * `args` - Command arguments (sanitized, no sensitive data)
    pub async fn log_cli_session_start(
        &self,
        ctx: &RequestContext,
        command_name: &str,
        args: Vec<String>,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::CliSessionStart);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("command_name".to_string(), json!(command_name));
        event.data.insert("args".to_string(), json!(args));
        event.data.insert("source".to_string(), json!("CLI"));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        self.audit_store.write_event(event).await
    }

    /// Log CLI session end
    ///
    /// # Arguments
    /// * `ctx` - Request context containing CLI source and actor information
    /// * `command_name` - Name of the CLI command that completed
    /// * `success` - Whether the command completed successfully
    /// * `error_message` - Optional error message if the command failed
    pub async fn log_cli_session_end(
        &self,
        ctx: &RequestContext,
        command_name: &str,
        success: bool,
        error_message: Option<String>,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::CliSessionEnd);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("command_name".to_string(), json!(command_name));
        event.data.insert("success".to_string(), json!(success));
        event.data.insert("source".to_string(), json!("CLI"));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        if let Some(error) = error_message {
            event.data.insert("error_message".to_string(), json!(error));
        }

        self.audit_store.write_event(event).await
    }

    /// Log user creation (primitive operation)
    ///
    /// # Arguments
    /// * `ctx` - Request context containing source and actor information
    /// * `user_id` - ID of the created user
    /// * `username` - Username of the created user
    pub async fn log_user_created(
        &self,
        ctx: &RequestContext,
        user_id: &str,
        username: &str,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::UserCreated);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("target_user_id".to_string(), json!(user_id));
        event.data.insert("username".to_string(), json!(username));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        self.audit_store.write_event(event).await
    }

    /// Log privilege change (assignment/removal)
    ///
    /// Logs the before and after state of all privilege flags.
    /// This provides a complete audit trail of what changed.
    ///
    /// # Arguments
    /// * `ctx` - Request context containing source and actor information
    /// * `target_user_id` - ID of the user whose privileges changed
    /// * `old_is_owner` - Previous owner flag value
    /// * `new_is_owner` - New owner flag value
    /// * `old_is_system_admin` - Previous system admin flag value
    /// * `new_is_system_admin` - New system admin flag value
    /// * `old_is_role_admin` - Previous role admin flag value
    /// * `new_is_role_admin` - New role admin flag value
    pub async fn log_privileges_changed(
        &self,
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
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("target_user_id".to_string(), json!(target_user_id));
        event
            .data
            .insert("old_is_owner".to_string(), json!(old_is_owner));
        event
            .data
            .insert("new_is_owner".to_string(), json!(new_is_owner));
        event.data.insert(
            "old_is_system_admin".to_string(),
            json!(old_is_system_admin),
        );
        event.data.insert(
            "new_is_system_admin".to_string(),
            json!(new_is_system_admin),
        );
        event
            .data
            .insert("old_is_role_admin".to_string(), json!(old_is_role_admin));
        event
            .data
            .insert("new_is_role_admin".to_string(), json!(new_is_role_admin));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        self.audit_store.write_event(event).await
    }

    /// Log operation rollback
    ///
    /// # Arguments
    /// * `ctx` - Request context containing source and actor information
    /// * `operation_type` - Type of operation that was rolled back (e.g., "user_creation_with_privileges")
    /// * `reason` - Reason for rollback (e.g., "privilege_assignment_failed")
    /// * `affected_user_id` - User ID involved in the rolled-back operation (if applicable)
    pub async fn log_operation_rolled_back(
        &self,
        ctx: &RequestContext,
        operation_type: &str,
        reason: &str,
        affected_user_id: Option<&str>,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::OperationRolledBack);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("operation_type".to_string(), json!(operation_type));
        event.data.insert("reason".to_string(), json!(reason));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        if let Some(user_id) = affected_user_id {
            event
                .data
                .insert("affected_user_id".to_string(), json!(user_id));
        }

        self.audit_store.write_event(event).await
    }

    /// Log successful password change
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `target_user_id` - ID of the user whose password was changed (target of the action)
    pub async fn log_password_changed(
        &self,
        ctx: &RequestContext,
        target_user_id: String,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::PasswordChanged);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address.map(|ip| ip.to_string()).unwrap_or("unknown".to_owned());
            
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("target_user_id".to_string(), json!(target_user_id));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id.clone()));

        self.audit_store.write_event(event).await
    }

    /// Log failed password change attempt
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `reason` - Reason for the password change failure (e.g., "incorrect_old_password", "validation_failed")
    pub async fn log_password_change_failed(
        &self,
        ctx: &RequestContext,
        reason: String,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::PasswordChangeFailed);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event.data.insert("reason".to_string(), json!(reason));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id.clone()));

        self.audit_store.write_event(event).await
    }

    /// Log transaction started
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `operation_type` - Type of operation the transaction is for (e.g., "password_change")
    pub async fn log_transaction_started(
        &self,
        ctx: &RequestContext,
        operation_type: &str,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::TransactionStarted);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("operation_type".to_string(), json!(operation_type));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        self.audit_store.write_event(event).await
    }

    /// Log transaction committed
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `operation_type` - Type of operation the transaction was for (e.g., "password_change")
    pub async fn log_transaction_committed(
        &self,
        ctx: &RequestContext,
        operation_type: &str,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::TransactionCommitted);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("operation_type".to_string(), json!(operation_type));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        self.audit_store.write_event(event).await
    }

    /// Log transaction rolled back
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `operation_type` - Type of operation the transaction was for (e.g., "password_change")
    /// * `reason` - Reason for rollback (e.g., "commit_failed", "operation_error")
    pub async fn log_transaction_rolled_back(
        &self,
        ctx: &RequestContext,
        operation_type: &str,
        reason: &str,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::TransactionRolledBack);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("operation_type".to_string(), json!(operation_type));
        event.data.insert("reason".to_string(), json!(reason));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        self.audit_store.write_event(event).await
    }

    /// Log common password list download
    ///
    /// Records when a common password list is downloaded from a URL and loaded into the database.
    /// This provides an audit trail of password policy updates.
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information (typically CLI source)
    /// * `url` - URL from which the password list was downloaded
    /// * `password_count` - Number of passwords successfully loaded into the database
    pub async fn log_common_password_list_downloaded(
        &self,
        ctx: &RequestContext,
        url: &str,
        password_count: usize,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::CommonPasswordListDownloaded);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event.data.insert("url".to_string(), json!(url));
        event
            .data
            .insert("password_count".to_string(), json!(password_count));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id));

        self.audit_store.write_event(event).await
    }

    /// Log an error event based on the InternalError type
    ///
    /// Uses the AuditableError trait to automatically create appropriate audit events
    /// based on the error type and context. This eliminates the need for specific
    /// error logging methods and allows each error type to define its own audit representation.
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `error` - The InternalError that occurred (must implement AuditableError)
    pub async fn log_error(
        &self,
        ctx: &RequestContext,
        error: &impl AuditableError,
    ) -> Result<(), InternalError> {
        // Get error-specific audit data from the trait implementation
        let (event_type, error_data) = error.to_audit_data();

        // Create audit event with the specified type
        let mut event = AuditEvent::new(event_type);

        // Add common fields from request context
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());

        // Add standard context fields
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id.clone()));
        event
            .data
            .insert("source".to_string(), json!(format!("{:?}", ctx.source)));

        // Add error-specific data from the trait implementation
        event.data.extend(error_data);

        self.audit_store.write_event(event).await
    }

    /// Log password validation failure
    ///
    /// Records when a password fails validation during password change or user creation.
    /// Never logs the actual password, only the validation failure reason.
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `validation_reason` - Reason for validation failure (e.g., "too_short", "common_password", "compromised")
    pub async fn log_password_validation_failed(
        &self,
        ctx: &RequestContext,
        validation_reason: String,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::PasswordChangeFailed);
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("reason".to_string(), json!("validation_failed"));
        event
            .data
            .insert("validation_reason".to_string(), json!(validation_reason));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id.clone()));

        self.audit_store.write_event(event).await
    }

    /// Log password change requirement cleared
    ///
    /// Records when the password_change_required flag is cleared for a user,
    /// typically after a successful password change.
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `target_user_id` - ID of the user whose password change requirement was cleared
    pub async fn log_password_change_requirement_cleared(
        &self,
        ctx: &RequestContext,
        target_user_id: String,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::Custom(
            "password_change_requirement_cleared".to_string(),
        ));
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("target_user_id".to_string(), json!(target_user_id));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id.clone()));

        self.audit_store.write_event(event).await
    }
}

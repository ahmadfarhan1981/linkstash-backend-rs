use std::collections::HashMap;
use std::fmt;

/// Event types for audit logging
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    LoginSuccess,
    LoginFailure,
    JwtIssued,
    JwtValidationFailure,
    JwtTampered,
    RefreshTokenIssued,
    RefreshTokenRevoked,
    RefreshTokenValidationFailure,
    // Bootstrap and owner management events
    BootstrapCompleted,
    OwnerActivated,
    OwnerDeactivated,
    AdminRoleAssigned,
    AdminRoleRemoved,
    // CLI session events
    CliSessionStart,
    CliSessionEnd,
    // User management events
    UserCreated,
    PrivilegesChanged,
    OperationRolledBack,
    // Password management events
    PasswordChanged,
    PasswordChangeFailed,
    CommonPasswordListDownloaded,
    // Transaction events
    TransactionStarted,
    TransactionCommitted,
    TransactionRolledBack,
    Custom(String),
}

impl EventType {
    /// Convert EventType to string representation for database storage
    pub fn as_str(&self) -> &str {
        match self {
            Self::LoginSuccess => "login_success",
            Self::LoginFailure => "login_failure",
            Self::JwtIssued => "jwt_issued",
            Self::JwtValidationFailure => "jwt_validation_failure",
            Self::JwtTampered => "jwt_tampered",
            Self::RefreshTokenIssued => "refresh_token_issued",
            Self::RefreshTokenRevoked => "refresh_token_revoked",
            Self::RefreshTokenValidationFailure => "refresh_token_validation_failure",
            Self::BootstrapCompleted => "bootstrap_completed",
            Self::OwnerActivated => "owner_activated",
            Self::OwnerDeactivated => "owner_deactivated",
            Self::AdminRoleAssigned => "admin_role_assigned",
            Self::AdminRoleRemoved => "admin_role_removed",
            Self::CliSessionStart => "cli_session_start",
            Self::CliSessionEnd => "cli_session_end",
            Self::UserCreated => "user_created",
            Self::PrivilegesChanged => "privileges_changed",
            Self::OperationRolledBack => "operation_rolled_back",
            Self::PasswordChanged => "password_changed",
            Self::PasswordChangeFailed => "password_change_failed",
            Self::CommonPasswordListDownloaded => "common_password_list_downloaded",
            Self::TransactionStarted => "transaction_started",
            Self::TransactionCommitted => "transaction_committed",
            Self::TransactionRolledBack => "transaction_rolled_back",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<T: Into<String>> From<T> for EventType {
    fn from(s: T) -> Self {
        EventType::Custom(s.into())
    }
}

/// Audit event structure for building and storing audit logs
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: EventType,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub jwt_id: Option<String>,
    pub data: HashMap<String, serde_json::Value>,
}

impl AuditEvent {
    /// Create a new audit event with the specified event type
    pub fn new(event_type: EventType) -> Self {
        Self {
            event_type,
            user_id: None,
            ip_address: None,
            jwt_id: None,
            data: HashMap::new(),
        }
    }
}

/// Errors that can occur during audit logging operations
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Missing user_id: user_id is required for all audit events")]
    MissingUserId,

    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

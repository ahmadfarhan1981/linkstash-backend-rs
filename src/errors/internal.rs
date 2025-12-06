use thiserror::Error;

/// Internal error type for store and service operations
/// 
/// This is a hybrid error type that separates:
/// - Infrastructure errors (Database, Parse, Transaction, Crypto) - shared by all stores
/// - Domain errors (Credential, SystemConfig, Audit) - specific to each store
/// 
/// This error type is NOT exposed via API. API endpoints must explicitly
/// convert these to AuthError or AdminError.
#[derive(Error, Debug)]
pub enum InternalError {
    // ============================================================
    // Infrastructure Errors (shared by all stores)
    // ============================================================
    
    /// Database query or operation failed
    #[error("Database error: {operation} failed: {source}")]
    Database {
        operation: String,
        #[source]
        source: sea_orm::DbErr,
    },
    
    /// Database transaction failed
    #[error("Transaction error: {operation} failed: {source}")]
    Transaction {
        operation: String,
        #[source]
        source: sea_orm::DbErr,
    },
    
    /// Failed to parse a value (UUID, timestamp, JSON, etc.)
    #[error("Parse error: failed to parse {value_type}: {message}")]
    Parse {
        value_type: String,
        message: String,
    },
    
    /// Cryptographic operation failed (hashing, verification, etc.)
    #[error("Crypto error: {operation} failed: {message}")]
    Crypto {
        operation: String,
        message: String,
    },
    
    // ============================================================
    // Domain-Specific Errors (one per store)
    // ============================================================
    
    /// Credential store errors (authentication, user management, tokens)
    #[error(transparent)]
    Credential(#[from] CredentialError),
    
    /// System config store errors (owner management, system settings)
    #[error(transparent)]
    SystemConfig(#[from] SystemConfigError),
    
    /// Audit store errors (audit logging failures)
    #[error(transparent)]
    Audit(#[from] AuditError),
}

impl InternalError {
    /// Create a database error with context
    pub fn database(operation: impl Into<String>, source: sea_orm::DbErr) -> Self {
        Self::Database {
            operation: operation.into(),
            source,
        }
    }
    
    /// Create a transaction error with context
    pub fn transaction(operation: impl Into<String>, source: sea_orm::DbErr) -> Self {
        Self::Transaction {
            operation: operation.into(),
            source,
        }
    }
    
    /// Create a parse error with context
    pub fn parse(value_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Parse {
            value_type: value_type.into(),
            message: message.into(),
        }
    }
    
    /// Create a crypto error with context
    pub fn crypto(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            operation: operation.into(),
            message: message.into(),
        }
    }
}

/// Credential store specific errors
#[derive(Error, Debug)]
pub enum CredentialError {
    /// Invalid username or password
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    /// Current password is incorrect (for password change)
    #[error("Current password is incorrect")]
    IncorrectPassword,
    
    /// Username already exists
    #[error("User already exists: {0}")]
    DuplicateUsername(String),
    
    /// User not found
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    /// Password hashing failed
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),
    
    /// Invalid or malformed token
    #[error("Invalid token: {token_type} - {reason}")]
    InvalidToken {
        token_type: String,
        reason: String,
    },
    
    /// Token has expired
    #[error("Expired token: {0}")]
    ExpiredToken(String),
}

impl CredentialError {
    /// Create an invalid token error
    pub fn invalid_token(token_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidToken {
            token_type: token_type.into(),
            reason: reason.into(),
        }
    }
}

/// System config store specific errors
#[derive(Error, Debug)]
pub enum SystemConfigError {
    /// System config not found
    #[error("System config not found")]
    ConfigNotFound,
    
    /// Owner account already exists
    #[error("Owner already exists")]
    OwnerAlreadyExists,
    
    /// Owner account not found
    #[error("Owner not found")]
    OwnerNotFound,
}

/// Audit store specific errors
#[derive(Error, Debug)]
pub enum AuditError {
    /// Failed to write audit log entry
    #[error("Failed to write audit log: {0}")]
    LogWriteFailed(String),
}

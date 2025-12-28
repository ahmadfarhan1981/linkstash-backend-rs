use thiserror::Error;

pub mod credential;
pub mod system_config;
pub mod audit;
pub mod database;
pub mod jwt_validation;

pub use credential::CredentialError;
pub use system_config::SystemConfigError;
pub use audit::AuditError;
pub use database::DatabaseError;
pub use jwt_validation::JWTValidationError;

/// Internal error type for store and service operations
/// 
/// Hybrid design separates infrastructure errors (shared) from domain errors (store-specific).
/// Not exposed via API - endpoints must convert to AuthError or AdminError.
#[derive(Error, Debug)]
pub enum InternalError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    
    #[error("Parse error: failed to parse {value_type}: {message}")]
    Parse {
        value_type: String,
        message: String,
    },
    
    #[error("Crypto error: {operation} failed: {message}")]
    Crypto {
        operation: String,
        message: String,
    },
    
    #[error(transparent)]
    Credential(#[from] CredentialError),
    
    #[error(transparent)]
    SystemConfig(#[from] SystemConfigError),
    
    #[error(transparent)]
    Audit(#[from] AuditError),
    
    #[error(transparent)]
    JWTValidation(#[from] JWTValidationError),
}
impl InternalError {
    pub fn database( operation: &str, source: sea_orm::DbErr)->InternalError{
        InternalError::Database(DatabaseError::Operation { operation: operation.to_string(), source })
    }
}
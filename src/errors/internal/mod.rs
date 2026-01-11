use thiserror::Error;

pub mod audit;
pub mod credential;
pub mod database;
pub mod jwt_validation;
pub mod login;
pub mod system_config;
pub mod crypto;

use crate::{config::ApplicationError, errors::internal::{crypto::CryptoError, jwt_validation::JwtValidationError, login::LoginError}};
pub use audit::AuditError;
pub use credential::CredentialError;
pub use database::DatabaseError;
pub use system_config::SystemConfigError;

/// Internal error type for store and service operations
///
/// Hybrid design separates infrastructure errors (shared) from domain errors (store-specific).
/// Not exposed via API - endpoints must convert to AuthError or AdminError.
#[derive(Error, Debug)]
pub enum InternalError {
    #[error(transparent)]
    Login(LoginError),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error("Parse error: failed to parse {value_type}: {message}")]
    Parse { value_type: String, message: String },

    // #[error("Crypto error: {operation} failed: {message}")]
    // Crypto { operation: String, message: String },
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Credential(#[from] CredentialError),

    #[error(transparent)]
    SystemConfig(#[from] SystemConfigError),

    #[error(transparent)]
    Audit(#[from] AuditError),

    #[error(transparent)]
    JWTValidation(#[from] JwtValidationError),
}
impl InternalError {
    pub fn database(operation: &str, source: sea_orm::DbErr) -> InternalError {
        InternalError::Database(DatabaseError::Operation {
            operation: operation.to_string(),
            source,
        })
    }
}

impl From<InternalError> for ApplicationError {
    fn from(internal_error: InternalError) -> Self {
        match internal_error {
            _ => ApplicationError::UnknownServerError {
                message: "Placeholder error".to_owned(),
            },
        }
    }
}

// Providers layer - Work performers and business logic
//
// Providers contain business logic and provide composable operations that
// coordinators can orchestrate. They perform actual work like calculations,
// validations, and database operations.

// Provider modules
pub mod token_provider;
pub mod password_validator_provider;
pub mod crypto_provider;
mod authentication_provider;

// Re-export providers for clean imports
pub use token_provider::TokenProvider;
pub use password_validator_provider::PasswordValidatorProvider;
pub use crate::audit::audit_logger_provider::AuditLogger;
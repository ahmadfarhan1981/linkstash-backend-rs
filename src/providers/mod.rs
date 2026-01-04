// Providers layer - Work performers and business logic
//
// Providers contain business logic and provide composable operations that
// coordinators can orchestrate. They perform actual work like calculations,
// validations, and database operations.

// Provider modules
pub mod token_provider;
// pub mod password_validator_provider;
pub mod authentication_provider;
pub mod crypto_provider;
// pub mod users;
pub mod context_provider;

// Re-export providers for clean imports
pub use crypto_provider::CryptoProvider;
pub use token_provider::TokenProvider;
pub use context_provider::ContextProvider;
// pub use password_validator_provider::PasswordValidatorProvider;

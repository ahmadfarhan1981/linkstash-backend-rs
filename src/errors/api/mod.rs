// API-facing error types
pub mod admin;
pub mod auth;

// Re-exports for convenience
pub use admin::AdminError;
pub use auth::AuthError;

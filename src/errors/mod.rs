// Errors layer - Error type definitions
pub mod api;
pub mod internal;

// Re-exports for convenience
pub use api::{AuthError, AdminError};
pub use internal::InternalError;



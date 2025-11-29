// API-facing error types
pub mod auth;
pub mod admin;

// Re-exports for convenience
pub use auth::AuthError;
pub use admin::AdminError;

#[cfg(test)]
mod auth_test;

#[cfg(test)]
mod admin_test;

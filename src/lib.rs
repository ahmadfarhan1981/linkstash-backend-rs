// Library exports for integration tests and external use

pub mod config;
pub mod services;
pub mod types;
pub mod errors;
pub mod stores;
pub mod api;
pub mod cli;

// Test utilities (available for unit and integration tests)
// Note: Compiled in all builds but only used during testing
pub mod test;

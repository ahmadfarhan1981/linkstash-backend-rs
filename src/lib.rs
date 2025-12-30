// Library exports for integration tests and external use

pub mod app_data;
pub mod config;
pub mod coordinators;
pub mod providers;
pub mod types;
pub mod errors;
pub mod stores;
pub mod api;
// pub mod cli;
pub mod audit;
pub use app_data::AppData;

// Test utilities (available for unit and integration tests)
// Note: Compiled in all builds but only used during testing
#[cfg(any(test, feature = "test-utils"))]
pub mod test;

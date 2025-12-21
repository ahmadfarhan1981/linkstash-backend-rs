mod secret_config;
mod secret_manager;
mod logging;
pub mod database;

// New modular settings management
mod errors;
mod config_spec;
mod bootstrap_settings; 
mod application_settings;
mod settings_registry;
mod settings_manager;
mod env_provider;

pub use secret_config::{SecretConfig, SecretType};
pub use secret_manager::SecretManager;
pub use env_provider::{EnvironmentProvider, SystemEnvironment};
pub use logging::init_logging;
pub use database::{ migrate_auth_database, migrate_audit_database};

// Export new modular settings management
pub use errors::{ApplicationError, SettingsError};
pub use config_spec::{ConfigSpec, ConfigSource, ConfigValue, ConfigValueSource};
pub use bootstrap_settings::BootstrapSettings;

pub use settings_registry::SettingsRegistry;
pub use settings_manager::SettingsManager;
pub use application_settings::ApplicationSettings;


// Export test utilities only in test builds
#[cfg(test)]
pub use env_provider::MockEnvironment;

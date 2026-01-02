pub mod database;
mod logging;
mod secret_config;
mod secret_manager;

// New modular settings management
mod application_settings;
mod bootstrap_settings;
mod config_spec;
mod env_provider;
mod errors;
mod settings_manager;
mod settings_registry;

pub use database::{migrate_audit_database, migrate_auth_database};
pub use env_provider::{EnvironmentProvider, SystemEnvironment};
pub use logging::init_logging;
pub use secret_config::{SecretConfig, SecretType};
pub use secret_manager::SecretManager;

// Export new modular settings management
pub use bootstrap_settings::BootstrapSettings;
pub use config_spec::{ConfigSource, ConfigSpec, ConfigValue, ConfigValueSource};
pub use errors::{ApplicationError, SettingsError};

pub use application_settings::ApplicationSettings;
pub use settings_manager::SettingsManager;
pub use settings_registry::SettingsRegistry;

// Export test utilities only in test builds
#[cfg(test)]
pub use env_provider::MockEnvironment;

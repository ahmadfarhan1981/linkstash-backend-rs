mod secret_config;
mod secret_manager;
mod logging;
mod database;

// New modular settings management
mod errors;
mod config_spec;
mod bootstrap_settings;
mod application_settings;
mod settings_manager;

pub use secret_config::{SecretConfig, SecretType};
pub use secret_manager::SecretManager;
pub use errors::{BootstrapError, ApplicationError, SettingsError};
pub use config_spec::{ConfigSource, ConfigSpec, ConfigValue, ConfigValueSource};
pub use bootstrap_settings::BootstrapSettings;
pub use application_settings::ApplicationSettings;
pub use settings_manager::SettingsManager;
pub use logging::init_logging;
pub use database::{init_database, init_audit_database, migrate_auth_database, migrate_audit_database};

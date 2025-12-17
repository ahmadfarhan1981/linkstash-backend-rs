use std::sync::Arc;
use std::time::Duration;

use crate::config::{
    bootstrap_settings::BootstrapSettings,
    settings_registry::SettingsRegistry,
    secret_manager::SecretManager,
    errors::SettingsError,
};

/// Main settings manager with lazy initialization
/// 
/// Coordinates between bootstrap settings, secrets, and application settings.
/// Supports both full initialization (for server startup) and bootstrap-only
/// initialization (for CLI operations).
pub struct SettingsManager {
    pub bootstrap_settings: BootstrapSettings,
    pub secrets: Option<SecretManager>,
    pub settings: Option<Arc<SettingsRegistry>>,
}

impl SettingsManager {
    /// Full initialization for server startup
    /// 
    /// Loads bootstrap settings, secrets, and application settings.
    /// All components are initialized and ready for use.
    pub async fn init_full() -> Result<Self, SettingsError> {
        // Step 1: Load bootstrap settings (always required)
        let bootstrap_settings = BootstrapSettings::from_env()
            .map_err(SettingsError::Application)?;
        
        // Step 2: Load secrets
        let secrets = Some(SecretManager::init()
            .map_err(SettingsError::Secret)?);
        
        // Step 3: Load application settings
        let settings = Some(SettingsRegistry::init(&bootstrap_settings).await
            .map_err(SettingsError::Application)?);
        
        Ok(Self {
            bootstrap_settings,
            secrets,
            settings,
        })
    }
    
    /// Bootstrap-only initialization for CLI operations
    /// 
    /// Only loads bootstrap settings. Secrets and application settings
    /// can be loaded later using lazy initialization methods.
    pub fn init_bootstrap_only() -> Result<Self, SettingsError> {
        let bootstrap_settings = BootstrapSettings::from_env()
            .map_err(SettingsError::Application)?;
        
        Ok(Self {
            bootstrap_settings,
            secrets: None,
            settings: None,
        })
    }
    
    /// Lazy initialization for secrets
    /// 
    /// Initializes secrets if not already loaded. Safe to call multiple times.
    pub async fn ensure_secrets(&mut self) -> Result<&SecretManager, SettingsError> {
        if self.secrets.is_none() {
            self.secrets = Some(SecretManager::init()
                .map_err(SettingsError::Secret)?);
        }
        Ok(self.secrets.as_ref().unwrap())
    }
    
    /// Lazy initialization for application settings
    /// 
    /// Initializes application settings if not already loaded. Safe to call multiple times.
    pub async fn ensure_application_settings(&mut self) -> Result<&SettingsRegistry, SettingsError> {
        if self.settings.is_none() {
            self.settings = Some(SettingsRegistry::init(&self.bootstrap_settings).await
                .map_err(SettingsError::Application)?);
        }
        Ok(self.settings.as_ref().unwrap())
    }
    
    // Convenience methods that delegate to appropriate layer
    
    /// Get server host from bootstrap settings
    pub fn server_host(&self) -> &str {
        self.bootstrap_settings.server_host()
    }
    
    /// Get server port from bootstrap settings
    pub fn server_port(&self) -> u16 {
        self.bootstrap_settings.server_port()
    }
    
    /// Get server address (host:port) from bootstrap settings
    pub fn server_address(&self) -> String {
        self.bootstrap_settings.server_address()
    }
    
    
    // Configuration management methods
    
    /// List all configuration settings with their sources and mutability
    /// 
    /// Returns settings from all initialized layers. If application settings
    /// are not initialized, only bootstrap settings are included.
    pub async fn list_all_settings(&self) -> Vec<(String, crate::config::config_spec::ConfigValue)> {
        let mut settings = Vec::new();
        
        // Add bootstrap settings (always available)
        settings.push(("DATABASE_URL".to_string(), crate::config::config_spec::ConfigValue {
            value: self.bootstrap_settings.database_url().to_string(),
            source: crate::config::config_spec::ConfigValueSource::EnvironmentVariable { 
                name: "DATABASE_URL".to_string() 
            },
            is_mutable: false,
        }));
        
        settings.push(("HOST".to_string(), crate::config::config_spec::ConfigValue {
            value: self.bootstrap_settings.server_host().to_string(),
            source: crate::config::config_spec::ConfigValueSource::EnvironmentVariable { 
                name: "HOST".to_string() 
            },
            is_mutable: false,
        }));
        
        settings.push(("PORT".to_string(), crate::config::config_spec::ConfigValue {
            value: self.bootstrap_settings.server_port().to_string(),
            source: crate::config::config_spec::ConfigValueSource::EnvironmentVariable { 
                name: "PORT".to_string() 
            },
            is_mutable: false,
        }));
        
        // Add application settings if initialized
        if let Some(app_settings) = &self.settings {
            let app_settings_list = app_settings.list_all_settings().await;
            settings.extend(app_settings_list);
        }
        
        settings
    }
    
    /// Get configuration information for a specific setting
    /// 
    /// Returns the current value, source, and mutability status for the specified setting.
    /// Searches across all initialized layers.
    /// 
    /// # Arguments
    /// * `setting_name` - Name of the setting to query
    /// 
    /// # Returns
    /// * `Ok(ConfigValue)` - Setting information with current value and source
    /// * `Err(SettingsError)` - Setting not found or layer not initialized
    pub async fn get_setting_info(&self, setting_name: &str) -> Result<crate::config::config_spec::ConfigValue, SettingsError> {
        // Check bootstrap settings first
        match setting_name {
            "DATABASE_URL" => Ok(crate::config::config_spec::ConfigValue {
                value: self.bootstrap_settings.database_url().to_string(),
                source: crate::config::config_spec::ConfigValueSource::EnvironmentVariable { 
                    name: "DATABASE_URL".to_string() 
                },
                is_mutable: false,
            }),
            "HOST" => Ok(crate::config::config_spec::ConfigValue {
                value: self.bootstrap_settings.server_host().to_string(),
                source: crate::config::config_spec::ConfigValueSource::EnvironmentVariable { 
                    name: "HOST".to_string() 
                },
                is_mutable: false,
            }),
            "PORT" => Ok(crate::config::config_spec::ConfigValue {
                value: self.bootstrap_settings.server_port().to_string(),
                source: crate::config::config_spec::ConfigValueSource::EnvironmentVariable { 
                    name: "PORT".to_string() 
                },
                is_mutable: false,
            }),
            _ => {
                // Check application settings if initialized
                if let Some(app_settings) = &self.settings {
                    app_settings.get_setting_info(setting_name).await
                        .map_err(SettingsError::Application)
                } else {
                    Err(SettingsError::Application(
                        crate::config::errors::ApplicationError::UnknownSetting { 
                            name: setting_name.to_string() 
                        }
                    ))
                }
            }
        }
    }
    
    /// Check if a setting can be updated at runtime
    /// 
    /// Returns true if the setting exists and is not overridden by an environment variable.
    /// Bootstrap settings are never mutable at runtime.
    /// 
    /// # Arguments
    /// * `setting_name` - Name of the setting to check
    pub async fn can_update_setting(&self, setting_name: &str) -> bool {
        match self.get_setting_info(setting_name).await {
            Ok(config_value) => config_value.is_mutable,
            Err(_) => false,
        }
    }
    
    /// Update a configuration setting at runtime
    /// 
    /// Updates both persistent storage and in-memory cache atomically.
    /// Only allows updates to settings that are not overridden by environment variables.
    /// Bootstrap settings cannot be updated at runtime.
    /// 
    /// # Arguments
    /// * `setting_name` - Name of the setting to update
    /// * `value` - New value for the setting
    /// 
    /// # Returns
    /// * `Ok(())` - Setting updated successfully
    /// * `Err(SettingsError)` - Setting not found, read-only, validation failed, or layer not initialized
    pub async fn update_setting(&mut self, setting_name: &str, value: String) -> Result<(), SettingsError> {
        // Bootstrap settings are never mutable
        match setting_name {
            "DATABASE_URL" | "HOST" | "PORT" => {
                return Err(SettingsError::Application(
                    crate::config::errors::ApplicationError::ReadOnlyFromEnvironment { 
                        setting_name: setting_name.to_string() 
                    }
                ));
            }
            _ => {}
        }
        
        // Delegate to application settings if initialized
        if let Some(app_settings) = &self.settings {
            app_settings.update_setting(setting_name, value).await
                .map_err(SettingsError::Application)
        } else {
            Err(SettingsError::Application(
                crate::config::errors::ApplicationError::DatabaseConnection(
                    "Application settings not initialized. Call ensure_application_settings() first.".to_string()
                )
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MockEnvironment, ApplicationError};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_test_env(vars: HashMap<String, String>) -> Arc<MockEnvironment> {
        Arc::new(MockEnvironment::new(vars))
    }

    #[test]
    fn test_settings_manager_bootstrap_only_initialization() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "8080".to_string()),
        ]);
        let _env_provider = create_test_env(env_vars);

        // Set environment variables for the test
        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
            std::env::set_var("HOST", "127.0.0.1");
            std::env::set_var("PORT", "8080");
        }

        let result = SettingsManager::init_bootstrap_only();
        
        // Clean up environment variables
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        assert!(result.is_ok());
        let settings_manager = result.unwrap();
        
        assert_eq!(settings_manager.server_host(), "127.0.0.1");
        assert_eq!(settings_manager.server_port(), 8080);
        assert_eq!(settings_manager.server_address(), "127.0.0.1:8080");
        
        // Secrets and application settings should not be initialized
        assert!(settings_manager.secrets.is_none());
        assert!(settings_manager.settings.is_none());
    }

    #[test]
    fn test_settings_manager_bootstrap_only_with_defaults() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        // Set minimal environment variables
        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
        }

        let result = SettingsManager::init_bootstrap_only();
        
        // Clean up environment variables
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        assert!(result.is_ok());
        let settings_manager = result.unwrap();
        
        // Should use default values for HOST and PORT
        assert_eq!(settings_manager.server_host(), "0.0.0.0");
        assert_eq!(settings_manager.server_port(), 3000);
        assert_eq!(settings_manager.server_address(), "0.0.0.0:3000");
    }

    #[test]
    fn test_settings_manager_bootstrap_only_missing_database_url() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        // Don't set DATABASE_URL to test default behavior
        let result = SettingsManager::init_bootstrap_only();
        
        // Should succeed with default DATABASE_URL
        assert!(result.is_ok());
        let settings_manager = result.unwrap();
        assert_eq!(settings_manager.bootstrap_settings.database_url(), "sqlite://auth.db?mode=rwc");
    }

    #[test]
    fn test_settings_manager_jwt_secret_without_secrets_initialized() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
        }

        let settings_manager = SettingsManager::init_bootstrap_only().unwrap();
        
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        let result = settings_manager.jwt_secret();
        assert!(result.is_err());
        
        match result.unwrap_err() {
            SettingsError::Application(ApplicationError::DatabaseConnection(msg)) => {
                assert!(msg.contains("Secrets not initialized"));
            }
            _ => panic!("Expected Application error about secrets not initialized"),
        }
    }

    #[test]
    fn test_settings_manager_jwt_expiration_without_application_settings() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
        }

        let settings_manager = SettingsManager::init_bootstrap_only().unwrap();
        
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        let result = settings_manager.jwt_expiration();
        assert!(result.is_err());
        
        match result.unwrap_err() {
            SettingsError::Application(ApplicationError::DatabaseConnection(msg)) => {
                assert!(msg.contains("Application settings not initialized"));
            }
            _ => panic!("Expected Application error about application settings not initialized"),
        }
    }

    #[tokio::test]
    async fn test_settings_manager_get_setting_info_bootstrap_settings() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
            std::env::set_var("HOST", "127.0.0.1");
            std::env::set_var("PORT", "8080");
        }

        let settings_manager = SettingsManager::init_bootstrap_only().unwrap();
        
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        // Test getting bootstrap setting info
        let database_url_info = settings_manager.get_setting_info("DATABASE_URL").await.unwrap();
        assert_eq!(database_url_info.value, "sqlite://test.db");
        assert!(!database_url_info.is_mutable);
        
        let host_info = settings_manager.get_setting_info("HOST").await.unwrap();
        assert_eq!(host_info.value, "127.0.0.1");
        assert!(!host_info.is_mutable);
        
        let port_info = settings_manager.get_setting_info("PORT").await.unwrap();
        assert_eq!(port_info.value, "8080");
        assert!(!port_info.is_mutable);
    }

    #[tokio::test]
    async fn test_settings_manager_get_setting_info_unknown_setting() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
        }

        let settings_manager = SettingsManager::init_bootstrap_only().unwrap();
        
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        let result = settings_manager.get_setting_info("UNKNOWN_SETTING").await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            SettingsError::Application(ApplicationError::UnknownSetting { name }) => {
                assert_eq!(name, "UNKNOWN_SETTING");
            }
            _ => panic!("Expected UnknownSetting error"),
        }
    }

    #[tokio::test]
    async fn test_settings_manager_can_update_setting_bootstrap_settings() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
        }

        let settings_manager = SettingsManager::init_bootstrap_only().unwrap();
        
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        // Bootstrap settings should never be mutable
        assert!(!settings_manager.can_update_setting("DATABASE_URL").await);
        assert!(!settings_manager.can_update_setting("HOST").await);
        assert!(!settings_manager.can_update_setting("PORT").await);
        
        // Unknown settings should return false
        assert!(!settings_manager.can_update_setting("UNKNOWN_SETTING").await);
    }

    #[tokio::test]
    async fn test_settings_manager_update_setting_bootstrap_settings_fails() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
        }

        let mut settings_manager = SettingsManager::init_bootstrap_only().unwrap();
        
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        // Attempting to update bootstrap settings should fail
        let result = settings_manager.update_setting("DATABASE_URL", "new_value".to_string()).await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            SettingsError::Application(ApplicationError::ReadOnlyFromEnvironment { setting_name }) => {
                assert_eq!(setting_name, "DATABASE_URL");
            }
            _ => panic!("Expected ReadOnlyFromEnvironment error"),
        }
    }

    #[tokio::test]
    async fn test_settings_manager_list_all_settings_bootstrap_only() {
        // Clean up any existing environment variables first
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        unsafe {
            std::env::set_var("DATABASE_URL", "sqlite://test.db");
            std::env::set_var("HOST", "127.0.0.1");
            std::env::set_var("PORT", "8080");
        }

        let settings_manager = SettingsManager::init_bootstrap_only().unwrap();
        
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HOST");
            std::env::remove_var("PORT");
        }

        let settings = settings_manager.list_all_settings().await;
        
        // Should have exactly 3 bootstrap settings
        assert_eq!(settings.len(), 3);
        
        let setting_names: Vec<String> = settings.iter().map(|(name, _)| name.clone()).collect();
        assert!(setting_names.contains(&"DATABASE_URL".to_string()));
        assert!(setting_names.contains(&"HOST".to_string()));
        assert!(setting_names.contains(&"PORT".to_string()));
        
        // All bootstrap settings should be immutable
        for (_, config_value) in settings {
            assert!(!config_value.is_mutable);
        }
    }
}
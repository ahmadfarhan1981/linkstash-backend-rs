use std::sync::Arc;
use std::time::Duration;

use sea_orm::DatabaseConnection;

use crate::config::{
    ApplicationError, bootstrap_settings::BootstrapSettings, errors::SettingsError, secret_manager::SecretManager, settings_registry::SettingsRegistry
};

/// Main settings manager with lazy initialization
/// 
/// Coordinates between bootstrap settings, secrets, and application settings.
/// Supports both full initialization (for server startup) and bootstrap-only
/// initialization (for CLI operations).
pub struct SettingsManager {
    pub secrets: SecretManager,
    pub settings: Arc<SettingsRegistry>,
}

impl SettingsManager {
    // TODO 
    // /// Full initialization for server startup
    // /// 
    // /// Loads bootstrap settings, secrets, and application settings.
    // /// All components are initialized and ready for use.
    // pub async fn init_full() -> Result<Self, SettingsError> {
    //     // Step 1: Load bootstrap settings (always required)
    //     let bootstrap_settings = BootstrapSettings::from_env()
    //         .map_err(SettingsError::Application)?;
        
    //     // Step 2: Load secrets
    //     let secrets = Some(SecretManager::init()
    //         .map_err(SettingsError::Secret)?);
        
    //     // Step 3: Load application settings
    //     let settings = Some(SettingsRegistry::init(&bootstrap_settings).await
    //         .map_err(SettingsError::Application)?);
        
    //     Ok(Self {
    //         bootstrap_settings,
    //         secrets,
    //         settings,
    //     })
    // }
 
    
   
   
    

    
    
    // Configuration management methods
    
    /// List all configuration settings with their sources and mutability
    /// 
    /// Returns settings from all initialized layers. If application settings
    /// are not initialized, only bootstrap settings are included.
    pub async fn list_all_settings(&self) -> Vec<(String, crate::config::config_spec::ConfigValue)> {
        let mut settings = Vec::new();
        
      
        
        // Add application settings if initialized
        // if let Some(app_settings) = &self.settings {
        //     let app_settings_list = app_settings.list_all_settings().await;
        //     settings.extend(app_settings_list);
        // }
        // TODO application settings

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
           
            _ => {
                // // Check application settings if initialized
                // if let Some(app_settings) = &self.settings {
                //     app_settings.get_setting_info(setting_name).await
                //         .map_err(SettingsError::Application)
                // } else {
                    Err(SettingsError::Application(
                        crate::config::errors::ApplicationError::UnknownSetting { 
                            name: setting_name.to_string() 
                        }
                    ))
                // }
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
        return Err(SettingsError::Application(ApplicationError::DatabaseConnection("TODO".to_string())));
    }
}

use crate::config::{
    bootstrap_settings::BootstrapSettings,
    application_settings::ApplicationSettings,
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
    pub application_settings: Option<ApplicationSettings>,
}

impl SettingsManager {
    /// Full initialization for server startup
    /// 
    /// Loads bootstrap settings, secrets, and application settings.
    /// All components are initialized and ready for use.
    pub async fn init_full() -> Result<Self, SettingsError> {
        // Step 1: Load bootstrap settings (always required)
        let bootstrap_settings = BootstrapSettings::from_env()
            .map_err(SettingsError::Bootstrap)?;
        
        // Step 2: Load secrets
        let secrets = Some(SecretManager::init()
            .map_err(|e| SettingsError::Application(
                crate::config::errors::ApplicationError::DatabaseConnection(
                    format!("Failed to initialize secrets: {}", e)
                )
            ))?);
        
        // Step 3: Load application settings
        let application_settings = Some(ApplicationSettings::init(&bootstrap_settings).await
            .map_err(SettingsError::Application)?);
        
        Ok(Self {
            bootstrap_settings,
            secrets,
            application_settings,
        })
    }
    
    /// Bootstrap-only initialization for CLI operations
    /// 
    /// Only loads bootstrap settings. Secrets and application settings
    /// can be loaded later using lazy initialization methods.
    pub fn init_bootstrap_only() -> Result<Self, SettingsError> {
        let bootstrap_settings = BootstrapSettings::from_env()
            .map_err(SettingsError::Bootstrap)?;
        
        Ok(Self {
            bootstrap_settings,
            secrets: None,
            application_settings: None,
        })
    }
    
    /// Lazy initialization for secrets
    /// 
    /// Initializes secrets if not already loaded. Safe to call multiple times.
    pub async fn ensure_secrets(&mut self) -> Result<&SecretManager, SettingsError> {
        if self.secrets.is_none() {
            self.secrets = Some(SecretManager::init()
                .map_err(|e| SettingsError::Application(
                    crate::config::errors::ApplicationError::DatabaseConnection(
                        format!("Failed to initialize secrets: {}", e)
                    )
                ))?);
        }
        Ok(self.secrets.as_ref().unwrap())
    }
    
    /// Lazy initialization for application settings
    /// 
    /// Initializes application settings if not already loaded. Safe to call multiple times.
    pub async fn ensure_application_settings(&mut self) -> Result<&ApplicationSettings, SettingsError> {
        if self.application_settings.is_none() {
            self.application_settings = Some(ApplicationSettings::init(&self.bootstrap_settings).await
                .map_err(SettingsError::Application)?);
        }
        Ok(self.application_settings.as_ref().unwrap())
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
    
    /// Get JWT secret (requires secrets to be initialized)
    pub fn jwt_secret(&self) -> Result<&str, SettingsError> {
        match &self.secrets {
            Some(secrets) => Ok(secrets.jwt_secret()),
            None => Err(SettingsError::Application(
                crate::config::errors::ApplicationError::DatabaseConnection(
                    "Secrets not initialized. Call ensure_secrets() first.".to_string()
                )
            )),
        }
    }
    
    /// Get JWT expiration duration (requires application settings to be initialized)
    pub fn jwt_expiration(&self) -> Result<std::time::Duration, SettingsError> {
        match &self.application_settings {
            Some(app_settings) => Ok(app_settings.jwt_expiration()),
            None => Err(SettingsError::Application(
                crate::config::errors::ApplicationError::DatabaseConnection(
                    "Application settings not initialized. Call ensure_application_settings() first.".to_string()
                )
            )),
        }
    }
    
    /// Get refresh token expiration duration (requires application settings to be initialized)
    pub fn refresh_token_expiration(&self) -> Result<std::time::Duration, SettingsError> {
        match &self.application_settings {
            Some(app_settings) => Ok(app_settings.refresh_token_expiration()),
            None => Err(SettingsError::Application(
                crate::config::errors::ApplicationError::DatabaseConnection(
                    "Application settings not initialized. Call ensure_application_settings() first.".to_string()
                )
            )),
        }
    }
}
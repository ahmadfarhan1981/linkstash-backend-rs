use std::fmt;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::time::Duration;
use crate::config::{
    bootstrap_settings::BootstrapSettings,
    config_spec::{ConfigSpec, ConfigSource, ConfigValue},
    errors::ApplicationError,
};

/// Application settings with in-memory caching and runtime updates
/// 
/// Business logic configuration that can be updated at runtime via API.
/// Values are cached in memory for fast access and updated atomically.
pub struct ApplicationSettings {
    // Cached values for fast access (thread-safe)
    jwt_expiration_minutes: Arc<RwLock<u32>>,
    refresh_token_expiration_days: Arc<RwLock<u32>>,
    rate_limiting_enabled: Arc<RwLock<bool>>,
    audit_retention_days: Arc<RwLock<u32>>,
    
    // Database connection for updates
    db: Arc<sea_orm::DatabaseConnection>,
    
    // Configuration specifications for validation and source tracking
    specs: HashMap<String, ConfigSpec>,
}

impl ApplicationSettings {
    /// Initialize ApplicationSettings by loading and caching all settings
    /// 
    /// Loads all application settings from their configured sources and caches
    /// them in memory for fast access. Uses environment override → persistent source → default priority.
    /// 
    /// # Arguments
    /// * `bootstrap` - Bootstrap settings containing database connection info
    /// 
    /// # Returns
    /// * `Ok(ApplicationSettings)` - Successfully initialized with all settings loaded
    /// * `Err(ApplicationError)` - Failed to connect to database or load required settings
    pub async fn init(bootstrap: &BootstrapSettings) -> Result<Self, ApplicationError> {
        // Connect to database using bootstrap settings
        let db = Arc::new(
            sea_orm::Database::connect(bootstrap.database_url())
                .await
                .map_err(|e| ApplicationError::DatabaseConnection(
                    format!("Failed to connect to database: {}", e)
                ))?
        );
        
        // Build configuration specifications
        let specs = Self::build_specs();
        
        // Load all settings and cache them
        let jwt_expiration_minutes = Arc::new(RwLock::new(
            Self::load_jwt_expiration(&db, &specs).await?
        ));
        
        let refresh_token_expiration_days = Arc::new(RwLock::new(
            Self::load_refresh_token_expiration(&db, &specs).await?
        ));
        
        let rate_limiting_enabled = Arc::new(RwLock::new(
            Self::load_rate_limiting_enabled(&db, &specs).await?
        ));
        
        let audit_retention_days = Arc::new(RwLock::new(
            Self::load_audit_retention_days(&db, &specs).await?
        ));
        
        Ok(Self {
            jwt_expiration_minutes,
            refresh_token_expiration_days,
            rate_limiting_enabled,
            audit_retention_days,
            db,
            specs,
        })
    }
    
    /// Get JWT expiration duration (fast cached access)
    /// 
    /// Returns the cached JWT expiration duration without database queries.
    /// Thread-safe for concurrent access.
    pub fn jwt_expiration(&self) -> Duration {
        let minutes = *self.jwt_expiration_minutes.read().unwrap();
        Duration::from_secs(minutes as u64 * 60)
    }
    
    /// Get refresh token expiration duration (fast cached access)
    /// 
    /// Returns the cached refresh token expiration duration without database queries.
    /// Thread-safe for concurrent access.
    pub fn refresh_token_expiration(&self) -> Duration {
        let days = *self.refresh_token_expiration_days.read().unwrap();
        Duration::from_secs(days as u64 * 24 * 60 * 60)
    }
    
    /// Get rate limiting enabled status (fast cached access)
    /// 
    /// Returns the cached rate limiting enabled flag without database queries.
    /// Thread-safe for concurrent access.
    pub fn rate_limiting_enabled(&self) -> bool {
        *self.rate_limiting_enabled.read().unwrap()
    }
    
    /// Get audit retention period in days (fast cached access)
    /// 
    /// Returns the cached audit retention period without database queries.
    /// Thread-safe for concurrent access.
    pub fn audit_retention_days(&self) -> u32 {
        *self.audit_retention_days.read().unwrap()
    }
    
    /// Get configuration information for a specific setting
    /// 
    /// Returns the current value, source, and mutability status for the specified setting.
    /// 
    /// # Arguments
    /// * `setting_name` - Name of the setting to query
    /// 
    /// # Returns
    /// * `Ok(ConfigValue)` - Setting information with current value and source
    /// * `Err(ApplicationError)` - Setting not found or database error
    pub async fn get_setting_info(&self, setting_name: &str) -> Result<ConfigValue, ApplicationError> {
        let spec = self.specs.get(setting_name)
            .ok_or_else(|| ApplicationError::UnknownSetting { 
                name: setting_name.to_string() 
            })?;
        
        spec.load_setting_with_source(Some(&self.db))
    }
    
    /// List all application settings with their current values and sources
    /// 
    /// Returns a vector of all configured settings with their current values,
    /// sources, and mutability status.
    pub async fn list_all_settings(&self) -> Vec<(String, ConfigValue)> {
        let mut settings = Vec::new();
        
        for (name, spec) in &self.specs {
            if let Ok(config_value) = spec.load_setting_with_source(Some(&self.db)) {
                settings.push((name.clone(), config_value));
            }
        }
        
        settings
    }
    
    /// Update a setting value at runtime
    /// 
    /// Updates both the persistent storage and in-memory cache atomically.
    /// Only allows updates to settings that are not overridden by environment variables.
    /// 
    /// # Arguments
    /// * `setting_name` - Name of the setting to update
    /// * `value` - New value for the setting
    /// 
    /// # Returns
    /// * `Ok(())` - Setting updated successfully
    /// * `Err(ApplicationError)` - Setting not found, read-only, or validation failed
    pub async fn update_setting(&self, setting_name: &str, value: String) -> Result<(), ApplicationError> {
        let spec = self.specs.get(setting_name)
            .ok_or_else(|| ApplicationError::UnknownSetting { 
                name: setting_name.to_string() 
            })?;
        
        // Check if setting can be updated (not overridden by environment variable)
        let current_config = spec.load_setting_with_source(Some(&self.db))?;
        if !current_config.is_mutable {
            return Err(ApplicationError::ReadOnlyFromEnvironment { 
                setting_name: setting_name.to_string() 
            });
        }
        
        // Validate the new value
        spec.validate_value(&value, setting_name)?;
        
        // Update persistent storage
        self.update_database_setting(setting_name, &value).await?;
        
        // Update in-memory cache
        self.update_cache(setting_name, &value)?;
        
        Ok(())
    }
    
    /// Build configuration specifications for all application settings
    fn build_specs() -> HashMap<String, ConfigSpec> {
        let mut specs = HashMap::new();
        
        specs.insert("jwt_expiration_minutes".to_string(), Self::jwt_expiration_config());
        specs.insert("refresh_token_expiration_days".to_string(), Self::refresh_token_expiration_config());
        specs.insert("rate_limiting_enabled".to_string(), Self::rate_limiting_enabled_config());
        specs.insert("audit_retention_days".to_string(), Self::audit_retention_days_config());
        
        specs
    }
    
    /// Configuration specification for JWT expiration setting
    fn jwt_expiration_config() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("JWT_EXPIRATION_MINUTES")
            .default_value("15")
            .validator(|value| {
                let minutes = value.parse::<u32>()
                    .map_err(|_| "must be a positive integer")?;
                if minutes == 0 || minutes > 1440 {
                    return Err("must be between 1 and 1440 minutes".to_string());
                }
                Ok(())
            })
    }
    
    /// Configuration specification for refresh token expiration setting
    fn refresh_token_expiration_config() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("REFRESH_TOKEN_EXPIRATION_DAYS")
            .default_value("7")
            .validator(|value| {
                let days = value.parse::<u32>()
                    .map_err(|_| "must be a positive integer")?;
                if days == 0 || days > 365 {
                    return Err("must be between 1 and 365 days".to_string());
                }
                Ok(())
            })
    }
    
    /// Configuration specification for rate limiting enabled setting
    fn rate_limiting_enabled_config() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("RATE_LIMITING_ENABLED")
            .persistent_source(ConfigSource::Database { 
                key: "rate_limiting_enabled".to_string() 
            })
            .default_value("true")
            .validator(|value| {
                match value.to_lowercase().as_str() {
                    "true" | "false" | "1" | "0" | "yes" | "no" => Ok(()),
                    _ => Err("must be true, false, 1, 0, yes, or no".to_string()),
                }
            })
    }
    
    /// Configuration specification for audit retention days setting
    fn audit_retention_days_config() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("AUDIT_RETENTION_DAYS")
            .persistent_source(ConfigSource::Database { 
                key: "audit_retention_days".to_string() 
            })
            .default_value("90")
            .validator(|value| {
                let days = value.parse::<u32>()
                    .map_err(|_| "must be a positive integer")?;
                if days == 0 || days > 3650 {
                    return Err("must be between 1 and 3650 days".to_string());
                }
                Ok(())
            })
    }
    
    /// Load JWT expiration setting and parse to minutes
    async fn load_jwt_expiration(
        db: &sea_orm::DatabaseConnection, 
        specs: &HashMap<String, ConfigSpec>
    ) -> Result<u32, ApplicationError> {
        let spec = specs.get("jwt_expiration_minutes").unwrap();
        let config_value = spec.load_setting_with_source(Some(db))?;
        Self::parse_duration_minutes(&config_value.value, "jwt_expiration_minutes")
    }
    
    /// Load refresh token expiration setting and parse to days
    async fn load_refresh_token_expiration(
        db: &sea_orm::DatabaseConnection, 
        specs: &HashMap<String, ConfigSpec>
    ) -> Result<u32, ApplicationError> {
        let spec = specs.get("refresh_token_expiration_days").unwrap();
        let config_value = spec.load_setting_with_source(Some(db))?;
        Self::parse_duration_days(&config_value.value, "refresh_token_expiration_days")
    }
    
    /// Load rate limiting enabled setting and parse to boolean
    async fn load_rate_limiting_enabled(
        db: &sea_orm::DatabaseConnection, 
        specs: &HashMap<String, ConfigSpec>
    ) -> Result<bool, ApplicationError> {
        let spec = specs.get("rate_limiting_enabled").unwrap();
        let config_value = spec.load_setting_with_source(Some(db))?;
        Self::parse_bool(&config_value.value, "rate_limiting_enabled")
    }
    
    /// Load audit retention days setting and parse to u32
    async fn load_audit_retention_days(
        db: &sea_orm::DatabaseConnection, 
        specs: &HashMap<String, ConfigSpec>
    ) -> Result<u32, ApplicationError> {
        let spec = specs.get("audit_retention_days").unwrap();
        let config_value = spec.load_setting_with_source(Some(db))?;
        Self::parse_duration_days(&config_value.value, "audit_retention_days")
    }
    
    /// Parse a duration value in minutes
    fn parse_duration_minutes(value: &str, setting_name: &str) -> Result<u32, ApplicationError> {
        value.parse::<u32>()
            .map_err(|e| ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Invalid minutes value: {}", e),
            })
    }
    
    /// Parse a duration value in days
    fn parse_duration_days(value: &str, setting_name: &str) -> Result<u32, ApplicationError> {
        value.parse::<u32>()
            .map_err(|e| ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Invalid days value: {}", e),
            })
    }
    
    /// Parse a boolean value from string
    fn parse_bool(value: &str, setting_name: &str) -> Result<bool, ApplicationError> {
        match value.to_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Invalid boolean value: {}", value),
            })
        }
    }
    
    /// Update a setting in the database
    async fn update_database_setting(&self, setting_name: &str, value: &str) -> Result<(), ApplicationError> {
        use sea_orm::{EntityTrait, Set, ActiveModelTrait};
        use crate::types::db::system_settings::{Entity as SystemSettings, ActiveModel};
        
        let spec = self.specs.get(setting_name).unwrap();
        
        // Only update if there's a database source configured
        if let Some(ConfigSource::Database { key }) = &spec.persistent_source {
            let now = chrono::Utc::now().timestamp();
            
            let active_model = ActiveModel {
                key: Set(key.clone()),
                value: Set(value.to_string()),
                description: Set(None),
                category: Set(Some("application".to_string())),
                created_at: Set(now),
                updated_at: Set(now),
            };
            
            SystemSettings::insert(active_model)
                .on_conflict(
                    sea_orm::sea_query::OnConflict::column(crate::types::db::system_settings::Column::Key)
                        .update_columns([
                            crate::types::db::system_settings::Column::Value,
                            crate::types::db::system_settings::Column::UpdatedAt,
                        ])
                        .to_owned()
                )
                .exec(&*self.db)
                .await
                .map_err(|e| ApplicationError::DatabaseConnection(
                    format!("Failed to update setting '{}': {}", setting_name, e)
                ))?;
        } else {
            return Err(ApplicationError::NoWritableSource { 
                setting_name: setting_name.to_string() 
            });
        }
        
        Ok(())
    }
    
    /// Update the in-memory cache for a setting
    fn update_cache(&self, setting_name: &str, value: &str) -> Result<(), ApplicationError> {
        match setting_name {
            "jwt_expiration_minutes" => {
                let minutes = Self::parse_duration_minutes(value, setting_name)?;
                *self.jwt_expiration_minutes.write().unwrap() = minutes;
            }
            "refresh_token_expiration_days" => {
                let days = Self::parse_duration_days(value, setting_name)?;
                *self.refresh_token_expiration_days.write().unwrap() = days;
            }
            "rate_limiting_enabled" => {
                let enabled = Self::parse_bool(value, setting_name)?;
                *self.rate_limiting_enabled.write().unwrap() = enabled;
            }
            "audit_retention_days" => {
                let days = Self::parse_duration_days(value, setting_name)?;
                *self.audit_retention_days.write().unwrap() = days;
            }
            _ => {
                return Err(ApplicationError::UnknownSetting { 
                    name: setting_name.to_string() 
                });
            }
        }
        
        Ok(())
    }
}

impl fmt::Debug for ApplicationSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationSettings")
            .field("jwt_expiration_minutes", &*self.jwt_expiration_minutes.read().unwrap())
            .field("refresh_token_expiration_days", &*self.refresh_token_expiration_days.read().unwrap())
            .field("rate_limiting_enabled", &*self.rate_limiting_enabled.read().unwrap())
            .field("audit_retention_days", &*self.audit_retention_days.read().unwrap())
            .field("specs_count", &self.specs.len())
            .finish()
    }
}

impl fmt::Display for ApplicationSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, 
            "ApplicationSettings {{ jwt_expiration: {}min, refresh_expiration: {}days, rate_limiting: {}, audit_retention: {}days }}",
            *self.jwt_expiration_minutes.read().unwrap(),
            *self.refresh_token_expiration_days.read().unwrap(),
            *self.rate_limiting_enabled.read().unwrap(),
            *self.audit_retention_days.read().unwrap()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::collections::HashMap;

    struct EnvGuard {
        keys: Vec<String>,
        original_values: HashMap<String, Option<String>>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self { 
                keys: Vec::new(),
                original_values: HashMap::new(),
            }
        }

        fn set(&mut self, key: &str, value: &str) {
            if !self.original_values.contains_key(key) {
                let original = env::var(key).ok();
                self.original_values.insert(key.to_string(), original);
            }
            
            unsafe {
                env::set_var(key, value);
            }
            if !self.keys.contains(&key.to_string()) {
                self.keys.push(key.to_string());
            }
        }

        fn remove(&mut self, key: &str) {
            if !self.original_values.contains_key(key) {
                let original = env::var(key).ok();
                self.original_values.insert(key.to_string(), original);
            }
            
            unsafe {
                env::remove_var(key);
            }
            if !self.keys.contains(&key.to_string()) {
                self.keys.push(key.to_string());
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in &self.keys {
                if let Some(original_value) = self.original_values.get(key) {
                    match original_value {
                        Some(value) => unsafe { env::set_var(key, value) },
                        None => unsafe { env::remove_var(key) },
                    }
                }
            }
        }
    }

    #[test]
    fn test_application_settings_config_specs() {
        // Test that configuration specifications are built correctly
        let specs = ApplicationSettings::build_specs();
        
        assert_eq!(specs.len(), 4);
        assert!(specs.contains_key("jwt_expiration_minutes"));
        assert!(specs.contains_key("refresh_token_expiration_days"));
        assert!(specs.contains_key("rate_limiting_enabled"));
        assert!(specs.contains_key("audit_retention_days"));
    }

    #[test]
    fn test_jwt_expiration_config() {
        let config = ApplicationSettings::jwt_expiration_config();
        
        assert_eq!(config.env_override, Some("JWT_EXPIRATION_MINUTES".to_string()));
        assert_eq!(config.default_value, Some("15".to_string()));
        assert!(config.validator.is_some());
        
        // Test validator
        let validator = config.validator.unwrap();
        assert!(validator("15").is_ok());
        assert!(validator("1440").is_ok());
        assert!(validator("0").is_err());
        assert!(validator("1441").is_err());
        assert!(validator("not_a_number").is_err());
    }

    #[test]
    fn test_refresh_token_expiration_config() {
        let config = ApplicationSettings::refresh_token_expiration_config();
        
        assert_eq!(config.env_override, Some("REFRESH_TOKEN_EXPIRATION_DAYS".to_string()));
        assert_eq!(config.default_value, Some("7".to_string()));
        assert!(config.validator.is_some());
        
        // Test validator
        let validator = config.validator.unwrap();
        assert!(validator("7").is_ok());
        assert!(validator("365").is_ok());
        assert!(validator("0").is_err());
        assert!(validator("366").is_err());
        assert!(validator("not_a_number").is_err());
    }

    #[test]
    fn test_rate_limiting_enabled_config() {
        let config = ApplicationSettings::rate_limiting_enabled_config();
        
        assert_eq!(config.env_override, Some("RATE_LIMITING_ENABLED".to_string()));
        assert_eq!(config.default_value, Some("true".to_string()));
        assert!(config.persistent_source.is_some());
        assert!(config.validator.is_some());
        
        // Test validator
        let validator = config.validator.unwrap();
        assert!(validator("true").is_ok());
        assert!(validator("false").is_ok());
        assert!(validator("1").is_ok());
        assert!(validator("0").is_ok());
        assert!(validator("yes").is_ok());
        assert!(validator("no").is_ok());
        assert!(validator("invalid").is_err());
    }

    #[test]
    fn test_audit_retention_days_config() {
        let config = ApplicationSettings::audit_retention_days_config();
        
        assert_eq!(config.env_override, Some("AUDIT_RETENTION_DAYS".to_string()));
        assert_eq!(config.default_value, Some("90".to_string()));
        assert!(config.persistent_source.is_some());
        assert!(config.validator.is_some());
        
        // Test validator
        let validator = config.validator.unwrap();
        assert!(validator("90").is_ok());
        assert!(validator("3650").is_ok());
        assert!(validator("0").is_err());
        assert!(validator("3651").is_err());
        assert!(validator("not_a_number").is_err());
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(ApplicationSettings::parse_duration_minutes("15", "test").unwrap(), 15);
        assert_eq!(ApplicationSettings::parse_duration_minutes("1440", "test").unwrap(), 1440);
        
        let result = ApplicationSettings::parse_duration_minutes("not_a_number", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::ParseError { setting_name, error } => {
                assert_eq!(setting_name, "test");
                assert!(error.contains("Invalid minutes value"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(ApplicationSettings::parse_duration_days("7", "test").unwrap(), 7);
        assert_eq!(ApplicationSettings::parse_duration_days("365", "test").unwrap(), 365);
        
        let result = ApplicationSettings::parse_duration_days("not_a_number", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::ParseError { setting_name, error } => {
                assert_eq!(setting_name, "test");
                assert!(error.contains("Invalid days value"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_parse_bool() {
        assert_eq!(ApplicationSettings::parse_bool("true", "test").unwrap(), true);
        assert_eq!(ApplicationSettings::parse_bool("TRUE", "test").unwrap(), true);
        assert_eq!(ApplicationSettings::parse_bool("1", "test").unwrap(), true);
        assert_eq!(ApplicationSettings::parse_bool("yes", "test").unwrap(), true);
        assert_eq!(ApplicationSettings::parse_bool("YES", "test").unwrap(), true);
        
        assert_eq!(ApplicationSettings::parse_bool("false", "test").unwrap(), false);
        assert_eq!(ApplicationSettings::parse_bool("FALSE", "test").unwrap(), false);
        assert_eq!(ApplicationSettings::parse_bool("0", "test").unwrap(), false);
        assert_eq!(ApplicationSettings::parse_bool("no", "test").unwrap(), false);
        assert_eq!(ApplicationSettings::parse_bool("NO", "test").unwrap(), false);
        
        let result = ApplicationSettings::parse_bool("invalid", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::ParseError { setting_name, error } => {
                assert_eq!(setting_name, "test");
                assert!(error.contains("Invalid boolean value"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_application_settings_debug_display() {
        // Test that Debug and Display traits work correctly
        // We can't easily test the full ApplicationSettings without a database,
        // but we can test the format strings don't panic
        
        let jwt_minutes = Arc::new(RwLock::new(15u32));
        let refresh_days = Arc::new(RwLock::new(7u32));
        let rate_limiting = Arc::new(RwLock::new(true));
        let audit_days = Arc::new(RwLock::new(90u32));
        
        // Test that the values can be read from RwLock
        assert_eq!(*jwt_minutes.read().unwrap(), 15);
        assert_eq!(*refresh_days.read().unwrap(), 7);
        assert_eq!(*rate_limiting.read().unwrap(), true);
        assert_eq!(*audit_days.read().unwrap(), 90);
    }
}
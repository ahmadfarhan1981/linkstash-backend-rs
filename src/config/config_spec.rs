use std::path::PathBuf;
use std::time::Duration;
use crate::config::errors::ApplicationError;

#[derive(Debug, Clone)]
pub enum ConfigSource {
    Database { key: String },
    File { path: PathBuf, key: String },
    // Future variants:
    // Vault { path: String },
}

#[derive(Debug, Clone)]
pub struct ConfigValue {
    pub value: String,
    pub source: ConfigValueSource,
    pub is_mutable: bool,
}

#[derive(Debug, Clone)]
pub enum ConfigValueSource {
    EnvironmentVariable { name: String },
    Database { key: String },
    File { path: PathBuf, key: String },
    Default,
}

/// Configuration specification with environment override → single persistent source → default priority
pub struct ConfigSpec {
    pub env_override: Option<String>,
    pub persistent_source: Option<ConfigSource>,
    pub default_value: Option<String>,
    pub required: bool,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub validator: Option<fn(&str) -> Result<(), String>>,
}

impl ConfigSpec {
    pub fn new() -> Self {
        Self {
            env_override: None,
            persistent_source: None,
            default_value: None,
            required: false,
            min_length: None,
            max_length: None,
            validator: None,
        }
    }

    pub fn env_override(mut self, name: &str) -> Self {
        self.env_override = Some(name.to_string());
        self
    }

    pub fn persistent_source(mut self, source: ConfigSource) -> Self {
        self.persistent_source = Some(source);
        self
    }

    pub fn default_value(mut self, value: &str) -> Self {
        self.default_value = Some(value.to_string());
        self
    }

    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    pub fn min_length(mut self, length: usize) -> Self {
        self.min_length = Some(length);
        self
    }

    pub fn max_length(mut self, length: usize) -> Self {
        self.max_length = Some(length);
        self
    }

    pub fn validator(mut self, f: fn(&str) -> Result<(), String>) -> Self {
        self.validator = Some(f);
        self
    }

    /// Load a setting value with source tracking according to priority rules
    /// 
    /// Uses environment override → persistent source → default priority.
    /// Environment variables are read-only; database sources are mutable.
    /// 
    /// This method is synchronous and will block on database operations when needed.
    /// Intended for use during application startup where blocking is acceptable.
    pub fn load_setting_with_source(
        &self,
        db: Option<&sea_orm::DatabaseConnection>,
    ) -> Result<ConfigValue, ApplicationError> {
        if let Some(env_var) = &self.env_override {
            if let Ok(value) = std::env::var(env_var) {
                self.validate_value(&value, env_var)?;
                
                return Ok(ConfigValue {
                    value,
                    source: ConfigValueSource::EnvironmentVariable { 
                        name: env_var.clone() 
                    },
                    is_mutable: false, // Cannot update env vars at runtime
                });
            }
        }

        if let Some(source) = &self.persistent_source {
            let value_result = match source {
                ConfigSource::Database { key } => {
                    if let Some(database) = db {
                        self.load_from_database_blocking(database, key)
                    } else {
                        Err(ApplicationError::DatabaseConnection(
                            "Database connection required for database source".to_string()
                        ))
                    }
                }
                ConfigSource::File { path, key } => {
                    self.load_from_file_blocking(path, key)
                }
            };

            match value_result {
                Ok(value) => {
                    let setting_name = self.get_setting_name_for_source(source);
                    self.validate_value(&value, &setting_name)?;
                    
                    let is_mutable = match source {
                        ConfigSource::Database { .. } => true,  // Can update via API
                        ConfigSource::File { .. } => false,     // Files are read-only
                    };
                    
                    return Ok(ConfigValue {
                        value,
                        source: match source {
                            ConfigSource::Database { key } => ConfigValueSource::Database { 
                                key: key.clone() 
                            },
                            ConfigSource::File { path, key } => ConfigValueSource::File { 
                                path: path.clone(), 
                                key: key.clone() 
                            },
                        },
                        is_mutable,
                    });
                }
                Err(_) => {
                    // Graceful fallback when database/file unavailable
                }
            }
        }

        if let Some(default) = &self.default_value {
            let setting_name = "default";
            self.validate_value(default, setting_name)?;
            
            return Ok(ConfigValue {
                value: default.clone(),
                source: ConfigValueSource::Default,
                is_mutable: self.persistent_source.is_some(), // Can update if has writable source
            });
        }

        if self.required {
            let setting_name = self.env_override
                .as_deref()
                .unwrap_or("unknown_setting");
            return Err(ApplicationError::InvalidSetting {
                setting_name: setting_name.to_string(),
                reason: "Required setting has no value from any source".to_string(),
            });
        }

        Ok(ConfigValue {
            value: String::new(),
            source: ConfigValueSource::Default,
            is_mutable: self.persistent_source.is_some(),
        })
    }

    /// Load a setting value from database (blocking)
    /// 
    /// This method blocks on the async database operation. It's intended for use
    /// during application startup where blocking is acceptable.
    fn load_from_database_blocking(
        &self,
        db: &sea_orm::DatabaseConnection,
        key: &str,
    ) -> Result<String, ApplicationError> {
        // Use tokio::task::block_in_place to block on the async database call
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                use sea_orm::{EntityTrait, ColumnTrait, QueryFilter};
                use crate::types::db::system_settings::{Entity as SystemSettings, Column};

                let result = SystemSettings::find()
                    .filter(Column::Key.eq(key))
                    .one(db)
                    .await
                    .map_err(|e| ApplicationError::DatabaseConnection(
                        format!("Failed to query setting '{}': {}", key, e)
                    ))?;

                match result {
                    Some(setting) => Ok(setting.value),
                    None => Err(ApplicationError::InvalidSetting {
                        setting_name: key.to_string(),
                        reason: "Setting not found in database".to_string(),
                    }),
                }
            })
        })
    }

    /// Load a setting value from file (blocking)
    /// 
    /// File operations are naturally synchronous, so this method doesn't need
    /// special blocking handling.
    fn load_from_file_blocking(
        &self,
        _path: &std::path::Path,
        _key: &str,
    ) -> Result<String, ApplicationError> {
        // File loading not yet implemented
        Err(ApplicationError::InvalidSetting {
            setting_name: "file_setting".to_string(),
            reason: "File-based configuration loading not yet implemented".to_string(),
        })
    }

    /// Validate a setting value according to the ConfigSpec rules
    pub fn validate_value(&self, value: &str, setting_name: &str) -> Result<(), ApplicationError> {
        if let Some(min_len) = self.min_length {
            if value.len() < min_len {
                return Err(ApplicationError::InvalidSetting {
                    setting_name: setting_name.to_string(),
                    reason: format!("Value must be at least {} characters long", min_len),
                });
            }
        }

        if let Some(max_len) = self.max_length {
            if value.len() > max_len {
                return Err(ApplicationError::InvalidSetting {
                    setting_name: setting_name.to_string(),
                    reason: format!("Value must be at most {} characters long", max_len),
                });
            }
        }

        if let Some(validator) = self.validator {
            validator(value).map_err(|reason| ApplicationError::InvalidSetting {
                setting_name: setting_name.to_string(),
                reason,
            })?;
        }

        Ok(())
    }

    /// Get a descriptive setting name for error messages based on the source
    fn get_setting_name_for_source(&self, source: &ConfigSource) -> String {
        match source {
            ConfigSource::Database { key } => key.clone(),
            ConfigSource::File { key, .. } => key.clone(),
        }
    }
}

impl Default for ConfigSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// Type parsing utilities for configuration values
impl ConfigSpec {
    /// Parse a duration value in minutes from string
    /// 
    /// Supports integer values representing minutes.
    /// 
    /// # Arguments
    /// * `value` - String value to parse (e.g., "15", "1440")
    /// * `setting_name` - Name of the setting for error messages
    /// 
    /// # Returns
    /// * `Ok(Duration)` - Parsed duration
    /// * `Err(ApplicationError)` - Parse error with descriptive message
    pub fn parse_duration_minutes(value: &str, setting_name: &str) -> Result<Duration, ApplicationError> {
        let minutes = value.parse::<u64>()
            .map_err(|e| ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Expected positive integer for minutes, got '{}': {}", value, e),
            })?;
        
        Ok(Duration::from_secs(minutes * 60))
    }

    /// Parse a duration value in days from string
    /// 
    /// Supports integer values representing days.
    /// 
    /// # Arguments
    /// * `value` - String value to parse (e.g., "7", "365")
    /// * `setting_name` - Name of the setting for error messages
    /// 
    /// # Returns
    /// * `Ok(Duration)` - Parsed duration
    /// * `Err(ApplicationError)` - Parse error with descriptive message
    pub fn parse_duration_days(value: &str, setting_name: &str) -> Result<Duration, ApplicationError> {
        let days = value.parse::<u64>()
            .map_err(|e| ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Expected positive integer for days, got '{}': {}", value, e),
            })?;
        
        Ok(Duration::from_secs(days * 24 * 60 * 60))
    }

    /// Parse a duration value from human-readable formats
    /// 
    /// Supports formats like:
    /// - "15m", "30min", "45minutes" (minutes)
    /// - "2h", "3hr", "4hours" (hours)  
    /// - "1d", "7days" (days)
    /// - "300s", "600sec", "900seconds" (seconds)
    /// - Plain numbers default to seconds
    /// 
    /// # Arguments
    /// * `value` - String value to parse (e.g., "15m", "2h", "7d")
    /// * `setting_name` - Name of the setting for error messages
    /// 
    /// # Returns
    /// * `Ok(Duration)` - Parsed duration
    /// * `Err(ApplicationError)` - Parse error with descriptive message
    pub fn parse_duration_human(value: &str, setting_name: &str) -> Result<Duration, ApplicationError> {
        let value = value.trim().to_lowercase();
        
        // Try to extract number and unit
        let (number_str, unit) = if let Some(pos) = value.find(|c: char| c.is_alphabetic()) {
            (&value[..pos], &value[pos..])
        } else {
            // No unit, assume seconds
            (value.as_str(), "s")
        };
        
        let number = number_str.parse::<u64>()
            .map_err(|e| ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Expected number in duration '{}': {}", value, e),
            })?;
        
        let seconds = match unit {
            "s" | "sec" | "second" | "seconds" => number,
            "m" | "min" | "minute" | "minutes" => number * 60,
            "h" | "hr" | "hour" | "hours" => number * 60 * 60,
            "d" | "day" | "days" => number * 24 * 60 * 60,
            _ => return Err(ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Unknown duration unit '{}' in '{}'. Supported: s, m, h, d", unit, value),
            }),
        };
        
        Ok(Duration::from_secs(seconds))
    }

    /// Parse a boolean value from string
    /// 
    /// Supports various boolean representations:
    /// - true: "true", "1", "yes", "on", "enabled" (case insensitive)
    /// - false: "false", "0", "no", "off", "disabled" (case insensitive)
    /// 
    /// # Arguments
    /// * `value` - String value to parse
    /// * `setting_name` - Name of the setting for error messages
    /// 
    /// # Returns
    /// * `Ok(bool)` - Parsed boolean value
    /// * `Err(ApplicationError)` - Parse error with descriptive message
    pub fn parse_bool(value: &str, setting_name: &str) -> Result<bool, ApplicationError> {
        match value.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" | "enabled" => Ok(true),
            "false" | "0" | "no" | "off" | "disabled" => Ok(false),
            _ => Err(ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!(
                    "Expected boolean value, got '{}'. Valid values: true/false, 1/0, yes/no, on/off, enabled/disabled",
                    value
                ),
            }),
        }
    }

    /// Parse an integer value from string
    /// 
    /// # Arguments
    /// * `value` - String value to parse
    /// * `setting_name` - Name of the setting for error messages
    /// 
    /// # Returns
    /// * `Ok(i64)` - Parsed integer value
    /// * `Err(ApplicationError)` - Parse error with descriptive message
    pub fn parse_integer(value: &str, setting_name: &str) -> Result<i64, ApplicationError> {
        value.trim().parse::<i64>()
            .map_err(|e| ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Expected integer, got '{}': {}", value, e),
            })
    }

    /// Parse a port number from string with validation
    /// 
    /// Validates that the port is in the valid range (1-65535).
    /// 
    /// # Arguments
    /// * `value` - String value to parse
    /// * `setting_name` - Name of the setting for error messages
    /// 
    /// # Returns
    /// * `Ok(u16)` - Parsed port number
    /// * `Err(ApplicationError)` - Parse error or validation error
    pub fn parse_port(value: &str, setting_name: &str) -> Result<u16, ApplicationError> {
        let port = value.trim().parse::<u16>()
            .map_err(|e| ApplicationError::ParseError {
                setting_name: setting_name.to_string(),
                error: format!("Expected port number (1-65535), got '{}': {}", value, e),
            })?;
        
        if port == 0 {
            return Err(ApplicationError::InvalidSetting {
                setting_name: setting_name.to_string(),
                reason: "Port number must be between 1 and 65535".to_string(),
            });
        }
        
        Ok(port)
    }

    /// Parse and validate a host address (IPv4, IPv6, or hostname)
    /// 
    /// Validates basic format but does not perform DNS resolution.
    /// 
    /// # Arguments
    /// * `value` - String value to parse
    /// * `setting_name` - Name of the setting for error messages
    /// 
    /// # Returns
    /// * `Ok(String)` - Validated host address
    /// * `Err(ApplicationError)` - Validation error
    pub fn parse_host(value: &str, setting_name: &str) -> Result<String, ApplicationError> {
        let host = value.trim();
        
        if host.is_empty() {
            return Err(ApplicationError::InvalidSetting {
                setting_name: setting_name.to_string(),
                reason: "Host address cannot be empty".to_string(),
            });
        }
        
        // Basic validation - check for obviously invalid characters
        if host.contains(' ') || host.contains('\t') || host.contains('\n') {
            return Err(ApplicationError::InvalidSetting {
                setting_name: setting_name.to_string(),
                reason: "Host address cannot contain whitespace characters".to_string(),
            });
        }
        
        // Check for IPv6 format (contains colons and brackets)
        if host.starts_with('[') && host.ends_with(']') {
            // IPv6 in brackets - basic validation
            let ipv6_part = &host[1..host.len()-1];
            if ipv6_part.is_empty() || !ipv6_part.contains(':') {
                return Err(ApplicationError::InvalidSetting {
                    setting_name: setting_name.to_string(),
                    reason: "Invalid IPv6 address format".to_string(),
                });
            }
        } else if host.contains(':') && (host.contains("::") || host.matches(':').count() > 1) {
            // Looks like IPv6 without brackets (either has :: or multiple colons)
            return Err(ApplicationError::InvalidSetting {
                setting_name: setting_name.to_string(),
                reason: "IPv6 addresses must be enclosed in brackets [::1]".to_string(),
            });
        }
        
        Ok(host.to_string())
    }

    /// Parse a string value with length validation
    /// 
    /// # Arguments
    /// * `value` - String value to parse
    /// * `setting_name` - Name of the setting for error messages
    /// * `min_length` - Optional minimum length
    /// * `max_length` - Optional maximum length
    /// 
    /// # Returns
    /// * `Ok(String)` - Validated string value
    /// * `Err(ApplicationError)` - Validation error
    pub fn parse_string(
        value: &str, 
        setting_name: &str,
        min_length: Option<usize>,
        max_length: Option<usize>
    ) -> Result<String, ApplicationError> {
        if let Some(min_len) = min_length {
            if value.len() < min_len {
                return Err(ApplicationError::InvalidSetting {
                    setting_name: setting_name.to_string(),
                    reason: format!("Value must be at least {} characters long", min_len),
                });
            }
        }

        if let Some(max_len) = max_length {
            if value.len() > max_len {
                return Err(ApplicationError::InvalidSetting {
                    setting_name: setting_name.to_string(),
                    reason: format!("Value must be at most {} characters long", max_len),
                });
            }
        }

        Ok(value.to_string())
    }
}

/// Range validation utilities
impl ConfigSpec {
    /// Validate an integer value is within the specified range
    /// 
    /// # Arguments
    /// * `value` - String value to validate
    /// * `min` - Minimum allowed value (inclusive)
    /// * `max` - Maximum allowed value (inclusive)
    /// 
    /// # Returns
    /// * `Ok(())` - Value is within range
    /// * `Err(String)` - Validation error message
    pub fn validate_integer_range(value: &str, min: i64, max: i64) -> Result<(), String> {
        let parsed = value.parse::<i64>()
            .map_err(|_| format!("Expected integer between {} and {}", min, max))?;
        
        if parsed < min || parsed > max {
            return Err(format!("Value {} is outside valid range {}-{}", parsed, min, max));
        }
        
        Ok(())
    }

    /// Validate a port number is within the specified range
    /// 
    /// # Arguments
    /// * `value` - String value to validate
    /// * `min` - Minimum allowed port (inclusive)
    /// * `max` - Maximum allowed port (inclusive)
    /// 
    /// # Returns
    /// * `Ok(())` - Port is within range
    /// * `Err(String)` - Validation error message
    pub fn validate_port_range(value: &str, min: u16, max: u16) -> Result<(), String> {
        let parsed = value.parse::<u16>()
            .map_err(|_| format!("Expected port number between {} and {}", min, max))?;
        
        if parsed < min || parsed > max {
            return Err(format!("Port {} is outside valid range {}-{}", parsed, min, max));
        }
        
        Ok(())
    }

    /// Validate a duration (in minutes) is within the specified range
    /// 
    /// # Arguments
    /// * `value` - String value to validate
    /// * `min_minutes` - Minimum allowed duration in minutes
    /// * `max_minutes` - Maximum allowed duration in minutes
    /// 
    /// # Returns
    /// * `Ok(())` - Duration is within range
    /// * `Err(String)` - Validation error message
    pub fn validate_duration_minutes_range(value: &str, min_minutes: u64, max_minutes: u64) -> Result<(), String> {
        let parsed = value.parse::<u64>()
            .map_err(|_| format!("Expected duration between {} and {} minutes", min_minutes, max_minutes))?;
        
        if parsed < min_minutes || parsed > max_minutes {
            return Err(format!("Duration {} minutes is outside valid range {}-{} minutes", parsed, min_minutes, max_minutes));
        }
        
        Ok(())
    }

    /// Validate a duration (in days) is within the specified range
    /// 
    /// # Arguments
    /// * `value` - String value to validate
    /// * `min_days` - Minimum allowed duration in days
    /// * `max_days` - Maximum allowed duration in days
    /// 
    /// # Returns
    /// * `Ok(())` - Duration is within range
    /// * `Err(String)` - Validation error message
    pub fn validate_duration_days_range(value: &str, min_days: u64, max_days: u64) -> Result<(), String> {
        let parsed = value.parse::<u64>()
            .map_err(|_| format!("Expected duration between {} and {} days", min_days, max_days))?;
        
        if parsed < min_days || parsed > max_days {
            return Err(format!("Duration {} days is outside valid range {}-{} days", parsed, min_days, max_days));
        }
        
        Ok(())
    }

    /// Validate an IPv4 address format (4 dot-separated integers 0-255)
    /// 
    /// # Arguments
    /// * `value` - String value to validate (e.g., "192.168.1.1", "0.0.0.0")
    /// 
    /// # Returns
    /// * `Ok(())` - Valid IPv4 address format
    /// * `Err(String)` - Validation error message
    pub fn validate_ipv4_address(value: &str) -> Result<(), String> {
        let parts: Vec<&str> = value.split('.').collect();
        
        if parts.len() != 4 {
            return Err(format!("IPv4 address must have exactly 4 parts separated by dots, got {}", parts.len()));
        }
        
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(format!("IPv4 address part {} cannot be empty", i + 1));
            }
            
            // Check for leading zeros (except for "0" itself)
            if part.len() > 1 && part.starts_with('0') {
                return Err(format!("IPv4 address part {} cannot have leading zeros: '{}'", i + 1, part));
            }
            
            let octet = part.parse::<u16>()
                .map_err(|_| format!("IPv4 address part {} must be a number: '{}'", i + 1, part))?;
            
            if octet > 255 {
                return Err(format!("IPv4 address part {} must be between 0-255, got {}", i + 1, octet));
            }
        }
        
        Ok(())
    }

    /// Validate a host address (IPv4, IPv6, or hostname) with comprehensive validation
    /// 
    /// This function handles all the complex logic for validating different types of host addresses:
    /// - IPv4 addresses (strict validation with proper octet ranges and no leading zeros)
    /// - IPv6 addresses (basic format validation, must be bracketed)
    /// - Hostnames (basic validation, no whitespace)
    /// 
    /// # Arguments
    /// * `value` - String value to validate
    /// 
    /// # Returns
    /// * `Ok(())` - Valid host address
    /// * `Err(String)` - Validation error message
    pub fn validate_host_address(value: &str) -> Result<(), String> {
        if value.is_empty() {
            return Err("Host address cannot be empty".to_string());
        }
        
        // Check if it looks like IPv6 (contains colons) - do this first
        if value.contains(':') {
            // Allow IPv6 addresses for backward compatibility
            // Basic validation - just ensure it's not empty and has colons
            if value.starts_with('[') && value.ends_with(']') {
                // Bracketed IPv6 - basic validation
                let ipv6_part = &value[1..value.len()-1];
                if ipv6_part.is_empty() || !ipv6_part.contains(':') {
                    return Err("Invalid IPv6 address format".to_string());
                }
            }
            // For unbracketed IPv6, just do basic validation
            return Ok(());
        }
        
        // Check for empty brackets (invalid IPv6)
        if value == "[]" {
            return Err("Invalid IPv6 address format".to_string());
        }
        
        // Check if it looks like IPv4 (contains dots and all parts are numeric)
        if value.contains('.') {
            let parts: Vec<&str> = value.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|part| part.chars().all(|c| c.is_ascii_digit())) {
                // This looks like an IPv4 address, validate it properly
                return Self::validate_ipv4_address(value);
            }
            // Contains dots but not a valid IPv4 pattern, treat as hostname
        }
        
        // Assume it's a hostname - basic validation
        if value.contains(' ') || value.contains('\t') || value.contains('\n') {
            return Err("Host address cannot contain whitespace characters".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::env;

    #[test]
    fn test_parse_duration_minutes() {
        // Valid cases
        assert_eq!(
            ConfigSpec::parse_duration_minutes("15", "test").unwrap(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_minutes("1440", "test").unwrap(),
            Duration::from_secs(1440 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_minutes("0", "test").unwrap(),
            Duration::from_secs(0)
        );

        // Invalid cases
        let result = ConfigSpec::parse_duration_minutes("not_a_number", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::ParseError { setting_name, error } => {
                assert_eq!(setting_name, "test");
                assert!(error.contains("Expected positive integer for minutes"));
            }
            _ => panic!("Expected ParseError"),
        }

        let result = ConfigSpec::parse_duration_minutes("-5", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_days() {
        // Valid cases
        assert_eq!(
            ConfigSpec::parse_duration_days("7", "test").unwrap(),
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_days("365", "test").unwrap(),
            Duration::from_secs(365 * 24 * 60 * 60)
        );

        // Invalid cases
        let result = ConfigSpec::parse_duration_days("not_a_number", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::ParseError { setting_name, error } => {
                assert_eq!(setting_name, "test");
                assert!(error.contains("Expected positive integer for days"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_parse_duration_human() {
        // Minutes
        assert_eq!(
            ConfigSpec::parse_duration_human("15m", "test").unwrap(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_human("30min", "test").unwrap(),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_human("45minutes", "test").unwrap(),
            Duration::from_secs(45 * 60)
        );

        // Hours
        assert_eq!(
            ConfigSpec::parse_duration_human("2h", "test").unwrap(),
            Duration::from_secs(2 * 60 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_human("3hr", "test").unwrap(),
            Duration::from_secs(3 * 60 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_human("4hours", "test").unwrap(),
            Duration::from_secs(4 * 60 * 60)
        );

        // Days
        assert_eq!(
            ConfigSpec::parse_duration_human("1d", "test").unwrap(),
            Duration::from_secs(24 * 60 * 60)
        );
        assert_eq!(
            ConfigSpec::parse_duration_human("7days", "test").unwrap(),
            Duration::from_secs(7 * 24 * 60 * 60)
        );

        // Seconds
        assert_eq!(
            ConfigSpec::parse_duration_human("300s", "test").unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            ConfigSpec::parse_duration_human("600sec", "test").unwrap(),
            Duration::from_secs(600)
        );
        assert_eq!(
            ConfigSpec::parse_duration_human("900seconds", "test").unwrap(),
            Duration::from_secs(900)
        );

        // Plain numbers (default to seconds)
        assert_eq!(
            ConfigSpec::parse_duration_human("120", "test").unwrap(),
            Duration::from_secs(120)
        );

        // Case insensitive
        assert_eq!(
            ConfigSpec::parse_duration_human("15M", "test").unwrap(),
            Duration::from_secs(15 * 60)
        );

        // Invalid cases
        let result = ConfigSpec::parse_duration_human("15x", "test");
        assert!(result.is_err());
        
        let result = ConfigSpec::parse_duration_human("not_a_number", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bool() {
        // True values
        assert_eq!(ConfigSpec::parse_bool("true", "test").unwrap(), true);
        assert_eq!(ConfigSpec::parse_bool("TRUE", "test").unwrap(), true);
        assert_eq!(ConfigSpec::parse_bool("1", "test").unwrap(), true);
        assert_eq!(ConfigSpec::parse_bool("yes", "test").unwrap(), true);
        assert_eq!(ConfigSpec::parse_bool("YES", "test").unwrap(), true);
        assert_eq!(ConfigSpec::parse_bool("on", "test").unwrap(), true);
        assert_eq!(ConfigSpec::parse_bool("enabled", "test").unwrap(), true);

        // False values
        assert_eq!(ConfigSpec::parse_bool("false", "test").unwrap(), false);
        assert_eq!(ConfigSpec::parse_bool("FALSE", "test").unwrap(), false);
        assert_eq!(ConfigSpec::parse_bool("0", "test").unwrap(), false);
        assert_eq!(ConfigSpec::parse_bool("no", "test").unwrap(), false);
        assert_eq!(ConfigSpec::parse_bool("NO", "test").unwrap(), false);
        assert_eq!(ConfigSpec::parse_bool("off", "test").unwrap(), false);
        assert_eq!(ConfigSpec::parse_bool("disabled", "test").unwrap(), false);

        // Whitespace handling
        assert_eq!(ConfigSpec::parse_bool(" true ", "test").unwrap(), true);
        assert_eq!(ConfigSpec::parse_bool(" false ", "test").unwrap(), false);

        // Invalid cases
        let result = ConfigSpec::parse_bool("invalid", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::ParseError { setting_name, error } => {
                assert_eq!(setting_name, "test");
                assert!(error.contains("Expected boolean value"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_parse_integer() {
        // Valid cases
        assert_eq!(ConfigSpec::parse_integer("42", "test").unwrap(), 42);
        assert_eq!(ConfigSpec::parse_integer("-42", "test").unwrap(), -42);
        assert_eq!(ConfigSpec::parse_integer("0", "test").unwrap(), 0);
        assert_eq!(ConfigSpec::parse_integer(" 123 ", "test").unwrap(), 123);

        // Invalid cases
        let result = ConfigSpec::parse_integer("not_a_number", "test");
        assert!(result.is_err());
        
        let result = ConfigSpec::parse_integer("12.34", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port() {
        // Valid cases
        assert_eq!(ConfigSpec::parse_port("80", "test").unwrap(), 80);
        assert_eq!(ConfigSpec::parse_port("443", "test").unwrap(), 443);
        assert_eq!(ConfigSpec::parse_port("3000", "test").unwrap(), 3000);
        assert_eq!(ConfigSpec::parse_port("65535", "test").unwrap(), 65535);

        // Invalid cases - port 0
        let result = ConfigSpec::parse_port("0", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "test");
                assert!(reason.contains("Port number must be between 1 and 65535"));
            }
            _ => panic!("Expected InvalidSetting"),
        }

        // Invalid cases - not a number
        let result = ConfigSpec::parse_port("not_a_number", "test");
        assert!(result.is_err());

        // Invalid cases - too large
        let result = ConfigSpec::parse_port("70000", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host() {
        // Valid cases
        assert_eq!(ConfigSpec::parse_host("localhost", "test").unwrap(), "localhost");
        assert_eq!(ConfigSpec::parse_host("127.0.0.1", "test").unwrap(), "127.0.0.1");
        assert_eq!(ConfigSpec::parse_host("0.0.0.0", "test").unwrap(), "0.0.0.0");
        assert_eq!(ConfigSpec::parse_host("[::1]", "test").unwrap(), "[::1]");
        assert_eq!(ConfigSpec::parse_host("[2001:db8::1]", "test").unwrap(), "[2001:db8::1]");
        assert_eq!(ConfigSpec::parse_host("example.com", "test").unwrap(), "example.com");

        // Invalid cases - empty
        let result = ConfigSpec::parse_host("", "test");
        assert!(result.is_err());

        // Invalid cases - whitespace
        let result = ConfigSpec::parse_host("local host", "test");
        assert!(result.is_err());

        // Invalid cases - IPv6 without brackets
        let result = ConfigSpec::parse_host("2001:db8::1", "test");
        assert!(result.is_err());

        // Invalid cases - malformed IPv6
        let result = ConfigSpec::parse_host("[]", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_string() {
        // Valid cases
        assert_eq!(
            ConfigSpec::parse_string("hello", "test", None, None).unwrap(),
            "hello"
        );
        assert_eq!(
            ConfigSpec::parse_string("hello", "test", Some(3), Some(10)).unwrap(),
            "hello"
        );

        // Invalid cases - too short
        let result = ConfigSpec::parse_string("hi", "test", Some(5), None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "test");
                assert!(reason.contains("must be at least 5 characters long"));
            }
            _ => panic!("Expected InvalidSetting"),
        }

        // Invalid cases - too long
        let result = ConfigSpec::parse_string("very long string", "test", None, Some(5));
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "test");
                assert!(reason.contains("must be at most 5 characters long"));
            }
            _ => panic!("Expected InvalidSetting"),
        }
    }

    #[test]
    fn test_range_validators() {
        // Integer range validation
        assert!(ConfigSpec::validate_integer_range("50", 1, 100).is_ok());
        assert!(ConfigSpec::validate_integer_range("1", 1, 100).is_ok());
        assert!(ConfigSpec::validate_integer_range("100", 1, 100).is_ok());
        assert!(ConfigSpec::validate_integer_range("0", 1, 100).is_err());
        assert!(ConfigSpec::validate_integer_range("101", 1, 100).is_err());
        assert!(ConfigSpec::validate_integer_range("not_a_number", 1, 100).is_err());

        // Port range validation
        assert!(ConfigSpec::validate_port_range("3000", 1024, 65535).is_ok());
        assert!(ConfigSpec::validate_port_range("1024", 1024, 65535).is_ok());
        assert!(ConfigSpec::validate_port_range("65535", 1024, 65535).is_ok());
        assert!(ConfigSpec::validate_port_range("80", 1024, 65535).is_err());
        assert!(ConfigSpec::validate_port_range("70000", 1024, 65535).is_err());

        // Duration minutes range validation
        assert!(ConfigSpec::validate_duration_minutes_range("15", 1, 1440).is_ok());
        assert!(ConfigSpec::validate_duration_minutes_range("1", 1, 1440).is_ok());
        assert!(ConfigSpec::validate_duration_minutes_range("1440", 1, 1440).is_ok());
        assert!(ConfigSpec::validate_duration_minutes_range("0", 1, 1440).is_err());
        assert!(ConfigSpec::validate_duration_minutes_range("1441", 1, 1440).is_err());

        // Duration days range validation
        assert!(ConfigSpec::validate_duration_days_range("7", 1, 365).is_ok());
        assert!(ConfigSpec::validate_duration_days_range("1", 1, 365).is_ok());
        assert!(ConfigSpec::validate_duration_days_range("365", 1, 365).is_ok());
        assert!(ConfigSpec::validate_duration_days_range("0", 1, 365).is_err());
        assert!(ConfigSpec::validate_duration_days_range("366", 1, 365).is_err());
    }

    #[test]
    fn test_validate_ipv4_address() {
        // Valid IPv4 addresses
        assert!(ConfigSpec::validate_ipv4_address("0.0.0.0").is_ok());
        assert!(ConfigSpec::validate_ipv4_address("127.0.0.1").is_ok());
        assert!(ConfigSpec::validate_ipv4_address("192.168.1.1").is_ok());
        assert!(ConfigSpec::validate_ipv4_address("255.255.255.255").is_ok());
        assert!(ConfigSpec::validate_ipv4_address("10.0.0.1").is_ok());

        // Invalid IPv4 addresses - wrong number of parts
        assert!(ConfigSpec::validate_ipv4_address("192.168.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("192.168.1.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("192").is_err());

        // Invalid IPv4 addresses - empty parts
        assert!(ConfigSpec::validate_ipv4_address("192..1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address(".168.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("192.168.1.").is_err());

        // Invalid IPv4 addresses - out of range
        assert!(ConfigSpec::validate_ipv4_address("256.1.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("1.256.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("1.1.256.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("1.1.1.256").is_err());

        // Invalid IPv4 addresses - leading zeros
        assert!(ConfigSpec::validate_ipv4_address("01.1.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("1.01.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("192.168.001.1").is_err());

        // Invalid IPv4 addresses - non-numeric
        assert!(ConfigSpec::validate_ipv4_address("abc.1.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("1.abc.1.1").is_err());
        assert!(ConfigSpec::validate_ipv4_address("1.1.1.abc").is_err());
    }

    #[test]
    fn test_validate_host_address() {
        // Valid IPv4 addresses
        assert!(ConfigSpec::validate_host_address("127.0.0.1").is_ok());
        assert!(ConfigSpec::validate_host_address("192.168.1.1").is_ok());
        assert!(ConfigSpec::validate_host_address("0.0.0.0").is_ok());
        assert!(ConfigSpec::validate_host_address("255.255.255.255").is_ok());

        // Valid hostnames
        assert!(ConfigSpec::validate_host_address("localhost").is_ok());
        assert!(ConfigSpec::validate_host_address("example.com").is_ok());
        assert!(ConfigSpec::validate_host_address("api.example.com").is_ok());

        // Valid IPv6 addresses (basic validation)
        assert!(ConfigSpec::validate_host_address("::1").is_ok());
        assert!(ConfigSpec::validate_host_address("[::1]").is_ok());
        assert!(ConfigSpec::validate_host_address("[2001:db8::1]").is_ok());

        // Invalid - empty
        assert!(ConfigSpec::validate_host_address("").is_err());

        // Invalid - whitespace
        assert!(ConfigSpec::validate_host_address("local host").is_err());
        assert!(ConfigSpec::validate_host_address("127.0.0.1 ").is_err());
        assert!(ConfigSpec::validate_host_address(" 127.0.0.1").is_err());

        // Invalid IPv4 addresses (should use strict validation)
        assert!(ConfigSpec::validate_host_address("256.1.1.1").is_err());
        assert!(ConfigSpec::validate_host_address("192.168.01.1").is_err());
        assert!(ConfigSpec::validate_host_address("300.300.300.300").is_err());

        

        // Edge cases - dots but not IPv4
        assert!(ConfigSpec::validate_host_address("example.com").is_ok()); // hostname with dots
        assert!(ConfigSpec::validate_host_address("1.2.3").is_ok()); // not 4 parts, treated as hostname
        assert!(ConfigSpec::validate_host_address("1.2.3.a").is_ok()); // non-numeric part, treated as hostname
    }

    #[test]
    fn test_load_setting_with_source_env_override() {
        // Test that environment variable override works (synchronously)
        unsafe {
            env::set_var("TEST_SETTING", "env_value");
        }
        
        let spec = ConfigSpec::new()
            .env_override("TEST_SETTING")
            .default_value("default_value");
        
        let result = spec.load_setting_with_source(None).unwrap();
        
        assert_eq!(result.value, "env_value");
        assert!(matches!(result.source, ConfigValueSource::EnvironmentVariable { .. }));
        assert!(!result.is_mutable);
        
        unsafe {
            env::remove_var("TEST_SETTING");
        }
    }

    #[test]
    fn test_load_setting_with_source_default() {
        // Test that default value works when no env var is set
        unsafe {
            env::remove_var("TEST_SETTING_DEFAULT");
        }
        
        let spec = ConfigSpec::new()
            .env_override("TEST_SETTING_DEFAULT")
            .default_value("default_value");
        
        let result = spec.load_setting_with_source(None).unwrap();
        
        assert_eq!(result.value, "default_value");
        assert!(matches!(result.source, ConfigValueSource::Default));
        assert!(!result.is_mutable); // No persistent source, so not mutable
    }

    #[test]
    fn test_load_setting_with_source_validation() {
        // Test that validation works in the synchronous version
        unsafe {
            env::set_var("TEST_SETTING_VALIDATION", "short");
        }
        
        let spec = ConfigSpec::new()
            .env_override("TEST_SETTING_VALIDATION")
            .min_length(10);
        
        let result = spec.load_setting_with_source(None);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "TEST_SETTING_VALIDATION");
                assert!(reason.contains("at least 10 characters"));
            }
            _ => panic!("Expected InvalidSetting error"),
        }
        
        unsafe {
            env::remove_var("TEST_SETTING_VALIDATION");
        }
    }
}
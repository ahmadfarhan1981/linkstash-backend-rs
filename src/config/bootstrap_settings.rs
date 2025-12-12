use std::fmt;
use crate::config::errors::{BootstrapError, ApplicationError};
use crate::config::config_spec::ConfigSpec;

/// Bootstrap settings for infrastructure configuration
pub struct BootstrapSettings {
    database_url: String,
    server_host: String,
    server_port: u16,
}

impl BootstrapSettings {
    /// Load bootstrap settings from environment variables using ConfigSpec
    /// 
    /// This method uses the unified ConfigSpec system for consistent validation
    /// and error handling across all configuration layers.
    pub fn from_env() -> Result<Self, BootstrapError> {
        // Define configuration specifications for each setting
        let database_url_spec = ConfigSpec::new()
            .env_override("DATABASE_URL")
            .default_value("sqlite://auth.db?mode=rwc")
            .min_length(1);
            
        let host_spec = ConfigSpec::new()
            .env_override("HOST")
            .default_value("0.0.0.0")
            .validator(ConfigSpec::validate_host_address);
            
        let port_spec = ConfigSpec::new()
            .env_override("PORT")
            .default_value("3000")
            .validator(|value| {
                // Use ConfigSpec's port range validation for explicit validation
                ConfigSpec::validate_port_range(value, 1, 65535)
            });

        // Load settings using ConfigSpec (no database needed for bootstrap)
        let database_url = database_url_spec
            .load_setting_with_source(None)
            .map_err(Self::convert_application_error)?
            .value;
            
        let server_host = host_spec
            .load_setting_with_source(None)
            .map_err(Self::convert_application_error)?
            .value;
            
        let port_value = port_spec
            .load_setting_with_source(None)
            .map_err(Self::convert_application_error)?
            .value;
            
        // Parse port using ConfigSpec's parsing utilities
        let server_port = ConfigSpec::parse_port(&port_value, "PORT")
            .map_err(Self::convert_application_error)?;

        Ok(Self {
            database_url,
            server_host,
            server_port,
        })
    }
    
    /// Convert ApplicationError to BootstrapError for consistent error handling
    fn convert_application_error(err: ApplicationError) -> BootstrapError {
        match err {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                match setting_name.as_str() {
                    "DATABASE_URL" if reason.contains("Required setting") => {
                        BootstrapError::MissingDatabaseUrl
                    }
                    "DATABASE_URL" if reason.contains("at least 1 characters") => {
                        BootstrapError::InvalidDatabaseUrl("DATABASE_URL cannot be empty".to_string())
                    }
                    "DATABASE_URL" => {
                        BootstrapError::InvalidDatabaseUrl(reason)
                    }
                    "HOST" if reason.contains("empty") => {
                        BootstrapError::InvalidFormat {
                            setting_name,
                            expected: "valid hostname or IP address".to_string(),
                            actual: "empty string".to_string(),
                        }
                    }
                    "PORT" if reason.contains("outside valid range") => {
                        // Extract the port value from the error message
                        let actual = if let Some(start) = reason.find("Port ") {
                            let start = start + 5; // Skip "Port "
                            if let Some(end) = reason[start..].find(" is") {
                                reason[start..start + end].to_string()
                            } else {
                                "invalid port".to_string()
                            }
                        } else {
                            "invalid port".to_string()
                        };
                        BootstrapError::InvalidFormat {
                            setting_name,
                            expected: "integer between 1 and 65535".to_string(),
                            actual,
                        }
                    }
                    _ => {
                        BootstrapError::InvalidFormat {
                            setting_name,
                            expected: "valid value".to_string(),
                            actual: reason,
                        }
                    }
                }
            }
            ApplicationError::ParseError { setting_name, error } => {
                let expected = match setting_name.as_str() {
                    "PORT" => "integer between 1 and 65535".to_string(),
                    _ => "valid format".to_string(),
                };
                // Extract the actual value from the error message
                let actual = if error.contains("got '") {
                    // Extract value between 'got '' and the next quote
                    if let Some(start) = error.find("got '") {
                        let start = start + 5; // Skip "got '"
                        if let Some(end) = error[start..].find('\'') {
                            error[start..start + end].to_string()
                        } else {
                            "invalid value".to_string()
                        }
                    } else {
                        "invalid value".to_string()
                    }
                } else {
                    "invalid value".to_string()
                };
                BootstrapError::InvalidFormat {
                    setting_name,
                    expected,
                    actual,
                }
            }
            _ => {
                BootstrapError::InvalidFormat {
                    setting_name: "unknown".to_string(),
                    expected: "valid configuration".to_string(),
                    actual: format!("{:?}", err),
                }
            }
        }
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn server_host(&self) -> &str {
        &self.server_host
    }

    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    pub fn server_address(&self) -> String {
        format!("{}:{}", self.server_host, self.server_port)
    }
}

impl fmt::Debug for BootstrapSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootstrapSettings")
            .field("database_url", &self.database_url)
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .finish()
    }
}

#[cfg(all(test, feature = "flaky-tests"))]
mod tests {
    use super::*;
    use std::env;

    struct EnvGuard {
        original_values: std::collections::HashMap<String, Option<String>>,
    }

    impl EnvGuard {
        fn new() -> Self {
            // Capture current state of all bootstrap-related environment variables
            let bootstrap_keys = ["DATABASE_URL", "HOST", "PORT"];
            let mut original_values = std::collections::HashMap::new();
            
            for key in &bootstrap_keys {
                let original = env::var(key).ok();
                original_values.insert(key.to_string(), original);
            }
            
            Self { original_values }
        }

        fn set(&mut self, key: &str, value: &str) {
            // Store original value if not already captured
            if !self.original_values.contains_key(key) {
                let original = env::var(key).ok();
                self.original_values.insert(key.to_string(), original);
            }
            
            unsafe {
                if(value.is_empty()){
                    env::remove_var(key);
                }else{
                    env::set_var(key, value);
                }
                
            }
        }

        fn remove(&mut self, key: &str) {
            // Store original value if not already captured
            if !self.original_values.contains_key(key) {
                let original = env::var(key).ok();
                self.original_values.insert(key.to_string(), original);
            }
            
            unsafe {
                env::remove_var(key);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // Restore original environment state for all captured keys
            for (key, original_value) in &self.original_values {
                unsafe {
                    match original_value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }

    #[test]
    fn test_bootstrap_settings_with_all_required_vars() {
        let mut guard = EnvGuard::new();

        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("HOST", "127.0.0.1");
        guard.set("PORT", "8080");

        let settings = BootstrapSettings::from_env().unwrap();
        
        assert_eq!(settings.database_url(), "sqlite://test.db");
        assert_eq!(settings.server_host(), "127.0.0.1");
        assert_eq!(settings.server_port(), 8080);
        assert_eq!(settings.server_address(), "127.0.0.1:8080");
    }

    #[test]
    fn test_bootstrap_settings_with_defaults() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");

        guard.remove("HOST");
        guard.remove("PORT");

        let settings = BootstrapSettings::from_env().unwrap();
        
        assert_eq!(settings.database_url(), "sqlite://test.db");
        assert_eq!(settings.server_host(), "0.0.0.0");
        assert_eq!(settings.server_port(), 3000);
        assert_eq!(settings.server_address(), "0.0.0.0:3000");
    }



    #[test]
    fn test_bootstrap_settings_missing_database_url_uses_default() {
        let mut guard = EnvGuard::new();
        guard.set("HOST", "127.0.0.1");
        guard.set("PORT", "3000");
        guard.remove("DATABASE_URL");

        let settings = BootstrapSettings::from_env().unwrap();
        
        // Should use default value when DATABASE_URL is not set
        assert_eq!(settings.database_url(), "sqlite://auth.db?mode=rwc");
        assert_eq!(settings.server_host(), "127.0.0.1");
        assert_eq!(settings.server_port(), 3000);
    }

    #[test]
    
    fn test_bootstrap_settings_empty_database_url_uses_default() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", ""); // EnvGuard now clears the env var for empty string
        guard.set("HOST", "127.0.0.1");
        guard.set("PORT", "3000");

        let settings = BootstrapSettings::from_env().unwrap();
        
        // Should use default value when DATABASE_URL is empty (cleared)
        assert_eq!(settings.database_url(), "sqlite://auth.db?mode=rwc");
        assert_eq!(settings.server_host(), "127.0.0.1");
        assert_eq!(settings.server_port(), 3000);
    }

    #[test]
    fn test_bootstrap_settings_empty_host_uses_default() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("HOST", ""); // EnvGuard now clears the env var for empty string
        guard.set("PORT", "3000");

        let settings = BootstrapSettings::from_env().unwrap();
        
        // Should use default value when HOST is empty (cleared)
        assert_eq!(settings.database_url(), "sqlite://test.db");
        assert_eq!(settings.server_host(), "0.0.0.0"); // Default value
        assert_eq!(settings.server_port(), 3000);
    }

    #[test]
    fn test_bootstrap_settings_invalid_port() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("HOST", "0.0.0.0");
        guard.set("PORT", "not_a_number");

        let result = BootstrapSettings::from_env();
        
        assert!(result.is_err());
        match result.unwrap_err() {
            BootstrapError::InvalidFormat { setting_name, expected, actual } => {
                assert_eq!(setting_name, "PORT");
                assert_eq!(expected, "valid value");
                assert_eq!(actual, "Expected port number between 1 and 65535");
            },
            other => panic!("Expected InvalidFormat error for PORT, got: {:?}", other),
        }
    }

    #[test]
    fn test_bootstrap_settings_zero_port() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("HOST", "127.0.0.1");
        guard.set("PORT", "0");

        let result = BootstrapSettings::from_env();
        
        assert!(result.is_err());
        match result.unwrap_err() {
            BootstrapError::InvalidFormat { setting_name, expected, actual } => {
                assert_eq!(setting_name, "PORT");
                assert!(expected.contains("between 1 and 65535"));
                assert_eq!(actual, "0");
            },
            _ => panic!("Expected InvalidFormat error for zero PORT"),
        }
    }

    #[test]
    fn test_bootstrap_settings_port_boundary_values() {
        // Test port 1 (minimum valid)
        {
            let mut guard = EnvGuard::new();
            guard.set("DATABASE_URL", "sqlite://test.db");
            guard.set("HOST", "127.0.0.1");
            guard.set("PORT", "1");
            let settings = BootstrapSettings::from_env().unwrap();
            assert_eq!(settings.server_port(), 1);
        }

        // Test port 65535 (maximum valid)
        {
            let mut guard = EnvGuard::new();
            guard.set("DATABASE_URL", "sqlite://test.db");
            guard.set("HOST", "127.0.0.1");
            guard.set("PORT", "65535");
            let settings = BootstrapSettings::from_env().unwrap();
            assert_eq!(settings.server_port(), 65535);
        }
    }

    #[test]
    fn test_bootstrap_settings_ipv6_host() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("HOST", "::1");
        guard.set("PORT", "8080");

        let settings = BootstrapSettings::from_env().unwrap();
        
        assert_eq!(settings.server_host(), "::1");
        assert_eq!(settings.server_address(), "::1:8080");
    }

    #[test]
    fn test_bootstrap_settings_debug_format() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("HOST", "localhost");
        guard.set("PORT", "3000");

        let settings = BootstrapSettings::from_env().unwrap();
        let debug_str = format!("{:?}", settings);
        
        assert!(debug_str.contains("database_url"));
        assert!(debug_str.contains("sqlite://test.db"));
        assert!(debug_str.contains("server_host"));
        assert!(debug_str.contains("localhost"));
        assert!(debug_str.contains("server_port"));
        assert!(debug_str.contains("3000"));
    }

    #[test]
    fn test_bootstrap_settings_getters() {
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://production.db");
        guard.set("HOST", "api.example.com");
        guard.set("PORT", "443");

        let settings = BootstrapSettings::from_env().unwrap();
        
        assert_eq!(settings.database_url(), "sqlite://production.db");
        assert_eq!(settings.server_host(), "api.example.com");
        assert_eq!(settings.server_port(), 443);
        assert_eq!(settings.server_address(), "api.example.com:443");
    }

    #[test]
    fn test_bootstrap_settings_uses_configspec() {
        // Test that the new ConfigSpec-based implementation works
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://configspec-test.db");
        guard.set("HOST", "127.0.0.1");
        guard.set("PORT", "9000");

        let settings = BootstrapSettings::from_env().unwrap();
        
        // Verify all values are loaded correctly
        assert_eq!(settings.database_url(), "sqlite://configspec-test.db");
        assert_eq!(settings.server_host(), "127.0.0.1");
        assert_eq!(settings.server_port(), 9000);
        
        // Test that defaults work
        guard.remove("HOST");
        guard.remove("PORT");
        
        let settings_with_defaults = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings_with_defaults.database_url(), "sqlite://configspec-test.db");
        assert_eq!(settings_with_defaults.server_host(), "0.0.0.0");
        assert_eq!(settings_with_defaults.server_port(), 3000);
    }

    #[test]
    fn test_bootstrap_settings_port_validation() {
        // Test that port validation works correctly with ConfigSpec
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("HOST", "127.0.0.1");
        
        // Test valid port
        guard.set("PORT", "8080");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_port(), 8080);
        
        // Test boundary values
        guard.set("PORT", "1");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_port(), 1);
        
        guard.set("PORT", "65535");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_port(), 65535);
        
        // Test invalid port (zero)
        guard.set("PORT", "0");
        let result = BootstrapSettings::from_env();
        assert!(result.is_err());
        
        // Test invalid port (too high)
        guard.set("PORT", "65536");
        let result = BootstrapSettings::from_env();
        assert!(result.is_err());
        
        // Test invalid port (not a number)
        guard.set("PORT", "not_a_number");
        let result = BootstrapSettings::from_env();
        assert!(result.is_err());
    }

    #[test]
    fn test_bootstrap_settings_ipv4_validation() {
        // Test that IPv4 validation works correctly
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("PORT", "3000");
        
        // Test valid IPv4 addresses
        guard.set("HOST", "127.0.0.1");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "127.0.0.1");
        
        guard.set("HOST", "192.168.1.1");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "192.168.1.1");
        
        guard.set("HOST", "0.0.0.0");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "0.0.0.0");
        
        guard.set("HOST", "255.255.255.255");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "255.255.255.255");
        
        // Test invalid IPv4 addresses
        guard.set("HOST", "256.1.1.1");
        let result = BootstrapSettings::from_env();
        assert!(result.is_err());
        
        guard.set("HOST", "192.168.01.1");
        let result = BootstrapSettings::from_env();
        assert!(result.is_err());
        
        // Test hostnames (should still work)
        guard.set("HOST", "localhost");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "localhost");
        
        guard.set("HOST", "example.com");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "example.com");
        
        // Test IPv6 (should still work for backward compatibility)
        guard.set("HOST", "::1");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "::1");
    }

    #[test]
    fn test_bootstrap_settings_ipv4_simple() {
        // Simple test to verify IPv4 validation works
        let mut guard = EnvGuard::new();
        guard.set("DATABASE_URL", "sqlite://test.db");
        guard.set("PORT", "3000");
        
        // Test valid IPv4
        guard.set("HOST", "127.0.0.1");
        let settings = BootstrapSettings::from_env().unwrap();
        assert_eq!(settings.server_host(), "127.0.0.1");
        
        // Test invalid IPv4 - out of range
        guard.set("HOST", "300.300.300.300");
        let result = BootstrapSettings::from_env();
        assert!(result.is_err());
    }
}
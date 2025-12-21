use std::fmt;
use std::sync::Arc;
use crate::config::errors::ApplicationError;
use crate::config::config_spec::ConfigSpec;
use crate::config::EnvironmentProvider;

/// Bootstrap settings for infrastructure configuration
pub struct BootstrapSettings {
    database_url: String,
    audit_database_url:String,
    server_host: String,
    server_port: u16,
}

impl BootstrapSettings {
    /// Load bootstrap settings from environment variables using ConfigSpec
    /// 
    /// This method uses the unified ConfigSpec system for consistent validation
    /// and error handling across all configuration layers.
    pub fn from_env_provider(env_provider: Arc<dyn EnvironmentProvider + Send + Sync>) -> Result<Self, ApplicationError> {
        // Define configuration specifications for each setting
        // Use the provided Arc for sharing across ConfigSpecs
        
        let database_url_spec = ConfigSpec::new(env_provider.clone())
            .env_override("DATABASE_URL")
            .default_value("sqlite://auth.db?mode=rwc")
            .min_length(1);
        
        let audit_database_url_spec = ConfigSpec::new(env_provider.clone())
            .env_override("AUDIT_DATABASE_URL")
            .default_value("sqlite://audit.db?mode=rwc")
            .min_length(1);

        let host_spec = ConfigSpec::new(env_provider.clone())
            .env_override("HOST")
            .default_value("0.0.0.0")
            .validator(ConfigSpec::validate_host_address);
            
        let port_spec = ConfigSpec::new(env_provider.clone())
            .env_override("PORT")
            .default_value("3000")
            .validator(|value| {
                // Use ConfigSpec's port range validation for explicit validation
                ConfigSpec::validate_port_range(value, 1, 65535)
            });

        // Load settings using ConfigSpec (no database needed for bootstrap)
        let database_url = database_url_spec
            .load_setting_with_source(None)?
            .value;
        
        let audit_database_url = audit_database_url_spec
            .load_setting_with_source(None)?
            .value;
            
        let server_host = host_spec
            .load_setting_with_source(None)?
            .value;
            
        let port_value = port_spec
            .load_setting_with_source(None)?
            .value;
            
        // Parse port using ConfigSpec's parsing utilities
        let server_port = ConfigSpec::parse_port(&port_value, "PORT")?;

        Ok(Self {
            audit_database_url,
            database_url,
            server_host,
            server_port,
        })
    }

    /// Convenience method that uses the system environment provider
    pub fn from_env() -> Result<Self, ApplicationError> {
        use crate::config::SystemEnvironment;
        Self::from_env_provider(Arc::new(SystemEnvironment))
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }
    pub fn audit_database_url(&self) -> &str {
        &self.audit_database_url
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MockEnvironment;
    use std::collections::HashMap;

    fn create_test_env(vars: HashMap<String, String>) -> Arc<MockEnvironment> {
        Arc::new(MockEnvironment::new(vars))
    }

    #[test]
    fn test_bootstrap_settings_with_all_required_vars() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "8080".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        
        assert_eq!(settings.database_url(), "sqlite://test.db");
        assert_eq!(settings.server_host(), "127.0.0.1");
        assert_eq!(settings.server_port(), 8080);
        assert_eq!(settings.server_address(), "127.0.0.1:8080");
    }

    #[test]
    fn test_bootstrap_settings_with_defaults() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        
        assert_eq!(settings.database_url(), "sqlite://test.db");
        assert_eq!(settings.server_host(), "0.0.0.0");
        assert_eq!(settings.server_port(), 3000);
        assert_eq!(settings.server_address(), "0.0.0.0:3000");
    }

    #[test]
    fn test_bootstrap_settings_missing_database_url_uses_default() {
        let env_vars = HashMap::from([
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "3000".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        
        // Should use default value when DATABASE_URL is not set
        assert_eq!(settings.database_url(), "sqlite://auth.db?mode=rwc");
        assert_eq!(settings.server_host(), "127.0.0.1");
        assert_eq!(settings.server_port(), 3000);
    }

    #[test]
    fn test_bootstrap_settings_empty_database_url_fails_validation() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "3000".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let result = BootstrapSettings::from_env_provider(env_provider);
        
        // Empty DATABASE_URL should fail validation (minimum length requirement)
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "DATABASE_URL");
                assert!(reason.contains("must be at least 1 characters long"));
            },
            other => panic!("Expected InvalidSetting for DATABASE_URL, got: {:?}", other),
        }
    }

    #[test]
    fn test_bootstrap_settings_empty_host_fails_validation() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "".to_string()),
            ("PORT".to_string(), "3000".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let result = BootstrapSettings::from_env_provider(env_provider);
        
        // Empty HOST should fail validation
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "HOST");
                assert!(reason.contains("cannot be empty"));
            },
            other => panic!("Expected InvalidSetting for HOST, got: {:?}", other),
        }
    }

    #[test]
    fn test_bootstrap_settings_invalid_port() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "0.0.0.0".to_string()),
            ("PORT".to_string(), "not_a_number".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let result = BootstrapSettings::from_env_provider(env_provider);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "PORT");
                assert!(reason.contains("Expected port number between 1 and 65535"));
            },
            other => panic!("Expected InvalidSetting for PORT, got: {:?}", other),
        }
    }

    #[test]
    fn test_bootstrap_settings_zero_port() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "0".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let result = BootstrapSettings::from_env_provider(env_provider);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::InvalidSetting { setting_name, reason } => {
                assert_eq!(setting_name, "PORT");
                assert!(reason.contains("outside valid range"));
            },
            _ => panic!("Expected InvalidSetting error for zero PORT"),
        }
    }

    #[test]
    fn test_bootstrap_settings_port_boundary_values() {
        // Test port 1 (minimum valid)
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "1".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        assert_eq!(settings.server_port(), 1);

        // Test port 65535 (maximum valid)
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "65535".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        assert_eq!(settings.server_port(), 65535);
    }

    #[test]
    fn test_bootstrap_settings_ipv6_host() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "::1".to_string()),
            ("PORT".to_string(), "8080".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        
        assert_eq!(settings.server_host(), "::1");
        assert_eq!(settings.server_address(), "::1:8080");
    }

    #[test]
    fn test_bootstrap_settings_debug_format() {
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "localhost".to_string()),
            ("PORT".to_string(), "3000".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
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
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://production.db".to_string()),
            ("HOST".to_string(), "api.example.com".to_string()),
            ("PORT".to_string(), "443".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        
        assert_eq!(settings.database_url(), "sqlite://production.db");
        assert_eq!(settings.server_host(), "api.example.com");
        assert_eq!(settings.server_port(), 443);
        assert_eq!(settings.server_address(), "api.example.com:443");
    }

    #[test]
    fn test_bootstrap_settings_uses_configspec() {
        // Test that the new ConfigSpec-based implementation works
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://configspec-test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "9000".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);

        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        
        // Verify all values are loaded correctly
        assert_eq!(settings.database_url(), "sqlite://configspec-test.db");
        assert_eq!(settings.server_host(), "127.0.0.1");
        assert_eq!(settings.server_port(), 9000);
        
        // Test that defaults work
        let env_vars_defaults = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://configspec-test.db".to_string()),
        ]);
        let env_provider_defaults = create_test_env(env_vars_defaults);
        
        let settings_with_defaults = BootstrapSettings::from_env_provider(env_provider_defaults).unwrap();
        assert_eq!(settings_with_defaults.database_url(), "sqlite://configspec-test.db");
        assert_eq!(settings_with_defaults.server_host(), "0.0.0.0");
        assert_eq!(settings_with_defaults.server_port(), 3000);
    }

    #[test]
    fn test_bootstrap_settings_port_validation() {
        // Test valid port
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "8080".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        assert_eq!(settings.server_port(), 8080);
        
        // Test boundary values
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "1".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        assert_eq!(settings.server_port(), 1);
        
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "65535".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        assert_eq!(settings.server_port(), 65535);
        
        // Test invalid port (zero)
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "0".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let result = BootstrapSettings::from_env_provider(env_provider);
        assert!(result.is_err());
        
        // Test invalid port (too high)
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "65536".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let result = BootstrapSettings::from_env_provider(env_provider);
        assert!(result.is_err());
        
        // Test invalid port (not a number)
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "not_a_number".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let result = BootstrapSettings::from_env_provider(env_provider);
        assert!(result.is_err());
    }

    #[test]
    fn test_bootstrap_settings_ipv4_validation() {
        // Test valid IPv4 addresses
        let test_cases = vec![
            "127.0.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
        ];
        
        for host in test_cases {
            let env_vars = HashMap::from([
                ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
                ("HOST".to_string(), host.to_string()),
                ("PORT".to_string(), "3000".to_string()),
            ]);
            let env_provider = create_test_env(env_vars);
            let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
            assert_eq!(settings.server_host(), host);
        }
        
        // Test invalid IPv4 addresses
        let invalid_cases = vec![
            "256.1.1.1",
            "192.168.01.1",
            "300.300.300.300",
        ];
        
        for host in invalid_cases {
            let env_vars = HashMap::from([
                ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
                ("HOST".to_string(), host.to_string()),
                ("PORT".to_string(), "3000".to_string()),
            ]);
            let env_provider = create_test_env(env_vars);
            let result = BootstrapSettings::from_env_provider(env_provider);
            assert!(result.is_err(), "Expected error for invalid host: {}", host);
        }
        
        // Test hostnames (should still work)
        let hostname_cases = vec![
            "localhost",
            "example.com",
            "::1", // IPv6
        ];
        
        for host in hostname_cases {
            let env_vars = HashMap::from([
                ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
                ("HOST".to_string(), host.to_string()),
                ("PORT".to_string(), "3000".to_string()),
            ]);
            let env_provider = create_test_env(env_vars);
            let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
            assert_eq!(settings.server_host(), host);
        }
    }

    #[test]
    fn test_bootstrap_settings_ipv4_simple() {
        // Test valid IPv4
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
            ("PORT".to_string(), "3000".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let settings = BootstrapSettings::from_env_provider(env_provider).unwrap();
        assert_eq!(settings.server_host(), "127.0.0.1");
        
        // Test invalid IPv4 - out of range
        let env_vars = HashMap::from([
            ("DATABASE_URL".to_string(), "sqlite://test.db".to_string()),
            ("HOST".to_string(), "300.300.300.300".to_string()),
            ("PORT".to_string(), "3000".to_string()),
        ]);
        let env_provider = create_test_env(env_vars);
        let result = BootstrapSettings::from_env_provider(env_provider);
        assert!(result.is_err());
    }
}
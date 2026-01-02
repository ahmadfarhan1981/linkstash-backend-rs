use crate::config::{SecretConfig, SecretType};
use std::fmt;

/// Custom error type for secret-related failures
#[derive(Debug)]
pub enum SecretError {
    Missing {
        secret_name: String,
    },
    InvalidLength {
        secret_name: String,
        expected: usize,
        actual: usize,
    },
}

impl SecretError {
    pub fn missing(secret_name: &str) -> Self {
        Self::Missing {
            secret_name: secret_name.to_string(),
        }
    }

    pub fn invalid_length(secret_name: &str, expected: usize, actual: usize) -> Self {
        Self::InvalidLength {
            secret_name: secret_name.to_string(),
            expected,
            actual,
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { secret_name } => {
                write!(f, "Required secret '{}' is missing", secret_name)
            }
            Self::InvalidLength {
                secret_name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Secret '{}' must be at least {} characters, got {}",
                    secret_name, expected, actual
                )
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// Centralized manager for application secrets
pub struct SecretManager {
    jwt_secret: String,
    password_pepper: String,
    refresh_token_secret: String,
}

impl SecretManager {
    /// Initialize the SecretManager by loading and validating all secrets
    ///
    /// # Errors
    /// Returns `SecretError` if any required secret is missing or fails validation
    pub fn init() -> Result<Self, SecretError> {
        // Load secrets with validation rules
        let jwt_secret = Self::load_secret(&Self::jwt_config())?;
        let password_pepper = Self::load_secret(&Self::password_pepper_config())?;
        let refresh_token_secret = Self::load_secret(&Self::refresh_token_config())?;

        Ok(Self {
            jwt_secret,
            password_pepper,
            refresh_token_secret,
        })
    }

    /// Configuration for JWT secret
    fn jwt_config() -> SecretConfig {
        SecretConfig::new(SecretType::EnvVar {
            name: "JWT_SECRET".to_string(),
        })
        .required(true)
        .min_length(32)
    }

    /// Configuration for password pepper
    fn password_pepper_config() -> SecretConfig {
        SecretConfig::new(SecretType::EnvVar {
            name: "PASSWORD_PEPPER".to_string(),
        })
        .required(true)
        .min_length(16)
    }

    /// Configuration for refresh token secret
    fn refresh_token_config() -> SecretConfig {
        SecretConfig::new(SecretType::EnvVar {
            name: "REFRESH_TOKEN_SECRET".to_string(),
        })
        .required(true)
        .min_length(32)
    }

    /// Get the JWT secret
    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    /// Get the password pepper for password hashing
    pub fn password_pepper(&self) -> &str {
        &self.password_pepper
    }

    /// Get the refresh token secret for HMAC
    pub fn refresh_token_secret(&self) -> &str {
        &self.refresh_token_secret
    }

    /// Load a secret based on its configuration
    pub(crate) fn load_secret(config: &SecretConfig) -> Result<String, SecretError> {
        // Match on secret type to determine loading strategy
        let value = match &config.secret_type {
            SecretType::EnvVar { name } => match std::env::var(name) {
                Ok(v) => v,
                Err(_) if !config.required => return Ok(String::new()),
                Err(_) => return Err(SecretError::missing(name)),
            }, // Future implementations:
               // SecretType::AwsSecretsManager { secret_id, region } => {
               //     load_from_aws(secret_id, region).await?
               // }
        };

        // Validate minimum length
        if let Some(min_len) = config.min_length {
            if value.len() < min_len {
                let name = match &config.secret_type {
                    SecretType::EnvVar { name } => name,
                };
                return Err(SecretError::invalid_length(name, min_len, value.len()));
            }
        }

        Ok(value)
    }
}

impl fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretManager")
            .field("jwt_secret", &"<redacted>")
            .field("password_pepper", &"<redacted>")
            .field("refresh_token_secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretManager {{ secrets_loaded: 3 }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Global mutex to ensure tests run serially (environment variables are global)
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to clean up environment variables after each test
    struct EnvGuard {
        vars: Vec<String>,
    }

    impl EnvGuard {
        fn new(vars: Vec<&str>) -> Self {
            // Clean up before setting new values
            for var in &vars {
                unsafe {
                    std::env::remove_var(var);
                }
            }
            Self {
                vars: vars.iter().map(|s| s.to_string()).collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for var in &self.vars {
                unsafe {
                    std::env::remove_var(var);
                }
            }
        }
    }

    // Helper to set all required secrets for testing
    fn set_valid_secrets() {
        unsafe {
            std::env::set_var(
                "JWT_SECRET",
                "this-is-a-valid-jwt-secret-with-32-characters",
            );
            std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
            std::env::set_var(
                "REFRESH_TOKEN_SECRET",
                "this-is-a-valid-refresh-token-secret-32",
            );
        }
    }

    #[test]
    fn test_successful_initialization_with_valid_secrets() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        set_valid_secrets();

        let result = SecretManager::init();
        assert!(result.is_ok());

        let manager = result.unwrap();
        assert_eq!(
            manager.jwt_secret(),
            "this-is-a-valid-jwt-secret-with-32-characters"
        );
        assert_eq!(manager.password_pepper(), "valid-pepper-16ch");
        assert_eq!(
            manager.refresh_token_secret(),
            "this-is-a-valid-refresh-token-secret-32"
        );
    }

    #[test]
    fn test_error_when_jwt_secret_missing() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        unsafe {
            std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
            std::env::set_var(
                "REFRESH_TOKEN_SECRET",
                "this-is-a-valid-refresh-token-secret-32",
            );
        }

        let result = SecretManager::init();
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SecretError::Missing { secret_name } => {
                assert_eq!(secret_name, "JWT_SECRET");
            }
            _ => panic!("Expected Missing error"),
        }
    }

    #[test]
    fn test_error_when_password_pepper_missing() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        unsafe {
            std::env::set_var(
                "JWT_SECRET",
                "this-is-a-valid-jwt-secret-with-32-characters",
            );
            std::env::set_var(
                "REFRESH_TOKEN_SECRET",
                "this-is-a-valid-refresh-token-secret-32",
            );
        }

        let result = SecretManager::init();
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SecretError::Missing { secret_name } => {
                assert_eq!(secret_name, "PASSWORD_PEPPER");
            }
            _ => panic!("Expected Missing error"),
        }
    }

    #[test]
    fn test_error_when_jwt_secret_too_short() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        unsafe {
            std::env::set_var("JWT_SECRET", "short-secret");
            std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
            std::env::set_var(
                "REFRESH_TOKEN_SECRET",
                "this-is-a-valid-refresh-token-secret-32",
            );
        }

        let result = SecretManager::init();
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SecretError::InvalidLength {
                secret_name,
                expected,
                actual,
            } => {
                assert_eq!(secret_name, "JWT_SECRET");
                assert_eq!(expected, 32);
                assert_eq!(actual, 12);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_error_when_password_pepper_too_short() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        unsafe {
            std::env::set_var(
                "JWT_SECRET",
                "this-is-a-valid-jwt-secret-with-32-characters",
            );
            std::env::set_var("PASSWORD_PEPPER", "short");
            std::env::set_var(
                "REFRESH_TOKEN_SECRET",
                "this-is-a-valid-refresh-token-secret-32",
            );
        }

        let result = SecretManager::init();
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SecretError::InvalidLength {
                secret_name,
                expected,
                actual,
            } => {
                assert_eq!(secret_name, "PASSWORD_PEPPER");
                assert_eq!(expected, 16);
                assert_eq!(actual, 5);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_getter_methods_return_correct_values() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        let jwt_value = "my-super-secret-jwt-key-with-32-chars";
        let pepper_value = "my-pepper-value-16";
        let refresh_value = "my-refresh-token-secret-with-32-chars";

        unsafe {
            std::env::set_var("JWT_SECRET", jwt_value);
            std::env::set_var("PASSWORD_PEPPER", pepper_value);
            std::env::set_var("REFRESH_TOKEN_SECRET", refresh_value);
        }

        let manager = SecretManager::init().unwrap();

        assert_eq!(manager.jwt_secret(), jwt_value);
        assert_eq!(manager.password_pepper(), pepper_value);
        assert_eq!(manager.refresh_token_secret(), refresh_value);
    }

    #[test]
    fn test_debug_trait_does_not_expose_secrets() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        set_valid_secrets();

        let manager = SecretManager::init().unwrap();
        let debug_output = format!("{:?}", manager);

        assert!(debug_output.contains("<redacted>"));
        assert!(!debug_output.contains("this-is-a-valid-jwt-secret-with-32-characters"));
        assert!(!debug_output.contains("valid-pepper-16ch"));
        assert!(!debug_output.contains("this-is-a-valid-refresh-token-secret-32"));
    }

    #[test]
    fn test_display_trait_shows_metadata_only() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        set_valid_secrets();

        let manager = SecretManager::init().unwrap();
        let display_output = format!("{}", manager);

        assert!(display_output.contains("secrets_loaded: 3"));
        assert!(!display_output.contains("this-is-a-valid-jwt-secret-with-32-characters"));
        assert!(!display_output.contains("valid-pepper-16ch"));
        assert!(!display_output.contains("this-is-a-valid-refresh-token-secret-32"));
    }

    #[test]
    fn test_secret_type_env_var_loading() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec!["TEST_VAR"]);

        unsafe {
            std::env::set_var("TEST_VAR", "test-value-with-sufficient-length");
        }

        let config = SecretConfig::new(SecretType::EnvVar {
            name: "TEST_VAR".to_string(),
        })
        .required(true)
        .min_length(10);

        let result = SecretManager::load_secret(&config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-value-with-sufficient-length");
    }

    // Tests for REFRESH_TOKEN_SECRET (subtask 2.1)

    #[test]
    fn test_successful_initialization_with_valid_refresh_token_secret() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        set_valid_secrets();

        let result = SecretManager::init();
        assert!(result.is_ok());

        let manager = result.unwrap();
        assert_eq!(
            manager.refresh_token_secret(),
            "this-is-a-valid-refresh-token-secret-32"
        );
    }

    #[test]
    fn test_error_when_refresh_token_secret_missing() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        unsafe {
            std::env::set_var(
                "JWT_SECRET",
                "this-is-a-valid-jwt-secret-with-32-characters",
            );
            std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        }

        let result = SecretManager::init();
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SecretError::Missing { secret_name } => {
                assert_eq!(secret_name, "REFRESH_TOKEN_SECRET");
            }
            _ => panic!("Expected Missing error"),
        }
    }

    #[test]
    fn test_error_when_refresh_token_secret_too_short() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        unsafe {
            std::env::set_var(
                "JWT_SECRET",
                "this-is-a-valid-jwt-secret-with-32-characters",
            );
            std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
            std::env::set_var("REFRESH_TOKEN_SECRET", "short");
        }

        let result = SecretManager::init();
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SecretError::InvalidLength {
                secret_name,
                expected,
                actual,
            } => {
                assert_eq!(secret_name, "REFRESH_TOKEN_SECRET");
                assert_eq!(expected, 32);
                assert_eq!(actual, 5);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_refresh_token_secret_getter_returns_correct_value() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        let refresh_value = "my-specific-refresh-token-secret-32-chars";

        unsafe {
            std::env::set_var(
                "JWT_SECRET",
                "this-is-a-valid-jwt-secret-with-32-characters",
            );
            std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
            std::env::set_var("REFRESH_TOKEN_SECRET", refresh_value);
        }

        let manager = SecretManager::init().unwrap();
        assert_eq!(manager.refresh_token_secret(), refresh_value);
    }

    #[test]
    fn test_debug_trait_does_not_expose_refresh_token_secret() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new(vec![
            "JWT_SECRET",
            "PASSWORD_PEPPER",
            "REFRESH_TOKEN_SECRET",
        ]);

        set_valid_secrets();

        let manager = SecretManager::init().unwrap();
        let debug_output = format!("{:?}", manager);

        // Verify refresh_token_secret field is present but redacted
        assert!(debug_output.contains("refresh_token_secret"));
        assert!(debug_output.contains("<redacted>"));
        assert!(!debug_output.contains("this-is-a-valid-refresh-token-secret-32"));
    }
}

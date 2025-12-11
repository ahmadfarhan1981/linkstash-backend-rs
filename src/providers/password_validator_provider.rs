use rand::Rng;
use std::sync::Arc;
use sha1::{Sha1, Digest};
use crate::stores::{CommonPasswordStore, HibpCacheStore};

/// Password validator provider that enforces password policies
/// 
/// Migrated from PasswordValidator as part of service layer refactor.
/// Implements multiple validation layers:
/// - Length validation (15-128 characters)
/// - Username substring check (case-insensitive)
/// - Common password detection (via database lookup)
/// - Compromised password detection (via HaveIBeenPwned with k-anonymity)
pub struct PasswordValidatorProvider {
    min_length: usize,
    max_length: usize,
    common_password_store: Arc<CommonPasswordStore>,
    hibp_cache_store: Arc<HibpCacheStore>,
}

impl PasswordValidatorProvider {
    /// Create a new password validator provider with common password and HIBP cache stores
    /// 
    /// # Arguments
    /// * `common_password_store` - Store for checking against common password list
    /// * `hibp_cache_store` - Store for caching HaveIBeenPwned API responses
    /// 
    /// # Returns
    /// PasswordValidatorProvider configured with 15-128 character length requirements,
    /// common password detection, and compromised password detection via HIBP
    pub fn new(
        common_password_store: Arc<CommonPasswordStore>,
        hibp_cache_store: Arc<HibpCacheStore>,
    ) -> Self {
        Self {
            min_length: 15,
            max_length: 128,
            common_password_store,
            hibp_cache_store,
        }
    }

    /// Validate a password against all configured rules
    /// 
    /// Validates in order (fail fast):
    /// 1. Length (15-128 characters)
    /// 2. Username substring check (case-insensitive, if username provided)
    /// 3. Common password check (database lookup)
    /// 4. Compromised password check (HaveIBeenPwned with k-anonymity)
    /// 
    /// # Arguments
    /// * `password` - The password to validate
    /// * `username` - Optional username for context-specific validation
    /// 
    /// # Returns
    /// * `Ok(())` - Password passes all validation rules
    /// * `Err(PasswordValidationError)` - Password fails validation with specific reason
    pub async fn validate(
        &self,
        password: &str,
        username: Option<&str>,
    ) -> Result<(), PasswordValidationError> {
        // 1. Length validation
        if password.len() < self.min_length {
            return Err(PasswordValidationError::TooShort(self.min_length));
        }
        if password.len() > self.max_length {
            return Err(PasswordValidationError::TooLong(self.max_length));
        }

        // 2. Username substring check (case-insensitive)
        if let Some(username) = username {
            if password.to_lowercase().contains(&username.to_lowercase()) {
                return Err(PasswordValidationError::ContainsUsername);
            }
        }

        // 3. Common password check
        if self.common_password_store.is_common_password(password).await
            .map_err(|e| PasswordValidationError::DatabaseError(e.to_string()))? 
        {
            return Err(PasswordValidationError::CommonPassword);
        }

        // 4. HIBP check (graceful degradation on API failure)
        match self.check_hibp(password).await {
            Ok(true) => return Err(PasswordValidationError::CompromisedPassword),
            Ok(false) => {},
            Err(e) => {
                // Log warning but allow password if API fails
                tracing::warn!("HIBP check failed, allowing password: {}", e);
            }
        }

        Ok(())
    }

    /// Check if password has been compromised using HaveIBeenPwned API
    /// 
    /// Uses k-anonymity model by only sending the first 5 characters of the SHA-1 hash
    /// to the HIBP API. Checks cache first to minimize API calls.
    /// 
    /// # Arguments
    /// * `password` - The password to check
    /// 
    /// # Returns
    /// * `Ok(true)` - Password found in HIBP database (compromised)
    /// * `Ok(false)` - Password not found in HIBP database (safe)
    /// * `Err(PasswordValidationError)` - API or network error
    async fn check_hibp(&self, password: &str) -> Result<bool, PasswordValidationError> {
        // Compute SHA-1 hash of password
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = format!("{:X}", hasher.finalize());

        let prefix = &hash[..5];
        let suffix = &hash[5..];

        // Check cache first
        if let Some(cached_data) = self.hibp_cache_store
            .get_cached_response(prefix)
            .await
            .map_err(|e| PasswordValidationError::DatabaseError(e.to_string()))? 
        {
            return Ok(cached_data.contains(suffix));
        }

        // Fetch from API if not cached
        let response = self.fetch_hibp_api(prefix).await?;
        
        // Store in cache
        self.hibp_cache_store
            .store_response(prefix, &response)
            .await
            .map_err(|e| PasswordValidationError::DatabaseError(e.to_string()))?;

        Ok(response.contains(suffix))
    }

    /// Fetch hash suffixes from HaveIBeenPwned API
    /// 
    /// Uses the k-anonymity model by only sending the 5-character hash prefix.
    /// 
    /// # Arguments
    /// * `prefix` - The 5-character SHA-1 hash prefix
    /// 
    /// # Returns
    /// * `Ok(response)` - API response containing hash suffixes and counts
    /// * `Err(PasswordValidationError)` - Network or API error
    async fn fetch_hibp_api(&self, prefix: &str) -> Result<String, PasswordValidationError> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let client = reqwest::Client::new();

        let response = client
            .get(&url)
            .header("User-Agent", "Linkstash-Auth")
            .send()
            .await
            .map_err(|e| PasswordValidationError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(PasswordValidationError::ApiError(format!(
                "HIBP API returned status: {}",
                response.status()
            )));
        }

        response
            .text()
            .await
            .map_err(|e| PasswordValidationError::NetworkError(e.to_string()))
    }

    /// Generate a cryptographically secure random password
    /// 
    /// Generates a 20-character password using uppercase letters, lowercase letters,
    /// digits, and special characters. The generated password is guaranteed to pass
    /// all validation requirements.
    /// 
    /// # Returns
    /// A 20-character random password string
    pub fn generate_secure_password(&self) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::rng();

        (0..20)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}

/// Errors that can occur during password validation
#[derive(Debug, thiserror::Error)]
pub enum PasswordValidationError {
    /// Password is shorter than the minimum required length
    #[error("Password must be at least {0} characters")]
    TooShort(usize),

    /// Password exceeds the maximum allowed length
    #[error("Password must not exceed {0} characters")]
    TooLong(usize),

    /// Password contains the username as a substring
    #[error("Password must not contain your username")]
    ContainsUsername,

    /// Password appears in the common password list
    #[error("Password is too common")]
    CommonPassword,

    /// Password has been compromised in a data breach
    #[error("Password has been compromised in a data breach")]
    CompromisedPassword,

    /// Database error during validation
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Network error during HIBP API call
    #[error("Network error: {0}")]
    NetworkError(String),

    /// HIBP API error
    #[error("API error: {0}")]
    ApiError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;

    async fn create_test_password_validator_provider() -> PasswordValidatorProvider {
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        let common_password_store = Arc::new(CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(HibpCacheStore::new(db.clone(), system_config_store));
        
        PasswordValidatorProvider::new(common_password_store, hibp_cache_store)
    }

    #[tokio::test]
    async fn test_password_too_short() {
        let validator = create_test_password_validator_provider().await;
        
        let result = validator.validate("short", None).await;
        
        assert!(matches!(result, Err(PasswordValidationError::TooShort(15))));
    }

    #[tokio::test]
    async fn test_password_too_long() {
        let validator = create_test_password_validator_provider().await;
        
        // Create a password longer than 128 characters
        let long_password = "a".repeat(129);
        let result = validator.validate(&long_password, None).await;
        
        assert!(matches!(result, Err(PasswordValidationError::TooLong(128))));
    }

    #[tokio::test]
    async fn test_password_contains_username() {
        let validator = create_test_password_validator_provider().await;
        
        let result = validator.validate("myusernamepassword123", Some("myusername")).await;
        
        assert!(matches!(result, Err(PasswordValidationError::ContainsUsername)));
    }

    #[tokio::test]
    async fn test_password_contains_username_case_insensitive() {
        let validator = create_test_password_validator_provider().await;
        
        let result = validator.validate("MyUserNamePassword123", Some("myusername")).await;
        
        assert!(matches!(result, Err(PasswordValidationError::ContainsUsername)));
    }

    #[tokio::test]
    async fn test_generate_secure_password_length() {
        let validator = create_test_password_validator_provider().await;
        
        let password = validator.generate_secure_password();
        
        assert_eq!(password.len(), 20);
    }

    #[tokio::test]
    async fn test_generate_secure_password_uniqueness() {
        let validator = create_test_password_validator_provider().await;
        
        let password1 = validator.generate_secure_password();
        let password2 = validator.generate_secure_password();
        
        assert_ne!(password1, password2);
    }

    #[tokio::test]
    async fn test_generate_secure_password_contains_valid_characters() {
        let validator = create_test_password_validator_provider().await;
        
        let password = validator.generate_secure_password();
        
        // Check that all characters are from the expected charset
        const CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        for ch in password.chars() {
            assert!(CHARSET.contains(ch), "Password contains invalid character: {}", ch);
        }
    }
}
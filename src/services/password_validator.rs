use rand::Rng;
use uuid::Uuid;
use std::sync::Arc;
use crate::stores::CommonPasswordStore;

/// Password validator service that enforces password policies
/// 
/// Implements multiple validation layers:
/// - Length validation (15-128 characters)
/// - Common password detection (via database lookup)
/// 
/// Future enhancements will add username checks and compromised password
/// checks via HaveIBeenPwned.
pub struct PasswordValidator {
    min_length: usize,
    max_length: usize,
    common_password_store: Arc<CommonPasswordStore>,
}

impl PasswordValidator {
    /// Create a new password validator with common password store
    /// 
    /// # Arguments
    /// * `common_password_store` - Store for checking against common password list
    /// 
    /// # Returns
    /// PasswordValidator configured with 15-128 character length requirements
    /// and common password detection
    pub fn new(common_password_store: Arc<CommonPasswordStore>) -> Self {
        Self {
            min_length: 15,
            max_length: 128,
            common_password_store,
        }
    }

    /// Validate a password against all configured rules
    /// 
    /// Validates in order (fail fast):
    /// 1. Length (15-128 characters)
    /// 2. Common password check (database lookup)
    /// 
    /// Future versions will add username substring checks and compromised
    /// password checks via HaveIBeenPwned.
    /// 
    /// # Arguments
    /// * `password` - The password to validate
    /// * `username` - Optional username for context-specific validation (not used yet)
    /// 
    /// # Returns
    /// * `Ok(())` - Password passes all validation rules
    /// * `Err(PasswordValidationError)` - Password fails validation with specific reason
    pub async fn validate(
        &self,
        password: &str,
        _username: Option<&str>,
    ) -> Result<(), PasswordValidationError> {
        // 1. Length validation
        if password.len() < self.min_length {
            return Err(PasswordValidationError::TooShort(self.min_length));
        }
        if password.len() > self.max_length {
            return Err(PasswordValidationError::TooLong(self.max_length));
        }

        // 2. Common password check
        if self.common_password_store.is_common_password(password).await
            .map_err(|e| PasswordValidationError::DatabaseError(e.to_string()))? 
        {
            return Err(PasswordValidationError::CommonPassword);
        }

        Ok(())
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

    /// Check if a string is a valid UUID
    /// 
    /// Used to skip username substring checks for system-generated UUID usernames
    /// (e.g., owner accounts created during bootstrap).
    /// 
    /// # Arguments
    /// * `s` - String to check
    /// 
    /// # Returns
    /// `true` if the string is a valid UUID, `false` otherwise
    fn is_uuid(s: &str) -> bool {
        Uuid::parse_str(s).is_ok()
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
}

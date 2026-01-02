use std::sync::Arc;

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;

use crate::{
    AppData, app_data,
    config::SecretManager,
    errors::{InternalError, internal::CredentialError},
};

type HmacSha256 = Hmac<Sha256>;

/// Cryptographic operations provider
///
/// Migrated from crypto module as part of service layer refactor.
/// Provides cryptographic operations including HMAC-SHA256 hashing
/// and secure password generation.
pub struct CryptoProvider {
    secret_manager: Arc<SecretManager>,
}

impl CryptoProvider {
    /// Create a new CryptoProvider
    // pub fn new(app_data: Arc<AppData>) -> Self {
    //     Self{
    //         secret_manager: app_data.secret_manager.clone(),
    //     }
    // }

    pub fn new(secret_manager: Arc<SecretManager>) -> Self {
        Self { secret_manager }
    }

    /// Compute HMAC-SHA256 for refresh tokens and return as hexadecimal string
    ///
    /// # Arguments
    /// * `key` - The secret key for HMAC computation
    /// * `token` - The token to hash
    ///
    /// # Returns
    /// Hexadecimal string representation of the HMAC-SHA256 hash
    pub fn hmac_sha256_token(&self, key: &str, token: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
        mac.update(token.as_bytes());
        let result = mac.finalize();
        format!("{:x}", result.into_bytes())
    }

    /// Hash a refresh token using HMAC-SHA256
    ///
    /// # Arguments
    /// * `token` - The plaintext refresh token to hash
    ///
    /// # Returns
    /// * `String` - The hex-encoded HMAC-SHA256 hash
    // pub fn hash_refresh_token(&self, token: &str) -> String {
    //     self.crypto_provider.hmac_sha256_token(self.secret_manager.refresh_token_secret(), token)
    // }

    /// Generate a cryptographically secure random password
    ///
    /// Generates a 20-character password with a mix of uppercase letters,
    /// lowercase letters, digits, and symbols using a cryptographically
    /// secure random number generator.
    ///
    /// # Returns
    /// A 20-character password string containing:
    /// - Uppercase letters (A-Z)
    /// - Lowercase letters (a-z)
    /// - Digits (0-9)
    /// - Symbols (!@#$%^&*()_+-=[]{}|;:,.<>?)
    pub fn generate_secure_password(&self) -> String {
        const PASSWORD_LENGTH: usize = 20;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789\
                                 !@#$%^&*()_+-=[]{}|;:,.<>?";

        let mut rng = rand::rng();
        let password: String = (0..PASSWORD_LENGTH)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        password
    }

    pub async fn verify_password(
        &self,
        stored_hash: &str,
        password: &str,
    ) -> Result<bool, InternalError> {
        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(|_| InternalError::Credential(CredentialError::InvalidCredentials))?; //TODO not invalid credential

        let argon2 = Argon2::new_with_secret(
            self.secret_manager.password_pepper().as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )
        .map_err(|_| InternalError::Credential(CredentialError::InvalidCredentials))?; //TODO not invalid credential

        // Always execute password verification (constant-time operation)
        let verification_result = argon2.verify_password(password.as_bytes(), &parsed_hash);
        match verification_result {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_password_meets_length_requirement() {
        // TODO
    }
}

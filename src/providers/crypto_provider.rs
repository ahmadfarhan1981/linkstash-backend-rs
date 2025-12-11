use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng;

type HmacSha256 = Hmac<Sha256>;

/// Cryptographic operations provider
/// 
/// Migrated from crypto module as part of service layer refactor.
/// Provides cryptographic operations including HMAC-SHA256 hashing
/// and secure password generation.
pub struct CryptoProvider;

impl CryptoProvider {
    /// Create a new CryptoProvider
    pub fn new() -> Self {
        Self
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
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(token.as_bytes());
        let result = mac.finalize();
        format!("{:x}", result.into_bytes())
    }

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
}

impl Default for CryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_crypto_provider() -> CryptoProvider {
        CryptoProvider::new()
    }

    #[test]
    fn test_hmac_sha256_token_consistency() {
        let crypto = create_test_crypto_provider();
        let key = "test-secret-key";
        let token = "test-token-12345";
        
        let hash1 = crypto.hmac_sha256_token(key, token);
        let hash2 = crypto.hmac_sha256_token(key, token);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hmac_sha256_token_different_keys_produce_different_hashes() {
        let crypto = create_test_crypto_provider();
        let token = "test-token-12345";
        
        let hash1 = crypto.hmac_sha256_token("key1", token);
        let hash2 = crypto.hmac_sha256_token("key2", token);
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hmac_sha256_token_different_tokens_produce_different_hashes() {
        let crypto = create_test_crypto_provider();
        let key = "test-secret-key";
        
        let hash1 = crypto.hmac_sha256_token(key, "token1");
        let hash2 = crypto.hmac_sha256_token(key, "token2");
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_generate_secure_password_length() {
        let crypto = create_test_crypto_provider();
        let password = crypto.generate_secure_password();
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_generate_secure_password_contains_valid_characters() {
        let crypto = create_test_crypto_provider();
        let password = crypto.generate_secure_password();
        
        assert!(password.chars().all(|c| {
            c.is_ascii_alphanumeric() || "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)
        }));
    }

    #[test]
    fn test_generate_secure_password_uniqueness() {
        let crypto = create_test_crypto_provider();
        
        let password1 = crypto.generate_secure_password();
        let password2 = crypto.generate_secure_password();
        
        assert_ne!(password1, password2);
    }

    #[test]
    fn test_hmac_sha256_token_hex_format() {
        let crypto = create_test_crypto_provider();
        let hash = crypto.hmac_sha256_token("key", "token");
        
        // Should be a valid hex string
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // HMAC-SHA256 produces 32 bytes = 64 hex characters
        assert_eq!(hash.len(), 64);
    }
}

// Standalone functions for use by other components
// These create temporary provider instances to maintain compatibility
// with existing code that expects standalone functions

/// Compute HMAC-SHA256 for refresh tokens and return as hexadecimal string (standalone function)
pub fn hmac_sha256_token(key: &str, token: &str) -> String {
    let provider = CryptoProvider::new();
    provider.hmac_sha256_token(key, token)
}

/// Generate a cryptographically secure random password (standalone function)
pub fn generate_secure_password() -> String {
    let provider = CryptoProvider::new();
    provider.generate_secure_password()
}
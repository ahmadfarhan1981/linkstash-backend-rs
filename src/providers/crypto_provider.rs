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

    #[test]
    fn test_generate_secure_password_meets_length_requirement() {
        let crypto = CryptoProvider::new();
        let password = crypto.generate_secure_password();
        assert_eq!(password.len(), 20);
    }
}


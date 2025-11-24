use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 for refresh tokens and return as hexadecimal string
pub fn hmac_sha256_token(key: &str, token: &str) -> String {
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
pub fn generate_secure_password() -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_password_length() {
        let password = generate_secure_password();
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_generate_secure_password_contains_valid_characters() {
        let password = generate_secure_password();
        
        assert!(password.chars().all(|c| {
            c.is_ascii_alphanumeric() || "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)
        }));
    }

    #[test]
    fn test_generate_secure_password_uniqueness() {
        let password1 = generate_secure_password();
        let password2 = generate_secure_password();
        
        assert_ne!(password1, password2);
    }
}

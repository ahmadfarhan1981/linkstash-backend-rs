use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 for refresh tokens and return as hexadecimal string
pub fn hmac_sha256_token(key: &str, token: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize();
    format!("{:x}", result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_consistency() {
        let key = "test-secret-key";
        let token = "test-token";
        
        let hash1 = hmac_sha256_token(key, token);
        let hash2 = hmac_sha256_token(key, token);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hmac_different_keys() {
        let token = "test-token";
        
        let hash1 = hmac_sha256_token("key1", token);
        let hash2 = hmac_sha256_token("key2", token);
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hmac_different_tokens() {
        let key = "test-secret-key";
        
        let hash1 = hmac_sha256_token(key, "token1");
        let hash2 = hmac_sha256_token(key, "token2");
        
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_hmac_output_length() {
        let key = "test-secret-key";
        let token = "test-token";
        
        let hash = hmac_sha256_token(key, token);
        
        // SHA-256 produces 64 hex characters (32 bytes)
        assert_eq!(hash.len(), 64);
    }
}

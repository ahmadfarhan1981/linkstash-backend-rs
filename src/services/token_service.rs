use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use chrono::Utc;
use uuid::Uuid;
use rand::prelude::*;
use base64::{Engine as _, engine::general_purpose};
use std::fmt;
use crate::types::internal::auth::Claims;
use crate::errors::auth::AuthError;
use crate::services::crypto;

/// Manages JWT token generation and validation
pub struct TokenService {
    jwt_secret: String,
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    refresh_token_secret: String,
}

impl TokenService {
    /// Create a new TokenService with the given JWT secret and refresh token secret
    pub fn new(jwt_secret: String, refresh_token_secret: String) -> Self {
        Self {
            jwt_secret,
            jwt_expiration_minutes: 15, // 15 minutes as per requirements
            refresh_expiration_days: 7, // 7 days as per requirements
            refresh_token_secret,
        }
    }
    
    /// Generate a JWT for the given user_id
    /// 
    /// # Arguments
    /// * `user_id` - The UUID of the user
    /// 
    /// # Returns
    /// * `Result<String, AuthError>` - The encoded JWT or an error
    pub fn generate_jwt(&self, user_id: &Uuid) -> Result<String, AuthError> {
        let now = Utc::now().timestamp();
        let expiration = now + (self.jwt_expiration_minutes * 60);
        
        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
            iat: now,
        };
        
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::internal_error(format!("Failed to generate JWT: {}", e)))?;
        
        Ok(token)
    }
    
    /// Validate a JWT and return the claims
    /// 
    /// # Arguments
    /// * `token` - The JWT to validate
    /// 
    /// # Returns
    /// * `Result<Claims, AuthError>` - The decoded claims or an error
    pub fn validate_jwt(&self, token: &str) -> Result<Claims, AuthError> {
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| {
            // Check if the error is due to expiration
            if e.to_string().contains("ExpiredSignature") {
                AuthError::expired_token()
            } else {
                AuthError::invalid_token()
            }
        })?;
        
        Ok(token_data.claims)
    }
    
    /// Generate a cryptographically secure refresh token
    /// 
    /// # Returns
    /// * `String` - A base64-encoded random token (32 bytes)
    pub fn generate_refresh_token(&self) -> String {
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();
        general_purpose::STANDARD.encode(random_bytes)
    }
    
    /// Hash a refresh token using HMAC-SHA256
    /// 
    /// # Arguments
    /// * `token` - The plaintext refresh token to hash
    /// 
    /// # Returns
    /// * `String` - The hex-encoded HMAC-SHA256 hash
    pub fn hash_refresh_token(&self, token: &str) -> String {
        crypto::hmac_sha256_token(&self.refresh_token_secret, token)
    }
    
    /// Get the expiration timestamp for a refresh token (7 days from now)
    /// 
    /// # Returns
    /// * `i64` - Unix timestamp for 7 days from now
    pub fn get_refresh_expiration(&self) -> i64 {
        let now = Utc::now().timestamp();
        now + (self.refresh_expiration_days * 24 * 60 * 60)
    }
}

impl fmt::Debug for TokenService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenService")
            .field("jwt_secret", &"<redacted>")
            .field("jwt_expiration_minutes", &self.jwt_expiration_minutes)
            .field("refresh_expiration_days", &self.refresh_expiration_days)
            .field("refresh_token_secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for TokenService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TokenService {{ jwt_expiration: {}min, refresh_expiration: {}days }}",
            self.jwt_expiration_minutes, self.refresh_expiration_days
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};

    #[test]
    fn test_generate_jwt_creates_valid_jwt() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let user_id = Uuid::new_v4();
        
        let result = token_manager.generate_jwt(&user_id);
        
        assert!(result.is_ok());
        let token = result.unwrap();
        
        // Verify token can be decoded
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false; // Don't validate expiration in this test
        
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        );
        
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_jwt_contains_correct_user_id() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let user_id = Uuid::new_v4();
        
        let token = token_manager.generate_jwt(&user_id).unwrap();
        
        // Decode and verify user_id in sub claim
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap();
        
        assert_eq!(decoded.claims.sub, user_id.to_string());
    }

    #[test]
    fn test_jwt_expiration_is_15_minutes() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let user_id = Uuid::new_v4();
        
        let token = token_manager.generate_jwt(&user_id).unwrap();
        
        // Decode and verify expiration
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap();
        
        let time_diff = decoded.claims.exp - decoded.claims.iat;
        assert_eq!(time_diff, 900); // 15 minutes = 900 seconds
    }

    #[test]
    fn test_jwt_has_iat_timestamp() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let user_id = Uuid::new_v4();
        
        let before = Utc::now().timestamp();
        let token = token_manager.generate_jwt(&user_id).unwrap();
        let after = Utc::now().timestamp();
        
        // Decode and verify iat is within reasonable range
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap();
        
        assert!(decoded.claims.iat >= before);
        assert!(decoded.claims.iat <= after);
    }

    #[test]
    fn test_validate_jwt_succeeds_with_valid_jwt() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let user_id = Uuid::new_v4();
        
        let token = token_manager.generate_jwt(&user_id).unwrap();
        let result = token_manager.validate_jwt(&token);
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_jwt_returns_correct_claims() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let user_id = Uuid::new_v4();
        
        let token = token_manager.generate_jwt(&user_id).unwrap();
        let claims = token_manager.validate_jwt(&token).unwrap();
        
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.exp - claims.iat, 900); // 15 minutes
    }

    #[test]
    fn test_validate_jwt_fails_with_invalid_signature() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let wrong_token_manager = TokenService::new(
            "wrong-secret-key-minimum-32-characters".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        let user_id = Uuid::new_v4();
        
        // Generate token with one secret
        let token = token_manager.generate_jwt(&user_id).unwrap();
        
        // Try to validate with different secret
        let result = wrong_token_manager.validate_jwt(&token);
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[test]
    fn test_validate_jwt_fails_with_expired_jwt() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        // Create an expired token manually
        let now = Utc::now().timestamp();
        let expired_claims = Claims {
            sub: Uuid::new_v4().to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 7200, // Issued 2 hours ago
        };
        
        let expired_token = encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
        ).unwrap();
        
        let result = token_manager.validate_jwt(&expired_token);
        
        assert!(result.is_err());
        match result {
            Err(AuthError::ExpiredToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected ExpiredToken error"),
        }
    }

    #[test]
    fn test_generate_refresh_token_creates_unique_tokens() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        let token1 = token_manager.generate_refresh_token();
        let token2 = token_manager.generate_refresh_token();
        
        // Tokens should be different
        assert_ne!(token1, token2);
        
        // Tokens should be base64-encoded (44 characters for 32 bytes)
        assert_eq!(token1.len(), 44);
        assert_eq!(token2.len(), 44);
    }

    #[test]
    fn test_hash_refresh_token_produces_consistent_hashes() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        let token = "test-refresh-token";
        let hash1 = token_manager.hash_refresh_token(token);
        let hash2 = token_manager.hash_refresh_token(token);
        
        // Same token should produce same hash
        assert_eq!(hash1, hash2);
        
        // Hash should be 64 characters (HMAC-SHA256 in hex)
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_hash_refresh_token_produces_different_hashes_for_different_tokens() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        let token1 = "token1";
        let token2 = "token2";
        
        let hash1 = token_manager.hash_refresh_token(token1);
        let hash2 = token_manager.hash_refresh_token(token2);
        
        // Different tokens should produce different hashes
        assert_ne!(hash1, hash2);
    }

    // Tests for HMAC-based refresh token hashing (Requirement 7.4, 2.4)
    
    #[test]
    fn test_hmac_refresh_token_hashing_produces_consistent_output() {
        let token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        let token = "test-refresh-token-12345";
        
        // Hash the same token multiple times
        let hash1 = token_manager.hash_refresh_token(token);
        let hash2 = token_manager.hash_refresh_token(token);
        let hash3 = token_manager.hash_refresh_token(token);
        
        // All hashes should be identical (HMAC is deterministic)
        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
        
        // Verify it's a valid hex string of correct length (64 chars for SHA-256)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_different_secrets_produce_different_hashes() {
        let token = "test-refresh-token-12345";
        
        let token_manager1 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "refresh-secret-one-minimum-32-chars".to_string(),
        );
        
        let token_manager2 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "refresh-secret-two-minimum-32-chars".to_string(),
        );
        
        let hash1 = token_manager1.hash_refresh_token(token);
        let hash2 = token_manager2.hash_refresh_token(token);
        
        // Different secrets should produce different hashes (prevents token minting)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_token_minting_prevention_without_correct_secret() {
        let token = "malicious-token-attempt";
        
        // Attacker tries to mint a token with wrong secret
        let attacker_token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "attacker-guessed-secret-wrong-value".to_string(),
        );
        
        // Legitimate server with correct secret
        let legitimate_token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "correct-refresh-secret-minimum-32-ch".to_string(),
        );
        
        let attacker_hash = attacker_token_manager.hash_refresh_token(token);
        let legitimate_hash = legitimate_token_manager.hash_refresh_token(token);
        
        // Attacker's hash won't match legitimate hash (can't mint valid tokens)
        assert_ne!(attacker_hash, legitimate_hash);
        
        // This simulates database lookup failure - attacker's hash won't be found
        // in database because it was computed with wrong secret
    }

    #[test]
    fn test_hmac_output_is_deterministic_across_instances() {
        let token = "test-token-for-determinism";
        let secret = "shared-refresh-secret-minimum-32-c";
        
        // Create multiple TokenService instances with same secret
        let manager1 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            secret.to_string(),
        );
        
        let manager2 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            secret.to_string(),
        );
        
        let hash1 = manager1.hash_refresh_token(token);
        let hash2 = manager2.hash_refresh_token(token);
        
        // Same secret and token should always produce same hash
        assert_eq!(hash1, hash2);
    }

    // Tests for Debug and Display trait protection
    
    #[test]
    fn test_debug_trait_does_not_expose_jwt_secret() {
        let token_service = TokenService::new(
            "super-secret-jwt-key-minimum-32-characters".to_string(),
            "super-secret-refresh-key-minimum-32-ch".to_string(),
        );
        
        let debug_output = format!("{:?}", token_service);
        
        // Debug output should not contain the actual secrets
        assert!(!debug_output.contains("super-secret-jwt-key"));
        assert!(!debug_output.contains("super-secret-refresh-key"));
        
        // Debug output should contain redacted markers
        assert!(debug_output.contains("<redacted>"));
        assert!(debug_output.contains("TokenService"));
    }

    #[test]
    fn test_debug_trait_does_not_expose_refresh_token_secret() {
        let token_service = TokenService::new(
            "test-jwt-secret-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        let debug_output = format!("{:?}", token_service);
        
        // Debug output should not contain the refresh token secret
        assert!(!debug_output.contains("test-refresh-secret"));
        
        // Debug output should show redacted for both secrets
        let redacted_count = debug_output.matches("<redacted>").count();
        assert_eq!(redacted_count, 2, "Should have 2 redacted fields (jwt_secret and refresh_token_secret)");
    }

    #[test]
    fn test_debug_trait_shows_non_sensitive_fields() {
        let token_service = TokenService::new(
            "test-jwt-secret-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        let debug_output = format!("{:?}", token_service);
        
        // Debug output should show non-sensitive configuration
        assert!(debug_output.contains("jwt_expiration_minutes"));
        assert!(debug_output.contains("15"));
        assert!(debug_output.contains("refresh_expiration_days"));
        assert!(debug_output.contains("7"));
    }

    #[test]
    fn test_display_trait_does_not_expose_secrets() {
        let token_service = TokenService::new(
            "super-secret-jwt-key-minimum-32-characters".to_string(),
            "super-secret-refresh-key-minimum-32-ch".to_string(),
        );
        
        let display_output = format!("{}", token_service);
        
        // Display output should not contain the actual secrets
        assert!(!display_output.contains("super-secret-jwt-key"));
        assert!(!display_output.contains("super-secret-refresh-key"));
        
        // Display output should show metadata only
        assert!(display_output.contains("TokenService"));
        assert!(display_output.contains("15min"));
        assert!(display_output.contains("7days"));
    }

    #[test]
    fn test_display_trait_shows_configuration_summary() {
        let token_service = TokenService::new(
            "test-jwt-secret-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        );
        
        let display_output = format!("{}", token_service);
        
        // Display should show a human-readable summary
        assert!(display_output.contains("jwt_expiration: 15min"));
        assert!(display_output.contains("refresh_expiration: 7days"));
    }
}


use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use chrono::Utc;
use uuid::Uuid;
use super::{Claims, AuthError};

/// Manages JWT token generation and validation
pub struct TokenManager {
    jwt_secret: String,
    jwt_expiration_minutes: i64,
}

impl TokenManager {
    /// Create a new TokenManager with the given JWT secret
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            jwt_expiration_minutes: 15, // 15 minutes as per requirements
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
}


#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};

    #[test]
    fn test_generate_jwt_creates_valid_jwt() {
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
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
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
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
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
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
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
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
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
        let user_id = Uuid::new_v4();
        
        let token = token_manager.generate_jwt(&user_id).unwrap();
        let result = token_manager.validate_jwt(&token);
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_jwt_returns_correct_claims() {
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
        let user_id = Uuid::new_v4();
        
        let token = token_manager.generate_jwt(&user_id).unwrap();
        let claims = token_manager.validate_jwt(&token).unwrap();
        
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.exp - claims.iat, 900); // 15 minutes
    }

    #[test]
    fn test_validate_jwt_fails_with_invalid_signature() {
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
        let wrong_token_manager = TokenManager::new("wrong-secret-key-minimum-32-characters".to_string());
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
        let token_manager = TokenManager::new("test-secret-key-minimum-32-characters-long".to_string());
        
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
}

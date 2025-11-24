use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use chrono::{Utc, DateTime};
use uuid::Uuid;
use rand::prelude::*;
use base64::{Engine as _, engine::general_purpose};
use std::fmt;
use std::sync::Arc;
use crate::types::internal::auth::Claims;
use crate::errors::auth::AuthError;
use crate::services::{crypto, audit_logger};
use crate::stores::AuditStore;

/// Manages JWT token generation and validation
pub struct TokenService {
    jwt_secret: String,
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    refresh_token_secret: String,
    audit_store: Arc<AuditStore>,
}

impl TokenService {
    /// Create a new TokenService with the given JWT secret, refresh token secret, and audit store
    pub fn new(jwt_secret: String, refresh_token_secret: String, audit_store: Arc<AuditStore>) -> Self {
        Self {
            jwt_secret,
            jwt_expiration_minutes: 15, // 15 minutes as per requirements
            refresh_expiration_days: 7, // 7 days as per requirements
            refresh_token_secret,
            audit_store,
        }
    }
    
    /// Generate a JWT for the given user with admin roles
    /// 
    /// Logs JWT issuance to audit database at point of action.
    /// 
    /// # Arguments
    /// * `user_id` - The UUID of the user
    /// * `is_owner` - Owner role flag
    /// * `is_system_admin` - System Admin role flag
    /// * `is_role_admin` - Role Admin role flag
    /// * `app_roles` - Application roles (list of role names)
    /// * `ip_address` - Client IP address for audit logging
    /// 
    /// # Returns
    /// * `Result<(String, String), AuthError>` - Tuple of (encoded JWT, JWT ID) or an error
    pub async fn generate_jwt(
        &self,
        user_id: &Uuid,
        is_owner: bool,
        is_system_admin: bool,
        is_role_admin: bool,
        app_roles: Vec<String>,
        ip_address: Option<String>,
    ) -> Result<(String, String), AuthError> {
        let now = Utc::now().timestamp();
        let expiration = now + (self.jwt_expiration_minutes * 60);
        
        // Validate expiration timestamp before creating JWT
        let expiration_dt = DateTime::from_timestamp(expiration, 0)
            .ok_or_else(|| AuthError::internal_error(format!("Invalid expiration timestamp: {}", expiration)))?;
        
        // Generate unique JWT ID
        let jti = Uuid::new_v4().to_string();
        
        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
            iat: now,
            jti: Some(jti.clone()),
            is_owner,
            is_system_admin,
            is_role_admin,
            app_roles,
        };
        
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::internal_error(format!("Failed to generate JWT: {}", e)))?;
        
        // Log JWT issuance at point of action (expiration_dt already validated above)
        if let Err(audit_err) = audit_logger::log_jwt_issued(
            &self.audit_store,
            user_id.to_string(),
            jti.clone(),
            expiration_dt,
            ip_address,
        ).await {
            tracing::error!("Failed to log JWT issuance: {:?}", audit_err);
        }
        
        Ok((token, jti))
    }
    
    /// Validate a JWT and return the claims
    /// 
    /// Logs validation failures to audit database at point of action.
    /// 
    /// # Arguments
    /// * `token` - The JWT to validate
    /// 
    /// # Returns
    /// * `Result<Claims, AuthError>` - The decoded claims or an error
    pub async fn validate_jwt(&self, token: &str) -> Result<Claims, AuthError> {
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
        });
        
        // Log validation failures at point of action
        if let Err(ref err) = token_data {
            // Try to extract claims without validation for audit logging
            if let Ok(unverified_claims) = self.extract_unverified_claims(token) {
                let failure_reason = match err {
                    AuthError::ExpiredToken(_) => "expired",
                    AuthError::InvalidToken(_) => "invalid_signature",
                    _ => "validation_error",
                };
                
                // Check if this is a tampering attempt (invalid signature)
                if matches!(err, AuthError::InvalidToken(_)) {
                    if let Err(audit_err) = audit_logger::log_jwt_tampered(
                        &self.audit_store,
                        unverified_claims.sub.clone(),
                        unverified_claims.jti.clone(),
                        token.to_string(),
                        failure_reason.to_string(),
                    ).await {
                        tracing::error!("Failed to log JWT tampering: {:?}", audit_err);
                    }
                } else {
                    // Normal validation failure (expired, etc.)
                    if let Err(audit_err) = audit_logger::log_jwt_validation_failure(
                        &self.audit_store,
                        unverified_claims.sub.clone(),
                        unverified_claims.jti.clone(),
                        failure_reason.to_string(),
                    ).await {
                        tracing::error!("Failed to log JWT validation failure: {:?}", audit_err);
                    }
                }
            }
        }
        
        token_data.map(|td| td.claims)
    }
    
    /// Extract claims from JWT without validation (for audit logging only)
    fn extract_unverified_claims(&self, token: &str) -> Result<Claims, AuthError> {
        use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(b"dummy"),
            &validation,
        )
        .map_err(|_| AuthError::invalid_token())?;
        
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
            .field("audit_store", &"<audit_store>")
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
    use sea_orm::Database;
    use migration::{AuditMigrator, MigratorTrait};

    async fn create_test_token_service() -> TokenService {
        let audit_db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create audit database");
        
        AuditMigrator::up(&audit_db, None)
            .await
            .expect("Failed to run audit migrations");
        
        let audit_store = Arc::new(AuditStore::new(audit_db));
        
        TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store,
        )
    }

    #[tokio::test]
    async fn test_generate_jwt_creates_valid_jwt() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let result = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await;
        
        assert!(result.is_ok());
        let (token, jwt_id) = result.unwrap();
        
        // Verify JWT ID is not empty
        assert!(!jwt_id.is_empty());
        
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

    #[tokio::test]
    async fn test_jwt_contains_correct_user_id() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let (token, _jwt_id) = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await.unwrap();
        
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

    #[tokio::test]
    async fn test_jwt_expiration_is_15_minutes() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let (token, _jwt_id) = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await.unwrap();
        
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

    #[tokio::test]
    async fn test_jwt_has_iat_timestamp() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let before = Utc::now().timestamp();
        let (token, _jwt_id) = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await.unwrap();
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

    #[tokio::test]
    async fn test_validate_jwt_succeeds_with_valid_jwt() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let (token, _jwt_id) = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await.unwrap();
        let result = token_manager.validate_jwt(&token).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_jwt_returns_correct_claims() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let (token, _jwt_id) = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await.unwrap();
        let claims = token_manager.validate_jwt(&token).await.unwrap();
        
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.exp - claims.iat, 900); // 15 minutes
    }

    #[tokio::test]
    async fn test_validate_jwt_fails_with_invalid_signature() {
        let token_manager = create_test_token_service().await;
        
        let audit_db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create audit database");
        AuditMigrator::up(&audit_db, None)
            .await
            .expect("Failed to run audit migrations");
        let audit_store = Arc::new(AuditStore::new(audit_db));
        
        let wrong_token_manager = TokenService::new(
            "wrong-secret-key-minimum-32-characters".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store,
        );
        let user_id = Uuid::new_v4();
        
        // Generate token with one secret
        let (token, _jwt_id) = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await.unwrap();
        
        // Try to validate with different secret
        let result = wrong_token_manager.validate_jwt(&token).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[tokio::test]
    async fn test_validate_jwt_fails_with_expired_jwt() {
        let token_manager = create_test_token_service().await;
        
        // Create an expired token manually
        let now = Utc::now().timestamp();
        let expired_claims = Claims {
            sub: Uuid::new_v4().to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 7200, // Issued 2 hours ago
            jti: Some(Uuid::new_v4().to_string()),
            is_owner: false,
            is_system_admin: false,
            is_role_admin: false,
            app_roles: vec![],
        };
        
        let expired_token = encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
        ).unwrap();
        
        let result = token_manager.validate_jwt(&expired_token).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::ExpiredToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected ExpiredToken error"),
        }
    }

    #[tokio::test]
    async fn test_generate_refresh_token_creates_unique_tokens() {
        let token_manager = create_test_token_service().await;
        
        let token1 = token_manager.generate_refresh_token();
        let token2 = token_manager.generate_refresh_token();
        
        // Tokens should be different
        assert_ne!(token1, token2);
        
        // Tokens should be base64-encoded (44 characters for 32 bytes)
        assert_eq!(token1.len(), 44);
        assert_eq!(token2.len(), 44);
    }

    #[tokio::test]
    async fn test_hash_refresh_token_produces_consistent_hashes() {
        let token_manager = create_test_token_service().await;
        
        let token = "test-refresh-token";
        let hash1 = token_manager.hash_refresh_token(token);
        let hash2 = token_manager.hash_refresh_token(token);
        
        // Same token should produce same hash
        assert_eq!(hash1, hash2);
        
        // Hash should be 64 characters (HMAC-SHA256 in hex)
        assert_eq!(hash1.len(), 64);
    }

    #[tokio::test]
    async fn test_hash_refresh_token_produces_different_hashes_for_different_tokens() {
        let token_manager = create_test_token_service().await;
        
        let token1 = "token1";
        let token2 = "token2";
        
        let hash1 = token_manager.hash_refresh_token(token1);
        let hash2 = token_manager.hash_refresh_token(token2);
        
        // Different tokens should produce different hashes
        assert_ne!(hash1, hash2);
    }

    // Tests for HMAC-based refresh token hashing (Requirement 7.4, 2.4)
    
    #[tokio::test]
    async fn test_hmac_refresh_token_hashing_produces_consistent_output() {
        let token_manager = create_test_token_service().await;
        
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

    #[tokio::test]
    async fn test_hmac_different_secrets_produce_different_hashes() {
        let token = "test-refresh-token-12345";
        
        let audit_db1 = Database::connect("sqlite::memory:").await.expect("Failed to create audit database");
        AuditMigrator::up(&audit_db1, None).await.expect("Failed to run audit migrations");
        let audit_store1 = Arc::new(AuditStore::new(audit_db1));
        
        let audit_db2 = Database::connect("sqlite::memory:").await.expect("Failed to create audit database");
        AuditMigrator::up(&audit_db2, None).await.expect("Failed to run audit migrations");
        let audit_store2 = Arc::new(AuditStore::new(audit_db2));
        
        let token_manager1 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "refresh-secret-one-minimum-32-chars".to_string(),
            audit_store1,
        );
        
        let token_manager2 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "refresh-secret-two-minimum-32-chars".to_string(),
            audit_store2,
        );
        
        let hash1 = token_manager1.hash_refresh_token(token);
        let hash2 = token_manager2.hash_refresh_token(token);
        
        // Different secrets should produce different hashes (prevents token minting)
        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_token_minting_prevention_without_correct_secret() {
        let token = "malicious-token-attempt";
        
        let audit_db1 = Database::connect("sqlite::memory:").await.expect("Failed to create audit database");
        AuditMigrator::up(&audit_db1, None).await.expect("Failed to run audit migrations");
        let audit_store1 = Arc::new(AuditStore::new(audit_db1));
        
        let audit_db2 = Database::connect("sqlite::memory:").await.expect("Failed to create audit database");
        AuditMigrator::up(&audit_db2, None).await.expect("Failed to run audit migrations");
        let audit_store2 = Arc::new(AuditStore::new(audit_db2));
        
        // Attacker tries to mint a token with wrong secret
        let attacker_token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "attacker-guessed-secret-wrong-value".to_string(),
            audit_store1,
        );
        
        // Legitimate server with correct secret
        let legitimate_token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "correct-refresh-secret-minimum-32-ch".to_string(),
            audit_store2,
        );
        
        let attacker_hash = attacker_token_manager.hash_refresh_token(token);
        let legitimate_hash = legitimate_token_manager.hash_refresh_token(token);
        
        // Attacker's hash won't match legitimate hash (can't mint valid tokens)
        assert_ne!(attacker_hash, legitimate_hash);
        
        // This simulates database lookup failure - attacker's hash won't be found
        // in database because it was computed with wrong secret
    }

    #[tokio::test]
    async fn test_hmac_output_is_deterministic_across_instances() {
        let token = "test-token-for-determinism";
        let secret = "shared-refresh-secret-minimum-32-c";
        
        let audit_db1 = Database::connect("sqlite::memory:").await.expect("Failed to create audit database");
        AuditMigrator::up(&audit_db1, None).await.expect("Failed to run audit migrations");
        let audit_store1 = Arc::new(AuditStore::new(audit_db1));
        
        let audit_db2 = Database::connect("sqlite::memory:").await.expect("Failed to create audit database");
        AuditMigrator::up(&audit_db2, None).await.expect("Failed to run audit migrations");
        let audit_store2 = Arc::new(AuditStore::new(audit_db2));
        
        // Create multiple TokenService instances with same secret
        let manager1 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            secret.to_string(),
            audit_store1,
        );
        
        let manager2 = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            secret.to_string(),
            audit_store2,
        );
        
        let hash1 = manager1.hash_refresh_token(token);
        let hash2 = manager2.hash_refresh_token(token);
        
        // Same secret and token should always produce same hash
        assert_eq!(hash1, hash2);
    }

    // Tests for Debug and Display trait protection
    
    #[tokio::test]
    async fn test_debug_trait_does_not_expose_jwt_secret() {
        let token_service = create_test_token_service().await;
        
        let debug_output = format!("{:?}", token_service);
        
        // Debug output should not contain the actual secrets
        assert!(!debug_output.contains("test-secret-key"));
        assert!(!debug_output.contains("test-refresh-secret"));
        
        // Debug output should contain redacted markers
        assert!(debug_output.contains("<redacted>"));
        assert!(debug_output.contains("TokenService"));
    }

    #[tokio::test]
    async fn test_debug_trait_does_not_expose_refresh_token_secret() {
        let token_service = create_test_token_service().await;
        
        let debug_output = format!("{:?}", token_service);
        
        // Debug output should not contain the refresh token secret
        assert!(!debug_output.contains("test-refresh-secret"));
        
        // Debug output should show redacted for both secrets
        let redacted_count = debug_output.matches("<redacted>").count();
        assert_eq!(redacted_count, 2, "Should have 2 redacted fields (jwt_secret and refresh_token_secret)");
    }

    #[tokio::test]
    async fn test_debug_trait_shows_non_sensitive_fields() {
        let token_service = create_test_token_service().await;
        
        let debug_output = format!("{:?}", token_service);
        
        // Debug output should show non-sensitive configuration
        assert!(debug_output.contains("jwt_expiration_minutes"));
        assert!(debug_output.contains("15"));
        assert!(debug_output.contains("refresh_expiration_days"));
        assert!(debug_output.contains("7"));
    }

    #[tokio::test]
    async fn test_display_trait_does_not_expose_secrets() {
        let token_service = create_test_token_service().await;
        
        let display_output = format!("{}", token_service);
        
        // Display output should not contain the actual secrets
        assert!(!display_output.contains("test-secret-key"));
        assert!(!display_output.contains("test-refresh-secret"));
        
        // Display output should show metadata only
        assert!(display_output.contains("TokenService"));
        assert!(display_output.contains("15min"));
        assert!(display_output.contains("7days"));
    }

    #[tokio::test]
    async fn test_display_trait_shows_configuration_summary() {
        let token_service = create_test_token_service().await;
        
        let display_output = format!("{}", token_service);
        
        // Display should show a human-readable summary
        assert!(display_output.contains("jwt_expiration: 15min"));
        assert!(display_output.contains("refresh_expiration: 7days"));
    }

    #[tokio::test]
    async fn test_jwt_includes_admin_roles() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        // Generate JWT with admin roles
        let (token, _jwt_id) = token_manager.generate_jwt(
            &user_id,
            true,  // is_owner
            true,  // is_system_admin
            false, // is_role_admin
            vec!["editor".to_string(), "viewer".to_string()],
            None
        ).await.unwrap();
        
        // Decode and verify admin roles in claims
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap();
        
        assert_eq!(decoded.claims.is_owner, true);
        assert_eq!(decoded.claims.is_system_admin, true);
        assert_eq!(decoded.claims.is_role_admin, false);
        assert_eq!(decoded.claims.app_roles, vec!["editor".to_string(), "viewer".to_string()]);
    }

    #[tokio::test]
    async fn test_jwt_with_no_admin_roles() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        // Generate JWT with no admin roles
        let (token, _jwt_id) = token_manager.generate_jwt(
            &user_id,
            false, // is_owner
            false, // is_system_admin
            false, // is_role_admin
            vec![],
            None
        ).await.unwrap();
        
        // Decode and verify no admin roles in claims
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap();
        
        assert_eq!(decoded.claims.is_owner, false);
        assert_eq!(decoded.claims.is_system_admin, false);
        assert_eq!(decoded.claims.is_role_admin, false);
        assert_eq!(decoded.claims.app_roles.len(), 0);
    }
}


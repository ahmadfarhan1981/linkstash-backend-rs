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
    use crate::test::utils::setup_test_stores;

    async fn create_test_token_service() -> TokenService {
        let (_db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        
        TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store,
        )
    }

    #[tokio::test]
    async fn test_jwt_expiration_is_15_minutes() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let (token, _jwt_id) = token_manager.generate_jwt(&user_id, false, false, false, vec![], None).await.unwrap();
        
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
    async fn test_generate_refresh_token_creates_unique_tokens() {
        let token_manager = create_test_token_service().await;
        
        let token1 = token_manager.generate_refresh_token();
        let token2 = token_manager.generate_refresh_token();
        
        assert_ne!(token1, token2);
        assert_eq!(token1.len(), 44); // base64-encoded 32 bytes
        assert_eq!(token2.len(), 44);
    }

    #[tokio::test]
    async fn test_hmac_different_secrets_produce_different_hashes() {
        let token = "test-refresh-token-12345";
        
        let (_db1, _audit_db1, _cred1, audit_store1) = setup_test_stores().await;
        let (_db2, _audit_db2, _cred2, audit_store2) = setup_test_stores().await;
        
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
        
        let (_db1, _audit_db1, _cred1, audit_store1) = setup_test_stores().await;
        let (_db2, _audit_db2, _cred2, audit_store2) = setup_test_stores().await;
        
        let attacker_token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "attacker-guessed-secret-wrong-value".to_string(),
            audit_store1,
        );
        
        let legitimate_token_manager = TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "correct-refresh-secret-minimum-32-ch".to_string(),
            audit_store2,
        );
        
        let attacker_hash = attacker_token_manager.hash_refresh_token(token);
        let legitimate_hash = legitimate_token_manager.hash_refresh_token(token);
        
        // Attacker's hash won't match legitimate hash (can't mint valid tokens)
        assert_ne!(attacker_hash, legitimate_hash);
    }

    #[tokio::test]
    async fn test_debug_trait_does_not_expose_secrets() {
        let token_service = create_test_token_service().await;
        
        let debug_output = format!("{:?}", token_service);
        
        assert!(!debug_output.contains("test-secret-key"));
        assert!(!debug_output.contains("test-refresh-secret"));
        assert!(debug_output.contains("<redacted>"));
        
        let redacted_count = debug_output.matches("<redacted>").count();
        assert_eq!(redacted_count, 2);
    }

    #[tokio::test]
    async fn test_display_trait_does_not_expose_secrets() {
        let token_service = create_test_token_service().await;
        
        let display_output = format!("{}", token_service);
        
        assert!(!display_output.contains("test-secret-key"));
        assert!(!display_output.contains("test-refresh-secret"));
        assert!(display_output.contains("15min"));
        assert!(display_output.contains("7days"));
    }

    #[tokio::test]
    async fn test_jwt_includes_admin_roles() {
        let token_manager = create_test_token_service().await;
        let user_id = Uuid::new_v4();
        
        let (token, _jwt_id) = token_manager.generate_jwt(
            &user_id,
            true,  // is_owner
            true,  // is_system_admin
            false, // is_role_admin
            vec!["editor".to_string(), "viewer".to_string()],
            None
        ).await.unwrap();
        
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
        
        let (token, _jwt_id) = token_manager.generate_jwt(
            &user_id,
            false, // is_owner
            false, // is_system_admin
            false, // is_role_admin
            vec![],
            None
        ).await.unwrap();
        
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


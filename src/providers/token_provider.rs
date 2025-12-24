use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use rand::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use std::fmt;
use std::sync::Arc;
use crate::audit::{audit_logger, AuditLogger};
use crate::types::internal::auth::Claims;
use crate::errors::InternalError;
use crate::errors::internal::CredentialError;
use crate::providers::crypto_provider;
use crate::stores::AuditStore;
use crate::config::SecretManager;

/// Provides JWT token generation, validation, and refresh token operations
/// 
/// Migrated from TokenService as part of service layer refactor.
/// Contains all business logic for token operations while maintaining
/// identical functionality and method signatures.
pub struct TokenProvider {
    secret_manager: Arc<SecretManager>,
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    audit_logger: Arc<AuditLogger>
}

impl TokenProvider {
    /// Create a new TokenProvider with the given SecretManager and audit store
    pub fn new(secret_manager: Arc<SecretManager>, audit_store: Arc<AuditStore>) -> Self {
        Self {
            secret_manager,
            jwt_expiration_minutes: 15, // 15 minutes as per requirements
            refresh_expiration_days: 7, // 7 days as per requirements
            audit_store,
        }
    }
    
    /// Generate a JWT for the given user with admin roles
    /// 
    /// Logs JWT issuance to audit database at point of action.
    /// 
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `user_id` - The UUID of the user (target of the JWT)
    /// * `is_owner` - Owner role flag
    /// * `is_system_admin` - System Admin role flag
    /// * `is_role_admin` - Role Admin role flag
    /// * `app_roles` - Application roles (list of role names)
    /// * `password_change_required` - Password change required flag
    /// 
    /// # Returns
    /// * `Result<(String, String), InternalError>` - Tuple of (encoded JWT, JWT ID) or an error
    pub async fn generate_jwt(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        user_id: &Uuid,
        is_owner: bool,
        is_system_admin: bool,
        is_role_admin: bool,
        app_roles: Vec<String>,
        password_change_required: bool,
    ) -> Result<(String, String), InternalError> {
        let now = Utc::now().timestamp();
        let expiration = now + (self.jwt_expiration_minutes * 60);
        
        // Validate expiration timestamp before creating JWT
        let expiration_dt = DateTime::from_timestamp(expiration, 0)
            .ok_or_else(|| InternalError::parse("timestamp", format!("Invalid expiration timestamp: {}", expiration)))?;
        
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
            password_change_required,
        };
        
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret_manager.jwt_secret().as_bytes()),
        )
        .map_err(|e| InternalError::crypto("jwt_generation", format!("Failed to generate JWT: {}", e)))?;
        
        // Log JWT issuance at point of action (expiration_dt already validated above)
        if let Err(audit_err) = audit_logger::log_jwt_issued(
            &self.audit_store,
            ctx,
            user_id.to_string(),
            jti.clone(),
            expiration_dt,
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
    /// * `Result<Claims, InternalError>` - The decoded claims or an error
    pub async fn validate_jwt(&self, token: &str) -> Result<Claims, InternalError> {
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret_manager.jwt_secret().as_bytes()),
            &validation,
        )
        .map_err(|e| {
            // Check if the error is due to expiration
            if e.to_string().contains("ExpiredSignature") {
                InternalError::from(CredentialError::ExpiredToken("jwt".to_string()))
            } else {
                InternalError::from(CredentialError::invalid_token("jwt", "invalid signature or malformed"))
            }
        });
        
        // Log validation failures at point of action
        if let Err(ref err) = token_data {
            // Try to extract claims without validation for audit logging
            if let Ok(unverified_claims) = self.extract_unverified_claims(token) {
                let failure_reason = match err {
                    InternalError::Credential(CredentialError::ExpiredToken(_)) => "expired",
                    InternalError::Credential(CredentialError::InvalidToken { .. }) => "invalid_signature",
                    _ => "validation_error",
                };
                
                // Create temporary RequestContext from unverified JWT claims for audit logging
                let ctx = crate::types::internal::context::RequestContext {
                    ip_address: None, // Not available in token validation context
                    request_id: uuid::Uuid::new_v4().to_string(),
                    authenticated: false, // JWT validation failed
                    claims: Some(unverified_claims.clone()),
                    source: crate::types::internal::context::RequestSource::API,
                    actor_id: unverified_claims.sub.clone(),
                };
                
                // Check if this is a tampering attempt (invalid signature)
                if matches!(err, InternalError::Credential(CredentialError::InvalidToken { .. })) {
                    if let Err(audit_err) = audit_logger::log_jwt_tampered(
                        &self.audit_store,
                        &ctx,
                        token.to_string(),
                        failure_reason.to_string(),
                    ).await {
                        tracing::error!("Failed to log JWT tampering: {:?}", audit_err);
                    }
                } else {
                    // Normal validation failure (expired, etc.)
                    if let Err(audit_err) = audit_logger::log_jwt_validation_failure(
                        &self.audit_store,
                        &ctx,
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
    fn extract_unverified_claims(&self, token: &str) -> Result<Claims, InternalError> {
        use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(b"dummy"),
            &validation,
        )
        .map_err(|_| InternalError::from(CredentialError::invalid_token("jwt", "malformed")))?;
        
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
        crypto_provider::hmac_sha256_token(self.secret_manager.refresh_token_secret(), token)
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

impl fmt::Debug for TokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenProvider")
            .field("secret_manager", &"<redacted>")
            .field("jwt_expiration_minutes", &self.jwt_expiration_minutes)
            .field("refresh_expiration_days", &self.refresh_expiration_days)
            .field("audit_store", &"<audit_store>")
            .finish()
    }
}

impl fmt::Display for TokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TokenProvider {{ jwt_expiration: {}min, refresh_expiration: {}days }}",
            self.jwt_expiration_minutes, self.refresh_expiration_days
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use crate::test::utils::setup_test_stores;

    async fn create_test_token_provider() -> TokenProvider {
        let (_db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        
        // Create mock SecretManager for testing
        // Set environment variables temporarily for SecretManager::init()
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
            std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
            std::env::set_var("REFRESH_TOKEN_SECRET", "test-refresh-secret-minimum-32-chars");
        }
        
        let secret_manager = Arc::new(crate::config::SecretManager::init()
            .expect("Failed to initialize test SecretManager"));
        
        TokenProvider::new(
            secret_manager,
            audit_store,
        )
    }

    #[tokio::test]
    async fn test_jwt_expiration_is_15_minutes() {
        let token_provider = create_test_token_provider().await;
        let user_id = Uuid::new_v4();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        let (token, _jwt_id) = token_provider.generate_jwt(&ctx, &user_id, false, false, false, vec![], false).await.unwrap();
        
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
        let token_provider = create_test_token_provider().await;
        
        let token1 = token_provider.generate_refresh_token();
        let token2 = token_provider.generate_refresh_token();
        
        assert_ne!(token1, token2);
        assert_eq!(token1.len(), 44); // base64-encoded 32 bytes
        assert_eq!(token2.len(), 44);
    }

    #[tokio::test]
    async fn test_hmac_different_secrets_produce_different_hashes() {
        let token = "test-refresh-token-12345";
        
        let (_db1, _audit_db1, _cred1, audit_store1) = setup_test_stores().await;
        let (_db2, _audit_db2, _cred2, audit_store2) = setup_test_stores().await;
        
        // Create first SecretManager with different refresh token secret
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
            std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
            std::env::set_var("REFRESH_TOKEN_SECRET", "refresh-secret-one-minimum-32-chars");
        }
        let secret_manager1 = Arc::new(crate::config::SecretManager::init()
            .expect("Failed to initialize test SecretManager"));
        
        let token_provider1 = TokenProvider::new(
            secret_manager1,
            audit_store1,
        );
        
        // Create second SecretManager with different refresh token secret
        unsafe {
            std::env::set_var("REFRESH_TOKEN_SECRET", "refresh-secret-two-minimum-32-chars");
        }
        let secret_manager2 = Arc::new(crate::config::SecretManager::init()
            .expect("Failed to initialize test SecretManager"));
        
        let token_provider2 = TokenProvider::new(
            secret_manager2,
            audit_store2,
        );
        
        let hash1 = token_provider1.hash_refresh_token(token);
        let hash2 = token_provider2.hash_refresh_token(token);
        
        // Different secrets should produce different hashes (prevents token minting)
        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_token_minting_prevention_without_correct_secret() {
        let token = "malicious-token-attempt";
        
        let (_db1, _audit_db1, _cred1, audit_store1) = setup_test_stores().await;
        let (_db2, _audit_db2, _cred2, audit_store2) = setup_test_stores().await;
        
        // Create attacker SecretManager with wrong secret
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
            std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
            std::env::set_var("REFRESH_TOKEN_SECRET", "attacker-guessed-secret-wrong-value");
        }
        let attacker_secret_manager = Arc::new(crate::config::SecretManager::init()
            .expect("Failed to initialize test SecretManager"));
        
        let attacker_token_provider = TokenProvider::new(
            attacker_secret_manager,
            audit_store1,
        );
        
        // Create legitimate SecretManager with correct secret
        unsafe {
            std::env::set_var("REFRESH_TOKEN_SECRET", "correct-refresh-secret-minimum-32-ch");
        }
        let legitimate_secret_manager = Arc::new(crate::config::SecretManager::init()
            .expect("Failed to initialize test SecretManager"));
        
        let legitimate_token_provider = TokenProvider::new(
            legitimate_secret_manager,
            audit_store2,
        );
        
        let attacker_hash = attacker_token_provider.hash_refresh_token(token);
        let legitimate_hash = legitimate_token_provider.hash_refresh_token(token);
        
        // Attacker's hash won't match legitimate hash (can't mint valid tokens)
        assert_ne!(attacker_hash, legitimate_hash);
    }

    #[tokio::test]
    async fn test_debug_trait_does_not_expose_secrets() {
        let token_provider = create_test_token_provider().await;
        
        let debug_output = format!("{:?}", token_provider);
        
        assert!(!debug_output.contains("test-secret-key"));
        assert!(!debug_output.contains("test-refresh-secret"));
        assert!(debug_output.contains("<redacted>"));
        
        let redacted_count = debug_output.matches("<redacted>").count();
        assert_eq!(redacted_count, 1); // Only secret_manager field is redacted now
    }

    #[tokio::test]
    async fn test_display_trait_does_not_expose_secrets() {
        let token_provider = create_test_token_provider().await;
        
        let display_output = format!("{}", token_provider);
        
        assert!(!display_output.contains("test-secret-key"));
        assert!(!display_output.contains("test-refresh-secret"));
        assert!(display_output.contains("15min"));
        assert!(display_output.contains("7days"));
    }

    #[tokio::test]
    async fn test_jwt_includes_admin_roles() {
        let token_provider = create_test_token_provider().await;
        let user_id = Uuid::new_v4();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        let (token, _jwt_id) = token_provider.generate_jwt(
            &ctx,
            &user_id,
            true,  // is_owner
            true,  // is_system_admin
            false, // is_role_admin
            vec!["editor".to_string(), "viewer".to_string()],
            false, // password_change_required
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
        let token_provider = create_test_token_provider().await;
        let user_id = Uuid::new_v4();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        let (token, _jwt_id) = token_provider.generate_jwt(
            &ctx,
            &user_id,
            false, // is_owner
            false, // is_system_admin
            false, // is_role_admin
            vec![],
            false, // password_change_required
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

    #[tokio::test]
    async fn test_jwt_includes_password_change_required_flag() {
        let token_provider = create_test_token_provider().await;
        let user_id = Uuid::new_v4();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        // Test with password_change_required = true
        let (token_true, _jwt_id) = token_provider.generate_jwt(
            &ctx,
            &user_id,
            false,
            false,
            false,
            vec![],
            true, // password_change_required
        ).await.unwrap();
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let decoded_true = decode::<Claims>(
            &token_true,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap();
        
        assert_eq!(decoded_true.claims.password_change_required, true);
        
        // Test with password_change_required = false
        let (token_false, _jwt_id) = token_provider.generate_jwt(
            &ctx,
            &user_id,
            false,
            false,
            false,
            vec![],
            false, // password_change_required
        ).await.unwrap();
        
        let decoded_false = decode::<Claims>(
            &token_false,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap();
        
        assert_eq!(decoded_false.claims.password_change_required, false);
    }
}
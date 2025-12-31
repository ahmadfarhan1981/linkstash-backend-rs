use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use rand::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use std::fmt;
use std::sync::Arc;
use crate::types::internal::auth::Claims;
use crate::errors::InternalError;
use crate::errors::internal::CredentialError;
use crate::providers::CryptoProvider;
use crate::config::SecretManager;
use crate::stores::user_store::UserForJWT;

/// Provides JWT token generation, validation, and refresh token operations
/// 
/// Migrated from TokenService as part of service layer refactor.
/// Contains all business logic for token operations while maintaining
/// identical functionality and method signatures.
pub struct TokenProvider {
    secret_manager: Arc<SecretManager>,
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    // audit_store: Arc<AuditStore>,
    // crypto_provider: Arc<CryptoProvider>,
    // audit_logger: Arc<AuditLogger>
}
pub struct GeneratedJWT{
    pub jwt: String,
    pub jti: String,
}

pub struct GeneratedRT{
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
}
impl TokenProvider {
    /// Create a new TokenProvider with the given SecretManager and audit store
    pub fn new(secret_manager: Arc<SecretManager>) -> Self {
        Self {
            secret_manager,
            jwt_expiration_minutes: 15, // 15 minutes as per requirements
            refresh_expiration_days: 7, // 7 days as per requirements
            // audit_store,
            // crypto_provider,
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
        // ctx: &crate::types::internal::context::RequestContext,
        user: &UserForJWT,
    ) -> Result<GeneratedJWT, InternalError> {
        let now = Utc::now().timestamp();
        let expiration = now + (self.jwt_expiration_minutes * 60);
        
        // Validate expiration timestamp before creating JWT
        let expiration_dt = DateTime::from_timestamp(expiration, 0)
            .ok_or_else(|| InternalError::Parse { 
                value_type: "timestamp".to_string(), 
                message: format!("Invalid expiration timestamp: {}", expiration) 
            })?;
        
        // Generate unique JWT ID
        let jti = Uuid::new_v4().to_string();
        let UserForJWT{id, is_owner,
            is_system_admin,
            is_role_admin,
            app_roles,
            password_change_required, ..
        } = user.clone();
        let claims = Claims {
            sub: id,
            exp: expiration,
            iat: now,
            jti: jti.clone(),
            is_owner,
            is_system_admin,
            is_role_admin,
            app_roles: serde_json::from_str::<Vec<String>>(&app_roles).unwrap_or_else(|_| vec![]),
            password_change_required,
        };
        
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret_manager.jwt_secret().as_bytes()),
        )
        .map_err(|e| InternalError::Crypto { operation: "jwt_generation".to_string(), message: format!("Failed to generate JWT: {}", e) } )?;
        
        // Log JWT issuance at point of action (expiration_dt already validated above)
        // if let Err(audit_err) = audit_logger::log_jwt_issued(
        //     &self.audit_store,
        //     ctx,
        //     user_id.to_string(),
        //     jti.clone(),
        //     expiration_dt,
        // ).await {
        //     tracing::error!("Failed to log JWT issuance: {:?}", audit_err);
        // }
        
        Ok(GeneratedJWT{jwt, jti})
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
                InternalError::from(CredentialError::InvalidToken{ token_type: "jwt".to_string(), reason: "invalid signature or malformed".to_string() })
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
                    // if let Err(audit_err) = audit_logger::log_jwt_tampered(
                    //     &self.audit_store,
                    //     &ctx,
                    //     token.to_string(),
                    //     failure_reason.to_string(),
                    // ).await {
                    //     tracing::error!("Failed to log JWT tampering: {:?}", audit_err);
                    // }
                } else {
                    // Normal validation failure (expired, etc.)
                    // if let Err(audit_err) = audit_logger::log_jwt_validation_failure(
                    //     &self.audit_store,
                    //     &ctx,
                    //     failure_reason.to_string(),
                    // ).await {
                    //     tracing::error!("Failed to log JWT validation failure: {:?}", audit_err);
                    // }
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
        .map_err(|_| InternalError::from(CredentialError::InvalidToken{token_type:"jwt".to_string(), reason:"malformed".to_string()}))?;
        
        Ok(token_data.claims)
    }
    
    /// Generate a cryptographically secure refresh token
    /// 
    /// # Returns
    /// * `String` - A base64-encoded random token (32 bytes)
    pub fn generate_refresh_token(&self) -> GeneratedRT {
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();
        let token = general_purpose::STANDARD.encode(random_bytes);
        let created_at = Utc::now().timestamp();
        let expires_at = self.get_refresh_expiration(created_at);

        GeneratedRT{
            token,
            created_at,
            expires_at,
        }
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
    
    /// Get the expiration timestamp for a refresh token (7 days from now)
    /// 
    /// # Returns
    /// * `i64` - Unix timestamp for `refresh_expiration_days` days from now
    pub fn get_refresh_expiration(&self, created: i64) -> i64 {
        created + (self.refresh_expiration_days * 24 * 60 * 60)
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

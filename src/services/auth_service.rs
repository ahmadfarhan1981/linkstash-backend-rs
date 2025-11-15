use std::sync::Arc;
use uuid::Uuid;
use chrono::DateTime;

use crate::stores::{CredentialStore, AuditStore};
use crate::services::{TokenService, audit_logger};
use crate::errors::auth::AuthError;

/// Authentication service that orchestrates login, logout, and token refresh flows
/// 
/// This service coordinates between CredentialStore, TokenService, and AuditStore
/// to provide complete authentication flows with built-in audit logging.
pub struct AuthService {
    credential_store: Arc<CredentialStore>,
    token_service: Arc<TokenService>,
    audit_store: Arc<AuditStore>,
}

impl AuthService {
    /// Initialize AuthService with all dependencies
    /// 
    /// Creates internal stores and services, optionally seeds test user in development
    pub async fn init(
        db: sea_orm::DatabaseConnection,
        audit_db: sea_orm::DatabaseConnection,
        secret_manager: Arc<crate::config::SecretManager>,
    ) -> Result<Self, AuthError> {
        // Create internal dependencies
        let credential_store = Arc::new(CredentialStore::new(
            db.clone(),
            secret_manager.password_pepper().to_string()
        ));
        
        let token_service = Arc::new(TokenService::new(
            secret_manager.jwt_secret().to_string(),
            secret_manager.refresh_token_secret().to_string(),
        ));
        
        let audit_store = Arc::new(AuditStore::new(audit_db.clone()));
        
        let service = Self {
            credential_store: credential_store.clone(),
            token_service,
            audit_store,
        };
        
        // Seed test user for development
        service.seed_test_user().await;
        
        Ok(service)
    }
    
    /// Get a reference to the internal TokenService
    /// 
    /// Useful for API layer that needs direct access to token validation
    pub fn token_service(&self) -> Arc<TokenService> {
        self.token_service.clone()
    }
    
    /// Create a new AuthService (for testing or manual construction)
    pub fn new(
        credential_store: Arc<CredentialStore>,
        token_service: Arc<TokenService>,
        audit_store: Arc<AuditStore>,
    ) -> Self {
        Self {
            credential_store,
            token_service,
            audit_store,
        }
    }
    
    /// Seed test user for development (TODO: Remove in production)
    async fn seed_test_user(&self) {
        match self.credential_store.add_user("testuser".to_string(), "testpass".to_string()).await {
            Ok(user_id) => {
                tracing::info!("Test user created successfully with ID: {}", user_id);
            }
            Err(AuthError::DuplicateUsername(_)) => {
                tracing::debug!("Test user already exists, skipping creation");
            }
            Err(e) => {
                tracing::error!("Failed to create test user: {:?}", e);
            }
        }
    }
    
    /// Perform a complete login flow with audit logging
    /// 
    /// # Arguments
    /// * `ctx` - Request context with IP address and request_id
    /// * `username` - Username to authenticate
    /// * `password` - Password to verify
    /// 
    /// # Returns
    /// * `Result<(String, String), AuthError>` - Tuple of (access_token, refresh_token) or error
    pub async fn login(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        username: String,
        password: String,
    ) -> Result<(String, String), AuthError> {
        let user_id_result = self.credential_store
            .verify_credentials(&username, &password)
            .await;
        
        if let Err(ref err) = user_id_result {
            let failure_reason = match err {
                AuthError::InvalidCredentials(_) => "invalid_credentials",
                _ => "authentication_error",
            };
            
            if let Err(audit_err) = audit_logger::log_login_failure(
                &self.audit_store,
                None,
                failure_reason.to_string(),
                ctx.ip_address.clone(),
            ).await {
                tracing::error!("Failed to log login failure: {:?}", audit_err);
            }
            
            return Err(user_id_result.unwrap_err());
        }
        
        let user_id_str = user_id_result.unwrap();
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        let (access_token, jwt_id) = self.token_service.generate_jwt(&user_id)?;
        
        let refresh_token = self.token_service.generate_refresh_token();
        
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        let expires_at = self.token_service.get_refresh_expiration();
        self.credential_store
            .store_refresh_token(token_hash.clone(), user_id_str.clone(), expires_at)
            .await?;
        
        if let Err(audit_err) = audit_logger::log_login_success(
            &self.audit_store,
            user_id_str.clone(),
            ctx.ip_address.clone(),
        ).await {
            tracing::error!("Failed to log login success: {:?}", audit_err);
        }
        
        let expiration = DateTime::from_timestamp(expires_at, 0)
            .unwrap_or_else(|| chrono::Utc::now());
        if let Err(audit_err) = audit_logger::log_jwt_issued(
            &self.audit_store,
            user_id_str.clone(),
            jwt_id.clone(),
            expiration,
            ctx.ip_address.clone(),
        ).await {
            tracing::error!("Failed to log JWT issuance: {:?}", audit_err);
        }
        
        if let Err(audit_err) = audit_logger::log_refresh_token_issued(
            &self.audit_store,
            user_id_str,
            jwt_id,
            token_hash,
            ctx.ip_address.clone(),
        ).await {
            tracing::error!("Failed to log refresh token issuance: {:?}", audit_err);
        }
        
        Ok((access_token, refresh_token))
    }
    
    /// Refresh an access token using a refresh token
    /// 
    /// # Arguments
    /// * `ctx` - Request context with IP address and request_id
    /// * `refresh_token` - The refresh token to validate
    /// 
    /// # Returns
    /// * `Result<String, AuthError>` - New access token or error
    pub async fn refresh(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        refresh_token: String,
    ) -> Result<String, AuthError> {
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        
        let user_id_result = self.credential_store.validate_refresh_token(&token_hash).await;
        
        if let Err(ref err) = user_id_result {
            let failure_reason = match err {
                AuthError::InvalidRefreshToken(_) => "not_found",
                AuthError::ExpiredRefreshToken(_) => "expired",
                _ => "validation_error",
            };
            
            if let Err(audit_err) = audit_logger::log_refresh_token_validation_failure(
                &self.audit_store,
                token_hash.clone(),
                failure_reason.to_string(),
                ctx.ip_address.clone(),
            ).await {
                tracing::error!("Failed to log refresh token validation failure: {:?}", audit_err);
            }
            
            return Err(user_id_result.unwrap_err());
        }
        
        let user_id_str = user_id_result.unwrap();
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        let (access_token, jwt_id) = self.token_service.generate_jwt(&user_id)?;
        
        let expiration = DateTime::from_timestamp(
            self.token_service.get_refresh_expiration(),
            0
        ).unwrap_or_else(|| chrono::Utc::now());
        
        if let Err(audit_err) = audit_logger::log_jwt_issued(
            &self.audit_store,
            user_id_str,
            jwt_id,
            expiration,
            ctx.ip_address.clone(),
        ).await {
            tracing::error!("Failed to log JWT issuance: {:?}", audit_err);
        }
        
        Ok(access_token)
    }
    
    /// Logout by revoking a refresh token
    /// 
    /// The refresh token itself is the authority - no user ownership verification.
    /// Authentication is optional and only affects audit log quality.
    /// 
    /// # Arguments
    /// * `ctx` - Request context (may or may not be authenticated)
    /// * `refresh_token` - The refresh token to revoke
    /// 
    /// # Returns
    /// * `Ok(())` - Token revoked successfully
    /// * `Err(AuthError)` - Token not found or database error
    pub async fn logout(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        refresh_token: String,
    ) -> Result<(), AuthError> {
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        let user_id = self.credential_store.revoke_refresh_token(&token_hash).await?;
        
        if ctx.authenticated {
            let claims = ctx.claims.as_ref().unwrap();
            
            if let Err(audit_err) = audit_logger::log_refresh_token_revoked(
                &self.audit_store,
                user_id,
                claims.jti.clone(),
                token_hash,
            ).await {
                tracing::error!("Failed to log refresh token revocation: {:?}", audit_err);
            }
        } else {
            tracing::warn!("Unauthenticated logout from IP: {:?}, user_id: {}", ctx.ip_address, user_id);
            
            if let Err(audit_err) = audit_logger::log_refresh_token_revoked(
                &self.audit_store,
                user_id,
                None,
                token_hash,
            ).await {
                tracing::error!("Failed to log unauthenticated logout: {:?}", audit_err);
            }
        }
        
        Ok(())
    }
    
    /// Validate a JWT and log any validation failures
    /// 
    /// # Arguments
    /// * `token` - The JWT to validate
    /// 
    /// # Returns
    /// * `Result<Claims, AuthError>` - Decoded claims or error
    pub async fn validate_jwt(
        &self,
        token: &str,
    ) -> Result<crate::types::internal::auth::Claims, AuthError> {
        let result = self.token_service.validate_jwt(token);
        
        // If validation failed, try to extract claims for audit logging
        if let Err(ref err) = result {
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
        
        result
    }
    
    /// Extract claims from JWT without validation (for audit logging only)
    fn extract_unverified_claims(&self, token: &str) -> Result<crate::types::internal::auth::Claims, AuthError> {
        use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        
        let token_data = decode::<crate::types::internal::auth::Claims>(
            token,
            &DecodingKey::from_secret(b"dummy"),
            &validation,
        )
        .map_err(|_| AuthError::invalid_token())?;
        
        Ok(token_data.claims)
    }
}

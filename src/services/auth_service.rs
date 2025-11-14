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
    /// Create a new AuthService
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
    
    /// Perform a complete login flow with audit logging
    /// 
    /// # Arguments
    /// * `username` - Username to authenticate
    /// * `password` - Password to verify
    /// * `ip_address` - Optional IP address of the client for audit logging
    /// 
    /// # Returns
    /// * `Result<(String, String), AuthError>` - Tuple of (access_token, refresh_token) or error
    pub async fn login(
        &self,
        username: String,
        password: String,
        ip_address: Option<String>,
    ) -> Result<(String, String), AuthError> {
        // Verify credentials using database
        let user_id_result = self.credential_store
            .verify_credentials(&username, &password)
            .await;
        
        // Handle authentication failure
        if let Err(ref err) = user_id_result {
            let failure_reason = match err {
                AuthError::InvalidCredentials(_) => "invalid_credentials",
                _ => "authentication_error",
            };
            
            // Log login failure (without user_id since we don't have it)
            if let Err(audit_err) = audit_logger::log_login_failure(
                &self.audit_store,
                None,
                failure_reason.to_string(),
                ip_address,
            ).await {
                tracing::error!("Failed to log login failure: {:?}", audit_err);
            }
            
            return Err(user_id_result.unwrap_err());
        }
        
        let user_id_str = user_id_result.unwrap();
        
        // Parse user_id string to UUID
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        // Generate JWT
        let (access_token, jwt_id) = self.token_service.generate_jwt(&user_id)?;
        
        // Generate refresh token
        let refresh_token = self.token_service.generate_refresh_token();
        
        // Hash and store refresh token
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        let expires_at = self.token_service.get_refresh_expiration();
        self.credential_store
            .store_refresh_token(token_hash.clone(), user_id_str.clone(), expires_at)
            .await?;
        
        // Audit logging - all in one place
        
        // Log successful login
        if let Err(audit_err) = audit_logger::log_login_success(
            &self.audit_store,
            user_id_str.clone(),
            ip_address.clone(),
        ).await {
            tracing::error!("Failed to log login success: {:?}", audit_err);
        }
        
        // Log JWT issuance
        let expiration = DateTime::from_timestamp(expires_at, 0)
            .unwrap_or_else(|| chrono::Utc::now());
        if let Err(audit_err) = audit_logger::log_jwt_issued(
            &self.audit_store,
            user_id_str.clone(),
            jwt_id.clone(),
            expiration,
            ip_address.clone(),
        ).await {
            tracing::error!("Failed to log JWT issuance: {:?}", audit_err);
        }
        
        // Log refresh token issuance
        if let Err(audit_err) = audit_logger::log_refresh_token_issued(
            &self.audit_store,
            user_id_str,
            jwt_id,
            token_hash,
            ip_address,
        ).await {
            tracing::error!("Failed to log refresh token issuance: {:?}", audit_err);
        }
        
        Ok((access_token, refresh_token))
    }
    
    /// Refresh an access token using a refresh token
    /// 
    /// # Arguments
    /// * `refresh_token` - The refresh token to validate
    /// 
    /// # Returns
    /// * `Result<String, AuthError>` - New access token or error
    pub async fn refresh(&self, refresh_token: String) -> Result<String, AuthError> {
        // Hash the refresh token
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        
        // Validate refresh token and get user_id
        let user_id_str = self.credential_store.validate_refresh_token(&token_hash).await?;
        
        // Parse user_id string to UUID
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        // Generate new JWT
        let (access_token, jwt_id) = self.token_service.generate_jwt(&user_id)?;
        
        // Log JWT issuance
        let expiration = DateTime::from_timestamp(
            self.token_service.get_refresh_expiration(),
            0
        ).unwrap_or_else(|| chrono::Utc::now());
        
        if let Err(audit_err) = audit_logger::log_jwt_issued(
            &self.audit_store,
            user_id_str,
            jwt_id,
            expiration,
            None, // No IP address available in refresh flow
        ).await {
            tracing::error!("Failed to log JWT issuance: {:?}", audit_err);
        }
        
        Ok(access_token)
    }
    
    /// Logout by revoking a refresh token
    /// 
    /// # Arguments
    /// * `refresh_token` - The refresh token to revoke
    /// * `authenticated_user_id` - The user ID from the validated JWT (for authorization)
    /// * `jwt_id` - Optional JWT ID from the access token
    /// 
    /// # Returns
    /// * `Result<(), AuthError>` - Success or error
    pub async fn logout(
        &self,
        refresh_token: String,
        authenticated_user_id: String,
        jwt_id: Option<String>,
    ) -> Result<(), AuthError> {
        // Hash the refresh token
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        
        // Revoke refresh token only if it belongs to the authenticated user
        self.credential_store
            .revoke_refresh_token(&token_hash, &authenticated_user_id)
            .await?;
        
        // Log refresh token revocation
        if let Err(audit_err) = audit_logger::log_refresh_token_revoked(
            &self.audit_store,
            authenticated_user_id,
            jwt_id,
            token_hash,
        ).await {
            tracing::error!("Failed to log refresh token revocation: {:?}", audit_err);
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
    pub async fn validate_jwt_with_audit(
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

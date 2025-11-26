use std::sync::Arc;
use uuid::Uuid;

use crate::stores::{CredentialStore, AuditStore, SystemConfigStore};
use crate::services::TokenService;
use crate::errors::auth::AuthError;
use crate::types::internal::context::RequestContext;

/// Authentication service that orchestrates login, logout, and token refresh flows
/// 
/// This service coordinates between CredentialStore, TokenService, and AuditStore
/// to provide complete authentication flows with built-in audit logging.
pub struct AuthService {
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_service: Arc<TokenService>,
    audit_store: Arc<AuditStore>,
}

impl AuthService {
    /// Create AuthService from AppData
    /// 
    /// Extracts only the dependencies needed by AuthService from the centralized AppData.
    /// This is the preferred way to create AuthService in production code.
    pub fn new(app_data: Arc<crate::app_data::AppData>) -> Self {
        Self {
            credential_store: app_data.credential_store.clone(),
            system_config_store: app_data.system_config_store.clone(),
            token_service: app_data.token_service.clone(),
            audit_store: app_data.audit_store.clone(),
        }
    }
    
    /// Get a reference to the internal TokenService
    /// 
    /// Useful for API layer that needs direct access to token validation
    pub fn token_service(&self) -> Arc<TokenService> {
        self.token_service.clone()
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
        ctx: &RequestContext,
        username: String,
        password: String,
    ) -> Result<(String, String), AuthError> {
        // Credential verification with audit logging happens in the store
        let user_id_str = self.credential_store
            .verify_credentials(&username, &password, ctx.ip_address.clone())
            .await?;
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        // Fetch user data to get admin roles
        let user = self.credential_store.get_user_by_id(&user_id_str).await?;
        
        // Parse app_roles from JSON
        let app_roles = if let Some(roles_json) = &user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json)
                .unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        // Generate JWT with admin roles and audit logging at point of action
        let (access_token, jwt_id) = self.token_service.generate_jwt(
            &user_id,
            user.is_owner,
            user.is_system_admin,
            user.is_role_admin,
            app_roles,
            ctx.ip_address.clone(),
        ).await?;
        
        let refresh_token = self.token_service.generate_refresh_token();
        
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        let expires_at = self.token_service.get_refresh_expiration();
        
        // Store refresh token with audit logging in the store
        self.credential_store
            .store_refresh_token(
                token_hash.clone(),
                user_id_str.clone(),
                expires_at,
                jwt_id.clone(),
                ctx.ip_address.clone(),
            )
            .await?;
        
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
        ctx: &RequestContext,
        refresh_token: String,
    ) -> Result<String, AuthError> {
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        
        // Validation with audit logging happens in the store
        let user_id_str = self.credential_store
            .validate_refresh_token(&token_hash, ctx.ip_address.clone())
            .await?;
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        // Fetch user data to get admin roles
        let user = self.credential_store.get_user_by_id(&user_id_str).await?;
        
        // Parse app_roles from JSON
        let app_roles = if let Some(roles_json) = &user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json)
                .unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        // Generate JWT with admin roles and audit logging at point of action
        let (access_token, _jwt_id) = self.token_service.generate_jwt(
            &user_id,
            user.is_owner,
            user.is_system_admin,
            user.is_role_admin,
            app_roles,
            ctx.ip_address.clone(),
        ).await?;
        
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
        ctx: &RequestContext,
        refresh_token: String,
    ) -> Result<(), AuthError> {
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        
        // Extract jwt_id if authenticated
        let jwt_id = if ctx.authenticated {
            ctx.claims.as_ref().and_then(|c| c.jti.clone())
        } else {
            tracing::warn!("Unauthenticated logout from IP: {:?}", ctx.ip_address);
            None
        };
        
        // Revocation with audit logging happens in the store
        self.credential_store.revoke_refresh_token(&token_hash, jwt_id).await?;
        
        Ok(())
    }
    

}

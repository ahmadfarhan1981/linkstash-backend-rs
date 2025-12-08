use std::sync::Arc;
use uuid::Uuid;

use crate::stores::{CredentialStore, AuditStore, SystemConfigStore};
use crate::services::{TokenService, PasswordValidator};
use crate::errors::InternalError;
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
    password_validator: Arc<PasswordValidator>,
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
            password_validator: app_data.password_validator.clone(),
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
    /// * `Result<(String, String), InternalError>` - Tuple of (access_token, refresh_token) or error
    pub async fn login(
        &self,
        ctx: &RequestContext,
        username: String,
        password: String,
    ) -> Result<(String, String), InternalError> {
        let user_id_str = self.credential_store
            .verify_credentials(ctx, &username, &password)
            .await?;
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| InternalError::parse("UUID", e.to_string()))?;
        
        let user = self.credential_store.get_user_by_id(&user_id_str).await?;
        
        let app_roles = if let Some(roles_json) = &user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json)
                .unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        let (access_token, jwt_id) = self.token_service.generate_jwt(
            ctx,
            &user_id,
            user.is_owner,
            user.is_system_admin,
            user.is_role_admin,
            app_roles,
            user.password_change_required,
        ).await?;
        
        let refresh_token = self.token_service.generate_refresh_token();
        
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        let expires_at = self.token_service.get_refresh_expiration();
        
        self.credential_store
            .store_refresh_token_no_txn(
                ctx,
                token_hash.clone(),
                user_id_str.clone(),
                expires_at,
                jwt_id.clone(),
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
    /// * `Result<String, InternalError>` - New access token or error
    pub async fn refresh(
        &self,
        ctx: &RequestContext,
        refresh_token: String,
    ) -> Result<String, InternalError> {
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        
        let user_id_str = self.credential_store
            .validate_refresh_token(ctx, &token_hash)
            .await?;
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| InternalError::parse("UUID", e.to_string()))?;
        
        let user = self.credential_store.get_user_by_id(&user_id_str).await?;
        
        let app_roles = if let Some(roles_json) = &user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json)
                .unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        let (access_token, _jwt_id) = self.token_service.generate_jwt(
            ctx,
            &user_id,
            user.is_owner,
            user.is_system_admin,
            user.is_role_admin,
            app_roles,
            user.password_change_required,
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
    /// * `Err(InternalError)` - Token not found or database error
    pub async fn logout(
        &self,
        ctx: &RequestContext,
        refresh_token: String,
    ) -> Result<(), InternalError> {
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        
        // Unauthenticated logout is allowed but logged for security monitoring
        if !ctx.authenticated {
            tracing::warn!("Unauthenticated logout from IP: {:?}", ctx.ip_address);
        }
        
        self.credential_store.revoke_refresh_token(ctx, &token_hash).await?;
        
        Ok(())
    }
    
    /// Change user password
    /// 
    /// Orchestrates the password change flow by coordinating store operations.
    /// The store handles password verification, hashing, and atomic updates.
    /// 
    /// Validates the new password using PasswordValidator (length, username substring,
    /// common passwords, and compromised passwords via HIBP).
    /// 
    /// # Arguments
    /// * `ctx` - Request context containing authenticated user information
    /// * `old_password` - Current password to verify
    /// * `new_password` - New password to set (validated against all password policies)
    /// 
    /// # Returns
    /// * `Ok((access_token, refresh_token))` - New tokens on success
    /// * `Err(InternalError)` - Invalid credentials, validation failure, user not found, or database error
    pub async fn change_password(
        &self,
        ctx: &RequestContext,
        old_password: &str,
        new_password: &str,
    ) -> Result<(String, String), InternalError> {
        let user_id = ctx.claims.as_ref()
            .ok_or_else(|| InternalError::Credential(crate::errors::internal::CredentialError::InvalidCredentials))?
            .sub.clone();
        
        let user = self.credential_store.get_user_by_id(&user_id).await?;
        self.credential_store.verify_credentials(ctx, &user.username, old_password).await?;
        
        self.password_validator
            .validate(new_password, Some(&user.username))
            .await
            .map_err(|e| InternalError::Credential(crate::errors::internal::CredentialError::PasswordValidationFailed(e.to_string())))?;
        
        let txn = self.credential_store.begin_transaction(ctx, "password_change").await?;
        
        let update_result = self.credential_store.update_password_in_txn(&txn, ctx, &user_id, new_password).await;
        if let Err(e) = update_result {
            if let Err(audit_err) = crate::services::audit_logger::log_transaction_rolled_back(
                &self.audit_store,
                ctx,
                "password_change",
                &format!("update_password_failed: {}", e),
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(e);
        }
        
        let clear_flag_result = self.credential_store.clear_password_change_required_in_txn(&txn, ctx, &user_id).await;
        if let Err(e) = clear_flag_result {
            if let Err(audit_err) = crate::services::audit_logger::log_transaction_rolled_back(
                &self.audit_store,
                ctx,
                "password_change",
                &format!("clear_password_change_required_failed: {}", e),
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(e);
        }
        
        let revoke_result = self.credential_store.revoke_all_refresh_tokens_in_txn(&txn, &user_id).await;
        if let Err(e) = revoke_result {
            if let Err(audit_err) = crate::services::audit_logger::log_transaction_rolled_back(
                &self.audit_store,
                ctx,
                "password_change",
                &format!("revoke_tokens_failed: {}", e),
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(e);
        }
        
        let user_uuid = Uuid::parse_str(&user_id)
            .map_err(|e| InternalError::parse("UUID", e.to_string()))?;
        
        // Re-fetch user within transaction to get current password_change_required state
        let updated_user = self.credential_store.get_user_by_id_in_txn(&txn, &user_id).await?;
        
        let app_roles = if let Some(roles_json) = &updated_user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json).unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        let (access_token, jwt_id) = self.token_service.generate_jwt(
            ctx,
            &user_uuid,
            updated_user.is_owner,
            updated_user.is_system_admin,
            updated_user.is_role_admin,
            app_roles,
            updated_user.password_change_required,
        ).await?;
        
        let refresh_token = self.token_service.generate_refresh_token();
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        let expires_at = self.token_service.get_refresh_expiration();
        
        let store_result = self.credential_store.store_refresh_token_in_txn(
            &txn,
            ctx,
            token_hash,
            user_id.clone(),
            expires_at,
            jwt_id,
        ).await;
        if let Err(e) = store_result {
            if let Err(audit_err) = crate::services::audit_logger::log_transaction_rolled_back(
                &self.audit_store,
                ctx,
                "password_change",
                &format!("store_refresh_token_failed: {}", e),
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(e);
        }
        
        let commit_result = txn.commit().await;
        if let Err(e) = commit_result {
            if let Err(audit_err) = crate::services::audit_logger::log_transaction_rolled_back(
                &self.audit_store,
                ctx,
                "password_change",
                "commit_failed",
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(InternalError::transaction("commit_password_change", e));
        }
        
        if let Err(audit_err) = crate::services::audit_logger::log_transaction_committed(
            &self.audit_store,
            ctx,
            "password_change",
        ).await {
            tracing::error!("Failed to log transaction commit: {:?}", audit_err);
        }
        
        Ok((access_token, refresh_token))
    }

}


#[cfg(test)]
mod change_password_tests {
    use super::*;
    use crate::test::utils::setup_test_stores;
    use crate::types::internal::context::RequestContext;
    use sea_orm::ActiveModelTrait;
    
    #[tokio::test]
    async fn test_change_password_success() {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let old_password = format!("OldSecure-{}", Uuid::new_v4());
        let new_password = format!("NewSecure-{}", Uuid::new_v4());
        
        // Create a user
        let _user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to create user");
        
        // Create auth service
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store.clone(),
        ));
        
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        let password_validator = Arc::new(PasswordValidator::new(common_password_store, hibp_cache_store));
        
        let auth_service = AuthService {
            credential_store: credential_store.clone(),
            system_config_store,
            token_service: token_service.clone(),
            audit_store: audit_store.clone(),
            password_validator,
        };
        
        // Login to get authenticated context
        let mut ctx = RequestContext::new();
        let (access_token, _refresh_token) = auth_service
            .login(&ctx, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to login");
        
        // Validate JWT to get claims
        let claims = token_service.validate_jwt(&access_token).await.expect("Failed to validate JWT");
        ctx.authenticated = true;
        ctx.claims = Some(claims);
        
        // Change password
        let result = auth_service
            .change_password(&ctx, &old_password, &new_password)
            .await;
        
        assert!(result.is_ok());
        let (new_access_token, new_refresh_token) = result.unwrap();
        
        // Verify new tokens are valid
        assert!(!new_access_token.is_empty());
        assert!(!new_refresh_token.is_empty());
        
        // Verify can login with new password
        let login_result = auth_service
            .login(&RequestContext::new(), "testuser".to_string(), new_password.clone())
            .await;
        assert!(login_result.is_ok());
        
        // Verify cannot login with old password
        let old_login_result = auth_service
            .login(&RequestContext::new(), "testuser".to_string(), old_password)
            .await;
        assert!(old_login_result.is_err());
    }
    
    #[tokio::test]
    async fn test_change_password_fails_with_incorrect_old_password() {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Create a user
        let _user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), "SecureTest-CorrectPass-123".to_string())
            .await
            .expect("Failed to create user");
        
        // Create auth service
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store.clone(),
        ));
        
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        let password_validator = Arc::new(PasswordValidator::new(common_password_store, hibp_cache_store));
        
        let auth_service = AuthService {
            credential_store: credential_store.clone(),
            system_config_store,
            token_service: token_service.clone(),
            audit_store: audit_store.clone(),
            password_validator,
        };
        
        // Login to get authenticated context
        let mut ctx = RequestContext::new();
        let (access_token, _refresh_token) = auth_service
            .login(&ctx, "testuser".to_string(), "SecureTest-CorrectPass-123".to_string())
            .await
            .expect("Failed to login");
        
        // Validate JWT to get claims
        let claims = token_service.validate_jwt(&access_token).await.expect("Failed to validate JWT");
        ctx.authenticated = true;
        ctx.claims = Some(claims);
        
        // Try to change password with incorrect old password
        let result = auth_service
            .change_password(&ctx, "wrongpassword123", "newpassword123456")
            .await;
        
        assert!(result.is_err());
        match result {
            Err(InternalError::Credential(crate::errors::internal::CredentialError::InvalidCredentials)) => {
                // Expected error
            }
            _ => panic!("Expected InvalidCredentials error"),
        }
    }
    
    #[tokio::test]
    async fn test_change_password_revokes_old_refresh_tokens() {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let old_password = format!("OldSecure-{}", Uuid::new_v4());
        let new_password = format!("NewSecure-{}", Uuid::new_v4());
        
        // Create a user
        let _user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to create user");
        
        // Create auth service
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store.clone(),
        ));
        
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        let password_validator = Arc::new(PasswordValidator::new(common_password_store, hibp_cache_store));
        
        let auth_service = AuthService {
            credential_store: credential_store.clone(),
            system_config_store,
            token_service: token_service.clone(),
            audit_store: audit_store.clone(),
            password_validator,
        };
        
        // Login to get authenticated context and old refresh token
        let mut ctx = RequestContext::new();
        let (access_token, old_refresh_token) = auth_service
            .login(&ctx, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to login");
        
        // Validate JWT to get claims
        let claims = token_service.validate_jwt(&access_token).await.expect("Failed to validate JWT");
        ctx.authenticated = true;
        ctx.claims = Some(claims);
        
        // Change password
        let result = auth_service
            .change_password(&ctx, &old_password, &new_password)
            .await;
        
        assert!(result.is_ok());
        
        // Try to use old refresh token - should fail
        let refresh_result = auth_service
            .refresh(&RequestContext::new(), old_refresh_token)
            .await;
        
        assert!(refresh_result.is_err());
    }
    
    #[tokio::test]
    async fn test_login_includes_password_change_required_from_user_record() {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Create a user
        let user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to create user");
        
        // Manually set password_change_required to true in the database
        use sea_orm::{EntityTrait, Set};
        use crate::types::db::user;
        
        let mut user_model: user::ActiveModel = user::Entity::find_by_id(user_id.clone())
            .one(&db)
            .await
            .expect("Failed to find user")
            .expect("User not found")
            .into();
        
        user_model.password_change_required = Set(true);
        user_model.update(&db).await.expect("Failed to update user");
        
        // Create auth service
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store.clone(),
        ));
        
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        let password_validator = Arc::new(PasswordValidator::new(common_password_store, hibp_cache_store));
        
        let auth_service = AuthService {
            credential_store: credential_store.clone(),
            system_config_store,
            token_service: token_service.clone(),
            audit_store: audit_store.clone(),
            password_validator,
        };
        
        // Login
        let ctx = RequestContext::new();
        let (access_token, _refresh_token) = auth_service
            .login(&ctx, "testuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to login");
        
        // Validate JWT and check password_change_required flag
        let claims = token_service.validate_jwt(&access_token).await.expect("Failed to validate JWT");
        
        assert_eq!(claims.password_change_required, true, "JWT should include password_change_required=true from user record");
    }
    
    #[tokio::test]
    async fn test_refresh_includes_password_change_required_from_user_record() {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Create a user
        let user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to create user");
        
        // Create auth service
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store.clone(),
        ));
        
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        let password_validator = Arc::new(PasswordValidator::new(common_password_store, hibp_cache_store));
        
        let auth_service = AuthService {
            credential_store: credential_store.clone(),
            system_config_store,
            token_service: token_service.clone(),
            audit_store: audit_store.clone(),
            password_validator,
        };
        
        // Login to get refresh token
        let ctx = RequestContext::new();
        let (_access_token, refresh_token) = auth_service
            .login(&ctx, "testuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to login");
        
        // Manually set password_change_required to true in the database
        use sea_orm::{EntityTrait, Set};
        use crate::types::db::user;
        
        let mut user_model: user::ActiveModel = user::Entity::find_by_id(user_id.clone())
            .one(&db)
            .await
            .expect("Failed to find user")
            .expect("User not found")
            .into();
        
        user_model.password_change_required = Set(true);
        user_model.update(&db).await.expect("Failed to update user");
        
        // Refresh token
        let new_access_token = auth_service
            .refresh(&ctx, refresh_token)
            .await
            .expect("Failed to refresh token");
        
        // Validate JWT and check password_change_required flag
        let claims = token_service.validate_jwt(&new_access_token).await.expect("Failed to validate JWT");
        
        assert_eq!(claims.password_change_required, true, "Refreshed JWT should include password_change_required=true from user record");
    }
    
    #[tokio::test]
    async fn test_change_password_clears_password_change_required() {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let old_password = format!("OldSecure-{}", Uuid::new_v4());
        let new_password = format!("NewSecure-{}", Uuid::new_v4());
        
        // Create a user with password_change_required=true
        let user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to create user");
        
        // Set password_change_required to true
        use sea_orm::{EntityTrait, Set};
        use crate::types::db::user;
        
        let mut user_model: user::ActiveModel = user::Entity::find_by_id(user_id.clone())
            .one(&db)
            .await
            .expect("Failed to find user")
            .expect("User not found")
            .into();
        
        user_model.password_change_required = Set(true);
        user_model.update(&db).await.expect("Failed to update user");
        
        // Verify flag is set
        let user_before = user::Entity::find_by_id(user_id.clone())
            .one(&db)
            .await
            .expect("Failed to find user")
            .expect("User not found");
        assert_eq!(user_before.password_change_required, true, "password_change_required should be true before password change");
        
        // Create auth service
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store.clone(),
        ));
        
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        let password_validator = Arc::new(PasswordValidator::new(common_password_store, hibp_cache_store));
        
        let auth_service = AuthService {
            credential_store: credential_store.clone(),
            system_config_store,
            token_service: token_service.clone(),
            audit_store: audit_store.clone(),
            password_validator,
        };
        
        // Login to get authenticated context
        let mut ctx = RequestContext::new();
        let (access_token, _refresh_token) = auth_service
            .login(&ctx, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to login");
        
        // Validate JWT to get claims
        let claims = token_service.validate_jwt(&access_token).await.expect("Failed to validate JWT");
        ctx.authenticated = true;
        ctx.claims = Some(claims);
        
        // Change password
        let result = auth_service
            .change_password(&ctx, &old_password, &new_password)
            .await;
        
        assert!(result.is_ok(), "Password change should succeed");
        
        // Verify flag is cleared in database
        let user_after = user::Entity::find_by_id(user_id.clone())
            .one(&db)
            .await
            .expect("Failed to find user")
            .expect("User not found");
        assert_eq!(user_after.password_change_required, false, "password_change_required should be false after successful password change");
    }
    
    #[tokio::test]
    async fn test_change_password_reads_password_change_required_from_transaction() {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let old_password = format!("OldSecure-{}", Uuid::new_v4());
        let new_password = format!("NewSecure-{}", Uuid::new_v4());
        
        // Create a user with password_change_required=true
        let user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to create user");
        
        // Set password_change_required to true
        use sea_orm::{EntityTrait, Set};
        use crate::types::db::user;
        
        let mut user_model: user::ActiveModel = user::Entity::find_by_id(user_id.clone())
            .one(&db)
            .await
            .expect("Failed to find user")
            .expect("User not found")
            .into();
        
        user_model.password_change_required = Set(true);
        user_model.update(&db).await.expect("Failed to update user");
        
        // Create auth service
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
            audit_store.clone(),
        ));
        
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        let password_validator = Arc::new(PasswordValidator::new(common_password_store, hibp_cache_store));
        
        let auth_service = AuthService {
            credential_store: credential_store.clone(),
            system_config_store,
            token_service: token_service.clone(),
            audit_store: audit_store.clone(),
            password_validator,
        };
        
        // Login to get authenticated context
        let mut ctx = RequestContext::new();
        let (access_token, _refresh_token) = auth_service
            .login(&ctx, "testuser".to_string(), old_password.clone())
            .await
            .expect("Failed to login");
        
        // Validate JWT to get claims
        let claims = token_service.validate_jwt(&access_token).await.expect("Failed to validate JWT");
        ctx.authenticated = true;
        ctx.claims = Some(claims);
        
        // Verify initial JWT has password_change_required=true
        let initial_claims = token_service.validate_jwt(&access_token).await.expect("Failed to validate JWT");
        assert_eq!(initial_claims.password_change_required, true, "Initial JWT should have password_change_required=true");
        
        // Change password
        let result = auth_service
            .change_password(&ctx, &old_password, &new_password)
            .await;
        
        assert!(result.is_ok());
        let (new_access_token, _new_refresh_token) = result.unwrap();
        
        // Verify new JWT reads password_change_required from database
        // Task 21 clears the flag after successful password change
        let new_claims = token_service.validate_jwt(&new_access_token).await.expect("Failed to validate JWT");
        assert_eq!(new_claims.password_change_required, false, "New JWT should have password_change_required=false after successful password change (task 21 clears it)");
    }
}

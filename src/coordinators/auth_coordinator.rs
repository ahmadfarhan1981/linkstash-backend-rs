use std::sync::Arc;
use uuid::Uuid;

use crate::app_data::AppData;
use crate::providers::{TokenProvider, PasswordValidatorProvider, AuditLogger};
use crate::stores::{CredentialStore, SystemConfigStore};
use crate::errors::InternalError;
use crate::types::internal::context::RequestContext;

/// Authentication coordinator that orchestrates login, logout, and token refresh workflows
/// 
/// Migrated from AuthService as part of service layer refactor.
/// Handles pure workflow orchestration by composing provider operations
/// for authentication-related API endpoints. Contains no business logic.
pub struct AuthCoordinator {
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_provider: Arc<TokenProvider>,
    password_validator_provider: Arc<PasswordValidatorProvider>,
    audit_logger_provider: Arc<AuditLogger>,
}

impl AuthCoordinator {
    /// Create AuthCoordinator from AppData
    /// 
    /// Follows the AppData pattern: takes Arc<AppData> as single parameter,
    /// extracts stores from AppData, and creates providers internally.
    /// 
    /// # Arguments
    /// * `app_data` - Application data containing all stores and configuration
    pub fn new(app_data: Arc<AppData>) -> Self {
        // Step 1: Create providers from AppData components
        let token_provider = Arc::new(TokenProvider::new(
            app_data.secret_manager.clone(),
            app_data.audit_store.clone(),
        ));
        
        let password_validator_provider = Arc::new(PasswordValidatorProvider::new(
            app_data.common_password_store.clone(),
            app_data.hibp_cache_store.clone(),
        ));
        
        let audit_logger_provider = Arc::new(AuditLogger::new(
            app_data.audit_store.clone(),
        ));
        
        // Step 2: Extract stores and assign providers
        Self {
            credential_store: app_data.credential_store.clone(),
            system_config_store: app_data.system_config_store.clone(),
            token_provider,
            password_validator_provider,
            audit_logger_provider,
        }
    }
    
    /// Get a reference to the internal TokenProvider
    /// 
    /// Useful for API layer that needs direct access to token validation
    pub fn token_provider(&self) -> Arc<TokenProvider> {
        self.token_provider.clone()
    }
    
    /// Orchestrate a complete login workflow with audit logging
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Verify credentials via credential store
    /// 2. Retrieve user details
    /// 3. Generate JWT via token provider
    /// 4. Generate refresh token via token provider
    /// 5. Store refresh token via credential store
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
        // Step 1: Verify credentials
        let user_id_str = self.credential_store
            .verify_credentials(ctx, &username, &password)
            .await?;
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| InternalError::parse("UUID", e.to_string()))?;
        
        // Step 2: Retrieve user details
        let user = self.credential_store.get_user_by_id(&user_id_str).await?;
        
        let app_roles = if let Some(roles_json) = &user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json)
                .unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        // Step 3: Generate JWT
        let (access_token, jwt_id) = self.token_provider.generate_jwt(
            ctx,
            &user_id,
            user.is_owner,
            user.is_system_admin,
            user.is_role_admin,
            app_roles,
            user.password_change_required,
        ).await?;
        
        // Step 4: Generate refresh token
        let refresh_token = self.token_provider.generate_refresh_token();
        
        let token_hash = self.token_provider.hash_refresh_token(&refresh_token);
        let expires_at = self.token_provider.get_refresh_expiration();
        
        // Step 5: Store refresh token
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
    
    /// Orchestrate refresh token workflow
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Hash refresh token via token provider
    /// 2. Validate refresh token via credential store
    /// 3. Retrieve user details
    /// 4. Generate new JWT via token provider
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
        // Step 1: Hash refresh token
        let token_hash = self.token_provider.hash_refresh_token(&refresh_token);
        
        // Step 2: Validate refresh token
        let user_id_str = self.credential_store
            .validate_refresh_token(ctx, &token_hash)
            .await?;
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| InternalError::parse("UUID", e.to_string()))?;
        
        // Step 3: Retrieve user details
        let user = self.credential_store.get_user_by_id(&user_id_str).await?;
        
        let app_roles = if let Some(roles_json) = &user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json)
                .unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        // Step 4: Generate new JWT
        let (access_token, _jwt_id) = self.token_provider.generate_jwt(
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
    
    /// Orchestrate logout workflow by revoking refresh token
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Hash refresh token via token provider
    /// 2. Revoke refresh token via credential store
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
        // Step 1: Hash refresh token
        let token_hash = self.token_provider.hash_refresh_token(&refresh_token);
        
        // Log unauthenticated logout for security monitoring
        if !ctx.authenticated {
            tracing::warn!("Unauthenticated logout from IP: {:?}", ctx.ip_address);
        }
        
        // Step 2: Revoke refresh token
        self.credential_store.revoke_refresh_token(ctx, &token_hash).await?;
        
        Ok(())
    }
    
    /// Orchestrate password change workflow
    /// 
    /// Coordinates the sequence of operations within a transaction:
    /// 1. Verify old password via credential store
    /// 2. Validate new password via password validator provider
    /// 3. Begin transaction
    /// 4. Update password in transaction
    /// 5. Clear password change required flag in transaction
    /// 6. Revoke all refresh tokens in transaction
    /// 7. Generate new JWT via token provider
    /// 8. Generate new refresh token via token provider
    /// 9. Store new refresh token in transaction
    /// 10. Commit transaction
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
        // Extract user ID from authenticated context
        let user_id = ctx.claims.as_ref()
            .ok_or_else(|| InternalError::Credential(crate::errors::internal::CredentialError::InvalidCredentials))?
            .sub.clone();
        
        // Step 1: Get user and verify old password
        let user = self.credential_store.get_user_by_id(&user_id).await?;
        self.credential_store.verify_credentials(ctx, &user.username, old_password).await?;
        
        // Step 2: Validate new password
        self.password_validator_provider
            .validate(new_password, Some(&user.username))
            .await
            .map_err(|e| InternalError::Credential(crate::errors::internal::CredentialError::PasswordValidationFailed(e.to_string())))?;
        
        // Step 3: Begin transaction
        let txn = self.credential_store.begin_transaction(ctx, "password_change").await?;
        
        // Step 4: Update password in transaction
        let update_result = self.credential_store.update_password_in_txn(&txn, ctx, &user_id, new_password).await;
        if let Err(e) = update_result {
            if let Err(audit_err) = self.audit_logger_provider.log_transaction_rolled_back(
                ctx,
                "password_change",
                &format!("update_password_failed: {}", e),
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(e);
        }
        
        // Step 5: Clear password change required flag in transaction
        let clear_flag_result = self.credential_store.clear_password_change_required_in_txn(&txn, ctx, &user_id).await;
        if let Err(e) = clear_flag_result {
            if let Err(audit_err) = self.audit_logger_provider.log_transaction_rolled_back(
                ctx,
                "password_change",
                &format!("clear_password_change_required_failed: {}", e),
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(e);
        }
        
        // Step 6: Revoke all refresh tokens in transaction
        let revoke_result = self.credential_store.revoke_all_refresh_tokens_in_txn(&txn, &user_id).await;
        if let Err(e) = revoke_result {
            if let Err(audit_err) = self.audit_logger_provider.log_transaction_rolled_back(
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
        
        // Step 7: Re-fetch user within transaction to get current password_change_required state
        let updated_user = self.credential_store.get_user_by_id_in_txn(&txn, &user_id).await?;
        
        let app_roles = if let Some(roles_json) = &updated_user.app_roles {
            serde_json::from_str::<Vec<String>>(roles_json).unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        
        // Step 8: Generate new JWT
        let (access_token, jwt_id) = self.token_provider.generate_jwt(
            ctx,
            &user_uuid,
            updated_user.is_owner,
            updated_user.is_system_admin,
            updated_user.is_role_admin,
            app_roles,
            updated_user.password_change_required,
        ).await?;
        
        // Step 9: Generate new refresh token
        let refresh_token = self.token_provider.generate_refresh_token();
        let token_hash = self.token_provider.hash_refresh_token(&refresh_token);
        let expires_at = self.token_provider.get_refresh_expiration();
        
        // Step 10: Store new refresh token in transaction
        let store_result = self.credential_store.store_refresh_token_in_txn(
            &txn,
            ctx,
            token_hash,
            user_id.clone(),
            expires_at,
            jwt_id,
        ).await;
        if let Err(e) = store_result {
            if let Err(audit_err) = self.audit_logger_provider.log_transaction_rolled_back(
                ctx,
                "password_change",
                &format!("store_refresh_token_failed: {}", e),
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(e);
        }
        
        // Step 11: Commit transaction
        let commit_result = txn.commit().await;
        if let Err(e) = commit_result {
            if let Err(audit_err) = self.audit_logger_provider.log_transaction_rolled_back(
                ctx,
                "password_change",
                "commit_failed",
            ).await {
                tracing::error!("Failed to log transaction rollback: {:?}", audit_err);
            }
            return Err(InternalError::transaction("commit_password_change", e));
        }
        
        // Log successful transaction commit
        if let Err(audit_err) = self.audit_logger_provider.log_transaction_committed(
            ctx,
            "password_change",
        ).await {
            tracing::error!("Failed to log transaction commit: {:?}", audit_err);
        }
        
        Ok((access_token, refresh_token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;
    use crate::types::internal::context::RequestContext;
    
    async fn create_test_auth_coordinator() -> AuthCoordinator {
        let (connections, credential_store, audit_store) = setup_test_stores().await;
        
        // Set environment variables temporarily for SecretManager::init()
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
            std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
            std::env::set_var("REFRESH_TOKEN_SECRET", "test-refresh-secret-minimum-32-chars");
        }
        
        let db = connections.auth.clone();
        // Create minimal AppData for testing
        let secret_manager = Arc::new(crate::config::SecretManager::init().unwrap());
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        
        let app_data = Arc::new(crate::app_data::AppData {
            connections,
            env_provider: Arc::new(crate::config::SystemEnvironment),
            secret_manager,
            audit_store,
            credential_store,
            system_config_store,
            common_password_store,
            hibp_cache_store,
        });
        
        AuthCoordinator::new(app_data)
    }

    #[tokio::test]
    async fn test_login_workflow_orchestration() {
        let coordinator = create_test_auth_coordinator().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let password = format!("SecureTest-{}", Uuid::new_v4());
        
        // Create a user first
        let _user_id = coordinator.credential_store
            .add_user(&password_validator, "testuser".to_string(), password.clone())
            .await
            .expect("Failed to create user");
        
        // Test login workflow
        let ctx = RequestContext::new();
        let result = coordinator.login(&ctx, "testuser".to_string(), password).await;
        
        assert!(result.is_ok());
        let (access_token, refresh_token) = result.unwrap();
        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_refresh_workflow_orchestration() {
        let coordinator = create_test_auth_coordinator().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let password = format!("SecureTest-{}", Uuid::new_v4());
        
        // Create a user and login first
        let _user_id = coordinator.credential_store
            .add_user(&password_validator, "testuser".to_string(), password.clone())
            .await
            .expect("Failed to create user");
        
        let ctx = RequestContext::new();
        let (_access_token, refresh_token) = coordinator.login(&ctx, "testuser".to_string(), password).await.unwrap();
        
        // Test refresh workflow
        let new_access_token = coordinator.refresh(&ctx, refresh_token).await;
        
        assert!(new_access_token.is_ok());
        assert!(!new_access_token.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_logout_workflow_orchestration() {
        let coordinator = create_test_auth_coordinator().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let password = format!("SecureTest-{}", Uuid::new_v4());
        
        // Create a user and login first
        let _user_id = coordinator.credential_store
            .add_user(&password_validator, "testuser".to_string(), password.clone())
            .await
            .expect("Failed to create user");
        
        let ctx = RequestContext::new();
        let (_access_token, refresh_token) = coordinator.login(&ctx, "testuser".to_string(), password).await.unwrap();
        
        // Test logout workflow
        let result = coordinator.logout(&ctx, refresh_token).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_provider_access() {
        let coordinator = create_test_auth_coordinator().await;
        
        // Test that we can access the token provider
        let token_provider = coordinator.token_provider();
        // The returned Arc should point to the same TokenProvider instance
        assert!(Arc::ptr_eq(&token_provider, &coordinator.token_provider));
    }
}
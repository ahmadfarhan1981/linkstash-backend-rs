use std::sync::Arc;

use crate::app_data::AppData;
use crate::providers::{TokenProvider, AuditLoggerProvider};
use crate::stores::{CredentialStore, SystemConfigStore};
use crate::errors::InternalError;
use crate::errors::internal::CredentialError;
use crate::types::internal::context::RequestContext;
use crate::types::internal::auth::AdminFlags;

/// Admin coordinator that orchestrates admin role management workflows
/// 
/// Migrated from AdminService as part of service layer refactor.
/// Handles pure workflow orchestration by composing provider operations
/// for admin management API endpoints. Contains no business logic.
pub struct AdminCoordinator {
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_provider: Arc<TokenProvider>,
    audit_logger_provider: Arc<AuditLoggerProvider>,
}

impl AdminCoordinator {
    /// Create AdminCoordinator from AppData
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
        
        let audit_logger_provider = Arc::new(AuditLoggerProvider::new(
            app_data.audit_store.clone(),
        ));
        
        // Step 2: Extract stores and assign providers
        Self {
            credential_store: app_data.credential_store.clone(),
            system_config_store: app_data.system_config_store.clone(),
            token_provider,
            audit_logger_provider,
        }
    }
    
    /// Get a reference to the internal TokenProvider
    /// 
    /// Useful for API layer that needs direct access to token validation
    pub fn token_provider(&self) -> Arc<TokenProvider> {
        self.token_provider.clone()
    }
    
    /// Orchestrate System Admin role assignment workflow
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Extract claims and validate authentication
    /// 2. Check authorization (requires owner)
    /// 3. Prevent self-modification
    /// 4. Get current user to preserve other privileges
    /// 5. Update privileges with is_system_admin=true
    /// 6. Invalidate all tokens to force re-authentication
    /// 
    /// # Authorization
    /// Requires is_owner=true in JWT claims
    /// 
    /// # Arguments
    /// * `ctx` - RequestContext with authenticated user info
    /// * `target_user_id` - User ID to assign System Admin role to
    /// 
    /// # Returns
    /// * `Ok(())` - Role assigned successfully
    /// * `Err(InternalError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn assign_system_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), InternalError> {
        // Step 1: Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| InternalError::parse("claims", "Unauthenticated"))?;
        
        // Step 2: Check authorization: only owner can assign System Admin
        if !claims.is_owner {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 3: Check self-modification: cannot assign role to yourself
        if claims.sub == target_user_id {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 4: Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await?;
        
        // Step 5: Build new AdminFlags with is_system_admin=true, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: true,
            is_role_admin: user.is_role_admin,
        };
        
        // Step 6: Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Step 7: Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "System Admin role assigned to user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Orchestrate System Admin role removal workflow
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Extract claims and validate authentication
    /// 2. Check authorization (requires owner)
    /// 3. Prevent self-modification
    /// 4. Get current user to preserve other privileges
    /// 5. Update privileges with is_system_admin=false
    /// 6. Invalidate all tokens to force re-authentication
    /// 
    /// # Authorization
    /// Requires is_owner=true in JWT claims
    /// 
    /// # Arguments
    /// * `ctx` - RequestContext with authenticated user info
    /// * `target_user_id` - User ID to remove System Admin role from
    /// 
    /// # Returns
    /// * `Ok(())` - Role removed successfully
    /// * `Err(InternalError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn remove_system_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), InternalError> {
        // Step 1: Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| InternalError::parse("claims", "Unauthenticated"))?;
        
        // Step 2: Check authorization: only owner can remove System Admin
        if !claims.is_owner {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 3: Check self-modification: cannot remove role from yourself
        if claims.sub == target_user_id {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 4: Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await?;
        
        // Step 5: Build new AdminFlags with is_system_admin=false, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: false,
            is_role_admin: user.is_role_admin,
        };
        
        // Step 6: Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Step 7: Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "System Admin role removed from user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Orchestrate Role Admin role assignment workflow
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Extract claims and validate authentication
    /// 2. Check authorization (requires owner OR system admin)
    /// 3. Prevent self-modification
    /// 4. Get current user to preserve other privileges
    /// 5. Update privileges with is_role_admin=true
    /// 6. Invalidate all tokens to force re-authentication
    /// 
    /// # Authorization
    /// Requires is_owner=true OR is_system_admin=true in JWT claims
    /// 
    /// # Arguments
    /// * `ctx` - RequestContext with authenticated user info
    /// * `target_user_id` - User ID to assign Role Admin role to
    /// 
    /// # Returns
    /// * `Ok(())` - Role assigned successfully
    /// * `Err(InternalError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn assign_role_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), InternalError> {
        // Step 1: Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| InternalError::parse("claims", "Unauthenticated"))?;
        
        // Step 2: Check authorization: owner OR system admin can assign Role Admin
        if !claims.is_owner && !claims.is_system_admin {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 3: Check self-modification: cannot assign role to yourself
        if claims.sub == target_user_id {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 4: Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await?;
        
        // Step 5: Build new AdminFlags with is_role_admin=true, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: user.is_system_admin,
            is_role_admin: true,
        };
        
        // Step 6: Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Step 7: Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "Role Admin role assigned to user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Orchestrate Role Admin role removal workflow
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Extract claims and validate authentication
    /// 2. Check authorization (requires owner OR system admin)
    /// 3. Prevent self-modification
    /// 4. Get current user to preserve other privileges
    /// 5. Update privileges with is_role_admin=false
    /// 6. Invalidate all tokens to force re-authentication
    /// 
    /// # Authorization
    /// Requires is_owner=true OR is_system_admin=true in JWT claims
    /// 
    /// # Arguments
    /// * `ctx` - RequestContext with authenticated user info
    /// * `target_user_id` - User ID to remove Role Admin role from
    /// 
    /// # Returns
    /// * `Ok(())` - Role removed successfully
    /// * `Err(InternalError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn remove_role_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), InternalError> {
        // Step 1: Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| InternalError::parse("claims", "Unauthenticated"))?;
        
        // Step 2: Check authorization: owner OR system admin can remove Role Admin
        if !claims.is_owner && !claims.is_system_admin {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 3: Check self-modification: cannot remove role from yourself
        if claims.sub == target_user_id {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 4: Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await?;
        
        // Step 5: Build new AdminFlags with is_role_admin=false, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: user.is_system_admin,
            is_role_admin: false,
        };
        
        // Step 6: Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Step 7: Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "Role Admin role removed from user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Orchestrate owner deactivation workflow (owner self-deactivation)
    /// 
    /// Coordinates the sequence of operations:
    /// 1. Extract claims and validate authentication
    /// 2. Check authorization (requires owner)
    /// 3. Set owner_active=false in system config
    /// 4. Invalidate all owner tokens
    /// 
    /// This allows the owner to deactivate their own account via API.
    /// Useful for locking the account after emergency use.
    /// 
    /// # Authorization
    /// Requires is_owner=true in JWT claims
    /// 
    /// # Arguments
    /// * `ctx` - RequestContext with authenticated owner info
    /// 
    /// # Returns
    /// * `Ok(())` - Owner deactivated successfully
    /// * `Err(InternalError)` - Authorization failed or database error
    pub async fn deactivate_owner(
        &self,
        ctx: &RequestContext,
    ) -> Result<(), InternalError> {
        // Step 1: Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| InternalError::parse("claims", "Unauthenticated"))?;
        
        // Step 2: Check authorization: only owner can deactivate themselves
        if !claims.is_owner {
            return Err(InternalError::from(CredentialError::InvalidCredentials));
        }
        
        // Step 3: Set owner_active=false in system config (with audit logging at point of action)
        self.system_config_store
            .set_owner_active(false, Some(claims.sub.clone()), ctx.ip_address.clone())
            .await?;
        
        // Step 4: Invalidate all tokens for the owner to force logout
        self.credential_store
            .invalidate_all_tokens(ctx, &claims.sub, "owner_deactivated")
            .await?;
        
        tracing::info!(
            "Owner account deactivated by {}",
            claims.sub
        );
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;
    use crate::types::internal::context::RequestContext;
    
    async fn create_test_admin_coordinator() -> AdminCoordinator {
        let (db, audit_db, credential_store, audit_store) = setup_test_stores().await;
        
        // Set environment variables temporarily for SecretManager::init()
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
            std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
            std::env::set_var("REFRESH_TOKEN_SECRET", "test-refresh-secret-minimum-32-chars");
        }
        
        // Create minimal AppData for testing
        let secret_manager = Arc::new(crate::config::SecretManager::init().unwrap());
        let system_config_store = Arc::new(crate::stores::SystemConfigStore::new(db.clone(), audit_store.clone()));
        let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
        let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(db.clone(), system_config_store.clone()));
        
        let app_data = Arc::new(crate::app_data::AppData {
            db,
            audit_db,
            env_provider: Arc::new(crate::config::SystemEnvironment),
            secret_manager,
            audit_store,
            credential_store,
            system_config_store,
            common_password_store,
            hibp_cache_store,
        });
        
        AdminCoordinator::new(app_data)
    }

    #[tokio::test]
    async fn test_token_provider_access() {
        let coordinator = create_test_admin_coordinator().await;
        
        // Test that we can access the token provider
        let token_provider = coordinator.token_provider();
        // The returned Arc should point to the same TokenProvider instance
        assert!(Arc::ptr_eq(&token_provider, &coordinator.token_provider));
    }

    #[tokio::test]
    async fn test_assign_system_admin_workflow_orchestration() {
        let coordinator = create_test_admin_coordinator().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let password = format!("SecureTest-{}", Uuid::new_v4());
        
        // Create owner and target users
        let owner_id = coordinator.credential_store
            .add_user(&password_validator, "owner".to_string(), password.clone())
            .await
            .expect("Failed to create owner");
        
        let target_id = coordinator.credential_store
            .add_user(&password_validator, "target".to_string(), password.clone())
            .await
            .expect("Failed to create target user");
        
        // Set owner privileges
        let owner_flags = AdminFlags {
            is_owner: true,
            is_system_admin: false,
            is_role_admin: false,
        };
        let ctx = RequestContext::new();
        coordinator.credential_store.set_privileges(&ctx, &owner_id, owner_flags).await.unwrap();
        
        // Create context with owner claims
        let mut owner_ctx = RequestContext::new();
        owner_ctx.authenticated = true;
        owner_ctx.claims = Some(crate::types::internal::auth::Claims {
            sub: owner_id.clone(),
            exp: 9999999999, // Far future
            iat: 1000000000,
            jti: Some("test-jwt-id".to_string()),
            is_owner: true,
            is_system_admin: false,
            is_role_admin: false,
            app_roles: vec![],
            password_change_required: false,
        });
        
        // Test assign system admin workflow
        let result = coordinator.assign_system_admin(&owner_ctx, &target_id).await;
        assert!(result.is_ok());
        
        // Verify the user now has system admin privileges
        let updated_user = coordinator.credential_store.get_user_by_id(&target_id).await.unwrap();
        assert!(updated_user.is_system_admin);
    }

    #[tokio::test]
    async fn test_deactivate_owner_workflow_orchestration() {
        let coordinator = create_test_admin_coordinator().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Use secure passwords that won't be in HIBP (UUID-based)
        use uuid::Uuid;
        let password = format!("SecureTest-{}", Uuid::new_v4());
        
        // Create owner user
        let owner_id = coordinator.credential_store
            .add_user(&password_validator, "owner".to_string(), password.clone())
            .await
            .expect("Failed to create owner");
        
        // Set owner privileges
        let owner_flags = AdminFlags {
            is_owner: true,
            is_system_admin: false,
            is_role_admin: false,
        };
        let ctx = RequestContext::new();
        coordinator.credential_store.set_privileges(&ctx, &owner_id, owner_flags).await.unwrap();
        
        // Create context with owner claims
        let mut owner_ctx = RequestContext::new();
        owner_ctx.authenticated = true;
        owner_ctx.claims = Some(crate::types::internal::auth::Claims {
            sub: owner_id.clone(),
            exp: 9999999999, // Far future
            iat: 1000000000,
            jti: Some("test-jwt-id".to_string()),
            is_owner: true,
            is_system_admin: false,
            is_role_admin: false,
            app_roles: vec![],
            password_change_required: false,
        });
        
        // Test deactivate owner workflow
        let result = coordinator.deactivate_owner(&owner_ctx).await;
        assert!(result.is_ok());
    }
}
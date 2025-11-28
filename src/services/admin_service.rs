use std::sync::Arc;
use crate::stores::{CredentialStore, SystemConfigStore, AuditStore};
use crate::services::TokenService;
use crate::errors::admin::AdminError;
use crate::types::internal::context::RequestContext;
use crate::types::internal::auth::AdminFlags;

/// Admin service that orchestrates admin role management operations
/// 
/// This service coordinates between CredentialStore, SystemConfigStore, TokenService,
/// and AuditStore to provide complete admin role management flows with built-in
/// authorization checks, self-modification prevention, and audit logging.
pub struct AdminService {
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_service: Arc<TokenService>,
    audit_store: Arc<AuditStore>,
}

impl AdminService {
    /// Create AdminService from AppData
    /// 
    /// Extracts only the dependencies needed by AdminService from the centralized AppData.
    /// This follows the same pattern as AuthService.
    /// 
    /// # Arguments
    /// * `app_data` - Centralized application data containing all stores and services
    /// 
    /// # Returns
    /// AdminService instance with references to required dependencies
    pub fn new(app_data: Arc<crate::app_data::AppData>) -> Self {
        Self {
            credential_store: app_data.credential_store.clone(),
            system_config_store: app_data.system_config_store.clone(),
            token_service: app_data.token_service.clone(),
            audit_store: app_data.audit_store.clone(),
        }
    }
    
    /// Get a reference to the TokenService
    /// 
    /// Useful for API layer that needs direct access to token validation
    /// 
    /// # Returns
    /// Arc reference to the TokenService
    pub fn token_service(&self) -> Arc<TokenService> {
        self.token_service.clone()
    }
    
    /// Assign System Admin role to a user
    /// 
    /// This method performs authorization checks (requires owner), prevents self-modification,
    /// updates the user's privileges in the database, and invalidates all active tokens
    /// to force re-authentication with updated JWT claims.
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
    /// * `Err(AdminError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn assign_system_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError> {
        // Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| AdminError::internal_error("Unauthenticated".to_string()))?;
        
        // Check authorization: only owner can assign System Admin
        if !claims.is_owner {
            return Err(AdminError::owner_required());
        }
        
        // Check self-modification: cannot assign role to yourself
        if claims.sub == target_user_id {
            return Err(AdminError::self_modification_denied());
        }
        
        // Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await
            .map_err(|_| AdminError::user_not_found(target_user_id.to_string()))?;
        
        // Build new AdminFlags with is_system_admin=true, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: true,
            is_role_admin: user.is_role_admin,
        };
        
        // Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "System Admin role assigned to user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Remove System Admin role from a user
    /// 
    /// This method performs authorization checks (requires owner), prevents self-modification,
    /// updates the user's privileges in the database, and invalidates all active tokens
    /// to force re-authentication with updated JWT claims.
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
    /// * `Err(AdminError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn remove_system_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError> {
        // Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| AdminError::internal_error("Unauthenticated".to_string()))?;
        
        // Check authorization: only owner can remove System Admin
        if !claims.is_owner {
            return Err(AdminError::owner_required());
        }
        
        // Check self-modification: cannot remove role from yourself
        if claims.sub == target_user_id {
            return Err(AdminError::self_modification_denied());
        }
        
        // Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await
            .map_err(|_| AdminError::user_not_found(target_user_id.to_string()))?;
        
        // Build new AdminFlags with is_system_admin=false, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: false,
            is_role_admin: user.is_role_admin,
        };
        
        // Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "System Admin role removed from user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Assign Role Admin role to a user
    /// 
    /// This method performs authorization checks (requires owner OR system admin),
    /// prevents self-modification, updates the user's privileges in the database,
    /// and invalidates all active tokens to force re-authentication with updated JWT claims.
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
    /// * `Err(AdminError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn assign_role_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError> {
        // Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| AdminError::internal_error("Unauthenticated".to_string()))?;
        
        // Check authorization: owner OR system admin can assign Role Admin
        if !claims.is_owner && !claims.is_system_admin {
            return Err(AdminError::owner_or_system_admin_required());
        }
        
        // Check self-modification: cannot assign role to yourself
        if claims.sub == target_user_id {
            return Err(AdminError::self_modification_denied());
        }
        
        // Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await
            .map_err(|_| AdminError::user_not_found(target_user_id.to_string()))?;
        
        // Build new AdminFlags with is_role_admin=true, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: user.is_system_admin,
            is_role_admin: true,
        };
        
        // Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "Role Admin role assigned to user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Remove Role Admin role from a user
    /// 
    /// This method performs authorization checks (requires owner OR system admin),
    /// prevents self-modification, updates the user's privileges in the database,
    /// and invalidates all active tokens to force re-authentication with updated JWT claims.
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
    /// * `Err(AdminError)` - Authorization failed, self-modification, user not found, or database error
    pub async fn remove_role_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError> {
        // Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| AdminError::internal_error("Unauthenticated".to_string()))?;
        
        // Check authorization: owner OR system admin can remove Role Admin
        if !claims.is_owner && !claims.is_system_admin {
            return Err(AdminError::owner_or_system_admin_required());
        }
        
        // Check self-modification: cannot remove role from yourself
        if claims.sub == target_user_id {
            return Err(AdminError::self_modification_denied());
        }
        
        // Get current user to build AdminFlags with updated privileges
        let user = self.credential_store.get_user_by_id(target_user_id).await
            .map_err(|_| AdminError::user_not_found(target_user_id.to_string()))?;
        
        // Build new AdminFlags with is_role_admin=false, preserving other flags
        let new_privileges = AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: user.is_system_admin,
            is_role_admin: false,
        };
        
        // Update privileges in database (with audit logging at point of action)
        self.credential_store.set_privileges(ctx, target_user_id, new_privileges).await?;
        
        // Invalidate all tokens to force re-authentication with updated claims
        self.credential_store.invalidate_all_tokens(ctx, target_user_id, "admin_role_changed").await?;
        
        tracing::info!(
            "Role Admin role removed from user {} by {}",
            target_user_id,
            claims.sub
        );
        
        Ok(())
    }
    
    /// Deactivate the owner account (owner self-deactivation)
    /// 
    /// This method allows the owner to deactivate their own account via API.
    /// It sets owner_active=false in system config and invalidates all owner tokens.
    /// This is useful for locking the account after emergency use.
    /// 
    /// # Authorization
    /// Requires is_owner=true in JWT claims
    /// 
    /// # Arguments
    /// * `ctx` - RequestContext with authenticated owner info
    /// 
    /// # Returns
    /// * `Ok(())` - Owner deactivated successfully
    /// * `Err(AdminError)` - Authorization failed or database error
    pub async fn deactivate_owner(
        &self,
        ctx: &RequestContext,
    ) -> Result<(), AdminError> {
        // Extract claims from context and check authentication
        let claims = ctx.claims.as_ref()
            .ok_or_else(|| AdminError::internal_error("Unauthenticated".to_string()))?;
        
        // Check authorization: only owner can deactivate themselves
        if !claims.is_owner {
            return Err(AdminError::owner_required());
        }
        
        // Set owner_active=false in system config (with audit logging at point of action)
        self.system_config_store
            .set_owner_active(false, Some(claims.sub.clone()), ctx.ip_address.clone())
            .await?;
        
        // Invalidate all tokens for the owner to force logout
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
#[path = "admin_service_tests.rs"]
mod admin_service_tests;

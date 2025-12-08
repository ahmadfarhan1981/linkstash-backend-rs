use poem_openapi::{payload::Json, OpenApi, Tags};
use poem::Request;
use crate::services::AdminService;
use crate::types::dto::admin::{
    AssignRoleRequest, AssignRoleResponse,
    RemoveRoleRequest, RemoveRoleResponse,
    DeactivateResponse,
};
use crate::api::auth::BearerAuth;
use crate::api::helpers;
use std::sync::Arc;

/// Admin role management API endpoints
pub struct AdminApi {
    admin_service: Arc<AdminService>,
}

impl AdminApi {
    /// Create a new AdminApi with the given AdminService
    pub fn new(admin_service: Arc<AdminService>) -> Self {
        Self { admin_service }
    }
}

/// API tags for admin endpoints
#[derive(Tags)]
enum AdminTags {
    /// Admin role management
    Admin,
}

#[OpenApi(prefix_path = "/api/admin")]
impl AdminApi {
    /// Grant System Admin privileges to a user
    /// 
    /// Assigns the System Admin role for day-to-day system operations.
    /// The user will need to re-authenticate to receive updated permissions.
    #[oai(path = "/roles/system-admin", method = "post", tag = "AdminTags::Admin")]
    async fn assign_system_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<AssignRoleRequest>,
    ) -> poem::Result<Json<AssignRoleResponse>> {
        // Admin endpoints should be blocked if password change is required
        let ctx = match helpers::create_request_context(
            req,
            Some(auth.0),
            &self.admin_service.token_service(),
        ).await.into_result() {
            Ok(ctx) => ctx,
            Err(auth_error) => {
                return Err(poem::Error::from_string(
                    auth_error.to_string(),
                    poem::http::StatusCode::FORBIDDEN,
                ));
            }
        };
        
        // Check authentication
        if !ctx.authenticated {
            return Err(poem::Error::from_string(
                "Unauthorized".to_string(),
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        
        // Call service layer and convert InternalError to AdminError
        self.admin_service
            .assign_system_admin(&ctx, &body.target_user_id)
            .await
            .map_err(|internal_error| {
                let admin_error = crate::errors::AdminError::from_internal_error(internal_error);
                poem::Error::from_string(
                    admin_error.to_string(),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;
        
        Ok(Json(AssignRoleResponse {
            success: true,
            message: "System Admin role assigned successfully".to_string(),
        }))
    }
    
    /// Revoke System Admin privileges from a user
    /// 
    /// Removes the System Admin role to revoke administrative privileges.
    /// The user will need to re-authenticate to receive updated permissions.
    #[oai(path = "/roles/system-admin", method = "delete", tag = "AdminTags::Admin")]
    async fn remove_system_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<RemoveRoleRequest>,
    ) -> poem::Result<Json<RemoveRoleResponse>> {
        // Admin endpoints should be blocked if password change is required
        let ctx = match helpers::create_request_context(
            req,
            Some(auth.0),
            &self.admin_service.token_service(),
        ).await.into_result() {
            Ok(ctx) => ctx,
            Err(auth_error) => {
                return Err(poem::Error::from_string(
                    auth_error.to_string(),
                    poem::http::StatusCode::FORBIDDEN,
                ));
            }
        };
        
        // Check authentication
        if !ctx.authenticated {
            return Err(poem::Error::from_string(
                "Unauthorized".to_string(),
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        
        // Call service layer and convert InternalError to AdminError
        self.admin_service
            .remove_system_admin(&ctx, &body.target_user_id)
            .await
            .map_err(|internal_error| {
                let admin_error = crate::errors::AdminError::from_internal_error(internal_error);
                poem::Error::from_string(
                    admin_error.to_string(),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;
        
        Ok(Json(RemoveRoleResponse {
            success: true,
            message: "System Admin role removed successfully".to_string(),
        }))
    }
    
    /// Grant Role Admin privileges to a user
    /// 
    /// Assigns the Role Admin role for application role management.
    /// The user will need to re-authenticate to receive updated permissions.
    #[oai(path = "/roles/role-admin", method = "post", tag = "AdminTags::Admin")]
    async fn assign_role_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<AssignRoleRequest>,
    ) -> poem::Result<Json<AssignRoleResponse>> {
        // Admin endpoints should be blocked if password change is required
        let ctx = match helpers::create_request_context(
            req,
            Some(auth.0),
            &self.admin_service.token_service(),
        ).await.into_result() {
            Ok(ctx) => ctx,
            Err(auth_error) => {
                return Err(poem::Error::from_string(
                    auth_error.to_string(),
                    poem::http::StatusCode::FORBIDDEN,
                ));
            }
        };
        
        // Check authentication
        if !ctx.authenticated {
            return Err(poem::Error::from_string(
                "Unauthorized".to_string(),
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        
        // Call service layer and convert InternalError to AdminError
        self.admin_service
            .assign_role_admin(&ctx, &body.target_user_id)
            .await
            .map_err(|internal_error| {
                let admin_error = crate::errors::AdminError::from_internal_error(internal_error);
                poem::Error::from_string(
                    admin_error.to_string(),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;
        
        Ok(Json(AssignRoleResponse {
            success: true,
            message: "Role Admin role assigned successfully".to_string(),
        }))
    }
    
    /// Revoke Role Admin privileges from a user
    /// 
    /// Removes the Role Admin role to revoke role management privileges.
    /// The user will need to re-authenticate to receive updated permissions.
    #[oai(path = "/roles/role-admin", method = "delete", tag = "AdminTags::Admin")]
    async fn remove_role_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<RemoveRoleRequest>,
    ) -> poem::Result<Json<RemoveRoleResponse>> {
        // Admin endpoints should be blocked if password change is required
        let ctx = match helpers::create_request_context(
            req,
            Some(auth.0),
            &self.admin_service.token_service(),
        ).await.into_result() {
            Ok(ctx) => ctx,
            Err(auth_error) => {
                return Err(poem::Error::from_string(
                    auth_error.to_string(),
                    poem::http::StatusCode::FORBIDDEN,
                ));
            }
        };
        
        // Check authentication
        if !ctx.authenticated {
            return Err(poem::Error::from_string(
                "Unauthorized".to_string(),
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        
        // Call service layer and convert InternalError to AdminError
        self.admin_service
            .remove_role_admin(&ctx, &body.target_user_id)
            .await
            .map_err(|internal_error| {
                let admin_error = crate::errors::AdminError::from_internal_error(internal_error);
                poem::Error::from_string(
                    admin_error.to_string(),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;
        
        Ok(Json(RemoveRoleResponse {
            success: true,
            message: "Role Admin role removed successfully".to_string(),
        }))
    }
    
    /// Deactivate the owner account
    /// 
    /// Locks the owner account after emergency use. CLI reactivation is required to log in again.
    #[oai(path = "/owner/deactivate", method = "post", tag = "AdminTags::Admin")]
    async fn deactivate_owner(
        &self,
        req: &Request,
        auth: BearerAuth,
    ) -> poem::Result<Json<DeactivateResponse>> {
        // Admin endpoints should be blocked if password change is required
        let ctx = match helpers::create_request_context(
            req,
            Some(auth.0),
            &self.admin_service.token_service(),
        ).await.into_result() {
            Ok(ctx) => ctx,
            Err(auth_error) => {
                return Err(poem::Error::from_string(
                    auth_error.to_string(),
                    poem::http::StatusCode::FORBIDDEN,
                ));
            }
        };
        
        // Check authentication
        if !ctx.authenticated {
            return Err(poem::Error::from_string(
                "Unauthorized".to_string(),
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        
        // Call service layer and convert InternalError to AdminError
        self.admin_service
            .deactivate_owner(&ctx)
            .await
            .map_err(|internal_error| {
                let admin_error = crate::errors::AdminError::from_internal_error(internal_error);
                poem::Error::from_string(
                    admin_error.to_string(),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;
        
        Ok(Json(DeactivateResponse {
            success: true,
            message: "Owner account deactivated successfully. CLI reactivation required to log in again.".to_string(),
        }))
    }
}

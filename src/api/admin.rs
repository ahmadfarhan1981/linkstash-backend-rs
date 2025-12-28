use poem_openapi::{payload::Json, OpenApi, Tags};
use poem::Request;
use crate::coordinators::AdminCoordinator;
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
    admin_coordinator: Arc<AdminCoordinator>,
}

impl AdminApi {
    /// Create a new AdminApi with the given AdminCoordinator
    pub fn new(admin_coordinator: Arc<AdminCoordinator>) -> Self {
        Self { admin_coordinator }
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
  
}

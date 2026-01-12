use poem::Request;
use poem_openapi::{OpenApi, Tags, payload::Json};
use std::sync::Arc;

/// Admin role management API endpoints
pub struct AdminApi {
    // admin_coordinator: Arc<AdminCoordinator>,
}

impl AdminApi {
    /// Create a new AdminApi with the given AdminCoordinator
    // pub fn new(admin_coordinator: Arc<AdminCoordinator>) -> Self {
    //     Self { admin_coordinator }
    // }
    pub fn new() -> Self {
        Self {}
    }
}

/// API tags for admin endpoints
#[derive(Tags)]
enum AdminTags {
    /// Admin role management
    Admin,
}

#[OpenApi(prefix_path = "/api/admin")]
impl AdminApi {}

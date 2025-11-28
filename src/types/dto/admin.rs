use poem_openapi::Object;

/// Request to assign an admin role to a user
#[derive(Object, Debug)]
pub struct AssignRoleRequest {
    /// The user ID to assign the role to
    pub target_user_id: String,
}

/// Response after assigning an admin role
#[derive(Object, Debug)]
pub struct AssignRoleResponse {
    /// Whether the operation was successful
    pub success: bool,
    
    /// Human-readable message describing the result
    pub message: String,
}

/// Request to remove an admin role from a user
#[derive(Object, Debug)]
pub struct RemoveRoleRequest {
    /// The user ID to remove the role from
    pub target_user_id: String,
}

/// Response after removing an admin role
#[derive(Object, Debug)]
pub struct RemoveRoleResponse {
    /// Whether the operation was successful
    pub success: bool,
    
    /// Human-readable message describing the result
    pub message: String,
}

/// Response after deactivating the owner account
#[derive(Object, Debug)]
pub struct DeactivateResponse {
    /// Whether the operation was successful
    pub success: bool,
    
    /// Human-readable message describing the result
    pub message: String,
}

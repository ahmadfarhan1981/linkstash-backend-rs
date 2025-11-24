# Admin Role API Management Design

## Overview

This design implements REST API endpoints for managing admin roles (System Admin and Role Admin) in the Linkstash authentication backend. Building on the bootstrap functionality from the admin-role-system spec, this adds remote management capabilities with proper authorization, self-modification prevention, token invalidation, and audit logging.

## Architecture

### API Flow

```
Client Request
    ↓
AdminApi (API Layer)
    ↓ Create RequestContext
    ↓ Check Authentication
    ↓ Extract Claims
    ↓
AdminService (Service Layer)
    ↓ Check Authorization (Owner/System Admin)
    ↓ Check Self-Modification
    ↓
CredentialStore (Store Layer)
    ↓ Update Admin Flags
    ↓ Log to Audit Database
    ↓
TokenService
    ↓ Invalidate Refresh Tokens
    ↓ Issue New JWT
    ↓
Response to Client
```

## Components and Interfaces

### 1. AdminService

Service layer component that orchestrates admin role management operations:

```rust
// src/services/admin_service.rs
pub struct AdminService {
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_service: Arc<TokenService>,
    audit_store: Arc<AuditStore>,
}

impl AdminService {
    /// Assign System Admin role to a user
    /// 
    /// # Authorization
    /// Requires is_owner=true in JWT claims
    /// 
    /// # Arguments
    /// * `ctx` - RequestContext with authenticated user info
    /// * `target_user_id` - User ID to assign role to
    /// 
    /// # Returns
    /// * `Ok(())` - Role assigned successfully
    /// * `Err(AdminError)` - Authorization failed, self-modification, or database error
    pub async fn assign_system_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError>;
    
    /// Remove System Admin role from a user
    pub async fn remove_system_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError>;
    
    /// Assign Role Admin role to a user
    /// 
    /// # Authorization
    /// Requires is_owner=true OR is_system_admin=true in JWT claims
    pub async fn assign_role_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError>;
    
    /// Remove Role Admin role from a user
    pub async fn remove_role_admin(
        &self,
        ctx: &RequestContext,
        target_user_id: &str,
    ) -> Result<(), AdminError>;
    
    /// Deactivate the owner account (owner self-deactivation)
    /// 
    /// # Authorization
    /// Requires is_owner=true in JWT claims
    pub async fn deactivate_owner(
        &self,
        ctx: &RequestContext,
    ) -> Result<(), AdminError>;
    
    // Helper methods
    async fn invalidate_user_tokens(&self, user_id: &str) -> Result<(), AdminError>;
}
```

**Authorization Logic:**
- `assign_system_admin` / `remove_system_admin`: Requires `is_owner=true`
- `assign_role_admin` / `remove_role_admin`: Requires `is_owner=true` OR `is_system_admin=true`
- `deactivate_owner`: Requires `is_owner=true`

**Self-Modification Check:**
```rust
// In each method before any role modification
if ctx.claims.unwrap().sub == target_user_id {
    return Err(AdminError::SelfModificationDenied);
}
```

### 2. AdminApi

API layer component that exposes REST endpoints:

```rust
// src/api/admin.rs
pub struct AdminApi {
    admin_service: Arc<AdminService>,
}

#[OpenApi(tag = "ApiTags::Admin")]
impl AdminApi {
    /// Assign System Admin role to a user
    /// 
    /// Requires Owner role
    #[oai(path = "/admin/roles/system-admin", method = "post")]
    async fn assign_system_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<AssignRoleRequest>,
    ) -> Result<Json<AssignRoleResponse>>;
    
    /// Remove System Admin role from a user
    /// 
    /// Requires Owner role
    #[oai(path = "/admin/roles/system-admin", method = "delete")]
    async fn remove_system_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<RemoveRoleRequest>,
    ) -> Result<Json<RemoveRoleResponse>>;
    
    /// Assign Role Admin role to a user
    /// 
    /// Requires Owner or System Admin role
    #[oai(path = "/admin/roles/role-admin", method = "post")]
    async fn assign_role_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<AssignRoleRequest>,
    ) -> Result<Json<AssignRoleResponse>>;
    
    /// Remove Role Admin role from a user
    /// 
    /// Requires Owner or System Admin role
    #[oai(path = "/admin/roles/role-admin", method = "delete")]
    async fn remove_role_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<RemoveRoleRequest>,
    ) -> Result<Json<RemoveRoleResponse>>;
    
    /// Deactivate owner account (owner self-deactivation)
    /// 
    /// Requires Owner role
    #[oai(path = "/admin/owner/deactivate", method = "post")]
    async fn deactivate_owner(
        &self,
        req: &Request,
        auth: BearerAuth,
    ) -> Result<Json<DeactivateResponse>>;
}
```

**Endpoint Pattern:**
```rust
async fn assign_system_admin(&self, req: &Request, auth: BearerAuth, body: Json<AssignRoleRequest>) -> Result<Json<AssignRoleResponse>> {
    // Create RequestContext
    let ctx = self.create_request_context(req, Some(auth)).await;
    
    // Check authentication
    if !ctx.authenticated {
        return Err(AuthError::Unauthorized.into());
    }
    
    // Call service layer
    self.admin_service
        .assign_system_admin(&ctx, &body.target_user_id)
        .await?;
    
    Ok(Json(AssignRoleResponse {
        success: true,
        message: "System Admin role assigned successfully".to_string(),
    }))
}
```

### 3. Request/Response DTOs

```rust
// src/types/dto/admin.rs
#[derive(Object)]
pub struct AssignRoleRequest {
    pub target_user_id: String,
}

#[derive(Object)]
pub struct AssignRoleResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Object)]
pub struct RemoveRoleRequest {
    pub target_user_id: String,
}

#[derive(Object)]
pub struct RemoveRoleResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Object)]
pub struct DeactivateResponse {
    pub success: bool,
    pub message: String,
}
```

### 4. Error Types

```rust
// src/errors/admin.rs
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("Owner role required")]
    OwnerRequired,
    
    #[error("System Admin role required")]
    SystemAdminRequired,
    
    #[error("Owner or System Admin role required")]
    OwnerOrSystemAdminRequired,
    
    #[error("Cannot modify your own admin roles")]
    SelfModificationDenied,
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
    
    #[error("Authentication error: {0}")]
    AuthError(#[from] crate::errors::auth::AuthError),
}

impl ResponseError for AdminError {
    fn status(&self) -> StatusCode {
        match self {
            Self::OwnerRequired | Self::SystemAdminRequired | Self::OwnerOrSystemAdminRequired => StatusCode::FORBIDDEN,
            Self::SelfModificationDenied => StatusCode::FORBIDDEN,
            Self::UserNotFound(_) => StatusCode::NOT_FOUND,
            Self::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::AuthError(_) => StatusCode::UNAUTHORIZED,
        }
    }
}
```

## Security Considerations

### 1. Authorization Checks

Service layer performs authorization before any role modification:

```rust
// Check if user has required role
let claims = ctx.claims.as_ref().ok_or(AdminError::AuthError(AuthError::Unauthorized))?;

// For System Admin operations
if !claims.is_owner {
    return Err(AdminError::OwnerRequired);
}

// For Role Admin operations
if !claims.is_owner && !claims.is_system_admin {
    return Err(AdminError::OwnerOrSystemAdminRequired);
}
```

### 2. Self-Modification Prevention

```rust
// Check for self-modification
if claims.sub == target_user_id {
    return Err(AdminError::SelfModificationDenied);
}
```

### 3. Token Invalidation

When admin roles change:
1. Delete all refresh tokens for the target user
2. User must re-authenticate to get new JWT with updated claims
3. Old JWTs become stale (claims don't match database state)

```rust
async fn invalidate_user_tokens(&self, user_id: &str) -> Result<(), AdminError> {
    use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
    
    RefreshToken::delete_many()
        .filter(Column::UserId.eq(user_id))
        .exec(&self.credential_store.db)
        .await?;
    
    Ok(())
}
```

### 4. Audit Logging

All operations logged at the store layer (point of action):
- Actor user_id (who performed the action)
- Target user_id (who was affected)
- Action type (assign/remove role)
- Role type (system_admin, role_admin)
- Timestamp and IP address

## Testing Strategy

### Unit Tests

1. **Authorization Logic**
   - Owner can assign/remove System Admin and Role Admin
   - System Admin can assign/remove Role Admin only
   - Non-admins cannot perform admin operations

2. **Self-Modification Checks**
   - Reject admin role self-assignment
   - Reject admin role self-removal

### Integration Tests

1. **Role Assignment Flow**
   - Owner assigns System Admin → verify database updated
   - System Admin assigns Role Admin → verify database updated
   - Verify tokens invalidated after role changes

2. **Permission Boundaries**
   - System Admin cannot assign System Admin (only Owner can)
   - Non-admin cannot assign any roles

3. **Audit Logging**
   - All role changes logged with correct metadata
   - Self-modification attempts logged

## Migration Path

No database migrations needed - this builds on the existing schema from admin-role-system spec.

## Dependencies

- Requires admin-role-system spec to be implemented first (database schema, JWT claims, store methods)
- Uses existing RequestContext pattern
- Uses existing audit logging infrastructure

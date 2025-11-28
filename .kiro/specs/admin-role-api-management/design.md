# Admin Role API Management Design

## Overview

This design implements REST API endpoints for managing admin roles (System Admin and Role Admin) in the Linkstash authentication backend. Building on the bootstrap functionality from the admin-role-system spec, this adds remote management capabilities with proper authorization, self-modification prevention, token invalidation, and audit logging.

## Architecture

### AppData Pattern

This implementation follows the AppData pattern where all stores and stateless services are created once in `main.rs` and shared across services via `Arc<AppData>`. This eliminates store duplication and provides stable service signatures.

**Initialization Flow:**
```
main.rs
  ↓
AppData::init()
  ↓ creates once
  ├─ credential_store
  ├─ system_config_store
  ├─ token_service
  └─ audit_store
  ↓ wrapped in Arc<AppData>
  ↓ passed to services
  ├─ AuthService::new(app_data)
  └─ AdminService::new(app_data) → extracts what it needs
```

See `docs/appdata-pattern.md` for complete documentation.

### API Flow

```
Client Request
    ↓
AdminApi (API Layer)
    ↓ Create RequestContext (using helpers)
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

### 0. API Helpers Module (Shared Infrastructure)

**Note:** Before implementing AdminApi, create a shared helpers module to avoid code duplication.

```rust
// src/api/helpers.rs
use poem::Request;
use poem_openapi::auth::Bearer;
use crate::types::internal::context::RequestContext;
use crate::services::TokenService;
use std::sync::Arc;

/// Extract IP address from request headers
/// 
/// Checks X-Forwarded-For, X-Real-IP, and falls back to remote address.
pub fn extract_ip_address(req: &Request) -> Option<String> {
    // Check X-Forwarded-For header (proxy/load balancer)
    if let Some(forwarded) = req.header("X-Forwarded-For") {
        if let Some(ip) = forwarded.split(',').next() {
            return Some(ip.trim().to_string());
        }
    }
    
    // Check X-Real-IP header (nginx)
    if let Some(real_ip) = req.header("X-Real-IP") {
        return Some(real_ip.to_string());
    }
    
    // Fall back to remote address
    req.remote_addr()
        .as_socket_addr()
        .map(|addr| addr.ip().to_string())
}

/// Create RequestContext from request and optional authentication
/// 
/// This helper function should be called at the beginning of every endpoint.
/// It creates a RequestContext with IP address and request_id, and if authentication
/// is provided, validates the JWT and populates the claims.
/// 
/// # Arguments
/// * `req` - The HTTP request
/// * `auth` - Optional Bearer token (None for unauthenticated endpoints)
/// * `token_service` - TokenService for JWT validation
/// 
/// # Returns
/// RequestContext with authenticated=true if JWT is valid, false otherwise
pub async fn create_request_context(
    req: &Request,
    auth: Option<Bearer>,
    token_service: &Arc<TokenService>,
) -> RequestContext {
    // Extract IP address
    let ip_address = extract_ip_address(req);
    
    // Create base context with IP and request_id (defaults to API source)
    let mut ctx = RequestContext::new()
        .with_ip_address(ip_address.unwrap_or_else(|| "unknown".to_string()));
    
    // If auth is provided, validate JWT and populate claims
    if let Some(bearer) = auth {
        match token_service.validate_jwt(&bearer.token).await {
            Ok(claims) => {
                ctx.actor_id = claims.sub.clone();
                ctx = ctx.with_auth(claims);
            }
            Err(_) => {
                // JWT validation failed, context remains unauthenticated
            }
        }
    }
    
    tracing::trace!("Request context created: {:?}", ctx);
    ctx
}
```

**Benefits:**
- Single implementation shared by all APIs (AuthApi, AdminApi, future APIs)
- Eliminates code duplication
- Easier to maintain and test
- Consistent behavior across all endpoints

**Migration:** AuthApi should be refactored to use these helpers before implementing AdminApi.

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
    /// Create AdminService from AppData
    /// 
    /// Extracts only the dependencies needed by AdminService from the centralized AppData.
    /// This follows the same pattern as AuthService.
    pub fn new(app_data: Arc<crate::app_data::AppData>) -> Self {
        Self {
            credential_store: app_data.credential_store.clone(),
            system_config_store: app_data.system_config_store.clone(),
            token_service: app_data.token_service.clone(),
            audit_store: app_data.audit_store.clone(),
        }
    }
    
    /// Get a reference to the TokenService (for AdminApi to validate JWTs)
    pub fn token_service(&self) -> Arc<TokenService> {
        self.token_service.clone()
    }
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
let claims = ctx.claims.as_ref()
    .ok_or_else(|| AdminError::internal_error("Unauthenticated".to_string()))?;

if claims.sub == target_user_id {
    return Err(AdminError::self_modification_denied());
}
```

### 2. AdminApi

API layer component that exposes REST endpoints:

```rust
// src/api/admin.rs
pub struct AdminApi {
    admin_service: Arc<AdminService>,
}

impl AdminApi {
    /// Create a new AdminApi
    pub fn new(admin_service: Arc<AdminService>) -> Self {
        Self { admin_service }
    }
}

// Note: AdminApi uses shared helpers from src/api/helpers.rs
// - helpers::create_request_context() - Creates RequestContext with JWT validation
// - helpers::extract_ip_address() - Extracts IP from request headers
// This avoids code duplication between AuthApi, AdminApi, and future APIs

/// API tags for admin endpoints
#[derive(Tags)]
enum AdminTags {
    /// Admin role management
    Admin,
}

#[OpenApi(prefix_path = "/api/admin")]
impl AdminApi {
    /// Assign System Admin role to a user
    /// 
    /// Requires Owner role
    #[oai(path = "/roles/system-admin", method = "post", tag = "AdminTags::Admin")]
    async fn assign_system_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<AssignRoleRequest>,
    ) -> poem::Result<Json<AssignRoleResponse>>;
    
    /// Remove System Admin role from a user
    /// 
    /// Requires Owner role
    #[oai(path = "/roles/system-admin", method = "delete", tag = "AdminTags::Admin")]
    async fn remove_system_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<RemoveRoleRequest>,
    ) -> poem::Result<Json<RemoveRoleResponse>>;
    
    /// Assign Role Admin role to a user
    /// 
    /// Requires Owner or System Admin role
    #[oai(path = "/roles/role-admin", method = "post", tag = "AdminTags::Admin")]
    async fn assign_role_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<AssignRoleRequest>,
    ) -> poem::Result<Json<AssignRoleResponse>>;
    
    /// Remove Role Admin role from a user
    /// 
    /// Requires Owner or System Admin role
    #[oai(path = "/roles/role-admin", method = "delete", tag = "AdminTags::Admin")]
    async fn remove_role_admin(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<RemoveRoleRequest>,
    ) -> poem::Result<Json<RemoveRoleResponse>>;
    
    /// Deactivate owner account (owner self-deactivation)
    /// 
    /// Requires Owner role
    #[oai(path = "/owner/deactivate", method = "post", tag = "AdminTags::Admin")]
    async fn deactivate_owner(
        &self,
        req: &Request,
        auth: BearerAuth,
    ) -> poem::Result<Json<DeactivateResponse>>;
}

// Note: Paths are relative to prefix_path "/api/admin"
// Full paths will be:
// - POST   /api/admin/roles/system-admin
// - DELETE /api/admin/roles/system-admin
// - POST   /api/admin/roles/role-admin
// - DELETE /api/admin/roles/role-admin
// - POST   /api/admin/owner/deactivate
```

**Endpoint Pattern:**
```rust
async fn assign_system_admin(
    &self, 
    req: &Request, 
    auth: BearerAuth, 
    body: Json<AssignRoleRequest>
) -> poem::Result<Json<AssignRoleResponse>> {
    // Use shared helper for context creation
    let ctx = helpers::create_request_context(
        req,
        Some(auth.0),
        &self.admin_service.token_service(),
    ).await;
    
    // Check authentication
    if !ctx.authenticated {
        return Err(poem::Error::from_string(
            "Unauthorized".to_string(),
            poem::http::StatusCode::UNAUTHORIZED,
        ));
    }
    
    // Call service layer (AdminError converts to poem::Error automatically)
    self.admin_service
        .assign_system_admin(&ctx, &body.target_user_id)
        .await
        .map_err(|e| poem::Error::from_string(
            e.message(),
            poem::http::StatusCode::from_u16(e.status_code()).unwrap(),
        ))?;
    
    Ok(Json(AssignRoleResponse {
        success: true,
        message: "System Admin role assigned successfully".to_string(),
    }))
}
```

**Note:** Uses `helpers::create_request_context()` from `src/api/helpers.rs` to avoid code duplication.

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

**NOTE:** `AdminError` already exists in `src/errors/admin.rs` from the admin-role-system spec. It already includes all required error variants:
- `OwnerRequired` - 403 Forbidden
- `SystemAdminRequired` - 403 Forbidden  
- `SelfModificationDenied` - 403 Forbidden
- `UserNotFound` - 404 Not Found
- `InternalError` - 500 Internal Server Error

**Additional error needed:**
```rust
// Add to existing AdminError enum in src/errors/admin.rs
#[derive(ApiResponse, Debug)]
pub enum AdminError {
    // ... existing variants ...
    
    /// Owner or System Admin role required
    #[oai(status = 403)]
    OwnerOrSystemAdminRequired(Json<AdminErrorResponse>),
}

impl AdminError {
    // ... existing methods ...
    
    /// Create an OwnerOrSystemAdminRequired error
    pub fn owner_or_system_admin_required() -> Self {
        AdminError::OwnerOrSystemAdminRequired(Json(AdminErrorResponse {
            error: "owner_or_system_admin_required".to_string(),
            message: "Owner or System Admin role required".to_string(),
            status_code: 403,
        }))
    }
}
```

**Error handling in AdminService:**
```rust
// Convert database errors to AdminError
impl From<sea_orm::DbErr> for AdminError {
    fn from(err: sea_orm::DbErr) -> Self {
        AdminError::internal_error(format!("Database error: {}", err))
    }
}

// Convert AuthError to AdminError
impl From<crate::errors::auth::AuthError> for AdminError {
    fn from(err: crate::errors::auth::AuthError) -> Self {
        AdminError::internal_error(format!("Authentication error: {}", err))
    }
}
```

## Security Considerations

### 1. Authorization Checks

Service layer performs authorization before any role modification:

```rust
// Check if user has required role
let claims = ctx.claims.as_ref()
    .ok_or_else(|| AdminError::internal_error("Unauthenticated".to_string()))?;

// For System Admin operations
if !claims.is_owner {
    return Err(AdminError::owner_required());
}

// For Role Admin operations
if !claims.is_owner && !claims.is_system_admin {
    return Err(AdminError::owner_or_system_admin_required());
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

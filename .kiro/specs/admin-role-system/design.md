# Admin Role System Design

## Overview

This design implements a three-tier administrative role system for the Linkstash authentication backend with clear separation of duties. The system introduces Owner (emergency admin management), System Admin (day-to-day operations), and Role Admin (reserved for future use) roles. The design emphasizes security through principle of least privilege, self-modification prevention, and comprehensive audit logging.

**Note:** The Role Admin role flag is included in the schema for future use, but the app_roles management functionality will be implemented in a separate spec.

## Architecture

### Role Hierarchy

```
Owner (is_owner)
├── Can assign/remove System Admin
├── Can assign/remove Role Admin
├── INACTIVE by default (emergency use only)
└── Only one per system

System Admin (is_system_admin)
├── Can assign/remove Role Admin
├── Can manage users (activate, ban, disable)
├── Can revoke tokens
└── Can manage system configuration

Role Admin (is_role_admin)
├── Reserved for future app_roles management
└── Flag exists in schema but functionality not yet implemented

User (no admin flags)
└── Standard user with no administrative privileges
```

**Design Decision:** Boolean flags instead of enum allows users to hold multiple admin roles simultaneously (e.g., a user can be both System Admin and Role Admin). This provides flexibility for small teams while maintaining clear permission boundaries.

### Admin Roles vs App Roles

- **Admin Roles**: Three boolean flags (`is_owner`, `is_system_admin`, `is_role_admin`) stored directly in user table
- **App Roles**: List of strings (e.g., `["editor", "viewer", "manager"]`) stored as JSON array in user table. The field exists in the schema for future use, but management functionality will be implemented in a separate spec.
- **Separation Rationale**: Admin roles control system-level permissions, while app_roles will control application-level permissions. This separation allows application developers to define their own role structure without conflicting with system administration.

## Components and Interfaces

### 1. Database Schema Changes

#### User Table Modifications

Add three new boolean columns and password change tracking to existing `user` table:

```rust
// In types/db/user.rs
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    
    // New admin role flags
    pub is_owner: bool,
    pub is_system_admin: bool,
    pub is_role_admin: bool,
    
    // Password change requirement
    pub password_change_required: bool,
    
    // Existing app_roles field (JSON array of strings)
    pub app_roles: Option<String>,  // JSON: ["role1", "role2"]
    
    pub created_at: DateTime,
    pub updated_at: DateTime,
}
```

**Migration Strategy:**
- Add columns with `DEFAULT FALSE` to avoid breaking existing data
- No data migration needed (all existing users default to non-admin and no password change required)

#### System Configuration Table

Create new singleton table for system-level flags:

```rust
// In types/db/system_config.rs
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "system_config")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,  // Always 1 (singleton table)
    pub owner_active: bool,
    pub updated_at: i64,
}
```

**Design Decision:** Single-row table with fixed schema provides type safety and simpler queries compared to key-value pairs. The table will only ever contain one row (id=1) representing the global system configuration.

**Owner Activation State:**
- Stored as boolean column `owner_active` in the single system_config row
- Default value is `false` (owner inactive)
- CLI commands modify this flag via UPDATE query
- Login checks this flag when authenticating owner account

### 2. JWT Claims Structure

Extend existing Claims struct to include admin roles and password change flag:

```rust
// In types/internal/auth.rs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // user_id
    pub jti: String,        // JWT ID (UUID)
    pub exp: i64,           // Expiration timestamp
    pub iat: i64,           // Issued at timestamp
    
    // New admin role claims
    pub is_owner: bool,
    pub is_system_admin: bool,
    pub is_role_admin: bool,
    
    // Password change requirement
    pub password_change_required: bool,
    
    // Existing app_roles claim
    pub app_roles: Vec<String>,
}
```

**Design Decision:** Include all roles and password change flag in JWT to enable stateless authorization checks without database queries. When roles change or password is updated, new JWTs are issued immediately.

### 3. CLI Commands Module

Create new module for CLI operations:

```rust
// In src/cli/mod.rs
pub mod bootstrap;
pub mod owner;
pub mod password_validator;
pub mod credential_export;
```

#### Bootstrap Command

```rust
// src/cli/bootstrap.rs
pub async fn bootstrap_system(db: &DatabaseConnection, audit_db: &DatabaseConnection) -> Result<()>
```

**Flow:**
1. Check if owner exists (reject if found)
2. Generate UUID username for owner account
3. Prompt for owner password (auto-generate or manual entry)
4. Accept any password without validation (validation will be added in future via password-management spec)
5. Create owner account (UUID username, is_owner=true)
6. System config already has `owner_active=false` from migration (no action needed)
7. Display owner credentials and export options
8. Display warning about owner being inactive
9. Prompt for System Admin count (0-10)
10. For each System Admin: prompt for password (auto-generate or manual), create account (UUID username, is_system_admin=true)
11. Handle each System Admin's credentials individually (display and export options)
12. Prompt for Role Admin count (0-10)
13. For each Role Admin: prompt for password (auto-generate or manual), create account (UUID username, is_role_admin=true)
14. Handle each Role Admin's credentials individually (display and export options)
15. Log bootstrap event to audit database

**Design Decision:** Individual credential handling for each account enables secure distribution to different administrators. Each account gets its own export file if requested. Passwords can be manually entered or auto-generated - manual passwords are accepted without validation for now (password strength enforcement will be added later via the password-management spec). Owner activation state is stored as a system-level flag (not on user record) since it's a global system state.

#### Owner Management Commands

```rust
// src/cli/owner.rs
pub async fn activate_owner(db: &DatabaseConnection, audit_db: &DatabaseConnection) -> Result<()>
pub async fn deactivate_owner(db: &DatabaseConnection, audit_db: &DatabaseConnection) -> Result<()>
pub async fn get_owner_info(db: &DatabaseConnection) -> Result<()>
```

**Security Note:** All commands require confirmation prompts and log to audit database.

### 4. Password Validation Library

Shared component for consistent password policy enforcement:

```rust
// src/services/password_validator.rs
pub struct PasswordValidator {
    min_length: usize,  // 15
    max_length: usize,  // 64
    common_passwords: HashSet<String>,  // Loaded from embedded list
}

impl PasswordValidator {
    pub fn validate(&self, password: &str) -> Result<(), ValidationError>
    pub fn generate_secure_password(&self) -> String  // For auto-generation
}
```

**Design Decision:** Use embedded common password list (e.g., top 10k from HaveIBeenPwned) to avoid external dependencies. List is compiled into binary for offline validation.

### 5. Credential Export Module

```rust
// src/cli/credential_export.rs
pub enum ExportFormat {
    DisplayOnly,
    CopyUsername,
    CopyPassword,
    KeePassXML,
    BitwardenJSON,
    Skip,
}

pub fn export_credentials(
    username: &str,
    password: &str,
    role_type: &str,
    format: ExportFormat
) -> Result<()>
```

**Export Formats:**
- **KeePassX XML**: Compatible with KeePass, KeePassX, KeePassXC
- **Bitwarden JSON**: Compatible with Bitwarden, Vaultwarden
- **Clipboard**: Uses `clipboard` crate for cross-platform support

**File Naming:** `{role_type}_{username}.{ext}` (e.g., `owner_a1b2c3d4.xml`)

### 6. API Endpoints

#### Admin Role Management

```rust
// src/api/admin.rs
#[OpenApi(tag = "ApiTags::Admin")]
impl AdminApi {
    // Owner operations
    #[oai(path = "/admin/roles/system-admin", method = "post")]
    async fn assign_system_admin(&self, req: &Request, auth: BearerAuth, body: AssignRoleRequest) -> Result<AssignRoleResponse>
    
    #[oai(path = "/admin/roles/system-admin", method = "delete")]
    async fn remove_system_admin(&self, req: &Request, auth: BearerAuth, body: RemoveRoleRequest) -> Result<RemoveRoleResponse>
    
    #[oai(path = "/admin/roles/role-admin", method = "post")]
    async fn assign_role_admin(&self, req: &Request, auth: BearerAuth, body: AssignRoleRequest) -> Result<AssignRoleResponse>
    
    #[oai(path = "/admin/roles/role-admin", method = "delete")]
    async fn remove_role_admin(&self, req: &Request, auth: BearerAuth, body: RemoveRoleRequest) -> Result<RemoveRoleResponse>
    
    // Owner self-deactivation
    #[oai(path = "/admin/owner/deactivate", method = "post")]
    async fn deactivate_owner(&self, req: &Request, auth: BearerAuth) -> Result<DeactivateResponse>
}

// src/api/auth.rs (extend existing)
#[OpenApi(tag = "ApiTags::Auth")]
impl AuthApi {
    // New endpoint for password change
    #[oai(path = "/auth/change-password", method = "post")]
    async fn change_password(&self, req: &Request, auth: BearerAuth, body: ChangePasswordRequest) -> Result<ChangePasswordResponse>
}
```

**Authorization Pattern:**
```rust
// Each endpoint checks appropriate admin flag from JWT claims
let ctx = self.create_request_context(req, Some(auth)).await;
if !ctx.authenticated {
    return Err(AuthError::Unauthorized);
}

let claims = ctx.claims.unwrap();

// Check if password change is required
if claims.password_change_required {
    return Err(AuthError::PasswordChangeRequired);
}

if !claims.is_owner {
    return Err(AuthError::Forbidden("Owner role required"));
}

// Check for self-modification
if claims.sub == target_user_id {
    return Err(AuthError::Forbidden("Cannot modify your own admin roles"));
}
```

**Password Change Enforcement:**
- All endpoints (except `/auth/change-password` and `/auth/whoami`) check `password_change_required` flag
- If true, return 403 with specific error message directing user to change password
- `/auth/change-password` endpoint is the only operation allowed when flag is set
- `/auth/whoami` endpoint is allowed to let users check their status

### 7. Service Layer

```rust
// src/services/admin_service.rs
pub struct AdminService {
    user_store: Arc<UserStore>,
    token_service: Arc<TokenService>,
    audit_store: Arc<AuditStore>,
}

impl AdminService {
    // Admin role management
    pub async fn assign_system_admin(&self, ctx: &RequestContext, target_user_id: &str) -> Result<()>
    pub async fn remove_system_admin(&self, ctx: &RequestContext, target_user_id: &str) -> Result<()>
    pub async fn assign_role_admin(&self, ctx: &RequestContext, target_user_id: &str) -> Result<()>
    pub async fn remove_role_admin(&self, ctx: &RequestContext, target_user_id: &str) -> Result<()>
    
    // Owner operations
    pub async fn deactivate_owner(&self, ctx: &RequestContext) -> Result<()>
    
    // Helper methods
    async fn invalidate_user_tokens(&self, user_id: &str) -> Result<()>
    async fn issue_new_tokens(&self, user_id: &str) -> Result<TokenPair>
}

// src/services/auth_service.rs (extend existing)
impl AuthService {
    // New method for password change
    pub async fn change_password(&self, ctx: &RequestContext, old_password: &str, new_password: &str) -> Result<TokenPair>
}
```

**Design Decision:** Service layer handles token invalidation and reissuance when roles change or password is updated. This ensures JWTs always reflect current permissions and password change status.

### 8. Store Layer

```rust
// src/stores/user_store.rs (extend existing)
impl UserStore {
    // Admin role operations
    pub async fn set_system_admin(&self, ctx: &RequestContext, user_id: &str, value: bool) -> Result<()>
    pub async fn set_role_admin(&self, ctx: &RequestContext, user_id: &str, value: bool) -> Result<()>
    
    // Owner operations
    pub async fn get_owner(&self) -> Result<Option<Model>>
}

// src/stores/system_config_store.rs (new)
impl SystemConfigStore {
    pub async fn get_config(&self) -> Result<Model>
    pub async fn set_owner_active(&self, ctx: &RequestContext, active: bool) -> Result<()>
    pub async fn is_owner_active(&self) -> Result<bool>
    
    // Helper to ensure singleton row exists
    async fn ensure_config_exists(&self) -> Result<()>
    
    // Password operations
    pub async fn update_password(&self, ctx: &RequestContext, user_id: &str, new_password_hash: &str) -> Result<()>
    pub async fn clear_password_change_required(&self, ctx: &RequestContext, user_id: &str) -> Result<()>
    
    // Bootstrap
    pub async fn create_admin_user(&self, ctx: &RequestContext, username: &str, password_hash: &str, admin_flags: AdminFlags) -> Result<Model>
}

pub struct AdminFlags {
    pub is_owner: bool,
    pub is_system_admin: bool,
    pub is_role_admin: bool,
}
```

**Logging Responsibility:** Store layer logs all role changes and password updates to audit database at point of action.

## Data Models

### Request/Response DTOs

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

#[derive(Object)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Object)]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub message: String,
    pub access_token: String,
    pub refresh_token: String,
}
```

## Error Handling

### New Error Types

```rust
// src/errors/admin.rs
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("Owner role required")]
    OwnerRequired,
    
    #[error("System Admin role required")]
    SystemAdminRequired,
    
    #[error("Role Admin role required")]
    RoleAdminRequired,
    
    #[error("Cannot modify your own admin roles")]
    SelfModificationDenied,
    
    #[error("Cannot modify your own roles")]
    SelfRoleModificationDenied,
    
    #[error("System already bootstrapped")]
    AlreadyBootstrapped,
    
    #[error("Owner account not found")]
    OwnerNotFound,
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Password validation failed: {0}")]
    PasswordValidationFailed(String),
    
    #[error("Password change required. Please change your password at /auth/change-password")]
    PasswordChangeRequired,
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
}

impl ResponseError for AdminError {
    fn status(&self) -> StatusCode {
        match self {
            Self::OwnerRequired | Self::SystemAdminRequired | Self::RoleAdminRequired => StatusCode::FORBIDDEN,
            Self::SelfModificationDenied | Self::SelfRoleModificationDenied => StatusCode::FORBIDDEN,
            Self::PasswordChangeRequired => StatusCode::FORBIDDEN,
            Self::AlreadyBootstrapped => StatusCode::CONFLICT,
            Self::OwnerNotFound | Self::UserNotFound(_) => StatusCode::NOT_FOUND,
            Self::PasswordValidationFailed(_) => StatusCode::BAD_REQUEST,
            Self::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    
    fn as_response(&self) -> Response {
        // Return consistent error format
    }
}
```

## Security Considerations

### 1. Self-Modification Prevention

**Implementation:**
```rust
// In service layer before any role modification
if ctx.claims.unwrap().sub == target_user_id {
    return Err(AdminError::SelfModificationDenied);
}
```

**Rationale:** Prevents privilege escalation through compromised sessions. Even if an attacker gains access to an admin account, they cannot grant themselves additional privileges.

**Note:** Self-modification prevention for app_roles will be implemented in the separate app_roles management spec.

### 2. Owner Account Protection

**Inactive by Default:**
- System config flag `owner_active` set to `false` during bootstrap
- Owner account cannot login until flag is set to `true` via CLI
- Minimizes attack surface (account exists but unusable)

**Activation Warning:**
```
⚠️  WARNING: Owner account is INACTIVE (system flag owner_active=false)
⚠️  The owner account cannot be used until activated via CLI:
⚠️  cargo run -- owner activate
⚠️  
⚠️  Keep owner credentials secure and only activate when needed for
⚠️  emergency admin management. Deactivate immediately after use.
```

**Design Decision:** Requiring CLI access for activation ensures only users with server access can enable the owner account, adding a physical security layer.

### 3. Token Invalidation on Role Changes

When admin roles change:
1. Delete all refresh tokens for that user
2. Issue new JWT with updated claims
3. Old JWTs become invalid at next validation (claims mismatch)

**Rationale:** Ensures permissions are enforced immediately without waiting for token expiration.

**Note:** Token invalidation for app_roles changes will be implemented in the separate app_roles management spec.

### 4. Password Change Requirement

**Bootstrap Accounts:**
- All accounts created during bootstrap have `password_change_required=true`
- Users must change password on first login before accessing any other endpoints
- Only `/auth/change-password` and `/auth/whoami` are accessible when flag is set

**Password Change Flow:**
1. User logs in with bootstrap credentials
2. JWT includes `password_change_required: true`
3. Any endpoint (except change-password/whoami) returns 403 with specific error
4. User calls `/auth/change-password` with old and new password
5. System validates old password, validates new password against policy
6. System updates password hash and sets `password_change_required=false`
7. System invalidates all refresh tokens and issues new JWT with updated flag
8. User can now access all endpoints normally

**Design Decision:** Keeping it simple for now - only bootstrap accounts require password change. Future enhancements could add admin-initiated password resets or periodic password rotation.

### 5. Audit Logging

All admin operations logged with:
- Timestamp
- IP address
- Actor user_id (who performed the action)
- Target user_id (who was affected)
- Action type (assign/remove role, password change)
- Role type (system_admin, role_admin, app_role)
- Success/failure status

**Log at Point of Action:** Store layer logs when database write occurs, ensuring audit trail even if higher layers fail.

## Testing Strategy

### Unit Tests

1. **Password Validator**
   - Length validation (< 15, 15-64, > 64)
   - Common password detection
   - Secure password generation

2. **Self-Modification Checks**
   - Reject admin role self-assignment
   - Reject admin role self-removal

3. **Authorization Logic**
   - Owner can assign/remove System Admin and Role Admin
   - System Admin can assign/remove Role Admin only
   - Non-admins cannot perform admin operations

### Integration Tests

1. **Bootstrap Flow**
   - Create owner + admins in one operation
   - Reject duplicate bootstrap
   - Verify system config `owner_active=false` after bootstrap
   - Verify all accounts created successfully

2. **Owner Activation/Deactivation**
   - CLI activation sets system config `owner_active=true`
   - API deactivation sets system config `owner_active=false`
   - Login checks system config flag when authenticating owner
   - Token invalidation on deactivation

3. **Role Assignment Flow**
   - Owner assigns System Admin → verify JWT claims updated
   - System Admin assigns Role Admin → verify JWT claims updated
   - Verify old tokens invalidated

4. **Permission Boundaries**
   - System Admin cannot assign System Admin (only Owner can)
   - Role Admin flag exists but has no functionality yet

5. **Password Change Requirement**
   - Bootstrap accounts have password_change_required=true
   - Login returns JWT with flag set
   - Endpoints reject requests with 403 when flag is true
   - Change password clears flag and issues new JWT
   - Old tokens invalidated after password change

6. **Audit Logging**
   - All role changes logged with correct metadata
   - Password changes logged
   - Self-modification attempts logged
   - CLI operations logged

### Manual Testing Scenarios

1. **Bootstrap and Initial Setup**
   - Run bootstrap command
   - Create 2 System Admins, 1 Role Admin
   - Export credentials to KeePassX and Bitwarden formats
   - Verify owner is INACTIVE

2. **Owner Emergency Use**
   - Activate owner via CLI
   - Login as owner
   - Assign System Admin to new user
   - Deactivate owner via API
   - Verify owner cannot login

3. **Day-to-Day Admin Operations**
   - Login as System Admin
   - Assign Role Admin to user
   - Manage user accounts (ban, disable)

4. **Password Change Flow**
   - Login with bootstrap credentials
   - Verify JWT has password_change_required=true
   - Attempt to access admin endpoint (should fail with 403)
   - Change password successfully
   - Verify new JWT has password_change_required=false
   - Access admin endpoints normally

5. **Security Boundaries**
   - Attempt self-modification (should fail)
   - Verify audit logs capture attempts
   - Verify token invalidation on role changes

## Migration Path

### Database Migration

```rust
// migration/src/m20250118_000001_add_admin_roles.rs
pub struct Migration;

impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add admin role columns to users table
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(ColumnDef::new(User::IsOwner).boolean().not_null().default(false))
                    .add_column(ColumnDef::new(User::IsSystemAdmin).boolean().not_null().default(false))
                    .add_column(ColumnDef::new(User::IsRoleAdmin).boolean().not_null().default(false))
                    .add_column(ColumnDef::new(User::PasswordChangeRequired).boolean().not_null().default(false))
                    .to_owned(),
            )
            .await?;
        
        // Create system_config table for system-level flags (singleton table)
        manager
            .create_table(
                Table::create()
                    .table(SystemConfig::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SystemConfig::Id).integer().not_null().primary_key())
                    .col(ColumnDef::new(SystemConfig::OwnerActive).boolean().not_null().default(false))
                    .col(ColumnDef::new(SystemConfig::UpdatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;
        
        // Insert the singleton row with default values
        let now = chrono::Utc::now().timestamp();
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(SystemConfig::Table)
                    .columns([SystemConfig::Id, SystemConfig::OwnerActive, SystemConfig::UpdatedAt])
                    .values_panic([1.into(), false.into(), now.into()])
                    .to_owned()
            )
            .await
    }
    
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::IsOwner)
                    .drop_column(User::IsSystemAdmin)
                    .drop_column(User::IsRoleAdmin)
                    .drop_column(User::PasswordChangeRequired)
                    .to_owned(),
            )
            .await?;
        
        manager
            .drop_table(Table::drop().table(SystemConfig::Table).to_owned())
            .await
    }
}
```

### Deployment Steps

1. Run database migration: `sea-orm-cli migrate up`
2. Deploy new binary with admin role support
3. Run bootstrap command: `cargo run -- bootstrap`
4. Distribute credentials to administrators
5. Activate owner only if needed for emergency operations

**Zero Downtime:** Migration adds columns with defaults, existing functionality continues working. No existing users gain admin privileges automatically.

## Future Enhancements

1. **Multi-Owner Support**: Allow multiple owner accounts with consensus requirements for critical operations
2. **Role Delegation**: Temporary role grants with expiration
3. **Audit Log UI**: Web interface for viewing audit logs
4. **Role Templates**: Predefined combinations of admin flags and app_roles
5. **RBAC for App Roles**: Define permissions for each app_role (currently just strings)
6. **MFA for Admin Operations**: Require second factor for sensitive admin actions

## Open Questions

None - all requirements are addressed in this design.

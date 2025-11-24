# Password Management Design

## Overview

This design implements comprehensive password management for the Linkstash authentication backend, including a reusable password validation library, password change functionality, and enforcement of password changes for bootstrap accounts. The system ensures strong password policies through length requirements and common password checks.

## Architecture

### Component Overview

```
Password Validator (Library)
├── Length validation (15-64 chars)
├── Common password check (embedded list)
└── Secure password generation

Password Change Flow
├── Verify old password
├── Validate new password
├── Update password hash
├── Invalidate refresh tokens
└── Issue new JWT

Password Change Requirement
├── Database flag (password_change_required)
├── JWT claim (password_change_required)
└── Endpoint middleware/check
```

## Components and Interfaces

### 1. Password Validator Service

```rust
// src/services/password_validator.rs
pub struct PasswordValidator {
    min_length: usize,  // 15
    max_length: usize,  // 64
    common_passwords: HashSet<String>,  // Loaded from embedded list
}

impl PasswordValidator {
    /// Create new validator with default settings
    pub fn new() -> Self {
        Self {
            min_length: 15,
            max_length: 64,
            common_passwords: Self::load_common_passwords(),
        }
    }
    
    /// Validate password against all rules
    /// 
    /// # Returns
    /// * `Ok(())` - Password is valid
    /// * `Err(PasswordValidationError)` - Password failed validation with specific reason
    pub fn validate(&self, password: &str) -> Result<(), PasswordValidationError> {
        // Check length
        if password.len() < self.min_length {
            return Err(PasswordValidationError::TooShort(self.min_length));
        }
        if password.len() > self.max_length {
            return Err(PasswordValidationError::TooLong(self.max_length));
        }
        
        // Check against common passwords (case-insensitive)
        if self.common_passwords.contains(&password.to_lowercase()) {
            return Err(PasswordValidationError::CommonPassword);
        }
        
        Ok(())
    }
    
    /// Generate a secure random password that passes all validation rules
    /// 
    /// Generates a 20-character password with mix of uppercase, lowercase, digits, and symbols
    pub fn generate_secure_password(&self) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();
        
        (0..20)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
    
    /// Load common passwords from embedded file
    fn load_common_passwords() -> HashSet<String> {
        // Embed common password list at compile time
        const COMMON_PASSWORDS: &str = include_str!("../../resources/common_passwords.txt");
        COMMON_PASSWORDS
            .lines()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordValidationError {
    #[error("Password must be at least {0} characters")]
    TooShort(usize),
    
    #[error("Password must not exceed {0} characters")]
    TooLong(usize),
    
    #[error("Password is too common or has been compromised")]
    CommonPassword,
}
```

**Design Decision:** Embed common password list at compile time using `include_str!` macro. This avoids external file dependencies and ensures the list is always available. Use top 10k passwords from HaveIBeenPwned or similar source.

### 2. Database Schema Changes

Add password change requirement flag to users table:

```rust
// In types/db/user.rs (extend existing Model)
pub struct Model {
    // ... existing fields ...
    pub password_change_required: bool,
}
```

**Migration:**
```rust
// migration/src/m20250119_000001_add_password_change_required.rs
pub struct Migration;

impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        ColumnDef::new(User::PasswordChangeRequired)
                            .boolean()
                            .not_null()
                            .default(false)
                    )
                    .to_owned(),
            )
            .await
    }
    
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::PasswordChangeRequired)
                    .to_owned(),
            )
            .await
    }
}
```

### 3. JWT Claims Extension

```rust
// In types/internal/auth.rs (extend existing Claims)
pub struct Claims {
    // ... existing fields ...
    pub password_change_required: bool,
}
```

**Design Decision:** Include flag in JWT to enable stateless checks without database queries. When password is changed, new JWT is issued with updated flag.

### 4. Store Layer

```rust
// src/stores/credential_store.rs (extend existing)
impl CredentialStore {
    /// Update user password hash
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `user_id` - User ID to update
    /// * `new_password_hash` - New argon2 password hash
    pub async fn update_password(
        &self,
        ctx: &RequestContext,
        user_id: &str,
        new_password_hash: &str,
    ) -> Result<(), AuthError> {
        // Update password hash
        // Log to audit database at point of action
    }
    
    /// Clear password change requirement flag
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `user_id` - User ID to update
    pub async fn clear_password_change_required(
        &self,
        ctx: &RequestContext,
        user_id: &str,
    ) -> Result<(), AuthError> {
        // Set password_change_required = false
        // Log to audit database at point of action
    }
}
```

### 5. Service Layer

```rust
// src/services/auth_service.rs (extend existing)
impl AuthService {
    /// Change user password
    /// 
    /// Verifies old password, validates new password, updates hash, clears password_change_required flag,
    /// invalidates all refresh tokens, and issues new JWT.
    /// 
    /// # Arguments
    /// * `ctx` - Request context with authenticated user
    /// * `old_password` - Current password for verification
    /// * `new_password` - New password to set
    /// 
    /// # Returns
    /// * `Ok((access_token, refresh_token))` - New tokens with updated claims
    /// * `Err(AuthError)` - Old password incorrect or new password invalid
    pub async fn change_password(
        &self,
        ctx: &RequestContext,
        old_password: &str,
        new_password: &str,
    ) -> Result<(String, String), AuthError> {
        let user_id = ctx.claims.as_ref().unwrap().sub.clone();
        
        // 1. Verify old password
        let user = self.credential_store.get_user_by_id(&user_id).await?;
        if !self.credential_store.verify_password(&user.password_hash, old_password)? {
            return Err(AuthError::InvalidCredentials);
        }
        
        // 2. Validate new password
        let validator = PasswordValidator::new();
        validator.validate(new_password)
            .map_err(|e| AuthError::PasswordValidationFailed(e.to_string()))?;
        
        // 3. Hash new password
        let new_hash = self.credential_store.hash_password(new_password)?;
        
        // 4. Update password hash
        self.credential_store.update_password(ctx, &user_id, &new_hash).await?;
        
        // 5. Clear password_change_required flag
        self.credential_store.clear_password_change_required(ctx, &user_id).await?;
        
        // 6. Invalidate all refresh tokens
        self.credential_store.revoke_all_refresh_tokens(&user_id).await?;
        
        // 7. Issue new JWT with updated claims
        let user_uuid = Uuid::parse_str(&user_id)?;
        let (access_token, jwt_id) = self.token_service.generate_jwt(&user_uuid, ctx.ip_address.clone()).await?;
        
        // 8. Generate and store new refresh token
        let refresh_token = self.token_service.generate_refresh_token();
        let token_hash = self.token_service.hash_refresh_token(&refresh_token);
        let expires_at = self.token_service.get_refresh_expiration();
        
        self.credential_store.store_refresh_token(
            token_hash,
            user_id.clone(),
            expires_at,
            jwt_id,
            ctx.ip_address.clone(),
        ).await?;
        
        Ok((access_token, refresh_token))
    }
}
```

### 6. API Endpoints

```rust
// src/api/auth.rs (extend existing AuthApi)
#[OpenApi(prefix_path = "/auth")]
impl AuthApi {
    /// Change user password
    /// 
    /// Accessible even when password_change_required=true (unlike other endpoints).
    /// Returns new access and refresh tokens after successful change.
    #[oai(path = "/change-password", method = "post", tag = "AuthTags::Authentication")]
    async fn change_password(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<ChangePasswordRequest>,
    ) -> ChangePasswordApiResponse {
        // Create request context (validates JWT)
        let ctx = self.create_request_context(req, Some(auth)).await;
        
        if !ctx.authenticated {
            return ChangePasswordApiResponse::Unauthorized(Json(ErrorResponse {
                error: "Unauthenticated".to_string(),
            }));
        }
        
        // NOTE: Do NOT check password_change_required here - this endpoint must be accessible
        // even when the flag is true
        
        match self.auth_service
            .change_password(&ctx, &body.old_password, &body.new_password)
            .await
        {
            Ok((access_token, refresh_token)) => {
                ChangePasswordApiResponse::Ok(Json(ChangePasswordResponse {
                    message: "Password changed successfully".to_string(),
                    access_token,
                    refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 900,
                }))
            }
            Err(e) => {
                ChangePasswordApiResponse::BadRequest(Json(ErrorResponse {
                    error: e.to_string(),
                }))
            }
        }
    }
}
```

### 7. Password Change Requirement Enforcement

**Option 1: Check in create_request_context (Recommended)**

```rust
// In src/api/auth.rs or shared helper
async fn create_request_context(
    &self,
    req: &Request,
    auth: Option<BearerAuth>,
) -> crate::types::internal::context::RequestContext {
    // ... existing JWT validation ...
    
    // After successful JWT validation, check password_change_required
    if let Some(claims) = &ctx.claims {
        if claims.password_change_required {
            // Check if this is an allowed endpoint
            let path = req.uri().path();
            let allowed_paths = ["/api/auth/change-password", "/api/auth/whoami"];
            
            if !allowed_paths.iter().any(|p| path.starts_with(p)) {
                // Set a flag in context to indicate password change is required
                ctx.password_change_blocked = true;
            }
        }
    }
    
    ctx
}

// Then in each endpoint:
if ctx.password_change_blocked {
    return ErrorResponse::PasswordChangeRequired;
}
```

**Option 2: Middleware (More complex, cleaner separation)**

Create a middleware that checks the flag and rejects requests before they reach handlers.

**Design Decision:** Use Option 1 (check in endpoints) for simplicity. Middleware would require more infrastructure changes.

## Data Models

### Request/Response DTOs

```rust
// src/types/dto/auth.rs (extend existing)
#[derive(Object)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Object)]
pub struct ChangePasswordResponse {
    pub message: String,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(ApiResponse)]
pub enum ChangePasswordApiResponse {
    #[oai(status = 200)]
    Ok(Json<ChangePasswordResponse>),
    
    #[oai(status = 400)]
    BadRequest(Json<ErrorResponse>),
    
    #[oai(status = 401)]
    Unauthorized(Json<ErrorResponse>),
}
```

## Error Handling

```rust
// src/errors/auth.rs (extend existing AuthError)
pub enum AuthError {
    // ... existing variants ...
    
    #[error("Password validation failed: {0}")]
    PasswordValidationFailed(String),
    
    #[error("Password change required. Please change your password at /auth/change-password")]
    PasswordChangeRequired,
    
    #[error("Current password is incorrect")]
    IncorrectPassword,
}
```

## Security Considerations

### 1. Password Validation

- **15-64 character range** balances security and usability
- **Common password check** prevents use of easily guessed passwords
- **Embedded list** ensures offline validation without external dependencies

### 2. Token Invalidation

When password changes:
1. All refresh tokens are deleted from database
2. New JWT issued with updated `password_change_required=false`
3. Old JWTs become invalid at next validation (claims mismatch)

**Rationale:** Ensures all sessions are terminated when password changes, preventing unauthorized access if password was compromised.

### 3. Password Change Requirement

- Bootstrap accounts created with `password_change_required=true`
- Users must change password before accessing protected endpoints
- Only `/auth/change-password` and `/auth/whoami` remain accessible
- Prevents use of auto-generated passwords in production

### 4. Audit Logging

All password changes logged with:
- Timestamp
- User ID
- IP address
- Success/failure status
- Validation failure reason (if applicable)

## Testing Strategy

### Unit Tests

1. **Password Validator**
   - Test length validation (< 15, 15-64, > 64)
   - Test common password detection
   - Test secure password generation
   - Test case-insensitive common password matching

2. **Password Change Logic**
   - Test old password verification
   - Test new password validation
   - Test password hash update
   - Test flag clearing

### Integration Tests

1. **Password Change Flow**
   - Test successful password change with valid credentials
   - Test rejection with incorrect old password
   - Test rejection with invalid new password (too short, too long, common)
   - Test new tokens issued after change
   - Test old refresh tokens invalidated

2. **Password Change Requirement**
   - Test bootstrap accounts have `password_change_required=true`
   - Test login returns JWT with flag set
   - Test protected endpoints reject requests with 403
   - Test `/auth/change-password` remains accessible
   - Test `/auth/whoami` remains accessible
   - Test flag cleared after successful password change
   - Test old tokens invalidated after password change

3. **Audit Logging**
   - Test password changes logged with correct metadata
   - Test failed password changes logged
   - Test validation failures logged

## Migration Path

### Database Migration

```rust
// migration/src/m20250119_000001_add_password_change_required.rs
// (See schema section above)
```

### Deployment Steps

1. Run database migration: `sea-orm-cli migrate up`
2. Deploy new binary with password management support
3. Existing users have `password_change_required=false` (no impact)
4. New bootstrap accounts will have `password_change_required=true`

**Zero Downtime:** Migration adds column with default `false`, existing functionality continues working.

## Future Enhancements

1. **Password History**: Prevent reuse of last N passwords
2. **Password Expiration**: Force periodic password changes
3. **Password Strength Meter**: Provide real-time feedback in UI
4. **Admin-Initiated Password Reset**: Allow admins to force password changes
5. **Configurable Password Policy**: Make min/max length configurable via environment variables


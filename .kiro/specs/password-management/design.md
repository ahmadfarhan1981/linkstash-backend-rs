# Password Management Design

## Overview

This design implements comprehensive password management for the Linkstash authentication backend, including a reusable password validation library with multiple validation layers, password change functionality, and enforcement of password changes for bootstrap accounts. The system ensures strong password policies through length requirements, common password checks, compromised password detection via HaveIBeenPwned, and context-specific validation.

## Architecture

### Component Overview

```
Password Validator (Stateless Service in AppData)
├── Length validation (15-128 chars)
├── Username substring check (context-specific)
├── Common password check (SQLite table)
├── Compromised password check (HIBP with cache)
└── Secure password generation

Stores (in AppData)
├── CommonPasswordStore (SQLite table for common passwords)
├── HibpCacheStore (SQLite table for HIBP cache)
├── CredentialStore (extended with password management)
└── SystemConfigStore (HIBP staleness config)

CLI Commands
├── download-passwords (fetch from URL, load into DB)
└── bootstrap (uses PasswordValidator)

Password Change Flow
├── Verify old password
├── Validate new password (all checks)
├── Update password hash
├── Invalidate refresh tokens
└── Issue new JWT

Password Change Requirement
├── Database flag (password_change_required)
├── JWT claim (password_change_required)
└── Endpoint enforcement
```

**Design Decisions:**

1. **SQLite table for common passwords**: Fast indexed lookups, minimal memory, easy updates
2. **AppData pattern**: PasswordValidator is stateless service, stores are shared
3. **Async validation**: HIBP checks require network I/O
4. **Graceful HIBP degradation**: Log warning but allow password if API fails
5. **UUID detection**: Skip username check for owner account
6. **Validation order**: Length → Username → Common → Compromised (fail fast)

## Components and Interfaces

### 1. Database Schema

#### Common Passwords Table

```rust
// types/db/common_password.rs
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "common_passwords")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub password: String,  // Lowercase password
}
```

**Migration:** `m20250127_000001_create_common_passwords.rs`

#### HIBP Cache Table

```rust
// types/db/hibp_cache.rs
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "hibp_cache")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub hash_prefix: String,  // 5-character SHA-1 prefix
    pub response_data: String,  // Full API response (hash suffixes)
    pub fetched_at: i64,  // Unix timestamp
}
```

**Migration:** `m20250127_000002_create_hibp_cache.rs`

#### Users Table Extension

```rust
// In types/db/user.rs (extend existing Model)
pub struct Model {
    // ... existing fields ...
    pub password_change_required: bool,
}
```

**Migration:** `m20250127_000003_add_password_change_required.rs`

#### System Configuration

Add via bootstrap or manual insert:
- Key: `hibp_cache_staleness_seconds`
- Value: `2592000` (30 days default)

### 2. Store Layer

#### CommonPasswordStore

```rust
// src/stores/common_password_store.rs
pub struct CommonPasswordStore {
    db: DatabaseConnection,
}

impl CommonPasswordStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
    
    /// Check if password exists in common passwords table (case-insensitive)
    pub async fn is_common_password(&self, password: &str) -> Result<bool, DbErr> {
        let password_lower = password.to_lowercase();
        let result = common_password::Entity::find_by_id(password_lower)
            .one(&self.db)
            .await?;
        Ok(result.is_some())
    }
    
    /// Bulk load passwords from iterator (clears existing, uses transaction)
    pub async fn load_passwords<I>(&self, passwords: I) -> Result<usize, DbErr>
    where
        I: IntoIterator<Item = String>,
    {
        let txn = self.db.begin().await?;
        common_password::Entity::delete_many().exec(&txn).await?;
        
        let mut count = 0;
        let mut batch = Vec::new();
        
        for password in passwords {
            let password_lower = password.trim().to_lowercase();
            if password_lower.is_empty() { continue; }
            
            batch.push(common_password::ActiveModel {
                password: Set(password_lower),
            });
            count += 1;
            
            if batch.len() >= 1000 {
                common_password::Entity::insert_many(batch.drain(..)).exec(&txn).await?;
            }
        }
        
        if !batch.is_empty() {
            common_password::Entity::insert_many(batch).exec(&txn).await?;
        }
        
        txn.commit().await?;
        Ok(count)
    }
    
    pub async fn count(&self) -> Result<u64, DbErr> {
        common_password::Entity::find().count(&self.db).await
    }
}
```

#### HibpCacheStore

```rust
// src/stores/hibp_cache_store.rs
pub struct HibpCacheStore {
    db: DatabaseConnection,
    system_config_store: Arc<SystemConfigStore>,
}

impl HibpCacheStore {
    pub fn new(db: DatabaseConnection, system_config_store: Arc<SystemConfigStore>) -> Self {
        Self { db, system_config_store }
    }
    
    /// Get cached HIBP response if not stale
    pub async fn get_cached_response(&self, prefix: &str) -> Result<Option<String>, DbErr> {
        let cache_entry = hibp_cache::Entity::find_by_id(prefix).one(&self.db).await?;
        
        if let Some(entry) = cache_entry {
            let staleness_seconds = self.system_config_store
                .get_config("hibp_cache_staleness_seconds")
                .await
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2592000); // Default 30 days
            
            let now = chrono::Utc::now().timestamp();
            let age = now - entry.fetched_at;
            
            if age < staleness_seconds {
                return Ok(Some(entry.response_data));
            }
        }
        
        Ok(None)
    }
    
    /// Store or update HIBP response in cache
    pub async fn store_response(&self, prefix: &str, data: &str) -> Result<(), DbErr> {
        let now = chrono::Utc::now().timestamp();
        
        let model = hibp_cache::ActiveModel {
            hash_prefix: Set(prefix.to_string()),
            response_data: Set(data.to_string()),
            fetched_at: Set(now),
        };
        
        hibp_cache::Entity::insert(model)
            .on_conflict(
                OnConflict::column(hibp_cache::Column::HashPrefix)
                    .update_columns([
                        hibp_cache::Column::ResponseData,
                        hibp_cache::Column::FetchedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        
        Ok(())
    }
}
```

#### CredentialStore Extensions

```rust
// src/stores/credential_store.rs (extend existing)
impl CredentialStore {
    /// Update user password hash
    pub async fn update_password(
        &self,
        ctx: &RequestContext,
        user_id: &str,
        new_password_hash: &str,
    ) -> Result<(), AuthError> {
        // Update password hash in database
        // Log to audit database at point of action
    }
    
    /// Clear password change requirement flag
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

### 3. Service Layer

#### PasswordValidator (Stateless Service)

```rust
// src/services/password_validator.rs
pub struct PasswordValidator {
    min_length: usize,  // 15
    max_length: usize,  // 128
    common_password_store: Arc<CommonPasswordStore>,
    hibp_cache_store: Arc<HibpCacheStore>,
}

impl PasswordValidator {
    pub fn new(
        common_password_store: Arc<CommonPasswordStore>,
        hibp_cache_store: Arc<HibpCacheStore>,
    ) -> Self {
        Self {
            min_length: 15,
            max_length: 128,
            common_password_store,
            hibp_cache_store,
        }
    }
    
    /// Validate password against all rules
    pub async fn validate(
        &self,
        password: &str,
        username: Option<&str>,
    ) -> Result<(), PasswordValidationError> {
        // 1. Length check
        if password.len() < self.min_length {
            return Err(PasswordValidationError::TooShort(self.min_length));
        }
        if password.len() > self.max_length {
            return Err(PasswordValidationError::TooLong(self.max_length));
        }
        
        // 2. Username substring check
        if let Some(username) = username {
            if password.to_lowercase().contains(&username.to_lowercase()) {
                return Err(PasswordValidationError::ContainsUsername);
            }
        }
        
        // 3. Common password check
        if self.common_password_store.is_common_password(password).await? {
            return Err(PasswordValidationError::CommonPassword);
        }
        
        // 4. HIBP check (graceful degradation)
        match self.check_hibp(password).await {
            Ok(true) => return Err(PasswordValidationError::CompromisedPassword),
            Ok(false) => {},
            Err(e) => tracing::warn!("HIBP check failed: {}", e),
        }
        
        Ok(())
    }
    
    async fn check_hibp(&self, password: &str) -> Result<bool, PasswordValidatorError> {
        use sha1::{Sha1, Digest};
        
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = format!("{:X}", hasher.finalize());
        
        let prefix = &hash[..5];
        let suffix = &hash[5..];
        
        // Check cache first
        if let Some(cached_data) = self.hibp_cache_store.get_cached_response(prefix).await? {
            return Ok(cached_data.contains(suffix));
        }
        
        // Fetch from API
        let response = self.fetch_hibp_api(prefix).await?;
        self.hibp_cache_store.store_response(prefix, &response).await?;
        
        Ok(response.contains(suffix))
    }
    
    async fn fetch_hibp_api(&self, prefix: &str) -> Result<String, PasswordValidatorError> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let client = reqwest::Client::new();
        
        let response = client
            .get(&url)
            .header("User-Agent", "Linkstash-Auth")
            .send()
            .await?
            .text()
            .await?;
        
        Ok(response)
    }
    
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
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordValidationError {
    #[error("Password must be at least {0} characters")]
    TooShort(usize),
    
    #[error("Password must not exceed {0} characters")]
    TooLong(usize),
    
    #[error("Password must not contain your username")]
    ContainsUsername,
    
    #[error("Password is too common")]
    CommonPassword,
    
    #[error("Password has been compromised in a data breach")]
    CompromisedPassword,
}
```

#### AuthService Extensions

```rust
// src/services/auth_service.rs (extend existing)
pub struct AuthService {
    // ... existing fields ...
    password_validator: Arc<PasswordValidator>,
}

impl AuthService {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            // ... existing fields ...
            password_validator: app_data.password_validator.clone(),
        }
    }
    
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
        
        // 2. Validate new password (with username context)
        self.password_validator
            .validate(new_password, Some(&user.username))
            .await
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

### 4. AppData Integration

```rust
// src/app_data.rs (extend existing)
pub struct AppData {
    // ... existing fields ...
    
    // New stores
    pub common_password_store: Arc<CommonPasswordStore>,
    pub hibp_cache_store: Arc<HibpCacheStore>,
    
    // New stateless service
    pub password_validator: Arc<PasswordValidator>,
}

impl AppData {
    pub async fn init() -> Result<Self, AuthError> {
        // ... existing initialization ...
        
        // Create new stores
        let common_password_store = Arc::new(CommonPasswordStore::new(db.clone()));
        
        let hibp_cache_store = Arc::new(HibpCacheStore::new(
            db.clone(),
            system_config_store.clone(),
        ));
        
        // Create password validator (stateless service)
        let password_validator = Arc::new(PasswordValidator::new(
            common_password_store.clone(),
            hibp_cache_store.clone(),
        ));
        
        Ok(Self {
            // ... existing fields ...
            common_password_store,
            hibp_cache_store,
            password_validator,
        })
    }
}
```

### 5. CLI Commands

```rust
// src/cli/password_management.rs
pub async fn download_and_load_passwords(
    url: &str,
    app_data: &AppData,
) -> Result<(), CliError> {
    println!("Downloading common password list from: {}", url);
    
    // 1. Fetch from URL
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    
    if !response.status().is_success() {
        return Err(CliError::DownloadFailed(format!("HTTP {}", response.status())));
    }
    
    let content = response.text().await?;
    
    // 2. Parse passwords (one per line)
    let passwords: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    
    // 3. Load into database
    let count = app_data.common_password_store.load_passwords(passwords).await?;
    
    println!("✓ Successfully loaded {} passwords into database", count);
    
    Ok(())
}

// In main CLI handler
#[derive(Parser)]
enum Commands {
    // ... existing commands ...
    
    /// Download and load common password list from URL
    DownloadPasswords {
        /// URL to download password list from
        #[arg(long)]
        url: String,
    },
}

// In execute_command
Commands::DownloadPasswords { url } => {
    download_and_load_passwords(&url, app_data).await?;
}
```

**Usage:**
```bash
cargo run -- download-passwords --url https://example.com/passwords.txt
```

### 6. JWT Claims Extension

```rust
// In types/internal/auth.rs (extend existing Claims)
pub struct Claims {
    // ... existing fields ...
    pub password_change_required: bool,
}
```

### 7. API Layer

#### DTOs

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

#### Endpoints

```rust
// src/api/auth.rs (extend existing AuthApi)
#[OpenApi(prefix_path = "/auth")]
impl AuthApi {
    #[oai(path = "/change-password", method = "post", tag = "AuthTags::Authentication")]
    async fn change_password(
        &self,
        req: &Request,
        auth: BearerAuth,
        body: Json<ChangePasswordRequest>,
    ) -> ChangePasswordApiResponse {
        let ctx = self.create_request_context(req, Some(auth)).await;
        
        if !ctx.authenticated {
            return ChangePasswordApiResponse::Unauthorized(Json(ErrorResponse {
                error: "Unauthenticated".to_string(),
            }));
        }
        
        // NOTE: Do NOT check password_change_required here - this endpoint must be accessible
        
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

#### Password Change Requirement Enforcement

**Design Decision: Fail-Secure by Default with Context in Error**

Instead of having endpoints check a flag, we make `create_request_context` return a `Result` where the error variant contains the `RequestContext`. This inverts the control flow:
- **Most endpoints** use `?` operator and automatically bubble up the error (rejected by default)
- **Allowed endpoints** extract the context from the error (opt-in)

This ensures:
- New endpoints are secure by default (using `?` is natural, forgetting means compile error)
- Impossible to accidentally allow access (must explicitly extract context from error)
- Clear visibility of which endpoints bypass the check
- No separate "unchecked" helper function needed

```rust
// In src/errors/auth.rs (extend existing AuthError)
pub enum AuthError {
    // ... existing variants ...
    
    #[error("Password validation failed: {0}")]
    PasswordValidationFailed(String),
    
    /// User must change password before accessing this endpoint
    /// Contains the RequestContext so allowed endpoints can extract it
    #[error("Password change required. Please change your password at /auth/change-password")]
    PasswordChangeRequired(RequestContext),
    
    #[error("Current password is incorrect")]
    IncorrectPassword,
}
```

```rust
// In src/api/helpers.rs

/// Create RequestContext and enforce password change requirement
/// 
/// Returns Err(AuthError::PasswordChangeRequired(ctx)) if user has password_change_required=true.
/// The error contains the RequestContext so allowed endpoints can extract it.
/// 
/// Most endpoints should use `?` to automatically reject these users.
/// Endpoints that should remain accessible (change-password, whoami) must explicitly
/// extract the context from the error.
/// 
/// # Arguments
/// * `req` - The HTTP request
/// * `auth` - Optional Bearer token
/// * `token_service` - TokenService for JWT validation
/// 
/// # Returns
/// * `Ok(RequestContext)` - Context ready to use
/// * `Err(AuthError::PasswordChangeRequired(ctx))` - User must change password first (context included)
pub async fn create_request_context(
    req: &Request,
    auth: Option<Bearer>,
    token_service: &Arc<TokenService>,
) -> Result<RequestContext, AuthError> {
    // Extract IP address
    let ip_address = extract_ip_address(req);
    
    // Create base context
    let mut ctx = RequestContext::new()
        .with_ip_address(ip_address.unwrap_or_else(|| "unknown".to_string()));
    
    // If auth is provided, validate JWT and populate claims
    if let Some(bearer) = auth {
        match token_service.validate_jwt(&bearer.token).await {
            Ok(claims) => {
                ctx = ctx.with_auth(claims.clone()).with_actor_id(claims.sub.clone());
                
                // Check password change requirement AFTER successful JWT validation
                if claims.password_change_required {
                    return Err(AuthError::PasswordChangeRequired(ctx));
                }
            }
            Err(_) => {
                // JWT validation failed - context remains unauthenticated
            }
        }
    }
    
    Ok(ctx)
}
```

**Usage in endpoints:**

```rust
// MOST ENDPOINTS: Automatically reject with `?` operator (fail-secure by default)
#[oai(path = "/refresh", method = "post")]
async fn refresh_token(&self, req: &Request, body: Json<RefreshRequest>) -> Result<RefreshApiResponse, AuthError> {
    // Using `?` automatically rejects users with password_change_required=true
    let ctx = self.create_request_context(req, None).await?;
    
    // Continue with normal logic - only reaches here if password change not required
    // ...
}

#[oai(path = "/admin/users", method = "get")]
async fn list_users(&self, req: &Request, auth: BearerAuth) -> Result<ListUsersApiResponse, AuthError> {
    // Using `?` automatically rejects users with password_change_required=true
    let ctx = self.create_request_context(req, Some(auth)).await?;
    
    // Continue with normal logic
    // ...
}

// ALLOWED ENDPOINTS: Extract context from error (opt-in)
#[oai(path = "/change-password", method = "post")]
async fn change_password(
    &self,
    req: &Request,
    auth: BearerAuth,
    body: Json<ChangePasswordRequest>,
) -> ChangePasswordApiResponse {
    // Extract context from PasswordChangeRequired error to allow access
    let ctx = match self.create_request_context(req, Some(auth)).await {
        Ok(ctx) => ctx,
        Err(AuthError::PasswordChangeRequired(ctx)) => {
            // This is expected and allowed for this endpoint
            // Extract the context from the error
            ctx
        }
        Err(e) => {
            // Other errors (invalid JWT, etc.) should still fail
            return ChangePasswordApiResponse::Unauthorized(Json(ErrorResponse {
                error: e.to_string(),
            }));
        }
    };
    
    if !ctx.authenticated {
        return ChangePasswordApiResponse::Unauthorized(Json(ErrorResponse {
            error: "Unauthenticated".to_string(),
        }));
    }
    
    // Continue with password change logic...
}

#[oai(path = "/whoami", method = "get")]
async fn whoami(&self, req: &Request, auth: BearerAuth) -> WhoamiApiResponse {
    // Extract context from PasswordChangeRequired error to allow access
    let ctx = match self.create_request_context(req, Some(auth)).await {
        Ok(ctx) => ctx,
        Err(AuthError::PasswordChangeRequired(ctx)) => {
            // This is expected and allowed - user needs to see their status
            ctx
        }
        Err(e) => {
            return WhoamiApiResponse::Unauthorized(Json(ErrorResponse {
                error: e.to_string(),
            }));
        }
    };
    
    // Return user info including password_change_required flag
    // ...
}
```

**Benefits:**
- **Fail-secure by default**: Using `?` is the natural Rust pattern, automatically rejects
- **Compile-time safety**: Forgetting to handle Result causes compile error
- **No separate helper needed**: Context is embedded in the error, no `create_request_context_unchecked()`
- **Impossible to accidentally allow**: Must explicitly extract context from error variant
- **Clear intent**: Pattern matching makes it obvious which endpoints allow password-change-required users
- **Auditable**: Easy to grep for `PasswordChangeRequired(ctx)` to find allowed endpoints
- **Clean API**: Single function, no duplication

### 8. Error Handling

Error types are defined in section 7 (API Layer) above, integrated with the password change requirement enforcement pattern.

## Environment Configuration

Add to `.env` and `.env.example`:

```bash
# Password Management
# (HIBP cache staleness stored in system_config table, default 30 days)
```

## Security Considerations

### 1. Password Validation

- **15-128 character range** supports passphrases
- **Username substring check** prevents obvious weak passwords
- **Common password check** via SQLite table (fast, updateable)
- **Compromised password check** via HIBP with k-anonymity
- **Validation order** optimized (cheap checks first, network last)

### 2. HIBP k-Anonymity

- Only 5-character hash prefix sent to API
- Prevents HIBP from knowing which password was checked
- Local cache minimizes API calls
- Graceful degradation if API unavailable

### 3. Token Invalidation

When password changes:
1. All refresh tokens deleted from database
2. New JWT issued with `password_change_required=false`
3. Old JWTs become invalid at next validation

### 4. Password Change Requirement

- Bootstrap accounts created with `password_change_required=true`
- Users must change password before accessing protected endpoints
- Only `/auth/change-password` and `/auth/whoami` remain accessible

### 5. Audit Logging

All password changes logged with:
- Timestamp, User ID, IP address
- Success/failure status
- Validation failure reason
- Never log actual passwords or hashes

## Testing Strategy

### Manual Verification Points

1. **Password Validator**
   - Verify length validation (< 15, 15-128, > 128)
   - Verify username substring detection (case-insensitive)
   - Verify common password detection from database
   - Verify HIBP compromised password detection
   - Verify secure password generation
   - Verify UUID username check is skipped

2. **Common Password Management**
   - Verify CLI download command works
   - Verify passwords loaded into database
   - Verify validator queries database correctly
   - Verify case-insensitive matching

3. **HIBP Cache**
   - Verify cache table created
   - Verify cache hit/miss logic
   - Verify staleness checking
   - Verify API calls only when needed
   - Verify graceful degradation on API failure

4. **Password Change Flow**
   - Verify successful password change with valid credentials
   - Verify rejection with incorrect old password
   - Verify rejection with invalid new password (all validation types)
   - Verify new tokens issued after change
   - Verify old refresh tokens invalidated

5. **Password Change Requirement**
   - Verify bootstrap accounts have `password_change_required=true`
   - Verify login returns JWT with flag set
   - Verify protected endpoints reject requests with 403
   - Verify `/auth/change-password` remains accessible
   - Verify `/auth/whoami` remains accessible
   - Verify flag cleared after successful password change

6. **Audit Logging**
   - Verify password changes logged with correct metadata
   - Verify failed password changes logged
   - Verify validation failures logged

## Migration Path

### Database Migrations

1. `m20250127_000001_create_common_passwords.rs` - Create common passwords table
2. `m20250127_000002_create_hibp_cache.rs` - Create HIBP cache table
3. `m20250127_000003_add_password_change_required.rs` - Add flag to users table
4. System config entry for HIBP staleness (via bootstrap or manual insert)

### Deployment Steps

1. Run database migrations: `sea-orm-cli migrate up`
2. Download common passwords: `cargo run -- download-passwords --url <URL>`
3. Deploy new binary with password management support
4. Existing users have `password_change_required=false` (no impact)
5. New bootstrap accounts will have `password_change_required=true`

**Zero Downtime:** Migrations add new tables/columns with defaults, existing functionality continues working.

## Future Enhancements

1. **Password History**: Prevent reuse of last N passwords
2. **Password Expiration**: Force periodic password changes
3. **Password Strength Meter**: Provide real-time feedback in UI
4. **Admin-Initiated Password Reset**: Allow admins to force password changes
5. **Configurable Password Policy**: Make min/max length configurable via environment variables

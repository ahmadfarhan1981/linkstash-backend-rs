# Error Handling Guide

## Overview

This system uses a **two-layer error architecture** that separates internal errors (for logging and debugging) from API errors (for user-facing responses). This design ensures that implementation details are never exposed to clients while providing rich context for developers.

## Architecture

### Two-Layer System

```
┌─────────────────────────────────────────────────────────┐
│                    API Layer                            │
│  (auth.rs, admin.rs)                                    │
│  Returns: AuthError, AdminError (poem-openapi types)   │
│  Purpose: User-facing error messages                    │
└─────────────────────────────────────────────────────────┘
                         ↑
                         │ Explicit conversion
                         │ (map_err with conversion logic)
                         │ Logs details, returns generic/specific message
                         │
┌─────────────────────────────────────────────────────────┐
│              Internal Layer (Services)                  │
│  (auth_service.rs, admin_service.rs, token_service.rs) │
│  Returns: InternalError                                 │
│  Purpose: Propagate errors with full context            │
└─────────────────────────────────────────────────────────┘
                         ↑
                         │ Propagates InternalError unchanged
                         │
┌─────────────────────────────────────────────────────────┐
│              Internal Layer (Stores)                    │
│  (credential_store.rs, system_config_store.rs, etc.)   │
│  Returns: InternalError (hybrid error type)            │
│    ├─ Infrastructure: Database, Parse, Transaction     │
│    └─ Domain: CredentialError, SystemConfigError, etc. │
│  Purpose: Create errors with rich context for logging   │
└─────────────────────────────────────────────────────────┘
```

### Key Principles

1. **Two-layer architecture** - Internal layer (stores + services) vs API layer (endpoints)
2. **Hybrid error structure** - Infrastructure errors (Database, Parse) are shared; domain errors (CredentialError) are store-specific
3. **Internal errors are detailed** - Full context with operation names, identifiers, error sources
4. **API errors are user-appropriate** - Generic for infrastructure failures, specific for domain failures
5. **Explicit conversion** - No automatic From implementations from internal to API errors
6. **Type safety** - Compiler prevents using wrong domain errors in wrong stores
7. **Security by design** - Implementation details logged but never exposed to API clients

## InternalError: The Hybrid Approach

`InternalError` uses a hybrid structure that separates infrastructure errors (shared by all stores) from domain-specific errors (unique to each store).

### Infrastructure Errors (Shared)

These errors represent technical failures and are available to all stores:

- **Database** - Database query or operation failed
- **Transaction** - Database transaction failed
- **Parse** - Failed to parse a value (UUID, timestamp, JSON, etc.)
- **Crypto** - Cryptographic operation failed (hashing, verification, etc.)

### Domain Errors (Store-Specific)

These errors represent business logic failures and are specific to each store:

- **CredentialError** - Authentication, user management, tokens (used by CredentialStore)
- **SystemConfigError** - Owner management, system settings (used by SystemConfigStore)
- **AuditError** - Audit logging failures (used by AuditStore)

### Why This Hybrid Approach?

**Shared Infrastructure:**
- Database, parsing, and crypto errors are common across all stores
- Sharing these reduces duplication and ensures consistent handling
- Infrastructure errors work immediately when adding new stores

**Isolated Domains:**
- Business logic errors are specific to each store's domain
- Isolating these provides type safety and prevents misuse
- Can't accidentally use `CredentialError` in `SystemConfigStore`

**Extensibility:**
- Adding a new store requires only defining its domain errors and adding one line to `InternalError`
- Infrastructure errors work immediately

**Clear Intent:**
- Code clearly shows whether an error is technical (infrastructure) or business logic (domain)

## When to Use Each Error Type

### Decision Tree

```
Is this error happening in an API endpoint?
├─ YES → Use AuthError or AdminError
│         (Convert from InternalError using from_internal_error())
│
└─ NO → Use InternalError
        │
        ├─ Is this a technical failure?
        │  (database, parsing, crypto, transaction)
        │  └─ YES → Use infrastructure error
        │            - InternalError::database()
        │            - InternalError::parse()
        │            - InternalError::crypto()
        │            - InternalError::transaction()
        │
        └─ Is this a business logic failure?
           (invalid credentials, user not found, etc.)
           └─ YES → Use domain error
                    - CredentialError::InvalidCredentials
                    - CredentialError::UserNotFound(id)
                    - SystemConfigError::OwnerNotFound
                    - etc.
```

### Infrastructure vs Domain Errors

**Use Infrastructure Errors when:**
- Database query fails
- UUID parsing fails
- JSON parsing fails
- Password hashing fails (technical failure)
- Transaction fails
- Crypto operation fails

**Use Domain Errors when:**
- Invalid credentials provided
- User not found
- Duplicate username
- Token expired
- Owner already exists
- Config not found

## Helper Methods

### Infrastructure Error Helpers

Infrastructure errors use helper methods on `InternalError`:

```rust
// Database error
InternalError::database("operation_name", db_err)

// Transaction error
InternalError::transaction("transaction_name", db_err)

// Parse error
InternalError::parse("value_type", error_message)

// Crypto error
InternalError::crypto("operation_name", error_message)
```

### Domain Error Constructors

Domain errors use their own constructors and auto-convert to `InternalError` via `#[from]`:

```rust
// CredentialError
CredentialError::InvalidCredentials.into()
CredentialError::DuplicateUsername(username).into()
CredentialError::UserNotFound(user_id).into()
CredentialError::invalid_token("jwt", "signature invalid").into()

// SystemConfigError
SystemConfigError::ConfigNotFound.into()
SystemConfigError::OwnerAlreadyExists.into()

// AuditError
AuditError::LogWriteFailed(message).into()
```

## Error Flow Examples

### Example 1: Infrastructure Error (Database Failure)

```rust
// 1. Store: Database query fails
pub async fn get_user(&self, user_id: &str) -> Result<User, InternalError> {
    User::find()
        .filter(user::Column::Id.eq(user_id))
        .one(&self.db)
        .await
        .map_err(|e| InternalError::database("get_user", e))?  // ← Creates InternalError
        .ok_or_else(|| CredentialError::UserNotFound(user_id.to_string()).into())
}

// 2. Service: Propagates error unchanged
pub async fn get_user_info(&self, user_id: &str) -> Result<UserInfo, InternalError> {
    let user = self.credential_store.get_user(user_id).await?;  // ← Propagates InternalError
    Ok(UserInfo::from(user))
}

// 3. API: Converts to user-facing error
#[oai(path = "/user/{id}", method = "get")]
async fn get_user(&self, id: Path<String>) -> Result<Json<UserInfo>, AuthError> {
    let user_info = self.auth_service
        .get_user_info(&id.0)
        .await
        .map_err(AuthError::from_internal_error)?;  // ← Explicit conversion
    
    Ok(Json(user_info))
}

// Conversion logic logs details but returns generic message:
InternalError::Database { operation, .. } => {
    tracing::error!("Database error in {}: {}", operation, err);  // ← Logs "get_user"
    AuthError::internal_server_error()  // ← Returns "An internal error occurred"
}
```

**Result:** Client sees generic message, logs contain full details.

### Example 2: Domain Error (Invalid Credentials)

```rust
// 1. Store: Invalid credentials
pub async fn verify_credentials(&self, username: &str, password: &str) -> Result<String, InternalError> {
    let user = self.get_user_by_username(username).await?;
    
    let password_valid = self.verify_password(&user.password_hash, password)?;
    
    if !password_valid {
        return Err(CredentialError::InvalidCredentials.into());  // ← Domain error
    }
    
    Ok(user.id.to_string())
}

// 2. Service: Propagates error unchanged
pub async fn login(&self, username: String, password: String) -> Result<(String, String), InternalError> {
    let user_id = self.credential_store
        .verify_credentials(&username, &password)
        .await?;  // ← Propagates InternalError
    
    // Generate tokens...
}

// 3. API: Converts to user-facing error
#[oai(path = "/login", method = "post")]
async fn login(&self, body: Json<LoginRequest>) -> Result<Json<TokenResponse>, AuthError> {
    let (access_token, refresh_token) = self.auth_service
        .login(body.username.clone(), body.password.clone())
        .await
        .map_err(AuthError::from_internal_error)?;  // ← Explicit conversion
    
    Ok(Json(TokenResponse { access_token, refresh_token }))
}

// Conversion logic logs and returns specific message:
InternalError::Credential(CredentialError::InvalidCredentials) => {
    tracing::debug!("Invalid credentials attempt");  // ← Logs at DEBUG level
    AuthError::invalid_credentials()  // ← Returns "Invalid username or password"
}
```

**Result:** Client sees specific, actionable message. Logs contain context.

### Example 3: Mixed Errors in One Function

```rust
pub async fn create_user(&self, username: &str, password: &str) -> Result<String, InternalError> {
    // Check for duplicate username (domain error)
    let existing = User::find()
        .filter(user::Column::Username.eq(username))
        .one(&self.db)
        .await
        .map_err(|e| InternalError::database("check_duplicate_username", e))?;  // ← Infrastructure
    
    if existing.is_some() {
        return Err(CredentialError::DuplicateUsername(username.to_string()).into());  // ← Domain
    }
    
    // Hash password (infrastructure error)
    let password_hash = self.hash_password(password)
        .map_err(|e| InternalError::crypto("hash_password", e.to_string()))?;  // ← Infrastructure
    
    // Insert user (infrastructure error)
    let user = user::ActiveModel {
        username: Set(username.to_string()),
        password_hash: Set(password_hash),
        ..Default::default()
    };
    
    let result = user.insert(&self.db)
        .await
        .map_err(|e| InternalError::database("insert_user", e))?;  // ← Infrastructure
    
    Ok(result.id.to_string())
}
```

## Layer-Specific Responsibilities

### Store Layer (stores/*)

**Responsibilities:**
- Create InternalError with rich context
- Use infrastructure errors for technical failures
- Use domain errors for business logic failures
- Include operation names in all errors
- Log at the point of action (see logging.md)

**Example:**
```rust
impl CredentialStore {
    pub async fn get_user(&self, user_id: &str) -> Result<User, InternalError> {
        // Parse UUID (infrastructure error)
        let uuid = Uuid::parse_str(user_id)
            .map_err(|e| InternalError::parse("UUID", e.to_string()))?;
        
        // Query database (infrastructure error)
        let user = User::find()
            .filter(user::Column::Id.eq(uuid))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("get_user", e))?
            .ok_or_else(|| CredentialError::UserNotFound(user_id.to_string()))?;  // Domain error
        
        Ok(user)
    }
}
```

### Service Layer (services/*)

**Responsibilities:**
- Propagate InternalError unchanged
- Orchestrate business logic
- No error conversion (errors flow through)

**Example:**
```rust
impl AuthService {
    pub async fn login(&self, username: String, password: String) -> Result<(String, String), InternalError> {
        // Errors from stores propagate unchanged
        let user_id = self.credential_store
            .verify_credentials(&username, &password)
            .await?;  // InternalError flows through
        
        let access_token = self.token_service
            .generate_access_token(&user_id)
            .await?;  // InternalError flows through
        
        let refresh_token = self.credential_store
            .create_refresh_token(&user_id)
            .await?;  // InternalError flows through
        
        Ok((access_token, refresh_token))
    }
}
```

### API Layer (api/*)

**Responsibilities:**
- Convert InternalError to AuthError/AdminError
- Use `.map_err(AuthError::from_internal_error)?`
- Never expose internal details to clients

**Example:**
```rust
#[OpenApi]
impl AuthApi {
    #[oai(path = "/login", method = "post")]
    async fn login(&self, body: Json<LoginRequest>) -> Result<Json<TokenResponse>, AuthError> {
        // Explicit conversion from InternalError to AuthError
        let (access_token, refresh_token) = self.auth_service
            .login(body.username.clone(), body.password.clone())
            .await
            .map_err(AuthError::from_internal_error)?;  // ← Explicit conversion
        
        Ok(Json(TokenResponse { access_token, refresh_token }))
    }
}
```

## Conversion Pattern at API Boundary

The `from_internal_error()` method is where internal errors are converted to API errors. This is the security checkpoint where we decide what to expose.

### Conversion Logic

```rust
impl AuthError {
    pub fn from_internal_error(err: InternalError) -> Self {
        match err {
            // Infrastructure errors → Generic message
            InternalError::Database { operation, .. } => {
                tracing::error!("Database error in {}: {}", operation, err);
                AuthError::internal_server_error()  // "An internal error occurred"
            }
            InternalError::Transaction { operation, .. } => {
                tracing::error!("Transaction error in {}: {}", operation, err);
                AuthError::internal_server_error()
            }
            InternalError::Parse { value_type, .. } => {
                tracing::error!("Parse error for {}: {}", value_type, err);
                AuthError::internal_server_error()
            }
            InternalError::Crypto { operation, .. } => {
                tracing::error!("Crypto error in {}: {}", operation, err);
                AuthError::internal_server_error()
            }
            
            // Domain errors → Specific messages
            InternalError::Credential(CredentialError::InvalidCredentials) => {
                tracing::debug!("Invalid credentials attempt");
                AuthError::invalid_credentials()  // "Invalid username or password"
            }
            InternalError::Credential(CredentialError::DuplicateUsername(username)) => {
                tracing::warn!("Duplicate username attempt: {}", username);
                AuthError::duplicate_username()  // "Username already exists"
            }
            InternalError::Credential(CredentialError::UserNotFound(user_id)) => {
                tracing::debug!("User not found: {}", user_id);
                AuthError::user_not_found()  // "User not found"
            }
            
            // Unexpected errors → Generic message
            err => {
                tracing::error!("Unexpected error: {}", err);
                AuthError::internal_server_error()
            }
        }
    }
}
```

### Logging Levels

- **ERROR** - Infrastructure failures (database, crypto, parse, transaction)
- **WARN** - Suspicious activity (duplicate username attempts)
- **DEBUG** - Expected failures (invalid credentials, expired tokens)

## Adding New Error Types

### Scenario 1: Adding Methods to Existing Stores

**Effort: Trivial** - Just use existing error variants.

```rust
// Adding a new method to CredentialStore
impl CredentialStore {
    pub async fn is_user_locked(&self, user_id: &str) -> Result<bool, InternalError> {
        // Use existing infrastructure error
        let user = User::find()
            .filter(user::Column::Id.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("is_user_locked", e))?;  // ✅ Existing
        
        // Use existing domain error
        let user = user.ok_or_else(|| CredentialError::UserNotFound(user_id.to_string()))?;  // ✅ Existing
        
        Ok(user.locked_until.map(|t| t > Utc::now().timestamp()).unwrap_or(false))
    }
}
```

**What's involved:**
- ✅ Zero changes to error types
- ✅ Use existing infrastructure errors
- ✅ Use existing domain errors
- ✅ No API changes needed
- ✅ Type safety enforced by compiler

### Scenario 2: Adding a New Store

**Effort: Moderate** - Define domain errors, add one line to InternalError, update API conversion.

**Step 1: Define domain errors** (in `src/errors/internal.rs`)

```rust
/// Session store specific errors
#[derive(Error, Debug)]
pub enum SessionError {
    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    
    /// Session has expired
    #[error("Session expired: {0}")]
    SessionExpired(String),
    
    /// Session already invalidated
    #[error("Session already invalidated: {0}")]
    SessionInvalidated(String),
}
```

**Step 2: Add to InternalError** (one line in `src/errors/internal.rs`)

```rust
pub enum InternalError {
    // ... existing variants ...
    
    /// Session store errors
    #[error(transparent)]
    Session(#[from] SessionError),
}
```

**Step 3: Implement store**

```rust
impl SessionStore {
    pub async fn get_session(&self, session_id: &str) -> Result<Session, InternalError> {
        // Infrastructure error (works immediately)
        let session = Session::find()
            .filter(session::Column::Id.eq(session_id))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("get_session", e))?;  // ✅ Infrastructure
        
        // Domain error (new)
        let session = session.ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
        
        // Domain error (new)
        if session.expires_at < Utc::now().timestamp() {
            return Err(SessionError::SessionExpired(session_id.to_string()).into());
        }
        
        Ok(session)
    }
}
```

**Step 4: Update API conversion** (in `src/errors/api/auth.rs` or `admin.rs`)

```rust
impl AuthError {
    pub fn from_internal_error(err: InternalError) -> Self {
        match err {
            // ... existing conversions ...
            
            // Add new domain error conversions
            InternalError::Session(SessionError::SessionNotFound(_)) => {
                tracing::debug!("Session not found");
                AuthError::invalid_token()  // Or create new AuthError variant
            }
            InternalError::Session(SessionError::SessionExpired(_)) => {
                tracing::debug!("Session expired");
                AuthError::expired_token()
            }
            InternalError::Session(SessionError::SessionInvalidated(_)) => {
                tracing::debug!("Session invalidated");
                AuthError::invalid_token()
            }
            
            // ... rest of conversions ...
        }
    }
}
```

**What's involved:**
- ⚠️ Define domain error enum (5-10 variants)
- ✅ Add one line to InternalError
- ⚠️ Update API conversion (add match arms)
- ✅ Infrastructure errors work immediately
- ✅ Type safety enforced
- ✅ Isolated from other stores

### Scenario 3: Adding a New Domain Error Variant

**Effort: Minimal** - Add variant to existing domain error enum, update API conversion.

**Step 1: Add variant to domain error** (in `src/errors/internal.rs`)

```rust
#[derive(Error, Debug)]
pub enum CredentialError {
    // ... existing variants ...
    
    /// User account is locked
    #[error("User account locked: {0}")]
    UserLocked(String),
}
```

**Step 2: Use in store**

```rust
impl CredentialStore {
    pub async fn verify_credentials(&self, username: &str, password: &str) -> Result<String, InternalError> {
        let user = self.get_user_by_username(username).await?;
        
        // Use new domain error
        if user.locked_until.map(|t| t > Utc::now().timestamp()).unwrap_or(false) {
            return Err(CredentialError::UserLocked(user.id.to_string()).into());
        }
        
        // ... rest of logic ...
    }
}
```

**Step 3: Update API conversion** (in `src/errors/api/auth.rs`)

```rust
impl AuthError {
    pub fn from_internal_error(err: InternalError) -> Self {
        match err {
            // ... existing conversions ...
            
            // Add new conversion
            InternalError::Credential(CredentialError::UserLocked(_)) => {
                tracing::warn!("Locked user login attempt");
                AuthError::user_locked()  // Or use existing variant
            }
            
            // ... rest of conversions ...
        }
    }
}
```

## Module Organization

The error system uses a clear module structure:

```
src/errors/
├── mod.rs              # Root module with re-exports
├── internal.rs         # InternalError + domain errors
└── api/
    ├── mod.rs          # API error module
    ├── auth.rs         # AuthError
    └── admin.rs        # AdminError
```

**Benefits:**
- Clear architectural boundary (`api/` folder)
- Enforceable rules (API endpoints only use `errors::api::*`)
- Scalable (easy to add new API error types)
- Human-friendly (developers immediately understand organization)

**Imports:**

```rust
// In stores and services
use crate::errors::InternalError;
use crate::errors::internal::{CredentialError, SystemConfigError};

// In API endpoints
use crate::errors::{AuthError, AdminError};
```

## Security Considerations

### Never Expose Internal Details

Infrastructure errors contain implementation details that should never be exposed:
- Database table names
- Operation names
- Stack traces
- Library error messages

**Always:**
- Log full details at ERROR level
- Return generic "An internal error occurred" to clients

### Domain Errors Can Be Specific

Domain errors represent business logic failures and can have specific messages:
- "Invalid username or password"
- "Username already exists"
- "Token expired"
- "User not found"

These don't expose implementation details and help users understand what went wrong.

### Logging Levels Matter

- **ERROR** - Infrastructure failures (need investigation)
- **WARN** - Suspicious activity (potential security issues)
- **DEBUG** - Expected failures (normal operation)

## Testing Error Handling

### Unit Tests

Test error creation and conversion:

```rust
#[test]
fn test_database_error_includes_operation() {
    let db_err = sea_orm::DbErr::RecordNotFound("test".to_string());
    let internal_err = InternalError::database("create_user", db_err);
    
    assert!(internal_err.to_string().contains("create_user"));
    assert!(internal_err.to_string().contains("Database error"));
}

#[test]
fn test_invalid_credentials_converts_correctly() {
    let internal_err = InternalError::Credential(CredentialError::InvalidCredentials);
    let auth_err = AuthError::from_internal_error(internal_err);
    
    match auth_err {
        AuthError::InvalidCredentials(_) => {},
        _ => panic!("Expected InvalidCredentials variant"),
    }
}

#[test]
fn test_infrastructure_error_converts_to_generic() {
    let db_err = sea_orm::DbErr::RecordNotFound("test".to_string());
    let internal_err = InternalError::database("some_operation", db_err);
    let auth_err = AuthError::from_internal_error(internal_err);
    
    match auth_err {
        AuthError::InternalError(json) => {
            // Should be generic message, not expose operation name
            assert_eq!(json.0.message, "An internal error occurred");
        },
        _ => panic!("Expected InternalError variant"),
    }
}
```

### Integration Tests

Test end-to-end error flow:

```rust
#[tokio::test]
async fn test_invalid_credentials_flow() {
    let app_data = setup_test_app().await;
    
    let response = app_data.auth_api
        .login(Json(LoginRequest {
            username: "user".to_string(),
            password: "wrong".to_string(),
        }))
        .await;
    
    assert!(response.is_err());
    match response.unwrap_err() {
        AuthError::InvalidCredentials(_) => {},
        _ => panic!("Expected InvalidCredentials"),
    }
}
```

## Common Patterns

### Pattern 1: Database Query with Not Found

```rust
let user = User::find()
    .filter(user::Column::Id.eq(user_id))
    .one(&self.db)
    .await
    .map_err(|e| InternalError::database("get_user", e))?  // Infrastructure
    .ok_or_else(|| CredentialError::UserNotFound(user_id.to_string()))?;  // Domain
```

### Pattern 2: Parse Then Query

```rust
let uuid = Uuid::parse_str(user_id)
    .map_err(|e| InternalError::parse("UUID", e.to_string()))?;  // Infrastructure

let user = User::find()
    .filter(user::Column::Id.eq(uuid))
    .one(&self.db)
    .await
    .map_err(|e| InternalError::database("get_user", e))?;  // Infrastructure
```

### Pattern 3: Transaction with Multiple Operations

```rust
let txn = self.db.begin()
    .await
    .map_err(|e| InternalError::transaction("create_user_with_roles", e))?;

// Operation 1
let user = user::ActiveModel { ... }
    .insert(&txn)
    .await
    .map_err(|e| InternalError::database("insert_user", e))?;

// Operation 2
let role = role::ActiveModel { ... }
    .insert(&txn)
    .await
    .map_err(|e| InternalError::database("insert_role", e))?;

txn.commit()
    .await
    .map_err(|e| InternalError::transaction("create_user_with_roles", e))?;
```

### Pattern 4: Conditional Domain Error

```rust
if existing_user.is_some() {
    return Err(CredentialError::DuplicateUsername(username.to_string()).into());
}

if !password_valid {
    return Err(CredentialError::InvalidCredentials.into());
}

if user.locked_until.map(|t| t > Utc::now().timestamp()).unwrap_or(false) {
    return Err(CredentialError::UserLocked(user.id.to_string()).into());
}
```

## Summary

### Key Takeaways

1. **Two layers** - Internal (stores + services) use InternalError, API uses AuthError/AdminError
2. **Hybrid structure** - Infrastructure errors are shared, domain errors are store-specific
3. **Explicit conversion** - API boundary explicitly converts internal to API errors
4. **Security by design** - Infrastructure errors logged but never exposed
5. **Type safety** - Compiler prevents using wrong domain errors in wrong stores
6. **Easy to extend** - Adding methods uses existing errors, adding stores requires minimal changes

### Quick Reference

**In Stores:**
- Return `Result<T, InternalError>`
- Use `InternalError::database()`, `::parse()`, `::crypto()`, `::transaction()`
- Use domain errors: `CredentialError::*`, `SystemConfigError::*`, etc.

**In Services:**
- Return `Result<T, InternalError>`
- Propagate errors unchanged (no conversion)

**In API:**
- Return `Result<T, AuthError>` or `Result<T, AdminError>`
- Convert with `.map_err(AuthError::from_internal_error)?`

**Adding New Stores:**
1. Define domain error enum in `src/errors/internal.rs`
2. Add one line to `InternalError`: `YourError(#[from] YourError)`
3. Update API conversion in `src/errors/api/auth.rs` or `admin.rs`
4. Infrastructure errors work immediately

### Further Reading

- `src/errors/internal.rs` - InternalError and domain error definitions
- `src/errors/api/auth.rs` - AuthError and conversion logic
- `src/errors/api/admin.rs` - AdminError and conversion logic
- `.kiro/specs/error-handling-refactor/design.md` - Complete design document

# Design Document

## Overview

This design refactors the error handling system from a catch-all `AuthError::Internal` approach to a hybrid error architecture with clear separation between internal and API-facing errors.

### Design Philosophy

**Two-Layer Error System:**

1. **Internal Layer** (Stores + Services): Uses `InternalError` with rich context for logging and debugging
2. **API Layer** (Endpoints): Uses `AuthError`/`AdminError` with user-appropriate messages

**Why "InternalError" instead of "StoreError"?**

The name `InternalError` better reflects its usage across both stores AND services. It represents "internal to the application" (not exposed via API), rather than being specific to the store layer. This naming makes the architecture clearer: internal operations use `InternalError`, API operations use `AuthError`/`AdminError`.

### Error Architecture Principles

**Hybrid Structure:**
- **Infrastructure errors** (Database, Parse, Transaction, Crypto) are shared across all stores
- **Domain errors** (CredentialError, SystemConfigError, etc.) are specific to each store's business logic

**Purpose Separation:**
- **InternalError**: Detailed context for logging and debugging (never exposed to clients)
- **API Errors**: User-facing messages that are purposely vague for security (hide implementation details)

**Security Through Explicit Conversion:**
- No automatic conversion from internal to API errors
- Conversion point logs full details but returns generic/specific messages
- Infrastructure failures → Generic "An internal error occurred"
- Domain failures → Specific messages ("Invalid username or password")

This design ensures that:
- Developers get rich error context for debugging
- Users get appropriate error messages
- Implementation details never leak to API clients
- Type safety prevents using wrong domain errors in wrong stores

### Design Rationale

**Why separate Internal and API errors?**

1. **Security**: Internal errors contain implementation details (table names, operation names, stack traces) that should never be exposed to clients. API errors are carefully crafted to be informative without leaking sensitive information.

2. **Logging vs Display**: Internal errors are optimized for logging and debugging (rich context, full details). API errors are optimized for user display (clear messages, actionable guidance).

3. **Flexibility**: Internal layer can change error details without affecting API contracts. API layer can adjust user messages without changing internal error handling.

**Why hybrid (infrastructure + domain) errors?**

1. **Shared Infrastructure**: Database, parsing, and crypto errors are common across all stores. Sharing these reduces duplication and ensures consistent handling.

2. **Isolated Domains**: Business logic errors (InvalidCredentials, DuplicateUsername) are specific to each store's domain. Isolating these provides type safety and prevents misuse.

3. **Extensibility**: Adding a new store requires only defining its domain errors and adding one line to `InternalError`. Infrastructure errors work immediately.

4. **Clear Intent**: Code clearly shows whether an error is technical (infrastructure) or business logic (domain).

**Why explicit conversion?**

1. **Security Checkpoint**: The conversion point is where we decide what to expose. Making it explicit ensures we consciously handle each error type.

2. **Logging Point**: Conversion is where we log internal details before returning generic messages. Explicit conversion makes this logging obvious.

3. **No Accidents**: Without automatic `From` implementations, you can't accidentally expose internal errors via API.

**Primary Use Cases:**

- **InternalError**: Logging, debugging, internal error propagation
- **API Errors**: User-facing messages, HTTP responses, client error handling

## Architecture

### Error Layer Architecture

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

### Error Flow Example

```
1. Store: Database query fails
   → Creates: InternalError::Database { operation: "get_user", source: DbErr }
   → Logs: Full error with operation name and DB error details
   
2. Service: Propagates error unchanged
   → Returns: InternalError::Database { ... }
   
3. API: Converts to user-facing error
   → Logs: "Database error in get_user: ..." (ERROR level)
   → Returns: AuthError::InternalError("An internal error occurred")
   → Client sees: Generic message, no implementation details
```

```
1. Store: Invalid credentials
   → Creates: CredentialError::InvalidCredentials
   → Auto-converts to: InternalError::Credential(InvalidCredentials)
   
2. Service: Propagates error unchanged
   → Returns: InternalError::Credential(InvalidCredentials)
   
3. API: Converts to user-facing error
   → Logs: "Invalid credentials attempt" (DEBUG level)
   → Returns: AuthError::InvalidCredentials("Invalid username or password")
   → Client sees: Specific, actionable message
```

## Components and Interfaces

### Module Organization

The error system uses a clear module structure to separate API-facing errors from internal errors:

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
- **Clear architectural boundary** - `api/` folder makes it obvious these are API-facing errors
- **Enforceable rules** - Can lint that API endpoints only use `errors::api::*`
- **Scalable** - Easy to add new API error types (e.g., `api/rate_limit.rs`)
- **Human-friendly** - Developers immediately understand the organization

**Module Setup:**

```rust
// src/errors/mod.rs
pub mod internal;
pub mod api;

// Re-exports for convenience
pub use internal::InternalError;
pub use api::{AuthError, AdminError};
```

```rust
// src/errors/api/mod.rs
pub mod auth;
pub mod admin;

pub use auth::AuthError;
pub use admin::AdminError;
```

### Internal Error Types

#### InternalError (Hybrid)

Located in `src/errors/internal.rs`, this is the primary internal error type used by stores and services. It uses a hybrid approach that separates infrastructure errors (shared by all stores) from domain-specific errors (unique to each store).

```rust
use thiserror::Error;

/// Internal error type for store and service operations
/// 
/// This is a hybrid error type that separates:
/// - Infrastructure errors (Database, Parse, Transaction, Crypto) - shared by all stores
/// - Domain errors (Credential, SystemConfig, Audit) - specific to each store
/// 
/// This error type is NOT exposed via API. API endpoints must explicitly
/// convert these to AuthError or AdminError.
#[derive(Error, Debug)]
pub enum InternalError {
    // ============================================================
    // Infrastructure Errors (shared by all stores)
    // ============================================================
    
    /// Database query or operation failed
    #[error("Database error: {operation} failed: {source}")]
    Database {
        operation: String,
        #[source]
        source: sea_orm::DbErr,
    },
    
    /// Database transaction failed
    #[error("Transaction error: {operation} failed: {source}")]
    Transaction {
        operation: String,
        #[source]
        source: sea_orm::DbErr,
    },
    
    /// Failed to parse a value (UUID, timestamp, JSON, etc.)
    #[error("Parse error: failed to parse {value_type}: {message}")]
    Parse {
        value_type: String,
        message: String,
    },
    
    /// Cryptographic operation failed (hashing, verification, etc.)
    #[error("Crypto error: {operation} failed: {message}")]
    Crypto {
        operation: String,
        message: String,
    },
    
    // ============================================================
    // Domain-Specific Errors (one per store)
    // ============================================================
    
    /// Credential store errors (authentication, user management, tokens)
    #[error(transparent)]
    Credential(#[from] CredentialError),
    
    /// System config store errors (owner management, system settings)
    #[error(transparent)]
    SystemConfig(#[from] SystemConfigError),
    
    /// Audit store errors (audit logging failures)
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// Credential store specific errors
#[derive(Error, Debug)]
pub enum CredentialError {
    /// Invalid username or password
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    /// Username already exists
    #[error("User already exists: {0}")]
    DuplicateUsername(String),
    
    /// User not found
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    /// Password hashing failed
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),
    
    /// Invalid or malformed token
    #[error("Invalid token: {token_type} - {reason}")]
    InvalidToken {
        token_type: String,
        reason: String,
    },
    
    /// Token has expired
    #[error("Expired token: {0}")]
    ExpiredToken(String),
}

/// System config store specific errors
#[derive(Error, Debug)]
pub enum SystemConfigError {
    /// System config not found
    #[error("System config not found")]
    ConfigNotFound,
    
    /// Owner account already exists
    #[error("Owner already exists")]
    OwnerAlreadyExists,
    
    /// Owner account not found
    #[error("Owner not found")]
    OwnerNotFound,
}

/// Audit store specific errors
#[derive(Error, Debug)]
pub enum AuditError {
    /// Failed to write audit log entry
    #[error("Failed to write audit log: {0}")]
    LogWriteFailed(String),
}
```

#### Helper Methods for Infrastructure Errors

Infrastructure errors use helper methods on `InternalError`:

```rust
impl InternalError {
    /// Create a database error with context
    pub fn database(operation: impl Into<String>, source: sea_orm::DbErr) -> Self {
        Self::Database {
            operation: operation.into(),
            source,
        }
    }
    
    /// Create a transaction error with context
    pub fn transaction(operation: impl Into<String>, source: sea_orm::DbErr) -> Self {
        Self::Transaction {
            operation: operation.into(),
            source,
        }
    }
    
    /// Create a parse error with context
    pub fn parse(value_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Parse {
            value_type: value_type.into(),
            message: message.into(),
        }
    }
    
    /// Create a crypto error with context
    pub fn crypto(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            operation: operation.into(),
            message: message.into(),
        }
    }
}
```

#### Helper Methods for Domain Errors

Domain errors use their own constructors and auto-convert to `InternalError` via `#[from]`:

```rust
impl CredentialError {
    /// Create an invalid token error
    pub fn invalid_token(token_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidToken {
            token_type: token_type.into(),
            reason: reason.into(),
        }
    }
}

// Usage in CredentialStore:
return Err(CredentialError::InvalidCredentials.into());  // Auto-converts to InternalError
return Err(CredentialError::DuplicateUsername(username).into());
return Err(CredentialError::invalid_token("jwt", "signature invalid").into());

// Usage in SystemConfigStore:
return Err(SystemConfigError::ConfigNotFound.into());  // Auto-converts to InternalError
return Err(SystemConfigError::OwnerAlreadyExists.into());
```

### API Error Types

#### AuthError (Updated)

Located in `src/errors/api/auth.rs`, this remains the API-facing error type but with updated conversion logic.

```rust
// Keep existing AuthError enum structure
// Remove internal_error() constructor
// Add conversion methods from InternalError

impl AuthError {
    /// Convert InternalError to AuthError
    /// 
    /// This is the explicit conversion point from internal errors to API errors.
    /// Internal error details are logged but not exposed to clients.
    pub fn from_store_error(err: InternalError) -> Self {
        match err {
            // Infrastructure errors - always log and return generic error
            InternalError::Database { operation, .. } => {
                tracing::error!("Database error in {}: {}", operation, err);
                AuthError::internal_server_error()
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
            
            // Domain errors - convert to specific API errors
            InternalError::Credential(CredentialError::InvalidCredentials) => {
                tracing::debug!("Invalid credentials attempt");
                AuthError::invalid_credentials()
            }
            InternalError::Credential(CredentialError::DuplicateUsername(username)) => {
                tracing::warn!("Duplicate username attempt: {}", username);
                AuthError::duplicate_username()
            }
            InternalError::Credential(CredentialError::InvalidToken { token_type, reason }) => {
                tracing::debug!("Invalid token: {} - {}", token_type, reason);
                if token_type == "jwt" {
                    AuthError::invalid_token()
                } else if token_type == "refresh_token" {
                    AuthError::invalid_refresh_token()
                } else {
                    AuthError::invalid_token()
                }
            }
            InternalError::Credential(CredentialError::ExpiredToken(token_type)) => {
                tracing::debug!("Expired token: {}", token_type);
                if token_type == "jwt" {
                    AuthError::expired_token()
                } else if token_type == "refresh_token" {
                    AuthError::expired_refresh_token()
                } else {
                    AuthError::expired_token()
                }
            }
            
            // Other domain errors that shouldn't appear in auth context
            err => {
                tracing::error!("Unexpected error in auth operation: {}", err);
                AuthError::internal_server_error()
            }
        }
    }
    
    /// Create a generic internal server error
    /// 
    /// This replaces the old internal_error() method. It always returns
    /// a generic message without exposing internal details.
    fn internal_server_error() -> Self {
        AuthError::InternalError(Json(AuthErrorResponse {
            error: "internal_error".to_string(),
            message: "An internal error occurred".to_string(),
            status_code: 500,
        }))
    }
}
```

#### AdminError (Updated)

Located in `src/errors/api/admin.rs`, similar conversion logic for admin operations.

```rust
impl AdminError {
    /// Convert InternalError to AdminError
    pub fn from_store_error(err: InternalError) -> Self {
        match err {
            // Infrastructure errors - always log and return generic error
            InternalError::Database { operation, .. } => {
                tracing::error!("Database error in {}: {}", operation, err);
                AdminError::internal_server_error()
            }
            InternalError::Transaction { operation, .. } => {
                tracing::error!("Transaction error in {}: {}", operation, err);
                AdminError::internal_server_error()
            }
            InternalError::Parse { value_type, .. } => {
                tracing::error!("Parse error for {}: {}", value_type, err);
                AdminError::internal_server_error()
            }
            InternalError::Crypto { operation, .. } => {
                tracing::error!("Crypto error in {}: {}", operation, err);
                AdminError::internal_server_error()
            }
            
            // Credential domain errors
            InternalError::Credential(CredentialError::UserNotFound(user_id)) => {
                AdminError::user_not_found(user_id)
            }
            InternalError::Credential(CredentialError::DuplicateUsername(username)) => {
                tracing::warn!("Duplicate username in admin operation: {}", username);
                AdminError::internal_server_error()  // Shouldn't happen in admin context
            }
            
            // SystemConfig domain errors
            InternalError::SystemConfig(SystemConfigError::OwnerAlreadyExists) => {
                AdminError::already_bootstrapped()
            }
            InternalError::SystemConfig(SystemConfigError::OwnerNotFound) => {
                AdminError::owner_not_found()
            }
            
            // Other domain errors
            err => {
                tracing::error!("Unexpected error in admin operation: {}", err);
                AdminError::internal_server_error()
            }
        }
    }
    
    /// Create a generic internal server error
    fn internal_server_error() -> Self {
        AdminError::InternalError(Json(AdminErrorResponse {
            error: "internal_error".to_string(),
            message: "An internal error occurred".to_string(),
            status_code: 500,
        }))
    }
}
```

## Data Models

### Error Context

Errors carry rich context through their variants:

- **Database errors**: Include operation name and underlying SeaORM error
- **Transaction errors**: Include transaction name and underlying error
- **Parse errors**: Include value type being parsed and error message
- **Crypto errors**: Include operation name and error message
- **Not found errors**: Include resource type and identifier
- **Already exists errors**: Include resource type and identifier
- **Token errors**: Include token type and reason/expiration info

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Database errors use specific error type

*For any* database operation that fails, the resulting error should be `InternalError::Database` with the operation name included in the error context.

**Validates: Requirements 1.1**

### Property 2: Parse errors use specific error type

*For any* parsing operation (UUID, JSON, timestamp) that fails, the resulting error should be `InternalError::Parse` with the value type included in the error context.

**Validates: Requirements 1.2**

### Property 3: Crypto errors use specific error type

*For any* cryptographic operation (hashing, verification) that fails, the resulting error should be `InternalError::Crypto` with the operation name included in the error context.

**Validates: Requirements 1.3**

### Property 4: Transaction errors use specific error type

*For any* database transaction that fails, the resulting error should be `InternalError::Transaction` with the transaction name included in the error context.

**Validates: Requirements 1.4**

### Property 5: Not-found errors use specific error type

*For any* resource lookup that fails to find the resource, the resulting error should be `InternalError::NotFound` with the resource type and identifier included in the error context.

**Validates: Requirements 1.5**

### Property 6: Infrastructure errors convert to generic API messages

*For any* infrastructure error (database, transaction, parse, crypto) converted to an API error, the resulting API error message should be the generic "An internal error occurred" without exposing implementation details.

**Validates: Requirements 2.2**

### Property 7: Domain errors convert to specific API messages

*For any* domain error (InvalidCredentials, AlreadyExists with resource_type="user") converted to an API error, the resulting API error should have a specific, appropriate message for that domain error.

**Validates: Requirements 2.3**

### Property 8: Internal to API conversion preserves semantics

*For any* InternalError converted to AuthError or AdminError, the error semantics should be preserved (e.g., InvalidCredentials → InvalidCredentials, NotFound("user") → UserNotFound) while hiding implementation details.

**Validates: Requirements 3.2, 3.3**

### Property 9: Database error messages include operation name

*For any* database error created with an operation name, the error's Display output should contain that operation name.

**Validates: Requirements 4.1**

### Property 10: Parse error messages include value type

*For any* parse error created with a value type, the error's Display output should contain that value type.

**Validates: Requirements 4.2**

### Property 11: Crypto error messages include operation name

*For any* crypto error created with an operation name, the error's Display output should contain that operation name.

**Validates: Requirements 4.3**

### Property 12: Transaction error messages include transaction name

*For any* transaction error created with a transaction name, the error's Display output should contain that transaction name.

**Validates: Requirements 4.4**

### Property 13: Not-found error messages include resource information

*For any* not-found error created with a resource type and identifier, the error's Display output should contain both the resource type and identifier.

**Validates: Requirements 4.5**

## Error Handling

### Store Layer Error Handling

Stores use infrastructure errors for technical failures and domain errors for business logic failures:

```rust
// CredentialStore examples

// Infrastructure error: Database query
User::find()
    .filter(user::Column::Id.eq(user_id))
    .one(&self.db)
    .await
    .map_err(|e| InternalError::database("get_user_by_id", e))?

// Infrastructure error: Parse UUID
let user_id = Uuid::parse_str(&user_id_str)
    .map_err(|e| InternalError::parse("UUID", e.to_string()))?;

// Domain error: User not found
let user = User::find()
    .filter(user::Column::Id.eq(user_id))
    .one(&self.db)
    .await
    .map_err(|e| InternalError::database("get_user_by_id", e))?
    .ok_or_else(|| CredentialError::UserNotFound(user_id.to_string()))?;
    // Note: CredentialError auto-converts to InternalError via #[from]

// Domain error: Invalid credentials
if !password_valid {
    return Err(CredentialError::InvalidCredentials.into());
}

// Infrastructure error: Crypto operation
let argon2 = Argon2::new_with_secret(...)
    .map_err(|e| InternalError::crypto("argon2_init", e.to_string()))?;

// Domain error: Password hashing (could also be infrastructure)
let password_hash = argon2.hash_password(...)
    .map_err(|e| CredentialError::PasswordHashingFailed(e.to_string()))?;

// Infrastructure error: Transaction
let txn = self.db.begin().await
    .map_err(|e| InternalError::transaction("create_admin_user", e))?;

// Domain error: Duplicate username
if existing_user.is_some() {
    return Err(CredentialError::DuplicateUsername(username).into());
}

// SystemConfigStore examples

// Domain error: Config not found
SystemConfig::find_by_id(1)
    .one(&self.db)
    .await
    .map_err(|e| InternalError::database("get_config", e))?
    .ok_or_else(|| SystemConfigError::ConfigNotFound)?;

// Domain error: Owner already exists
if owner.is_some() {
    return Err(SystemConfigError::OwnerAlreadyExists.into());
}
```

### Service Layer Error Handling

Services propagate InternalError unchanged:

```rust
pub async fn login(
    &self,
    ctx: &RequestContext,
    username: String,
    password: String,
) -> Result<(String, String), InternalError> {
    // Errors from stores are propagated as-is
    let user_id_str = self.credential_store
        .verify_credentials(&username, &password, ctx.ip_address.clone())
        .await?;  // InternalError propagates
    
    // ... rest of logic
}
```

### API Layer Error Handling

API endpoints explicitly convert InternalError to AuthError/AdminError:

```rust
#[oai(path = "/login", method = "post")]
async fn login(
    &self,
    req: &Request,
    body: Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AuthError> {
    let ctx = self.create_request_context(req, None).await;
    
    // Explicit conversion from InternalError to AuthError
    let (access_token, refresh_token) = self.auth_service
        .login(&ctx, body.username.clone(), body.password.clone())
        .await
        .map_err(AuthError::from_store_error)?;
    
    // ... rest of logic
}
```

## Testing Strategy

### Unit Testing

Unit tests will verify:

1. **Error creation with context** - Test that errors include expected context fields
2. **Error conversion logic** - Test that InternalError converts to correct AuthError/AdminError variants
3. **Error message formatting** - Test that error messages are formatted correctly
4. **Logging behavior** - Test that internal errors are logged during conversion

Example unit tests:

```rust
#[test]
fn test_database_error_includes_operation() {
    let db_err = sea_orm::DbErr::RecordNotFound("test".to_string());
    let store_err = InternalError::database("create_user", db_err);
    
    assert!(store_err.to_string().contains("create_user"));
    assert!(store_err.to_string().contains("Database error"));
}

#[test]
fn test_invalid_credentials_converts_correctly() {
    let store_err = InternalError::InvalidCredentials;
    let auth_err = AuthError::from_store_error(store_err);
    
    match auth_err {
        AuthError::InvalidCredentials(_) => {},
        _ => panic!("Expected InvalidCredentials variant"),
    }
}

#[test]
fn test_database_error_converts_to_internal() {
    let db_err = sea_orm::DbErr::RecordNotFound("test".to_string());
    let store_err = InternalError::database("some_operation", db_err);
    let auth_err = AuthError::from_store_error(store_err);
    
    match auth_err {
        AuthError::InternalError(json) => {
            // Should be generic message, not expose operation name
            assert_eq!(json.0.message, "An internal error occurred");
        },
        _ => panic!("Expected InternalError variant"),
    }
}
```

### Integration Testing

Integration tests will verify:

1. **End-to-end error flow** - Test that errors flow correctly from store → service → API
2. **Error logging** - Test that errors are logged at appropriate points
3. **API error responses** - Test that API returns correct HTTP status codes and error messages
4. **Security** - Test that internal details are not exposed in API responses

### Property-Based Testing

Property-based tests will verify:

1. **Error context preservation** - For any error created with context, the context should be present in the error message
2. **API error safety** - For any internal error converted to API error, the API error should not contain internal details
3. **Conversion consistency** - For any InternalError variant, conversion to AuthError/AdminError should be deterministic

## Migration Strategy

### Phase 1: Create Module Structure and InternalError Type

1. Create `src/errors/api/` directory
2. Move `src/errors/auth.rs` to `src/errors/api/auth.rs`
3. Move `src/errors/admin.rs` to `src/errors/api/admin.rs`
4. Create `src/errors/api/mod.rs` with re-exports
5. Create `src/errors/internal.rs` with InternalError enum and domain error enums
6. Update `src/errors/mod.rs` to include both `internal` and `api` modules
7. Add `thiserror = "1.0"` dependency to `Cargo.toml`

**Files created:**
- `src/errors/api/mod.rs` - API error module with re-exports
- `src/errors/internal.rs` - Contains `InternalError`, `CredentialError`, `SystemConfigError`, `AuditError`

**Files moved:**
- `src/errors/auth.rs` → `src/errors/api/auth.rs`
- `src/errors/admin.rs` → `src/errors/api/admin.rs`

**Files modified:**
- `src/errors/mod.rs` - Update module structure

### Phase 2: Update AuthError and AdminError

1. Add `from_internal_error()` methods to AuthError and AdminError
2. Add `internal_server_error()` private methods
3. Keep existing error constructors for backward compatibility during migration

**Files modified:**
- `src/errors/api/auth.rs` - Add conversion method
- `src/errors/api/admin.rs` - Add conversion method

### Phase 3: Update Stores (One at a Time)

For each store:
1. Change return type from `Result<T, AuthError>` to `Result<T, InternalError>`
2. Replace `AuthError::internal_error()` calls with appropriate InternalError variants
3. Use infrastructure errors (`InternalError::database()`, etc.) for technical failures
4. Use domain errors (`CredentialError::InvalidCredentials`, etc.) for business logic failures
5. Update error context to include operation names
6. Run tests to verify behavior

**Order:**
1. `system_config_store.rs` (smallest, simplest) - Uses `SystemConfigError`
2. `audit_store.rs` - Uses `AuditError`
3. `credential_store.rs` (largest, most complex) - Uses `CredentialError`

### Phase 4: Update Services

For each service:
1. Change return type from `Result<T, AuthError>` to `Result<T, InternalError>`
2. Propagate InternalError from stores unchanged (no conversion needed)
3. Run tests to verify behavior

**Order:**
1. `token_service.rs`
2. `auth_service.rs`
3. `admin_service.rs`

### Phase 5: Update API Endpoints

For each API file:
1. Add `.map_err(AuthError::from_internal_error)?` or `.map_err(AdminError::from_internal_error)?` to service calls
2. Run tests to verify behavior
3. Verify that error messages are appropriate for users

**Order:**
1. `health.rs` (if needed)
2. `auth.rs`
3. `admin.rs`

### Phase 6: Update AppData

1. Change `AppData::init()` return type from `Result<Self, AuthError>` to `Result<Self, InternalError>`
2. Update `main.rs` to handle InternalError from AppData::init()
3. Convert to appropriate error type for application startup
4. Run tests to verify behavior

**Files modified:**
- `src/app_data.rs`
- `src/main.rs`

### Phase 7: Cleanup

1. Remove `internal_error()` constructor from AuthError and AdminError
2. Remove any remaining `AuthError` or `AdminError` usage in stores/services
3. Update documentation in `docs/` directory
4. Final test pass across all components
5. Verify no internal details are exposed in API responses

## Implementation Notes

### Using thiserror

The `thiserror` crate provides convenient error handling:

```toml
[dependencies]
thiserror = "1.0"
```

Benefits:
- Automatic `Error` trait implementation
- Automatic `Display` implementation
- Source error chaining with `#[source]`
- Clean error variant definitions

### Logging Strategy

Internal errors should be logged when converted to API errors:

```rust
pub fn from_store_error(err: InternalError) -> Self {
    match err {
        // Domain errors - log at debug level
        InternalError::InvalidCredentials => {
            tracing::debug!("Invalid credentials attempt");
            AuthError::invalid_credentials()
        }
        // Infrastructure errors - log at error level
        err @ InternalError::Database { .. } => {
            tracing::error!("Database error: {}", err);
            AuthError::internal_server_error()
        }
        // ... etc
    }
}
```

### Backward Compatibility

During migration:
- Keep existing error constructors working
- Add new error types alongside old ones
- Migrate one component at a time
- Tests ensure behavior doesn't change

### Extending the Error System

#### Adding Methods to Existing Stores

When adding new methods to existing stores, use existing error types:

```rust
// CredentialStore - new method
pub async fn is_user_locked(&self, user_id: &str) -> Result<bool, InternalError> {
    let user = User::find()
        .filter(user::Column::Id.eq(user_id))
        .one(&self.db)
        .await
        .map_err(|e| InternalError::database("is_user_locked", e))?  // ✅ Infrastructure error
        .ok_or_else(|| CredentialError::UserNotFound(user_id.to_string()))?;  // ✅ Domain error
    
    Ok(user.locked_until.map(|t| t > Utc::now().timestamp()).unwrap_or(false))
}
```

**What's involved:**
- ✅ **Zero changes to error types** - Use existing infrastructure and domain errors
- ✅ **Use infrastructure errors** - `InternalError::database()`, `InternalError::parse()`, etc.
- ✅ **Use domain errors** - `CredentialError::UserNotFound`, `SystemConfigError::ConfigNotFound`, etc.
- ✅ **No API changes** - Conversion logic already handles these errors
- ✅ **Type safety** - Compiler ensures you use correct domain errors for the store

**Verdict: Trivial** - Just use existing error variants with appropriate context.

#### Adding New Stores

When adding a new store, define its domain errors and add one line to `InternalError`:

```rust
// Step 1: Define domain errors (in src/errors/internal.rs)
#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    
    #[error("Session expired: {0}")]
    SessionExpired(String),
}

// Step 2: Add to InternalError (one line in src/errors/internal.rs)
pub enum InternalError {
    // ... existing variants ...
    
    #[error(transparent)]
    Session(#[from] SessionError),
}

// Step 3: Implement store
impl SessionStore {
    pub async fn get_session(&self, session_id: &str) -> Result<Session, InternalError> {
        let session = Session::find()
            .filter(session::Column::Id.eq(session_id))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("get_session", e))?  // ✅ Infrastructure error
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;  // ✅ Domain error
        
        if session.expires_at < Utc::now().timestamp() {
            return Err(SessionError::SessionExpired(session_id.to_string()).into());
        }
        
        Ok(session)
    }
}

// Step 4: Update API conversion (in src/errors/auth.rs or admin.rs)
impl AuthError {
    pub fn from_internal_error(err: InternalError) -> Self {
        match err {
            // ... existing conversions ...
            
            InternalError::Session(SessionError::SessionNotFound(_)) => {
                tracing::debug!("Session not found");
                AuthError::invalid_token()  // Or create new AuthError variant
            }
            InternalError::Session(SessionError::SessionExpired(_)) => {
                tracing::debug!("Session expired");
                AuthError::expired_token()
            }
            
            // ... rest of conversions ...
        }
    }
}
```

**What's involved:**
- ⚠️ **Define domain error enum** - Small enum (5-10 variants) focused on store's domain
- ✅ **Add one line to InternalError** - `Session(#[from] SessionError)`
- ⚠️ **Update API conversion** - Add match arms in `src/errors/api/auth.rs` or `admin.rs`
- ✅ **Infrastructure errors work immediately** - Database, Parse, Transaction, Crypto all available
- ✅ **Type safety** - Can't accidentally use `CredentialError` in `SessionStore`
- ✅ **Isolated** - New store's errors don't affect existing stores
- ✅ **Clear organization** - API errors in `errors/api/`, internal errors in `errors/internal.rs`

**Verdict: Moderate effort** - Requires defining domain errors and updating conversion, but infrastructure is ready to use.

### Future: Linting Rules

The module structure enables enforceable architectural rules:

```rust
// Potential clippy or custom lint rules:
// 1. API layer (src/api/*) can only use errors::api::*
// 2. Internal layer (src/stores/*, src/services/*) can only use errors::InternalError
// 3. No direct use of domain errors (CredentialError, etc.) outside their store
```

This makes architectural violations detectable at compile time or via CI/CD.

### Future Extensions

This design makes it easy to add:
- New stores with isolated domain errors
- New error variants for new failure modes
- Error codes for client-side error handling
- Structured error responses with additional fields
- Error metrics and monitoring
- Retry logic based on error type


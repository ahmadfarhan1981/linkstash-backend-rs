# Test Utilities

## Overview

Common test utilities are centralized in `tests/common/mod.rs` to eliminate code duplication across integration tests.

## Available Utilities

### Database Setup

#### `setup_test_auth_db() -> DatabaseConnection`
Creates an in-memory SQLite database with auth migrations applied.

```rust
let db = common::setup_test_auth_db().await;
```

#### `setup_test_audit_db() -> DatabaseConnection`
Creates an in-memory SQLite database with audit migrations applied.

```rust
let audit_db = common::setup_test_audit_db().await;
```

#### `setup_test_databases() -> (DatabaseConnection, DatabaseConnection)`
Creates both auth and audit databases together.

```rust
let (auth_db, audit_db) = common::setup_test_databases().await;
```

#### `create_test_audit_store() -> Arc<AuditStore>`
Creates an AuditStore with in-memory database, ready for use in tests.

```rust
let audit_store = common::create_test_audit_store().await;
```

### Store Setup

#### `create_test_credential_store() -> (DatabaseConnection, Arc<CredentialStore>)`
Creates a CredentialStore with standard test configuration (test password pepper).

```rust
let (db, credential_store) = common::create_test_credential_store().await;
```

For tests that need custom password peppers (e.g., testing pepper functionality), create the store inline in the test.

#### `create_test_system_config_store() -> (DatabaseConnection, Arc<SystemConfigStore>)`
Creates a SystemConfigStore with standard test configuration.

```rust
let (db, system_config_store) = common::create_test_system_config_store().await;
```

#### `create_test_auth_setup() -> (DatabaseConnection, DatabaseConnection, Arc<AuthService>, Arc<TokenService>, Arc<CredentialStore>)`
Creates a complete auth test setup with all services configured and a test user "testuser"/"testpass" already created.

```rust
let (db, audit_db, auth_service, token_service, credential_store) = common::create_test_auth_setup().await;
```

### Environment Variable Management

#### `EnvGuard`
RAII guard for managing environment variables in tests. Automatically cleans up variables on creation and when dropped, ensuring test isolation.

```rust
let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER"]);
unsafe {
    std::env::set_var("JWT_SECRET", "test-secret");
}
// Variables automatically cleaned up when _guard drops
```

#### `ENV_TEST_MUTEX`
Global mutex for tests that modify environment variables. Since environment variables are process-global, tests that modify them must run serially.

```rust
let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
let _guard = common::EnvGuard::new(vec!["JWT_SECRET"]);
// Test code that modifies environment variables
```

## Usage Pattern

Import the common module at the top of your test file:

```rust
mod common;

use linkstash_backend::stores::SystemConfigStore;

async fn setup_test_db() -> SystemConfigStore {
    let db = common::setup_test_auth_db().await;
    let audit_store = common::create_test_audit_store().await;
    SystemConfigStore::new(db, audit_store)
}
```

## Benefits

- **DRY Principle** - Database setup code written once, used everywhere
- **Consistency** - All tests use the same setup patterns
- **Maintainability** - Changes to test infrastructure happen in one place
- **Test Isolation** - EnvGuard ensures environment variables don't leak between tests
- **Thread Safety** - ENV_TEST_MUTEX prevents race conditions in environment variable tests

## Additional Refactoring Opportunities

### 1. Test User Creation Helper
Many tests create users with similar patterns. Consider adding:

```rust
pub async fn create_test_user(
    store: &CredentialStore,
    username: &str,
    password: &str,
) -> String {
    let ctx = RequestContext::for_cli("test");
    // ctx.actor_id = "cli:test"
    store.add_user(username, password, &ctx)
        .await
        .expect("Failed to create test user")
}
```

### 2. Test Credential Helpers
For tests that need authenticated users:

```rust
pub async fn create_test_user_with_token(
    store: &CredentialStore,
    token_service: &TokenService,
    username: &str,
) -> (String, String) {
    let user_id = create_test_user(store, username, "password").await;
    let (jwt, _) = token_service.generate_jwt(&user_id, false, false, false, vec![], None)
        .await
        .expect("Failed to generate JWT");
    (user_id, jwt)
}
```

### 3. Request Context Builders
For tests that need various request contexts:

```rust
use crate::types::internal::auth::Claims;

/// Create a test context for an authenticated user
pub fn test_context_authenticated(user_id: &str) -> RequestContext {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: (Utc::now() + Duration::minutes(15)).timestamp(),
        iat: Utc::now().timestamp(),
        jti: Some(Uuid::new_v4().to_string()),
        is_owner: false,
        is_system_admin: false,
        is_role_admin: false,
        app_roles: vec![],
    };
    
    RequestContext::new()
        .with_auth(claims)  // Sets authenticated=true, actor_id from claims.sub
        .with_ip_address("127.0.0.1")
}

/// Create a test context for an unauthenticated request
pub fn test_context_unauthenticated() -> RequestContext {
    RequestContext::new()
        .with_ip_address("127.0.0.1")
    // actor_id = "unknown", authenticated = false
}

/// Create a test context for a CLI operation
pub fn test_context_cli(command: &str) -> RequestContext {
    RequestContext::for_cli(command)
    // actor_id = "cli:{command}"
}

/// Create a test context for a system operation
pub fn test_context_system(operation: &str) -> RequestContext {
    RequestContext::for_system(operation)
    // actor_id = "system:{operation}"
}
```

### 4. Assertion Helpers
For common assertion patterns:

```rust
pub fn assert_audit_event_exists(
    audit_store: &AuditStore,
    event_type: EventType,
    user_id: &str,
) {
    // Query audit log and assert event exists
}
```

## When to Add New Utilities

Add utilities to `tests/common/mod.rs` when:
- The same setup code appears in 3+ test files
- The pattern is likely to be reused in future tests
- The utility improves test readability significantly
- The utility enforces best practices (like EnvGuard for test isolation)

Avoid adding utilities that:
- Are only used in one test file
- Make tests harder to understand
- Hide important test setup details

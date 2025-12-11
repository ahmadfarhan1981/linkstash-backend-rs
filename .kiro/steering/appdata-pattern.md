---
inclusion: always
---

# AppData Pattern for AI Agents

## Critical Rules

**ALWAYS use AppData pattern for coordinator instantiation. NEVER create coordinators with manual dependency injection.**

## Pattern Requirements

### 1. Coordinator Constructor Signature
```rust
impl SomeCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self
}
```

**Rules:**
- MUST take `Arc<AppData>` as single parameter
- MUST NOT take individual stores/providers as parameters
- MUST NOT be async
- MUST extract stores from AppData
- MUST create providers internally from AppData components

### 2. Coordinator Implementation Pattern
```rust
impl AuthCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self {
        // Step 1: Create providers from AppData components
        let token_provider = Arc::new(TokenProvider::new(
            app_data.secret_manager.jwt_secret().to_string(),
            app_data.secret_manager.refresh_token_secret().to_string(),
            app_data.audit_store.clone(),
        ));
        
        let password_validator_provider = Arc::new(PasswordValidatorProvider::new(
            app_data.common_password_store.clone(),
            app_data.hibp_cache_store.clone(),
        ));
        
        let audit_logger_provider = Arc::new(AuditLoggerProvider::new(
            app_data.audit_store.clone(),
        ));
        
        // Step 2: Extract stores and assign providers
        Self {
            credential_store: app_data.credential_store.clone(),
            system_config_store: app_data.system_config_store.clone(),
            token_provider,
            password_validator_provider,
            audit_logger_provider,
        }
    }
}
```

### 3. main.rs Usage Pattern
```rust
// ✅ CORRECT
let app_data = Arc::new(AppData::init().await?);
let auth_coordinator = Arc::new(AuthCoordinator::new(app_data.clone()));
let admin_coordinator = Arc::new(AdminCoordinator::new(app_data.clone()));

// ❌ WRONG - Manual dependency injection
let token_provider = Arc::new(TokenProvider::new(/* ... */));
let auth_coordinator = Arc::new(AuthCoordinator::new(
    credential_store,
    token_provider,
    // ... more parameters
));
```

## Implementation Checklist

When creating/updating coordinators:

- [ ] Constructor takes `Arc<AppData>` only
- [ ] Constructor is NOT async
- [ ] Extracts required stores from `app_data.store_name.clone()`
- [ ] Creates providers internally using AppData components
- [ ] Stores providers as `Arc<Provider>` in struct fields
- [ ] Documents which AppData fields are used

## Provider Creation Rules

**Providers MUST be created by coordinators, NOT stored in AppData.**

### Token Provider Creation
```rust
let token_provider = Arc::new(TokenProvider::new(
    app_data.secret_manager.jwt_secret().to_string(),
    app_data.secret_manager.refresh_token_secret().to_string(),
    app_data.audit_store.clone(),
));
```

### Password Validator Provider Creation
```rust
let password_validator_provider = Arc::new(PasswordValidatorProvider::new(
    app_data.common_password_store.clone(),
    app_data.hibp_cache_store.clone(),
));
```

### Audit Logger Provider Creation
```rust
let audit_logger_provider = Arc::new(AuditLoggerProvider::new(
    app_data.audit_store.clone(),
));
```

## What Goes Where

### AppData Contains (Shared Resources)
- Database connections
- Stores (CredentialStore, AuditStore, etc.)
- Configuration (SecretManager)
- Shared utilities

### AppData Does NOT Contain
- Coordinators (created from AppData)
- Providers (created by coordinators)
- Request-specific data

### Coordinators Contain
- Extracted stores from AppData
- Self-created providers
- Business logic orchestration

## Error Patterns to Avoid

### ❌ Wrong: Manual Provider Creation in main.rs
```rust
// DON'T DO THIS
let token_provider = Arc::new(TokenProvider::new(/* ... */));
let auth_coordinator = Arc::new(AuthCoordinator::new(
    app_data.credential_store.clone(),
    token_provider,
));
```

### ❌ Wrong: Storing AppData in Coordinator
```rust
// DON'T DO THIS
pub struct AuthCoordinator {
    app_data: Arc<AppData>,  // Wrong!
}
```

### ❌ Wrong: Async Constructor
```rust
// DON'T DO THIS
impl AuthCoordinator {
    pub async fn new(app_data: Arc<AppData>) -> Self {  // Wrong!
        // ...
    }
}
```

### ❌ Wrong: Multiple Parameters
```rust
// DON'T DO THIS
impl AuthCoordinator {
    pub fn new(
        app_data: Arc<AppData>,
        extra_param: String,  // Wrong!
    ) -> Self {
        // ...
    }
}
```

## Testing Pattern

### Test Setup
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;
    
    async fn create_test_coordinator() -> AuthCoordinator {
        let (db, _audit_db, credential_store, audit_store) = setup_test_stores().await;
        
        // Create minimal AppData for testing
        let app_data = Arc::new(AppData {
            credential_store,
            audit_store,
            secret_manager: Arc::new(MockSecretManager::new()),
            // ... other required fields
        });
        
        AuthCoordinator::new(app_data)
    }
    
    #[tokio::test]
    async fn test_coordinator_functionality() {
        let coordinator = create_test_coordinator().await;
        // Test coordinator methods...
    }
}
```

## Adding New Stores

When adding new stores to AppData:

1. **Add to AppData struct**
2. **Initialize in AppData::init()**
3. **Extract in coordinators that need it**
4. **NO changes to coordinator signatures**

Example:
```rust
// 1. Add to AppData
pub struct AppData {
    // ... existing fields ...
    pub new_store: Arc<NewStore>,
}

// 2. Initialize in AppData::init()
let new_store = Arc::new(NewStore::new(db.clone()));

// 3. Extract in coordinator
impl SomeCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            // ... existing fields ...
            new_store: app_data.new_store.clone(),
        }
    }
}
```

## Validation Commands

Before submitting coordinator code, verify:

```bash
# Check that coordinators follow pattern
grep -r "pub fn new(" src/coordinators/
# Should show: pub fn new(app_data: Arc<AppData>) -> Self

# Check no manual provider creation in main.rs
grep -r "Provider::new" src/main.rs
# Should be empty (providers created in coordinators only)

# Check no async constructors
grep -r "pub async fn new" src/coordinators/
# Should be empty
```

## Summary

**Key Rule: Coordinators take AppData, extract stores, create providers internally.**

This pattern ensures:
- Stable coordinator signatures
- Centralized resource management
- Clear dependency boundaries
- Easy testing and mocking
- No resource duplication
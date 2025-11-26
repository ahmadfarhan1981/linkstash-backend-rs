# AppData Pattern

## Overview

The AppData pattern is a centralized initialization approach where all application dependencies (databases, stores, and stateless services) are created once in `main.rs` and shared across the application. This eliminates duplication, makes dependencies explicit, and provides stable service signatures.

## What is AppData?

`AppData` is a struct that contains all shared application state:

```rust
pub struct AppData {
    // Databases
    pub db: DatabaseConnection,
    pub audit_db: DatabaseConnection,
    
    // Config
    pub secret_manager: Arc<SecretManager>,
    
    // Stores
    pub audit_store: Arc<AuditStore>,
    pub credential_store: Arc<CredentialStore>,
    pub system_config_store: Arc<SystemConfigStore>,
    
    // Stateless Services
    pub token_service: Arc<TokenService>,
}
```

## Architecture

```
main.rs
  ↓
AppData::init()
  ↓ creates once
  ├─ db (DatabaseConnection)
  ├─ audit_db (DatabaseConnection)
  ├─ secret_manager (Arc<SecretManager>)
  ├─ audit_store (Arc<AuditStore>)
  ├─ credential_store (Arc<CredentialStore>)
  ├─ system_config_store (Arc<SystemConfigStore>)
  └─ token_service (Arc<TokenService>)
  ↓ wrapped in Arc<AppData>
  ↓ passed to services
  ├─ AuthService::new(app_data) → extracts what it needs
  └─ AdminService::new(app_data) → extracts what it needs
```

## Benefits

1. **No Duplication**: Single instance of each store shared across all services
2. **Explicit Dependencies**: Services clearly show what they use via struct fields
3. **Stable Signatures**: Adding stores doesn't break existing service constructors
4. **Easy Testing**: Mock AppData for unit tests
5. **Centralized Initialization**: All setup logic in one place

## Usage in main.rs

```rust
#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Load environment and initialize logging
    dotenv::dotenv().ok();
    init_logging().expect("Failed to initialize logging");
    
    // Initialize AppData (databases, stores, stateless services)
    let app_data = Arc::new(
        AppData::init().await
            .expect("Failed to initialize application data")
    );
    
    // CLI mode
    if args.len() > 1 {
        let cli = cli::Cli::parse();
        cli::execute_command(cli, &app_data).await?;
        std::process::exit(0);
    }
    
    // Server mode - Create services
    let auth_service = Arc::new(AuthService::new(app_data.clone()));
    
    // Seed test user in debug mode
    #[cfg(debug_assertions)]
    seed_test_user(&app_data.credential_store).await;
    
    // Create APIs and start server...
}
```

## Creating Services with AppData

### Explicit Extraction Pattern

Services should extract only the dependencies they need from AppData:

```rust
pub struct AuthService {
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_service: Arc<TokenService>,
    audit_store: Arc<AuditStore>,
}

impl AuthService {
    /// Create AuthService from AppData
    /// 
    /// Extracts only the dependencies needed by AuthService.
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            credential_store: app_data.credential_store.clone(),
            system_config_store: app_data.system_config_store.clone(),
            token_service: app_data.token_service.clone(),
            audit_store: app_data.audit_store.clone(),
        }
    }
}
```

**Why extract instead of storing AppData?**

- Makes dependencies explicit and visible in struct fields
- Clear what each service actually uses
- Easier to understand service boundaries
- Better for testing (can mock individual stores)

## Adding New Stores to AppData

When adding a new store:

1. **Add field to AppData struct** (`src/app_data.rs`):
```rust
pub struct AppData {
    // ... existing fields ...
    pub new_store: Arc<NewStore>,
}
```

2. **Initialize in AppData::init()**:
```rust
impl AppData {
    pub async fn init() -> Result<Self, AuthError> {
        // ... existing initialization ...
        
        let new_store = Arc::new(NewStore::new(
            db.clone(),
            audit_store.clone(),
        ));
        
        Ok(Self {
            // ... existing fields ...
            new_store,
        })
    }
}
```

3. **Extract in services that need it**:
```rust
pub fn new(app_data: Arc<AppData>) -> Self {
    Self {
        // ... existing fields ...
        new_store: app_data.new_store.clone(),
    }
}
```

**That's it!** No need to update service signatures or CLI command signatures.

## CLI Command Pattern

CLI commands receive AppData and extract what they need:

```rust
pub async fn execute_command(
    cli: Cli,
    app_data: &AppData,
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Bootstrap => {
            bootstrap::bootstrap_system(
                &app_data.credential_store,
                &app_data.system_config_store,
                &app_data.audit_store,
                &app_data.secret_manager,
            ).await?;
        }
        // ... other commands
    }
    Ok(())
}
```

Individual command handlers extract stores directly:

```rust
pub async fn bootstrap_system(
    credential_store: &CredentialStore,
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
    secret_manager: &SecretManager,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use stores directly
    let owner = credential_store.get_owner().await?;
    // ...
}
```

## What Should Go in AppData?

**DO include:**
- Database connections
- Stores (data access layer)
- Stateless services (like TokenService)
- Configuration managers (like SecretManager)
- Shared resources needed by multiple services

**DON'T include:**
- Stateful services (like AuthService) - these are created from AppData
- API handlers - these depend on services
- Request-specific data
- Temporary or transient state

## Testing with AppData

### Mock AppData for Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_mock_app_data() -> Arc<AppData> {
        let mock_db = create_mock_database();
        let mock_audit_db = create_mock_audit_database();
        let mock_secret_manager = Arc::new(MockSecretManager::new());
        
        let audit_store = Arc::new(AuditStore::new(mock_audit_db.clone()));
        let credential_store = Arc::new(CredentialStore::new(
            mock_db.clone(),
            "test-pepper".to_string(),
            audit_store.clone(),
        ));
        
        Arc::new(AppData {
            db: mock_db,
            audit_db: mock_audit_db,
            secret_manager: mock_secret_manager,
            audit_store,
            credential_store,
            // ... other fields
        })
    }
    
    #[tokio::test]
    async fn test_auth_service_with_mock_data() {
        let app_data = create_mock_app_data();
        let auth_service = AuthService::new(app_data);
        
        // Test auth_service methods...
    }
}
```

### Mock Individual Stores

For more focused tests, mock only the stores you need:

```rust
#[tokio::test]
async fn test_specific_functionality() {
    let mock_credential_store = Arc::new(MockCredentialStore::new());
    let mock_token_service = Arc::new(MockTokenService::new());
    
    let service = AuthService {
        credential_store: mock_credential_store,
        token_service: mock_token_service,
        // ... other fields
    };
    
    // Test specific functionality...
}
```

## Migration from Service-Owned Stores

### Before (Service-Owned)

```rust
// main.rs
let auth_service = AuthService::init(db, audit_db, secret_manager).await?;

// AuthService creates stores internally
impl AuthService {
    pub async fn init(
        db: DatabaseConnection,
        audit_db: DatabaseConnection,
        secret_manager: Arc<SecretManager>,
    ) -> Result<Self, AuthError> {
        let audit_store = Arc::new(AuditStore::new(audit_db));
        let credential_store = Arc::new(CredentialStore::new(db, pepper, audit_store));
        // ...
    }
}
```

**Problem:** Each service creates its own store instances, leading to duplication.

### After (AppData Pattern)

```rust
// main.rs
let app_data = Arc::new(AppData::init().await?);
let auth_service = Arc::new(AuthService::new(app_data.clone()));

// AuthService extracts stores from AppData
impl AuthService {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            credential_store: app_data.credential_store.clone(),
            // ...
        }
    }
}
```

**Solution:** Stores created once, shared by all services.

## Common Patterns

### Accessing Stores in Services

```rust
impl AuthService {
    pub async fn login(&self, ctx: &RequestContext, username: String, password: String) 
        -> Result<(String, String), AuthError> 
    {
        // Use extracted stores directly
        let user_id = self.credential_store
            .verify_credentials(&username, &password, ctx.ip_address.clone())
            .await?;
        
        let (access_token, jwt_id) = self.token_service
            .generate_jwt(&user_id, /* ... */)
            .await?;
        
        // ...
    }
}
```

### Sharing Stores Between Services

```rust
// Both services use the same credential_store instance
let auth_service = Arc::new(AuthService::new(app_data.clone()));
let admin_service = Arc::new(AdminService::new(app_data.clone()));

// They share the same Arc<CredentialStore> from AppData
```

## Best Practices

1. **Initialize in Order**: Databases → Secrets → Stores → Services
2. **Extract Explicitly**: Don't store AppData in services, extract what you need
3. **Document Dependencies**: Service struct fields show what it uses
4. **Keep Constructors Simple**: No async operations, no internal creation
5. **Test with Mocks**: Create mock AppData for unit tests
6. **Add Logging**: Log initialization steps for debugging

## Troubleshooting

### "Cannot find value in scope" errors

Make sure you're extracting the field from AppData:

```rust
// ❌ Wrong
let result = credential_store.get_user().await?;

// ✅ Correct
let result = self.credential_store.get_user().await?;
```

### Service signature changes when adding stores

You shouldn't need to change service signatures. If you do, you're not following the pattern:

```rust
// ❌ Wrong - signature changes when adding stores
pub fn new(
    credential_store: Arc<CredentialStore>,
    new_store: Arc<NewStore>,  // Added parameter!
) -> Self

// ✅ Correct - signature stays stable
pub fn new(app_data: Arc<AppData>) -> Self {
    Self {
        credential_store: app_data.credential_store.clone(),
        new_store: app_data.new_store.clone(),  // Just extract it
    }
}
```

### Circular dependencies

If you have circular dependencies, your architecture needs refactoring. Stores should not depend on services, only other stores.

## See Also

- `src/app_data.rs` - AppData implementation
- `src/main.rs` - AppData usage in main
- `src/services/auth_service.rs` - Example service using AppData
- `src/cli/mod.rs` - CLI usage of AppData

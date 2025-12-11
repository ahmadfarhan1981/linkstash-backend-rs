# AppData Pattern

## Overview

The AppData pattern is a centralized initialization approach where all application dependencies (databases, stores, and providers) are created once in `main.rs` and shared across the application. This eliminates duplication, makes dependencies explicit, and provides stable coordinator signatures.

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
  ├─ common_password_store (Arc<CommonPasswordStore>)
  └─ hibp_cache_store (Arc<HibpCacheStore>)
  ↓ wrapped in Arc<AppData>
  ↓ passed to coordinators
  ├─ AuthCoordinator::new(app_data) → creates providers internally
  └─ AdminCoordinator::new(app_data) → creates providers internally
  ↓ coordinators create providers from AppData
  ├─ TokenProvider::new(secrets, audit_store)
  ├─ PasswordValidatorProvider::new(stores)
  └─ AuditLoggerProvider::new(audit_store)
```

## Benefits

1. **No Duplication**: Single instance of each store shared across all coordinators
2. **Explicit Dependencies**: Coordinators clearly show what they use via struct fields
3. **Stable Signatures**: Adding stores doesn't break existing coordinator constructors
4. **Easy Testing**: Mock AppData for unit tests
5. **Centralized Initialization**: All setup logic in one place
6. **Provider Encapsulation**: Coordinators create and manage their own providers internally

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
    
    // Server mode - Create coordinators
    let auth_coordinator = Arc::new(AuthCoordinator::new(app_data.clone()));
    let admin_coordinator = Arc::new(AdminCoordinator::new(app_data.clone()));
    
    // Seed test user in debug mode
    #[cfg(debug_assertions)]
    seed_test_user(&app_data.credential_store).await;
    
    // Create APIs and start server...
}
```

## Creating Coordinators with AppData

### Explicit Extraction Pattern

Coordinators should extract only the dependencies they need from AppData and create their own providers internally:

```rust
pub struct AuthCoordinator {
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_provider: Arc<TokenProvider>,
    password_validator_provider: Arc<PasswordValidatorProvider>,
    audit_logger_provider: Arc<AuditLoggerProvider>,
}

impl AuthCoordinator {
    /// Create AuthCoordinator from AppData
    /// 
    /// Extracts stores from AppData and creates providers internally.
    pub fn new(app_data: Arc<AppData>) -> Self {
        // Create providers from AppData components
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

**Why extract stores and create providers internally?**

- Makes store dependencies explicit and visible in struct fields
- Encapsulates provider creation within coordinators
- Clear what each coordinator actually uses from AppData
- Easier to understand coordinator boundaries
- Better for testing (can mock individual stores or entire AppData)

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

3. **Extract in coordinators that need it**:
```rust
pub fn new(app_data: Arc<AppData>) -> Self {
    // ... create providers ...
    
    Self {
        // ... existing fields ...
        new_store: app_data.new_store.clone(),
        // ... providers ...
    }
}
```

**That's it!** No need to update coordinator signatures or CLI command signatures.

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
- Configuration managers (like SecretManager)
- Shared resources needed by multiple coordinators

**DON'T include:**
- Coordinators - these are created from AppData
- Providers - these are created by coordinators from AppData components
- API handlers - these depend on coordinators
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
    async fn test_auth_coordinator_with_mock_data() {
        let app_data = create_mock_app_data();
        let auth_coordinator = AuthCoordinator::new(app_data);
        
        // Test auth_coordinator methods...
    }
}
```

### Mock Individual Stores

For more focused tests, mock only the stores you need:

```rust
#[tokio::test]
async fn test_specific_functionality() {
    let mock_credential_store = Arc::new(MockCredentialStore::new());
    let mock_audit_store = Arc::new(MockAuditStore::new());
    
    // Create minimal AppData with only what's needed
    let app_data = Arc::new(AppData {
        credential_store: mock_credential_store,
        audit_store: mock_audit_store,
        // ... other required fields with mocks
    });
    
    let coordinator = AuthCoordinator::new(app_data);
    
    // Test specific functionality...
}
```

## AppData Pattern Benefits

### Centralized Initialization

```rust
// main.rs
let app_data = Arc::new(AppData::init().await?);
let auth_coordinator = Arc::new(AuthCoordinator::new(app_data.clone()));
let admin_coordinator = Arc::new(AdminCoordinator::new(app_data.clone()));

// Coordinators extract stores from AppData and create providers internally
impl AuthCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self {
        // Create providers from AppData components
        let token_provider = Arc::new(TokenProvider::new(
            app_data.secret_manager.jwt_secret().to_string(),
            app_data.secret_manager.refresh_token_secret().to_string(),
            app_data.audit_store.clone(),
        ));
        
        Self {
            credential_store: app_data.credential_store.clone(),
            token_provider,
            // ...
        }
    }
}
```

**Benefits:** 
- Stores created once, shared by all coordinators
- Providers created by coordinators from shared AppData components
- Clean separation between shared resources (stores) and coordinator-specific resources (providers)

## Common Patterns

### Accessing Stores and Providers in Coordinators

```rust
impl AuthCoordinator {
    pub async fn login(&self, ctx: &RequestContext, username: String, password: String) 
        -> Result<(String, String), InternalError> 
    {
        // Use extracted stores directly
        let user_id_str = self.credential_store
            .verify_credentials(ctx, &username, &password)
            .await?;
        
        // Use coordinator-owned providers
        let (access_token, jwt_id) = self.token_provider
            .generate_jwt(ctx, &user_id, /* ... */)
            .await?;
        
        // ...
    }
}
```

### Sharing Stores Between Coordinators

```rust
// Both coordinators use the same credential_store instance from AppData
let auth_coordinator = Arc::new(AuthCoordinator::new(app_data.clone()));
let admin_coordinator = Arc::new(AdminCoordinator::new(app_data.clone()));

// They share the same Arc<CredentialStore> from AppData
// But each creates their own providers internally
```

## Best Practices

1. **Initialize in Order**: Databases → Secrets → Stores → Coordinators
2. **Extract Explicitly**: Don't store AppData in coordinators, extract stores and create providers
3. **Document Dependencies**: Coordinator struct fields show what stores they use
4. **Keep Constructors Simple**: No async operations in coordinator constructors
5. **Test with Mocks**: Create mock AppData for unit tests
6. **Add Logging**: Log initialization steps for debugging
7. **Provider Encapsulation**: Let coordinators create and manage their own providers

## Troubleshooting

### "Cannot find value in scope" errors

Make sure you're extracting the field from AppData:

```rust
// ❌ Wrong
let result = credential_store.get_user().await?;

// ✅ Correct
let result = self.credential_store.get_user().await?;
```

### Coordinator signature changes when adding stores

You shouldn't need to change coordinator signatures. If you do, you're not following the pattern:

```rust
// ❌ Wrong - signature changes when adding stores
pub fn new(
    credential_store: Arc<CredentialStore>,
    new_store: Arc<NewStore>,  // Added parameter!
) -> Self

// ✅ Correct - signature stays stable
pub fn new(app_data: Arc<AppData>) -> Self {
    // Create providers from AppData
    let token_provider = Arc::new(TokenProvider::new(/* ... */));
    
    Self {
        credential_store: app_data.credential_store.clone(),
        new_store: app_data.new_store.clone(),  // Just extract it
        token_provider,
    }
}
```

### Circular dependencies

If you have circular dependencies, your architecture needs refactoring. The dependency flow should be:
- Stores should not depend on coordinators or providers, only other stores
- Providers should not depend on coordinators, only stores and other providers
- Coordinators can depend on stores and create providers

## See Also

- `src/app_data.rs` - AppData implementation
- `src/main.rs` - AppData usage in main
- `src/coordinators/auth_coordinator.rs` - Example coordinator using AppData
- `src/cli/mod.rs` - CLI usage of AppData

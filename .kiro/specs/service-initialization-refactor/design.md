# Service Initialization Refactor - Design

## Overview

This refactor changes from service-owned stores (where each service creates its own store instances) to main-owned stores (where main.rs creates stores once and passes them to services). This follows Rust ecosystem conventions and eliminates duplication.

## Architecture Changes

### Before (Service-Owned)

```
main.rs
  ↓
AuthService::init(db, audit_db, secret_manager)
  ↓ creates internally
  ├─ AuditStore::new(audit_db)
  ├─ CredentialStore::new(db, pepper, audit_store)
  ├─ TokenService::new(jwt_secret, refresh_secret, audit_store)
  └─ SystemConfigStore::new(db, audit_store)  [will be added]
```

**Problem:** When we add AdminService, it would create duplicate instances of all stores.

### After (AppData Pattern)

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

**Benefits:**
- Single instance of each store
- Centralized initialization
- Stable service signatures
- Easy to add new stores

## Component Changes

### 1. AppData Struct (NEW)

```rust
// src/app_data.rs
use std::sync::Arc;
use sea_orm::DatabaseConnection;
use crate::config::SecretManager;
use crate::stores::{AuditStore, CredentialStore, SystemConfigStore};
use crate::services::TokenService;
use crate::errors::auth::AuthError;

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

impl AppData {
    /// Initialize all application data
    /// 
    /// Creates databases, stores, and stateless services in correct order.
    pub async fn init() -> Result<Self, AuthError> {
        // 1. Initialize databases
        let db = crate::config::init_database().await
            .map_err(|e| AuthError::internal_error(format!("Database init failed: {}", e)))?;
        let audit_db = crate::config::init_audit_database().await
            .map_err(|e| AuthError::internal_error(format!("Audit DB init failed: {}", e)))?;
        
        // 2. Initialize secrets
        let secret_manager = Arc::new(SecretManager::init()
            .map_err(|e| AuthError::internal_error(format!("Secret manager init failed: {}", e)))?);
        
        // 3. Create stores
        let audit_store = Arc::new(AuditStore::new(audit_db.clone()));
        
        let credential_store = Arc::new(CredentialStore::new(
            db.clone(),
            secret_manager.password_pepper().to_string(),
            audit_store.clone(),
        ));
        
        let system_config_store = Arc::new(SystemConfigStore::new(
            db.clone(),
            audit_store.clone(),
        ));
        
        // 4. Create stateless services
        let token_service = Arc::new(TokenService::new(
            secret_manager.jwt_secret().to_string(),
            secret_manager.refresh_token_secret().to_string(),
            audit_store.clone(),
        ));
        
        Ok(Self {
            db,
            audit_db,
            secret_manager,
            audit_store,
            credential_store,
            system_config_store,
            token_service,
        })
    }
}
```

### 2. AuthService

**Before:**
```rust
impl AuthService {
    pub async fn init(
        db: sea_orm::DatabaseConnection,
        audit_db: sea_orm::DatabaseConnection,
        secret_manager: Arc<SecretManager>,
    ) -> Result<Self, AuthError> {
        // Creates stores internally
        let audit_store = Arc::new(AuditStore::new(audit_db));
        let credential_store = Arc::new(CredentialStore::new(...));
        let token_service = Arc::new(TokenService::new(...));
        
        let service = Self { credential_store, token_service, audit_store };
        service.seed_test_user().await;
        Ok(service)
    }
}
```

**After:**
```rust
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

**Changes:**
- Remove `init()` method
- Add `new()` constructor accepting `Arc<AppData>`
- Extract only needed dependencies from AppData
- Store extracted dependencies, not AppData itself
- Remove internal store creation
- Remove test user seeding (moved to main.rs)
- Add `system_config_store` field (needed for owner_active check)

### 3. main.rs Structure

**New Initialization Order:**

```rust
#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // 1. Environment and logging
    dotenv::dotenv().ok();
    init_logging().expect("Failed to initialize logging");
    
    // 2. Initialize AppData (databases, stores, stateless services)
    let app_data = Arc::new(
        AppData::init().await
            .expect("Failed to initialize application data")
    );
    
    // 3. Check if CLI mode
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let cli = cli::Cli::parse();
        cli::execute_command(cli, &app_data).await
            .map_err(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            })?;
        std::process::exit(0);
    }
    
    // 4. Server mode - Create services
    let auth_service = Arc::new(AuthService::new(app_data.clone()));
    
    // 5. Seed test user (debug mode only)
    #[cfg(debug_assertions)]
    seed_test_user(&app_data.credential_store).await;
    
    // 6. Create APIs
    let auth_api = AuthApi::new(auth_service);
    
    // 7. Create OpenAPI service
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);
    let server_url = format!("http://localhost:{}/api", port);
    
    let api_service = OpenApiService::new(
        (HealthApi, auth_api),
        "Linkstash API",
        "1.0"
    ).server(server_url);
    
    // 8. Start server
    let app = Route::new()
        .at("/", poem::get(index))
        .nest("/api", api_service)
        .nest("/swagger", api_service.swagger_ui());
    
    tracing::info!("Starting server on http://{}", bind_address);
    tracing::info!("Swagger UI available at http://localhost:{}/swagger", port);
    
    Server::new(TcpListener::bind(&bind_address))
        .run(app)
        .await
}
```

**Key Changes:**
- Single `AppData::init()` call replaces all individual store creation
- AppData shared by both CLI and server mode
- Clean, minimal main.rs
- Easy to add new stores (just update AppData)

### 4. Test User Seeding

**Extract to standalone function:**

```rust
// In main.rs or a helper module
#[cfg(debug_assertions)]
async fn seed_test_user(credential_store: &CredentialStore) {
    match credential_store.add_user("testuser".to_string(), "testpass".to_string()).await {
        Ok(user_id) => {
            tracing::info!("Test user created successfully with ID: {}", user_id);
        }
        Err(AuthError::DuplicateUsername(_)) => {
            tracing::debug!("Test user already exists, skipping creation");
        }
        Err(e) => {
            tracing::error!("Failed to create test user: {:?}", e);
        }
    }
}
```

### 5. CLI Command Handler Updates

**Before:**
```rust
pub async fn execute_command(
    cli: Cli,
    db: &DatabaseConnection,
    audit_db: &DatabaseConnection,
    secret_manager: &SecretManager,
) -> Result<(), String>
```

**After:**
```rust
pub async fn execute_command(
    cli: Cli,
    app_data: &AppData,
) -> Result<(), String> {
    match cli.command {
        Commands::Bootstrap { .. } => {
            bootstrap::execute(
                &app_data.credential_store,
                &app_data.system_config_store,
            ).await
        }
        Commands::Owner { command } => {
            match command {
                OwnerCommands::Activate => {
                    owner::activate(&app_data.system_config_store).await
                }
                // ... other commands access what they need from app_data
            }
        }
    }
}
```

**Changes:**
- Accept single `app_data` parameter instead of multiple parameters
- CLI commands extract what they need from AppData
- Adding new stores doesn't require signature changes

## Benefits

### 1. No Store Duplication
- Single AuditStore instance shared by all services
- Single CredentialStore instance shared by all services
- Single SystemConfigStore instance shared by all services
- Single TokenService instance shared by all services

### 2. Explicit Dependencies
```rust
// Clear what AuthService needs
pub fn new(
    credential_store: Arc<CredentialStore>,
    system_config_store: Arc<SystemConfigStore>,
    token_service: Arc<TokenService>,
    audit_store: Arc<AuditStore>,
) -> Self
```

### 3. Easy Testing
```rust
// In tests, create mock stores
let mock_credential_store = Arc::new(MockCredentialStore::new());
let mock_token_service = Arc::new(MockTokenService::new());

let service = AuthService::new(
    mock_credential_store,
    mock_system_config_store,
    mock_token_service,
    mock_audit_store,
);
```

### 4. Visible Dependency Graph
```rust
// In main.rs, you can SEE:
// 1. Stores depend on: databases + secrets
// 2. Services depend on: stores
// 3. APIs depend on: services
```

### 5. Prepares for AdminService
```rust
// Easy to add AdminService with same stores
let admin_service = Arc::new(AdminService::new(
    credential_store.clone(),  // Same instance as AuthService
    system_config_store.clone(),
    token_service.clone(),
    audit_store.clone(),
));
```

## Migration Strategy

### Phase 1: Update AuthService
1. Remove `init()` method
2. Add `new()` constructor with all dependencies
3. Add `system_config_store` field
4. Remove `seed_test_user()` method

### Phase 2: Update main.rs
1. Create all stores in main.rs
2. Create AuthService with `new()` instead of `init()`
3. Add test user seeding after service creation
4. Update CLI mode to create stores and pass to commands

### Phase 3: Update CLI
1. Update `execute_command()` signature
2. Update all CLI command handlers to use stores directly
3. Remove service creation from CLI commands

### Phase 4: Verify
1. Run all tests
2. Verify server starts
3. Verify CLI commands work
4. Verify API endpoints work

## Testing Strategy

### Unit Tests
- AuthService can be instantiated with mock stores
- Test user seeding function works correctly

### Integration Tests
- Server starts successfully with new initialization
- CLI commands work with new initialization
- API endpoints continue to function
- All existing tests pass without modification

## No Breaking Changes

### API Layer
- AuthApi receives AuthService via constructor (unchanged)
- API endpoints use AuthService methods (unchanged)
- No changes needed to API code

### Store Layer
- Stores remain unchanged
- Store interfaces remain unchanged

### Service Layer
- AuthService public methods remain unchanged
- Only constructor changes (internal detail)

## Compatibility

### Debug vs Release
```rust
#[cfg(debug_assertions)]
seed_test_user(&credential_store).await;
```
- Debug builds seed test user
- Release builds skip test user seeding

### CLI vs Server
- Both modes create stores the same way
- CLI mode creates only needed stores
- Server mode creates all stores

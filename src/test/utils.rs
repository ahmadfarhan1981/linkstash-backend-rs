// Test utilities shared across unit and integration tests
// Only compiled when running tests

use sea_orm::{Database, DatabaseConnection};
use migration::{AuthMigrator, AuditMigrator, MigratorTrait};
use crate::{providers::{TokenProvider, PasswordValidatorProvider}, stores::{AuditStore, CredentialStore, SystemConfigStore}, app_data::AppData, coordinators::AuthCoordinator};
use std::sync::{Arc, Mutex};

/// Creates a test password validator with in-memory stores
/// 
/// Returns a PasswordValidator configured with empty common password and HIBP cache stores.
/// Useful for tests that need password validation but don't need full auth services.
pub async fn setup_test_password_validator() -> Arc<PasswordValidatorProvider> {
    // Create in-memory database for stores
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");
    
    AuthMigrator::up(&db, None)
        .await
        .expect("Failed to run auth migrations");
    
    // Create audit database (required for system_config_store)
    let audit_db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create audit database");
    
    AuditMigrator::up(&audit_db, None)
        .await
        .expect("Failed to run audit migrations");
    
    let audit_store = Arc::new(AuditStore::new(audit_db.clone()));
    
    // Create stores needed for password validator
    let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(db.clone()));
    let system_config_store = Arc::new(SystemConfigStore::new(db.clone(), audit_store));
    let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(
        db.clone(),
        system_config_store,
    ));
    
    Arc::new(PasswordValidatorProvider::new(
        common_password_store,
        hibp_cache_store,
    ))
}

/// Creates test databases and stores with standard configuration
/// 
/// Returns (auth_db, audit_db, credential_store, audit_store)
/// 
/// Callers can discard what they don't need:
/// ```rust
/// let (db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
/// let (_db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
/// ```
pub async fn setup_test_stores() -> (
    DatabaseConnection,
    DatabaseConnection,
    Arc<CredentialStore>,
    Arc<AuditStore>,
) {
    // Create auth database
    let auth_db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");
    
    AuthMigrator::up(&auth_db, None)
        .await
        .expect("Failed to run auth migrations");
    
    // Create audit database
    let audit_db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create audit database");
    
    AuditMigrator::up(&audit_db, None)
        .await
        .expect("Failed to run audit migrations");
    
    // Create stores
    let audit_store = Arc::new(AuditStore::new(audit_db.clone()));
    let password_pepper = "test-pepper-for-unit-tests".to_string();
    let credential_store = Arc::new(CredentialStore::new(
        auth_db.clone(),
        password_pepper,
        audit_store.clone(),
    ));
    
    (auth_db, audit_db, credential_store, audit_store)
}

/// Creates a full auth test setup with token provider configured
/// 
/// Returns (auth_db, audit_db, credential_store, audit_store, token_provider)
/// with a test user "testuser"/"TestSecure-Pass-12345-UUID" already created.
/// 
/// Callers can discard what they don't need:
/// ```rust
/// let (_db, _audit_db, _cred, _audit, token_provider) = setup_test_auth_services().await;
/// ```
pub async fn setup_test_auth_services() -> (
    DatabaseConnection,
    DatabaseConnection,
    Arc<CredentialStore>,
    Arc<AuditStore>,
    Arc<TokenProvider>,
) {
    let (auth_db, audit_db, credential_store, audit_store) = setup_test_stores().await;
    
    // Create mock SecretManager for testing
    // Set environment variables temporarily for SecretManager::init()
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
        std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
        std::env::set_var("REFRESH_TOKEN_SECRET", "test-refresh-secret-minimum-32-chars");
    }
    
    let secret_manager = Arc::new(crate::config::SecretManager::init()
        .expect("Failed to initialize test SecretManager"));
    
    // Create token provider with SecretManager
    let token_provider = Arc::new(TokenProvider::new(
        secret_manager,
        audit_store.clone(),
    ));
    
    // Create system_config_store for AppData
    let system_config_store = Arc::new(SystemConfigStore::new(
        auth_db.clone(),
        audit_store.clone(),
    ));
    
    // Create mock SecretManager for testing
    // Set environment variables temporarily for SecretManager::init()
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
        std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
        std::env::set_var("REFRESH_TOKEN_SECRET", "test-refresh-secret-minimum-32-chars");
    }
    
    let secret_manager = Arc::new(crate::config::SecretManager::init()
        .expect("Failed to initialize test SecretManager"));
    
    // Create common password store
    let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(auth_db.clone()));
    
    // Create HIBP cache store
    let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(
        auth_db.clone(),
        system_config_store.clone(),
    ));
    
    // Create password validator
    let _password_validator = Arc::new(PasswordValidatorProvider::new(
        common_password_store.clone(),
        hibp_cache_store.clone(),
    ));
    
    // Create mock AppData for testing
    let _app_data = Arc::new(AppData {
        db: auth_db.clone(),
        audit_db: audit_db.clone(),
        env_provider: Arc::new(crate::config::SystemEnvironment),
        secret_manager,
        audit_store: audit_store.clone(),
        credential_store: credential_store.clone(),
        system_config_store,
        common_password_store,
        hibp_cache_store,
    });
    
    // Add test user (using password validator)
    // Password must be at least 15 characters and not in HIBP database
    // Using a UUID-based password to ensure it's unique and secure
    let password_validator = setup_test_password_validator().await;
    credential_store
        .add_user(&password_validator, "testuser".to_string(), "TestSecure-Pass-12345-UUID".to_string())
        .await
        .expect("Failed to create test user");
    
    (auth_db, audit_db, credential_store, audit_store, token_provider)
}

/// Creates a full coordinator test setup with all coordinators configured using AppData pattern
/// 
/// Returns (auth_db, audit_db, credential_store, audit_store, auth_coordinator, app_data)
/// with a test user "testuser"/"TestSecure-Pass-12345-UUID" already created.
/// 
/// This is the coordinator equivalent of setup_test_auth_services().
pub async fn setup_test_coordinators() -> (
    DatabaseConnection,
    DatabaseConnection,
    Arc<CredentialStore>,
    Arc<AuditStore>,
    Arc<AuthCoordinator>,
    Arc<AppData>,
) {
    let (auth_db, audit_db, credential_store, audit_store) = setup_test_stores().await;
    
    // Set environment variables temporarily for SecretManager::init()
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
        std::env::set_var("PASSWORD_PEPPER", "test-pepper-for-unit-tests");
        std::env::set_var("REFRESH_TOKEN_SECRET", "test-refresh-secret-minimum-32-chars");
    }
    
    let secret_manager = Arc::new(crate::config::SecretManager::init()
        .expect("Failed to initialize test SecretManager"));
    
    let system_config_store = Arc::new(SystemConfigStore::new(auth_db.clone(), audit_store.clone()));
    let common_password_store = Arc::new(crate::stores::CommonPasswordStore::new(auth_db.clone()));
    let hibp_cache_store = Arc::new(crate::stores::HibpCacheStore::new(
        auth_db.clone(),
        system_config_store.clone(),
    ));
    
    // Create AppData for testing
    let app_data = Arc::new(AppData {
        db: auth_db.clone(),
        audit_db: audit_db.clone(),
        env_provider: Arc::new(crate::config::SystemEnvironment),
        secret_manager,
        audit_store: audit_store.clone(),
        credential_store: credential_store.clone(),
        system_config_store,
        common_password_store,
        hibp_cache_store,
    });
    
    // Create coordinator using AppData pattern
    let auth_coordinator = Arc::new(AuthCoordinator::new(app_data.clone()));
    
    // Add test user (using password validator)
    // Password must be at least 15 characters and not in HIBP database
    // Using a UUID-based password to ensure it's unique and secure
    let password_validator = setup_test_password_validator().await;
    credential_store
        .add_user(&password_validator, "testuser".to_string(), "TestSecure-Pass-12345-UUID".to_string())
        .await
        .expect("Failed to create test user");
    
    (auth_db, audit_db, credential_store, audit_store, auth_coordinator, app_data)
}

/// Helper to manage environment variables in tests
/// 
/// Cleans up specified environment variables on creation and drop,
/// ensuring test isolation when dealing with global environment state.
pub struct EnvGuard {
    vars: Vec<String>,
}

impl EnvGuard {
    pub fn new(vars: Vec<&str>) -> Self {
        // Clean up before setting new values
        for var in &vars {
            unsafe {
                std::env::remove_var(var);
            }
        }
        Self {
            vars: vars.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for var in &self.vars {
            unsafe {
                std::env::remove_var(var);
            }
        }
    }
}

/// Global mutex for tests that modify environment variables
/// 
/// Environment variables are process-global, so tests that modify them
/// must run serially to avoid race conditions.
pub static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

// Test utilities shared across unit and integration tests
// Only compiled when running tests

use sea_orm::{Database, DatabaseConnection};
use migration::{AuthMigrator, AuditMigrator, MigratorTrait};
use crate::{services::{AuthService, TokenService, PasswordValidator}, stores::{AuditStore, CredentialStore, SystemConfigStore}, app_data::AppData};
use std::sync::{Arc, Mutex};

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

/// Creates a full auth test setup with all services configured
/// 
/// Returns (auth_db, audit_db, credential_store, audit_store, auth_service, token_service)
/// with a test user "testuser"/"testpass" already created.
/// 
/// Callers can discard what they don't need:
/// ```rust
/// let (_db, _audit_db, _cred, _audit, auth_service, token_service) = setup_test_auth_services().await;
/// ```
pub async fn setup_test_auth_services() -> (
    DatabaseConnection,
    DatabaseConnection,
    Arc<CredentialStore>,
    Arc<AuditStore>,
    Arc<AuthService>,
    Arc<TokenService>,
) {
    let (auth_db, audit_db, credential_store, audit_store) = setup_test_stores().await;
    
    // Create token service with test secrets
    let token_service = Arc::new(TokenService::new(
        "test-secret-key-minimum-32-characters-long".to_string(),
        "test-refresh-secret-minimum-32-chars".to_string(),
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
    
    // Create password validator
    let password_validator = Arc::new(PasswordValidator::new(common_password_store.clone()));
    
    // Create mock AppData for testing
    let app_data = Arc::new(AppData {
        db: auth_db.clone(),
        audit_db: audit_db.clone(),
        secret_manager,
        audit_store: audit_store.clone(),
        credential_store: credential_store.clone(),
        system_config_store,
        common_password_store,
        token_service: token_service.clone(),
        password_validator,
    });
    
    // Create auth service using AppData
    let auth_service = Arc::new(AuthService::new(app_data));
    
    // Add test user
    credential_store
        .add_user("testuser".to_string(), "testpass".to_string())
        .await
        .expect("Failed to create test user");
    
    (auth_db, audit_db, credential_store, audit_store, auth_service, token_service)
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

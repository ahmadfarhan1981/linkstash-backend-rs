// Common test utilities for integration tests

use sea_orm::{Database, DatabaseConnection};
use migration::{AuthMigrator, AuditMigrator, MigratorTrait};
use linkstash_backend::stores::AuditStore;
use std::sync::{Arc, Mutex};

/// Creates a test auth database with migrations applied
pub async fn setup_test_auth_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");
    
    AuthMigrator::up(&db, None)
        .await
        .expect("Failed to run auth migrations");
    
    db
}

/// Creates a test audit database with migrations applied
pub async fn setup_test_audit_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create audit database");
    
    AuditMigrator::up(&db, None)
        .await
        .expect("Failed to run audit migrations");
    
    db
}

/// Creates a test audit store
pub async fn create_test_audit_store() -> Arc<AuditStore> {
    let audit_db = setup_test_audit_db().await;
    Arc::new(AuditStore::new(audit_db))
}

/// Creates both test databases
pub async fn setup_test_databases() -> (DatabaseConnection, DatabaseConnection) {
    let auth_db = setup_test_auth_db().await;
    let audit_db = setup_test_audit_db().await;
    (auth_db, audit_db)
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

use linkstash_backend::stores::{SystemConfigStore, AuditStore};
use sea_orm::{Database, DatabaseConnection};
use migration::{Migrator, MigratorTrait};
use std::sync::Arc;

async fn setup_test_db() -> (DatabaseConnection, SystemConfigStore) {
    // Create in-memory SQLite database for testing
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");
    
    // Run migrations
    Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations");
    
    // Create in-memory audit database for testing
    let audit_db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to create audit database");
    
    // Run audit migrations
    Migrator::up(&audit_db, None)
        .await
        .expect("Failed to run audit migrations");
    
    // Create system config store with audit store
    let audit_store = Arc::new(AuditStore::new(audit_db));
    let system_config_store = SystemConfigStore::new(db.clone(), audit_store);
    
    (db, system_config_store)
}

#[tokio::test]
async fn test_get_config_creates_singleton_if_not_exists() {
    let (_db, store) = setup_test_db().await;
    
    // First call should create the config
    let config = store.get_config().await;
    assert!(config.is_ok());
    
    let config = config.unwrap();
    assert_eq!(config.id, 1);
    assert_eq!(config.owner_active, false); // Default value
}

#[tokio::test]
async fn test_is_owner_active_returns_false_by_default() {
    let (_db, store) = setup_test_db().await;
    
    let is_active = store.is_owner_active().await;
    assert!(is_active.is_ok());
    assert_eq!(is_active.unwrap(), false);
}

#[tokio::test]
async fn test_set_owner_active_updates_flag() {
    let (_db, store) = setup_test_db().await;
    
    // Initially false
    let is_active = store.is_owner_active().await.unwrap();
    assert_eq!(is_active, false);
    
    // Set to true
    let result = store.set_owner_active(true, Some("test-user".to_string()), Some("127.0.0.1".to_string())).await;
    assert!(result.is_ok());
    
    // Verify it's now true
    let is_active = store.is_owner_active().await.unwrap();
    assert_eq!(is_active, true);
    
    // Set back to false
    let result = store.set_owner_active(false, Some("test-user".to_string()), Some("127.0.0.1".to_string())).await;
    assert!(result.is_ok());
    
    // Verify it's now false
    let is_active = store.is_owner_active().await.unwrap();
    assert_eq!(is_active, false);
}

#[tokio::test]
async fn test_set_owner_active_updates_timestamp() {
    let (_db, store) = setup_test_db().await;
    
    // Get initial config
    let config1 = store.get_config().await.unwrap();
    let timestamp1 = config1.updated_at;
    
    // Wait a moment to ensure timestamp changes
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    
    // Update owner_active
    store.set_owner_active(true, Some("test-user".to_string()), Some("127.0.0.1".to_string())).await.unwrap();
    
    // Get updated config
    let config2 = store.get_config().await.unwrap();
    let timestamp2 = config2.updated_at;
    
    // Timestamp should have changed
    assert!(timestamp2 > timestamp1);
}

#[tokio::test]
async fn test_multiple_calls_to_ensure_config_exists_are_idempotent() {
    let (_db, store) = setup_test_db().await;
    
    // Call get_config multiple times
    let config1 = store.get_config().await.unwrap();
    let config2 = store.get_config().await.unwrap();
    let config3 = store.get_config().await.unwrap();
    
    // All should return the same singleton row
    assert_eq!(config1.id, 1);
    assert_eq!(config2.id, 1);
    assert_eq!(config3.id, 1);
}

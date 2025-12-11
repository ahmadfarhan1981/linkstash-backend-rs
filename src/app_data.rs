use std::sync::Arc;
use sea_orm::DatabaseConnection;
use crate::config::SecretManager;
use crate::stores::{AuditStore, CredentialStore, SystemConfigStore, CommonPasswordStore, HibpCacheStore};
use crate::errors::InternalError;

/// Centralized application data containing all databases, stores, and configuration
/// 
/// AppData follows the main-owned stores pattern where all dependencies are created once
/// in main.rs and shared across coordinators. This eliminates store duplication and makes
/// dependencies explicit.
/// 
/// # Architecture
/// 
/// ```text
/// main.rs
///   ↓
/// AppData::init()
///   ↓ creates once
///   ├─ db (DatabaseConnection)
///   ├─ audit_db (DatabaseConnection)
///   ├─ secret_manager (Arc<SecretManager>)
///   ├─ audit_store (Arc<AuditStore>)
///   ├─ credential_store (Arc<CredentialStore>)
///   ├─ system_config_store (Arc<SystemConfigStore>)
///   ├─ common_password_store (Arc<CommonPasswordStore>)
///   └─ hibp_cache_store (Arc<HibpCacheStore>)
///   ↓ wrapped in Arc<AppData>
///   ↓ passed to coordinators
///   ├─ AuthCoordinator::new(app_data) → extracts stores, creates providers
///   └─ AdminCoordinator::new(app_data) → extracts stores, creates providers
/// ```
/// 
/// # Benefits
/// 
/// - Single instance of each store (no duplication)
/// - Centralized initialization
/// - Stable coordinator signatures (adding stores doesn't break coordinators)
/// - Easy to test (mock AppData for testing)
pub struct AppData {
    /// Main database connection (auth.db)
    pub db: DatabaseConnection,
    
    /// Audit database connection (audit.db)
    pub audit_db: DatabaseConnection,
    
    /// Secret manager for accessing JWT secrets, password pepper, etc.
    pub secret_manager: Arc<SecretManager>,
    
    /// Audit store for security event logging
    pub audit_store: Arc<AuditStore>,
    
    /// Credential store for user authentication
    pub credential_store: Arc<CredentialStore>,
    
    /// System configuration store for owner status and system settings
    pub system_config_store: Arc<SystemConfigStore>,
    
    /// Common password store for checking against common password list
    pub common_password_store: Arc<CommonPasswordStore>,
    
    /// HIBP cache store for caching HaveIBeenPwned API responses
    pub hibp_cache_store: Arc<HibpCacheStore>,
}

impl AppData {
    /// Initialize all application data
    /// 
    /// Creates stores using the provided database connections.
    /// Database connections should be initialized and migrated before calling this.
    /// 
    /// # Arguments
    /// 
    /// * `db` - Main database connection (auth.db) - should already be migrated
    /// * `audit_db` - Audit database connection (audit.db) - should already be migrated
    /// 
    /// # Initialization Order
    /// 
    /// 1. Initialize secret manager (loads JWT secrets, password pepper, etc.)
    /// 2. Create stores (audit, credential, system_config, common_password, hibp_cache)
    /// 
    /// # Returns
    /// 
    /// * `Ok(AppData)` - Fully initialized application data
    /// * `Err(InternalError)` - Secret manager initialization failed
    /// 
    /// # Errors
    /// 
    /// Returns `InternalError` when:
    /// - Secret manager initialization fails (missing or invalid environment variables)
    pub async fn init(db: DatabaseConnection, audit_db: DatabaseConnection) -> Result<Self, InternalError> {
        tracing::info!("Initializing AppData...");
        
        // 1. Initialize secrets
        tracing::debug!("Initializing secret manager...");
        let secret_manager = Arc::new(SecretManager::init()
            .map_err(|e| InternalError::parse("secret_manager", format!("Secret manager init failed: {}", e)))?);
        tracing::debug!("Secret manager initialized");
        
        // 2. Create stores (order matters: audit_store first, then others that depend on it)
        tracing::debug!("Creating stores...");
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
        
        let common_password_store = Arc::new(CommonPasswordStore::new(db.clone()));
        
        let hibp_cache_store = Arc::new(HibpCacheStore::new(
            db.clone(),
            system_config_store.clone(),
        ));
        
        tracing::debug!("Stores created");
        
        tracing::info!("AppData initialization complete");
        
        Ok(Self {
            db,
            audit_db,
            secret_manager,
            audit_store,
            credential_store,
            system_config_store,
            common_password_store,
            hibp_cache_store,
        })
    }
}

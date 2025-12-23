use std::sync::Arc;
use sea_orm::DatabaseConnection;
use crate::config::{EnvironmentProvider, SecretManager, SystemEnvironment};
use crate::config::database::DatabaseConnections;
use crate::stores::{AuditStore, CredentialStore, SystemConfigStore, CommonPasswordStore, HibpCacheStore};
use crate::errors::InternalError;
use crate::providers::AuditLogger;

/// Centralized application data following the main-owned stores pattern
/// 
/// All dependencies are created once in main.rs and shared across coordinators.
/// This eliminates store duplication and provides stable coordinator signatures.
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
pub struct AppData {
    pub connections: DatabaseConnections,
    pub audit_logger: AuditLogger,
    pub env_provider: Arc<dyn EnvironmentProvider + Send + Sync>,
    pub secret_manager: Arc<SecretManager>,
    pub audit_store: Arc<AuditStore>,
    pub credential_store: Arc<CredentialStore>,
    pub system_config_store: Arc<SystemConfigStore>,
    pub common_password_store: Arc<CommonPasswordStore>,
    pub hibp_cache_store: Arc<HibpCacheStore>,
}

impl AppData {
    /// Initialize all application data
    /// 
    /// Database connections should be initialized and migrated before calling this.
    /// Audit store is created first since other stores depend on it for logging.
    /// 
    /// # Errors
    /// 
    /// Returns `InternalError` when secret manager initialization fails
    pub async fn init(connections: DatabaseConnections) -> Result<Self, InternalError> {
        tracing::info!("Initializing AppData...");
        let db = connections.auth.clone();
        let audit_db = connections.audit.clone();

        let env_provider: Arc<dyn EnvironmentProvider + Send + Sync> = Arc::new(SystemEnvironment);

        tracing::debug!("Initializing secret manager...");
        let secret_manager = Arc::new(SecretManager::init()
            .map_err(|e| InternalError::parse("secret_manager", format!("Secret manager init failed: {}", e)))?);
        tracing::debug!("Secret manager initialized");

        // Order matters: audit_store first, then others that depend on it
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
            connections,
            env_provider,
            secret_manager,
            audit_store,
            credential_store,
            system_config_store,
            common_password_store,
            hibp_cache_store,
        })
    }
}

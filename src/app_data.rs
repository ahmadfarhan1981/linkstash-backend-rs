use crate::audit::{AuditLogger, audit_logger};
use crate::config::database::DatabaseConnections;
use crate::config::{EnvironmentProvider, SecretManager, SystemEnvironment};
use crate::errors::InternalError;
use crate::providers::{CryptoProvider, TokenProvider, token_provider};
use crate::providers::authentication_provider::AuthenticationProvider;
use crate::stores::user_store::UserStore;
use crate::stores::{AuditStore, user_store};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

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
    pub audit_logger: Arc<AuditLogger>,
    pub env_provider: Arc<dyn EnvironmentProvider + Send + Sync>,
    pub secret_manager: Arc<SecretManager>,
    pub stores: Stores,
    pub providers: Providers,
}

pub struct Providers {
    pub authentication_provider: Arc<AuthenticationProvider>,
    pub crypto_provider: Arc<CryptoProvider>,
}
pub struct Stores {
    pub user_store: Arc<UserStore>,
    // pub credential_store: Arc<CredentialStore>,
    // pub system_config_store: Arc<SystemConfigStore>,
    // pub common_password_store: Arc<CommonPasswordStore>,
    // pub hibp_cache_store: Arc<HibpCacheStore>,
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
        let secret_manager = Arc::new(SecretManager::init().map_err(|e| InternalError::Parse {
            value_type: "secret_manager".to_string(),
            message: format!("Secret manager init failed: {}", e),
        })?);
        tracing::debug!("Secret manager initialized");

        // Order matters: audit_store first, then others that depend on it
        tracing::debug!("Creating stores...");
        let audit_store = Arc::new(AuditStore::new(audit_db.clone()));
        let user_store = Arc::new(UserStore::new());
        // let credential_store = Arc::new(CredentialStore::new(
        //     db.clone(),
        //     secret_manager.password_pepper().to_string(),
        //     audit_store.clone(),
        // ));
        //
        // let system_config_store = Arc::new(SystemConfigStore::new(
        //     db.clone(),
        //     audit_store.clone(),
        // ));
        //
        // let common_password_store = Arc::new(CommonPasswordStore::new(db.clone()));
        //
        // let hibp_cache_store = Arc::new(HibpCacheStore::new(
        //     db.clone(),
        //     system_config_store.clone(),
        // ));

        let stores = Stores{
            user_store: Arc::clone(&user_store),
            // credential_store,
            // system_config_store,
            // common_password_store,
            // hibp_cache_store,
        };


        tracing::debug!("Stores created");

        tracing::debug!("Initializing audit logger...");
        let audit_logger = Arc::new(AuditLogger::new(audit_store.clone()));
        
        tracing::debug!("Initializing providers...");
        let crypto_provider = Arc::new(CryptoProvider::new(Arc::clone(&secret_manager)));
        let token_provider= Arc::new(TokenProvider::new(Arc::clone(&secret_manager)));
        let authentication_provider = Arc::new(AuthenticationProvider::new(
            Arc::clone(&user_store),
            Arc::clone(&crypto_provider),     
            Arc::clone(&token_provider),
        ));
        let providers = Providers{
            crypto_provider,
            authentication_provider,
        };

        
        Ok(Self {
            connections,
            audit_logger,
            env_provider,
            secret_manager,
            stores,
            providers,
        })
    }
}

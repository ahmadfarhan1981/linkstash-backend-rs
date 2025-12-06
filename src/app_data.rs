use std::sync::Arc;
use sea_orm::DatabaseConnection;
use crate::config::SecretManager;
use crate::stores::{AuditStore, CredentialStore, SystemConfigStore, CommonPasswordStore};
use crate::services::{TokenService, PasswordValidator};
use crate::errors::InternalError;

/// Centralized application data containing all databases, stores, and stateless services
/// 
/// AppData follows the main-owned stores pattern where all dependencies are created once
/// in main.rs and shared across services. This eliminates store duplication and makes
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
///   └─ token_service (Arc<TokenService>)
///   ↓ wrapped in Arc<AppData>
///   ↓ passed to services
///   ├─ AuthService::new(app_data) → extracts what it needs
///   └─ AdminService::new(app_data) → extracts what it needs
/// ```
/// 
/// # Benefits
/// 
/// - Single instance of each store (no duplication)
/// - Centralized initialization
/// - Stable service signatures (adding stores doesn't break services)
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
    
    /// Token service for JWT generation and validation
    pub token_service: Arc<TokenService>,
    
    /// Password validator for enforcing password policies
    pub password_validator: Arc<PasswordValidator>,
}

impl AppData {
    /// Initialize all application data
    /// 
    /// Creates stores and stateless services using the provided database connections.
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
    /// 2. Create stores (audit, credential, system_config)
    /// 3. Create stateless services (token_service)
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
        
        tracing::debug!("Stores created");
        
        // 3. Create stateless services
        tracing::debug!("Creating stateless services...");
        let token_service = Arc::new(TokenService::new(
            secret_manager.jwt_secret().to_string(),
            secret_manager.refresh_token_secret().to_string(),
            audit_store.clone(),
        ));
        
        // Initialize password validator with common password store
        let password_validator = Arc::new(PasswordValidator::new(common_password_store.clone()));
        
        tracing::debug!("Stateless services created");
        
        tracing::info!("AppData initialization complete");
        
        Ok(Self {
            db,
            audit_db,
            secret_manager,
            audit_store,
            credential_store,
            system_config_store,
            common_password_store,
            token_service,
            password_validator,
        })
    }
}

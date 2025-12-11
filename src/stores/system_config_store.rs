use sea_orm::{DatabaseConnection, EntityTrait, ActiveModelTrait, Set};
use chrono::Utc;
use std::sync::Arc;
use crate::types::db::system_config::{self, Entity as SystemConfig, ActiveModel};
use crate::errors::InternalError;
use crate::errors::internal::SystemConfigError;
use crate::stores::AuditStore;
use crate::providers::audit_logger_provider;

/// SystemConfigStore manages system-level configuration flags in the database
pub struct SystemConfigStore {
    db: DatabaseConnection,
    audit_store: Arc<AuditStore>,
}

impl SystemConfigStore {
    /// Create a new SystemConfigStore with the given database connection
    /// 
    /// # Arguments
    /// * `db` - The database connection
    /// * `audit_store` - The audit store for logging security events
    pub fn new(db: DatabaseConnection, audit_store: Arc<AuditStore>) -> Self {
        Self { db, audit_store }
    }

    /// Ensure the singleton system_config row exists
    /// 
    /// Creates the row with default values if it doesn't exist.
    /// This is a helper method called by other methods to ensure the table is initialized.
    /// 
    /// # Returns
    /// * `Ok(())` - Config row exists or was created successfully
    /// * `Err(InternalError)` - Database error
    async fn ensure_config_exists(&self) -> Result<(), InternalError> {
        // Check if config row exists
        let config = SystemConfig::find_by_id(1)
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("check_system_config_exists", e))?;

        if config.is_none() {
            // Create the singleton row with default values
            let now = Utc::now().timestamp();
            let new_config = ActiveModel {
                id: Set(1),
                owner_active: Set(false),
                updated_at: Set(now),
            };

            new_config
                .insert(&self.db)
                .await
                .map_err(|e| InternalError::database("create_system_config", e))?;
        }

        Ok(())
    }

    /// Get the system configuration
    /// 
    /// Retrieves the singleton system_config row (id=1).
    /// 
    /// # Returns
    /// * `Ok(Model)` - The system configuration
    /// * `Err(InternalError)` - Database error or config not found
    pub async fn get_config(&self) -> Result<system_config::Model, InternalError> {
        self.ensure_config_exists().await?;

        SystemConfig::find_by_id(1)
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("get_system_config", e))?
            .ok_or_else(|| SystemConfigError::ConfigNotFound.into())
    }

    /// Set the owner_active flag
    /// 
    /// Updates the owner_active flag in the system_config table.
    /// Logs the change to the audit database at point of action.
    /// 
    /// # Arguments
    /// * `active` - The new value for owner_active
    /// * `actor_user_id` - Optional user ID of who performed the action (for audit logging)
    /// * `ip_address` - Optional IP address (for audit logging)
    /// 
    /// # Returns
    /// * `Ok(())` - Flag updated successfully
    /// * `Err(InternalError)` - Database error
    pub async fn set_owner_active(
        &self,
        active: bool,
        actor_user_id: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(), InternalError> {
        self.ensure_config_exists().await?;

        // Get current config
        let config = SystemConfig::find_by_id(1)
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("get_system_config_for_update", e))?
            .ok_or_else(|| SystemConfigError::ConfigNotFound)?;

        // Update the config
        let now = Utc::now().timestamp();
        let mut active_model: ActiveModel = config.into();
        active_model.owner_active = Set(active);
        active_model.updated_at = Set(now);

        active_model
            .update(&self.db)
            .await
            .map_err(|e| InternalError::database("update_owner_active", e))?;

        // Log at point of action
        let actor = actor_user_id.unwrap_or_else(|| "system".to_string());
        let ip = ip_address.clone();
        
        // Determine activation method based on actor
        let activation_method = if actor == "cli" || actor == "system" {
            "cli".to_string()
        } else {
            "api".to_string()
        };

        let log_result = if active {
            audit_logger_provider::log_owner_activated(
                &self.audit_store,
                actor,
                ip,
                activation_method,
            ).await
        } else {
            audit_logger_provider::log_owner_deactivated(
                &self.audit_store,
                actor,
                ip,
                activation_method,
            ).await
        };

        if let Err(audit_err) = log_result {
            tracing::error!("Failed to log owner activation change: {:?}", audit_err);
        }

        Ok(())
    }

    /// Check if the owner account is active
    /// 
    /// Returns the current value of the owner_active flag.
    /// 
    /// # Returns
    /// * `Ok(bool)` - True if owner is active, false otherwise
    /// * `Err(InternalError)` - Database error
    pub async fn is_owner_active(&self) -> Result<bool, InternalError> {
        let config = self.get_config().await?;
        Ok(config.owner_active)
    }
}

impl std::fmt::Debug for SystemConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemConfigStore")
            .field("db", &"<connection>")
            .field("audit_store", &"<audit_store>")
            .finish()
    }
}

impl std::fmt::Display for SystemConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SystemConfigStore {{ db: <connection>, audit_store: <audit_store> }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;

    async fn setup_test_db() -> (sea_orm::DatabaseConnection, Arc<SystemConfigStore>) {
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        let system_config_store = Arc::new(SystemConfigStore::new(db.clone(), audit_store));
        (db, system_config_store)
    }

    #[tokio::test]
    async fn test_ensure_config_exists_creates_singleton_row() {
        let (_db, store) = setup_test_db().await;
        
        // Ensure config exists
        let result = store.ensure_config_exists().await;
        assert!(result.is_ok());
        
        // Verify we can get the config
        let config = store.get_config().await;
        assert!(config.is_ok());
        
        let config = config.unwrap();
        assert_eq!(config.id, 1);
        assert_eq!(config.owner_active, false);
    }

    #[tokio::test]
    async fn test_get_config_returns_singleton_row() {
        let (_db, store) = setup_test_db().await;
        
        // Get config (should create it if it doesn't exist)
        let result = store.get_config().await;
        assert!(result.is_ok());
        
        let config = result.unwrap();
        assert_eq!(config.id, 1);
        assert_eq!(config.owner_active, false);
    }

    #[tokio::test]
    async fn test_is_owner_active_returns_false_by_default() {
        let (_db, store) = setup_test_db().await;
        
        // Check owner_active flag
        let result = store.is_owner_active().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_set_owner_active_updates_flag_to_true() {
        let (_db, store) = setup_test_db().await;
        
        // Set owner_active to true
        let result = store.set_owner_active(true, Some("test_user".to_string()), Some("127.0.0.1".to_string())).await;
        assert!(result.is_ok());
        
        // Verify flag is now true
        let is_active = store.is_owner_active().await;
        assert!(is_active.is_ok());
        assert_eq!(is_active.unwrap(), true);
    }

    #[tokio::test]
    async fn test_set_owner_active_updates_flag_to_false() {
        let (_db, store) = setup_test_db().await;
        
        // First set to true
        store.set_owner_active(true, Some("test_user".to_string()), Some("127.0.0.1".to_string())).await.unwrap();
        
        // Then set to false
        let result = store.set_owner_active(false, Some("test_user".to_string()), Some("127.0.0.1".to_string())).await;
        assert!(result.is_ok());
        
        // Verify flag is now false
        let is_active = store.is_owner_active().await;
        assert!(is_active.is_ok());
        assert_eq!(is_active.unwrap(), false);
    }

    #[tokio::test]
    async fn test_set_owner_active_updates_timestamp() {
        let (_db, store) = setup_test_db().await;
        
        // Get initial config
        let initial_config = store.get_config().await.unwrap();
        let initial_timestamp = initial_config.updated_at;
        
        // Wait a moment to ensure timestamp changes
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Update owner_active
        store.set_owner_active(true, Some("test_user".to_string()), Some("127.0.0.1".to_string())).await.unwrap();
        
        // Get updated config
        let updated_config = store.get_config().await.unwrap();
        let updated_timestamp = updated_config.updated_at;
        
        // Verify timestamp was updated
        assert!(updated_timestamp > initial_timestamp);
    }

    #[tokio::test]
    async fn test_multiple_calls_to_ensure_config_exists_are_idempotent() {
        let (_db, store) = setup_test_db().await;
        
        // Call ensure_config_exists multiple times
        let result1 = store.ensure_config_exists().await;
        assert!(result1.is_ok());
        
        let result2 = store.ensure_config_exists().await;
        assert!(result2.is_ok());
        
        let result3 = store.ensure_config_exists().await;
        assert!(result3.is_ok());
        
        // Verify only one config row exists
        let config = store.get_config().await.unwrap();
        assert_eq!(config.id, 1);
    }
}

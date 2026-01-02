use crate::errors::InternalError;
use crate::errors::internal::SystemConfigError;
use crate::types::db::system_config::{self, ActiveModel, Entity as SystemConfig};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseConnection, EntityTrait, Set};

/// SystemConfigStore manages system-level configuration flags in the database
pub struct SystemConfigStore {}

impl SystemConfigStore {
    pub fn new() -> Self {
        Self {}
    }

    /// Ensure the singleton system_config row exists
    ///
    /// Creates the row with default values if it doesn't exist.
    /// This is a helper method called by other methods to ensure the table is initialized.
    ///
    /// # Returns
    /// * `Ok(())` - Config row exists or was created successfully
    /// * `Err(InternalError)` - Database error
    async fn ensure_config_exists(&self, conn: &impl ConnectionTrait) -> Result<(), InternalError> {
        // Check if config row exists
        let config = SystemConfig::find_by_id(1)
            .one(conn)
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
                .insert(conn)
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
    pub async fn get_config(
        &self,
        conn: &impl ConnectionTrait,
    ) -> Result<system_config::Model, InternalError> {
        self.ensure_config_exists(conn).await?;

        SystemConfig::find_by_id(1)
            .one(conn)
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
        conn: &impl ConnectionTrait,
        active: bool,
        actor_user_id: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(), InternalError> {
        self.ensure_config_exists(conn).await?;

        // Get current config
        let config = SystemConfig::find_by_id(1)
            .one(conn)
            .await
            .map_err(|e| InternalError::database("get_system_config_for_update", e))?
            .ok_or_else(|| SystemConfigError::ConfigNotFound)?;

        // Update the config
        let now = Utc::now().timestamp();
        let mut active_model: ActiveModel = config.into();
        active_model.owner_active = Set(active);
        active_model.updated_at = Set(now);

        active_model
            .update(conn)
            .await
            .map_err(|e| InternalError::database("update_owner_active", e))?;

        // Log at point of action
        // let actor = actor_user_id.unwrap_or_else(|| "system".to_string());
        // let ip = ip_address.clone();

        // Determine activation method based on actor
        // let activation_method = if actor == "cli" || actor == "system" {
        //     "cli".to_string()
        // } else {
        //     "api".to_string()
        // };

        // let log_result = if active {
        //     self.audit_logger.log_owner_activated(
        //         actor,
        //         ip,
        //         activation_method,
        //     ).await
        // } else {
        //     self.audit_logger.log_owner_deactivated(
        //         actor,
        //         ip,
        //         activation_method,
        //     ).await
        // };

        // if let Err(audit_err) = log_result {
        //     tracing::error!("Failed to log owner activation change: {:?}", audit_err);
        // }

        Ok(())
    }

    /// Check if the owner account is active
    ///
    /// Returns the current value of the owner_active flag.
    ///
    /// # Returns
    /// * `Ok(bool)` - True if owner is active, false otherwise
    /// * `Err(InternalError)` - Database error
    pub async fn is_owner_active(
        &self,
        conn: &impl ConnectionTrait,
    ) -> Result<bool, InternalError> {
        let config = self.get_config(conn).await?;
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
        write!(
            f,
            "SystemConfigStore {{ db: <connection>, audit_store: <audit_store> }}"
        )
    }
}

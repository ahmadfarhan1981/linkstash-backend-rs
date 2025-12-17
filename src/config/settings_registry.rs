use std::{collections::HashMap, sync::{Arc, RwLock, Weak}};

use std::time::Duration;

use crate::config::application_settings;

use super::{ApplicationError, BootstrapSettings, ConfigSource, ConfigSpec, ConfigValue, ApplicationSettings};



/// Settings registry with in-memory caching and runtime updates
/// 
/// Business logic configuration that can be updated at runtime via API.
/// Values are cached in memory for fast access and updated atomically.
pub struct SettingsRegistry {
    db: Arc<sea_orm::DatabaseConnection>,
    application_settings: Arc<ApplicationSettings>,
}

impl SettingsRegistry {
    /// Initialize SettingsRegistry by loading and caching all settings
    /// 
    /// Loads all application settings from their configured sources and caches
    /// them in memory for fast access. Uses environment override → persistent source → default priority.
    /// 
    /// # Arguments
    /// * `bootstrap` - Bootstrap settings containing database connection info
    /// 
    /// # Returns
    /// * `Ok(SettingsRegistry)` - Successfully initialized with all settings loaded
    /// * `Err(ApplicationError)` - Failed to connect to database or load required settings
    pub async fn init(db:Arc<sea_orm::DatabaseConnection> ) -> Result<Arc<Self>, ApplicationError> {
       
       
        let registry = Arc::new_cyclic(|weak_registry| {
            let application_settings = ApplicationSettings::init( weak_registry.clone() ).unwrap();            
            Self {
                db,
                application_settings: Arc::new( application_settings)
            }
        });

        Ok(registry)
        
    }    
   
}



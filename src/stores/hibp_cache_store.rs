use sea_orm::{DatabaseConnection, EntityTrait, Set};
use sea_orm::sea_query::OnConflict;
use std::sync::Arc;
use crate::types::db::hibp_cache::{self, Entity as HibpCache, ActiveModel};
use crate::errors::InternalError;
use crate::stores::SystemConfigStore;

/// HibpCacheStore manages cached HaveIBeenPwned API responses
/// 
/// Caches HIBP API responses by hash prefix to minimize API calls and improve performance.
/// Uses staleness checking to determine when cached entries should be refreshed.
pub struct HibpCacheStore {
    db: DatabaseConnection,
    system_config_store: Arc<SystemConfigStore>,
}

impl HibpCacheStore {
    /// Create a new HibpCacheStore
    /// 
    /// # Arguments
    /// * `db` - The database connection
    /// * `system_config_store` - The system config store for staleness configuration
    pub fn new(db: DatabaseConnection, system_config_store: Arc<SystemConfigStore>) -> Self {
        Self {
            db,
            system_config_store,
        }
    }

    /// Get cached HIBP response if not stale
    /// 
    /// Retrieves a cached HIBP API response for the given hash prefix.
    /// Returns None if the cache entry doesn't exist or is stale.
    /// 
    /// # Arguments
    /// * `prefix` - The 5-character SHA-1 hash prefix
    /// 
    /// # Returns
    /// * `Ok(Some(response_data))` - Cached response is fresh
    /// * `Ok(None)` - No cache entry or entry is stale
    /// * `Err(InternalError)` - Database error
    pub async fn get_cached_response(&self, prefix: &str) -> Result<Option<String>, InternalError> {
        let cache_entry = HibpCache::find_by_id(prefix)
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("get_hibp_cache", e))?;

        if let Some(entry) = cache_entry {
            // Default staleness: 30 days (2592000 seconds)
            let staleness_seconds = 2592000i64;

            let now = chrono::Utc::now().timestamp();
            let age = now - entry.fetched_at;

            if age < staleness_seconds {
                return Ok(Some(entry.response_data));
            }
        }

        Ok(None)
    }

    /// Store or update HIBP response in cache
    /// 
    /// Stores a new HIBP API response or updates an existing one using upsert logic.
    /// Sets the fetched_at timestamp to the current time.
    /// 
    /// # Arguments
    /// * `prefix` - The 5-character SHA-1 hash prefix
    /// * `data` - The HIBP API response data (hash suffixes)
    /// 
    /// # Returns
    /// * `Ok(())` - Response stored successfully
    /// * `Err(InternalError)` - Database error
    pub async fn store_response(&self, prefix: &str, data: &str) -> Result<(), InternalError> {
        let now = chrono::Utc::now().timestamp();

        let model = ActiveModel {
            hash_prefix: Set(prefix.to_string()),
            response_data: Set(data.to_string()),
            fetched_at: Set(now),
        };

        HibpCache::insert(model)
            .on_conflict(
                OnConflict::column(hibp_cache::Column::HashPrefix)
                    .update_columns([
                        hibp_cache::Column::ResponseData,
                        hibp_cache::Column::FetchedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await
            .map_err(|e| InternalError::database("store_hibp_cache", e))?;

        Ok(())
    }
}

impl std::fmt::Debug for HibpCacheStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HibpCacheStore")
            .field("db", &"<connection>")
            .field("system_config_store", &"<system_config_store>")
            .finish()
    }
}

impl std::fmt::Display for HibpCacheStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HibpCacheStore {{ db: <connection>, system_config_store: <system_config_store> }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;

    async fn setup_test_db() -> (sea_orm::DatabaseConnection, Arc<HibpCacheStore>) {
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        let system_config_store = Arc::new(SystemConfigStore::new(db.clone(), audit_store));
        let hibp_cache_store = Arc::new(HibpCacheStore::new(db.clone(), system_config_store));
        (db, hibp_cache_store)
    }

    #[tokio::test]
    async fn test_get_cached_response_returns_none_when_no_entry() {
        let (_db, store) = setup_test_db().await;

        let result = store.get_cached_response("ABCDE").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn test_store_response_creates_new_entry() {
        let (_db, store) = setup_test_db().await;

        let prefix = "12345";
        let data = "ABC123:5\nDEF456:10";

        let result = store.store_response(prefix, data).await;
        assert!(result.is_ok());

        // Verify entry was created
        let cached = store.get_cached_response(prefix).await;
        assert!(cached.is_ok());
        assert_eq!(cached.unwrap(), Some(data.to_string()));
    }

    #[tokio::test]
    async fn test_store_response_updates_existing_entry() {
        let (_db, store) = setup_test_db().await;

        let prefix = "AAAAA";
        let data1 = "OLD:1";
        let data2 = "NEW:2";

        // Store initial data
        store.store_response(prefix, data1).await.unwrap();

        // Update with new data
        let result = store.store_response(prefix, data2).await;
        assert!(result.is_ok());

        // Verify entry was updated
        let cached = store.get_cached_response(prefix).await;
        assert!(cached.is_ok());
        assert_eq!(cached.unwrap(), Some(data2.to_string()));
    }

    #[tokio::test]
    async fn test_get_cached_response_returns_fresh_entry() {
        let (_db, store) = setup_test_db().await;

        let prefix = "FRESH";
        let data = "HASH1:100\nHASH2:200";

        // Store entry
        store.store_response(prefix, data).await.unwrap();

        // Retrieve immediately (should be fresh)
        let result = store.get_cached_response(prefix).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(data.to_string()));
    }

    #[tokio::test]
    async fn test_multiple_prefixes_stored_independently() {
        let (_db, store) = setup_test_db().await;

        let prefix1 = "AAA11";
        let data1 = "DATA1";
        let prefix2 = "BBB22";
        let data2 = "DATA2";

        // Store two different entries
        store.store_response(prefix1, data1).await.unwrap();
        store.store_response(prefix2, data2).await.unwrap();

        // Verify both are stored correctly
        let cached1 = store.get_cached_response(prefix1).await.unwrap();
        let cached2 = store.get_cached_response(prefix2).await.unwrap();

        assert_eq!(cached1, Some(data1.to_string()));
        assert_eq!(cached2, Some(data2.to_string()));
    }

    #[tokio::test]
    async fn test_stale_cache_entry_returns_none() {
        let (db, store) = setup_test_db().await;

        let prefix = "STALE";
        let old_data = "OLD_DATA:123";

        // Manually insert a stale entry (31 days old, staleness threshold is 30 days)
        let stale_timestamp = chrono::Utc::now().timestamp() - (31 * 24 * 60 * 60);
        
        let stale_model = ActiveModel {
            hash_prefix: Set(prefix.to_string()),
            response_data: Set(old_data.to_string()),
            fetched_at: Set(stale_timestamp),
        };

        HibpCache::insert(stale_model)
            .exec(&db)
            .await
            .expect("Failed to insert stale entry");

        // Verify the stale entry returns None (treated as cache miss)
        let result = store.get_cached_response(prefix).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None, "Stale cache entry should return None");

        // Now store fresh data
        let new_data = "NEW_DATA:456";
        store.store_response(prefix, new_data).await.unwrap();

        // Verify the fresh entry is returned
        let cached = store.get_cached_response(prefix).await.unwrap();
        assert_eq!(cached, Some(new_data.to_string()), "Fresh cache entry should be returned");
    }
}

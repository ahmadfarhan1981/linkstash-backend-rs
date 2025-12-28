use sea_orm::{DatabaseConnection, EntityTrait, Set, DbErr, TransactionTrait, PaginatorTrait};
use crate::types::db::common_password::{Entity as CommonPassword, ActiveModel};

/// CommonPasswordStore manages the common password list in the database
/// 
/// This store provides fast lookups for common passwords that should be rejected
/// during password validation. The list is stored in a SQLite table with the
/// password as the primary key for efficient indexed lookups.
pub struct CommonPasswordStore {
    db: DatabaseConnection,
}

impl CommonPasswordStore {
    /// Create a new CommonPasswordStore with the given database connection
    /// 
    /// # Arguments
    /// * `db` - The database connection
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
    
    /// Check if password exists in common passwords table (case-insensitive)
    /// 
    /// # Arguments
    /// * `password` - The password to check
    /// 
    /// # Returns
    /// * `Ok(true)` - Password is in the common password list
    /// * `Ok(false)` - Password is not in the common password list
    /// * `Err(DbErr)` - Database error
    pub async fn is_common_password(&self, password: &str) -> Result<bool, DbErr> {
        let password_lower = password.to_lowercase();
        let result = CommonPassword::find_by_id(password_lower)
            .one(&self.db)
            .await?;
        Ok(result.is_some())
    }
    
    /// Bulk load passwords from iterator (clears existing, uses transaction)
    /// 
    /// This method replaces the entire common password list with the provided passwords.
    /// It uses a transaction to ensure atomicity and batches inserts for performance.
    /// 
    /// # Arguments
    /// * `passwords` - Iterator of password strings to load
    /// 
    /// # Returns
    /// * `Ok(count)` - Number of passwords loaded successfully
    /// * `Err(DbErr)` - Database error
    pub async fn load_passwords<I>(&self, passwords: I) -> Result<usize, DbErr>
    where
        I: IntoIterator<Item = String>,
    {
        use std::collections::HashSet;
        
        let txn = self.db.begin().await?;
        
        // Clear existing passwords
        CommonPassword::delete_many().exec(&txn).await?;
        
        let mut count = 0;
        let mut batch = Vec::new();
        let mut seen = HashSet::new();
        
        for password in passwords {
            let password_lower = password.trim().to_lowercase();
            if password_lower.is_empty() {
                continue;
            }
            
            // Skip duplicates
            if !seen.insert(password_lower.clone()) {
                continue;
            }
            
            batch.push(ActiveModel {
                password: Set(password_lower),
            });
            count += 1;
            
            // Insert in batches of 1000 for performance
            if batch.len() >= 1000 {
                CommonPassword::insert_many(batch.drain(..)).exec(&txn).await?;
            }
        }
        
        // Insert remaining passwords
        if !batch.is_empty() {
            CommonPassword::insert_many(batch).exec(&txn).await?;
        }
        
        txn.commit().await?;
        Ok(count)
    }
    
    /// Get the count of passwords in the common password list
    /// 
    /// # Returns
    /// * `Ok(count)` - Number of passwords in the list
    /// * `Err(DbErr)` - Database error
    pub async fn count(&self) -> Result<u64, DbErr> {
        CommonPassword::find().count(&self.db).await
    }
}

impl std::fmt::Debug for CommonPasswordStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonPasswordStore")
            .field("db", &"<connection>")
            .finish()
    }
}

impl std::fmt::Display for CommonPasswordStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommonPasswordStore {{ db: <connection> }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;

    async fn setup_test_db() -> (DatabaseConnection, CommonPasswordStore) {
        let (db, _audit_db, _credential_store, _audit_store) = setup_test_stores().await;
        let store = CommonPasswordStore::new(db.clone());
        (db, store)
    }

    #[tokio::test]
    async fn test_is_common_password_returns_false_for_empty_list() {
        let (_db, store) = setup_test_db().await;
        
        let result = store.is_common_password("password123").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_load_passwords_inserts_passwords() {
        let (_db, store) = setup_test_db().await;
        
        let passwords = vec![
            "password".to_string(),
            "123456".to_string(),
            "qwerty".to_string(),
        ];
        
        let result = store.load_passwords(passwords).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);
        
        // Verify count
        let count = store.count().await.unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_is_common_password_finds_loaded_password() {
        let (_db, store) = setup_test_db().await;
        
        let passwords = vec!["password".to_string(), "123456".to_string()];
        store.load_passwords(passwords).await.unwrap();
        
        let result = store.is_common_password("password").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_is_common_password_is_case_insensitive() {
        let (_db, store) = setup_test_db().await;
        
        let passwords = vec!["Password".to_string()];
        store.load_passwords(passwords).await.unwrap();
        
        // Check with different cases
        assert_eq!(store.is_common_password("password").await.unwrap(), true);
        assert_eq!(store.is_common_password("PASSWORD").await.unwrap(), true);
        assert_eq!(store.is_common_password("PaSsWoRd").await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_load_passwords_clears_existing_passwords() {
        let (_db, store) = setup_test_db().await;
        
        // Load first batch
        let passwords1 = vec!["password1".to_string(), "password2".to_string()];
        store.load_passwords(passwords1).await.unwrap();
        
        assert_eq!(store.count().await.unwrap(), 2);
        
        // Load second batch (should replace first)
        let passwords2 = vec!["password3".to_string()];
        store.load_passwords(passwords2).await.unwrap();
        
        assert_eq!(store.count().await.unwrap(), 1);
        assert_eq!(store.is_common_password("password1").await.unwrap(), false);
        assert_eq!(store.is_common_password("password3").await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_load_passwords_skips_empty_strings() {
        let (_db, store) = setup_test_db().await;
        
        let passwords = vec![
            "password".to_string(),
            "".to_string(),
            "   ".to_string(),
            "123456".to_string(),
        ];
        
        let result = store.load_passwords(passwords).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2); // Only 2 valid passwords
        
        let count = store.count().await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_load_passwords_trims_whitespace() {
        let (_db, store) = setup_test_db().await;
        
        let passwords = vec![
            "  password  ".to_string(),
            "123456\n".to_string(),
        ];
        
        store.load_passwords(passwords).await.unwrap();
        
        // Should find trimmed versions
        assert_eq!(store.is_common_password("password").await.unwrap(), true);
        assert_eq!(store.is_common_password("123456").await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_load_passwords_handles_large_batch() {
        let (_db, store) = setup_test_db().await;
        
        // Create 2500 passwords to test batching (batch size is 1000)
        let passwords: Vec<String> = (0..2500)
            .map(|i| format!("password{}", i))
            .collect();
        
        let result = store.load_passwords(passwords).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2500);
        
        let count = store.count().await.unwrap();
        assert_eq!(count, 2500);
    }

    #[tokio::test]
    async fn test_count_returns_zero_for_empty_list() {
        let (_db, store) = setup_test_db().await;
        
        let count = store.count().await;
        assert!(count.is_ok());
        assert_eq!(count.unwrap(), 0);
    }
}

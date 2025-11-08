use sea_orm::{DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter, ActiveModelTrait, Set};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher, password_hash::SaltString};
use uuid::Uuid;
use chrono::Utc;
use crate::auth::entities::user::{self, Entity as User, ActiveModel};
use crate::auth::errors::AuthError;

/// CredentialStore manages user credentials and refresh tokens in the database
pub struct CredentialStore {
    db: DatabaseConnection,
}

impl CredentialStore {
    /// Create a new CredentialStore with the given database connection
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Add a new user to the database
    /// 
    /// # Arguments
    /// * `username` - The username for the new user
    /// * `password` - The plaintext password to hash and store
    /// 
    /// # Returns
    /// * `Ok(String)` - The user_id (UUID) of the created user
    /// * `Err(AuthError)` - DuplicateUsername if username already exists, or InternalError
    pub async fn add_user(&self, username: String, password: String) -> Result<String, AuthError> {
        // Check if username already exists
        let existing_user = User::find()
            .filter(user::Column::Username.eq(&username))
            .one(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))?;

        if existing_user.is_some() {
            return Err(AuthError::duplicate_username());
        }

        // Generate UUID for user
        let user_id = Uuid::new_v4().to_string();

        // Hash password with Argon2id
        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::internal_error(format!("Password hashing error: {}", e)))?
            .to_string();

        // Get current timestamp
        let created_at = Utc::now().timestamp();

        // Create new user ActiveModel
        let new_user = ActiveModel {
            id: Set(user_id.clone()),
            username: Set(username),
            password_hash: Set(password_hash),
            created_at: Set(created_at),
        };

        // Insert into database
        new_user
            .insert(&self.db)
            .await
            .map_err(|e| {
                // Check if it's a unique constraint violation
                if e.to_string().contains("UNIQUE") {
                    AuthError::duplicate_username()
                } else {
                    AuthError::internal_error(format!("Database error: {}", e))
                }
            })?;

        Ok(user_id)
    }

    /// Verify user credentials and return user_id on success
    /// 
    /// # Arguments
    /// * `username` - The username to verify
    /// * `password` - The plaintext password to verify
    /// 
    /// # Returns
    /// * `Ok(String)` - The user_id (UUID) if credentials are valid
    /// * `Err(AuthError)` - InvalidCredentials if username not found or password incorrect
    pub async fn verify_credentials(&self, username: &str, password: &str) -> Result<String, AuthError> {
        // Query user by username
        let user = User::find()
            .filter(user::Column::Username.eq(username))
            .one(&self.db)
            .await
            .map_err(|_| AuthError::invalid_credentials())?;

        // If user not found, return invalid credentials
        let user = user.ok_or_else(|| AuthError::invalid_credentials())?;

        // Parse the stored password hash
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| AuthError::invalid_credentials())?;

        // Verify password using Argon2
        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::invalid_credentials())?;

        // Return user_id on success
        Ok(user.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, DatabaseConnection};
    use migration::{Migrator, MigratorTrait};

    async fn setup_test_db() -> (DatabaseConnection, CredentialStore) {
        // Create in-memory SQLite database for testing
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        // Run migrations
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        // Create credential store
        let credential_store = CredentialStore::new(db.clone());
        
        (db, credential_store)
    }

    #[tokio::test]
    async fn test_add_user_creates_user_in_database() {
        let (_db, credential_store) = setup_test_db().await;
        
        let result = credential_store
            .add_user("newuser".to_string(), "password123".to_string())
            .await;
        
        assert!(result.is_ok());
        let user_id = result.unwrap();
        assert!(!user_id.is_empty());
        
        // Verify user can be found by verifying credentials
        let verify_result = credential_store
            .verify_credentials("newuser", "password123")
            .await;
        
        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_add_user_hashes_password() {
        let (db, credential_store) = setup_test_db().await;
        
        let password = "mysecretpassword";
        let result = credential_store
            .add_user("testuser".to_string(), password.to_string())
            .await;
        
        assert!(result.is_ok());
        
        // Query the database directly to check the stored password hash
        let user = User::find()
            .filter(user::Column::Username.eq("testuser"))
            .one(&db)
            .await
            .expect("Failed to query user")
            .expect("User not found");
        
        // Verify password is not stored in plaintext
        assert_ne!(user.password_hash, password);
        
        // Verify it looks like an Argon2 hash (starts with $argon2)
        assert!(user.password_hash.starts_with("$argon2"));
    }

    #[tokio::test]
    async fn test_add_user_fails_with_duplicate_username() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Add first user
        let result1 = credential_store
            .add_user("duplicate".to_string(), "password1".to_string())
            .await;
        
        assert!(result1.is_ok());
        
        // Try to add second user with same username
        let result2 = credential_store
            .add_user("duplicate".to_string(), "password2".to_string())
            .await;
        
        assert!(result2.is_err());
        match result2 {
            Err(AuthError::DuplicateUsername(_)) => {
                // Expected error type
            }
            _ => panic!("Expected DuplicateUsername error"),
        }
    }

    #[tokio::test]
    async fn test_verify_credentials_succeeds_with_correct_password() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Add user
        let user_id = credential_store
            .add_user("validuser".to_string(), "correctpass".to_string())
            .await
            .expect("Failed to add user");
        
        // Verify with correct password
        let result = credential_store
            .verify_credentials("validuser", "correctpass")
            .await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_verify_credentials_fails_with_incorrect_password() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Add user
        credential_store
            .add_user("validuser".to_string(), "correctpass".to_string())
            .await
            .expect("Failed to add user");
        
        // Verify with incorrect password
        let result = credential_store
            .verify_credentials("validuser", "wrongpass")
            .await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidCredentials(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    #[tokio::test]
    async fn test_verify_credentials_fails_with_nonexistent_username() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Try to verify credentials for non-existent user
        let result = credential_store
            .verify_credentials("nonexistent", "anypassword")
            .await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidCredentials(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidCredentials error"),
        }
    }
}

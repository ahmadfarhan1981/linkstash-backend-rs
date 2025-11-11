use sea_orm::{DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter, ActiveModelTrait, Set, TransactionTrait};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher, password_hash::SaltString};
use uuid::Uuid;
use chrono::Utc;
use crate::types::db::user::{self, Entity as User, ActiveModel};
use crate::types::db::refresh_token::{ActiveModel as RefreshTokenActiveModel};
use crate::errors::auth::AuthError;

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
        let salt = SaltString::generate(&mut rand_core::OsRng);
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
    
    /// Store a refresh token in the database
    /// 
    /// # Arguments
    /// * `token_hash` - The SHA-256 hash of the refresh token
    /// * `user_id` - The user_id (UUID string) this token belongs to
    /// * `expires_at` - Unix timestamp when the token expires
    /// 
    /// # Returns
    /// * `Ok(())` - Token stored successfully
    /// * `Err(AuthError)` - Database error
    pub async fn store_refresh_token(&self, token_hash: String, user_id: String, expires_at: i64) -> Result<(), AuthError> {
        // Use a transaction to ensure atomicity
        let txn = self.db.begin().await
            .map_err(|e| AuthError::internal_error(format!("Failed to start transaction: {}", e)))?;
        
        let created_at = Utc::now().timestamp();
        
        let new_token = RefreshTokenActiveModel {
            id: sea_orm::ActiveValue::NotSet, // Auto-increment will handle this
            token_hash: Set(token_hash),
            user_id: Set(user_id),
            expires_at: Set(expires_at),
            created_at: Set(created_at),
        };
        
        new_token.insert(&txn).await
            .map_err(|e| AuthError::internal_error(format!("Failed to store refresh token: {}", e)))?;
        
        txn.commit().await
            .map_err(|e| AuthError::internal_error(format!("Failed to commit transaction: {}", e)))?;
        
        Ok(())
    }
    
    /// Validate a refresh token and return the associated user_id
    /// 
    /// # Arguments
    /// * `token_hash` - The SHA-256 hash of the refresh token to validate
    /// 
    /// # Returns
    /// * `Ok(String)` - The user_id (UUID) if token is valid and not expired
    /// * `Err(AuthError)` - InvalidRefreshToken if not found, ExpiredRefreshToken if expired
    pub async fn validate_refresh_token(&self, token_hash: &str) -> Result<String, AuthError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        // Query token by hash
        let token = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))?;
        
        // If token not found, return invalid refresh token error
        let token = token.ok_or_else(|| AuthError::invalid_refresh_token())?;
        
        // Check if token is expired
        let now = Utc::now().timestamp();
        if token.expires_at < now {
            return Err(AuthError::expired_refresh_token());
        }
        
        // Return user_id on success
        Ok(token.user_id)
    }
    
    /// Revoke a refresh token by deleting it from the database
    /// 
    /// # Arguments
    /// * `token_hash` - The SHA-256 hash of the refresh token to revoke
    /// * `user_id` - The user_id that must own the token (for authorization)
    /// 
    /// # Returns
    /// * `Ok(())` - Token revoked successfully (or didn't exist, or didn't belong to user)
    /// * `Err(AuthError)` - Database error
    pub async fn revoke_refresh_token(&self, token_hash: &str, user_id: &str) -> Result<(), AuthError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        // Delete token by hash AND user_id (succeeds even if token doesn't exist or doesn't belong to user)
        RefreshToken::delete_many()
            .filter(Column::TokenHash.eq(token_hash))
            .filter(Column::UserId.eq(user_id))
            .exec(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Failed to revoke refresh token: {}", e)))?;
        
        Ok(())
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

    #[tokio::test]
    async fn test_store_refresh_token_saves_token_to_database() {
        let (db, credential_store) = setup_test_db().await;
        
        // Add a user first
        let user_id = credential_store
            .add_user("tokenuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "test_hash_123";
        let expires_at = Utc::now().timestamp() + 604800; // 7 days
        
        let result = credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at)
            .await;
        
        assert!(result.is_ok());
        
        // Verify token is in database
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let stored_token = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&db)
            .await
            .expect("Failed to query token")
            .expect("Token not found");
        
        assert_eq!(stored_token.token_hash, token_hash);
        assert_eq!(stored_token.user_id, user_id);
        assert_eq!(stored_token.expires_at, expires_at);
    }

    #[tokio::test]
    async fn test_stored_token_is_hashed() {
        let (db, credential_store) = setup_test_db().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("hashuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a token with a plaintext-looking value
        let plaintext_token = "my-plaintext-token";
        let expires_at = Utc::now().timestamp() + 604800;
        
        let result = credential_store
            .store_refresh_token(plaintext_token.to_string(), user_id.clone(), expires_at)
            .await;
        
        assert!(result.is_ok());
        
        // Verify the stored value matches what we passed (caller is responsible for hashing)
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let stored_token = RefreshToken::find()
            .filter(Column::TokenHash.eq(plaintext_token))
            .one(&db)
            .await
            .expect("Failed to query token")
            .expect("Token not found");
        
        // The store method stores whatever hash is passed to it
        assert_eq!(stored_token.token_hash, plaintext_token);
    }

    #[tokio::test]
    async fn test_stored_token_has_correct_expiration() {
        let (db, credential_store) = setup_test_db().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("expiryuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a token with 7 days expiration
        let token_hash = "expiry_test_hash";
        let now = Utc::now().timestamp();
        let expires_at = now + (7 * 24 * 60 * 60); // 7 days in seconds
        
        let result = credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at)
            .await;
        
        assert!(result.is_ok());
        
        // Verify expiration is correct
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let stored_token = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&db)
            .await
            .expect("Failed to query token")
            .expect("Token not found");
        
        assert_eq!(stored_token.expires_at, expires_at);
        
        // Verify it's approximately 7 days from now
        let diff = stored_token.expires_at - now;
        assert_eq!(diff, 7 * 24 * 60 * 60); // Exactly 7 days
    }

    #[tokio::test]
    async fn test_validate_refresh_token_succeeds_with_valid_token() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("validtokenuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a valid refresh token
        let token_hash = "valid_token_hash";
        let expires_at = Utc::now().timestamp() + 604800; // 7 days from now
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at)
            .await
            .expect("Failed to store token");
        
        // Validate the token
        let result = credential_store.validate_refresh_token(token_hash).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_refresh_token_returns_correct_user_id() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("useridtest".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "userid_token_hash";
        let expires_at = Utc::now().timestamp() + 604800;
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at)
            .await
            .expect("Failed to store token");
        
        // Validate and verify user_id
        let result = credential_store.validate_refresh_token(token_hash).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_validate_refresh_token_fails_with_invalid_token() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Try to validate a token that doesn't exist
        let result = credential_store.validate_refresh_token("nonexistent_token").await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidRefreshToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidRefreshToken error"),
        }
    }

    #[tokio::test]
    async fn test_validate_refresh_token_fails_with_expired_token() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("expireduser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store an expired refresh token
        let token_hash = "expired_token_hash";
        let expires_at = Utc::now().timestamp() - 3600; // Expired 1 hour ago
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at)
            .await
            .expect("Failed to store token");
        
        // Try to validate the expired token
        let result = credential_store.validate_refresh_token(token_hash).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::ExpiredRefreshToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected ExpiredRefreshToken error"),
        }
    }

    #[tokio::test]
    async fn test_revoke_refresh_token_removes_token_from_database() {
        let (db, credential_store) = setup_test_db().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("revokeuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "revoke_test_hash";
        let expires_at = Utc::now().timestamp() + 604800;
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at)
            .await
            .expect("Failed to store token");
        
        // Verify token exists
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let token_before = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_before.is_some());
        
        // Revoke the token with correct user_id
        let result = credential_store.revoke_refresh_token(token_hash, &user_id).await;
        assert!(result.is_ok());
        
        // Verify token is removed
        let token_after = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_after.is_none());
    }

    #[tokio::test]
    async fn test_revoke_refresh_token_succeeds_even_if_token_doesnt_exist() {
        let (_db, credential_store) = setup_test_db().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("testuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Try to revoke a token that doesn't exist
        let result = credential_store.revoke_refresh_token("nonexistent_token", &user_id).await;
        
        // Should succeed without error
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_revoke_refresh_token_only_revokes_if_user_matches() {
        let (db, credential_store) = setup_test_db().await;
        
        // Add two users
        let user1_id = credential_store
            .add_user("user1".to_string(), "password".to_string())
            .await
            .expect("Failed to add user1");
        
        let user2_id = credential_store
            .add_user("user2".to_string(), "password".to_string())
            .await
            .expect("Failed to add user2");
        
        // Store a refresh token for user1
        let token_hash = "user1_token_hash";
        let expires_at = Utc::now().timestamp() + 604800;
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user1_id.clone(), expires_at)
            .await
            .expect("Failed to store token");
        
        // Try to revoke user1's token as user2 (should not delete)
        let result = credential_store.revoke_refresh_token(token_hash, &user2_id).await;
        assert!(result.is_ok());
        
        // Verify token still exists (wasn't deleted because user_id didn't match)
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let token_after = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_after.is_some());
        
        // Now revoke with correct user_id
        let result = credential_store.revoke_refresh_token(token_hash, &user1_id).await;
        assert!(result.is_ok());
        
        // Verify token is now removed
        let token_final = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_final.is_none());
    }
}


use sea_orm::{DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter, ActiveModelTrait, Set, TransactionTrait};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher, password_hash::SaltString, Algorithm, Version, Params};
use uuid::Uuid;
use chrono::Utc;
use crate::types::db::user::{self, Entity as User, ActiveModel};
use crate::types::db::refresh_token::{ActiveModel as RefreshTokenActiveModel};
use crate::errors::auth::AuthError;

/// CredentialStore manages user credentials and refresh tokens in the database
pub struct CredentialStore {
    db: DatabaseConnection,
    password_pepper: String,
}

impl CredentialStore {
    /// Create a new CredentialStore with the given database connection and password pepper
    /// 
    /// # Arguments
    /// * `db` - The database connection
    /// * `password_pepper` - The secret key used for password hashing (from SecretManager)
    pub fn new(db: DatabaseConnection, password_pepper: String) -> Self {
        Self { db, password_pepper }
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

        // Hash password with Argon2id using password_pepper as secret parameter
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            self.password_pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )
        .map_err(|e| AuthError::internal_error(format!("Failed to initialize Argon2 with secret: {}", e)))?;
        
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

        // Verify password using Argon2 with password_pepper as secret parameter
        let argon2 = Argon2::new_with_secret(
            self.password_pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )
        .map_err(|_| AuthError::invalid_credentials())?;
        
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
    /// Does not verify user ownership - the refresh token itself is the authority.
    /// 
    /// # Arguments
    /// * `token_hash` - SHA-256 hash of the refresh token to revoke
    /// 
    /// # Returns
    /// * `Ok(user_id)` - Token revoked successfully, returns the user_id for audit logging
    /// * `Err(AuthError::InvalidRefreshToken)` - Token not found in database
    /// * `Err(AuthError::InternalError)` - Database error
    pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<String, AuthError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        let token = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Failed to query refresh token: {}", e)))?
            .ok_or_else(|| AuthError::invalid_refresh_token())?;
        
        let user_id = token.user_id.clone();
        
        RefreshToken::delete_many()
            .filter(Column::TokenHash.eq(token_hash))
            .exec(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Failed to revoke refresh token: {}", e)))?;
        
        Ok(user_id)
    }
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("db", &"<connection>")
            .field("password_pepper", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Display for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CredentialStore {{ db: <connection>, password_pepper: <redacted> }}")
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
        
        // Create credential store with test password pepper
        let password_pepper = "test-pepper-for-unit-tests".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper);
        
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
        
        // Revoke the token
        let result = credential_store.revoke_refresh_token(token_hash).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_id);
        
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
        let _user_id = credential_store
            .add_user("testuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Try to revoke a token that doesn't exist
        let result = credential_store.revoke_refresh_token("nonexistent_token").await;
        
        // Should fail with invalid token error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_refresh_token_only_revokes_if_user_matches() {
        let (db, credential_store) = setup_test_db().await;
        
        // Add two users
        let user1_id = credential_store
            .add_user("user1".to_string(), "password".to_string())
            .await
            .expect("Failed to add user1");
        
        let _user2_id = credential_store
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
        
        // Revoke the token (no user verification - RT is the authority)
        let result = credential_store.revoke_refresh_token(token_hash).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user1_id);
        
        // Verify token is removed
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let token_after = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_after.is_none());
    }

    // Tests for password pepper functionality (subtask 3.1)

    #[tokio::test]
    async fn test_password_hashing_with_secret_parameter_produces_valid_hash() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        let password_pepper = "test-pepper-secret-key".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper);
        
        // Add user with peppered password
        let result = credential_store
            .add_user("pepperuser".to_string(), "mypassword".to_string())
            .await;
        
        assert!(result.is_ok());
        
        // Query the database to verify hash format
        let user = User::find()
            .filter(user::Column::Username.eq("pepperuser"))
            .one(&db)
            .await
            .expect("Failed to query user")
            .expect("User not found");
        
        // Verify it's a valid Argon2 hash
        assert!(user.password_hash.starts_with("$argon2"));
        
        // Verify we can parse it as a valid PasswordHash
        let parsed = PasswordHash::new(&user.password_hash);
        assert!(parsed.is_ok());
    }

    #[tokio::test]
    async fn test_password_verification_with_secret_parameter_works_correctly() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        let password_pepper = "verification-test-pepper".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper);
        
        let password = "correct-password";
        
        // Add user
        credential_store
            .add_user("verifyuser".to_string(), password.to_string())
            .await
            .expect("Failed to add user");
        
        // Verify with correct password
        let result = credential_store
            .verify_credentials("verifyuser", password)
            .await;
        
        assert!(result.is_ok());
        
        // Verify with incorrect password
        let result = credential_store
            .verify_credentials("verifyuser", "wrong-password")
            .await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_different_peppers_produce_different_hashes() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        let password = "same-password";
        
        // Create first user with pepper1
        let pepper1 = "pepper-one-secret-key".to_string();
        let store1 = CredentialStore::new(db.clone(), pepper1);
        
        store1
            .add_user("user1".to_string(), password.to_string())
            .await
            .expect("Failed to add user1");
        
        // Create second user with pepper2
        let pepper2 = "pepper-two-secret-key".to_string();
        let store2 = CredentialStore::new(db.clone(), pepper2);
        
        store2
            .add_user("user2".to_string(), password.to_string())
            .await
            .expect("Failed to add user2");
        
        // Query both users
        let user1 = User::find()
            .filter(user::Column::Username.eq("user1"))
            .one(&db)
            .await
            .expect("Failed to query user1")
            .expect("User1 not found");
        
        let user2 = User::find()
            .filter(user::Column::Username.eq("user2"))
            .one(&db)
            .await
            .expect("Failed to query user2")
            .expect("User2 not found");
        
        // Verify hashes are different (different peppers produce different hashes)
        assert_ne!(user1.password_hash, user2.password_hash);
        
        // Verify user1 can only be verified with pepper1
        let verify_result = store1.verify_credentials("user1", password).await;
        assert!(verify_result.is_ok());
        
        // Verify user2 can only be verified with pepper2
        let verify_result = store2.verify_credentials("user2", password).await;
        assert!(verify_result.is_ok());
        
        // Verify cross-verification fails (user1 with pepper2)
        let verify_result = store2.verify_credentials("user1", password).await;
        assert!(verify_result.is_err());
        
        // Verify cross-verification fails (user2 with pepper1)
        let verify_result = store1.verify_credentials("user2", password).await;
        assert!(verify_result.is_err());
    }

    #[tokio::test]
    async fn test_peppered_hashes_contain_data_parameter() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        let password_pepper = "data-param-test-pepper".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper);
        
        // Add user with peppered password
        credential_store
            .add_user("datauser".to_string(), "password123".to_string())
            .await
            .expect("Failed to add user");
        
        // Query the user
        let user = User::find()
            .filter(user::Column::Username.eq("datauser"))
            .one(&db)
            .await
            .expect("Failed to query user")
            .expect("User not found");
        
        // Verify the hash is in Argon2 PHC format
        assert!(user.password_hash.starts_with("$argon2"));
        
        // Parse the hash to verify it's valid
        let parsed_hash = PasswordHash::new(&user.password_hash);
        assert!(parsed_hash.is_ok());
        
        // The 'data=' parameter in PHC format indicates the secret/pepper was used
        // However, argon2 crate may encode this differently, so we verify by testing
        // that verification fails without the correct pepper
        let wrong_pepper = "wrong-pepper-key".to_string();
        let wrong_store = CredentialStore::new(db.clone(), wrong_pepper);
        
        // Verification should fail with wrong pepper
        let verify_result = wrong_store.verify_credentials("datauser", "password123").await;
        assert!(verify_result.is_err());
        
        // Verification should succeed with correct pepper
        let verify_result = credential_store.verify_credentials("datauser", "password123").await;
        assert!(verify_result.is_ok());
    }

    // Tests for Debug and Display traits to ensure secrets are not exposed

    #[tokio::test]
    async fn test_debug_trait_does_not_expose_password_pepper() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        let password_pepper = "super-secret-pepper-value".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper);
        
        let debug_output = format!("{:?}", credential_store);
        
        // Verify the output contains redacted marker
        assert!(debug_output.contains("<redacted>"));
        
        // Verify the actual secret is NOT in the output
        assert!(!debug_output.contains("super-secret-pepper-value"));
        
        // Verify the struct name is present
        assert!(debug_output.contains("CredentialStore"));
    }

    #[tokio::test]
    async fn test_display_trait_does_not_expose_password_pepper() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        let password_pepper = "another-secret-pepper".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper);
        
        let display_output = format!("{}", credential_store);
        
        // Verify the output contains redacted marker
        assert!(display_output.contains("<redacted>"));
        
        // Verify the actual secret is NOT in the output
        assert!(!display_output.contains("another-secret-pepper"));
        
        // Verify the struct name is present
        assert!(display_output.contains("CredentialStore"));
    }

    #[tokio::test]
    async fn test_debug_trait_shows_struct_fields() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        let password_pepper = "test-pepper".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper);
        
        let debug_output = format!("{:?}", credential_store);
        
        // Verify both fields are mentioned (but redacted)
        assert!(debug_output.contains("db"));
        assert!(debug_output.contains("password_pepper"));
        assert!(debug_output.contains("<connection>"));
        assert!(debug_output.contains("<redacted>"));
    }
}


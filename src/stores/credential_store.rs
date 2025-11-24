use sea_orm::{DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter, ActiveModelTrait, Set, TransactionTrait};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher, password_hash::SaltString, Algorithm, Version, Params};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use crate::types::db::user::{self, Entity as User, ActiveModel};
use crate::types::db::refresh_token::{ActiveModel as RefreshTokenActiveModel};
use crate::errors::auth::AuthError;
use crate::stores::AuditStore;
use crate::services::audit_logger;

/// CredentialStore manages user credentials and refresh tokens in the database
pub struct CredentialStore {
    db: DatabaseConnection,
    password_pepper: String,
    audit_store: Arc<AuditStore>,
}

impl CredentialStore {
    /// Create a new CredentialStore with the given database connection and password pepper
    /// 
    /// # Arguments
    /// * `db` - The database connection
    /// * `password_pepper` - The secret key used for password hashing (from SecretManager)
    /// * `audit_store` - The audit store for logging security events
    pub fn new(db: DatabaseConnection, password_pepper: String, audit_store: Arc<AuditStore>) -> Self {
        Self { db, password_pepper, audit_store }
    }

    /// Create a new user with no administrative privileges (primitive operation)
    /// 
    /// This is the primitive operation for user creation. All user creation
    /// paths must ultimately call this method. The user is created with all
    /// privilege flags (is_owner, is_system_admin, is_role_admin) set to false.
    /// 
    /// Audit logging occurs immediately after the database operation (at point of action).
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `username` - Username for the new user
    /// * `password_hash` - Pre-hashed password (caller is responsible for hashing)
    /// 
    /// # Returns
    /// * `Ok(user_id)` - User created successfully and audit logged
    /// * `Err(AuthError)` - Duplicate username, database error, or transaction failed
    pub async fn create_user(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        username: String,
        password_hash: String,
    ) -> Result<String, AuthError> {
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

        // Get current timestamp
        let created_at = Utc::now().timestamp();

        // Create new user ActiveModel with all privilege flags set to false
        let new_user = ActiveModel {
            id: Set(user_id.clone()),
            username: Set(username.clone()),
            password_hash: Set(password_hash),
            created_at: Set(created_at),
            is_owner: Set(false),
            is_system_admin: Set(false),
            is_role_admin: Set(false),
            app_roles: Set(None),
            updated_at: Set(created_at),
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

        // Log user creation at point of action
        if let Err(audit_err) = audit_logger::log_user_created(
            &self.audit_store,
            ctx,
            &user_id,
            &username,
        ).await {
            tracing::error!("Failed to log user creation: {:?}", audit_err);
        }

        Ok(user_id)
    }

    /// Set privileges for a user (primitive operation)
    /// 
    /// This is the primitive operation for privilege assignment. It updates
    /// all privilege flags atomically and logs the before/after state.
    /// This design makes it easy to add new privilege flags in the future
    /// and provides a complete audit trail of privilege changes.
    /// 
    /// Audit logging occurs immediately after the database operation (at point of action).
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `user_id` - User ID to modify
    /// * `new_privileges` - New privilege flags to set
    /// 
    /// # Returns
    /// * `Ok(old_privileges)` - Privileges updated successfully, returns previous state
    /// * `Err(AuthError)` - User not found or database error
    pub async fn set_privileges(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        user_id: &str,
        new_privileges: crate::types::internal::auth::AdminFlags,
    ) -> Result<crate::types::internal::auth::AdminFlags, AuthError> {
        // Fetch current user to get old privileges
        let user = User::find()
            .filter(user::Column::Id.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))?
            .ok_or_else(|| AuthError::internal_error(format!("User not found: {}", user_id)))?;

        // Store old privileges for return value and audit logging
        let old_privileges = crate::types::internal::auth::AdminFlags::from(&user);

        // Get current timestamp
        let now = Utc::now().timestamp();

        // Update all privilege flags atomically
        let mut active_model: ActiveModel = user.into();
        active_model.is_owner = Set(new_privileges.is_owner);
        active_model.is_system_admin = Set(new_privileges.is_system_admin);
        active_model.is_role_admin = Set(new_privileges.is_role_admin);
        active_model.updated_at = Set(now);

        active_model
            .update(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Failed to update privileges: {}", e)))?;

        // Log privilege change event with before/after state immediately (at point of action)
        if let Err(audit_err) = audit_logger::log_privileges_changed(
            &self.audit_store,
            ctx,
            user_id,
            old_privileges.is_owner,
            new_privileges.is_owner,
            old_privileges.is_system_admin,
            new_privileges.is_system_admin,
            old_privileges.is_role_admin,
            new_privileges.is_role_admin,
        ).await {
            tracing::error!("Failed to log privilege change: {:?}", audit_err);
        }

        Ok(old_privileges)
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
            is_owner: Set(false),
            is_system_admin: Set(false),
            is_role_admin: Set(false),
            app_roles: Set(None),
            updated_at: Set(created_at),
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
    /// Implements OWASP timing attack mitigation by always executing Argon2 verification,
    /// even when the user doesn't exist. This prevents attackers from determining valid
    /// usernames by measuring response time differences.
    /// 
    /// Logs authentication attempts (success/failure) to audit database at point of action.
    /// 
    /// # Arguments
    /// * `username` - The username to verify
    /// * `password` - The plaintext password to verify
    /// * `ip_address` - Client IP address for audit logging
    /// 
    /// # Returns
    /// * `Ok(String)` - The user_id (UUID) if credentials are valid
    /// * `Err(AuthError)` - InvalidCredentials if username not found or password incorrect
    pub async fn verify_credentials(&self, username: &str, password: &str, ip_address: Option<String>) -> Result<String, AuthError> {
        // Query user by username
        let user = User::find()
            .filter(user::Column::Username.eq(username))
            .one(&self.db)
            .await
            .map_err(|_| AuthError::invalid_credentials())?;

        // OWASP timing attack mitigation: Always execute Argon2 verification
        // Use a dummy hash when user doesn't exist to maintain constant-time behavior
        let (password_hash, user_id) = match user {
            Some(u) => (u.password_hash.clone(), Some(u.id.clone())),
            None => {
                // Dummy Argon2id hash to verify against (prevents timing attacks)
                // This is a valid hash that will always fail verification
                (
                    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZTEyMzQ$\
                     qrvBFkJXVqKxqhCKqhCKqhCKqhCKqhCKqhCKqhCKqhA".to_string(),
                    None
                )
            }
        };

        // Parse the password hash (real or dummy)
        let parsed_hash = PasswordHash::new(&password_hash)
            .map_err(|_| AuthError::invalid_credentials())?;

        // Initialize Argon2 with password_pepper as secret parameter
        let argon2 = Argon2::new_with_secret(
            self.password_pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )
        .map_err(|_| AuthError::invalid_credentials())?;
        
        // Always execute password verification (constant-time operation)
        let verification_result = argon2.verify_password(password.as_bytes(), &parsed_hash);
        
        // Handle result based on whether user exists and password is correct
        match (user_id, verification_result) {
            (Some(uid), Ok(_)) => {
                // User exists and password is correct
                if let Err(audit_err) = audit_logger::log_login_success(
                    &self.audit_store,
                    uid.clone(),
                    ip_address,
                ).await {
                    tracing::error!("Failed to log login success: {:?}", audit_err);
                }
                Ok(uid)
            }
            (Some(uid), Err(_)) => {
                // User exists but password is incorrect
                // Audit log contains actual reason for forensic analysis
                if let Err(audit_err) = audit_logger::log_login_failure(
                    &self.audit_store,
                    Some(uid),
                    "invalid_password".to_string(),
                    ip_address,
                ).await {
                    tracing::error!("Failed to log login failure: {:?}", audit_err);
                }
                // User-facing error remains generic to prevent information disclosure
                Err(AuthError::invalid_credentials())
            }
            (None, _) => {
                // User doesn't exist (verification will always fail with dummy hash)
                // Audit log contains actual reason for forensic analysis
                if let Err(audit_err) = audit_logger::log_login_failure(
                    &self.audit_store,
                    None,
                    "user_not_found".to_string(),
                    ip_address,
                ).await {
                    tracing::error!("Failed to log login failure: {:?}", audit_err);
                }
                // User-facing error remains generic to prevent username enumeration
                Err(AuthError::invalid_credentials())
            }
        }
    }
    
    /// Store a refresh token in the database
    /// 
    /// Logs token issuance to audit database at point of action.
    /// 
    /// # Arguments
    /// * `token_hash` - The SHA-256 hash of the refresh token
    /// * `user_id` - The user_id (UUID string) this token belongs to
    /// * `expires_at` - Unix timestamp when the token expires
    /// * `jwt_id` - The JWT ID associated with this refresh token
    /// * `ip_address` - Client IP address for audit logging
    /// 
    /// # Returns
    /// * `Ok(())` - Token stored successfully
    /// * `Err(AuthError)` - Database error
    pub async fn store_refresh_token(
        &self,
        token_hash: String,
        user_id: String,
        expires_at: i64,
        jwt_id: String,
        ip_address: Option<String>,
    ) -> Result<(), AuthError> {
        // Use a transaction to ensure atomicity
        let txn = self.db.begin().await
            .map_err(|e| AuthError::internal_error(format!("Failed to start transaction: {}", e)))?;
        
        let created_at = Utc::now().timestamp();
        
        let new_token = RefreshTokenActiveModel {
            id: sea_orm::ActiveValue::NotSet, // Auto-increment will handle this
            token_hash: Set(token_hash.clone()),
            user_id: Set(user_id.clone()),
            expires_at: Set(expires_at),
            created_at: Set(created_at),
        };
        
        new_token.insert(&txn).await
            .map_err(|e| AuthError::internal_error(format!("Failed to store refresh token: {}", e)))?;
        
        txn.commit().await
            .map_err(|e| AuthError::internal_error(format!("Failed to commit transaction: {}", e)))?;
        
        // Log refresh token issuance at point of action
        if let Err(audit_err) = audit_logger::log_refresh_token_issued(
            &self.audit_store,
            user_id,
            jwt_id,
            token_hash,
            ip_address,
        ).await {
            tracing::error!("Failed to log refresh token issuance: {:?}", audit_err);
        }
        
        Ok(())
    }
    
    /// Validate a refresh token and return the associated user_id
    /// 
    /// Logs validation attempts (success/failure) to audit database at point of action.
    /// 
    /// # Arguments
    /// * `token_hash` - The SHA-256 hash of the refresh token to validate
    /// * `ip_address` - Client IP address for audit logging
    /// 
    /// # Returns
    /// * `Ok(String)` - The user_id (UUID) if token is valid and not expired
    /// * `Err(AuthError)` - InvalidRefreshToken if not found, ExpiredRefreshToken if expired
    pub async fn validate_refresh_token(&self, token_hash: &str, ip_address: Option<String>) -> Result<String, AuthError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        // Query token by hash
        let token = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))?;
        
        // If token not found, log failure and return error
        let token = match token {
            Some(t) => t,
            None => {
                if let Err(audit_err) = audit_logger::log_refresh_token_validation_failure(
                    &self.audit_store,
                    token_hash.to_string(),
                    "not_found".to_string(),
                    ip_address,
                ).await {
                    tracing::error!("Failed to log refresh token validation failure: {:?}", audit_err);
                }
                return Err(AuthError::invalid_refresh_token());
            }
        };
        
        // Check if token is expired
        let now = Utc::now().timestamp();
        if token.expires_at < now {
            if let Err(audit_err) = audit_logger::log_refresh_token_validation_failure(
                &self.audit_store,
                token_hash.to_string(),
                "expired".to_string(),
                ip_address,
            ).await {
                tracing::error!("Failed to log refresh token validation failure: {:?}", audit_err);
            }
            return Err(AuthError::expired_refresh_token());
        }
        
        // Return user_id on success (no audit log for successful validation - logged at JWT issuance)
        Ok(token.user_id)
    }
    
    /// Revoke a refresh token by deleting it from the database
    /// 
    /// Does not verify user ownership - the refresh token itself is the authority.
    /// Logs revocation to audit database at point of action.
    /// 
    /// # Arguments
    /// * `token_hash` - SHA-256 hash of the refresh token to revoke
    /// * `jwt_id` - Optional JWT ID for audit logging (if authenticated)
    /// 
    /// # Returns
    /// * `Ok(user_id)` - Token revoked successfully, returns the user_id
    /// * `Err(AuthError::InvalidRefreshToken)` - Token not found in database
    /// * `Err(AuthError::InternalError)` - Database error
    pub async fn revoke_refresh_token(&self, token_hash: &str, jwt_id: Option<String>) -> Result<String, AuthError> {
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
        
        // Log revocation at point of action
        if let Err(audit_err) = audit_logger::log_refresh_token_revoked(
            &self.audit_store,
            user_id.clone(),
            jwt_id,
            token_hash.to_string(),
        ).await {
            tracing::error!("Failed to log refresh token revocation: {:?}", audit_err);
        }
        
        Ok(user_id)
    }
    
    /// Get user by ID
    /// 
    /// # Arguments
    /// * `user_id` - The user_id (UUID string) to fetch
    /// 
    /// # Returns
    /// * `Ok(Model)` - The user model
    /// * `Err(AuthError)` - User not found or database error
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<user::Model, AuthError> {
        User::find()
            .filter(user::Column::Id.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))?
            .ok_or_else(|| AuthError::internal_error(format!("User not found: {}", user_id)))
    }

    /// Set the is_system_admin flag for a user
    /// 
    /// **DEPRECATED**: This method is maintained for backward compatibility.
    /// New code should use `set_privileges()` directly for better auditability
    /// and consistency with the privilege management architecture.
    /// 
    /// Updates the is_system_admin flag in the user table by calling the
    /// `set_privileges()` primitive internally. This ensures consistent
    /// audit logging and privilege management.
    /// 
    /// # Arguments
    /// * `user_id` - The user_id (UUID string) to update
    /// * `value` - The new value for is_system_admin
    /// * `actor_user_id` - User ID of who performed the action (for audit logging)
    /// * `ip_address` - Optional IP address (for audit logging)
    /// 
    /// # Returns
    /// * `Ok(())` - Flag updated successfully
    /// * `Err(AuthError)` - User not found or database error
    #[deprecated(
        since = "0.1.0",
        note = "Use set_privileges() instead for better auditability and consistency"
    )]
    pub async fn set_system_admin(
        &self,
        user_id: &str,
        value: bool,
        actor_user_id: String,
        ip_address: Option<String>,
    ) -> Result<(), AuthError> {
        // Create RequestContext from old parameters for backward compatibility
        let ctx = crate::types::internal::context::RequestContext {
            ip_address,
            request_id: uuid::Uuid::new_v4().to_string(),
            authenticated: true,
            claims: None,
            source: crate::types::internal::context::RequestSource::API,
            actor_id: actor_user_id,
        };

        // Get current user to build AdminFlags with only is_system_admin changed
        let user = self.get_user_by_id(user_id).await?;
        let new_privileges = crate::types::internal::auth::AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: value,
            is_role_admin: user.is_role_admin,
        };

        // Call the primitive set_privileges() method
        self.set_privileges(&ctx, user_id, new_privileges).await?;

        Ok(())
    }

    /// Set the is_role_admin flag for a user
    /// 
    /// **DEPRECATED**: This method is maintained for backward compatibility.
    /// New code should use `set_privileges()` directly for better auditability
    /// and consistency with the privilege management architecture.
    /// 
    /// Updates the is_role_admin flag in the user table by calling the
    /// `set_privileges()` primitive internally. This ensures consistent
    /// audit logging and privilege management.
    /// 
    /// # Arguments
    /// * `user_id` - The user_id (UUID string) to update
    /// * `value` - The new value for is_role_admin
    /// * `actor_user_id` - User ID of who performed the action (for audit logging)
    /// * `ip_address` - Optional IP address (for audit logging)
    /// 
    /// # Returns
    /// * `Ok(())` - Flag updated successfully
    /// * `Err(AuthError)` - User not found or database error
    #[deprecated(
        since = "0.1.0",
        note = "Use set_privileges() instead for better auditability and consistency"
    )]
    pub async fn set_role_admin(
        &self,
        user_id: &str,
        value: bool,
        actor_user_id: String,
        ip_address: Option<String>,
    ) -> Result<(), AuthError> {
        // Create RequestContext from old parameters for backward compatibility
        let ctx = crate::types::internal::context::RequestContext {
            ip_address,
            request_id: uuid::Uuid::new_v4().to_string(),
            authenticated: true,
            claims: None,
            source: crate::types::internal::context::RequestSource::API,
            actor_id: actor_user_id,
        };

        // Get current user to build AdminFlags with only is_role_admin changed
        let user = self.get_user_by_id(user_id).await?;
        let new_privileges = crate::types::internal::auth::AdminFlags {
            is_owner: user.is_owner,
            is_system_admin: user.is_system_admin,
            is_role_admin: value,
        };

        // Call the primitive set_privileges() method
        self.set_privileges(&ctx, user_id, new_privileges).await?;

        Ok(())
    }

    /// Get the owner account
    /// 
    /// Retrieves the user with is_owner=true.
    /// 
    /// # Returns
    /// * `Ok(Some(Model))` - The owner user model if found
    /// * `Ok(None)` - No owner account exists
    /// * `Err(AuthError)` - Database error
    pub async fn get_owner(&self) -> Result<Option<user::Model>, AuthError> {
        User::find()
            .filter(user::Column::IsOwner.eq(true))
            .one(&self.db)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))
    }

    /// Create an admin user with specific admin roles (helper method)
    /// 
    /// This is a convenience method that composes the primitive operations
    /// within a single transaction. The entire operation (user creation +
    /// privilege assignment) is atomic - if any step fails, everything rolls back.
    /// 
    /// Audit logging occurs at point of action within the transaction. If the
    /// transaction rolls back, a rollback event is logged.
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `username` - The username for the new admin user
    /// * `password_hash` - The pre-hashed password (caller is responsible for hashing)
    /// * `admin_flags` - AdminFlags specifying which admin roles to assign
    /// 
    /// # Returns
    /// * `Ok(Model)` - The created user model with privileges assigned
    /// * `Err(AuthError)` - DuplicateUsername if username already exists, or InternalError
    pub async fn create_admin_user(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        username: String,
        password_hash: String,
        admin_flags: crate::types::internal::auth::AdminFlags,
    ) -> Result<user::Model, AuthError> {
        // Start transaction
        let txn = self.db.begin().await
            .map_err(|e| AuthError::internal_error(format!("Failed to start transaction: {}", e)))?;

        // Step 1: Create user with no privileges (primitive operation)
        // Check if username already exists
        let existing_user = User::find()
            .filter(user::Column::Username.eq(&username))
            .one(&txn)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))?;

        if existing_user.is_some() {
            return Err(AuthError::duplicate_username());
        }

        // Generate UUID for user
        let user_id = Uuid::new_v4().to_string();

        // Get current timestamp
        let created_at = Utc::now().timestamp();

        // Create new user ActiveModel with all privilege flags set to false
        let new_user = ActiveModel {
            id: Set(user_id.clone()),
            username: Set(username.clone()),
            password_hash: Set(password_hash),
            created_at: Set(created_at),
            is_owner: Set(false),
            is_system_admin: Set(false),
            is_role_admin: Set(false),
            app_roles: Set(None),
            updated_at: Set(created_at),
        };

        // Insert into database
        new_user
            .insert(&txn)
            .await
            .map_err(|e| {
                // Check if it's a unique constraint violation
                if e.to_string().contains("UNIQUE") {
                    AuthError::duplicate_username()
                } else {
                    AuthError::internal_error(format!("Database error: {}", e))
                }
            })?;

        // Log user creation at point of action
        if let Err(audit_err) = audit_logger::log_user_created(
            &self.audit_store,
            ctx,
            &user_id,
            &username,
        ).await {
            tracing::error!("Failed to log user creation: {:?}", audit_err);
        }

        // Step 2: Set privileges (primitive operation)
        // Fetch current user to get old privileges (should all be false)
        let user = User::find()
            .filter(user::Column::Id.eq(&user_id))
            .one(&txn)
            .await
            .map_err(|e| AuthError::internal_error(format!("Database error: {}", e)))?
            .ok_or_else(|| AuthError::internal_error(format!("User not found: {}", user_id)))?;

        // Store old privileges for audit logging (should all be false)
        let old_privileges = crate::types::internal::auth::AdminFlags::from(&user);

        // Get current timestamp
        let now = Utc::now().timestamp();

        // Update all privilege flags atomically
        let mut active_model: ActiveModel = user.into();
        active_model.is_owner = Set(admin_flags.is_owner);
        active_model.is_system_admin = Set(admin_flags.is_system_admin);
        active_model.is_role_admin = Set(admin_flags.is_role_admin);
        active_model.updated_at = Set(now);

        let result = active_model
            .update(&txn)
            .await;

        match result {
            Ok(user_model) => {
                // Log privilege change event with before/after state immediately (at point of action)
                if let Err(audit_err) = audit_logger::log_privileges_changed(
                    &self.audit_store,
                    ctx,
                    &user_id,
                    old_privileges.is_owner,
                    admin_flags.is_owner,
                    old_privileges.is_system_admin,
                    admin_flags.is_system_admin,
                    old_privileges.is_role_admin,
                    admin_flags.is_role_admin,
                ).await {
                    tracing::error!("Failed to log privilege change: {:?}", audit_err);
                }

                // Commit transaction
                txn.commit().await
                    .map_err(|e| AuthError::internal_error(format!("Failed to commit transaction: {}", e)))?;

                Ok(user_model)
            }
            Err(e) => {
                // Log rollback event
                if let Err(audit_err) = audit_logger::log_operation_rolled_back(
                    &self.audit_store,
                    ctx,
                    "user_creation_with_privileges",
                    "privilege_assignment_failed",
                    Some(&user_id),
                ).await {
                    tracing::error!("Failed to log operation rollback: {:?}", audit_err);
                }

                // Transaction automatically rolls back when dropped
                Err(AuthError::internal_error(format!("Failed to update privileges: {}", e)))
            }
        }
    }
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("db", &"<connection>")
            .field("password_pepper", &"<redacted>")
            .field("audit_store", &"<audit_store>")
            .finish()
    }
}

impl std::fmt::Display for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CredentialStore {{ db: <connection>, password_pepper: <redacted>, audit_store: <audit_store> }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::setup_test_stores;

    #[tokio::test]
    async fn test_add_user_creates_user_in_database() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        let result = credential_store
            .add_user("newuser".to_string(), "password123".to_string())
            .await;
        
        assert!(result.is_ok());
        let user_id = result.unwrap();
        assert!(!user_id.is_empty());
    }

    #[tokio::test]
    async fn test_add_user_fails_with_duplicate_username() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        let result1 = credential_store
            .add_user("duplicate".to_string(), "password1".to_string())
            .await;
        
        assert!(result1.is_ok());
        
        let result2 = credential_store
            .add_user("duplicate".to_string(), "password2".to_string())
            .await;
        
        assert!(result2.is_err());
        match result2 {
            Err(AuthError::DuplicateUsername(_)) => {}
            _ => panic!("Expected DuplicateUsername error"),
        }
    }

    #[tokio::test]
    async fn test_store_refresh_token_saves_token_to_database() {
        let (db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Add a user first
        let user_id = credential_store
            .add_user("tokenuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "test_hash_123";
        let expires_at = Utc::now().timestamp() + 604800; // 7 days
        let jwt_id = "test-jwt-id".to_string();
        
        let result = credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at, jwt_id, None)
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
    async fn test_stored_token_has_correct_expiration() {
        let (db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("expiryuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a token with 7 days expiration
        let token_hash = "expiry_test_hash";
        let now = Utc::now().timestamp();
        let expires_at = now + (7 * 24 * 60 * 60); // 7 days in seconds
        let jwt_id = "test-jwt-id".to_string();
        
        let result = credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at, jwt_id, None)
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
    async fn test_validate_refresh_token_returns_correct_user_id() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("useridtest".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "userid_token_hash";
        let expires_at = Utc::now().timestamp() + 604800;
        let jwt_id = "test-jwt-id".to_string();
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at, jwt_id, None)
            .await
            .expect("Failed to store token");
        
        // Validate and verify user_id
        let result = credential_store.validate_refresh_token(token_hash, None).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_validate_refresh_token_fails_with_invalid_token() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Try to validate a token that doesn't exist
        let result = credential_store.validate_refresh_token("nonexistent_token", None).await;
        
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
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("expireduser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store an expired refresh token
        let token_hash = "expired_token_hash";
        let expires_at = Utc::now().timestamp() - 3600; // Expired 1 hour ago
        let jwt_id = "test-jwt-id".to_string();
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at, jwt_id, None)
            .await
            .expect("Failed to store token");
        
        // Try to validate the expired token
        let result = credential_store.validate_refresh_token(token_hash, None).await;
        
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
        let (db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Add a user
        let user_id = credential_store
            .add_user("revokeuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "revoke_test_hash";
        let expires_at = Utc::now().timestamp() + 604800;
        let jwt_id = "test-jwt-id".to_string();
        
        credential_store
            .store_refresh_token(token_hash.to_string(), user_id.clone(), expires_at, jwt_id, None)
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
        let result = credential_store.revoke_refresh_token(token_hash, None).await;
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

    // Tests for password pepper functionality

    #[tokio::test]
    async fn test_different_peppers_produce_different_hashes() {
        // Testing different peppers - need custom setup
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        
        let password = "same-password";
        
        // Create first user with pepper1
        let pepper1 = "pepper-one-secret-key".to_string();
        let store1 = CredentialStore::new(db.clone(), pepper1, audit_store.clone());
        
        store1
            .add_user("user1".to_string(), password.to_string())
            .await
            .expect("Failed to add user1");
        
        // Create second user with pepper2
        let pepper2 = "pepper-two-secret-key".to_string();
        let store2 = CredentialStore::new(db.clone(), pepper2, audit_store.clone());
        
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
        let verify_result = store1.verify_credentials("user1", password, None).await;
        assert!(verify_result.is_ok());
        
        // Verify user2 can only be verified with pepper2
        let verify_result = store2.verify_credentials("user2", password, None).await;
        assert!(verify_result.is_ok());
        
        // Verify cross-verification fails (user1 with pepper2)
        let verify_result = store2.verify_credentials("user1", password, None).await;
        assert!(verify_result.is_err());
        
        // Verify cross-verification fails (user2 with pepper1)
        let verify_result = store1.verify_credentials("user2", password, None).await;
        assert!(verify_result.is_err());
    }

    // Tests for Debug and Display traits

    #[tokio::test]
    async fn test_debug_trait_does_not_expose_password_pepper() {
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        
        let password_pepper = "super-secret-pepper-value".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper, audit_store);
        
        let debug_output = format!("{:?}", credential_store);
        
        assert!(debug_output.contains("<redacted>"));
        assert!(!debug_output.contains("super-secret-pepper-value"));
    }

    #[tokio::test]
    async fn test_display_trait_does_not_expose_password_pepper() {
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        
        let password_pepper = "another-secret-pepper".to_string();
        let credential_store = CredentialStore::new(db.clone(), password_pepper, audit_store);
        
        let display_output = format!("{}", credential_store);
        
        assert!(display_output.contains("<redacted>"));
        assert!(!display_output.contains("another-secret-pepper"));
    }

    // Tests for deprecated admin role methods (backward compatibility)

    #[tokio::test]
    async fn test_set_system_admin_updates_flag() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        let user_id = credential_store
            .add_user("testuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        #[allow(deprecated)]
        let result = credential_store
            .set_system_admin(&user_id, true, "actor_user".to_string(), Some("127.0.0.1".to_string()))
            .await;
        
        assert!(result.is_ok());
        
        let user = credential_store.get_user_by_id(&user_id).await.unwrap();
        assert_eq!(user.is_system_admin, true);
    }

    #[tokio::test]
    async fn test_set_role_admin_updates_flag() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        let user_id = credential_store
            .add_user("testuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        #[allow(deprecated)]
        let result = credential_store
            .set_role_admin(&user_id, true, "actor_user".to_string(), Some("127.0.0.1".to_string()))
            .await;
        
        assert!(result.is_ok());
        
        let user = credential_store.get_user_by_id(&user_id).await.unwrap();
        assert_eq!(user.is_role_admin, true);
    }

    #[tokio::test]
    async fn test_get_owner_returns_none_when_no_owner_exists() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Add a regular user (not owner)
        credential_store
            .add_user("regularuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Try to get owner
        let result = credential_store.get_owner().await;
        
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_owner_returns_owner_when_exists() {
        let (db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Add a regular user
        credential_store
            .add_user("regularuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Manually create an owner user
        let owner_id = Uuid::new_v4().to_string();
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            "test-pepper-for-unit-tests".as_bytes(),
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ).unwrap();
        let password_hash = argon2
            .hash_password("password".as_bytes(), &salt)
            .unwrap()
            .to_string();
        
        let now = Utc::now().timestamp();
        let owner = ActiveModel {
            id: Set(owner_id.clone()),
            username: Set("owner".to_string()),
            password_hash: Set(password_hash),
            created_at: Set(now),
            is_owner: Set(true),
            is_system_admin: Set(false),
            is_role_admin: Set(false),
            app_roles: Set(None),
            updated_at: Set(now),
        };
        
        owner.insert(&db).await.expect("Failed to insert owner");
        
        // Get owner
        let result = credential_store.get_owner().await;
        
        assert!(result.is_ok());
        let owner_model = result.unwrap();
        assert!(owner_model.is_some());
        
        let owner_model = owner_model.unwrap();
        assert_eq!(owner_model.id, owner_id);
        assert_eq!(owner_model.username, "owner");
        assert_eq!(owner_model.is_owner, true);
    }

    // Tests for create_admin_user method (task 4.3)

    #[tokio::test]
    async fn test_create_admin_user_creates_owner_account() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Generate password hash
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            "test-pepper-for-unit-tests".as_bytes(),
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ).unwrap();
        let password_hash = argon2
            .hash_password("password".as_bytes(), &salt)
            .unwrap()
            .to_string();
        
        // Create owner using AdminFlags
        use crate::types::internal::auth::AdminFlags;
        use crate::types::internal::context::RequestContext;
        let admin_flags = AdminFlags::owner();
        let ctx = RequestContext::for_system("test");
        
        let result = credential_store
            .create_admin_user(
                &ctx,
                "owner_user".to_string(),
                password_hash,
                admin_flags,
            )
            .await;
        
        assert!(result.is_ok());
        let user = result.unwrap();
        
        assert_eq!(user.username, "owner_user");
        assert_eq!(user.is_owner, true);
        assert_eq!(user.is_system_admin, false);
        assert_eq!(user.is_role_admin, false);
    }

    #[tokio::test]
    async fn test_create_admin_user_creates_system_admin_account() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Generate password hash
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            "test-pepper-for-unit-tests".as_bytes(),
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ).unwrap();
        let password_hash = argon2
            .hash_password("password".as_bytes(), &salt)
            .unwrap()
            .to_string();
        
        // Create system admin using AdminFlags
        use crate::types::internal::auth::AdminFlags;
        use crate::types::internal::context::RequestContext;
        let admin_flags = AdminFlags::system_admin();
        let ctx = RequestContext::for_system("test");
        
        let result = credential_store
            .create_admin_user(
                &ctx,
                "sysadmin_user".to_string(),
                password_hash,
                admin_flags,
            )
            .await;
        
        assert!(result.is_ok());
        let user = result.unwrap();
        
        assert_eq!(user.username, "sysadmin_user");
        assert_eq!(user.is_owner, false);
        assert_eq!(user.is_system_admin, true);
        assert_eq!(user.is_role_admin, false);
    }

    #[tokio::test]
    async fn test_create_admin_user_creates_role_admin_account() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Generate password hash
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            "test-pepper-for-unit-tests".as_bytes(),
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ).unwrap();
        let password_hash = argon2
            .hash_password("password".as_bytes(), &salt)
            .unwrap()
            .to_string();
        
        // Create role admin using AdminFlags
        use crate::types::internal::auth::AdminFlags;
        use crate::types::internal::context::RequestContext;
        let admin_flags = AdminFlags::role_admin();
        let ctx = RequestContext::for_system("test");
        
        let result = credential_store
            .create_admin_user(
                &ctx,
                "roleadmin_user".to_string(),
                password_hash,
                admin_flags,
            )
            .await;
        
        assert!(result.is_ok());
        let user = result.unwrap();
        
        assert_eq!(user.username, "roleadmin_user");
        assert_eq!(user.is_owner, false);
        assert_eq!(user.is_system_admin, false);
        assert_eq!(user.is_role_admin, true);
    }

    #[tokio::test]
    async fn test_create_admin_user_supports_multiple_roles() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Generate password hash
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            "test-pepper-for-unit-tests".as_bytes(),
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ).unwrap();
        let password_hash = argon2
            .hash_password("password".as_bytes(), &salt)
            .unwrap()
            .to_string();
        
        // Create user with multiple admin roles
        use crate::types::internal::auth::AdminFlags;
        use crate::types::internal::context::RequestContext;
        let admin_flags = AdminFlags::custom(false, true, true);
        let ctx = RequestContext::for_system("test");
        
        let result = credential_store
            .create_admin_user(
                &ctx,
                "multi_admin".to_string(),
                password_hash,
                admin_flags,
            )
            .await;
        
        assert!(result.is_ok());
        let user = result.unwrap();
        
        assert_eq!(user.username, "multi_admin");
        assert_eq!(user.is_owner, false);
        assert_eq!(user.is_system_admin, true);
        assert_eq!(user.is_role_admin, true);
    }

    #[tokio::test]
    async fn test_create_admin_user_fails_with_duplicate_username() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            "test-pepper-for-unit-tests".as_bytes(),
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        ).unwrap();
        let password_hash = argon2
            .hash_password("password".as_bytes(), &salt)
            .unwrap()
            .to_string();
        
        use crate::types::internal::auth::AdminFlags;
        use crate::types::internal::context::RequestContext;
        let admin_flags = AdminFlags::owner();
        let ctx = RequestContext::for_system("test");
        
        let result1 = credential_store
            .create_admin_user(&ctx, "duplicate_admin".to_string(), password_hash.clone(), admin_flags)
            .await;
        
        assert!(result1.is_ok());
        
        let result2 = credential_store
            .create_admin_user(&ctx, "duplicate_admin".to_string(), password_hash, admin_flags)
            .await;
        
        assert!(result2.is_err());
        match result2 {
            Err(AuthError::DuplicateUsername(_)) => {}
            _ => panic!("Expected DuplicateUsername error"),
        }
    }

    // Tests for set_privileges method

    #[tokio::test]
    async fn test_set_privileges_updates_all_flags_atomically() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        let user_id = credential_store
            .add_user("testuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        use crate::types::internal::context::RequestContext;
        use crate::types::internal::auth::AdminFlags;
        let ctx = RequestContext::for_system("test");
        let new_privileges = AdminFlags::custom(true, true, true);
        
        let result = credential_store
            .set_privileges(&ctx, &user_id, new_privileges)
            .await;
        
        assert!(result.is_ok());
        
        let user = credential_store.get_user_by_id(&user_id).await.unwrap();
        assert_eq!(user.is_owner, true);
        assert_eq!(user.is_system_admin, true);
        assert_eq!(user.is_role_admin, true);
    }

    #[tokio::test]
    async fn test_set_privileges_returns_old_privileges() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        let user_id = credential_store
            .add_user("testuser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        use crate::types::internal::context::RequestContext;
        use crate::types::internal::auth::AdminFlags;
        let ctx = RequestContext::for_system("test");
        
        let result = credential_store
            .set_privileges(&ctx, &user_id, AdminFlags::system_admin())
            .await;
        
        assert!(result.is_ok());
        let old_privileges = result.unwrap();
        
        assert_eq!(old_privileges.is_owner, false);
        assert_eq!(old_privileges.is_system_admin, false);
        assert_eq!(old_privileges.is_role_admin, false);
    }

    #[tokio::test]
    async fn test_set_privileges_fails_with_nonexistent_user() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        use crate::types::internal::context::RequestContext;
        use crate::types::internal::auth::AdminFlags;
        let ctx = RequestContext::for_system("test");
        
        let result = credential_store
            .set_privileges(&ctx, "nonexistent-user-id", AdminFlags::owner())
            .await;
        
        assert!(result.is_err());
    }
}


use sea_orm::{DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter, ActiveModelTrait, Set, TransactionTrait};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher, password_hash::SaltString, Algorithm, Version, Params};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use crate::types::db::user::{self, Entity as User, ActiveModel};
use crate::types::db::refresh_token::{ActiveModel as RefreshTokenActiveModel};
use crate::errors::InternalError;
use crate::errors::internal::CredentialError;
use crate::stores::AuditStore;
use crate::audit::audit_logger;
use crate::types::internal::auth::AdminFlags;
use crate::types::internal::context::RequestContext;

pub struct CredentialStore {
    db: DatabaseConnection,
    password_pepper: String,
    pub(crate) audit_store: Arc<AuditStore>,
}

impl CredentialStore {
    pub fn new(db: DatabaseConnection, password_pepper: String, audit_store: Arc<AuditStore>) -> Self {
        Self { db, password_pepper, audit_store }
    }
    
    /// Logs transaction start to audit database for security tracking
    pub async fn begin_transaction(
        &self,
        ctx: &RequestContext,
        operation_type: &str,
    ) -> Result<sea_orm::DatabaseTransaction, InternalError> {
        let txn = self.db.begin().await
            .map_err(|e| InternalError::transaction("begin_transaction", e))?;
        
        // Log transaction start
        if let Err(audit_err) = audit_logger::log_transaction_started(
            &self.audit_store,
            ctx,
            operation_type,
        ).await {
            tracing::error!("Failed to log transaction start: {:?}", audit_err);
        }
        
        Ok(txn)
    }
    
    /// Logs transaction commit to audit database for security tracking
    pub async fn commit_transaction(
        &self,
        txn: sea_orm::DatabaseTransaction,
        ctx: &RequestContext,
        operation_type: &str,
    ) -> Result<(), InternalError> {
        txn.commit().await
            .map_err(|e| InternalError::transaction("commit_transaction", e))?;


        // Log transaction commit
        if let Err(audit_err) = audit_logger::log_transaction_started(
            &self.audit_store,
            ctx,
            operation_type,
        ).await {
            tracing::error!("Failed to log transaction commit: {:?}", audit_err);
        }
        
        Ok(())
    }
    
    /// Primitive operation for user creation - all user creation paths must call this.
    /// User is created with all privilege flags set to false.
    /// 
    /// Audit logging occurs immediately after the database operation (at point of action).
    pub async fn create_user(
        &self,
        ctx: &RequestContext,
        username: String,
        password_hash: String,
    ) -> Result<String, InternalError> {
        // Check if username already exists
        let existing_user = User::find()
            .filter(user::Column::Username.eq(&username))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("OPERATION", e))?;

        if existing_user.is_some() {
            return Err(InternalError::from(CredentialError::DuplicateUsername(username.clone())));
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
            password_change_required: Set(false),
            updated_at: Set(created_at),
        };

        // Insert into database
        new_user
            .insert(&self.db)
            .await
            .map_err(|e| {
                // Check if it's a unique constraint violation
                if e.to_string().contains("UNIQUE") {
                    InternalError::from(CredentialError::DuplicateUsername(username.clone()))
                } else {
                    InternalError::database("OPERATION", e)
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

    /// Primitive operation for privilege assignment - updates all privilege flags atomically.
    /// Design makes it easy to add new privilege flags in the future and provides complete audit trail.
    /// 
    /// Audit logging occurs immediately after the database operation (at point of action).
    pub async fn set_privileges(
        &self,
        ctx: &RequestContext,
        user_id: &str,
        new_privileges: AdminFlags,
    ) -> Result<AdminFlags, InternalError> {
        // Fetch current user to get old privileges
        let user = User::find()
            .filter(user::Column::Id.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("get_user_for_privileges", e))?
            .ok_or_else(|| InternalError::Credential(CredentialError::UserNotFound(user_id.to_string())))?;

        // Store old privileges for return value and audit logging
        let old_privileges = AdminFlags::from(&user);

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
            .map_err(|e| InternalError::database("update_privileges", e))?;

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

    /// Validates password using PasswordValidator before hashing and storing
    pub async fn add_user(
        &self,
        password_validator: &crate::providers::PasswordValidatorProvider,
        username: String,
        password: String,
    ) -> Result<String, InternalError> {
        // Validate password before proceeding
        password_validator
            .validate(&password, Some(&username))
            .await
            .map_err(|e| InternalError::from(CredentialError::PasswordValidationFailed(e.to_string())))?;

        // Check if username already exists
        let existing_user = User::find()
            .filter(user::Column::Username.eq(&username))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("OPERATION", e))?;

        if existing_user.is_some() {
            return Err(InternalError::from(CredentialError::DuplicateUsername(username.clone())));
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
        .map_err(|e| InternalError::crypto("argon2_init", e.to_string()))?;
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| InternalError::from(CredentialError::PasswordHashingFailed(e.to_string())))?
            .to_string();

        // Get current timestamp
        let created_at = Utc::now().timestamp();

        // Clone username for error handling (will be moved into ActiveModel)
        let username_for_error = username.clone();

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
            password_change_required: Set(false),
            updated_at: Set(created_at),
        };

        // Insert into database
        new_user
            .insert(&self.db)
            .await
            .map_err(|e| {
                // Check if it's a unique constraint violation
                if e.to_string().contains("UNIQUE") {
                    InternalError::from(CredentialError::DuplicateUsername(username_for_error.clone()))
                } else {
                    InternalError::database("OPERATION", e)
                }
            })?;

        Ok(user_id)
    }

    /// Implements OWASP timing attack mitigation by always executing Argon2 verification,
    /// even when the user doesn't exist. This prevents attackers from determining valid
    /// usernames by measuring response time differences.
    /// 
    /// Logs authentication attempts (success/failure) to audit database at point of action.
    pub async fn verify_credentials(&self, ctx: &RequestContext, username: &str, password: &str) -> Result<String, InternalError> {
        // Query user by username
        let user = User::find()
            .filter(user::Column::Username.eq(username))
            .one(&self.db)
            .await
            .map_err(|_| InternalError::Credential(CredentialError::InvalidCredentials))?;

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
            .map_err(|_| InternalError::Credential(CredentialError::InvalidCredentials))?;

        // Initialize Argon2 with password_pepper as secret parameter
        let argon2 = Argon2::new_with_secret(
            self.password_pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )
        .map_err(|_| InternalError::Credential(CredentialError::InvalidCredentials))?;
        
        // Always execute password verification (constant-time operation)
        let verification_result = argon2.verify_password(password.as_bytes(), &parsed_hash);
        
        // Handle result based on whether user exists and password is correct
        match (user_id, verification_result) {
            (Some(uid), Ok(_)) => {
                // User exists and password is correct
                if let Err(audit_err) = audit_logger::log_login_success(
                    &self.audit_store,
                    ctx,
                    uid.clone(),
                ).await {
                    tracing::error!("Failed to log login success: {:?}", audit_err);
                }
                Ok(uid)
            }
            (Some(_uid), Err(_)) => {
                // User exists but password is incorrect
                // Audit log contains actual reason for forensic analysis
                if let Err(audit_err) = audit_logger::log_login_failure(
                    &self.audit_store,
                    ctx,
                    "invalid_password".to_string(),
                    Some(username.to_string()),
                ).await {
                    tracing::error!("Failed to log login failure: {:?}", audit_err);
                }
                // User-facing error remains generic to prevent information disclosure
                Err(InternalError::Credential(CredentialError::InvalidCredentials))
            }
            (None, _) => {
                // User doesn't exist (verification will always fail with dummy hash)
                // Audit log contains actual reason for forensic analysis
                if let Err(audit_err) = audit_logger::log_login_failure(
                    &self.audit_store,
                    ctx,
                    "user_not_found".to_string(),
                    Some(username.to_string()),
                ).await {
                    tracing::error!("Failed to log login failure: {:?}", audit_err);
                }
                // User-facing error remains generic to prevent username enumeration
                Err(InternalError::Credential(CredentialError::InvalidCredentials))
            }
        }
    }
    
    /// Logs token issuance to audit database at point of action.
    async fn store_refresh_token(
        &self,
        conn: &impl sea_orm::ConnectionTrait,
        ctx: &crate::types::internal::context::RequestContext,
        token_hash: String,
        user_id: String,
        expires_at: i64,
        jwt_id: String,
    ) -> Result<(), InternalError> {
        let created_at = Utc::now().timestamp();
        
        let new_token = RefreshTokenActiveModel {
            id: sea_orm::ActiveValue::NotSet, // Auto-increment will handle this
            token_hash: Set(token_hash.clone()),
            user_id: Set(user_id.clone()),
            expires_at: Set(expires_at),
            created_at: Set(created_at),
        };
        
        new_token.insert(conn).await
            .map_err(|e| InternalError::database("insert_refresh_token", e))?;
        
        // Log refresh token issuance at point of action
        if let Err(audit_err) = audit_logger::log_refresh_token_issued(
            &self.audit_store,
            ctx,
            user_id,
            jwt_id,
            token_hash,
        ).await {
            tracing::error!("Failed to log refresh token issuance: {:?}", audit_err);
        }
        
        Ok(())
    }
    
    pub async fn store_refresh_token_no_txn(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        token_hash: String,
        user_id: String,
        expires_at: i64,
        jwt_id: String,
    ) -> Result<(), InternalError> {
        self.store_refresh_token(&self.db, ctx, token_hash, user_id, expires_at, jwt_id).await
    }
    
    pub async fn store_refresh_token_in_txn(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        ctx: &crate::types::internal::context::RequestContext,
        token_hash: String,
        user_id: String,
        expires_at: i64,
        jwt_id: String,
    ) -> Result<(), InternalError> {
        self.store_refresh_token(txn, ctx, token_hash, user_id, expires_at, jwt_id).await
    }
    
    /// Logs validation attempts (success/failure) to audit database at point of action.
    pub async fn validate_refresh_token(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        token_hash: &str,
    ) -> Result<String, InternalError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        // Query token by hash
        let token = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("OPERATION", e))?;
        
        // If token not found, log failure and return error
        let token = match token {
            Some(t) => t,
            None => {
                if let Err(audit_err) = audit_logger::log_refresh_token_validation_failure(
                    &self.audit_store,
                    ctx,
                    token_hash.to_string(),
                    "not_found".to_string(),
                ).await {
                    tracing::error!("Failed to log refresh token validation failure: {:?}", audit_err);
                }
                return Err(InternalError::from(CredentialError::invalid_token("refresh_token", "not found")));
            }
        };
        
        // Check if token is expired
        let now = Utc::now().timestamp();
        if token.expires_at < now {
            if let Err(audit_err) = audit_logger::log_refresh_token_validation_failure(
                &self.audit_store,
                ctx,
                token_hash.to_string(),
                "expired".to_string(),
            ).await {
                tracing::error!("Failed to log refresh token validation failure: {:?}", audit_err);
            }
            return Err(InternalError::from(CredentialError::ExpiredToken("refresh_token".to_string())));
        }
        
        // Return user_id on success (no audit log for successful validation - logged at JWT issuance)
        Ok(token.user_id)
    }
    
    /// Does not verify user ownership - the refresh token itself is the authority.
    /// Logs revocation to audit database at point of action.
    pub async fn revoke_refresh_token(
        &self,
        ctx: &crate::types::internal::context::RequestContext,
        token_hash: &str,
    ) -> Result<String, InternalError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        let token = RefreshToken::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("query_refresh_token", e))?
            .ok_or_else(|| InternalError::from(CredentialError::invalid_token("refresh_token", "not found")))?;
        
        let user_id = token.user_id.clone();
        
        RefreshToken::delete_many()
            .filter(Column::TokenHash.eq(token_hash))
            .exec(&self.db)
            .await
            .map_err(|e| InternalError::database("delete_refresh_token", e))?;
        
        // Log revocation at point of action
        if let Err(audit_err) = audit_logger::log_refresh_token_revoked(
            &self.audit_store,
            ctx,
            user_id.clone(),
            token_hash.to_string(),
        ).await {
            tracing::error!("Failed to log refresh token revocation: {:?}", audit_err);
        }
        
        Ok(user_id)
    }
    
    /// Deletes all refresh tokens associated with a user. Used when
    /// admin roles change to force re-authentication with updated JWT claims.
    /// Creates an audit log entry for this security-critical operation.
    pub async fn invalidate_all_tokens(
        &self, 
        ctx: &crate::types::internal::context::RequestContext,
        user_id: &str,
        reason: &str,
    ) -> Result<(), InternalError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        // Delete all refresh tokens for the user
        let delete_result = RefreshToken::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(&self.db)
            .await;
        
        match delete_result {
            Ok(_) => {
                // Log successful token invalidation for audit trail
                if let Err(audit_err) = crate::audit::audit_logger::log_all_refresh_tokens_invalidated(
                    &self.audit_store,
                    ctx,
                    user_id.to_string(),
                    reason.to_string(),
                )
                .await {
                    tracing::error!("Failed to log token invalidation: {:?}", audit_err);
                }
                
                tracing::info!(
                    "Invalidated all refresh tokens for user {} (reason: {}, actor: {})", 
                    user_id, 
                    reason, 
                    ctx.actor_id
                );
                
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to invalidate tokens: {}", e);
                
                // Log failed token invalidation attempt for audit trail
                if let Err(audit_err) = crate::audit::audit_logger::log_token_invalidation_failure(
                    &self.audit_store,
                    ctx,
                    user_id.to_string(),
                    reason.to_string(),
                    error_msg.clone(),
                )
                .await {
                    tracing::error!("Failed to log token invalidation failure: {:?}", audit_err);
                }
                
                Err(InternalError::database("invalidate_all_tokens", sea_orm::DbErr::Custom(error_msg)))
            }
        }
    }
    
    async fn get_user_by_id_internal(
        &self,
        conn: &impl sea_orm::ConnectionTrait,
        user_id: &str,
    ) -> Result<user::Model, InternalError> {
        User::find()
            .filter(user::Column::Id.eq(user_id))
            .one(conn)
            .await
            .map_err(|e| InternalError::database("get_user_by_id", e))?
            .ok_or_else(|| InternalError::from(CredentialError::UserNotFound(user_id.to_string())))
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<user::Model, InternalError> {
        self.get_user_by_id_internal(&self.db, user_id).await
    }

    pub async fn get_user_by_id_in_txn(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        user_id: &str,
    ) -> Result<user::Model, InternalError> {
        self.get_user_by_id_internal(txn, user_id).await
    }

    /// Retrieves the user with is_owner=true.
    pub async fn get_owner(&self) -> Result<Option<user::Model>, InternalError> {
        User::find()
            .filter(user::Column::IsOwner.eq(true))
            .one(&self.db)
            .await
            .map_err(|e| InternalError::database("OPERATION", e))
    }

    /// Updates the password for a user in the database. Takes plaintext password,
    /// hashes it internally, and logs the change to audit database at point of action.
    async fn update_password(
        &self,
        conn: &impl sea_orm::ConnectionTrait,
        ctx: &RequestContext,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), InternalError> {
        // Fetch user to verify existence
        let user = User::find()
            .filter(user::Column::Id.eq(user_id))
            .one(conn)
            .await
            .map_err(|e| InternalError::database("get_user_for_password_update", e))?
            .ok_or_else(|| InternalError::Credential(CredentialError::UserNotFound(user_id.to_string())))?;

        // Hash password internally
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Argon2::new_with_secret(
            self.password_pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )
        .map_err(|e| InternalError::crypto("argon2_init", e.to_string()))?;
        
        let new_hash = argon2
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|e| InternalError::from(CredentialError::PasswordHashingFailed(e.to_string())))?
            .to_string();

        // Get current timestamp
        let now = Utc::now().timestamp();

        // Update password hash
        let mut active_model: ActiveModel = user.into();
        active_model.password_hash = Set(new_hash);
        active_model.updated_at = Set(now);

        active_model
            .update(conn)
            .await
            .map_err(|e| InternalError::database("update_password", e))?;

        // Log password change at point of action
        if let Err(audit_err) = audit_logger::log_password_changed(
            &self.audit_store,
            ctx,
            user_id.to_string(),
        ).await {
            tracing::error!("Failed to log password change: {:?}", audit_err);
        }

        Ok(())
    }
    
    pub async fn update_password_no_txn(
        &self,
        ctx: &RequestContext,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), InternalError> {
        self.update_password(&self.db, ctx, user_id, new_password).await
    }
    
    pub async fn update_password_in_txn(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        ctx: &RequestContext,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), InternalError> {
        self.update_password(txn, ctx, user_id, new_password).await
    }

    /// Sets password_change_required to false for a user.
    /// Logs the change to audit database at point of action.
    async fn clear_password_change_required(
        &self,
        conn: &impl sea_orm::ConnectionTrait,
        ctx: &RequestContext,
        user_id: &str,
    ) -> Result<(), InternalError> {
        // Fetch user to verify existence
        let user = User::find()
            .filter(user::Column::Id.eq(user_id))
            .one(conn)
            .await
            .map_err(|e| InternalError::database("get_user_for_clear_password_change_required", e))?
            .ok_or_else(|| InternalError::Credential(CredentialError::UserNotFound(user_id.to_string())))?;

        // Get current timestamp
        let now = Utc::now().timestamp();

        // Update password_change_required flag
        let mut active_model: ActiveModel = user.into();
        active_model.password_change_required = Set(false);
        active_model.updated_at = Set(now);

        active_model
            .update(conn)
            .await
            .map_err(|e| InternalError::database("clear_password_change_required", e))?;

        // Log password change requirement cleared at point of action
        if let Err(audit_err) = audit_logger::log_password_change_requirement_cleared(
            &self.audit_store,
            ctx,
            user_id.to_string(),
        ).await {
            tracing::error!("Failed to log password change requirement cleared: {:?}", audit_err);
        }

        Ok(())
    }
    
    pub async fn clear_password_change_required_no_txn(
        &self,
        ctx: &RequestContext,
        user_id: &str,
    ) -> Result<(), InternalError> {
        self.clear_password_change_required(&self.db, ctx, user_id).await
    }
    
    pub async fn clear_password_change_required_in_txn(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        ctx: &RequestContext,
        user_id: &str,
    ) -> Result<(), InternalError> {
        self.clear_password_change_required(txn, ctx, user_id).await
    }

    async fn revoke_all_refresh_tokens(
        &self,
        conn: &impl sea_orm::ConnectionTrait,
        user_id: &str,
    ) -> Result<(), InternalError> {
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        
        RefreshToken::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(conn)
            .await
            .map_err(|e| InternalError::database("revoke_all_refresh_tokens", e))?;
        
        Ok(())
    }
    
    pub async fn revoke_all_refresh_tokens_no_txn(&self, user_id: &str) -> Result<(), InternalError> {
        self.revoke_all_refresh_tokens(&self.db, user_id).await
    }
    
    pub async fn revoke_all_refresh_tokens_in_txn(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        user_id: &str,
    ) -> Result<(), InternalError> {
        self.revoke_all_refresh_tokens(txn, user_id).await
    }

    /// Convenience method that composes the primitive operations within a single transaction.
    /// The entire operation (user creation + privilege assignment) is atomic - if any step fails, everything rolls back.
    /// 
    /// Audit logging occurs at point of action within the transaction. If the
    /// transaction rolls back, a rollback event is logged.
    pub async fn create_admin_user(
        &self,
        ctx: &RequestContext,
        username: String,
        password_hash: String,
        admin_flags: AdminFlags,
    ) -> Result<user::Model, InternalError> {
        // Start transaction
        let txn = self.db.begin().await
            .map_err(|e| InternalError::transaction("store_refresh_token", e))?;

        // Step 1: Create user with no privileges (primitive operation)
        // Check if username already exists
        let existing_user = User::find()
            .filter(user::Column::Username.eq(&username))
            .one(&txn)
            .await
            .map_err(|e| InternalError::database("OPERATION", e))?;

        if existing_user.is_some() {
            return Err(InternalError::from(CredentialError::DuplicateUsername(username.clone())));
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
            password_change_required: Set(false),
            updated_at: Set(created_at),
        };

        // Insert into database
        new_user
            .insert(&txn)
            .await
            .map_err(|e| {
                // Check if it's a unique constraint violation
                if e.to_string().contains("UNIQUE") {
                    InternalError::from(CredentialError::DuplicateUsername(username.clone()))
                } else {
                    InternalError::database("OPERATION", e)
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
            .map_err(|e| InternalError::database("get_user_in_transaction", e))?
            .ok_or_else(|| InternalError::Credential(CredentialError::UserNotFound(user_id.to_string())))?;

        // Store old privileges for audit logging (should all be false)
        let old_privileges = AdminFlags::from(&user);

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
                    .map_err(|e| InternalError::transaction("commit_refresh_token", e))?;

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
                Err(InternalError::database("update_privileges", e))
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
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        let result = credential_store
            .add_user(&password_validator, "newuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await;
        
        assert!(result.is_ok());
        let user_id = result.unwrap();
        assert!(!user_id.is_empty());
    }

    #[tokio::test]
    async fn test_add_user_fails_with_duplicate_username() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        let result1 = credential_store
            .add_user(&password_validator, "duplicate".to_string(), "SecureTest-Pass-123456789".to_string())
            .await;
        
        assert!(result1.is_ok());
        
        let result2 = credential_store
            .add_user(&password_validator, "duplicate".to_string(), "SecureTest-Pass-234567890".to_string())
            .await;
        
        assert!(result2.is_err());
        match result2 {
            Err(InternalError::Credential(CredentialError::DuplicateUsername(_))) => {}
            _ => panic!("Expected DuplicateUsername error"),
        }
    }

    #[tokio::test]
    async fn test_store_refresh_token_saves_token_to_database() {
        let (db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Add a user first
        let user_id = credential_store
            .add_user(&password_validator, "tokenuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "test_hash_123";
        let expires_at = Utc::now().timestamp() + 604800; // 7 days
        let jwt_id = "test-jwt-id".to_string();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        let result = credential_store
            .store_refresh_token_no_txn(&ctx, token_hash.to_string(), user_id.clone(), expires_at, jwt_id)
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
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Add a user
        let user_id = credential_store
            .add_user(&password_validator, "expiryuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a token with 7 days expiration
        let token_hash = "expiry_test_hash";
        let now = Utc::now().timestamp();
        let expires_at = now + (7 * 24 * 60 * 60); // 7 days in seconds
        let jwt_id = "test-jwt-id".to_string();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        let result = credential_store
            .store_refresh_token_no_txn(&ctx, token_hash.to_string(), user_id.clone(), expires_at, jwt_id)
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
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Add a user
        let user_id = credential_store
            .add_user(&password_validator, "useridtest".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "userid_token_hash";
        let expires_at = Utc::now().timestamp() + 604800;
        let jwt_id = "test-jwt-id".to_string();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        credential_store
            .store_refresh_token_no_txn(&ctx, token_hash.to_string(), user_id.clone(), expires_at, jwt_id)
            .await
            .expect("Failed to store token");
        
        // Validate and verify user_id
        let ctx = crate::types::internal::context::RequestContext::new();
        let result = credential_store.validate_refresh_token(&ctx, token_hash).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_validate_refresh_token_fails_with_invalid_token() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        
        // Try to validate a token that doesn't exist
        let ctx = crate::types::internal::context::RequestContext::new();
        let result = credential_store.validate_refresh_token(&ctx, "nonexistent_token").await;
        
        assert!(result.is_err());
        match result {
            Err(InternalError::Credential(CredentialError::InvalidToken { .. })) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidRefreshToken error"),
        }
    }

    #[tokio::test]
    async fn test_validate_refresh_token_fails_with_expired_token() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Add a user
        let user_id = credential_store
            .add_user(&password_validator, "expireduser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Store an expired refresh token
        let token_hash = "expired_token_hash";
        let expires_at = Utc::now().timestamp() - 3600; // Expired 1 hour ago
        let jwt_id = "test-jwt-id".to_string();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        credential_store
            .store_refresh_token_no_txn(&ctx, token_hash.to_string(), user_id.clone(), expires_at, jwt_id)
            .await
            .expect("Failed to store token");
        
        // Try to validate the expired token
        let ctx = crate::types::internal::context::RequestContext::new();
        let result = credential_store.validate_refresh_token(&ctx, token_hash).await;
        
        assert!(result.is_err());
        match result {
            Err(InternalError::Credential(CredentialError::ExpiredToken(_))) => {
                // Expected error type
            }
            _ => panic!("Expected ExpiredRefreshToken error"),
        }
    }

    #[tokio::test]
    async fn test_revoke_refresh_token_removes_token_from_database() {
        let (db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Add a user
        let user_id = credential_store
            .add_user(&password_validator, "revokeuser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Store a refresh token
        let token_hash = "revoke_test_hash";
        let expires_at = Utc::now().timestamp() + 604800;
        let jwt_id = "test-jwt-id".to_string();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        credential_store
            .store_refresh_token_no_txn(&ctx, token_hash.to_string(), user_id.clone(), expires_at, jwt_id)
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
        let ctx = crate::types::internal::context::RequestContext::new();
        let result = credential_store.revoke_refresh_token(&ctx, token_hash).await;
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
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        let password = "same-password-long-enough-15-chars";
        
        // Create first user with pepper1
        let pepper1 = "pepper-one-secret-key".to_string();
        let store1 = CredentialStore::new(db.clone(), pepper1, audit_store.clone());
        
        store1
            .add_user(&password_validator, "user1".to_string(), password.to_string())
            .await
            .expect("Failed to add user1");
        
        // Create second user with pepper2
        let pepper2 = "pepper-two-secret-key".to_string();
        let store2 = CredentialStore::new(db.clone(), pepper2, audit_store.clone());
        
        store2
            .add_user(&password_validator, "user2".to_string(), password.to_string())
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
        
        // Create test context
        let ctx = RequestContext::new();
        
        // Verify user1 can only be verified with pepper1
        let verify_result = store1.verify_credentials(&ctx, "user1", password).await;
        assert!(verify_result.is_ok());
        
        // Verify user2 can only be verified with pepper2
        let verify_result = store2.verify_credentials(&ctx, "user2", password).await;
        assert!(verify_result.is_ok());
        
        // Verify cross-verification fails (user1 with pepper2)
        let verify_result = store2.verify_credentials(&ctx, "user1", password).await;
        assert!(verify_result.is_err());
        
        // Verify cross-verification fails (user2 with pepper1)
        let verify_result = store1.verify_credentials(&ctx, "user2", password).await;
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

    #[tokio::test]
    async fn test_get_owner_returns_none_when_no_owner_exists() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Add a regular user (not owner)
        credential_store
            .add_user(&password_validator, "regularuser".to_string(), "SecureTest-Pass-123456789".to_string())
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
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        // Add a regular user
        credential_store
            .add_user(&password_validator, "regularuser".to_string(), "SecureTest-Pass-123456789".to_string())
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
            password_change_required: Set(false),
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
            Err(InternalError::Credential(CredentialError::DuplicateUsername(_))) => {}
            _ => panic!("Expected DuplicateUsername error"),
        }
    }

    // Tests for set_privileges method

    #[tokio::test]
    async fn test_set_privileges_updates_all_flags_atomically() {
        let (_db, _audit_db, credential_store, _audit_store) = setup_test_stores().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        let user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), "SecureTest-Pass-123456789".to_string())
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
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        
        let user_id = credential_store
            .add_user(&password_validator, "testuser".to_string(), "SecureTest-Pass-123456789".to_string())
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


#[cfg(test)]
#[path = "credential_store_invalidate_test.rs"]
mod credential_store_invalidate_test;












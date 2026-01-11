use crate::errors::InternalError;
use crate::errors::internal::login::LoginError::*;
use crate::errors::internal::{CredentialError, DatabaseError, UserError};
use crate::providers::crypto_provider::PasswordHash;
use crate::types::db;
use crate::types::db::user;
use crate::types::internal::action_outcome::ActionOutcome;
use crate::errors::InternalError::User;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    FromQueryResult, QueryFilter, QuerySelect, Set,
};
use uuid::Uuid;

pub struct UserStore {}
impl UserStore {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn create_user(
        &self,
        conn: &impl ConnectionTrait,
        user_to_create: UserToCreate,
    ) -> Result<ActionOutcome<CreatedUser>, InternalError> {
         // Check if username already exists
        let existing_user = crate::types::db::user::Entity::find()
            .filter(user::Column::Username.eq(&user_to_create.username))
            .one(conn)
            .await
            .map_err(|e| InternalError::Database(DatabaseError::Operation { operation: "find existing user for create", source: e }))?;

        if existing_user.is_some() {
            return Err( InternalError::User( UserError::DuplicateUsername { username: user_to_create.username.clone() }));
        }

        let userid = UserId::new();
        let now = Utc::now().timestamp();
        let new_user = crate::types::db::user::ActiveModel {
            id: Set(userid.0.to_string()),
            username: Set(user_to_create.username.clone()),
            password_hash: Set(user_to_create.password.0.clone()),
            created_at: Set(now),
            is_owner: Set(false),
            is_system_admin: Set(false),
            is_role_admin: Set(false),
            app_roles: Set(None),
            password_change_required: Set(false),
            updated_at: Set(now),
        };

        // Insert into database
        new_user
            .insert(conn)
            .await
            .map_err(|e| {
                InternalError::database("OPERATION", e)
            })?;

        // Log user creation at point of action
        
        Ok(ActionOutcome::new(CreatedUser{
            id: userid,
            username: user_to_create.username.clone(),
        }))
    }

    pub async fn get_user_from_username_for_auth(
        &self,
        conn: &impl ConnectionTrait,
        username: &str,
    ) -> Result<UserForAuth, InternalError> {
        let user = db::user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .filter(user::Column::IsOwner.eq(false))
            .select_only()
            .column(user::Column::Id)
            .column(user::Column::Username)
            .column(user::Column::PasswordHash)
            .into_model::<UserForAuth>()
            .one(conn)
            .await
            .map_err(|e| {
                InternalError::Database(DatabaseError::Operation {
                    operation: "get_user_from_username_for_auth",
                    source: e,
                })
            })?;

        match user {
            Some(u) => Ok(u),
            None => Err(InternalError::Login(UsernameNotFound {
                username: username.to_owned(),
            })),
        }
    }

    pub async fn get_user_roles_for_jwt(
        &self,
        conn: &impl ConnectionTrait,
        user_id: &str,
    ) -> Result<ActionOutcome<UserForJWT>, InternalError> {
        let user = db::user::Entity::find()
            .filter(user::Column::Id.eq(user_id))
            .select_only()
            .column(user::Column::Id)
            .column(user::Column::Username)
            .column(user::Column::IsOwner)
            .column(user::Column::IsSystemAdmin)
            .column(user::Column::IsRoleAdmin)
            .column(user::Column::AppRoles)
            .column(user::Column::PasswordChangeRequired)
            .into_model::<UserForJWT>()
            .one(conn)
            .await
            .map_err(|e| {
                InternalError::Database(DatabaseError::Operation {
                    operation: "get_user_from_username_for_jwt",
                    source: e,
                })
            })?;

        match user {
            Some(u) => {
                let result = ActionOutcome {
                    value: u,
                    audit: Vec::new(),
                };
                Ok(result)
            }
            None => Err(InternalError::Credential(CredentialError::UserIdNotFound {
                user_id: user_id.to_owned(),
            })),
        }
    }

    pub async fn save_refresh_token_for_user(
        &self,
        conn: &impl ConnectionTrait,
        user_id: &str,
        token_hash: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), InternalError> {
        let new_token = db::refresh_token::ActiveModel {
            token_hash: Set(token_hash.to_owned()),
            user_id: Set(user_id.to_owned()),
            expires_at: Set(expires_at),
            created_at: Set(created_at),
        };

        new_token
            .insert(conn)
            .await
            .map_err(|e| InternalError::database("insert_refresh_token", e))?;

        // // Log refresh token issuance at point of action
        // if let Err(audit_err) = audit_logger::log_refresh_token_issued(
        //     &self.audit_store,
        //     ctx,
        //     user_id,
        //     jwt_id,
        //     token_hash,
        // ).await {
        //     tracing::error!("Failed to log refresh token issuance: {:?}", audit_err);
        // }

        Ok(())
    }
}

#[derive(FromQueryResult, Clone)]
pub struct UserForAuth {
    pub id: String,
    pub username: String,
    pub password_hash: String,
}
#[derive(FromQueryResult, Clone)]
pub struct UserForJWT {
    pub id: String,
    pub username: String,
    pub is_owner: bool,
    pub is_system_admin: bool,
    pub is_role_admin: bool,
    /// json strings array
    pub app_roles: String,
    pub password_change_required: bool,
}

pub struct UserId(Uuid);

impl UserId {
    pub fn new()->Self{
        Self(Uuid::new_v4())
    }
    
}

impl From<&UserId> for String {
    fn from(value: &UserId) -> Self {
        value.0.to_string()
    }
}

pub struct UserToCreate {
    pub id: UserId,
    pub username: String,
    pub password: PasswordHash,
}

pub struct CreatedUser {
    pub id: UserId,
    pub username: String,
}

use sea_orm::{ActiveModelTrait, ColumnTrait, Set};
use sea_orm::QuerySelect;
use sea_orm::QueryFilter;
use sea_orm::{ConnectionTrait, EntityTrait};
use crate::errors::internal::{CredentialError, DatabaseError};
use crate::errors::internal::login::LoginError::UsernameNotFound;
use crate::errors::InternalError;
use crate::stores::user_store::{UserForAuth, UserForJWT};
use crate::types::db;
use crate::types::db::user;
use crate::types::internal::action_outcome::ActionOutcome;

pub struct AuthenticationStore{

}

impl AuthenticationStore {
    pub fn new() -> Self {
        Self{}
    }
    pub async fn get_user_from_username_for_auth(
        &self,
        conn: &impl ConnectionTrait,
        username: &str,
    ) -> Result<UserForAuth, InternalError> {
        let user = crate::types::db::user::Entity::find()
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
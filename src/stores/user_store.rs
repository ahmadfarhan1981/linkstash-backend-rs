use crate::AppData;
use crate::audit::AuditLogger;
use crate::coordinators::ActionOutcome;
use crate::errors::InternalError;
use crate::errors::internal::login::LoginError::*;
use crate::errors::internal::{CredentialError, DatabaseError};
use crate::types::db;
use crate::types::db::refresh_token;
use crate::types::db::user;
use crate::types::internal::context::RequestContext;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    FromQueryResult, QueryFilter, QuerySelect, Set,
};
use std::sync::Arc;

pub struct UserStore {}
impl UserStore {
    pub fn new() -> Self {
        Self {}
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
                    operation: "get_user_from_username_for_auth".to_string(),
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
                    operation: "get_user_from_username_for_jwt".to_string(),
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

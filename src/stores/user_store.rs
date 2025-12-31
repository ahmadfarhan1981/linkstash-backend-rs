use std::sync::Arc;
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, FromQueryResult, QueryFilter, QuerySelect};
use crate::AppData;
use crate::audit::AuditLogger;
use crate::errors::internal::{CredentialError, DatabaseError};
use crate::errors::InternalError;
use crate::types::db;
use crate::types::db::user;
use crate::types::internal::context::RequestContext;

pub struct UserStore {
}
impl UserStore {
    pub fn new() -> Self {
        Self{           
        }
    }
    pub async fn get_user_from_username_for_auth(
        &self,
        conn: &impl ConnectionTrait,
        username: &str,
    )->Result<UserForAuth, InternalError> {
        let user: Option<UserForAuth> = db::user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .filter(user::Column::IsOwner.eq(false))
            .select_only()
            .column(user::Column::Id)
            .column(user::Column::Username)
            .column(user::Column::PasswordHash)
            .into_model::<UserForAuth>()
            .one(conn)
            .await
            .map_err(|e| InternalError::Database(DatabaseError::Operation{ operation: "get_user_from_username_for_auth".to_string(), source: e }))?;

        match user {
            Some(u) => Ok(u),
            None => Err(InternalError::Credential(CredentialError::UserNotFound(username.to_string())))
        }

    }
}

#[derive(FromQueryResult, Clone)]
pub struct UserForAuth{
    pub id: String,
    pub username: String,
    pub password_hash: String,

}
impl From<user::Model> for UserForAuth {
    fn from(u: user::Model) -> Self {
        Self{
            id:u.id,
            password_hash:u.password_hash,
            username: u.username,
        }

    }
}
use std::borrow::Cow;
use crate::errors::internal::DatabaseError;
use crate::errors::InternalError;
use crate::types::db::user;
use crate::types::internal::action_outcome::ActionOutcome;

use chrono::Utc;
use poem_openapi::{NewType, Object};
use poem_openapi::registry::MetaSchemaRef;
use poem_openapi::types::{ToJSON, Type};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait,
    FromQueryResult, QueryFilter, Set,
};
use serde_json::Value;
use uuid::Uuid;

pub struct UserStore {}
impl UserStore {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn username_in_use(
        &self,
        conn: &impl ConnectionTrait,
        username: impl AsRef<str>,
    ) -> Result<ActionOutcome<bool>, InternalError> {
        let existing_user = user::Entity::find()
            .filter(user::Column::Username.eq(username.as_ref()))
            .one(conn)
            .await
            .map_err(|e| {
                InternalError::Database(DatabaseError::Operation {
                    operation: "find existing user",
                    source: e,
                })
            })?;

        Ok(ActionOutcome::new(existing_user.is_some())) // TODO logging
    }

    pub async fn create_user(
        &self,
        conn: &impl ConnectionTrait,
        user_to_create: UserToCreate,
    ) -> Result<ActionOutcome<CreatedUser>, InternalError> {
        let userid = UserId::new();
        let now = Utc::now().timestamp();
        let new_user = user::ActiveModel {
            id: Set(userid.0.to_string()),
            username: Set(user_to_create.username.clone()),
            password_hash: Set(None),
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
            .map_err(|e| InternalError::database("Create new user", e))?;

        // TODO
        // Log user creation at point of action


        Ok(ActionOutcome::new(CreatedUser {
            id: userid,
            username: user_to_create.username.clone(),
        }))
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


#[derive(Copy, Clone, Debug)]
pub struct UserId(pub Uuid);
impl From<&UserId> for String {
    fn from(value: &UserId) -> Self {
        value.0.to_string()
    }
}

impl From<UserId> for String {
    fn from(value: UserId) -> Self {
        value.0.to_string()
    }
}

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
pub struct UserToCreate {
    pub id: UserId,
    pub username: String,
}

pub struct CreatedUser {
    pub id: UserId,
    pub username: String,
}

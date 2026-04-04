use crate::errors::internal::SystemConfigError;
use crate::stores::user_store::{UserForAuth, UserId};
use crate::types::db::system_config::Entity as SystemConfig;
use crate::types::db::user;
use crate::types::db::user::{ActiveModel, Entity as User};
use crate::InternalError;
use argon2::PasswordHash;
use chrono::Utc;
use poem_openapi::Object;
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, Set};
use uuid::Uuid;

// use crate::providers::crypto_provider::PasswordHash;

pub struct OwnerStore {}

pub enum OwnerStatus {
    DoesNotExist,
    ExistsNotActivated,
    ExistsActivated(UserForAuth),
}

#[derive(Debug, Clone)]
pub struct CreateOwnerResponse {
    pub user_id: UserId,
    pub username: String,
    pub is_active: bool,
    pub created_at: i64,
}

impl OwnerStore {
    pub fn new() -> Self {
        Self {}
    }


    pub async fn check_owner(
        &self,
        conn: &impl ConnectionTrait,
    ) -> Result<OwnerStatus, InternalError> {
        let activated = SystemConfig::find_by_id(1) // TODO magic id
            .one(conn)
            .await
            .map_err(|e| InternalError::database("Fetching config", e))?
            .ok_or_else(|| SystemConfigError::config_not_found())?
            .owner_active;

        if !activated {return Ok(OwnerStatus::ExistsNotActivated);}

        let result = User::find()
            .filter(user::Column::IsOwner.eq(true))
            .select_only()
            .column(user::Column::Id)
            .column(user::Column::Username)
            .column(user::Column::PasswordHash)
            .into_model::<UserForAuth>()
            .one(conn)
            .await
            .map_err(|e| InternalError::database("Owner check", e))?;

        match result {
            None => Ok(OwnerStatus::DoesNotExist),
            Some(owner) => {
                Ok(OwnerStatus::ExistsActivated(owner))
            }
        }
    }
}

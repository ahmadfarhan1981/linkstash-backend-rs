use crate::InternalError;
use crate::errors::internal::SystemConfigError;
use crate::errors::internal::login::LoginError;
use crate::stores::user_store::UserForAuth;
use crate::types::db::system_config::Entity as SystemConfig;
use crate::types::db::user;
use crate::types::db::user::Entity as User;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};

pub struct OwnerStore {}

pub enum OwnerStatus {
    DoesNotExist,
    ExistsNotActivated,
    ExistsActivated(UserForAuth),
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
            .ok_or_else(||{SystemConfigError::config_not_found()})?
            .owner_active;

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
                if activated {
                    return Ok(OwnerStatus::ExistsActivated(owner));
                }
                Ok(OwnerStatus::ExistsNotActivated)
            }
        }
    }
}

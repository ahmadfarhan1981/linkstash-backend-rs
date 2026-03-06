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

#[derive(Debug, Clone, Object)]
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

    pub async fn create_owner(
        &self,
        conn: &impl ConnectionTrait,
        username: String,
        password_hash: PasswordHash<'_>,
        
    ) -> Result<OwnerStatus, InternalError> {
        // Generate UUID for user
        let user_id = Uuid::new_v4().to_string();

        // Get current timestamp
        let created_at = Utc::now().timestamp();

        // Create new user ActiveModel with password_change_required=true
        let new_user = ActiveModel {
            id: Set(user_id.clone()),
            username: Set(username.clone()),
            password_hash: Set(Some(password_hash.to_string())),
            created_at: Set(created_at),
            // is_owner: Set(admin_flags.is_owner),
            // is_system_admin: Set(admin_flags.is_system_admin),
            // is_role_admin: Set(admin_flags.is_role_admin),
            app_roles: Set(None),
            password_change_required: Set(true), // Force password change on first login
            updated_at: Set(created_at),
            ..Default::default()
        };
        let owner = new_user.insert(conn).await.map_err(|e| InternalError::database("create owner", e))?;


        // UserForAuth{
        //     id: owner.id,
        //     username: owner.username,
        //     password_hash: owner.password_hash.unwrap().to_string(),
        // }

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

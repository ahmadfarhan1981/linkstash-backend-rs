use crate::errors::internal::authorization::AuthorizationError;
use crate::errors::InternalError;
use crate::stores::user_store::UserId;
use crate::types::db::user;
use crate::types::internal::action_outcome::ActionOutcome;
use crate::types::PasswordHash;
use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::ColumnTrait;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, FromQueryResult};
use sea_orm::{QueryFilter, QuerySelect};
use std::fmt;

pub struct AuthorizationStore {}

pub struct PasswordChangeRequest {
    id: String,
    new_password_hash: PasswordHash,

}

#[derive(Debug)]
pub struct RoleDefinition {
    is_owner: bool,
    is_admin: bool,
    is_role_admin: bool,
}

impl fmt::Display for RoleDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut roles = Vec::new();
        if self.is_owner {
            roles.push("owner");
        }
        if self.is_admin {
            roles.push("admin");
        }
        if self.is_role_admin {
            roles.push("role_admin");
        }
        write!(f, "[{}]", roles.join(", "))
    }
}

pub struct RoleUpdateRequest {
    id: UserId,
    new_roles: RoleDefinition,
}

#[derive(FromQueryResult)]
pub struct UserWithRoles {
    id: String,
    username: String,
    is_owner: bool,
    is_system_admin: bool,
    is_role_admin: bool,
}

impl AuthorizationStore {
    pub async fn change_password(
        &self,
        conn: &impl ConnectionTrait,
        password_change_request: PasswordChangeRequest,
    ) -> Result<ActionOutcome<()>, InternalError> {
        let new_user = user::ActiveModel {
            id: Set(password_change_request.id.to_owned()),
            password_hash: Set(Some(password_change_request.new_password_hash.0)),
            password_change_required: Set(false),
            updated_at: Set(Utc::now().timestamp()),
            ..Default::default()
        };

        // Insert into database
        new_user
            .update(conn)
            .await
            .map_err(|e| InternalError::database("OPERATION", e))?;
        Ok(ActionOutcome::new(()))
    }

    pub async fn set_permissions(
        &self,
        conn: &impl ConnectionTrait,
        role_update_request: RoleUpdateRequest,
    ) -> Result<ActionOutcome<()>, InternalError> {
        let user = user::Entity::find()
            .filter(user::Column::Id.eq::<String>(role_update_request.id.into()))
            .select_only()
            .column(user::Column::Id)
            .column(user::Column::Username)
            .column(user::Column::IsOwner)
            .column(user::Column::IsSystemAdmin)
            .column(user::Column::IsRoleAdmin)
            .one(conn)
            .await.map_err(|e| InternalError::database("find user to change role", e))?;

        return match user {
            None => {
                Err(InternalError::Authorization(AuthorizationError::SettingRoleOnNonExistentUser { user_id: role_update_request.id.into(), role: role_update_request.new_roles }))
            }
            Some(mut userWithRole) => {
                let mut user: user::ActiveModel = userWithRole.into();

                user.is_role_admin = Set(role_update_request.new_roles.is_role_admin);
                user.is_owner = Set(role_update_request.new_roles.is_owner);
                user.is_system_admin = Set(role_update_request.new_roles.is_admin);
                user.updated_at = Set(Utc::now().timestamp());
                user.update(conn).await.map_err(|e| InternalError::database("update user", e))?;

                Ok(ActionOutcome::new(()))
            }
        }


        // Ok(ActionOutcome::new(()))
    }
}
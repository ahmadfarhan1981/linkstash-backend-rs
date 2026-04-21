use crate::stores::authorization_store::RoleDefinition;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Setting role {role} on non existent user with id: {user_id}")]
    SettingRoleOnNonExistentUser {
        user_id: String,
        role: RoleDefinition,
    },
}

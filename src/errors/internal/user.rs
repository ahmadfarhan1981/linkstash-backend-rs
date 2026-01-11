use crate::config::ApplicationError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    
    #[error("User already exists: {username}")]
    DuplicateUsername{username: String},

    #[error("User not found: {username}")]
    UserNotFound{username: String},

    #[error("User ID not found: {user_id}")]
    UserIdNotFound { user_id: String },
}

impl Into<ApplicationError> for UserError {
    fn into(self) -> ApplicationError {
        match self {
            UserError::DuplicateUsername { username } => todo!(),
            UserError::UserNotFound { username } => todo!(),
            UserError::UserIdNotFound { user_id } => todo!(),
                    }
    }
}

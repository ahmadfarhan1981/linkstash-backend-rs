use thiserror::Error;
use super::InternalError;

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("Password incorrect")]
    IncorrectPassword,
    #[error("Username not found: {username}")]
    UsernameNotFound { username: String },
}

impl LoginError {
    pub fn username_not_found(username: String) -> InternalError {
        InternalError::Login(Self::UsernameNotFound { username })
    }
    
    pub fn incorrect_password() -> InternalError {
        InternalError::Login(Self::IncorrectPassword)
    }
}

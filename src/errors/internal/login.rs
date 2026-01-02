use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("Password incorrect")]
    IncorrectPassword,
    #[error("Username not found: {username}")]
    UsernameNotFound { username: String },
}

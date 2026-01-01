use thiserror::Error;
use crate::config::ApplicationError;

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Current password is incorrect")]
    IncorrectPassword,
    
    #[error("Password validation failed: {0}")]
    PasswordValidationFailed(String),
    
    #[error("User already exists: {0}")]
    DuplicateUsername(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),
    
    #[error("Invalid token: {token_type} - {reason}")]
    InvalidToken {
        token_type: String,
        reason: String,
    },
    
    #[error("Expired token: {0}")]
    ExpiredToken(String),

    /// Generic credential related error
    #[error("User ID not found: {user_id}")]
    UserIdNotFound{user_id:String},

}

impl Into<ApplicationError> for CredentialError{
    fn into(self) -> ApplicationError {

        match self {

            /** Login **/
            CredentialError::InvalidCredentials => todo!(),
            CredentialError::IncorrectPassword => todo!(),
            CredentialError::PasswordValidationFailed(_) => todo!(),
            CredentialError::DuplicateUsername(_) => todo!(),
            CredentialError::UserNotFound(_) => todo!(),
            
            CredentialError::InvalidToken { token_type, reason } => todo!(),
            CredentialError::ExpiredToken(_) => todo!(),

            CredentialError::PasswordHashingFailed(_) => todo!(),

            CredentialError::UserIdNotFound{ user_id: _ } => todo!()
        }
    }
}
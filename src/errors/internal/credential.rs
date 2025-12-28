use thiserror::Error;

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
}
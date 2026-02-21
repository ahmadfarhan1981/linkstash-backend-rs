use thiserror::Error;
use super::InternalError;

#[derive(Error, Debug)]
pub enum SystemConfigError {
    #[error("System config not found")]
    ConfigNotFound,

    #[error("Owner already exists")]
    OwnerAlreadyExists,

    #[error("Owner not found")]
    OwnerNotFound,
}

impl SystemConfigError {
    pub fn config_not_found() -> InternalError {
        InternalError::SystemConfig(Self::ConfigNotFound)
    }
    
    pub fn owner_already_exists() -> InternalError {
        InternalError::SystemConfig(Self::OwnerAlreadyExists)
    }
    
    pub fn owner_not_found() -> InternalError {
        InternalError::SystemConfig(Self::OwnerNotFound)
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SystemConfigError {
    #[error("System config not found")]
    ConfigNotFound,
    
    #[error("Owner already exists")]
    OwnerAlreadyExists,
    
    #[error("Owner not found")]
    OwnerNotFound,
}
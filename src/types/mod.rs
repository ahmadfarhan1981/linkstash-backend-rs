
use crate::{config::ApplicationError, errors::InternalError, types::internal::{action_outcome::ActionOutcome, audit::AuditEvent}};

// Types layer - All data structures
pub mod db;
pub mod dto;
pub mod internal;


pub type ProviderResult<T> = Result<ActionOutcome<T>, InternalError>;
pub type ApiResult<T> = Result<ActionOutcome<T>, ApplicationError>;


pub trait ApiResultTrait<T> {
    fn new (value: T) -> ProviderResult<T>{
        Ok(ActionOutcome::new(value))
    }
    fn error(error: InternalError)->ProviderResult<T>{
        Err(error)
    }
}
pub trait ProviderResultTrait<T> {
    fn new (value: T) -> ProviderResult<T>{
        Ok(ActionOutcome::new(value))
    }
   
    fn error(error: InternalError)->ProviderResult<T>{
        Err(error)
    }
}
impl<T>  ProviderResultTrait<T> for ProviderResult<T> {}

pub struct PasswordHash(pub String);
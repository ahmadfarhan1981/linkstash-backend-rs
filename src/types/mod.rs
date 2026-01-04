
use crate::{coordinators::ActionOutcome, errors::InternalError};

// Types layer - All data structures
pub mod db;
pub mod dto;
pub mod internal;


pub type ProviderResult<T> = Result<ActionOutcome<T>, InternalError>;

pub trait ProviderResultTrait<T> {
    fn some (value: T) -> ProviderResult<T>{
        Ok(ActionOutcome::new(value))
    }
}
impl<T>  ProviderResultTrait<T> for ProviderResult<T> {}
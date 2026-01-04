
use crate::{config::ApplicationError, coordinators::ActionOutcome, errors::InternalError, types::internal::audit::AuditEvent};

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
    // fn audit(&self, event: AuditEvent) -> ProviderResult<T> {
    //     match self {
    //         Ok(outcome) => {
    //             // Clone the outcome and add the audit event
    //             let mut new_outcome = outcome.clone();
    //             // new_outcome.add_audit_event(event);
    //             Ok(new_outcome)
    //         }
    //         Err(error) => {
    //             // For errors, we could either:
    //             // 1. Just return the error as-is
    //             // 2. Or attach the audit event to the error if it supports it
    //             Err(error.clone())
    //         }
    //     }
    // }
    fn error(error: InternalError)->ProviderResult<T>{
        Err(error)
    }
}
impl<T>  ProviderResultTrait<T> for ProviderResult<T> {}
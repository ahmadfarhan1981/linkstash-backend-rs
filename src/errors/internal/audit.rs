use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Failed to write audit log: {0}")]
    LogWriteFailed(String),
}
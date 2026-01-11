use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database error: {operation} failed: {source}")]
    Operation {
        operation: &'static str,
        #[source]
        source: sea_orm::DbErr,
    },

    #[error("Starting transaction failed: {source}")]
    TransactionBegin {
        #[source]
        source: sea_orm::DbErr,
    },

    #[error("Committing transaction failed: {source}")]
    TransactionCommit {
        #[source]
        source: sea_orm::DbErr,
    },
}

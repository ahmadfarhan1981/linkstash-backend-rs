use std::sync::Arc;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction, TransactionTrait};
use migration::{AuthMigrator, AuditMigrator, MigratorTrait};
use crate::{config::{BootstrapSettings, bootstrap_settings}, errors::InternalError};
use crate::audit::AuditLogger;

pub struct  DatabaseConnections{
    pub auth : DatabaseConnection,
    pub audit : DatabaseConnection,

}

impl DatabaseConnections{
    pub fn init(bootstrap_settings: &BootstrapSettings) -> Result<Self, InternalError>{
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let auth = Self::init_database(bootstrap_settings).await?;
                let audit = Self::init_audit_database(bootstrap_settings).await?;

                Ok(Self {
                    auth,
                    audit,
                })
            })
        })
    }

    pub async fn migrate(&self) -> Result<(), InternalError> {
        migrate_auth_database(&self.auth).await?;
        migrate_audit_database(&self.audit).await?;

        Ok(())
    }

    /// Initialize the main database connection
    ///
    /// Connects to the database and returns the connection.
    /// Does NOT run migrations - call migrate_auth_database() separately.
    ///
    /// # Returns
    /// * `Ok(DatabaseConnection)` - Connection established successfully
    /// * `Err(InternalError)` - Connection failed
    async fn init_database(bootstrap_settings: &BootstrapSettings) -> Result<DatabaseConnection, InternalError> {

        let database_url = bootstrap_settings.database_url();

        let db = Database::connect(database_url)
            .await
            .map_err(|e| InternalError::database("connect_database", e))?;

        tracing::debug!("Connected to auth database: {}", database_url);

        Ok(db)
    }

    /// Initialize the audit database connection
    ///
    /// Connects to the database and returns the connection.
    /// Does NOT run migrations - call migrate_audit_database() separately.
    ///
    /// # Returns
    /// * `Ok(DatabaseConnection)` - Connection established successfully
    /// * `Err(InternalError)` - Connection failed
    async fn init_audit_database(bootstrap_settings: &BootstrapSettings) -> Result<DatabaseConnection, InternalError> {

        let audit_database_url = bootstrap_settings.audit_database_url();

        let audit_db = Database::connect(audit_database_url)
            .await
            .map_err(|e| InternalError::database("connect_audit_database", e))?;

        tracing::debug!("Connected to audit database: {}", audit_database_url);

        Ok(audit_db)
    }


     pub async fn begin_auth_transaction(&self)->Result<impl ConnectionTrait, InternalError>{
        Self::begin_transaction(self.auth).await
     }
    pub async fn begin_audit_transaction(&self)->Result<impl ConnectionTrait, InternalError>{
        Self::begin_transaction(self.audit).await
    }
    async fn begin_transaction(
        db: DatabaseConnection,
    ) -> Result<sea_orm::DatabaseTransaction, InternalError> {
        let txn = db.begin().await
            .map_err(|source| InternalError::TransactionBegin{source})?;
        Ok(txn)
    }
    
    async fn commit_transaction(
        txn: sea_orm::DatabaseTransaction,
    ) -> Result<(), InternalError> {
        txn.commit().await
            .map_err(|source| InternalError::TransactionCommit{source})?;
        Ok(())
    }
    


}




/// Run migrations on the auth database
/// 
/// Runs all pending migrations on the provided database connection.
/// 
/// # Arguments
/// * `db` - Database connection to run migrations on
/// 
/// # Returns
/// * `Ok(())` - Migrations completed successfully
/// * `Err(InternalError)` - Migration failed
pub async fn migrate_auth_database(db: &DatabaseConnection) -> Result<(), InternalError> {
    AuthMigrator::up(db, None)
        .await
        .map_err(|e| InternalError::database("run_migrations", e))?;
    
    tracing::debug!("Auth database migrations completed");
    
    Ok(())
}



/// Run migrations on the audit database
/// 
/// Runs all pending migrations on the provided database connection.
/// 
/// # Arguments
/// * `audit_db` - Database connection to run migrations on
/// 
/// # Returns
/// * `Ok(())` - Migrations completed successfully
/// * `Err(InternalError)` - Migration failed
pub async fn migrate_audit_database(audit_db: &DatabaseConnection) -> Result<(), InternalError> {
    AuditMigrator::up(audit_db, None)
        .await
        .map_err(|e| InternalError::database("run_audit_migrations", e))?;
    
    tracing::debug!("Audit database migrations completed");
    
    Ok(())
}

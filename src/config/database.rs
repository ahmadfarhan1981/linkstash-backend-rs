use sea_orm::{Database, DatabaseConnection};
use migration::{AuthMigrator, AuditMigrator, MigratorTrait};
use crate::errors::InternalError;

/// Initialize the main database connection
/// 
/// Connects to the database and returns the connection.
/// Does NOT run migrations - call migrate_auth_database() separately.
/// 
/// # Returns
/// * `Ok(DatabaseConnection)` - Connection established successfully
/// * `Err(InternalError)` - Connection failed
pub async fn init_database() -> Result<DatabaseConnection, InternalError> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://auth.db?mode=rwc".to_string());
    
    let db = Database::connect(&database_url)
        .await
        .map_err(|e| InternalError::database("connect_database", e))?;
    
    tracing::debug!("Connected to auth database: {}", database_url);
    
    Ok(db)
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

/// Initialize the audit database connection
/// 
/// Connects to the database and returns the connection.
/// Does NOT run migrations - call migrate_audit_database() separately.
/// 
/// # Returns
/// * `Ok(DatabaseConnection)` - Connection established successfully
/// * `Err(InternalError)` - Connection failed
pub async fn init_audit_database() -> Result<DatabaseConnection, InternalError> {
    let audit_db_path = std::env::var("AUDIT_DB_PATH")
        .unwrap_or_else(|_| "audit.db".to_string());
    let audit_database_url = format!("sqlite://{}?mode=rwc", audit_db_path);
    
    let audit_db = Database::connect(&audit_database_url)
        .await
        .map_err(|e| InternalError::database("connect_audit_database", e))?;
    
    tracing::debug!("Connected to audit database: {}", audit_database_url);
    
    Ok(audit_db)
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

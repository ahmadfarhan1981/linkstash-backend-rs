use sea_orm::{Database, DatabaseConnection};
use migration::{Migrator, MigratorTrait};

/// Initialize the main database connection and run migrations
/// 
/// Reads DATABASE_URL from environment or uses default: sqlite://auth.db?mode=rwc
pub async fn init_database() -> Result<DatabaseConnection, std::io::Error> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://auth.db?mode=rwc".to_string());
    
    let db = Database::connect(&database_url)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to connect to database: {}", e)))?;
    
    tracing::info!("Connected to database: {}", database_url);
    
    Migrator::up(&db, None)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to run migrations: {}", e)))?;
    
    tracing::info!("Database migrations completed");
    
    Ok(db)
}

/// Initialize the audit database connection and run migrations
/// 
/// Reads AUDIT_DB_PATH from environment or uses default: audit.db
pub async fn init_audit_database() -> Result<DatabaseConnection, std::io::Error> {
    let audit_db_path = std::env::var("AUDIT_DB_PATH")
        .unwrap_or_else(|_| "audit.db".to_string());
    let audit_database_url = format!("sqlite://{}?mode=rwc", audit_db_path);
    
    let audit_db = Database::connect(&audit_database_url)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to connect to audit database: {}", e)))?;
    
    tracing::info!("Connected to audit database: {}", audit_database_url);
    
    Migrator::up(&audit_db, None)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to run audit database migrations: {}", e)))?;
    
    tracing::info!("Audit database migrations completed");
    
    Ok(audit_db)
}

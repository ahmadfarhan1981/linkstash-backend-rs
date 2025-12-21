use crate::app_data::AppData;
use crate::config::{migrate_auth_database, migrate_audit_database};

/// Run database migrations for auth and audit databases
/// 
/// This function connects to both databases and runs all pending migrations.
/// It does not initialize the full AppData structure.
/// 
/// # Returns
/// * `Ok(())` - Migrations completed successfully
/// * `Err(...)` - Migration failed
pub async fn run_migrations() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Running database migrations...");
    
    // Connect to auth database
    tracing::info!("Connecting to auth database...");
    let auth_db = init_database().await?;
    
    // Run auth database migrations
    tracing::info!("Migrating auth database...");
    migrate_auth_database(&auth_db).await?;
    
    // Connect to audit database
    tracing::info!("Connecting to audit database...");
    let audit_db = init_audit_database().await?;
    
    // Run audit database migrations
    tracing::info!("Migrating audit database...");
    migrate_audit_database(&audit_db).await?;
    
    tracing::info!("All migrations completed successfully");
    
    Ok(())
}

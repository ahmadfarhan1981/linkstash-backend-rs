// CLI module for administrative operations requiring server access

pub mod bootstrap;
pub mod owner;
pub mod credential_export;

use clap::{Parser, Subcommand};
use sea_orm::DatabaseConnection;

/// Linkstash CLI for administrative operations
#[derive(Parser)]
#[command(name = "linkstash")]
#[command(about = "Linkstash authentication backend CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Bootstrap the system by creating owner and initial admin accounts
    Bootstrap,
    
    /// Owner account management commands
    #[command(subcommand)]
    Owner(OwnerCommands),
}

#[derive(Subcommand)]
pub enum OwnerCommands {
    /// Activate the owner account
    Activate,
    
    /// Deactivate the owner account
    Deactivate,
    
    /// Display owner account information
    Info,
}

/// Execute CLI command
/// 
/// Routes the parsed CLI command to the appropriate handler function.
/// 
/// # Arguments
/// * `cli` - Parsed CLI arguments
/// * `db` - Main database connection
/// * `audit_db` - Audit database connection
/// * `secret_manager` - Secret manager for accessing secrets
/// 
/// # Returns
/// * `Ok(())` - Command executed successfully
/// * `Err(...)` - Command execution failed
pub async fn execute_command(
    cli: Cli,
    db: &DatabaseConnection,
    audit_db: &DatabaseConnection,
    secret_manager: &crate::config::SecretManager,
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Bootstrap => {
            bootstrap::bootstrap_system(db, audit_db, secret_manager).await?;
        }
        Commands::Owner(owner_cmd) => {
            match owner_cmd {
                OwnerCommands::Activate => {
                    owner::activate_owner(db, audit_db).await?;
                }
                OwnerCommands::Deactivate => {
                    owner::deactivate_owner(db, audit_db).await?;
                }
                OwnerCommands::Info => {
                    owner::get_owner_info(db, audit_db).await?;
                }
            }
        }
    }
    
    Ok(())
}

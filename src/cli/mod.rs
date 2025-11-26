// CLI module for administrative operations requiring server access

pub mod bootstrap;
pub mod owner;
pub mod credential_export;

use clap::{Parser, Subcommand};

use crate::app_data::AppData;

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
/// * `app_data` - Application data containing all stores and services
/// 
/// # Returns
/// * `Ok(())` - Command executed successfully
/// * `Err(...)` - Command execution failed
pub async fn execute_command(
    cli: Cli,
    app_data: &AppData,
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Bootstrap => {
            bootstrap::bootstrap_system(
                &app_data.credential_store,
                &app_data.system_config_store,
                &app_data.audit_store,
                &app_data.secret_manager,
            ).await?;
        }
        Commands::Owner(owner_cmd) => {
            match owner_cmd {
                OwnerCommands::Activate => {
                    owner::activate_owner(
                        &app_data.credential_store,
                        &app_data.system_config_store,
                        &app_data.audit_store,
                    ).await?;
                }
                OwnerCommands::Deactivate => {
                    owner::deactivate_owner(
                        &app_data.credential_store,
                        &app_data.system_config_store,
                        &app_data.audit_store,
                    ).await?;
                }
                OwnerCommands::Info => {
                    owner::get_owner_info(
                        &app_data.credential_store,
                        &app_data.system_config_store,
                    ).await?;
                }
            }
        }
    }
    
    Ok(())
}

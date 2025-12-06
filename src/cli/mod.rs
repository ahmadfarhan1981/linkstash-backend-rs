// CLI module for administrative operations requiring server access

pub mod bootstrap;
pub mod owner;
pub mod credential_export;
pub mod migrate;
pub mod password_management;

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
    /// Run database migrations
    Migrate,
    
    /// Bootstrap the system by creating owner and initial admin accounts
    Bootstrap,
    
    /// Owner account management commands
    #[command(subcommand)]
    Owner(OwnerCommands),
    
    /// Download and load common password list from URL
    DownloadPasswords {
        /// URL to download password list from (default: Top 1000 most common passwords)
        /// Good pro value : https://github.com/danielmiessler/SecLists/raw/refs/heads/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt
        #[arg(long, default_value = "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt")]
        url: String,
    },
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
        Commands::Migrate => {
            migrate::run_migrations().await?;
        }
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
        Commands::DownloadPasswords { url } => {
            password_management::download_and_load_passwords(&url, app_data).await?;
        }
    }
    
    Ok(())
}

// CLI module for administrative operations requiring server access

// pub mod bootstrap;
// pub mod owner;
// pub mod credential_export;
// pub mod password_management;

use clap::{Parser, Subcommand};
use std::sync::Arc;

use crate::app_data::AppData;

/// Linkstash CLI for administrative operations
#[derive(Parser)]
#[command(name = "linkstash")]
#[command(about = "Linkstash authentication backend CLI", long_about = None)]
pub struct Cli {
    /// Path to environment file (default: .env)
    #[arg(long, global = true, default_value = ".env")]
    pub env_file: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run database migrations
    Migrate,

    /// Bootstrap the system by creating owner and initial admin accounts
    Bootstrap {
        /// Non-interactive mode (TEST ONLY - creates owner with fixed password, no prompts)
        #[cfg(any(debug_assertions, feature = "test-utils"))]
        #[arg(long)]
        non_interactive: bool,
    },

    /// Owner account management commands
    #[command(subcommand)]
    Owner(OwnerCommands),

    /// Load common password blocklist from URL
    LoadCommonPasswordBlocklist {
        /// URL to download password blocklist from (default: Top 1000 most common passwords)
        /// Good value for prod: https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt
        #[arg(
            long,
            default_value = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt"
        )]
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
    // let conn = app_data.connections.auth;
    match cli.command {
        Commands::Migrate => Err("Unexpected cli path".to_string().into()),
        Commands::Bootstrap {
            #[cfg(any(debug_assertions, feature = "test-utils"))]
            non_interactive,
        } => {
            #[cfg(any(debug_assertions, feature = "test-utils"))]
            {
                if non_interactive {
                    tracing::warn!("NOT IMPLEMENTED");
                    Ok(())
                    // Create password validator from AppData stores
                    // let password_validator = Arc::new(crate::providers::PasswordValidatorProvider::new(
                    //     app_data.stores.common_password_store.clone(),
                    //     app_data.stores.hibp_cache_store.clone(),
                    // ));

                    // bootstrap::bootstrap_system_non_interactive(
                    //     &app_data.stores.credential_store,
                    //     &app_data.stores.system_config_store,
                    //     &app_data.audit_logger.audit_store,
                    //     &app_data.secret_manager,
                    //     &password_validator,
                    // ).await
                } else {
                    tracing::warn!("NOT IMPLEMENTED");
                    Ok(())

                    // Create password validator from AppData stores
                    // let password_validator = Arc::new(crate::providers::PasswordValidatorProvider::new(
                    //     app_data.stores.common_password_store.clone(),
                    //     app_data.stores.hibp_cache_store.clone(),
                    // ));

                    // bootstrap::bootstrap_system(
                    //     &app_data.stores.credential_store,
                    //     &app_data.stores.system_config_store,
                    //     &app_data.audit_logger.audit_store,
                    //     &app_data.secret_manager,
                    //     &password_validator,
                    // ).await
                }
            }

            #[cfg(not(any(debug_assertions, feature = "test-utils")))]
            {
                bootstrap::bootstrap_system(
                    &app_data.credential_store,
                    &app_data.system_config_store,
                    &app_data.audit_store,
                    &app_data.secret_manager,
                    &app_data.password_validator,
                )
                .await
            }
        }
        Commands::Owner(owner_cmd) => {
            tracing::warn!("NOT IMPLEMENTED");
            Ok(())
            // match owner_cmd {
            // OwnerCommands::Activate => {
            //     owner::activate_owner(
            //         &app_data.stores.credential_store,
            //         &app_data.stores.system_config_store,
            //         &app_data.audit_logger.audit_store,
            //     ).await
            // }
            // OwnerCommands::Deactivate => {
            //     owner::deactivate_owner(
            //         &app_data.stores.credential_store,
            //         &app_data.stores.system_config_store,
            //         &app_data.audit_logger.audit_store,
            //     ).await
            // }
            // OwnerCommands::Info => {
            //     owner::get_owner_info(
            //         &app_data.stores.credential_store,
            //         &app_data.stores.system_config_store,
            //     ).await
            // }
            // }
        }
        Commands::LoadCommonPasswordBlocklist { url } => {
            tracing::warn!("NOT IMPLEMENTED");
            Ok(())
            // password_management::download_and_load_passwords(&url, app_data).await
        }
    }

    // Ok(())
}

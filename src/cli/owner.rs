// Owner management CLI commands
// Provides commands for activating/deactivating owner account and retrieving owner info

use std::io::{self, Write};
use std::sync::Arc;
use crate::stores::{CredentialStore, SystemConfigStore, AuditStore};
use crate::types::internal::context::RequestContext;
use crate::providers::audit_logger_provider;

/// Activate the owner account
/// 
/// Sets the system config owner_active flag to true after confirmation prompt.
/// 
/// # Arguments
/// * `credential_store` - Credential store for user management
/// * `system_config_store` - System config store for owner status
/// * `audit_store` - Audit store for logging
/// 
/// # Returns
/// * `Ok(())` - Owner activated successfully
/// * `Err(...)` - Activation failed
pub async fn activate_owner(
    credential_store: &CredentialStore,
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create RequestContext for CLI operation
    let ctx = RequestContext::for_cli("owner_activate");

    // Log CLI session start
    if let Err(e) = audit_logger_provider::log_cli_session_start(
        audit_store,
        &ctx,
        "owner_activate",
        vec![],
    ).await {
        tracing::error!("Failed to log CLI session start: {:?}", e);
    }

    // Track success for session end logging
    let mut success = false;
    let mut error_message: Option<String> = None;

    let result: Result<(), Box<dyn std::error::Error>> = async {
        // Check if owner exists
        let owner = credential_store.get_owner().await
            .map_err(|e| format!("Failed to get owner: {}", e))?;
        let owner = match owner {
            Some(o) => o,
            None => {
                println!("❌ Error: No owner account found. Run bootstrap first.");
                return Err("Owner not found".into());
            }
        };

        // Check current status
        let is_active = system_config_store.is_owner_active().await
            .map_err(|e| format!("Failed to check owner status: {}", e))?;
        if is_active {
            println!("ℹ️  Owner account is already active.");
            return Ok(());
        }

        // Display confirmation prompt
        println!("⚠️  WARNING: You are about to activate the owner account.");
        println!("   Owner: {} ({})", owner.username, owner.id);
        println!();
        print!("   Are you sure you want to activate the owner account? (yes/no): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input != "yes" {
            println!("❌ Activation cancelled.");
            return Ok(());
        }

        // Activate owner
        system_config_store.set_owner_active(true, Some("cli".to_string()), Some("localhost".to_string())).await
            .map_err(|e| format!("Failed to activate owner: {}", e))?;

        println!("✅ Owner account activated successfully.");
        println!("   The owner can now log in using their credentials.");

        Ok(())
    }.await;

    // Update success status based on result
    match &result {
        Ok(_) => success = true,
        Err(e) => error_message = Some(e.to_string()),
    }

    // Log CLI session end
    if let Err(e) = audit_logger_provider::log_cli_session_end(
        audit_store,
        &ctx,
        "owner_activate",
        success,
        error_message,
    ).await {
        tracing::error!("Failed to log CLI session end: {:?}", e);
    }

    result
}

/// Deactivate the owner account
/// 
/// Sets the system config owner_active flag to false after confirmation prompt.
/// 
/// # Arguments
/// * `credential_store` - Credential store for user management
/// * `system_config_store` - System config store for owner status
/// * `audit_store` - Audit store for logging
/// 
/// # Returns
/// * `Ok(())` - Owner deactivated successfully
/// * `Err(...)` - Deactivation failed
pub async fn deactivate_owner(
    credential_store: &CredentialStore,
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create RequestContext for CLI operation
    let ctx = RequestContext::for_cli("owner_deactivate");

    // Log CLI session start
    if let Err(e) = audit_logger_provider::log_cli_session_start(
        audit_store,
        &ctx,
        "owner_deactivate",
        vec![],
    ).await {
        tracing::error!("Failed to log CLI session start: {:?}", e);
    }

    // Track success for session end logging
    let mut success = false;
    let mut error_message: Option<String> = None;

    let result: Result<(), Box<dyn std::error::Error>> = async {
        // Check if owner exists
        let owner = credential_store.get_owner().await
            .map_err(|e| format!("Failed to get owner: {}", e))?;
        let owner = match owner {
            Some(o) => o,
            None => {
                println!("❌ Error: No owner account found. Run bootstrap first.");
                return Err("Owner not found".into());
            }
        };

        // Check current status
        let is_active = system_config_store.is_owner_active().await
            .map_err(|e| format!("Failed to check owner status: {}", e))?;
        if !is_active {
            println!("ℹ️  Owner account is already inactive.");
            return Ok(());
        }

        // Display confirmation prompt
        println!("⚠️  WARNING: You are about to deactivate the owner account.");
        println!("   Owner: {} ({})", owner.username, owner.id);
        println!("   The owner will not be able to log in until reactivated.");
        println!();
        print!("   Are you sure you want to deactivate the owner account? (yes/no): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input != "yes" {
            println!("❌ Deactivation cancelled.");
            return Ok(());
        }

        // Deactivate owner
        system_config_store.set_owner_active(false, Some("cli".to_string()), Some("localhost".to_string())).await
            .map_err(|e| format!("Failed to deactivate owner: {}", e))?;

        println!("✅ Owner account deactivated successfully.");
        println!("   The owner cannot log in until reactivated via CLI.");

        Ok(())
    }.await;

    // Update success status based on result
    match &result {
        Ok(_) => success = true,
        Err(e) => error_message = Some(e.to_string()),
    }

    // Log CLI session end
    if let Err(e) = audit_logger_provider::log_cli_session_end(
        audit_store,
        &ctx,
        "owner_deactivate",
        success,
        error_message,
    ).await {
        tracing::error!("Failed to log CLI session end: {:?}", e);
    }

    result
}

/// Retrieve and display owner account information
/// 
/// Displays owner username, UUID, and active status.
/// 
/// # Arguments
/// * `credential_store` - Credential store for user management
/// * `system_config_store` - System config store for owner status
/// 
/// # Returns
/// * `Ok(())` - Owner info displayed successfully
/// * `Err(...)` - Failed to retrieve owner info
pub async fn get_owner_info(
    credential_store: &CredentialStore,
    system_config_store: &SystemConfigStore,
) -> Result<(), Box<dyn std::error::Error>> {

    // Get owner
    let owner = credential_store.get_owner().await
        .map_err(|e| format!("Failed to get owner: {}", e))?;
    let owner = match owner {
        Some(o) => o,
        None => {
            println!("❌ Error: No owner account found. Run bootstrap first.");
            return Err("Owner not found".into());
        }
    };

    // Get active status
    let is_active = system_config_store.is_owner_active().await
        .map_err(|e| format!("Failed to check owner status: {}", e))?;

    // Display owner information
    println!("Owner Account Information:");
    println!("  Username: {}", owner.username);
    println!("  UUID:     {}", owner.id);
    println!("  Status:   {}", if is_active { "ACTIVE ✅" } else { "INACTIVE ⚠️" });
    println!();
    
    if !is_active {
        println!("ℹ️  The owner account is currently inactive and cannot log in.");
        println!("   To activate: cargo run -- owner activate");
    } else {
        println!("ℹ️  The owner account is active and can log in.");
        println!("   To deactivate: cargo run -- owner deactivate");
    }

    Ok(())
}

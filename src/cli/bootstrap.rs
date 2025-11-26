// Bootstrap command implementation
// Creates owner account and initial admin accounts during system setup

use std::io::{self, Write};
use std::sync::Arc;
use uuid::Uuid;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString, Algorithm, Version, Params};

use crate::config::SecretManager;
use crate::stores::{CredentialStore, SystemConfigStore, AuditStore};
use crate::types::internal::auth::AdminFlags;
use crate::services::crypto::generate_secure_password;
use crate::cli::credential_export::{ExportFormat, export_credentials};
use crate::types::internal::context::RequestContext;

/// Bootstrap the system by creating owner and initial admin accounts
/// 
/// # Arguments
/// * `credential_store` - Credential store for user management
/// * `system_config_store` - System config store for owner status
/// * `audit_store` - Audit store for logging
/// * `secret_manager` - Secret manager for accessing password pepper
/// 
/// # Returns
/// * `Ok(())` - Bootstrap completed successfully
/// * `Err(...)` - Bootstrap failed (e.g., system already bootstrapped)
pub async fn bootstrap_system(
    credential_store: &CredentialStore,
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
    secret_manager: &SecretManager,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Linkstash Bootstrap ===\n");
    
    // Create RequestContext for CLI operation
    use crate::types::internal::context::RequestContext;
    let ctx = RequestContext::for_cli("bootstrap");
    
    // Log CLI session start
    use crate::services::audit_logger;
    if let Err(audit_err) = audit_logger::log_cli_session_start(
        audit_store,
        &ctx,
        "bootstrap",
        vec![], // No sensitive args to log
    ).await {
        eprintln!("Warning: Failed to log CLI session start: {:?}", audit_err);
    }
    
    // Execute bootstrap logic and capture result
    let result = bootstrap_system_impl(credential_store, system_config_store, audit_store, secret_manager, &ctx).await;
    
    // Log CLI session end based on result
    match &result {
        Ok(_) => {
            if let Err(audit_err) = audit_logger::log_cli_session_end(
                audit_store,
                &ctx,
                "bootstrap",
                true,
                None,
            ).await {
                eprintln!("Warning: Failed to log CLI session end: {:?}", audit_err);
            }
        }
        Err(e) => {
            if let Err(audit_err) = audit_logger::log_cli_session_end(
                audit_store,
                &ctx,
                "bootstrap",
                false,
                Some(e.to_string()),
            ).await {
                eprintln!("Warning: Failed to log CLI session end: {:?}", audit_err);
            }
        }
    }
    
    result
}

/// Internal implementation of bootstrap system
async fn bootstrap_system_impl(
    credential_store: &CredentialStore,
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
    secret_manager: &SecretManager,
    ctx: &RequestContext,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::services::audit_logger;
    
    // Get password pepper from secret manager
    let password_pepper = secret_manager.password_pepper();
    
    // Check if owner already exists
    let existing_owner = credential_store.get_owner().await
        .map_err(|e| format!("Failed to check for existing owner: {}", e))?;
    if existing_owner.is_some() {
        return Err("System already bootstrapped".into());
    }
    
    println!("No owner account found. Starting bootstrap process...\n");
    
    // Create owner account
    let owner_username = Uuid::new_v4().to_string();
    let owner_password = prompt_for_password("Owner")?;
    let owner_password_hash = hash_password(&owner_password, &password_pepper)?;
    
    let _owner = credential_store.create_admin_user(
        &ctx,
        owner_username.clone(),
        owner_password_hash,
        AdminFlags::owner(),
    ).await
        .map_err(|e| format!("Failed to create owner account: {}", e))?;
    
    println!("\n✓ Owner account created");
    println!("  Username: {}", owner_username);
    println!("  Password: {}", owner_password);
    
    // Handle owner credentials
    handle_credential_export(&owner_username, &owner_password, "owner")?;
    
    // Display owner inactive warning
    println!("\n ⚠️  WARNING: Owner account is INACTIVE (system flag owner_active=false)");
    println!("⚠️  The owner account cannot be used until activated via CLI:");
    println!("⚠️  cargo run -- owner activate");
    println!("⚠️  ");
    println!("⚠️  Keep owner credentials secure and only activate when needed for");
    println!("⚠️  emergency admin management. Deactivate immediately after use.\n");
    
    // Verify system config has owner_active=false
    let is_active = system_config_store.is_owner_active().await
        .map_err(|e| format!("Failed to check owner_active flag: {}", e))?;
    if is_active {
        println!("⚠️  WARNING: owner_active flag is unexpectedly true. Setting to false...");
        system_config_store.set_owner_active(false, Some("system".to_string()), None).await
            .map_err(|e| format!("Failed to set owner_active flag: {}", e))?;
    }
    
    // Prompt for System Admin count
    let system_admin_count = prompt_for_count("System Admin", 10)?;
    
    // Create System Admin accounts
    for i in 1..=system_admin_count {
        println!("\n--- System Admin {} of {} ---", i, system_admin_count);
        let username = Uuid::new_v4().to_string();
        let password = prompt_for_password("System Admin")?;
        let password_hash = hash_password(&password, &password_pepper)?;
        
        let _admin = credential_store.create_admin_user(
            &ctx,
            username.clone(),
            password_hash,
            AdminFlags::system_admin(),
        ).await
            .map_err(|e| format!("Failed to create System Admin account: {}", e))?;
        
        println!("\n✓ System Admin account created");
        println!("  Username: {}", username);
        println!("  Password: {}", password);
        
        handle_credential_export(&username, &password, "system_admin")?;
    }
    
    // Prompt for Role Admin count
    let role_admin_count = prompt_for_count("Role Admin", 10)?;
    
    // Create Role Admin accounts
    for i in 1..=role_admin_count {
        println!("\n--- Role Admin {} of {} ---", i, role_admin_count);
        let username = Uuid::new_v4().to_string();
        let password = prompt_for_password("Role Admin")?;
        let password_hash = hash_password(&password, &password_pepper)?;
        
        let _admin = credential_store.create_admin_user(
            &ctx,
            username.clone(),
            password_hash,
            AdminFlags::role_admin(),
        ).await
            .map_err(|e| format!("Failed to create Role Admin account: {}", e))?;
        
        println!("\n✓ Role Admin account created");
        println!("  Username: {}", username);
        println!("  Password: {}", password);
        
        handle_credential_export(&username, &password, "role_admin")?;
    }
    
    // Log bootstrap completion
    if let Err(audit_err) = audit_logger::log_bootstrap_completed(
        audit_store,
        "system".to_string(),
        Some("localhost".to_string()),
        owner_username.clone(),
        system_admin_count,
        role_admin_count,
    ).await
    {
        eprintln!("Warning: Failed to log bootstrap completion: {:?}", audit_err);
    }
    
    println!("\n=== Bootstrap Complete ===");
    println!("Total accounts created:");
    println!("  - 1 Owner (INACTIVE)");
    println!("  - {} System Admin(s)", system_admin_count);
    println!("  - {} Role Admin(s)", role_admin_count);
    println!("\nRemember to activate the owner account when needed:");
    println!("  cargo run -- owner activate\n");
    
    Ok(())
}

/// Prompt user for password (auto-generate or manual entry)
/// 
/// Default: Auto-generate (on empty input)
/// Accepts: y/yes (any case) for yes, n/no (any case) for no
fn prompt_for_password(role_type: &str) -> Result<String, Box<dyn std::error::Error>> {
    // ANSI codes: \x1b[1m = bold, \x1b[36m = cyan, \x1b[0m = reset
    print!("Generate password for {} automatically? (\x1b[1m\x1b[36mY\x1b[0m/n) [default: Y]: ", role_type);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    
    // Validate input: accept y/yes/n/no (any case) or empty
    match input.as_str() {
        "" | "y" | "yes" => {
            // Default or explicit yes: auto-generate
            let password = generate_secure_password();
            println!("✓ Password auto-generated");
            Ok(password)
        }
        "n" | "no" => {
            // Explicit no: manual entry
            print!("Enter password for {}: ", role_type);
            io::stdout().flush()?;
            
            let mut password = String::new();
            io::stdin().read_line(&mut password)?;
            let password = password.trim().to_string();
            
            // Accept any password without validation (validation will be added later)
            if password.is_empty() {
                return Err("Password cannot be empty".into());
            }
            
            Ok(password)
        }
        _ => {
            println!("Invalid input. Please enter 'y'/'yes', 'n'/'no', or press Enter for default.");
            prompt_for_password(role_type) // Retry
        }
    }
}

/// Prompt user for admin account count
/// 
/// Default: 0 (on empty input)
fn prompt_for_count(role_type: &str, max_count: u32) -> Result<u32, Box<dyn std::error::Error>> {
    // ANSI codes: \x1b[1m = bold, \x1b[36m = cyan, \x1b[0m = reset
    print!("How many {} accounts to create? (0-{}) [default: \x1b[1m\x1b[36m0\x1b[0m]: ", role_type, max_count);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    // Default to 0 if empty
    if input.is_empty() {
        return Ok(0);
    }
    
    let count: u32 = input.parse()
        .map_err(|_| format!("Invalid number: {}", input))?;
    
    if count > max_count {
        return Err(format!("Count must be between 0 and {}", max_count).into());
    }
    
    Ok(count)
}

/// Handle credential export for an account
/// 
/// Loops until user selects "Next" to allow multiple operations
/// (e.g., copy username, then copy password, then export to file)
/// 
/// Default: Next (option 6, on empty input)
fn handle_credential_export(username: &str, password: &str, role_type: &str) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\nCredential export options:");
        println!("  1. Display credentials");
        println!("  2. Copy username to clipboard");
        println!("  3. Copy password to clipboard");
        println!("  4. Export to KeePassX XML");
        println!("  5. Export to Bitwarden JSON");
        println!("  6. Next (continue to next account)");
        
        // ANSI codes: \x1b[1m = bold, \x1b[36m = cyan, \x1b[0m = reset
        print!("Select option (1-6) [default: \x1b[1m\x1b[36m6\x1b[0m]: ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        match input {
            "" | "6" => {
                // Default: Next
                println!("Continuing to next step...");
                break; // Exit loop, continue to next account
            }
            "1" => {
                // Display credentials
                println!("\n========================================");
                println!("Credentials:");
                println!("  Username: {}", username);
                println!("  Password: {}", password);
                println!("========================================");
            }
            "2" => {
                export_credentials(username, password, role_type, ExportFormat::CopyUsername)?;
            }
            "3" => {
                export_credentials(username, password, role_type, ExportFormat::CopyPassword)?;
            }
            "4" => {
                export_credentials(username, password, role_type, ExportFormat::KeePassXML)?;
            }
            "5" => {
                export_credentials(username, password, role_type, ExportFormat::BitwardenJSON)?;
            }
            _ => {
                println!("Invalid option. Please enter a number between 1-6 or press Enter for default.");
            }
        }
        
        // Loop continues, menu will redisplay
    }
    
    Ok(())
}

/// Hash a password using Argon2id with the password pepper
fn hash_password(password: &str, password_pepper: &str) -> Result<String, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::new_with_secret(
        password_pepper.as_bytes(),
        Algorithm::Argon2id,
        Version::V0x13,
        Params::default(),
    )
        .map_err(|e| format!("Failed to initialize Argon2: {}", e))?;
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))?
        .to_string();
    
    Ok(password_hash)
}

// Bootstrap command implementation
// Creates owner account and initial admin accounts during system setup

use crate::stores::authorization_store::AuthorizationStore;
use crate::stores::authorization_store::AuthorizationStore;
use crate::cli::credential_export::{export_credentials, ExportFormat};
use crate::config::database::DatabaseConnections;
use crate::config::SecretManager;
use crate::stores::owner_store::{OwnerStatus, OwnerStore};
use crate::stores::user_store::{UserId, UserStore, UserToCreate};
use crate::stores::{AuditStore, SystemConfigStore};
use crate::types::internal::auth::AdminFlags;
use crate::types::internal::context::RequestContext;
use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use rand::Rng;
use sea_orm::ConnectionTrait;
use std::io::{self, Write};
use std::sync::Arc;
use uuid::Uuid;

/// Bootstrap the system by creating owner and initial admin accounts
/// 
/// # Arguments
/// * `credential_store` - Credential store for user management
/// * `system_config_store` - System config store for owner status
/// * `audit_store` - Audit store for logging
/// * `secret_manager` - Secret manager for accessing password pepper
/// * `password_validator` - Password validator for validating passwords
/// 
/// # Returns
/// * `Ok(())` - Bootstrap completed successfully
/// * `Err(...)` - Bootstrap failed (e.g., system already bootstrapped)
pub async fn bootstrap_system(
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
    owner_store: &Arc<OwnerStore>,
    secret_manager: &SecretManager,
    database_connections: DatabaseConnections,

    // password_validator: &PasswordValidatorProvider, // TODO password validator
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Linkstash Bootstrap ===\n");
    
    // Create RequestContext for CLI operation
    use crate::types::internal::context::RequestContext;
    let ctx = RequestContext::for_cli("bootstrap");
    
    // TODO Log CLI session start

    let conn = database_connections.begin_auth_transaction().await?;
    // Execute bootstrap logic and capture result
    let result = bootstrap_system_impl(system_config_store,
                                       audit_store,
                                       secret_manager,
                                       conn,
                                       owner_store,
                                       &ctx).await;
    
    // TODO Log CLI session end based on result

    result
}

/// Internal implementation of bootstrap system
async fn bootstrap_system_impl(
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
    secret_manager: &SecretManager,
    conn: impl ConnectionTrait,
    // password_validator: &PasswordValidatorProvider, // TODO Password validator
    owner_store: &Arc<OwnerStore>,
    ctx: &RequestContext,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::audit::audit_logger;

    
    // Check if owner already exists
    let existing_owner = owner_store.check_owner(&conn).await
        .map_err(|e| format!("Failed to check for existing owner: {}", e))?;
    match existing_owner {
        // return Err("System already bootstrapped".into());
        OwnerStatus::DoesNotExist => {}//intentionally pass // TODO look for better structure
        OwnerStatus::ExistsNotActivated => {return Err("System already bootstrapped".into());}
        OwnerStatus::ExistsActivated(_) => {return Err("System already bootstrapped".into());}
    }
    
    println!("No owner account found. Starting bootstrap process...\n");
    
    // Create owner account
    let owner_username = Uuid::new_v4().to_string();
    let owner_password = prompt_for_password("Owner"/*, password_validator*/, Some(&owner_username)).await?;
    
    create_owner_account(/* conn */, /* &UserStore */, /* authorization_store */, /* &SystemConfigStore */, /* &SecretManager */, /* &types::internal::context::request_context::RequestContext */, /* std::string::String */, /* std::string::String */, /* bool */).await?;
    
    // Create System Admin accounts
    let system_admin_count = create_system_admin_accounts(
        // credential_store,
        secret_manager,
        // password_validator,
        ctx,
    ).await?;
    
    // Create Role Admin accounts
    let role_admin_count = create_role_admin_accounts(
        credential_store,
        secret_manager,
        password_validator,
        ctx,
    ).await?;
    
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

/// Create owner account
/// 
/// # Arguments
/// * `owner_username` - Username for the owner account
/// * `owner_password` - Password for the owner account (will be hashed)
/// * `skip_export` - If true, skip the credential export prompt
async fn create_owner_account(
    conn: &impl ConnectionTrait,
    user_store: &UserStore,
    authorization_store: &AuthorizationStore,
    system_config_store: &SystemConfigStore,
    secret_manager: &SecretManager,
    ctx: &RequestContext,
    owner_username: String,
    owner_password: String,
    skip_export: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let password_pepper = secret_manager.password_pepper();
    let owner_password_hash = hash_password(&owner_password, &password_pepper)?;
    
    let _owner = create_admin_user_with_password_change_required(
        conn,
        user_store,
        authorization_store,
        ctx,
        owner_username.clone(),
        owner_password_hash,
        AdminFlags::owner(),
    ).await
        .map_err(|e| format!("Failed to create owner account: {}", e))?;
    
    println!("\n✓ Owner account created");
    println!("  Username: {}", owner_username);
    println!("  Password: {}", owner_password);
    
    // Handle owner credentials (skip if requested)
    if !skip_export {
        handle_credential_export(&owner_username, &owner_password, "owner")?;
    }
    
    // Display owner inactive warning
    println!("\n ⚠️  WARNING: Owner account is INACTIVE (system flag owner_active=false)");
    println!("⚠️  The owner account cannot be used until activated via CLI:");
    println!("⚠️  cargo run -- owner activate");
    println!("⚠️  ");
    println!("⚠️  Keep owner credentials secure and only activate when needed for");
    println!("⚠️  emergency admin management. Deactivate immediately after use.\n");
    
    // Display password change requirement warning
    println!("⚠️  WARNING: Password change required on first login");
    println!("⚠️  This account must change its password before accessing protected endpoints.\n");
    
    // Verify system config has owner_active=false
    let is_active = system_config_store.is_owner_active().await
        .map_err(|e| format!("Failed to check owner_active flag: {}", e))?;
    if is_active {
        println!("⚠️  WARNING: owner_active flag is unexpectedly true. Setting to false...");
        system_config_store.set_owner_active(false, Some("system".to_string()), None).await
            .map_err(|e| format!("Failed to set owner_active flag: {}", e))?;
    }
    
    Ok(())
}

/// Create System Admin accounts with interactive prompts
/// 
/// Returns the count of System Admin accounts created
async fn create_system_admin_accounts(
    conn: &impl ConnectionTrait,
    user_store: &UserStore,
    authorization_store: &crate::stores::AuthorizationStore,
    secret_manager: &SecretManager,
    ctx: &RequestContext,
) -> Result<u32, Box<dyn std::error::Error>> {
    let password_pepper = secret_manager.password_pepper();
    
    // Prompt for System Admin count
    let system_admin_count = prompt_for_count("System Admin", 10)?;
    
    // Create System Admin accounts
    for i in 1..=system_admin_count {
        println!("\n--- System Admin {} of {} ---", i, system_admin_count);
        let username = Uuid::new_v4().to_string();
        let password = prompt_for_password("System Admin", Some(&username)).await?;
        let password_hash = hash_password(&password, &password_pepper)?;
        
        let _admin = create_admin_user_with_password_change_required(
            conn,
            user_store,
            authorization_store,
            ctx,
            username.clone(),
            password_hash,
            AdminFlags::system_admin(),
        ).await
            .map_err(|e| format!("Failed to create System Admin account: {}", e))?;
        
        println!("\n✓ System Admin account created");
        println!("  Username: {}", username);
        println!("  Password: {}", password);
        println!("  ⚠️  Password change required on first login");
        
        handle_credential_export(&username, &password, "system_admin")?;
    }
    
    Ok(system_admin_count)
}

/// Create Role Admin accounts with interactive prompts
/// 
/// Returns the count of Role Admin accounts created
async fn create_role_admin_accounts(
    // credential_store: &CredentialStore,
    secret_manager: &SecretManager,
    // password_validator: &PasswordValidatorProvider,
    ctx: &RequestContext,
) -> Result<u32, Box<dyn std::error::Error>> {
    let password_pepper = secret_manager.password_pepper();
    
    // Prompt for Role Admin count
    let role_admin_count = prompt_for_count("Role Admin", 10)?;
    
    // Create Role Admin accounts
    for i in 1..=role_admin_count {
        println!("\n--- Role Admin {} of {} ---", i, role_admin_count);
        let username = Uuid::new_v4().to_string();
        let password = prompt_for_password("Role Admin", password_validator, Some(&username)).await?;
        let password_hash = hash_password(&password, &password_pepper)?;
        
        let _admin = create_admin_user_with_password_change_required(
            // credential_store,
            /* UserStore */,
            ctx,
            password_hash,
            username.clone(),
            AdminFlags::role_admin(),
        ).await
            .map_err(|e| format!("Failed to create Role Admin account: {}", e))?;
        
        println!("\n✓ Role Admin account created");
        println!("  Username: {}", username);
        println!("  Password: {}", password);
        println!("  ⚠️  Password change required on first login");
        
        handle_credential_export(&username, &password, "role_admin")?;
    }
    
    Ok(role_admin_count)
}

//temp put here for now.
// TODO figure out where to put this
pub fn generate_secure_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::rng();

    (0..20)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}


/// Prompt user for password (auto-generate or manual entry)
/// 
/// Default: Auto-generate (on empty input)
/// Accepts: y/yes (any case) for yes, n/no (any case) for no
/// 
/// # Arguments
/// * `role_type` - The type of role (e.g., "Owner", "System Admin")
/// * `password_validator` - Password validator for validating manual passwords
/// * `username` - Optional username for context-specific validation
/// 
/// # Returns
/// * `Ok(String)` - Valid password (auto-generated or manually entered)
/// * `Err(...)` - I/O error or validation error
async fn prompt_for_password(
    role_type: &str,
    // password_validator: &PasswordValidatorProvider,
    username: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Loop for retry on invalid input (y/n choice)
    loop {
        // ANSI codes: \x1b[1m = bold, \x1b[36m = cyan, \x1b[0m = reset
        print!("Generate password for {} automatically? (\x1b[1m\x1b[36mY\x1b[0m/n) [default: Y]: ", role_type);
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        
        // Validate input: accept y/yes/n/no (any case) or empty
        match input.as_str() {
            "" | "y" | "yes" => {
                // Default or explicit yes: auto-generate using PasswordValidator
                let password = generate_secure_password();
                println!("✓ Password auto-generated");
                return Ok(password);
            }
            "n" | "no" => {
                // Explicit no: manual entry with validation
                loop {
                    print!("Enter password for {}: ", role_type);
                    io::stdout().flush()?;
                    
                    let mut password = String::new();
                    io::stdin().read_line(&mut password)?;
                    let password = password.trim().to_string();
                    
                    if password.is_empty() {
                        println!("❌ Password cannot be empty");
                        continue;
                    }
                    return Ok(password);
                    // // Validate password using PasswordValidator
                    // match password_validator.validate(&password, username).await {
                    //     Ok(_) => {
                    //         println!("✓ Password validated successfully");
                    //         return Ok(password);
                    //     }
                    //     Err(e) => {
                    //         println!("❌ Password validation failed: {}", e);
                    //         println!("Please try again or press Ctrl+C to cancel.");
                    //         // Loop continues, prompting for password again
                    //     }
                    // }
                }
            }
            _ => {
                println!("Invalid input. Please enter 'y'/'yes', 'n'/'no', or press Enter for default.");
                // Loop continues, prompting for y/n choice again
            }
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



/// Create an admin user with password_change_required=true
/// 
/// This is a helper function for bootstrap that creates admin users with the
/// password_change_required flag set to true, forcing them to change their
/// password on first login.
/// 
/// # Arguments
/// * `credential_store` - Credential store for user management
/// * `ctx` - Request context for audit logging
/// * `username` - Username for the new admin user
/// * `password_hash` - Pre-hashed password
/// * `admin_flags` - Admin flags specifying which admin roles to assign
/// 
/// # Returns
/// * `Ok(Model)` - The created user model with password_change_required=true
/// * `Err(InternalError)` - User creation or privilege assignment failed
async fn create_admin_user_with_password_change_required(
    // credential_store: &CredentialStore,
    conn: &impl ConnectionTrait,
    user_store: &UserStore,
    authorization_store: &AuthorizationStore,
    ctx: &RequestContext,
    username: String,
    password_hash: String,
    admin_flags: AdminFlags,
) -> Result<crate::types::db::user::Model, crate::errors::InternalError> {
    use chrono::Utc;
    
    // Start transaction
    //let txn = credential_store.begin_transaction(ctx, "create_admin_with_password_change_required").await?;

    let exists = user_store.username_in_use(conn, &username).await?.value;
    if exists {
        return Err(crate::errors::InternalError::from(
            crate::errors::internal::CredentialError::DuplicateUsername(username.clone())
        ));
    }


    // Generate UUID for user
    let user_id = Uuid::new_v4();
    // Get current timestamp
    let created_at = Utc::now().timestamp();

    let new_user = UserToCreate { id: UserId(user_id), username };
    let user = user_store.create_user(conn, new_user).await?.value;

    let role_update = crate::stores::authorization_store::RoleUpdateRequest {
        id: UserId(user_id),
        new_roles: crate::stores::authorization_store::RoleDefinition {
            is_owner: admin_flags.is_owner,
            is_admin: admin_flags.is_system_admin,
            is_role_admin: admin_flags.is_role_admin,
        },
    };
    
    authorization_store.set_permissions(conn, role_update).await?;

    // Log user creation at point of action
    // if let Err(audit_err) = audit_logger::log_user_created(
    //     &credential_store.audit_store,
    //     ctx,
    //     &user_id,
    //     &username,
    // ).await {
    //     tracing::error!("Failed to log user creation: {:?}", audit_err);
    // }

    // Log privilege assignment //TODO audit intent
    // if let Err(audit_err) = audit_logger::log_privileges_changed(
    //     &credential_store.audit_store,
    //     ctx,
    //     &user_id,
    //     false, // old is_owner
    //     admin_flags.is_owner, // new is_owner
    //     false, // old is_system_admin
    //     admin_flags.is_system_admin, // new is_system_admin
    //     false, // old is_role_admin
    //     admin_flags.is_role_admin, // new is_role_admin
    // ).await {
    //     tracing::error!("Failed to log privilege change: {:?}", audit_err);
    // }
    
    // Commit transaction
    // txn.commit().await
    //     .map_err(|e| crate::errors::InternalError::transaction("commit_admin_user", e))?;
    //
    Ok(user)
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

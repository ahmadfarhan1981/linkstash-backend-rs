# Implementation Plan

**Note:** This spec focuses on establishing the three-tier admin role structure (Owner, System Admin, Role Admin) and implementing the bootstrap CLI functionality. The app_roles field is included in the database schema and JWT claims for future use. API-based admin role management has been moved to a separate spec (admin-role-api-management).

- [x] 1. Database schema and migrations







  - [x] 1.1 Create migration to add admin role columns to users table and system_config table
    - Add `is_owner`, `is_system_admin`, `is_role_admin` boolean columns to users table with DEFAULT FALSE
    - Add `app_roles` column (TEXT) to users table for JSON array of application roles
    - Add `updated_at` column (BIGINT) to users table for tracking last modification
    - Create `system_config` singleton table with columns: id (INTEGER PRIMARY KEY), owner_active (BOOLEAN DEFAULT FALSE), updated_at (BIGINT)
    - Insert single row into system_config with id=1, owner_active=false


    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.5, 2.9, 2.10, 3.1_
  
  - [x] 1.2 Update user entity model to include new fields
    - Add admin role boolean fields to Model struct


    - Add app_roles field as Option<String> for JSON storage
    - Add updated_at timestamp field
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  
  - [x] 1.3 Create system_config entity model


    - Create types/db/system_config.rs with Model struct
    - Add id (i32, primary key), owner_active (bool), and updated_at (i64) fields
    - This is a singleton table (only one row with id=1)
    - Export from types/db/mod.rs
    - _Requirements: 3.1_
  
  - [ ] 1.4 Run migration and verify schema changes
    - Execute `sea-orm-cli migrate up` to apply migration
    - Verify all columns added correctly with proper defaults
    - Verify system_config table created
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 3.1_

- [x] 2. JWT claims and internal types
  - [x] 2.1 Update Claims struct to include admin roles





    - Add `is_owner`, `is_system_admin`, `is_role_admin` boolean fields
    - Add `app_roles` Vec<String> field
    - Update all JWT generation to include new claims
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_
  
  - [x] 2.2 Create AdminFlags struct for role management



    - Define struct with is_owner, is_system_admin, is_role_admin fields
    - Add helper methods for validation and conversion
    - _Requirements: 1.1, 1.2, 1.3_

- [x] 3. Password generation for bootstrap
  - [x] 3.1 Implement secure password generation





    - Generate 20-character passwords with mix of uppercase, lowercase, digits, and symbols
    - Use cryptographically secure random number generator (rand crate)
    - _Requirements: 11.1, 11.3_

- [-] 4 system-level flags

  - [x] 4.1 Create system_config_store for system-level flags






    - Implement SystemConfigStore with database connection
    - Implement get_config() to retrieve the singleton system_config row (id=1)
    - Implement set_owner_active() to update owner_active flag via UPDATE query
    - Implement is_owner_active() to check owner_active flag
    - Implement ensure_config_exists() helper to verify singleton row exists
    - All methods must log to audit database at point of action
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 10.1_
  
  - [x] 4.2 Add admin role management methods to user store





    - Implement set_system_admin() to update is_system_admin flag
    - Implement set_role_admin() to update is_role_admin flag
    - Implement get_owner() to retrieve owner account
    - All methods must log to audit database at point of action
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 9.2, 9.3_
  
  - [x] 4.3 Add bootstrap user creation method to user store





    - Implement create_admin_user() accepting username, password_hash, and AdminFlags
    - Support creating users with specific admin roles and status
    - Log creation to audit database
    - _Requirements: 2.1, 2.4, 2.5, 2.8, 2.9, 2.10_

- [ ] 5. Error handling for bootstrap operations
  - [x] 5.1 Create AdminError enum with bootstrap-related error types



    - Add AlreadyBootstrapped, OwnerNotFound, UserNotFound variants
    - Implement proper error messages
    - Implement Display trait for error messages
    - _Requirements: 2.2_

- [-] 6. CLI module for bootstrap and owner management




  - [x] 6.1 Create CLI module structure





    - Create src/cli/mod.rs with submodules
    - Add bootstrap, owner, credential_export modules
    - Update src/lib.rs and src/main.rs to include CLI module
    - _Requirements: 2.1, 7.1_
  
  - [x] 6.2 Implement credential export functionality





    - Create ExportFormat enum (DisplayOnly, CopyUsername, CopyPassword, KeePassXML, BitwardenJSON, Skip)
    - Implement export_credentials() function for each format
    - Add clipboard support using clipboard crate
    - Implement KeePassX XML export format
    - Implement Bitwarden JSON export format
    - Use file naming pattern: {role_type}_{username}.{ext}
    - _Requirements: 10.5, 10.6_
  
  - [x] 6.3 Implement bootstrap command





    - Create bootstrap_system() function that checks if owner exists
    - Reject with "System already bootstrapped" if owner found
    - Generate UUID username for owner account
    - Prompt for owner password (auto-generate or manual entry)
    - Accept any password without validation (validation will be added later)
    - Create owner with is_owner=true
    - System config owner_active already set to false by migration (verify it)
    - Display owner credentials and export options
    - Display warning about owner being inactive
    - Prompt for System Admin count (0-10) and create accounts
    - Prompt for Role Admin count (0-10) and create accounts
    - For each admin account, prompt for password (auto-generate or manual entry)
    - Handle credentials individually for each account
    - Log bootstrap event to audit database
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 10.1, 10.3, 10.4, 10.5, 10.6_
  
  - [x] 6.4 Implement owner management CLI commands



    - Create activate_owner() command that sets system config owner_active=true with confirmation prompt
    - Create deactivate_owner() command that sets system config owner_active=false with confirmation prompt
    - Create get_owner_info() command to display owner username, UUID, and active status
    - All commands must log to audit database with CLI operation type
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 9.1_
  
  - [x] 6.5 Add CLI argument parsing and command routing

    - Use clap or similar for CLI argument parsing
    - Add subcommands: bootstrap, owner (activate/deactivate/info)
    - Route commands to appropriate functions
    - Handle errors and display user-friendly messages
    - _Requirements: 2.1, 7.1_
  
  - [x] 6.6 Update main.rs to support CLI mode


    - Check for CLI arguments at startup
    - If CLI args present, run CLI mode instead of server mode
    - Initialize database connections for CLI operations
    - _Requirements: 2.1, 7.1_

- [-] 7. Audit logging for bootstrap operations


  - [-] 7.1 Extend audit event types for bootstrap operations

    - Add event types for owner activation/deactivation
    - Add event types for CLI operations
    - _Requirements: 9.1, 9.4_
  
  - [ ] 7.2 Update audit logger to capture bootstrap operation metadata
    - Ensure actor_user_id and target_user_id are captured
    - Ensure activation_method distinguishes CLI operations
    - _Requirements: 9.1, 9.4_

- [ ]* 8. Testing
  - [ ]* 8.1 Write integration tests for bootstrap flow
    - Test creating owner + admins in one operation
    - Test rejection of duplicate bootstrap
    - Test system config owner_active=false after bootstrap
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10_
  
  - [ ]* 8.2 Write integration tests for owner activation/deactivation
    - Test CLI activation sets system config owner_active=true
    - Test CLI deactivation sets system config owner_active=false
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [ ]* 8.3 Write integration tests for audit logging
    - Test bootstrap operations logged with correct metadata
    - Test CLI operations logged
    - _Requirements: 9.1, 9.4_

- [ ] 9. Documentation
  - [ ] 9.1 Update .env.example with new configuration options
    - Document any new environment variables needed for admin system
    - _Requirements: All requirements_
  
  - [ ] 9.2 Create bootstrap usage documentation
    - Document bootstrap process and initial setup
    - Document owner activation/deactivation procedures
    - Add to docs/ directory
    - _Requirements: All requirements_

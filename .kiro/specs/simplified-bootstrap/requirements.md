# Requirements Document

## Introduction

Temporary replacement for the existing CLI module (`src/cli/`) during an architecture refactoring period. The current CLI module has accumulated broken references and commented-out code as the app's layered architecture evolves. This feature removes the entire CLI module and replaces it with a single, minimal bootstrap command that directly inserts hardcoded seed users into the SQLite database using SeaORM, bypassing the coordinator/provider/store layers entirely. The goal is to keep the app compilable and bootstrappable while the user finalizes the new architecture. The full CLI will be rebuilt later.

## Glossary

- **Bootstrap_Command**: A single CLI subcommand (`bootstrap`) that seeds the database with hardcoded users
- **Auth_Database**: The main SQLite database storing user accounts (connection available via `DatabaseConnections.auth`)
- **Owner_User**: A hardcoded user with `is_owner = true`, representing the system owner
- **Admin_User**: A hardcoded user with `is_system_admin = true`, representing a system administrator
- **Login_User**: A hardcoded regular user with no admin flags, used for basic authentication testing
- **CLI_Module**: The `src/cli/` directory and all its submodules (`bootstrap.rs`, `credential_export.rs`, `owner.rs`, `password_management.rs`, `old/`)
- **Simplified_Bootstrap**: The replacement module that provides only the bootstrap command

## Requirements

### Requirement 1: Remove Existing CLI Module

**User Story:** As a developer, I want the old CLI module removed, so that I can refactor the architecture without maintaining broken CLI code.

#### Acceptance Criteria

1. WHEN the Simplified_Bootstrap feature is implemented, THE CLI_Module SHALL be replaced with a single module containing only the Bootstrap_Command
2. THE application SHALL compile without errors after the CLI_Module is replaced
3. WHEN the old CLI_Module is removed, THE `lib.rs` and `main.rs` files SHALL be updated to reference the Simplified_Bootstrap module instead
4. THE implementation SHALL only modify files within the CLI_Module, `lib.rs`, and `main.rs`; no other modules SHALL be changed
5. IF compile errors remain outside the CLI_Module after replacement, THE implementation SHALL report them to the developer without attempting to fix them

### Requirement 2: Bootstrap Command Seeds Three Hardcoded Users

**User Story:** As a developer, I want a single bootstrap command that creates an owner, admin, and login user with hardcoded credentials, so that I can quickly seed the database for development and testing.

#### Acceptance Criteria

1. WHEN the Bootstrap_Command is executed, THE Simplified_Bootstrap SHALL insert an Owner_User into the Auth_Database with `is_owner = true`, `is_system_admin = false`, `is_role_admin = false`
2. WHEN the Bootstrap_Command is executed, THE Simplified_Bootstrap SHALL insert an Admin_User into the Auth_Database with `is_owner = false`, `is_system_admin = true`, `is_role_admin = false`
3. WHEN the Bootstrap_Command is executed, THE Simplified_Bootstrap SHALL insert a Login_User into the Auth_Database with `is_owner = false`, `is_system_admin = false`, `is_role_admin = false`
4. THE Simplified_Bootstrap SHALL hash all user passwords using Argon2id before storing them in the Auth_Database
5. THE Simplified_Bootstrap SHALL assign each user a unique UUID as their `id` field
6. THE Simplified_Bootstrap SHALL print the hardcoded usernames and passwords to the console after successful seeding so the developer knows the credentials

### Requirement 3: Direct Database Access

**User Story:** As a developer, I want the bootstrap to write directly to SQLite via SeaORM, so that it does not depend on the coordinator/provider/store layers that are being refactored.

#### Acceptance Criteria

1. THE Simplified_Bootstrap SHALL use the `DatabaseConnection` from `DatabaseConnections.auth` to insert users directly via SeaORM `ActiveModel` operations
2. THE Simplified_Bootstrap SHALL operate independently of the coordinator, provider, and store layers

### Requirement 4: Idempotent Bootstrap

**User Story:** As a developer, I want to run bootstrap multiple times without errors, so that I can re-seed the database after deleting it without worrying about duplicate key conflicts.

#### Acceptance Criteria

1. IF a user with the same username already exists in the Auth_Database, THEN THE Simplified_Bootstrap SHALL skip that user and continue with the remaining users
2. WHEN a user is skipped due to an existing username, THE Simplified_Bootstrap SHALL print a message indicating the user was skipped
3. WHEN the Bootstrap_Command completes, THE Simplified_Bootstrap SHALL print a summary of how many users were created and how many were skipped

### Requirement 5: Minimal CLI Argument Parsing

**User Story:** As a developer, I want the CLI to remain simple with just a bootstrap subcommand and an optional env-file flag, so that the existing main.rs flow stays mostly intact.

#### Acceptance Criteria

1. THE Simplified_Bootstrap SHALL accept an optional `--env-file` argument that defaults to `.env`
2. WHEN no subcommand is provided, THE application SHALL start the web server as normal
3. WHEN the `bootstrap` subcommand is provided, THE application SHALL execute the Bootstrap_Command and exit

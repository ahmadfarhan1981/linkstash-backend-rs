# Design Document

## Overview

This feature adds a `migrate` CLI command that runs database migrations independently of server startup. The design refactors the current migration logic from `init_database()` and `init_audit_database()` into separate, reusable functions that can be called from multiple entry points: the new CLI command, server startup, and existing CLI commands.

The key architectural change is separating "connect to database" from "run migrations" so that migrations can be executed explicitly without initializing the full `AppData` structure.

## Architecture

### Current Architecture

```
main.rs
  ↓
AppData::init()
  ↓
config::init_database() → connects + runs AuthMigrator::up()  [will be renamed to init_auth_database]
config::init_audit_database() → connects + runs AuditMigrator::up()
  ↓
[Server starts OR CLI command runs]
```

**Problem**: Migrations are tightly coupled with database initialization. No way to run migrations without initializing full AppData. Also, `init_database()` naming is inconsistent with `init_audit_database()`.

### Proposed Architecture

```
main.rs
  ↓
[Check CLI args]
  ↓
If "migrate" command:
  config::run_migrations() → connects + migrates + exits
  
If server or other CLI:
  AppData::init()
    ↓
  config::init_auth_database() → calls migrate_auth_database() + returns connection
  config::init_audit_database() → calls migrate_audit_database() + returns connection
    ↓
  [Server starts OR CLI command runs]
```

**Solution**: Extract migration logic into dedicated functions that can be called independently. Rename `init_database()` to `init_auth_database()` for consistency.

## Components and Interfaces

### 1. New CLI Command

**Location**: `src/cli/mod.rs`

Add new `Migrate` command to the `Commands` enum:

```rust
#[derive(Subcommand)]
pub enum Commands {
    /// Run database migrations
    Migrate,
    
    /// Bootstrap the system by creating owner and initial admin accounts
    Bootstrap,
    
    /// Owner account management commands
    #[command(subcommand)]
    Owner(OwnerCommands),
}
```

### 2. Migration CLI Handler

**Location**: `src/cli/migrate.rs` (new file)

```rust
/// Run database migrations for auth and audit databases
/// 
/// This function connects to both databases and runs all pending migrations.
/// It does not initialize the full AppData structure.
/// 
/// # Returns
/// * `Ok(())` - Migrations completed successfully
/// * `Err(...)` - Migration failed
pub async fn run_migrations() -> Result<(), Box<dyn std::error::Error>> {
    // Implementation details in next section
}
```

### 3. Refactored Database Module

**Location**: `src/config/database.rs`

Add new helper functions for explicit migration control:

```rust
/// Run migrations on the auth database
/// 
/// Connects to the database, runs all pending migrations, and closes the connection.
/// 
/// # Returns
/// * `Ok(())` - Migrations completed successfully
/// * `Err(InternalError)` - Connection or migration failed
pub async fn migrate_auth_database() -> Result<(), InternalError> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://auth.db?mode=rwc".to_string());
    
    let db = Database::connect(&database_url).await?;
    tracing::info!("Connected to database: {}", database_url);
    
    AuthMigrator::up(&db, None).await?;
    tracing::info!("Database migrations completed");
    
    Ok(())
}

/// Run migrations on the audit database
/// 
/// Connects to the database, runs all pending migrations, and closes the connection.
/// 
/// # Returns
/// * `Ok(())` - Migrations completed successfully
/// * `Err(InternalError)` - Connection or migration failed
pub async fn migrate_audit_database() -> Result<(), InternalError> {
    let audit_db_path = std::env::var("AUDIT_DB_PATH")
        .unwrap_or_else(|_| "audit.db".to_string());
    let audit_database_url = format!("sqlite://{}?mode=rwc", audit_db_path);
    
    let audit_db = Database::connect(&audit_database_url).await?;
    tracing::info!("Connected to audit database: {}", audit_database_url);
    
    AuditMigrator::up(&audit_db, None).await?;
    tracing::info!("Audit database migrations completed");
    
    Ok(())
}
```

Rename and refactor existing functions to use the new helpers (eliminates code duplication):

```rust
/// Initialize the auth database connection and run migrations
/// 
/// Reads DATABASE_URL from environment or uses default: sqlite://auth.db?mode=rwc
/// 
/// **Note**: Renamed from `init_database()` for consistency with `init_audit_database()`
pub async fn init_auth_database() -> Result<DatabaseConnection, InternalError> {
    // Run migrations first
    migrate_auth_database().await?;
    
    // Then connect and return the connection for use by stores
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://auth.db?mode=rwc".to_string());
    
    let db = Database::connect(&database_url)
        .await
        .map_err(|e| InternalError::database("connect_database", e))?;
    
    Ok(db)
}

/// Initialize the audit database connection and run migrations
/// 
/// Reads AUDIT_DB_PATH from environment or uses default: audit.db
pub async fn init_audit_database() -> Result<DatabaseConnection, InternalError> {
    // Run migrations first
    migrate_audit_database().await?;
    
    // Then connect and return the connection for use by stores
    let audit_db_path = std::env::var("AUDIT_DB_PATH")
        .unwrap_or_else(|_| "audit.db".to_string());
    let audit_database_url = format!("sqlite://{}?mode=rwc", audit_db_path);
    
    let audit_db = Database::connect(&audit_database_url)
        .await
        .map_err(|e| InternalError::database("connect_audit_database", e))?;
    
    Ok(audit_db)
}
```

**Key Design Decision**: The migration functions connect, migrate, and close. The init functions call the migration functions, then connect again and return the connection. This creates two connections briefly but ensures:
1. No code duplication
2. Clean separation of concerns
3. Migration functions can be used independently

## Data Models

No new data models required. Uses existing SeaORM migration infrastructure.


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Migrate command applies all pending migrations

*For any* database state with pending migrations, running the migrate command should result in all migrations being applied to both auth and audit databases.

**Validates: Requirements 1.1**

### Property 2: Successful migration exits with code 0

*For any* database state where migrations succeed, the migrate command should exit with status code 0.

**Validates: Requirements 1.2**

### Property 3: Failed migration exits with code 1

*For any* migration failure scenario, the migrate command should exit with status code 1 and display error details.

**Validates: Requirements 1.3**

### Property 4: Migrate command never starts server

*For any* execution of the migrate command, the web server initialization code should not be invoked.

**Validates: Requirements 1.4**

### Property 5: Migrate command initializes minimal components

*For any* execution of the migrate command, only database connections should be initialized (no stores, services, or secret manager).

**Validates: Requirements 1.5**

### Property 6: Server startup runs migrations

*For any* server startup without CLI arguments, migrations should execute before the web server starts listening.

**Validates: Requirements 2.1**

### Property 7: Migration failure prevents server startup

*For any* migration failure during server startup, the server should not start listening and should display error details.

**Validates: Requirements 2.2**

### Property 8: Server startup logs migration completion

*For any* successful server startup, the logs should contain messages indicating migrations completed.

**Validates: Requirements 2.3**

### Property 9: CLI commands run migrations automatically

*For any* existing CLI command (bootstrap, owner activate, owner deactivate, owner info), migrations should execute before the command logic runs.

**Validates: Requirements 3.1**

### Property 10: Migration failure prevents CLI command execution

*For any* CLI command when migrations fail, the command logic should not execute and error details should be displayed.

**Validates: Requirements 3.2**

### Property 11: CLI commands never start server

*For any* CLI command execution, the web server should not start.

**Validates: Requirements 3.3**

### Property 12: Migration output includes database names

*For any* migration execution, the output should contain identifiers for which database is being migrated (auth or audit).

**Validates: Requirements 4.1**

### Property 13: Connection strings are redacted in output

*For any* migration execution, connection strings in output should not contain sensitive data (passwords, tokens).

**Validates: Requirements 4.2**

### Property 14: Migration output includes summary

*For any* migration execution, the output should contain a summary of migrations applied.

**Validates: Requirements 4.3**

### Property 15: Different entry points produce identical results

*For any* database state, running migrations via the migrate command, server startup, or CLI command should produce identical database schemas.

**Validates: Requirements 5.2**

## Error Handling

### Migration Failures

**Scenario**: Database connection fails
- **Handling**: Return `InternalError::Database` with connection error details
- **User Impact**: Clear error message indicating connection failure
- **Exit Code**: 1

**Scenario**: Migration execution fails (e.g., SQL error)
- **Handling**: Return `InternalError::Database` with migration error details
- **User Impact**: Clear error message indicating which migration failed and why
- **Exit Code**: 1

**Scenario**: Environment variable missing or invalid
- **Handling**: Use default values (auth.db, audit.db)
- **User Impact**: Migrations run on default databases
- **Exit Code**: 0 (success if migrations complete)

### Server Startup Failures

**Scenario**: Migrations fail during server startup
- **Handling**: Panic with error message (current behavior via `expect()`)
- **User Impact**: Server does not start, clear error message displayed
- **Exit Code**: 1

**Scenario**: Migrations succeed but server fails to start
- **Handling**: Existing error handling (not changed by this feature)
- **User Impact**: Error message from server initialization
- **Exit Code**: 1

### CLI Command Failures

**Scenario**: Migrations fail before CLI command
- **Handling**: Panic with error message (current behavior via `expect()`)
- **User Impact**: CLI command does not execute, clear error message displayed
- **Exit Code**: 1

## Testing Strategy

### Unit Tests

Unit tests will verify individual components:

1. **Migration function behavior**
   - Test `migrate_auth_database()` with valid database
   - Test `migrate_audit_database()` with valid database
   - Test error handling for connection failures
   - Test error handling for migration failures

2. **CLI command parsing**
   - Test that `migrate` command is recognized
   - Test that command routes to correct handler

3. **Output formatting**
   - Test that database names appear in output
   - Test that connection strings are redacted
   - Test that success messages are displayed

### Integration Tests

Integration tests will verify end-to-end behavior:

1. **Migrate command execution**
   - Create test databases with pending migrations
   - Run migrate command
   - Verify all migrations applied
   - Verify exit code 0

2. **Server startup with migrations**
   - Create test database with pending migrations
   - Start server (in test mode)
   - Verify migrations ran before server started
   - Verify server starts successfully

3. **CLI command with migrations**
   - Create test database with pending migrations
   - Run bootstrap command
   - Verify migrations ran before bootstrap logic
   - Verify bootstrap completes successfully

4. **Migration failure scenarios**
   - Simulate connection failure
   - Run migrate command
   - Verify exit code 1
   - Verify error message displayed

### Manual Testing

Manual testing will verify user experience:

1. Run `cargo run migrate` on fresh database
2. Run `cargo run migrate` on up-to-date database
3. Run `cargo run` (server) and verify migrations run
4. Run `cargo run bootstrap` and verify migrations run
5. Verify output messages are clear and helpful

## Implementation Notes

### Backward Compatibility

The refactoring maintains backward compatibility:
- `init_database()` and `init_audit_database()` remain unchanged
- Server startup behavior unchanged
- Existing CLI commands unchanged
- Only adds new functionality (migrate command)

### Code Reuse

The new `migrate_auth_database()` and `migrate_audit_database()` functions can be called from:
1. The new `migrate` CLI command
2. The existing `init_database()` and `init_audit_database()` functions (optional refactor)
3. Future migration-related features

### Logging

Migration operations will use the existing `tracing` infrastructure:
- `tracing::info!()` for successful operations
- `tracing::error!()` for failures
- Connection strings logged with sensitive data redacted

### Environment Variables

Uses existing environment variables:
- `DATABASE_URL` - Main database connection string (default: `sqlite://auth.db?mode=rwc`)
- `AUDIT_DB_PATH` - Audit database path (default: `audit.db`)

No new environment variables required.

## Alternative Designs Considered

### Alternative 1: Separate Migration Binary

**Approach**: Create a separate binary (`migration/src/main.rs`) for running migrations.

**Pros**:
- Complete separation of concerns
- Smaller binary for migration-only operations
- Standard SeaORM pattern

**Cons**:
- Requires separate compilation
- Users must know about two binaries
- Duplicates environment variable handling
- More complex deployment

**Decision**: Rejected. CLI command approach is simpler and more user-friendly.

### Alternative 2: Always Run Migrations

**Approach**: Keep current behavior, don't add explicit migrate command.

**Pros**:
- No code changes required
- Simplest implementation

**Cons**:
- No explicit control over migrations
- Can't run migrations without starting server or running another command
- Poor fit for CI/CD pipelines
- Difficult to troubleshoot migration issues

**Decision**: Rejected. Explicit control is valuable for production deployments.

### Alternative 3: Lazy Migration Loading

**Approach**: Don't run migrations automatically, require explicit migrate command before any operation.

**Pros**:
- Maximum control
- Clear separation of migration and operation phases

**Cons**:
- Breaks existing workflow
- Requires manual step for local development
- Poor developer experience
- Breaking change

**Decision**: Rejected. Automatic migrations for server/CLI is good developer experience.

## Future Enhancements

Potential future improvements (out of scope for this feature):

1. **Migration rollback**: Add `migrate down` command to rollback migrations
2. **Migration status**: Add `migrate status` command to show pending migrations
3. **Dry run**: Add `--dry-run` flag to show what would be migrated
4. **Specific migration**: Add ability to migrate to specific version
5. **Migration history**: Show history of applied migrations with timestamps

These enhancements would build on the foundation established by this feature.

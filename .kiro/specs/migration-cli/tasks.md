# Implementation Plan

## Core Implementation (Completed)

- [x] 1. Implement database connection and migration separation
  - Created `init_database()` function that only connects to auth database
  - Created `init_audit_database()` function that only connects to audit database
  - Created `migrate_auth_database(db)` function that runs migrations on provided connection
  - Created `migrate_audit_database(audit_db)` function that runs migrations on provided connection
  - Updated `main.rs` to orchestrate: connect → migrate → use connections
  - Updated `AppData::init()` to accept pre-migrated database connections as parameters
  - _Requirements: 5.1, 5.2, 5.3_

- [x] 2. Add migrate CLI command
  - Added `Migrate` variant to `Commands` enum in `src/cli/mod.rs`
  - Created `src/cli/migrate.rs` with `run_migrations()` implementation
  - Implemented connection and migration logic in migrate handler
  - Added routing in `main.rs` to detect migrate command and exit after migrations
  - Verified `cargo run migrate` works correctly
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 3. Verify automatic migrations work
  - Tested server startup - migrations run automatically before server starts
  - Tested CLI commands (bootstrap) - migrations run automatically before command executes
  - Verified migration failures prevent server/CLI execution
  - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.2, 3.3_

## Remaining Tasks

- [x] 4. Enhance migration output formatting


  - Add explicit "Migrations completed successfully" message with count of migrations applied
  - Add "Database already up to date" message when no pending migrations exist
  - Ensure connection strings are visible in output (currently using debug level)
  - Test via `cargo run migrate` and verify output is clear and informative
  - _Requirements: 4.2, 4.3, 4.4_



- [x] 5. Update tech.md documentation

  - Add `cargo run migrate` command to Commands section
  - Document that migrations run automatically on server startup
  - Document that migrations run automatically before CLI commands
  - Explain the new architecture (connect → migrate → use)
  - _Requirements: 1.1_

- [ ]* 6. Write unit tests for migration functions (optional)
  - Test `migrate_auth_database()` with valid database connection
  - Test `migrate_audit_database()` with valid database connection
  - Test error handling for migration failures
  - _Requirements: 1.1, 1.2, 1.3_

- [ ]* 7. Write integration tests for migrate command (optional)
  - Test migrate command with pending migrations
  - Test migrate command with up-to-date database
  - Test migrate command with connection failure
  - Test that server startup still runs migrations
  - Test that CLI commands still run migrations
  - _Requirements: 1.1, 2.1, 3.1_

- [ ] 8. Final verification
  - Run all tests and ensure they pass
  - Manually test all scenarios (migrate command, server startup, CLI commands)
  - Verify error handling works correctly
  - Ask user if any questions arise

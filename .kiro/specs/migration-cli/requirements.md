# Requirements Document

## Introduction

This feature adds a dedicated CLI command for running database migrations independently of server startup or other CLI operations. Currently, migrations run automatically during `AppData::init()`, which means they execute whether starting the server or running any CLI command. This feature provides explicit control over when migrations run, supporting deployment scenarios, troubleshooting, and CI/CD pipelines.

## Glossary

- **Migration**: A database schema change operation that transforms the database from one version to another
- **AuthMigrator**: The SeaORM migrator for the main authentication database (auth.db)
- **AuditMigrator**: The SeaORM migrator for the audit logging database (audit.db)
- **CLI**: Command-line interface for administrative operations
- **AppData**: Centralized application data structure containing database connections and stores

## Requirements

### Requirement 1

**User Story:** As a system administrator, I want to run database migrations explicitly via CLI command, so that I can control when schema changes are applied independently of server startup.

#### Acceptance Criteria

1. WHEN a user runs the migrate command THEN the system SHALL execute all pending migrations for both auth and audit databases
2. WHEN migrations complete successfully THEN the system SHALL exit with status code 0 and display success message
3. WHEN migrations fail THEN the system SHALL exit with status code 1 and display error details
4. WHEN the migrate command runs THEN the system SHALL NOT start the web server
5. WHEN the migrate command runs THEN the system SHALL initialize only the database connections required for migrations

### Requirement 2

**User Story:** As a developer, I want migrations to continue running automatically on server startup, so that local development remains seamless without manual migration steps.

#### Acceptance Criteria

1. WHEN the server starts without CLI arguments THEN the system SHALL run migrations automatically before starting the web server
2. WHEN migrations fail during server startup THEN the system SHALL prevent server startup and display error details
3. WHEN the server starts successfully THEN the system SHALL log that migrations completed

### Requirement 3

**User Story:** As a developer, I want existing CLI commands to continue working without requiring manual migration steps, so that the current workflow remains unchanged.

#### Acceptance Criteria

1. WHEN a user runs bootstrap, owner, or other CLI commands THEN the system SHALL run migrations automatically before executing the command
2. WHEN migrations fail before a CLI command THEN the system SHALL prevent command execution and display error details
3. WHEN a CLI command completes THEN the system SHALL exit without starting the web server

### Requirement 4

**User Story:** As a system administrator, I want the migrate command to provide clear output about migration progress, so that I can verify which migrations were applied.

#### Acceptance Criteria

1. WHEN migrations run THEN the system SHALL display which database is being migrated (auth or audit)
2. WHEN migrations run THEN the system SHALL display the connection string being used (with sensitive data redacted)
3. WHEN migrations complete THEN the system SHALL display a summary of migrations applied
4. WHEN no pending migrations exist THEN the system SHALL display a message indicating the database is up to date

### Requirement 5

**User Story:** As a developer, I want the migration logic to be centralized and reusable, so that the same code runs migrations whether invoked via CLI, server startup, or other commands.

#### Acceptance Criteria

1. WHEN migration logic is refactored THEN the system SHALL use a single function for running migrations
2. WHEN migrations are invoked from different entry points THEN the system SHALL execute identical migration logic
3. WHEN migration behavior changes THEN the system SHALL require updates in only one location

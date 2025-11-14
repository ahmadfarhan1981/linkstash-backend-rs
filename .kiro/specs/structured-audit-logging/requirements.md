# Requirements Document

## Introduction

This document specifies a structured logging system for the Linkstash backend that separates ephemeral application logs from long-term security audit logs. The system provides both type-safe helper functions for common authentication events and an extensible builder pattern for custom audit events, ensuring consistent formatting and preventing accidental exposure of sensitive data.

## Glossary

- **Logging System**: The complete logging infrastructure including application logs and audit logs
- **Application Log**: Ephemeral operational log entries for debugging and monitoring (DEBUG, INFO, WARN, ERROR levels)
- **Audit Log**: Long-term security event records tracking user actions and authentication events
- **Audit Event**: A structured, immutable record of a security-relevant action with timestamp, event type, user identifier, and contextual fields
- **Helper Function**: Pre-defined function for logging common authentication events (e.g., login_success, jwt_issued)
- **Audit Builder**: Extensible API for creating custom audit events with type-safe field addition
- **Sensitive Data**: Information that must not appear in logs including passwords, tokens, API keys, and cryptographic secrets
- **Audit Database**: Dedicated SQLite database file separate from application data for storing Audit Events
- **Hybrid Schema**: Database schema with indexed columns for common queryable fields and a JSON column for event-specific extensible data
- **Common Fields**: Frequently queried fields stored as database columns (timestamp, event_type, user_id, username, ip_address) for fast filtering
- **Event-Specific Fields**: Fields unique to particular event types stored in a JSON column for extensibility without schema migrations

## Requirements

### Requirement 1

**User Story:** As a system administrator, I want application logs displayed in the console and optionally written to files, so that I can monitor system operations and debug issues

#### Acceptance Criteria

1. WHEN the Logging System initializes, THE Logging System SHALL configure console output for Application Logs with human-readable formatting
2. THE Logging System SHALL support standard log levels (DEBUG, INFO, WARN, ERROR) for Application Logs
3. WHERE file output is enabled via environment variable, THE Logging System SHALL write Application Logs to a rotating file with configurable retention period
4. THE Logging System SHALL include timestamp, log level, module path, and message in each Application Log entry
5. THE Logging System SHALL use the tracing framework with tracing-subscriber for Application Log output

### Requirement 2

**User Story:** As a security auditor, I want all authentication and authorization events logged to a dedicated audit database with queryable structure, so that I can efficiently review security incidents and maintain compliance

#### Acceptance Criteria

1. THE Logging System SHALL store all Audit Events in a dedicated SQLite database file separate from the application database
2. THE Logging System SHALL use a hybrid schema with indexed columns for common fields (timestamp, event_type, user_id, username, ip_address) and a JSON column for event-specific fields
3. WHEN an Audit Event is created, THE Logging System SHALL include timestamp in UTC, event_type, and at least one user identifier (user_id or username)
4. THE Logging System SHALL store the Audit Database file at a configurable path with default value audit.db
5. THE Logging System SHALL ensure Audit Events are append-only with no update or delete operations exposed through the API
6. THE Logging System SHALL create indexes on timestamp, event_type, user_id, and username columns for efficient forensic queries
7. THE Logging System SHALL store event-specific fields (token_id, failure_reason, expiration_timestamp, etc.) in the JSON data column to allow extensibility without schema migrations

### Requirement 3

**User Story:** As a developer, I want pre-defined helper functions for common authentication events, so that I can log security events consistently without manually constructing log entries

#### Acceptance Criteria

1. THE Logging System SHALL provide a helper function for logging successful login events with user_id and IP address parameters
2. THE Logging System SHALL provide a helper function for logging failed login events with username, failure reason, and IP address parameters
3. THE Logging System SHALL provide a helper function for logging JWT issuance with user_id, token identifier, and expiration timestamp parameters
4. THE Logging System SHALL provide a helper function for logging JWT validation failures with failure reason and token identifier hash parameters
5. THE Logging System SHALL provide a helper function for logging refresh token issuance with user_id and token identifier parameters
6. THE Logging System SHALL provide a helper function for logging refresh token revocation with user_id and token identifier parameters
7. WHEN a helper function is called, THE Logging System SHALL automatically format the Audit Event with consistent field names and structure

### Requirement 4

**User Story:** As a developer extending the system with new features, I want an extensible API for logging custom audit events, so that I can maintain audit trails for new security-relevant actions

#### Acceptance Criteria

1. THE Logging System SHALL provide an Audit Builder API that accepts custom event type strings
2. THE Logging System SHALL require either user_id or username to be set before an Audit Event can be written via the Audit Builder
3. THE Logging System SHALL allow arbitrary fields to be added to Audit Events via the Audit Builder with automatic JSON serialization
4. THE Logging System SHALL provide a method in the Audit Builder for marking fields as sensitive with automatic redaction
5. WHEN the Audit Builder write method is called, THE Logging System SHALL validate that required fields are present and return an error if validation fails

### Requirement 5

**User Story:** As a security engineer, I want the logging system to prevent accidental exposure of sensitive data, so that passwords, tokens, and secrets never appear in any log output

#### Acceptance Criteria

1. THE Logging System SHALL never log passwords, JWT tokens, refresh tokens, API keys, or cryptographic secrets in plaintext
2. WHEN logging token-related events, THE Logging System SHALL log only token identifiers or SHA-256 hashes, never full token values
3. THE Logging System SHALL provide clear documentation on what constitutes Sensitive Data and how to handle it in custom Audit Events
4. THE Logging System SHALL redact Sensitive Data fields marked via the Audit Builder add_sensitive method
5. THE Logging System SHALL include guidelines in documentation for developers on avoiding Sensitive Data exposure in Application Logs

### Requirement 6

**User Story:** As a system administrator, I want logging configuration controlled via environment variables, so that I can adjust log levels, database paths, and retention without code changes

#### Acceptance Criteria

1. THE Logging System SHALL read log level configuration from a LOG_LEVEL environment variable with default value INFO
2. THE Logging System SHALL read Audit Database file path from an AUDIT_DB_PATH environment variable with default value audit.db
3. THE Logging System SHALL read Audit Log retention period from an AUDIT_LOG_RETENTION_DAYS environment variable with default value 90
4. WHERE an APP_LOG_FILE environment variable is set, THE Logging System SHALL enable Application Log file output to the specified path
5. THE Logging System SHALL read Application Log retention period from an APP_LOG_RETENTION_DAYS environment variable with default value 7
6. THE Logging System SHALL validate environment variable values and log warnings for invalid configurations while using default values

### Requirement 7

**User Story:** As a developer, I want comprehensive documentation on extending audit logging, so that I can add custom audit events correctly and securely

#### Acceptance Criteria

1. THE Logging System SHALL include documentation in docs/extending-audit-logs.md explaining the Audit Builder API
2. THE documentation SHALL provide code examples for common custom audit event scenarios
3. THE documentation SHALL list all available helper functions with parameter descriptions
4. THE documentation SHALL explain security guidelines for handling Sensitive Data in custom Audit Events
5. THE documentation SHALL describe the hybrid database schema with common indexed fields and JSON data column
6. THE documentation SHALL provide SQL query examples for common forensic analysis scenarios (filtering by time range, event type, user, and event-specific fields)

### Requirement 8

**User Story:** As a system administrator, I want the audit database to be easily archivable and separate from application data, so that I can manage long-term storage and compliance requirements independently

#### Acceptance Criteria

1. THE Logging System SHALL use a separate SQLite database file for audit logs distinct from the application database
2. THE Logging System SHALL support configuring the Audit Database file path via environment variable to enable custom storage locations
3. THE Logging System SHALL maintain a separate database connection pool for the Audit Database to prevent contention with application database operations
4. THE Logging System SHALL document procedures for archiving old audit data by copying or moving the Audit Database file
5. THE Logging System SHALL ensure the Audit Database can be safely copied while the application is running for backup purposes

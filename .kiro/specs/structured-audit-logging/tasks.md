# Implementation Plan

- [x] 1. Set up audit database infrastructure





  - Create migration for audit_events table with indexed columns (timestamp, event_type, user_id, jwt_id) and JSON data column
  - Add audit database connection initialization in main.rs with separate connection pool
  - Configure audit database path from AUDIT_DB_PATH environment variable (default: audit.db)
  - _Requirements: 2.1, 2.2, 2.4, 2.6, 6.2, 8.1, 8.3_

- [x] 2. Implement audit event data structures






  - Create EventType enum in types/internal/audit.rs with variants for LoginSuccess, LoginFailure, JwtIssued, JwtValidationFailure, JwtTampered, RefreshTokenIssued, RefreshTokenRevoked, and Custom
  - Create AuditEvent struct with event_type, user_id, ip_address, jwt_id, and data HashMap fields
  - Create AuditError enum with MissingUserId, DatabaseError, SerializationError, and ConfigError variants
  - Implement Display trait for EventType to convert enum variants to string event type names
  - _Requirements: 2.2, 2.3, 4.1, 4.5_

- [x] 3. Create audit store repository





  - Implement AuditStore struct in stores/audit_store.rs with DatabaseConnection field
  - Implement write_event method that validates user_id presence, serializes data HashMap to JSON, and inserts into audit_events table
  - Handle database errors and return AuditError variants appropriately
  - _Requirements: 2.1, 2.5, 4.5_

- [x] 4. Implement helper functions for common authentication events




- [x] 4.1 Create audit_logger service module


  - Create services/audit_logger.rs module file
  - Define module structure for helper functions and AuditBuilder
  - _Requirements: 3.7_

- [x] 4.2 Implement login event helpers


  - Implement log_login_success function accepting AuditStore, user_id, and optional ip_address
  - Implement log_login_failure function accepting AuditStore, optional user_id, failure_reason, and optional ip_address
  - _Requirements: 3.1, 3.2, 3.7_

- [x] 4.3 Implement JWT event helpers


  - Implement log_jwt_issued function accepting AuditStore, user_id, jwt_id, and expiration timestamp
  - Implement log_jwt_validation_failure function accepting AuditStore, user_id, optional jwt_id, and failure_reason
  - Implement log_jwt_tampered function accepting AuditStore, user_id, optional jwt_id, full_jwt string, and failure_reason
  - _Requirements: 3.3, 3.4, 3.7, 5.1, 5.2_

- [x] 4.4 Implement refresh token event helpers


  - Implement log_refresh_token_issued function accepting AuditStore, user_id, jwt_id, and token_id
  - Implement log_refresh_token_revoked function accepting AuditStore, user_id, optional jwt_id, and token_id
  - _Requirements: 3.5, 3.6, 3.7_

- [x] 5. Implement AuditBuilder for custom events





  - Create AuditBuilder struct with AuditEvent and Arc<AuditStore> fields
  - Implement new method accepting AuditStore and event_type (Into<EventType>)
  - Implement user_id, ip_address, and jwt_id setter methods with builder pattern
  - Implement add_field method for arbitrary field addition with JSON serialization
  - Implement add_sensitive method that redacts values by storing "[REDACTED]" string
  - Implement write method that validates user_id presence and calls AuditStore::write_event
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 5.4_

- [x] 6. Set up application logging with tracing framework





  - Add tracing and tracing-subscriber dependencies to Cargo.toml
  - Create config/logging.rs module with LoggingConfig struct for log_level, app_log_file, and app_log_retention_days
  - Implement init_logging function that configures tracing_subscriber with console layer and optional file layer
  - Configure log level filter from LOG_LEVEL environment variable (default: INFO)
  - Configure file output if APP_LOG_FILE environment variable is set
  - Configure file rotation based on APP_LOG_RETENTION_DAYS environment variable (default: 7)
  - Initialize logging in main.rs before server startup
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 6.1, 6.4, 6.5, 6.6_

- [x] 7. Integrate audit logging into authentication endpoints






  - Add audit_store to API handler state/context
  - Call log_login_success in auth login endpoint after successful authentication
  - Call log_login_failure in auth login endpoint when authentication fails
  - Call log_jwt_issued in token generation code after creating JWT
  - Call log_jwt_validation_failure in JWT validation middleware for normal failures (expired, missing)
  - Call log_jwt_tampered in JWT validation middleware when signature validation fails or token is malformed
  - Call log_refresh_token_issued in refresh endpoint after generating new refresh token
  - Extract IP address from request headers and pass to audit logging functions
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 5.1, 5.2_

- [x] 8. Create developer documentation






  - Create docs/extending-audit-logs.md with sections for Overview, Helper Functions, AuditBuilder API, Security Guidelines, Database Schema, and Query Examples
  - Document all helper functions with parameter descriptions and usage examples
  - Provide AuditBuilder code examples for custom event scenarios
  - List sensitive data types that must never be logged (passwords, full tokens, API keys, secrets)
  - Explain when to use add_sensitive method for redaction
  - Document hybrid schema with indexed common fields and JSON data column
  - Provide SQL query examples for filtering by time range, event_type, user_id, jwt_id, and extracting JSON fields
  - Include archival procedures for copying audit database file
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 5.3, 5.5, 8.4, 8.5_

- [x] 9. Update environment configuration





  - Add LOG_LEVEL, APP_LOG_FILE, APP_LOG_RETENTION_DAYS, AUDIT_DB_PATH, and AUDIT_LOG_RETENTION_DAYS to .env.example with example values and comments
  - Document default values for each environment variable
  - Add comments explaining purpose and format requirements for each variable
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 8.2_


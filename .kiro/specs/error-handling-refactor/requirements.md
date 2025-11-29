# Requirements Document

## Introduction

The current error handling system uses a catch-all `AuthError::Internal` variant for many different types of errors (database errors, parsing errors, cryptographic errors, etc.). This makes it difficult to handle errors appropriately, provide meaningful error messages, and debug issues. This feature will refactor the error handling system to use specific error types that accurately represent the underlying failure modes while maintaining security best practices.

## Glossary

- **AuthError**: Error type for authentication-related operations exposed via API endpoints
- **AdminError**: Error type for administrative operations exposed via API endpoints
- **Internal Error**: An error that occurs within the system (database, parsing, crypto) that should not expose implementation details to API clients
- **Domain Error**: An error specific to business logic (invalid credentials, duplicate username, etc.)
- **Infrastructure Error**: An error from external dependencies (database, crypto libraries, etc.)
- **Error Propagation**: The process of converting internal errors to API-appropriate error responses
- **SeaORM**: The database ORM library that can produce `DbErr` errors
- **Argon2**: Password hashing library that can produce hashing/verification errors

## Requirements

### Requirement 1

**User Story:** As a developer, I want specific error types for different failure modes, so that I can handle errors appropriately and debug issues effectively.

#### Acceptance Criteria

1. WHEN a database operation fails THEN the system SHALL represent it with a specific database error type
2. WHEN a UUID parsing operation fails THEN the system SHALL represent it with a specific parsing error type
3. WHEN a cryptographic operation fails THEN the system SHALL represent it with a specific cryptographic error type
4. WHEN a transaction fails THEN the system SHALL represent it with a specific transaction error type
5. WHEN a required resource is not found THEN the system SHALL represent it with a specific not-found error type

### Requirement 2

**User Story:** As a security engineer, I want internal errors to be logged with full details but exposed to API clients with generic messages, so that implementation details are not leaked.

#### Acceptance Criteria

1. WHEN an internal error occurs THEN the system SHALL log the full error details including error type and message
2. WHEN an internal error is converted to an API response THEN the system SHALL return a generic "Internal server error" message
3. WHEN a domain error occurs THEN the system SHALL return a specific error message appropriate for the client
4. WHEN an infrastructure error occurs THEN the system SHALL log the underlying library error details
5. WHEN an error is logged THEN the system SHALL include sufficient context to debug the issue

### Requirement 3

**User Story:** As a developer, I want a clear separation between internal errors and API errors, so that error handling is consistent and maintainable.

#### Acceptance Criteria

1. WHEN defining error types THEN the system SHALL separate internal error types from API error types
2. WHEN an internal error needs to be returned via API THEN the system SHALL convert it to an appropriate API error type
3. WHEN converting internal errors to API errors THEN the system SHALL preserve error semantics while protecting implementation details
4. WHEN a store or service returns an error THEN the system SHALL use internal error types
5. WHEN an API endpoint returns an error THEN the system SHALL use API error types

### Requirement 4

**User Story:** As a developer, I want errors to carry context about what operation failed, so that I can understand the error without examining stack traces.

#### Acceptance Criteria

1. WHEN a database query fails THEN the error SHALL include information about which entity or operation failed
2. WHEN a parsing operation fails THEN the error SHALL include information about what was being parsed
3. WHEN a cryptographic operation fails THEN the error SHALL include information about which operation failed
4. WHEN a transaction fails THEN the error SHALL include information about which transaction failed
5. WHEN a resource is not found THEN the error SHALL include information about which resource was not found

### Requirement 5

**User Story:** As a developer, I want error conversion to be explicit and type-safe, so that I don't accidentally expose internal details.

#### Acceptance Criteria

1. WHEN converting internal errors to API errors THEN the system SHALL require explicit conversion (no automatic From implementations for internal-to-API conversions)
2. WHEN an internal error type is defined THEN the system SHALL NOT implement poem-openapi traits
3. WHEN an API error type is defined THEN the system SHALL implement poem-openapi ApiResponse trait
4. WHEN a store function returns an error THEN the system SHALL return an internal error type
5. WHEN an API endpoint returns an error THEN the system SHALL explicitly convert internal errors to API errors

### Requirement 6

**User Story:** As a developer, I want consistent error handling patterns across all stores and services, so that error handling is predictable.

#### Acceptance Criteria

1. WHEN a store performs a database operation THEN the system SHALL handle database errors consistently
2. WHEN a service calls multiple stores THEN the system SHALL propagate errors consistently
3. WHEN an API endpoint calls a service THEN the system SHALL convert errors consistently
4. WHEN an error occurs in a transaction THEN the system SHALL handle rollback errors consistently
5. WHEN multiple error types can occur THEN the system SHALL use a unified error enum that represents all possibilities

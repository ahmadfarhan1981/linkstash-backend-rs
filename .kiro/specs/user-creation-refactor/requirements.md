# Requirements Document

## Introduction

This specification defines a refactoring of the user creation and privilege assignment system to improve auditability, consistency, and separation of concerns. The current implementation has multiple methods for creating users with different privilege levels (`add_user`, `create_admin_user`), which makes audit log filtering difficult and violates the single responsibility principle. This refactoring will establish clear primitives for user creation and privilege assignment, ensure all operations (including CLI operations) are properly audited, and provide consistent request context throughout the system.

## Glossary

- **CredentialStore**: The data access layer responsible for user credential management and database operations
- **RequestContext**: A data structure containing contextual information about a request (IP address, request ID, authentication state, claims, and source)
- **User**: A system account with credentials (username and password hash)
- **Privilege**: Administrative rights assigned to a user (owner, system admin, or role admin)
- **CLI**: Command-line interface for administrative operations
- **Audit Log**: Immutable record of security-relevant events stored in the audit database
- **Bootstrap**: Initial system setup process that creates the owner and initial admin accounts
- **Owner**: The highest-privilege account with emergency admin management capabilities
- **System Admin**: Administrative account with system-wide privileges
- **Role Admin**: Administrative account with role management privileges
- **Primitive Operation**: A fundamental, atomic operation that cannot be decomposed further

## Requirements

### Requirement 1

**User Story:** As a security auditor, I want all user creation operations to use a single primitive method, so that I can reliably filter and analyze user creation events in the audit logs.

#### Acceptance Criteria

1. THE CredentialStore SHALL provide a single primitive method for creating users that never assigns administrative privileges
2. WHEN a user is created through the primitive method THEN the system SHALL set all privilege flags (is_owner, is_system_admin, is_role_admin) to false
3. WHEN any code path creates a user THEN the system SHALL ultimately call the primitive user creation method
4. THE primitive user creation method SHALL accept a RequestContext parameter for audit logging
5. THE primitive user creation method SHALL log user creation events to the audit database at the point of action

### Requirement 2

**User Story:** As a security auditor, I want privilege assignment to be a separate operation from user creation, so that I can easily identify when administrative rights are granted and filter audit logs by privilege type.

#### Acceptance Criteria

1. THE CredentialStore SHALL provide separate primitive methods for assigning each privilege type (owner, system admin, role admin)
2. WHEN a privilege is assigned to a user THEN the system SHALL log the privilege assignment as a distinct audit event
3. WHEN a privilege is removed from a user THEN the system SHALL log the privilege removal as a distinct audit event
4. THE privilege assignment methods SHALL accept a RequestContext parameter for audit logging
5. THE privilege assignment methods SHALL update only the specific privilege flag being modified

### Requirement 3

**User Story:** As a developer, I want helper methods that combine user creation and privilege assignment, so that I can maintain backward compatibility and convenience while using the new primitives internally.

#### Acceptance Criteria

1. WHEN a helper method creates an admin user THEN the system SHALL first call the primitive user creation method
2. WHEN a helper method creates an admin user THEN the system SHALL subsequently call the appropriate privilege assignment method(s)
3. THE helper methods SHALL accept a RequestContext parameter and pass it to the primitive operations
4. THE helper methods SHALL maintain the same external interface as existing methods for backward compatibility
5. WHEN a helper method fails during privilege assignment THEN the system SHALL handle the partially-created user appropriately

### Requirement 4

**User Story:** As a system administrator, I want CLI operations to be audited with clear source identification, so that I can distinguish between API-initiated and CLI-initiated operations in the audit logs.

#### Acceptance Criteria

1. THE RequestContext SHALL include a source field indicating the origin of the request (API, CLI, or System)
2. WHEN a CLI command creates or modifies users THEN the system SHALL create a RequestContext with source set to CLI
3. WHEN an API endpoint creates or modifies users THEN the system SHALL create a RequestContext with source set to API
4. WHEN the system performs automated operations THEN the system SHALL create a RequestContext with source set to System
5. THE audit logs SHALL include the request source for all user creation and privilege assignment events

### Requirement 5

**User Story:** As a security auditor, I want CLI session lifecycle events to be audited, so that I can track when administrative CLI operations begin and end.

#### Acceptance Criteria

1. WHEN a CLI command starts execution THEN the system SHALL log a CLI session start event to the audit database
2. WHEN a CLI command completes successfully THEN the system SHALL log a CLI session end event with success status
3. WHEN a CLI command fails or is interrupted THEN the system SHALL log a CLI session end event with failure status
4. THE CLI session events SHALL include the command name and any relevant parameters (excluding sensitive data)
5. THE CLI session events SHALL use a RequestContext with CLI source and appropriate actor identification

### Requirement 6

**User Story:** As a developer, I want the RequestContext structure to support CLI operations, so that all operations can use a consistent context pattern regardless of their origin.

#### Acceptance Criteria

1. THE RequestContext SHALL include an optional actor_id field for identifying who initiated the operation
2. WHEN a CLI operation is performed THEN the system SHALL populate actor_id with "cli" or the authenticated user if available
3. WHEN an API operation is performed THEN the system SHALL populate actor_id from the JWT claims
4. WHEN a system operation is performed THEN the system SHALL populate actor_id with "system"
5. THE RequestContext SHALL support operations where IP address is not available (CLI operations)

### Requirement 7

**User Story:** As a developer, I want clear documentation of the refactored user creation flow, so that I can correctly implement new features that create or modify users.

#### Acceptance Criteria

1. THE system SHALL provide documentation explaining the primitive operations and their usage
2. THE documentation SHALL include examples of creating users with and without privileges
3. THE documentation SHALL explain when to use primitive operations versus helper methods
4. THE documentation SHALL describe the RequestContext requirements for different operation sources
5. THE documentation SHALL include migration guidance for existing code using the old methods

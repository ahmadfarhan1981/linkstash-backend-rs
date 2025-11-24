# Requirements Document

## Introduction

This feature implements API endpoints for managing admin roles (System Admin and Role Admin) in the Linkstash authentication backend. Building on the bootstrap functionality, this spec adds the ability for owners and system admins to assign and remove admin roles via REST API, with proper authorization checks, self-modification prevention, and comprehensive audit logging.

## Glossary

- **Owner**: A special account with the highest privileges, used for emergency admin management. Can assign/remove System Admin and Role Admin roles via API.
- **System Admin**: Administrative account for day-to-day system operations. Can assign/remove Role Admin roles via API.
- **Role Admin**: Administrative role flag reserved for future application role management functionality.
- **Self-Modification**: Any attempt by a user to assign or remove admin roles to/from their own account.
- **System**: The Linkstash authentication backend.
- **AdminService**: Service layer component that orchestrates admin role management operations.
- **AdminApi**: API layer component that exposes REST endpoints for admin role management.

## Requirements

### Requirement 1: Owner API Privileges

**User Story:** As an owner, I want API endpoints to assign and remove System Admin and Role Admin roles, so that I can manage the administrative team remotely without CLI access.

#### Acceptance Criteria

1. WHEN a user has is_owner set to true, THE System SHALL provide an API endpoint to assign System Admin role to other users
2. WHEN a user has is_owner set to true, THE System SHALL provide an API endpoint to remove System Admin role from other users
3. WHEN a user has is_owner set to true, THE System SHALL provide an API endpoint to assign Role Admin role to other users
4. WHEN a user has is_owner set to true, THE System SHALL provide an API endpoint to remove Role Admin role from other users
5. THE System SHALL log all admin role assignment and removal actions to the audit database

### Requirement 2: System Admin API Privileges

**User Story:** As a system admin, I want API endpoints to manage Role Admin assignments, so that I can delegate role management responsibilities without requiring owner access.

#### Acceptance Criteria

1. WHEN a user has is_system_admin set to true, THE System SHALL provide an API endpoint to assign Role Admin role to other users
2. WHEN a user has is_system_admin set to true, THE System SHALL provide an API endpoint to remove Role Admin role from other users

### Requirement 3: Self-Modification Prevention via API

**User Story:** As a security architect, I want to prevent users from modifying their own admin roles via API, so that compromised sessions cannot be used for privilege escalation.

#### Acceptance Criteria

1. WHEN a user attempts to assign any admin role to their own account via API, THE System SHALL reject the operation with error message "Cannot modify your own admin roles"
2. WHEN a user attempts to remove any admin role from their own account via API, THE System SHALL reject the operation with error message "Cannot modify your own admin roles"
3. THE System SHALL log all attempted self-modification operations to the audit database

### Requirement 4: Token Invalidation on Role Changes

**User Story:** As a security architect, I want all active tokens invalidated when admin roles change, so that permissions are enforced immediately without waiting for token expiration.

#### Acceptance Criteria

1. WHEN an admin role is assigned to a user, THE System SHALL invalidate all active refresh tokens for that user
2. WHEN an admin role is removed from a user, THE System SHALL invalidate all active refresh tokens for that user
3. WHEN admin roles change, THE System SHALL issue new JWTs with updated claims

### Requirement 5: Owner Self-Deactivation via API

**User Story:** As an owner, I want an API endpoint to deactivate my own account, so that I can lock the account after emergency use without requiring CLI access.

#### Acceptance Criteria

1. THE System SHALL provide an API endpoint for the owner to deactivate their own account
2. WHEN the owner account is deactivated via API, THE System SHALL invalidate all active JWTs for that account
3. WHEN the owner account is deactivated via API, THE System SHALL log the deactivation to the audit database

### Requirement 6: Authorization Enforcement

**User Story:** As a security architect, I want strict authorization checks on all admin role management endpoints, so that only users with appropriate privileges can modify admin roles.

#### Acceptance Criteria

1. WHEN a non-owner user attempts to assign System Admin role, THE System SHALL reject the operation with error "Owner role required"
2. WHEN a non-owner user attempts to remove System Admin role, THE System SHALL reject the operation with error "Owner role required"
3. WHEN a non-owner and non-system-admin user attempts to assign Role Admin role, THE System SHALL reject the operation with error "Owner or System Admin role required"
4. WHEN a non-owner and non-system-admin user attempts to remove Role Admin role, THE System SHALL reject the operation with error "Owner or System Admin role required"

### Requirement 7: Audit Logging for API Operations

**User Story:** As a security auditor, I want comprehensive logging of all API-based admin role changes, so that I can investigate security incidents and verify compliance.

#### Acceptance Criteria

1. THE System SHALL log all System Admin role assignments via API with timestamp, IP address, actor user_id, and target user_id
2. THE System SHALL log all System Admin role removals via API with timestamp, IP address, actor user_id, and target user_id
3. THE System SHALL log all Role Admin role assignments via API with timestamp, IP address, actor user_id, and target user_id
4. THE System SHALL log all Role Admin role removals via API with timestamp, IP address, actor user_id, and target user_id
5. THE System SHALL log all attempted self-modification operations via API with timestamp, IP address, user_id, and attempted action
6. THE System SHALL log owner self-deactivation via API with timestamp, IP address, and user_id

### Requirement 8: Error Handling

**User Story:** As an API consumer, I want clear error messages and appropriate HTTP status codes, so that I can understand why operations fail and handle errors appropriately.

#### Acceptance Criteria

1. WHEN authorization fails, THE System SHALL return HTTP 403 Forbidden with descriptive error message
2. WHEN a target user is not found, THE System SHALL return HTTP 404 Not Found with error message "User not found"
3. WHEN self-modification is attempted, THE System SHALL return HTTP 403 Forbidden with error message "Cannot modify your own admin roles"
4. WHEN database errors occur, THE System SHALL return HTTP 500 Internal Server Error with generic error message

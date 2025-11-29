# Requirements Document

## Introduction

This specification addresses a critical audit logging architecture flaw where the `user_id` field in audit events incorrectly represents the **target user** (the user being acted upon) instead of the **actor** (the user performing the action). This makes it impossible to distinguish between authorized administrative actions and unauthorized access attempts.

For example, when an admin generates a JWT for another user, the audit log should show the admin as the actor, not the target user. Similarly, when a user logs in, we need to distinguish between:
- Unauthenticated login attempts (actor_id = "unknown")
- Authenticated users calling the login endpoint (actor_id = their user_id from JWT)

## Glossary

- **Actor**: The user or system component performing an action (from RequestContext.actor_id)
- **Target User**: The user being acted upon or affected by an action
- **Audit Event**: A security-relevant event logged to the audit database
- **RequestContext**: Context object containing actor information that flows through all layers
- **JWT**: JSON Web Token used for authentication
- **Refresh Token**: Long-lived token used to obtain new JWTs

## Requirements

### Requirement 1

**User Story:** As a security auditor, I want audit logs to clearly identify who performed each action, so that I can trace unauthorized access attempts and administrative actions.

#### Acceptance Criteria

1. WHEN any audit event is logged THEN the system SHALL populate the user_id field with the actor_id from RequestContext
2. WHEN an action affects a specific user THEN the system SHALL include the target_user_id in the event details
3. WHEN an unauthenticated request occurs THEN the system SHALL log the actor_id as "unknown" or the appropriate system identifier
4. WHEN an authenticated request occurs THEN the system SHALL log the actor_id from the JWT claims
5. WHEN a system operation occurs THEN the system SHALL log the actor_id with a "system:" prefix

### Requirement 2

**User Story:** As a security auditor, I want login events to distinguish between authenticated and unauthenticated login attempts, so that I can identify suspicious patterns.

#### Acceptance Criteria

1. WHEN an unauthenticated user attempts to login THEN the system SHALL log the actor_id as "unknown"
2. WHEN an authenticated user calls the login endpoint THEN the system SHALL log their user_id from JWT as the actor_id
3. WHEN a login succeeds THEN the system SHALL include the target_user_id (logged-in user) in event details
4. WHEN a login fails THEN the system SHALL include the attempted username in event details
5. WHEN a JWT is issued THEN the system SHALL include the target_user_id (JWT subject) in event details

### Requirement 3

**User Story:** As a security auditor, I want refresh token events to clearly show who requested the token operation, so that I can detect token theft or misuse.

#### Acceptance Criteria

1. WHEN a refresh token is issued THEN the system SHALL log the actor_id from RequestContext as user_id
2. WHEN a refresh token is issued THEN the system SHALL include the target_user_id (token owner) in event details
3. WHEN a refresh token is validated THEN the system SHALL log the actor_id from RequestContext as user_id
4. WHEN a refresh token is revoked THEN the system SHALL log the actor_id from RequestContext as user_id
5. WHEN a refresh token is revoked THEN the system SHALL include the target_user_id (token owner) in event details

### Requirement 4

**User Story:** As a security auditor, I want JWT validation events to show who attempted to use the JWT, so that I can identify replay attacks or stolen tokens.

#### Acceptance Criteria

1. WHEN a JWT is issued THEN the system SHALL log the actor_id from RequestContext as user_id
2. WHEN a JWT is issued THEN the system SHALL include the target_user_id (JWT subject) in event details
3. WHEN a JWT validation fails THEN the system SHALL log the actor_id from the JWT claims as user_id
4. WHEN a JWT is tampered THEN the system SHALL log the actor_id from unverified claims as user_id
5. WHEN a JWT validation succeeds THEN the system SHALL NOT create a separate audit event (validation success is implicit in subsequent actions)

### Requirement 5

**User Story:** As a developer, I want consistent audit logging patterns across all authentication operations, so that the codebase is maintainable and audit logs are reliable.

#### Acceptance Criteria

1. WHEN any audit logging function is called THEN the system SHALL accept RequestContext as the first parameter
2. WHEN any audit logging function logs an event THEN the system SHALL extract actor_id from RequestContext for the user_id field
3. WHEN an action affects a specific user THEN the system SHALL accept target_user_id as a separate parameter
4. WHEN an action affects a specific user THEN the system SHALL include target_user_id in event details
5. WHEN audit logging functions are updated THEN the system SHALL maintain backward compatibility with existing call sites

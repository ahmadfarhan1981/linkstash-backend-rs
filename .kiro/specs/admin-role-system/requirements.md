# Requirements Document

## Introduction

This feature introduces a three-tier administrative role system for the Linkstash authentication backend. The system includes: Owner (emergency account for admin management), System Admin (day-to-day system management), and Role Admin (reserved for future application role management). The owner is a special account used during initial setup and emergency situations, normally kept inactive to minimize attack surface. This design implements principle of least privilege and limits the impact of compromised accounts through clear separation of duties.

Note: The Role Admin role is defined in the schema but its functionality (managing app_roles) will be implemented in a separate spec.

## Glossary

- **Owner**: A special account with the highest privileges, used for emergency admin management. Only one can exist per system. Created during bootstrap in INACTIVE state. Can assign/remove System Admin and Role Admin roles. Not intended for regular administrative tasks.
- **System Admin**: Administrative account for day-to-day system operations (user management, system configuration, token revocation). Can assign/remove Role Admin roles.
- **Role Admin**: Administrative role flag reserved for future application role management functionality. The flag exists in the schema but management functionality will be implemented in a separate spec.
- **User**: Standard user account with no administrative privileges.
- **Admin Roles**: The three boolean flags (is_owner, is_system_admin, is_role_admin) that determine administrative privileges.
- **App Roles**: User-defined roles for application-level permissions (e.g., "editor", "viewer", "manager"). Stored as a list of strings in the user table. Management functionality will be implemented in a separate spec.
- **Activation**: The process of enabling the owner account, making it available for login.
- **Deactivation**: The process of disabling the owner account, preventing login.
- **Self-Modification**: Any attempt by a user to assign or remove admin roles to/from their own account.
- **System**: The Linkstash authentication backend.
- **CLI**: Command-line interface for administrative operations requiring server access.
- **Bootstrap**: The initial system setup process that creates the owner account and optionally creates System Admin and Role Admin accounts.
- **Password Validator**: A shared library component that validates password strength, including length requirements and checks against common/compromised password lists.
- **Credential Export**: The process of exporting owner credentials in formats compatible with password managers (KeePassX XML, Bitwarden JSON).

## Requirements

### Requirement 1: Three-Tier Admin Role System

**User Story:** As a system architect, I want three distinct administrative roles with clear separation of duties, so that I can implement principle of least privilege and limit the impact of compromised accounts.

#### Acceptance Criteria

1. THE System SHALL support three administrative role flags: is_owner, is_system_admin, and is_role_admin
2. THE System SHALL store admin role flags as separate boolean fields in the user table
3. THE System SHALL include all three admin role flags in JWT claims
4. THE System SHALL support users having multiple admin roles simultaneously (e.g., both is_system_admin and is_role_admin)
5. THE System SHALL include app_roles field in the user table and JWT claims for future use

### Requirement 2: Bootstrap Command and System Initialization

**User Story:** As a system administrator deploying the application, I want a bootstrap command that creates the owner and initial admin accounts, so that I can set up a working administrative team in one operation.

#### Acceptance Criteria

1. THE System SHALL provide a CLI bootstrap command that creates the owner account and optionally creates System Admin and Role Admin accounts
2. WHEN the bootstrap command is executed and an owner already exists, THE System SHALL reject the operation with error message "System already bootstrapped"
3. WHEN the bootstrap command is executed, THE System SHALL check that no owner exists before proceeding
4. THE System SHALL generate a UUID as the username for the owner account
5. WHEN the owner account is created during bootstrap, THE System SHALL set is_owner to true and status to INACTIVE
6. WHEN the bootstrap command is executed, THE System SHALL prompt for the number of System Admin accounts to create (0-10)
7. WHEN the bootstrap command is executed, THE System SHALL prompt for the number of Role Admin accounts to create (0-10)
8. THE System SHALL generate a UUID as the username for each System Admin and Role Admin account created during bootstrap
9. WHEN System Admin accounts are created during bootstrap, THE System SHALL set is_system_admin to true and status to ACTIVE
10. WHEN Role Admin accounts are created during bootstrap, THE System SHALL set is_role_admin to true and status to ACTIVE

### Requirement 3: Owner Account Status Management

**User Story:** As an owner, I want to activate and deactivate my account, so that the account cannot be used until explicitly enabled and can be locked after use.

#### Acceptance Criteria

1. THE System SHALL store the owner account status (ACTIVE or INACTIVE) in the database
2. WHEN the owner account status is INACTIVE, THE System SHALL reject login attempts for that account
3. THE System SHALL provide a CLI command to activate the owner account
4. THE System SHALL provide an API endpoint for the owner to deactivate their own account
5. WHEN the owner account is deactivated, THE System SHALL invalidate all active JWTs for that account

### Requirement 4: Owner Privileges

**User Story:** As an owner, I want the ability to assign and remove System Admin and Role Admin roles, so that I can manage the administrative team during setup and emergency situations.

#### Acceptance Criteria

1. WHEN a user has is_owner set to true, THE System SHALL permit that user to assign System Admin role to other users
2. WHEN a user has is_owner set to true, THE System SHALL permit that user to remove System Admin role from other users
3. WHEN a user has is_owner set to true, THE System SHALL permit that user to assign Role Admin role to other users
4. WHEN a user has is_owner set to true, THE System SHALL permit that user to remove Role Admin role from other users
5. THE System SHALL log all admin role assignment and removal actions to the audit database

### Requirement 5: System Admin Privileges

**User Story:** As a system admin, I want to manage system configuration and users, so that I can perform day-to-day administrative operations without requiring owner access.

#### Acceptance Criteria

1. WHEN a user has is_system_admin set to true, THE System SHALL permit that user to assign Role Admin role to other users
2. WHEN a user has is_system_admin set to true, THE System SHALL permit that user to remove Role Admin role from other users
3. WHEN a user has is_system_admin set to true, THE System SHALL permit that user to manage system configuration parameters
4. WHEN a user has is_system_admin set to true, THE System SHALL permit that user to activate, ban, disable users and revoke tokens

### Requirement 6: Self-Modification Prevention

**User Story:** As a security architect, I want to prevent users from modifying their own admin roles, so that compromised sessions cannot be used for privilege escalation.

#### Acceptance Criteria

1. WHEN a user attempts to assign any admin role to their own account, THE System SHALL reject the operation with error message "Cannot modify your own admin roles"
2. WHEN a user attempts to remove any admin role from their own account, THE System SHALL reject the operation with error message "Cannot modify your own admin roles"
3. THE System SHALL log all attempted self-modification operations to the audit database

### Requirement 7: Owner CLI Operations

**User Story:** As a system administrator with server access, I want CLI commands to manage the owner account, so that I can perform emergency operations when the account is inactive or inaccessible via API.

#### Acceptance Criteria

1. THE System SHALL provide a CLI command to activate the owner account
2. WHEN the CLI activation command is executed, THE System SHALL prompt for confirmation before proceeding
3. WHEN the CLI activation command is confirmed, THE System SHALL change the owner account status to ACTIVE
4. THE System SHALL provide a CLI command to deactivate the owner account
5. WHEN the CLI deactivation command is executed, THE System SHALL prompt for confirmation before proceeding
6. THE System SHALL provide a CLI command to retrieve the owner username and UUID
7. THE System SHALL log all CLI operations to the audit database with timestamp and operation type

### Requirement 8: JWT Claims Structure

**User Story:** As an application developer, I want all admin roles included in JWT claims, so that I can make authorization decisions without additional database queries.

#### Acceptance Criteria

1. THE System SHALL include is_owner boolean in JWT claims
2. THE System SHALL include is_system_admin boolean in JWT claims
3. THE System SHALL include is_role_admin boolean in JWT claims
4. THE System SHALL include app_roles as an array of strings in JWT claims for future use
5. THE System SHALL issue new JWTs with updated claims when admin roles are modified

### Requirement 9: Audit Logging for Admin Role Operations

**User Story:** As a security auditor, I want comprehensive logging of all admin role changes, so that I can investigate security incidents and verify compliance.

#### Acceptance Criteria

1. THE System SHALL log owner activation and deactivation events with timestamp, IP address, and activation method
2. THE System SHALL log all System Admin role assignments and removals with timestamp, IP address, actor user_id, and target user_id
3. THE System SHALL log all Role Admin role assignments and removals with timestamp, IP address, actor user_id, and target user_id
4. THE System SHALL log all attempted self-modification operations with timestamp, IP address, user_id, and attempted action

### Requirement 10: Credential Management During Bootstrap

**User Story:** As a system administrator running bootstrap, I want individual credential handling for each account created, so that I can securely distribute credentials to different administrators.

#### Acceptance Criteria

1. WHEN each account is created during bootstrap, THE System SHALL offer the user a choice to auto-generate a password or enter a password manually
2. WHEN a password is entered manually during bootstrap, THE System SHALL validate it using the Password Validator
3. WHEN a password is auto-generated during bootstrap, THE System SHALL generate a password that satisfies all Password Validator requirements
4. WHEN each account is created during bootstrap, THE System SHALL display the username and password exactly once in the CLI output
5. WHEN each account is created during bootstrap, THE System SHALL prompt for credential export with options: display only, copy username to clipboard, copy password to clipboard, export to KeePassX XML, export to Bitwarden JSON, or skip
6. WHEN credentials are exported to file during bootstrap, THE System SHALL create separate files for each account to enable individual distribution
7. WHEN the owner account is created during bootstrap, THE System SHALL display a warning message emphasizing that the account is INACTIVE and requires explicit activation

### Requirement 11: Password Validation Library

**User Story:** As a security architect, I want a reusable password validation library, so that consistent password policies can be enforced across all user creation flows.

#### Acceptance Criteria

1. THE System SHALL provide a Password Validator component that validates password length between 15 and 64 characters
2. THE System SHALL provide a Password Validator component that checks passwords against common/compromised password lists
3. WHEN a password is shorter than 15 characters, THE Password Validator SHALL reject it with error message "Password must be at least 15 characters"
4. WHEN a password is longer than 64 characters, THE Password Validator SHALL reject it with error message "Password must not exceed 64 characters"
5. WHEN a password appears in the common/compromised password list, THE Password Validator SHALL reject it with error message "Password is too common or has been compromised"
6. THE Password Validator SHALL be implemented as a shared library component usable by CLI and API endpoints

---

**Note:** Requirements for Role Admin functionality (managing app_roles) have been moved to a separate spec that will be implemented later. This spec focuses on establishing the three-tier role structure and Owner/System Admin management capabilities.

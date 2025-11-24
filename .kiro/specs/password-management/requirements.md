# Requirements Document

## Introduction

This feature implements password management capabilities for the Linkstash authentication backend, including a reusable password validation library, password change functionality, and enforcement of password changes for bootstrap accounts. The system ensures strong password policies are consistently applied across all user creation and password change flows.

## Glossary

- **Password Validator**: A shared library component that validates password strength, including length requirements and checks against common/compromised password lists.
- **Password Change Requirement**: A flag that forces users to change their password before accessing protected endpoints.
- **Bootstrap Accounts**: User accounts created during system initialization that require password changes on first login.
- **Common Password List**: A curated list of frequently used or compromised passwords (e.g., top 10k from HaveIBeenPwned).
- **System**: The Linkstash authentication backend.

## Requirements

### Requirement 1: Password Validation Library

**User Story:** As a security architect, I want a reusable password validation library, so that consistent password policies can be enforced across all user creation and password change flows.

#### Acceptance Criteria

1. THE System SHALL provide a Password Validator component that validates password length between 15 and 64 characters
2. THE System SHALL provide a Password Validator component that checks passwords against common/compromised password lists
3. WHEN a password is shorter than 15 characters, THE Password Validator SHALL reject it with error message "Password must be at least 15 characters"
4. WHEN a password is longer than 64 characters, THE Password Validator SHALL reject it with error message "Password must not exceed 64 characters"
5. WHEN a password appears in the common/compromised password list, THE Password Validator SHALL reject it with error message "Password is too common or has been compromised"
6. THE Password Validator SHALL be implemented as a shared library component usable by CLI and API endpoints
7. THE Password Validator SHALL provide a method to generate secure passwords that satisfy all validation requirements

### Requirement 2: Password Change Endpoint

**User Story:** As a user, I want to change my password through an API endpoint, so that I can update my credentials when needed.

#### Acceptance Criteria

1. THE System SHALL provide a POST /auth/change-password endpoint that accepts old password and new password
2. WHEN a user calls the password change endpoint, THE System SHALL verify the old password matches the current password hash
3. WHEN a user calls the password change endpoint, THE System SHALL validate the new password using the Password Validator
4. WHEN the old password is incorrect, THE System SHALL reject the request with error message "Current password is incorrect"
5. WHEN the new password fails validation, THE System SHALL reject the request with the Password Validator error message
6. WHEN the password change is successful, THE System SHALL update the password hash in the database
7. WHEN the password change is successful, THE System SHALL invalidate all existing refresh tokens for that user
8. WHEN the password change is successful, THE System SHALL issue new access and refresh tokens
9. THE System SHALL log all password change attempts to the audit database with timestamp, user_id, IP address, and success/failure status

### Requirement 3: Password Change Requirement Flag

**User Story:** As a system administrator, I want to force users to change their password on first login, so that bootstrap accounts use administrator-chosen passwords instead of auto-generated ones.

#### Acceptance Criteria

1. THE System SHALL store a password_change_required boolean flag in the user table
2. THE System SHALL include the password_change_required flag in JWT claims
3. WHEN a user account is created during bootstrap, THE System SHALL set password_change_required to true
4. WHEN a user successfully changes their password, THE System SHALL set password_change_required to false
5. WHEN a user with password_change_required=true attempts to access any endpoint except /auth/change-password and /auth/whoami, THE System SHALL reject the request with 403 status code and error message "Password change required. Please change your password at /auth/change-password"
6. THE System SHALL allow users with password_change_required=true to access /auth/whoami to check their status
7. THE System SHALL allow users with password_change_required=true to access /auth/change-password to update their password

### Requirement 4: Integration with User Creation Flows

**User Story:** As a developer, I want the password validator to be integrated into all user creation flows, so that password policies are consistently enforced.

#### Acceptance Criteria

1. WHEN a user is created via CLI bootstrap command, THE System SHALL validate the password using the Password Validator
2. WHEN a user is created via API (future user registration), THE System SHALL validate the password using the Password Validator
3. WHEN a password is auto-generated during bootstrap, THE System SHALL generate a password that passes Password Validator requirements
4. THE System SHALL reject user creation attempts with invalid passwords and return the Password Validator error message


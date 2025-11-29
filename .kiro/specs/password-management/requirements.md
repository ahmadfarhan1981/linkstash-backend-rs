# Requirements Document

## Introduction

This feature implements password management capabilities for the Linkstash authentication backend, including a reusable password validation library, password change functionality, and enforcement of password changes for bootstrap accounts. The system ensures strong password policies are consistently applied across all user creation and password change flows.

## Glossary

- **Password Validator**: A shared library component that validates password strength, including length requirements and checks against common/compromised password lists.
- **Password Change Requirement**: A flag that forces users to change their password before accessing protected endpoints.
- **Bootstrap Accounts**: User accounts created during system initialization that require password changes on first login.
- **Common Password List**: A local file containing frequently used passwords that should be rejected. Administrators can download this list from a configurable URL.
- **Compromised Password Check**: A validation that checks passwords against the HaveIBeenPwned API using k-anonymity (hash prefix matching) with local caching.
- **HIBP Cache**: A database table storing HaveIBeenPwned API responses with timestamps to minimize API calls and improve performance.
- **Cache Staleness**: The duration after which cached HIBP results are considered outdated and require re-fetching from the API.
- **System**: The Linkstash authentication backend.

## Requirements

### Requirement 1: Password Validation Library

**User Story:** As a security architect, I want a reusable password validation library, so that consistent password policies can be enforced across all user creation and password change flows.

#### Acceptance Criteria

1. THE System SHALL provide a Password Validator component that validates password length between 15 and 128 characters
2. THE System SHALL provide a Password Validator component that checks passwords against a local common password list
3. THE System SHALL provide a Password Validator component that checks passwords against the HaveIBeenPwned compromised password database
4. WHEN a password is shorter than 15 characters, THE Password Validator SHALL reject it with error message "Password must be at least 15 characters"
5. WHEN a password is longer than 128 characters, THE Password Validator SHALL reject it with error message "Password must not exceed 128 characters"
6. WHEN a password appears in the local common password list, THE Password Validator SHALL reject it with error message "Password is too common"
7. WHEN a password appears in the HaveIBeenPwned database, THE Password Validator SHALL reject it with error message "Password has been compromised in a data breach"
8. THE Password Validator SHALL be implemented as a shared library component usable by CLI and API endpoints
9. THE Password Validator SHALL provide a method to generate secure passwords that satisfy all validation requirements

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

### Requirement 5: Common Password List Management

**User Story:** As a system administrator, I want to manage the common password list via CLI, so that I can keep the list updated with current threat intelligence.

#### Acceptance Criteria

1. THE System SHALL store the common password list in a local file at a configurable path
2. THE System SHALL provide a CLI command to download the common password list from a specified URL
3. WHEN the download command is executed with a URL, THE System SHALL fetch the content and save it to the local common password list file
4. WHEN the download command completes successfully, THE System SHALL display a success message with the number of passwords downloaded
5. WHEN the download command fails, THE System SHALL display an error message and preserve the existing common password list file
6. THE System SHALL load the common password list from the local file when the Password Validator is initialized
7. WHEN the common password list file does not exist, THE Password Validator SHALL initialize with an empty list and log a warning

### Requirement 6: HaveIBeenPwned Integration with Caching

**User Story:** As a security architect, I want to check passwords against the HaveIBeenPwned database with local caching, so that I can detect compromised passwords while minimizing API calls and maintaining performance.

#### Acceptance Criteria

1. THE System SHALL create a database table to cache HaveIBeenPwned API responses with hash prefix, response data, and fetch timestamp
2. THE System SHALL store a system configuration value for HIBP cache staleness duration in seconds
3. WHEN validating a password against HIBP, THE System SHALL compute the SHA-1 hash of the password
4. WHEN validating a password against HIBP, THE System SHALL extract the first 5 characters of the hash as the prefix
5. WHEN a cache entry exists for the hash prefix and is not stale, THE System SHALL use the cached response data
6. WHEN a cache entry does not exist or is stale, THE System SHALL fetch the hash suffix list from the HIBP API using the prefix
7. WHEN fetching from the HIBP API, THE System SHALL store or update the cache entry with the response data and current timestamp
8. WHEN the HIBP API request fails, THE System SHALL log the error and allow the password validation to proceed without compromised password check
9. THE System SHALL check if the full password hash suffix appears in the HIBP response data
10. WHEN the password hash appears in the HIBP data, THE System SHALL reject the password
11. THE System SHALL use the k-anonymity model by only sending the 5-character hash prefix to the HIBP API

### Requirement 7: Context-Specific Password Validation

**User Story:** As a security architect, I want to prevent passwords that contain the username, so that users cannot choose easily guessable passwords based on their identity.

#### Acceptance Criteria

1. WHEN validating a password for a user, THE Password Validator SHALL check if the password contains the username as a substring
2. WHEN a password contains the username, THE Password Validator SHALL reject it with error message "Password must not contain your username"
3. THE username check SHALL be case-insensitive
4. WHEN the username is a UUID, THE System SHALL skip the username substring check


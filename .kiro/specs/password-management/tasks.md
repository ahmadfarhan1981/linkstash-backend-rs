# Implementation Plan

- [ ] 1. Database schema and migration
  - [ ] 1.1 Create migration to add password_change_required column
    - Add `password_change_required` boolean column to users table with DEFAULT FALSE
    - _Requirements: 3.1_
  
  - [ ] 1.2 Update user entity model
    - Add password_change_required field to Model struct
    - _Requirements: 3.1_
  
  - [ ] 1.3 Run migration and verify schema changes
    - Execute `sea-orm-cli migrate up` to apply migration
    - Verify column added correctly with proper default
    - _Requirements: 3.1_

- [ ] 2. Password validator library
  - [ ] 2.1 Create common password list resource
    - Download top 10k common passwords from HaveIBeenPwned or similar source
    - Create resources/common_passwords.txt file with one password per line
    - Ensure file is lowercase for case-insensitive matching
    - _Requirements: 1.2, 1.5_
  
  - [ ] 2.2 Implement PasswordValidator service
    - Create src/services/password_validator.rs
    - Implement PasswordValidator struct with min_length, max_length, common_passwords fields
    - Implement new() constructor that loads embedded password list
    - Implement validate() method with length and common password checks
    - Implement generate_secure_password() method for auto-generation
    - Implement load_common_passwords() using include_str! macro
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_
  
  - [ ] 2.3 Create PasswordValidationError enum
    - Define error variants: TooShort, TooLong, CommonPassword
    - Implement Display trait with proper error messages
    - _Requirements: 1.3, 1.4, 1.5_
  
  - [ ] 2.4 Export PasswordValidator from services module
    - Add password_validator module to src/services/mod.rs
    - Export PasswordValidator and PasswordValidationError
    - _Requirements: 1.6_

- [ ] 3. JWT claims extension
  - [ ] 3.1 Update Claims struct to include password_change_required
    - Add password_change_required boolean field to Claims
    - Update all JWT generation to include the flag
    - _Requirements: 3.2_

- [ ] 4. Store layer extensions
  - [ ] 4.1 Add password management methods to credential store
    - Implement update_password() to change user password hash
    - Implement clear_password_change_required() to set flag to false
    - Implement revoke_all_refresh_tokens() to invalidate all user tokens
    - All methods must log to audit database at point of action
    - _Requirements: 2.6, 2.7, 3.4_

- [ ] 5. Service layer for password change
  - [ ] 5.1 Extend AuthService with password change functionality
    - Implement change_password() method accepting old and new passwords
    - Verify old password matches current hash
    - Validate new password using PasswordValidator
    - Update password hash and clear password_change_required flag
    - Invalidate all refresh tokens
    - Issue new JWT with updated claims
    - Log password change to audit database
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9_

- [ ] 6. Error handling
  - [ ] 6.1 Extend AuthError enum with password-related errors
    - Add PasswordValidationFailed variant
    - Add PasswordChangeRequired variant
    - Add IncorrectPassword variant
    - Implement proper HTTP status codes for each error type
    - _Requirements: 2.4, 2.5, 3.5_

- [ ] 7. API endpoint for password change
  - [ ] 7.1 Add password change endpoint to AuthApi
    - Implement POST /auth/change-password accepting old and new passwords
    - Must be accessible even when password_change_required is true
    - Must validate authentication but skip password_change_required check
    - Returns new access and refresh tokens after successful change
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_
  
  - [ ] 7.2 Create ChangePasswordRequest and ChangePasswordResponse DTOs
    - Define request DTO with old_password and new_password fields
    - Define response DTO with message, access_token, refresh_token, token_type, expires_in
    - Define ChangePasswordApiResponse enum with Ok, BadRequest, Unauthorized variants
    - _Requirements: 2.1, 2.8_

- [ ] 8. Password change requirement enforcement
  - [ ] 8.1 Update create_request_context to check password_change_required flag
    - After JWT validation, check if password_change_required is true
    - If true and endpoint is not /auth/change-password or /auth/whoami, set blocked flag
    - Add password_change_blocked field to RequestContext
    - _Requirements: 3.5, 3.6, 3.7_
  
  - [ ] 8.2 Update all protected endpoints to check password_change_blocked flag
    - Add check at beginning of each endpoint handler
    - Return 403 with PasswordChangeRequired error if flag is true
    - Ensure /auth/change-password and /auth/whoami skip this check
    - _Requirements: 3.5, 3.6, 3.7_

- [ ] 9. Integration with user creation flows
  - [ ] 9.1 Integrate password validator into credential store add_user()
    - Update add_user() to validate password using PasswordValidator
    - Return validation error if password fails checks
    - _Requirements: 4.1, 4.2_
  
  - [ ] 9.2 Update bootstrap command to set password_change_required flag
    - When creating users during bootstrap, set password_change_required=true
    - Display warning about password change requirement
    - _Requirements: 3.3_
  
  - [ ] 9.3 Update bootstrap password generation to use PasswordValidator
    - Use PasswordValidator.generate_secure_password() for auto-generated passwords
    - Validate manually entered passwords using PasswordValidator
    - _Requirements: 4.3_

- [ ] 10. Audit logging
  - [ ] 10.1 Extend audit event types for password operations
    - Add event type for password change success
    - Add event type for password change failure (incorrect old password)
    - Add event type for password validation failure
    - _Requirements: 2.9_
  
  - [ ] 10.2 Update audit logger to capture password change metadata
    - Ensure user_id, IP address, timestamp are captured
    - Ensure validation failure reasons are logged
    - Never log actual passwords
    - _Requirements: 2.9_

- [ ]* 11. Testing
  - [ ]* 11.1 Write unit tests for password validator
    - Test length validation (< 15, 15-64, > 64 characters)
    - Test common password detection (case-insensitive)
    - Test secure password generation
    - Test generated passwords pass validation
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7_
  
  - [ ]* 11.2 Write integration tests for password change flow
    - Test successful password change with valid credentials
    - Test rejection with incorrect old password
    - Test rejection with invalid new password (too short, too long, common)
    - Test new tokens issued after change
    - Test old refresh tokens invalidated
    - Test password_change_required flag cleared
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 3.4_
  
  - [ ]* 11.3 Write integration tests for password change requirement
    - Test bootstrap accounts have password_change_required=true
    - Test login returns JWT with flag set
    - Test protected endpoints reject requests with 403 when flag is true
    - Test /auth/change-password remains accessible
    - Test /auth/whoami remains accessible
    - Test flag cleared after successful password change
    - Test old tokens invalidated after password change
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_
  
  - [ ]* 11.4 Write integration tests for audit logging
    - Test password changes logged with correct metadata
    - Test failed password changes logged
    - Test validation failures logged
    - Test passwords never appear in logs
    - _Requirements: 2.9_

- [ ] 12. Documentation
  - [ ] 12.1 Update .env.example if needed
    - Document any new environment variables (if added)
    - _Requirements: All requirements_
  
  - [ ] 12.2 Create password management documentation
    - Document password policy (15-64 chars, no common passwords)
    - Document password change flow
    - Document password change requirement for bootstrap accounts
    - Add to docs/ directory
    - _Requirements: All requirements_


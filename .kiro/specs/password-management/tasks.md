# Implementation Plan

## Phase 1: Basic Password Change (No Validation)

- [x] 1. Create minimal database schema for password change
  - Create migration `m20250127_000003_add_password_change_required.rs` adding boolean column to users table (default false)
  - Update migration lib.rs to register migration
  - Run migration
  - _Requirements: 3.1_

- [x] 2. Define minimal error types and DTOs for password change





  - Add IncorrectPassword to AuthError enum
  - Implement Display and ResponseError for new variant
  - Create ChangePasswordRequest, ChangePasswordResponse, ChangePasswordApiResponse DTOs in `src/types/dto/auth.rs`
  - _Requirements: 2.4_

- [x] 3. Add audit logging for password operations





  - Implement `log_password_changed()` in audit_logger.rs (accepts ctx, target_user_id)
  - Implement `log_password_change_failed()` in audit_logger.rs (accepts ctx, reason)
  - Never log actual passwords or hashes
  - _Requirements: 2.9_

- [x] 4. Extend CredentialStore with basic password management





  - Add `update_password()` with audit logging at point of action
  - Verify `revoke_all_refresh_tokens()` exists (or implement if missing)
  - _Requirements: 2.6, 2.7_

- [x] 5. Implement basic password change in AuthService (NO VALIDATION)







  - Implement `change_password()` method: verify old password → hash new password → update DB → revoke tokens → issue new tokens
  - Skip all validation for now (will add later)
  - _Requirements: 2.1, 2.2, 2.3, 2.6, 2.7, 2.8_

- [x] 6. Create password change API endpoint (USER-FACING FEATURE!)





  - Implement POST /auth/change-password endpoint in AuthApi
  - Create request context, validate authentication
  - Call auth_service.change_password() and return new tokens
  - Verify endpoint works via Swagger UI: change password, get new tokens, old tokens invalidated
  - _Requirements: 2.1, 2.2, 2.3, 2.6, 2.7, 2.8_

- [x] 7. Checkpoint - Basic password change is working!
  - Users can change passwords through API (no validation yet)
  - Old tokens are invalidated, new tokens issued
  - Audit logs capture password changes

## Phase 2: Add Password Validation

- [x] 8. Create remaining database schema for validation


  - Create migration `m20250127_000001_create_common_passwords.rs` with password column (TEXT, primary key)
  - Create migration `m20250127_000002_create_hibp_cache.rs` with hash_prefix, response_data, fetched_at columns
  - Update migration lib.rs to register migrations
  - Run migrations
  - _Requirements: 5.1, 6.1_

- [x] 9. Create database entity models for validation


  - Create `src/types/db/common_password.rs` with DeriveEntityModel
  - Create `src/types/db/hibp_cache.rs` with DeriveEntityModel
  - Update `src/types/db/user.rs` to add password_change_required field
  - Export all entities from `src/types/db/mod.rs`
  - _Requirements: 3.1, 5.1, 6.1_

- [x] 10. Add validation error types




  - Add PasswordValidationFailed(String) to AuthError enum
  - Implement Display and ResponseError for new variant
  - _Requirements: 2.5_

- [x] 11. Implement basic password validator (length only)





  - Create `src/services/password_validator.rs` with PasswordValidator struct
  - Define complete PasswordValidationError enum (TooShort, TooLong, ContainsUsername, CommonPassword, CompromisedPassword)
  - Implement length validation only (15-128 characters)
  - Implement `generate_secure_password()` method (20 chars, mixed charset)
  - Implement `is_uuid()` helper (for future use)
  - Add stub `validate()` method accepting password and optional username (only checks length for now)
  - Export from `src/services/mod.rs`
  - _Requirements: 1.1, 1.4, 1.5, 1.9_

- [x] 12. Integrate basic password validator into AppData and AuthService






  - Add password_validator field to AppData struct
  - Initialize PasswordValidator in AppData::init() (no stores yet)
  - Add password_validator field to AuthService
  - Update AuthService constructor to get validator from AppData
  - Update `change_password()` to validate new password (length only)
  - Verify password change endpoint now enforces length requirements
  - _Requirements: 1.8, 2.4, 2.5_

- [x] 13. Implement CommonPasswordStore



  - Create `src/stores/common_password_store.rs`
  - Implement `is_common_password()` with case-insensitive lookup
  - Implement `load_passwords()` with transaction and batch inserts (1000 per batch)
  - Implement `count()` method
  - Export from `src/stores/mod.rs`
  - _Requirements: 1.2, 5.1, 5.6, 5.7_

- [x] 14. Enhance password validator with common password check



  - Update PasswordValidator constructor to accept Arc<CommonPasswordStore>
  - Update AppData to create CommonPasswordStore and pass to validator
  - Add common password validation to `validate()` method (after length check)
  - Verify password change endpoint now rejects common passwords
  - _Requirements: 1.2, 1.6_

- [x] 15. Implement download-passwords CLI command (USER-FACING FEATURE!)



  - Create `src/cli/password_management.rs` with download_and_load_passwords function
  - Use reqwest to fetch from URL, parse passwords (one per line)
  - Call common_password_store.load_passwords()
  - Add DownloadPasswords variant to CLI Commands enum
  - Wire up handler in execute_command
  - Test command: `cargo run -- download-passwords --url <URL>`
  - _Requirements: 5.2, 5.3, 5.4, 5.5_

- [x] 16. Implement HibpCacheStore
  - Create `src/stores/hibp_cache_store.rs`
  - Implement `get_cached_response()` with staleness check using system_config_store
  - Implement `store_response()` with upsert logic
  - Export from `src/stores/mod.rs`
  - Add HIBP cache staleness config to system_config table (30 days default) via manual insert or bootstrap
  - _Requirements: 6.1, 6.2, 6.5, 6.7_

- [x] 17. Enhance password validator with HIBP check
  - Update PasswordValidator constructor to accept Arc<HibpCacheStore>
  - Update AppData to create HibpCacheStore and pass to validator
  - Add HIBP validation to `validate()` method (after common password check)
  - Implement `check_hibp()` with SHA-1 hashing and k-anonymity (5-char prefix)
  - Implement `fetch_hibp_api()` using reqwest with User-Agent header
  - Add graceful degradation (log warning, allow password if API fails)
  - Add `log_password_validation_failed()` audit logging
  - Verify password change endpoint now rejects compromised passwords
  - _Requirements: 1.3, 1.7, 6.3, 6.4, 6.6, 6.8, 6.9, 6.10, 6.11_

- [ ] 18. Enhance password validator with username check
  - Add username substring check to `validate()` method (case-insensitive, skip for UUIDs using is_uuid helper)
  - Update AuthService change_password to pass username to validator
  - Verify password change endpoint rejects passwords containing username
  - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ] 19. Checkpoint - Password validation is complete!
  - All validation rules working: length, username, common passwords, compromised passwords
  - Test each validation type through password change endpoint

## Phase 3: Password Change Requirement Enforcement

- [ ] 20. Update TokenService to include password_change_required in JWT
  - Add password_change_required field to Claims struct in `src/types/internal/auth.rs`
  - Update `generate_jwt()` to accept password_change_required parameter
  - Include password_change_required in JWT claims
  - Update all existing callers to pass false (default for existing users)
  - _Requirements: 3.2_

- [ ] 21. Extend CredentialStore with password change requirement management
  - Add `clear_password_change_required()` with audit logging at point of action
  - Update AuthService `change_password()` to clear flag after successful change
  - _Requirements: 3.4_

- [ ] 22. Update CredentialStore to validate passwords on user creation
  - Update `add_user()` in CredentialStore to validate password using PasswordValidator before hashing
  - Return PasswordValidationFailed error if validation fails
  - _Requirements: 4.1, 4.2, 4.4_

- [ ] 23. Update bootstrap command for password management
  - Set password_change_required=true when creating owner/admin users
  - Display warning: "Password change required on first login"
  - Use PasswordValidator::generate_secure_password() for auto-generated passwords
  - Validate manual passwords using PasswordValidator before accepting
  - Test bootstrap flow with both auto-generated and manual passwords
  - _Requirements: 3.3, 4.3_

- [ ] 24. Implement password change requirement enforcement
  - Add PasswordChangeRequired to AuthError enum
  - Add password_change_blocked field to RequestContext struct
  - Update create_request_context helper to check password_change_required claim and set blocked flag if path not in allowed list (["/api/auth/change-password", "/api/auth/whoami"])
  - Update protected endpoints (/auth/refresh, /auth/logout, admin endpoints) to check blocked flag and return 403 PasswordChangeRequired
  - Verify enforcement: bootstrap user → login → attempt protected endpoint (403) → change password → access works
  - _Requirements: 3.5, 3.6, 3.7_

- [ ] 25. Final checkpoint - Complete end-to-end verification
  - Run bootstrap with password_change_required flag
  - Login and verify JWT contains password_change_required=true
  - Attempt to access protected endpoint (should get 403)
  - Access /auth/whoami (should work)
  - Change password via /auth/change-password (should work, return new tokens)
  - Verify old refresh token invalidated
  - Verify new JWT has password_change_required=false
  - Verify can now access protected endpoints
  - Check audit logs contain all expected events
  - _Requirements: All_

- [ ] 26. Create password management documentation
  - Create `docs/password-management.md`
  - Document password policy (15-128 chars, common/compromised checks, username check)
  - Document password change flow and API usage
  - Document password change requirement for bootstrap accounts
  - Document CLI download-passwords command with example
  - Document HIBP integration, caching, and k-anonymity
  - Update .env.example if needed
  - _Requirements: All_

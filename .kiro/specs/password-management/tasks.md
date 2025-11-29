# Implementation Plan

## Phase 0: Database Schema and Migration

- [ ] 1. Add password_change_required column to users table
  - Create migration file `m20250127_000001_add_password_change_required.rs`
  - Add `password_change_required BOOLEAN NOT NULL DEFAULT FALSE` column
  - Update `user.rs` Model struct to include `password_change_required: bool` field
  - Run migration with `sea-orm-cli migrate up`
  - Verify schema change in database
  - _Requirements: 3.1_

## Phase 1: Password Validator Library

- [ ] 2. Create common password list resource
  - Download top 10k common passwords from HaveIBeenPwned
  - Create `resources/common_passwords.txt` with one password per line (lowercase)
  - Verify file is embedded correctly at compile time
  - _Requirements: 1.2, 1.5_

- [ ] 3. Implement PasswordValidator service
  - Create `src/services/password_validator.rs`
  - Implement `PasswordValidator` struct with `min_length: 15`, `max_length: 64`, `common_passwords: HashSet<String>`
  - Implement `new()` constructor that loads embedded password list using `include_str!`
  - Implement `validate(&self, password: &str) -> Result<(), PasswordValidationError>` with length and common password checks
  - Implement `generate_secure_password(&self) -> String` (20 chars, mixed types)
  - Create `PasswordValidationError` enum with `TooShort(usize)`, `TooLong(usize)`, `CommonPassword` variants
  - Export from `src/services/mod.rs`
  - Verify validator works by testing with sample passwords (too short, too long, common, valid)
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

## Phase 2: JWT Claims Extension

- [ ] 4. Add password_change_required to JWT Claims
  - Update `Claims` struct in `src/types/internal/auth.rs` to include `password_change_required: bool`
  - Update `TokenService.generate_jwt()` to accept `password_change_required` parameter
  - Update all callers of `generate_jwt()` to pass `user.password_change_required` value
  - Verify JWTs now include the new claim by decoding a test token
  - _Requirements: 3.2_

## Phase 3: Store Layer - Password Management

- [ ] 5. Add password management methods to CredentialStore
  - Implement `update_password(&self, ctx: &RequestContext, user_id: &str, new_password_hash: &str) -> Result<(), AuthError>`
  - Implement `clear_password_change_required(&self, ctx: &RequestContext, user_id: &str) -> Result<(), AuthError>`
  - Implement `revoke_all_refresh_tokens(&self, user_id: &str) -> Result<(), AuthError>` (note: `invalidate_all_tokens` already exists, may need to adapt)
  - Add audit logging to each method at point of action
  - Verify methods work by calling them directly and checking database state
  - _Requirements: 2.6, 2.7, 3.4_

- [ ] 6. Integrate PasswordValidator into user creation
  - Update `add_user()` in CredentialStore to validate password using PasswordValidator before hashing
  - Return `PasswordValidationFailed` error if validation fails
  - Verify by attempting to create users with invalid passwords (should fail) and valid passwords (should succeed)
  - _Requirements: 4.1, 4.2_

## Phase 4: Error Handling

- [ ] 7. Extend AuthError enum with password-related errors
  - Add `PasswordValidationFailed(Json<AuthErrorResponse>)` variant with 400 status
  - Add `PasswordChangeRequired(Json<AuthErrorResponse>)` variant with 403 status
  - Add `IncorrectPassword(Json<AuthErrorResponse>)` variant with 401 status
  - Implement helper methods: `password_validation_failed(reason: String)`, `password_change_required()`, `incorrect_password()`
  - Update `message()` and `Display` implementations
  - Verify error responses have correct status codes and messages
  - _Requirements: 2.4, 2.5, 3.5_

## Phase 5: Service Layer - Password Change

- [ ] 8. Implement password change in AuthService
  - Add `change_password(&self, ctx: &RequestContext, old_password: &str, new_password: &str) -> Result<(String, String), AuthError>` method
  - Verify old password matches current hash
  - Validate new password using PasswordValidator
  - Hash new password using existing `hash_password()` method
  - Update password hash via store
  - Clear password_change_required flag via store
  - Revoke all refresh tokens via store
  - Generate new JWT with `password_change_required: false`
  - Generate and store new refresh token
  - Return (access_token, refresh_token)
  - Verify by performing a password change and checking all side effects (tokens invalidated, flag cleared, new tokens work)
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9_

## Phase 6: API Layer - Password Change Endpoint

- [ ] 9. Create DTOs for password change
  - Add `ChangePasswordRequest` struct with `old_password: String`, `new_password: String` to `src/types/dto/auth.rs`
  - Add `ChangePasswordResponse` struct with `message`, `access_token`, `refresh_token`, `token_type`, `expires_in`
  - Add `ChangePasswordApiResponse` enum with `Ok(200)`, `BadRequest(400)`, `Unauthorized(401)` variants
  - _Requirements: 2.1, 2.8_

- [ ] 10. Implement /auth/change-password endpoint
  - Add `change_password()` endpoint to AuthApi in `src/api/auth.rs`
  - Path: `/change-password`, method: POST, requires BearerAuth
  - Create request context and validate authentication
  - Call `auth_service.change_password()` with old and new passwords
  - Return new tokens on success, appropriate error on failure
  - NOTE: This endpoint must be accessible even when password_change_required=true (enforcement comes in Phase 7)
  - Verify endpoint works by calling it with valid/invalid credentials via curl or Swagger UI
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_

## Phase 7: Password Change Requirement Enforcement

- [ ] 11. Add password_change_blocked to RequestContext
  - Update `RequestContext` struct in `src/types/internal/context.rs` to include `password_change_blocked: bool` field
  - Initialize to `false` by default
  - _Requirements: 3.5, 3.6, 3.7_

- [ ] 12. Update create_request_context to check password_change_required
  - In `src/api/helpers.rs` (or wherever `create_request_context` is defined)
  - After JWT validation, check if `claims.password_change_required == true`
  - If true, check if current path is `/api/auth/change-password` or `/api/auth/whoami`
  - If path is NOT allowed, set `ctx.password_change_blocked = true`
  - Verify by creating a user with password_change_required=true and testing endpoint access
  - _Requirements: 3.5, 3.6, 3.7_

- [ ] 13. Update protected endpoints to check password_change_blocked
  - Add check at beginning of each protected endpoint (except /auth/change-password and /auth/whoami)
  - If `ctx.password_change_blocked == true`, return `AuthError::PasswordChangeRequired` (403)
  - Update endpoints: /auth/refresh, /auth/logout, and any admin endpoints
  - Verify by attempting to access protected endpoints with password_change_required=true (should get 403)
  - Verify /auth/change-password and /auth/whoami remain accessible
  - _Requirements: 3.5, 3.6, 3.7_

## Phase 8: Bootstrap Integration

- [ ] 14. Update bootstrap command to set password_change_required flag
  - In `src/cli/bootstrap.rs`, when creating owner/admin users, set `password_change_required: true` in database
  - Display warning message: "Password change required on first login"
  - Verify by running bootstrap and checking database that flag is set
  - _Requirements: 3.3_

- [ ] 15. Update bootstrap password generation to use PasswordValidator
  - Replace `crypto::generate_secure_password()` calls with `PasswordValidator::generate_secure_password()`
  - For manual password entry, validate using PasswordValidator before accepting
  - Return validation error message if password fails validation
  - Verify by attempting bootstrap with invalid manual password (should reject) and valid password (should accept)
  - _Requirements: 4.3_

## Phase 9: Audit Logging

- [ ] 16. Extend audit event types for password operations
  - Add audit event types in `src/services/audit_logger.rs`:
    - `log_password_changed(audit_store, ctx, user_id, success: bool)`
    - `log_password_change_failed(audit_store, ctx, user_id, reason: String)`
    - `log_password_validation_failed(audit_store, ctx, user_id, reason: String)`
  - Ensure events capture user_id, IP address, timestamp, and reason
  - Never log actual passwords
  - Verify audit logs are created by performing password operations and checking audit database
  - _Requirements: 2.9_

## Phase 10: Integration and Verification

- [ ] 17. End-to-end verification
  - Run full bootstrap process with password_change_required flag
  - Login with bootstrap credentials and verify JWT contains password_change_required=true
  - Attempt to access protected endpoint (should get 403)
  - Access /auth/whoami (should work)
  - Change password via /auth/change-password (should work and return new tokens)
  - Verify old refresh token is invalidated
  - Verify new JWT has password_change_required=false
  - Verify can now access protected endpoints
  - Check audit logs contain all expected events

## Phase 11: Documentation

- [ ] 18. Update .env.example
  - Verify no new environment variables are needed
  - If any added, document them with examples
  - _Requirements: All requirements_

- [ ] 19. Create password management documentation
  - Create `docs/password-management.md`
  - Document password policy (15-64 chars, no common passwords)
  - Document password change flow and API usage
  - Document password change requirement for bootstrap accounts
  - Document how to handle password_change_required=true scenario
  - _Requirements: All requirements_

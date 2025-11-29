# Implementation Plan

- [x] 1. Reorganize error module structure
  - Create `src/errors/api/` directory
  - Move `src/errors/auth.rs` to `src/errors/api/auth.rs`
  - Move `src/errors/admin.rs` to `src/errors/api/admin.rs`
  - Create `src/errors/api/mod.rs` with `pub mod auth;`, `pub mod admin;`, and re-exports
  - Update `src/errors/mod.rs` to add `pub mod api;` and re-export `pub use api::{AuthError, AdminError};`
  - Update all imports in codebase from `crate::errors::auth::AuthError` to `crate::errors::AuthError` (or `crate::errors::api::AuthError`)
  - Update all imports in codebase from `crate::errors::admin::AdminError` to `crate::errors::AdminError` (or `crate::errors::api::AdminError`)
  - Run tests to verify no breakage from file moves
  - _Requirements: 3.1_

- [x] 2. Create InternalError type and domain error enums



  - Add `thiserror = "1.0"` to `Cargo.toml` dependencies
  - Create `src/errors/internal.rs` with `InternalError` enum
  - Define infrastructure error variants: `Database { operation, source }`, `Transaction { operation, source }`, `Parse { value_type, message }`, `Crypto { operation, message }`
  - Define `CredentialError` enum with variants: `InvalidCredentials`, `DuplicateUsername(String)`, `UserNotFound(String)`, `PasswordHashingFailed(String)`, `InvalidToken { token_type, reason }`, `ExpiredToken(String)`
  - Define `SystemConfigError` enum with variants: `ConfigNotFound`, `OwnerAlreadyExists`, `OwnerNotFound`
  - Define `AuditError` enum with variants: `LogWriteFailed(String)`
  - Add domain error variants to `InternalError`: `Credential(#[from] CredentialError)`, `SystemConfig(#[from] SystemConfigError)`, `Audit(#[from] AuditError)`
  - Implement helper methods: `InternalError::database()`, `::transaction()`, `::parse()`, `::crypto()`
  - Implement helper methods for domain errors: `CredentialError::invalid_token()`
  - Add `pub mod internal;` and `pub use internal::InternalError;` to `src/errors/mod.rs`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 4.1, 4.2, 4.3, 4.4_

- [x] 3. Update AuthError with conversion logic



  - Add `from_internal_error(err: InternalError) -> Self` method to `AuthError` in `src/errors/api/auth.rs`
  - Add private `internal_server_error() -> Self` helper method that returns generic "An internal error occurred" message
  - Implement conversion for infrastructure errors: `Database`, `Transaction`, `Parse`, `Crypto` → log at ERROR level and return `internal_server_error()`
  - Implement conversion for `CredentialError::InvalidCredentials` → log at DEBUG level and return `AuthError::invalid_credentials()`
  - Implement conversion for `CredentialError::DuplicateUsername` → log at WARN level and return `AuthError::duplicate_username()`
  - Implement conversion for `CredentialError::InvalidToken` → log at DEBUG level and return appropriate token error based on token_type
  - Implement conversion for `CredentialError::ExpiredToken` → log at DEBUG level and return appropriate expired token error based on token_type
  - Add catch-all for unexpected errors → log at ERROR level and return `internal_server_error()`
  - Keep existing error constructors for backward compatibility
  - _Requirements: 2.2, 2.3, 3.2, 3.3_

- [x] 4. Update AdminError with conversion logic






  - Add `from_internal_error(err: InternalError) -> Self` method to `AdminError` in `src/errors/api/admin.rs`
  - Add private `internal_server_error() -> Self` helper method that returns generic "An internal error occurred" message
  - Implement conversion for infrastructure errors: `Database`, `Transaction`, `Parse`, `Crypto` → log at ERROR level and return `internal_server_error()`
  - Implement conversion for `CredentialError::UserNotFound` → return `AdminError::user_not_found(user_id)`
  - Implement conversion for `CredentialError::DuplicateUsername` → log at WARN level and return `internal_server_error()` (shouldn't happen in admin context)
  - Implement conversion for `SystemConfigError::OwnerAlreadyExists` → return `AdminError::already_bootstrapped()`
  - Implement conversion for `SystemConfigError::OwnerNotFound` → return `AdminError::owner_not_found()`
  - Add catch-all for unexpected errors → log at ERROR level and return `internal_server_error()`
  - Keep existing error constructors for backward compatibility
  - _Requirements: 2.2, 2.3, 3.2, 3.3_

- [x] 5. Update SystemConfigStore to use InternalError



  - Change all method return types from `Result<T, AuthError>` to `Result<T, InternalError>`
  - Replace `AuthError::internal_error("Database error: ...")` with `InternalError::database("operation_name", e)` for all database operations
  - Replace `AuthError::internal_error("System config not found")` with `SystemConfigError::ConfigNotFound.into()`
  - Replace `AuthError::internal_error("Owner already exists")` with `SystemConfigError::OwnerAlreadyExists.into()`
  - Update error context to include operation names in all `InternalError::database()` calls (e.g., "get_config", "set_owner_active")
  - Run tests to verify behavior unchanged
  - _Requirements: 1.1, 1.5, 4.1, 4.5, 6.1_

- [x] 6. Update AuditStore to use InternalError


  - Change return types from `Result<T, AuthError>` to `Result<T, InternalError>`
  - Replace `AuthError::internal_error()` with `InternalError::database()` for DB errors
  - Replace domain-specific errors with `AuditError` variants
  - Update error context to include operation names
  - Run tests to verify behavior
  - _Requirements: 1.1, 4.1, 6.1_

- [x] 7. Update CredentialStore to use InternalError






  - Change all method return types from `Result<T, AuthError>` to `Result<T, InternalError>`
  - Replace `AuthError::internal_error("Database error: ...")` with `InternalError::database("operation_name", e)` for all database queries
  - Replace `AuthError::duplicate_username()` with `CredentialError::DuplicateUsername(username).into()`
  - Replace `AuthError::invalid_credentials()` with `CredentialError::InvalidCredentials.into()`
  - Replace `AuthError::internal_error("User not found: ...")` with `CredentialError::UserNotFound(user_id).into()`
  - Replace `AuthError::internal_error("Password hashing error: ...")` with `CredentialError::PasswordHashingFailed(msg).into()`
  - Replace `AuthError::invalid_refresh_token()` with `CredentialError::InvalidToken { token_type: "refresh_token", reason }.into()`
  - Replace `AuthError::expired_refresh_token()` with `CredentialError::ExpiredToken("refresh_token").into()`
  - Update crypto errors: `AuthError::internal_error("Failed to initialize Argon2...")` → `InternalError::crypto("argon2_init", msg)`
  - Update parse errors: UUID parsing failures → `InternalError::parse("UUID", msg)` (if any in this store)
  - Update transaction errors: `AuthError::internal_error("Failed to start transaction...")` → `InternalError::transaction("operation_name", e)`
  - Update error context to include operation names in all infrastructure error calls
  - Run tests to verify behavior unchanged
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 4.1, 4.2, 4.3, 4.4, 4.5, 6.1_

- [x] 8. Update TokenService to use InternalError


  - Change all method return types from `Result<T, AuthError>` to `Result<T, InternalError>`
  - Replace `AuthError::internal_error("Invalid expiration timestamp...")` with `InternalError::parse("timestamp", msg)`
  - Replace `AuthError::internal_error("Failed to generate JWT...")` with `InternalError::crypto("jwt_generation", msg)` or appropriate variant
  - Replace `AuthError::invalid_token()` with `CredentialError::InvalidToken { token_type: "jwt", reason }.into()`
  - Replace `AuthError::expired_token()` with `CredentialError::ExpiredToken("jwt").into()`
  - Update error context to include operation names in all infrastructure error calls
  - Propagate InternalError from AuditStore unchanged (no conversion needed)
  - Run tests to verify behavior unchanged
  - _Requirements: 3.1, 6.2_


- [x] 9. Update AuthService to use InternalError

  - Change all method return types from `Result<T, AuthError>` to `Result<T, InternalError>`
  - Replace `AuthError::internal_error("Invalid user_id format...")` with `InternalError::parse("UUID", e.to_string())`
  - Propagate InternalError from CredentialStore unchanged (no conversion needed)
  - Propagate InternalError from TokenService unchanged (no conversion needed)
  - Remove any error conversions between internal types (they should flow through naturally)
  - Run tests to verify behavior unchanged
  - _Requirements: 1.2, 3.1, 4.2, 6.2_


- [x] 10. Update AdminService to use InternalError


  - Change all method return types from `Result<T, AuthError>` to `Result<T, InternalError>`
  - Propagate InternalError from CredentialStore unchanged (no conversion needed)
  - Propagate InternalError from SystemConfigStore unchanged (no conversion needed)
  - Remove any error conversions between internal types (they should flow through naturally)
  - Run tests to verify behavior unchanged
  - _Requirements: 3.1, 6.2_

- [x] 11. Update auth API endpoints to convert errors


  - Add `.map_err(AuthError::from_internal_error)?` to all service calls in `src/api/auth.rs`
  - Verify error messages are appropriate for users
  - Run tests to verify correct HTTP status codes
  - Verify no internal details are exposed in responses
  - _Requirements: 2.2, 2.3, 3.2, 3.3, 3.5, 5.1_

- [x] 12. Update admin API endpoints to convert errors



  - Add `.map_err(AdminError::from_internal_error)?` to all service calls in `src/api/admin.rs`
  - Verify error messages are appropriate for users
  - Run tests to verify correct HTTP status codes
  - Verify no internal details are exposed in responses
  - _Requirements: 2.2, 2.3, 3.2, 3.3, 3.5, 5.1_

- [x] 13. Update AppData initialization



  - Change `AppData::init()` return type to `Result<Self, InternalError>`
  - Update `main.rs` to handle InternalError from AppData::init()
  - Convert InternalError to appropriate startup error
  - Run tests to verify behavior
  - _Requirements: 3.1_

- [x] 14. Checkpoint - Ensure all tests pass


  - Ensure all tests pass, ask the user if questions arise.




- [x] 15. Remove deprecated error constructors
  - Remove `internal_error(message: String)` method from `AuthError` in `src/errors/api/auth.rs`
  - Remove `internal_error(message: String)` method from `AdminError` in `src/errors/api/admin.rs`
  - Search codebase for any remaining `AuthError::internal_error` usage in stores/services
  - Search codebase for any remaining `AdminError::internal_error` usage in stores/services
  - Update any remaining usages to use appropriate `InternalError` variants
  - Verify compilation succeeds (compiler will catch any missed usages)
  - _Requirements: 3.1, 3.4_

- [ ] 16. Final verification and cleanup
  - Run full test suite
  - Verify no internal details exposed in API responses (manual testing)
  - Verify error logging includes full context
  - Verify error messages are user-appropriate
  - Update inline code comments if needed
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [x] 17. Create error handling documentation





  - Create `docs/error-handling.md` for developers extending the system
  - Document the two-layer error architecture (InternalError vs API errors)
  - Explain when to use each InternalError variant (infrastructure vs domain errors)
  - Document domain error enums and their use cases (CredentialError, SystemConfigError, AuditError)
  - Show concrete code examples of error flow through layers (Store → Service → API)
  - Document the conversion pattern at API boundary using `from_internal_error()`
  - Provide step-by-step guide for adding new error types to the system
  - Document helper method conventions (database(), transaction(), parse(), crypto())
  - Explain layer-specific error handling responsibilities
  - Include decision tree: "Which error type should I use?"
  - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 3.4, 3.5_

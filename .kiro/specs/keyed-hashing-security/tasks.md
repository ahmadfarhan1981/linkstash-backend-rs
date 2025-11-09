# Implementation Plan

- [ ] 1. Add HMAC dependencies and create crypto utility module
  - Add `hmac = "0.12"` and `sha2 = "0.10"` to Cargo.toml dependencies
  - Create `src/auth/crypto.rs` with HMAC-SHA256 utility function for refresh tokens
  - Implement `hmac_sha256_token(key: &str, token: &str) -> String` function
  - Export crypto module in `src/auth/mod.rs`
  - _Requirements: 2.1, 2.2, 6.1, 6.3_

- [ ] 1.1 Write unit tests for HMAC utility
  - Test HMAC consistency (same key + token = same hash)
  - Test output length (64 hex characters)
  - _Requirements: 7.1, 7.2_

- [ ] 2. Implement password pepper support in CredentialStore
  - Add `password_pepper: String` field to `CredentialStore` struct
  - Update `CredentialStore::new()` to accept `password_pepper` parameter
  - Modify `add_user()` to use `Argon2::new_with_secret()` with pepper for password hashing
  - Modify `verify_credentials()` to support both legacy (no pepper) and new (with pepper) password verification
  - Implement `is_legacy_password_hash()` helper to detect legacy hashes (check for absence of `data=` parameter)
  - Implement `migrate_user_password()` to re-hash legacy passwords with pepper on successful login
  - _Requirements: 1.1, 1.2, 1.3, 4.1, 4.2_

- [ ] 2.1 Write unit tests for password pepper functionality
  - Test password hashing with secret parameter produces valid hash
  - Test password verification with secret parameter works correctly
  - Test legacy password detection (hashes without `data=` parameter)
  - Test legacy password verification still works
  - Test automatic migration on successful legacy login
  - Test peppered hashes contain `data=` parameter
  - _Requirements: 7.3, 4.1, 4.2_

- [ ] 3. Implement HMAC-based refresh token hashing in TokenManager
  - Add `refresh_token_secret: String` field to `TokenManager` struct
  - Update `TokenManager::new()` to accept `refresh_token_secret` parameter
  - Add `hash_refresh_token(&self, token: &str) -> String` method using HMAC-SHA256 from crypto module
  - Update any existing refresh token generation/validation to use HMAC hashing
  - _Requirements: 2.1, 2.2, 2.3, 6.1, 6.2, 6.3_

- [ ] 3.1 Write unit tests for HMAC-based refresh token hashing
  - Test refresh token HMAC hashing produces consistent output
  - Test refresh token validation with HMAC works correctly
  - Test token minting prevention (can't validate without correct secret)
  - _Requirements: 7.4, 2.4_

- [ ] 4. Add secret key validation and loading in main.rs
  - Create `validate_secrets()` function to load and validate all three secret keys from environment
  - Validate `JWT_SECRET`, `PASSWORD_PEPPER`, and `REFRESH_TOKEN_SECRET` are present
  - Validate each secret has minimum 32 characters (256 bits)
  - Validate all three secrets are different from each other
  - Return clear error messages indicating which key is missing or invalid
  - Call `validate_secrets()` at startup before database connection
  - Update `CredentialStore::new()` call to pass `password_pepper`
  - Update `TokenManager::new()` call to pass `refresh_token_secret`
  - _Requirements: 1.3, 1.4, 2.3, 3.1, 3.2, 3.3, 3.4, 3.5, 6.4_

- [ ] 4.1 Write integration tests for secret validation
  - Test app fails to start with missing JWT_SECRET
  - Test app fails to start with missing PASSWORD_PEPPER
  - Test app fails to start with missing REFRESH_TOKEN_SECRET
  - Test app fails to start with secrets shorter than 32 characters
  - Test app fails to start when secrets are not unique
  - _Requirements: 7.5, 3.3_

- [ ] 5. Create documentation for secret key management
  - Update README.md with secret key generation instructions using `openssl rand -base64 32`
  - Document all three required environment variables (JWT_SECRET, PASSWORD_PEPPER, REFRESH_TOKEN_SECRET)
  - Add security warnings about key backup and storage
  - Document that loss of PASSWORD_PEPPER locks out all users
  - Document that loss of REFRESH_TOKEN_SECRET invalidates all refresh tokens
  - Warn against storing keys in version control or logs
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

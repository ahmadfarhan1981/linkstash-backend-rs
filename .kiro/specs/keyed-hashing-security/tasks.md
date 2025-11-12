# Implementation Plan

- [x] 1. Add HMAC dependencies and create crypto utility module



  - Add `hmac = "0.12"` to Cargo.toml dependencies (sha2 already exists)
  - Create `src/services/crypto.rs` with HMAC-SHA256 utility function for refresh tokens
  - Implement `hmac_sha256_token(key: &str, token: &str) -> String` function
  - Export crypto module in `src/services/mod.rs`
  - _Requirements: 2.1, 2.2, 6.1, 6.3_


- [x] 2. Add REFRESH_TOKEN_SECRET support to SecretManager





  - Add `refresh_token_secret: String` field to `SecretManager` struct
  - Add `refresh_token_config()` method with min_length validation of 32 characters
  - Update `SecretManager::init()` to load REFRESH_TOKEN_SECRET from environment
  - Add `refresh_token_secret()` getter method
  - Rename `pepper` field to `password_pepper` for clarity
  - Rename `pepper_config()` method to `password_pepper_config()` and update env var name from "PEPPER" to "PASSWORD_PEPPER"
  - Rename `pepper()` getter to `password_pepper()`
  - Update Debug and Display implementations to include new secret (redacted)
  - _Requirements: 2.3, 3.1, 3.2, 3.3, 3.5_

- [x] 2.1 Write unit tests for REFRESH_TOKEN_SECRET in SecretManager


  - Test successful initialization with valid REFRESH_TOKEN_SECRET
  - Test error when REFRESH_TOKEN_SECRET is missing
  - Test error when REFRESH_TOKEN_SECRET is too short (< 32 chars)
  - Test getter method returns correct value
  - Test Debug trait doesn't expose secret
  - _Requirements: 7.5, 3.3_

- [x] 3. Implement password pepper support in CredentialStore





  - Add `password_pepper: String` field to `CredentialStore` struct
  - Update `CredentialStore::new()` to accept `password_pepper` parameter
  - Modify `add_user()` to use `Argon2::new_with_secret()` with password_pepper for password hashing
  - Modify `verify_credentials()` to use `Argon2::new_with_secret()` with password_pepper for password verification
  - _Requirements: 1.1, 1.2, 1.3_



- [x] 3.1 Write unit tests for password pepper functionality






  - Test password hashing with secret parameter produces valid hash
  - Test password verification with secret parameter works correctly
  - Test different peppers produce different hashes
  - Test peppered hashes contain `data=` parameter
  - _Requirements: 7.3_

- [x] 4. Implement HMAC-based refresh token hashing in TokenService





  - Add `refresh_token_secret: String` field to `TokenService` struct
  - Update `TokenService::new()` to accept `refresh_token_secret` parameter
  - Add `hash_refresh_token(&self, token: &str) -> String` method using HMAC-SHA256 from crypto module
  - Update any existing refresh token generation/validation to use HMAC hashing
  - _Requirements: 2.1, 2.2, 2.3, 6.1, 6.2, 6.3_


- [ ] 4.1 Write unit tests for HMAC-based refresh token hashing

  - Test refresh token HMAC hashing produces consistent output
  - Test refresh token validation with HMAC works correctly
  - Test token minting prevention (can't validate without correct secret)
  - _Requirements: 7.4, 2.4_

- [ ] 5. Update main.rs to pass secrets from SecretManager
  - Update `CredentialStore::new()` call to pass `secret_manager.password_pepper()` as password_pepper parameter
  - Update `TokenService::new()` call to pass `secret_manager.refresh_token_secret()` as second parameter
  - Verify SecretManager initialization already handles validation and error messages
  - _Requirements: 1.3, 1.4, 2.3, 3.1, 3.2, 3.4, 6.4_

- [ ] 5.1 Write integration tests for end-to-end flows

  - Test end-to-end password flow with pepper (create user → login → verify peppered hash)
  - Test end-to-end refresh token flow with HMAC (login → get RT → refresh → verify HMAC protection)
  - _Requirements: 7.3, 7.4_

- [ ] 6. Update documentation for secret key management
  - Update README.md with secret key generation instructions using `openssl rand -base64 32`
  - Document all three required environment variables (JWT_SECRET, PASSWORD_PEPPER, REFRESH_TOKEN_SECRET)
  - Update .env.example with REFRESH_TOKEN_SECRET placeholder and rename PEPPER to PASSWORD_PEPPER
  - Add security warnings about key backup and storage
  - Document that loss of PASSWORD_PEPPER locks out all users
  - Document that loss of REFRESH_TOKEN_SECRET invalidates all refresh tokens
  - Warn against storing keys in version control or logs
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

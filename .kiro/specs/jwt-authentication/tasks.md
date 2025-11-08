# Implementation Plan: JWT Authentication System

## Strategy

Build incrementally with working endpoints at each step. Start with a basic login endpoint returning placeholder tokens, then progressively add real JWT generation, database persistence, and additional endpoints. This allows manual and automated testing at each phase.

---

## Phase 1: Basic Login Endpoint (Placeholder Tokens)

- [ ] 1. Create minimal auth models and error types
  - [ ] 1.1 Add basic dependencies to Cargo.toml
    - Add poem-openapi Object derive support (already have)
    - Add serde for serialization
    - _Requirements: 7.1_
  - [ ] 1.2 Create LoginRequest and TokenResponse models
    - Implement LoginRequest with username and password fields
    - Implement TokenResponse with access_token, refresh_token, token_type, expires_in
    - Use poem-openapi Object derive for automatic schema generation
    - _Requirements: 1.1, 7.1_
  - [ ] 1.3 Create basic AuthError enum
    - Add InvalidCredentials variant
    - Implement conversion to HTTP 401 response
    - _Requirements: 7.1, 7.2_
  - [ ] 1.4 Create auth module structure
    - Create src/auth/mod.rs with module exports
    - Create src/auth/models.rs for request/response types
    - Create src/auth/errors.rs for error types
    - _Requirements: All_

- [ ] 2. Implement basic login endpoint with hardcoded validation
  - [ ] 2.1 Create AuthApi struct with login endpoint
    - Create src/auth/api.rs with AuthApi struct
    - Implement POST /auth/login endpoint that accepts LoginRequest
    - Hardcode credential check: username="testuser", password="testpass"
    - Return placeholder tokens: access_token="placeholder-jwt", refresh_token="placeholder-rt"
    - Return 401 for invalid credentials
    - _Requirements: 1.1, 1.2, 7.2_
  - [ ] 2.2 Register AuthApi in main.rs
    - Import AuthApi in main.rs
    - Add AuthApi to OpenApiService
    - Verify endpoint appears in Swagger UI at /api/auth/login
    - _Requirements: All_
  - [ ] 2.3 Manual test the login endpoint
    - Test via Swagger UI with valid credentials (should return 200 with placeholder tokens)
    - Test with invalid credentials (should return 401)
    - _Requirements: 1.1, 1.2_
  - [ ] 2.4 Write unit tests for login endpoint
    - Test login with valid credentials returns 200 and TokenResponse
    - Test login with invalid credentials returns 401
    - Test response contains access_token and refresh_token fields
    - _Requirements: 1.1, 1.2_

---

## Phase 2: Real JWT Generation

- [ ] 3. Add JWT dependencies and implement TokenManager
  - [ ] 3.1 Add JWT dependencies to Cargo.toml
    - Add jsonwebtoken = "9.2"
    - Add chrono for timestamps (already have)
    - _Requirements: 6.1_
  - [ ] 3.2 Create Claims struct
    - Define Claims with sub (user_id), exp, iat fields in models.rs
    - Add serde Serialize/Deserialize derives
    - _Requirements: 6.4, 6.5_
  - [ ] 3.3 Implement TokenManager for JWT operations
    - Create src/auth/token_manager.rs
    - Implement TokenManager struct with jwt_secret field
    - Implement generate_jwt method (15 min expiration, HS256 signing)
    - Load JWT_SECRET from environment variable in main.rs
    - _Requirements: 1.3, 6.1, 6.4, 6.5_
  - [ ] 3.4 Update login endpoint to return real JWT
    - Pass TokenManager to AuthApi
    - Replace placeholder access_token with real JWT
    - Keep placeholder refresh_token for now
    - _Requirements: 1.3_
  - [ ] 3.5 Manual test JWT generation
    - Login via Swagger UI
    - Copy JWT and decode at jwt.io to verify claims
    - Verify expiration is 15 minutes from now
    - _Requirements: 1.3_
  - [ ] 3.6 Write unit tests for JWT generation
    - Test TokenManager.generate_jwt creates valid JWT
    - Test JWT contains correct user_id in sub claim
    - Test JWT expiration is 15 minutes from issuance
    - Test JWT has iat (issued at) timestamp
    - _Requirements: 1.3, 6.4, 6.5_
  - [ ] 3.7 Update login tests to verify real JWT
    - Update existing login test to decode and verify JWT structure
    - Test JWT can be decoded and contains expected claims
    - _Requirements: 1.3_

---

## Phase 3: WhoAmI Endpoint (JWT Validation)

- [ ] 4. Implement JWT validation and whoami endpoint
  - [ ] 4.1 Create WhoAmIResponse model
    - Add WhoAmIResponse with user_id and expires_at fields
    - _Requirements: 3.1_
  - [ ] 4.2 Implement JWT validation in TokenManager
    - Add validate_jwt method that verifies signature and expiration
    - Return Claims on success
    - Handle expired vs invalid token errors separately
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [ ] 4.3 Update AuthError with token validation errors
    - Add InvalidToken, ExpiredToken, MissingAuthHeader, InvalidAuthHeader variants
    - Map to HTTP 401 responses
    - _Requirements: 7.2_
  - [ ] 4.4 Implement GET /auth/whoami endpoint
    - Extract JWT from Authorization header (Bearer token)
    - Validate JWT using TokenManager
    - Return user_id and expiration from claims
    - Return appropriate errors for missing/invalid/expired tokens
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [ ] 4.5 Manual test whoami endpoint
    - Login to get JWT
    - Call /auth/whoami with Authorization header
    - Verify user_id is returned
    - Test without header (should return 401)
    - Test with invalid JWT (should return 401)
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [ ] 4.6 Write unit tests for JWT validation
    - Test TokenManager.validate_jwt succeeds with valid JWT
    - Test validate_jwt returns correct Claims
    - Test validate_jwt fails with invalid signature
    - Test validate_jwt fails with expired JWT
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [ ] 4.7 Write unit tests for whoami endpoint
    - Test whoami with valid JWT returns 200 and user_id
    - Test whoami without Authorization header returns 401
    - Test whoami with invalid JWT returns 401
    - Test whoami with expired JWT returns 401
    - Test whoami with malformed Authorization header returns 401
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

---

## Phase 4: Database Setup and User Storage

- [ ] 5. Set up database infrastructure
  - [ ] 5.1 Add database dependencies to Cargo.toml
    - Add sea-orm with sqlx-sqlite, runtime-tokio-native-tls, macros features
    - Add argon2 = "0.5" for password hashing
    - _Requirements: 5.1, 6.1_
  - [ ] 5.2 Create database migration for users table
    - Set up migration crate structure
    - Create migration for users table (id, username, password_hash, created_at)
    - Add unique index on username
    - _Requirements: 5.1, 5.3_
  - [ ] 5.3 Create User entity model
    - Create src/auth/entities/user.rs
    - Define User entity with DeriveEntityModel
    - _Requirements: 5.1, 6.4_
  - [ ] 5.4 Initialize database in main.rs
    - Load DATABASE_URL from environment (default: sqlite://auth.db)
    - Create DatabaseConnection
    - Run migrations on startup
    - _Requirements: 5.3_

- [ ] 6. Implement CredentialStore with user operations
  - [ ] 6.1 Create CredentialStore struct
    - Create src/auth/credential_store.rs
    - Initialize with DatabaseConnection
    - _Requirements: 5.1, 5.2_
  - [ ] 6.2 Implement add_user method
    - Hash password with Argon2id
    - Generate UUID for user
    - Insert into database
    - Handle duplicate username errors
    - _Requirements: 5.1_
  - [ ] 6.3 Implement verify_credentials method
    - Query user by username
    - Verify password using Argon2
    - Return user_id (UUID) on success
    - _Requirements: 1.1, 1.2_
  - [ ] 6.4 Seed test user on startup
    - Add test user in main.rs if not exists (username: "testuser", password: "testpass")
    - Log success/failure
    - _Requirements: 5.1_
  - [ ] 6.5 Update login endpoint to use database
    - Pass CredentialStore to AuthApi
    - Replace hardcoded check with verify_credentials call
    - Generate JWT with real user_id from database
    - _Requirements: 1.1, 1.2_
  - [ ] 6.6 Manual test database-backed login
    - Login with test user credentials
    - Verify JWT contains correct user_id
    - Test with wrong password (should return 401)
    - _Requirements: 1.1, 1.2_
  - [ ] 6.7 Write unit tests for CredentialStore
    - Test add_user creates user in database
    - Test add_user hashes password (not stored in plaintext)
    - Test add_user fails with duplicate username
    - Test verify_credentials succeeds with correct password
    - Test verify_credentials fails with incorrect password
    - Test verify_credentials fails with non-existent username
    - _Requirements: 1.1, 1.2, 5.1_
  - [ ] 6.8 Update login tests for database authentication
    - Update login test to verify JWT contains real user_id from database
    - Test login with non-existent user returns 401
    - _Requirements: 1.1, 1.2_

---

## Phase 5: Refresh Token Implementation

- [ ] 7. Implement refresh token generation and storage
  - [ ] 7.1 Add crypto dependencies
    - Add rand = "0.8", sha2 = "0.10", base64 = "0.21" to Cargo.toml
    - _Requirements: 6.2, 6.3_
  - [ ] 7.2 Create refresh_tokens table migration
    - Create migration for refresh_tokens table (id, token_hash, user_id, expires_at, created_at)
    - Add indexes on token_hash and expires_at
    - Add foreign key to users table
    - _Requirements: 5.2, 5.3_
  - [ ] 7.3 Create RefreshToken entity model
    - Create src/auth/entities/refresh_token.rs
    - Define RefreshToken entity with DeriveEntityModel
    - _Requirements: 5.2, 6.3_
  - [ ] 7.4 Implement refresh token generation in TokenManager
    - Add generate_refresh_token (32 random bytes, base64-encoded)
    - Add hash_refresh_token (SHA-256)
    - Add get_refresh_expiration (7 days)
    - _Requirements: 1.4, 6.2, 6.3_
  - [ ] 7.5 Implement refresh token storage in CredentialStore
    - Add store_refresh_token method (insert hashed token with user_id and expiration)
    - Use database transaction
    - _Requirements: 1.5, 5.2, 5.4, 6.3_
  - [ ] 7.6 Update login endpoint to generate and store real refresh token
    - Generate refresh token via TokenManager
    - Hash and store via CredentialStore
    - Return real refresh token in response
    - _Requirements: 1.4, 1.5_
  - [ ] 7.7 Manual test refresh token generation
    - Login and verify refresh_token is no longer "placeholder-rt"
    - Verify token is stored in database (check refresh_tokens table)
    - _Requirements: 1.4, 1.5_
  - [ ] 7.8 Write unit tests for refresh token generation
    - Test TokenManager.generate_refresh_token creates unique tokens
    - Test hash_refresh_token produces consistent hashes
    - Test hash_refresh_token produces different hashes for different tokens
    - _Requirements: 1.4, 6.2, 6.3_
  - [ ] 7.9 Write unit tests for refresh token storage
    - Test store_refresh_token saves token to database
    - Test stored token is hashed (not plaintext)
    - Test stored token has correct expiration (7 days)
    - _Requirements: 1.5, 5.2, 5.4_
  - [ ] 7.10 Update login tests for real refresh tokens
    - Update login test to verify refresh_token is not placeholder
    - Test refresh token is stored in database after login
    - _Requirements: 1.4, 1.5_

- [ ] 8. Implement refresh endpoint
  - [ ] 8.1 Create RefreshRequest and RefreshResponse models
    - Add RefreshRequest with refresh_token field
    - Add RefreshResponse with access_token, token_type, expires_in
    - _Requirements: 2.1_
  - [ ] 8.2 Implement refresh token validation in CredentialStore
    - Add validate_refresh_token method (query by hash, check expiration)
    - Return user_id on success
    - _Requirements: 2.1, 2.2, 2.3_
  - [ ] 8.3 Implement POST /auth/refresh endpoint
    - Accept RefreshRequest
    - Hash and validate refresh token
    - Generate new JWT for user_id
    - Return new JWT (keep same refresh token)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [ ] 8.4 Manual test refresh flow
    - Login to get tokens
    - Call /auth/refresh with refresh_token
    - Verify new JWT is returned
    - Verify new JWT has updated expiration
    - Test with invalid refresh token (should return 401)
    - _Requirements: 2.1, 2.2, 2.3_
  - [ ] 8.5 Write unit tests for refresh token validation
    - Test validate_refresh_token succeeds with valid token
    - Test validate_refresh_token returns correct user_id
    - Test validate_refresh_token fails with invalid token
    - Test validate_refresh_token fails with expired token
    - _Requirements: 2.1, 2.2, 2.3_
  - [ ] 8.6 Write unit tests for refresh endpoint
    - Test refresh with valid token returns 200 and new JWT
    - Test refresh with invalid token returns 401
    - Test refresh with expired token returns 401
    - Test new JWT has updated expiration time
    - Test new JWT contains correct user_id
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

---

## Phase 6: Logout and Cleanup

- [ ] 9. Implement logout endpoint
  - [ ] 9.1 Create LogoutRequest and LogoutResponse models
    - Add LogoutRequest with refresh_token field
    - Add LogoutResponse with message field
    - _Requirements: 4.1_
  - [ ] 9.2 Implement refresh token revocation in CredentialStore
    - Add revoke_refresh_token method (delete by hash)
    - _Requirements: 4.1, 4.4_
  - [ ] 9.3 Implement POST /auth/logout endpoint
    - Accept LogoutRequest
    - Hash and revoke refresh token
    - Return success message regardless of token validity
    - _Requirements: 4.1, 4.2, 4.3_
  - [ ] 9.4 Manual test logout
    - Login to get tokens
    - Call /auth/logout with refresh_token
    - Verify token is removed from database
    - Try to refresh with revoked token (should return 401)
    - _Requirements: 4.1, 4.2_
  - [ ] 9.5 Write unit tests for refresh token revocation
    - Test revoke_refresh_token removes token from database
    - Test revoke_refresh_token succeeds even if token doesn't exist
    - _Requirements: 4.1, 4.4_
  - [ ] 9.6 Write unit tests for logout endpoint
    - Test logout with valid token returns 200
    - Test logout removes token from database
    - Test logout with invalid token still returns 200
    - Test refresh fails after logout with 401
    - _Requirements: 4.1, 4.2, 4.3_

- [ ] 10. Implement token cleanup
  - [ ] 10.1 Implement cleanup_expired_tokens in CredentialStore
    - Add method to delete expired tokens
    - Return count of deleted tokens
    - _Requirements: 5.5_
  - [ ] 10.2 Add background cleanup task in main.rs
    - Spawn Tokio task that runs cleanup every hour
    - Log cleanup results
    - _Requirements: 5.5_
  - [ ] 10.3 Write unit tests for token cleanup
    - Test cleanup_expired_tokens removes only expired tokens
    - Test cleanup_expired_tokens returns correct count
    - Test cleanup_expired_tokens doesn't remove valid tokens
    - Test cleanup with no expired tokens returns 0
    - _Requirements: 5.5_

---

## Phase 7: Testing and Polish

- [ ] 11. Create integration tests
  - Write end-to-end test: login → whoami → refresh → logout
  - Test invalid credentials return 401
  - Test expired JWT returns 401
  - Test invalid refresh token returns 401
  - Test whoami without auth header returns 401
  - _Requirements: All_

- [ ] 12. Final verification
  - Test all endpoints via Swagger UI
  - Verify error messages don't leak sensitive info
  - Verify all endpoints documented in OpenAPI spec
  - Check database schema and indexes
  - _Requirements: All_

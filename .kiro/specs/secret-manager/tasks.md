# Implementation Plan

- [x] 1. Create SecretManager module structure





  - Create `src/config/` directory for configuration management
  - Create `src/config/mod.rs` with public exports
  - Create `src/config/secret_manager.rs` for SecretManager implementation
  - Create `src/config/secret_config.rs` for SecretConfig and validation rules
  - Update `src/main.rs` to include the new `config` module
  - _Requirements: 1.1, 1.3, 1.4_

- [x] 2. Implement SecretType enum and SecretConfig




  - [x] 2.1 Define `SecretType` enum with `EnvVar { name: String }` variant

    - Add Debug and Clone derives
    - Add comments for future variants (AWS, Azure, File)
    - _Requirements: 1.5_
  
  - [x] 2.2 Define `SecretConfig` struct with validation rules

    - Add `secret_type: SecretType` field
    - Add `required: bool` and `min_length: Option<usize>` fields
    - Implement builder pattern methods: `new()`, `required()`, `min_length()`
    - _Requirements: 1.5, 2.1, 2.3_

- [x] 3. Implement SecretError type





  - Create `SecretError` enum with `Missing` and `InvalidLength` variants
  - Implement helper methods: `missing()` and `invalid_length()`
  - Implement `Display` trait with clear, actionable error messages
  - Implement `std::error::Error` trait
  - _Requirements: 2.2, 2.4, 2.5_

- [x] 4. Implement SecretManager core functionality





  - [x] 4.1 Create SecretManager struct with typed fields


    - Add `jwt_secret: String` field
    - Add `pepper: String` field
    - _Requirements: 1.1, 1.2, 1.4_

  - [x] 4.2 Implement initialization and loading


    - Implement `init()` method that loads and validates all secrets
    - Implement private `jwt_config()` method using `SecretType::EnvVar` (required, min 32 chars)
    - Implement private `pepper_config()` method using `SecretType::EnvVar` (required, min 16 chars)
    - Implement private `load_secret()` helper that matches on `SecretType` and loads accordingly
    - For `SecretType::EnvVar`, use `std::env::var()` to load the secret
    - Validate minimum length after loading
    - _Requirements: 1.3, 1.5, 2.1, 2.2, 2.3, 2.4_

  - [x] 4.3 Implement getter methods


    - Implement `jwt_secret()` returning `&str`
    - Implement `pepper()` returning `&str`
    - Ensure methods don't allow modification after initialization
    - _Requirements: 1.1, 1.2, 3.1, 3.2, 3.3, 3.4_

  - [x] 4.4 Implement Debug and Display traits


    - Implement `Debug` trait that redacts secret values (shows "<redacted>")
    - Implement `Display` trait that shows metadata only (e.g., "secrets_loaded: 2")
    - Ensure no secret values are exposed through formatting
    - _Requirements: 4.1, 4.2, 4.3_

- [x] 5. Update main.rs to use SecretManager





  - Replace direct `std::env::var("JWT_SECRET")` call with `SecretManager::init()`
  - Wrap SecretManager in `Arc` for shared access
  - Pass `secret_manager.jwt_secret().to_string()` to TokenService
  - Handle initialization errors with clear panic messages
  - _Requirements: 1.1, 1.3, 3.4_

- [x] 6. Update .env and .env.example files




  - Add `PEPPER` environment variable to `.env` with example value (min 16 chars)
  - Add `PEPPER` to `.env.example` with documentation
  - Ensure `JWT_SECRET` meets minimum 32 character requirement
  - Add comments explaining minimum length requirements
  - _Requirements: 1.2, 1.3, 2.3, 2.4_
- [x] 7. Write unit tests for SecretManager
  - Test successful initialization with valid secrets from environment variables
  - Test error when JWT_SECRET environment variable is missing
  - Test error when PEPPER environment variable is missing
  - Test error when JWT_SECRET is too short (< 32 chars)
  - Test error when PEPPER is too short (< 16 chars)
  - Test getter methods return correct values
  - Test Debug trait doesn't expose secrets
  - Test Display trait shows metadata only
  - Test SecretType::EnvVar loading works correctly
  - Use `std::env::set_var` and `std::env::remove_var` for test setup/cleanup
  - _Requirements: 1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 4.1, 4.2, 4.3_

- [x] 8. Write integration tests





  - Test application startup with valid secrets
  - Test application fails gracefully with missing secrets
  - Test TokenService integration with SecretManager
  - Test JWT generation still works with secrets from SecretManager
  - _Requirements: 1.1, 1.3, 3.4_
-

- [x] 9. Create documentation for adding new secrets




  - Create `docs/adding-secrets.md` with step-by-step guide
  - Document how to add a new secret field to SecretManager
  - Document how to add validation rules using SecretConfig
  - Document how to update .env files
  - Add section on how to add a new SecretType (high-level steps only)
  - Include example code snippets
  - Review documentation against actual implementation to ensure accuracy
  - _Requirements: 1.5, 2.1, 2.3, 4.4_

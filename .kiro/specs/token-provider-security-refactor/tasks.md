# Implementation Plan

- [x] 1. Refactor TokenProvider constructor to use SecretManager reference





  - Update TokenProvider::new() to accept Arc<SecretManager> instead of plain string secrets
  - Remove jwt_secret and refresh_token_secret fields from TokenProvider struct
  - Add secret_manager field to TokenProvider struct
  - Update all internal methods to access secrets through secret_manager reference
  - _Requirements: 1.1, 1.2, 1.5, 2.1_

- [ ]* 1.1 Write property test for TokenProvider constructor
  - **Property 1: No plain string secret storage**
  - **Validates: Requirements 1.1, 1.2**

- [ ]* 1.2 Write property test for SecretManager reference storage
  - **Property 2: SecretManager reference storage**
  - **Validates: Requirements 1.5**

- [ ]* 1.3 Write property test for secret access through SecretManager
  - **Property 3: Secret access through SecretManager**
  - **Validates: Requirements 1.3, 1.4, 2.3**

- [x] 2. Update TokenProvider method implementations





  - Modify generate_jwt() to use self.secret_manager.jwt_secret() instead of self.jwt_secret
  - Modify validate_jwt() to use self.secret_manager.jwt_secret() instead of self.jwt_secret
  - Modify hash_refresh_token() to use self.secret_manager.refresh_token_secret() instead of self.refresh_token_secret
  - Ensure all method signatures remain unchanged for backward compatibility
  - _Requirements: 1.3, 1.4, 2.2, 2.3_

- [ ]* 2.1 Write property test for JWT generation compatibility
  - **Property 6: JWT generation compatibility**
  - **Validates: Requirements 3.1**

- [ ]* 2.2 Write property test for JWT validation compatibility
  - **Property 7: JWT validation compatibility**
  - **Validates: Requirements 3.2**

- [ ]* 2.3 Write property test for refresh token hash compatibility
  - **Property 9: Refresh token hash compatibility**
  - **Validates: Requirements 3.4**

- [x] 3. Update coordinator instantiation patterns




  - Update AuthCoordinator::new() to pass Arc<SecretManager> to TokenProvider::new()
  - Update AdminCoordinator::new() to pass Arc<SecretManager> to TokenProvider::new()
  - Remove .to_string() calls on jwt_secret() and refresh_token_secret()
  - Ensure coordinators follow AppData pattern correctly
  - _Requirements: 2.1, 2.4_

- [ ]* 3.1 Write property test for constructor signature compatibility
  - **Property 4: Constructor signature compatibility**
  - **Validates: Requirements 2.1**

- [ ]* 3.2 Write property test for method signature preservation
  - **Property 5: Method signature preservation**
  - **Validates: Requirements 2.2**

- [x] 4. Update Debug and Display trait implementations





  - Ensure Debug trait does not expose SecretManager secrets
  - Ensure Display trait does not expose SecretManager secrets
  - Update debug output to show redacted placeholders for secret fields
  - Maintain existing secret protection mechanisms
  - _Requirements: 2.5, 4.1, 4.2, 4.3_

- [ ]* 4.1 Write property test for Debug trait security
  - **Property 10: Debug trait security**
  - **Validates: Requirements 2.5, 4.1, 4.3**

- [ ]* 4.2 Write property test for Display trait security
  - **Property 11: Display trait security**
  - **Validates: Requirements 4.2**

- [x] 5. Update all test implementations





  - Update TokenProvider unit tests to use Arc<SecretManager> constructor
  - Update coordinator tests to use new TokenProvider constructor pattern
  - Update integration tests in secret_manager_integration.rs
  - Update test utilities in test/utils.rs
  - Update credential_store_invalidate_test.rs
  - Ensure all tests pass with new implementation
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ]* 5.1 Write property test for refresh token generation security
  - **Property 8: Refresh token generation security**
  - **Validates: Requirements 3.3**

- [ ]* 5.2 Write property test for error message security
  - **Property 12: Error message security**
  - **Validates: Requirements 4.5**

- [ ] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
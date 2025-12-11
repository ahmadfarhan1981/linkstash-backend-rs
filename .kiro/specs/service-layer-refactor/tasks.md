# Implementation Plan

- [x] 1. Create new architectural structure and module organization





  - Create `src/coordinators/` directory with mod.rs
  - Create `src/providers/` directory with mod.rs  
  - Set up proper module exports and public interfaces
  - _Requirements: 5.3, 5.4, 7.1, 7.2_

- [ ]* 1.1 Write property test for architectural layer separation
  - **Property 1: Architectural Layer Separation**
  - **Validates: Requirements 1.1, 1.2, 1.4, 2.1, 3.1, 8.1, 8.2**

- [x] 2. Migrate TokenService to TokenProvider




  - Create `src/providers/token_provider.rs` with `TokenProvider` struct
  - Move all JWT generation, validation, and refresh token operations
  - Preserve all existing method signatures and functionality
  - Update imports and dependencies
  - _Requirements: 5.2, 6.3_

- [ ]* 2.1 Write property test for naming convention consistency
  - **Property 2: Naming Convention Consistency**
  - **Validates: Requirements 1.3, 5.1, 5.2, 5.3, 5.4, 5.5**

- [ ]* 2.2 Write unit tests for TokenProvider
  - Test JWT generation with various claim combinations
  - Test JWT validation with valid and invalid tokens
  - Test refresh token generation and hashing
  - _Requirements: 6.3_

- [x] 3. Migrate PasswordValidator to PasswordValidatorProvider


  - Create `src/providers/password_validator_provider.rs` with `PasswordValidatorProvider` struct
  - Move all password validation logic and HIBP integration
  - Preserve all existing validation rules and error types
  - Update imports and dependencies
  - _Requirements: 5.2, 6.4_

- [ ]* 3.1 Write unit tests for PasswordValidatorProvider
  - Test password validation rules (length, username, common passwords)
  - Test HIBP integration with mocked responses
  - Test secure password generation
  - _Requirements: 6.4_

- [x] 4. Migrate crypto functions to CryptoProvider


  - Create `src/providers/crypto_provider.rs` with `CryptoProvider` struct
  - Convert crypto module functions to provider methods
  - Preserve all existing cryptographic operations
  - Update imports and dependencies
  - _Requirements: 5.2, 6.4_

- [ ]* 4.1 Write unit tests for CryptoProvider
  - Test HMAC-SHA256 token hashing
  - Test secure password generation
  - Test cryptographic function consistency
  - _Requirements: 6.4_

- [x] 5. Migrate audit_logger functions to AuditLoggerProvider



  - Create `src/providers/audit_logger_provider.rs` with `AuditLoggerProvider` struct
  - Convert audit_logger module functions to provider methods
  - Preserve all existing audit logging functionality and AuditBuilder
  - Maintain actor/target separation pattern
  - Update imports and dependencies
  - _Requirements: 5.2, 6.4_

- [ ]* 5.1 Write unit tests for AuditLoggerProvider
  - Test audit event creation and logging
  - Test AuditBuilder functionality
  - Test actor/target separation in audit logs
  - _Requirements: 6.4_

- [x] 6. Migrate AuthService to AuthCoordinator




  - Create `src/coordinators/auth_coordinator.rs` with `AuthCoordinator` struct
  - Move workflow orchestration logic from AuthService
  - Update to use new providers instead of services
  - Preserve all existing method signatures (login, refresh, logout, change_password)
  - Ensure pure orchestration with no business logic
  - _Requirements: 5.1, 6.1_

- [ ]* 6.1 Write property test for coordinator orchestration purity
  - **Property 4: Coordinator Orchestration Purity**
  - **Validates: Requirements 2.1, 2.2, 2.3, 2.4**

- [ ]* 6.2 Write unit tests for AuthCoordinator
  - Test login workflow orchestration
  - Test refresh workflow orchestration
  - Test logout workflow orchestration
  - Test password change workflow orchestration
  - _Requirements: 6.1_

- [x] 7. Migrate AdminService to AdminCoordinator




  - Create `src/coordinators/admin_coordinator.rs` with `AdminCoordinator` struct
  - Move workflow orchestration logic from AdminService
  - Update to use new providers instead of services
  - Preserve all existing method signatures (assign/remove admin roles, deactivate owner)
  - Ensure pure orchestration with no business logic
  - _Requirements: 5.1, 6.2_

- [ ]* 7.1 Write property test for provider business logic containment
  - **Property 5: Provider Business Logic Containment**
  - **Validates: Requirements 3.1, 3.2, 3.3, 3.4**

- [ ]* 7.2 Write unit tests for AdminCoordinator
  - Test system admin assignment/removal workflows
  - Test role admin assignment/removal workflows
  - Test owner deactivation workflow
  - Test authorization and self-modification prevention
  - _Requirements: 6.2_

- [x] 8. Update API layer to use coordinators




  - Update `src/api/auth.rs` to import and use AuthCoordinator
  - Update `src/api/admin.rs` to import and use AdminCoordinator
  - Remove direct service imports from API layer
  - Ensure API layer only calls coordinators, never providers
  - _Requirements: 4.1_

- [ ]* 8.1 Write property test for dependency flow enforcement
  - **Property 3: Dependency Flow Enforcement**
  - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 8.3, 8.4, 8.5**

- [ ]* 8.2 Write integration tests for API layer
  - Test complete authentication flows through new architecture
  - Test complete admin management flows through new architecture
  - Verify API responses remain identical to original behavior
  - _Requirements: 6.5_

- [x] 9. Update AppData and dependency injection




  - Update `src/app_data.rs` to create and manage coordinators and providers
  - Update dependency injection to wire coordinators with providers
  - Remove old service references
  - Ensure clean initialization of new architecture
  - _Requirements: 7.3, 7.4_

- [ ]* 9.1 Write unit tests for AppData integration
  - Test coordinator and provider initialization
  - Test dependency injection correctness
  - Test clean startup and shutdown
  - _Requirements: 7.3, 7.4_

- [x] 10. Remove old services directory and update imports
  - Remove `src/services/auth_service.rs`
  - Remove `src/services/admin_service.rs`
  - Remove `src/services/token_service.rs`
  - Remove `src/services/password_validator.rs`
  - Remove `src/services/crypto.rs`
  - Remove `src/services/audit_logger.rs`
  - Update `src/services/mod.rs` or remove if empty
  - Update all remaining imports throughout codebase
  - _Requirements: 1.1, 1.4_

- [ ]* 10.1 Write property test for functional preservation during migration
  - **Property 6: Functional Preservation During Migration**
  - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**

- [x] 11. Finalize module exports and public interfaces
  - Complete `src/coordinators/mod.rs` with proper exports
  - Complete `src/providers/mod.rs` with proper exports
  - Ensure clean import paths for external usage
  - Verify no implementation details are exposed
  - _Requirements: 7.1, 7.2, 7.3_

- [ ]* 11.1 Write property test for module export consistency
  - **Property 7: Module Export Consistency**
  - **Validates: Requirements 7.1, 7.2, 7.3, 7.4**

- [ ] 12. Final validation and testing
  - Run all existing tests to ensure no regressions
  - Verify all new property-based tests pass
  - Test complete application startup and basic functionality
  - Validate architectural integrity through dependency analysis
  - _Requirements: 6.5, 8.5_

- [ ]* 12.1 Write comprehensive integration tests
  - Test end-to-end authentication flows
  - Test end-to-end admin management flows
  - Test error handling and rollback scenarios
  - Test audit logging through new architecture
  - _Requirements: 6.5_

- [ ] 13. Checkpoint - Ensure all tests pass, ask the user if questions arise
  - Ensure all tests pass, ask the user if questions arise.
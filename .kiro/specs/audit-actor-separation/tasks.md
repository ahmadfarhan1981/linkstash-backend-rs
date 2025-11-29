# Implementation Plan

- [x] 1. Login Flow - Update login success/failure logging
  - [x] 1.1 Update log_login_success and log_login_failure
    - Update `log_login_success` to accept `RequestContext` and `target_user_id`
    - Update `log_login_failure` to accept `RequestContext` (username already in details)
    - Extract `actor_id` from `RequestContext` for `user_id` field
    - Store `target_user_id` in event details with key "target_user_id"
    - Update function documentation
    - _Requirements: 1.1, 1.2, 2.1, 2.2, 2.3, 2.4_
  - [x] 1.2 Update CredentialStore.verify_credentials
    - Add `RequestContext` parameter to `verify_credentials` method
    - Pass `RequestContext` to `log_login_success`
    - Pass authenticated user ID as `target_user_id` parameter
    - Pass `RequestContext` to `log_login_failure`
    - Update function documentation
    - _Requirements: 1.1, 1.2, 2.1, 2.2, 2.3, 2.4_
  - [x] 1.3 Update AuthService.login to pass RequestContext
    - Update call to `credential_store.verify_credentials` to pass `RequestContext`
    - Verify login authentication flow compiles
    - _Requirements: 1.1, 1.2_
  - [x] 1.4 Update any other callers of verify_credentials
    - Search codebase for other calls to `verify_credentials`
    - Update them to pass `RequestContext`
    - Verify all changes compile
    - _Requirements: 1.1, 1.2_
  - [x] 1.5 Verify and test login flow
    - Run `cargo build` to ensure no compilation errors
    - Run `cargo test --lib` to ensure tests pass
    - Start server and test login via API
    - Check audit database to verify actor/target separation
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3_

- [x] 2. JWT Issuance - Update JWT generation logging





  - [x] 2.1 Update log_jwt_issued


    - Update `log_jwt_issued` to accept `RequestContext` and `target_user_id`
    - Extract `actor_id` from `RequestContext` for `user_id` field
    - Extract `jwt_id` from `RequestContext.claims` for `jwt_id` field (if authenticated)
    - Store `target_user_id` in event details with key "target_user_id"
    - Update function documentation
    - _Requirements: 1.1, 1.2, 4.1, 4.2_
  - [x] 2.2 Update TokenService.generate_jwt


    - Add `RequestContext` parameter to `generate_jwt` method
    - Pass `RequestContext` to `log_jwt_issued`
    - Pass JWT subject (`user_id`) as `target_user_id` parameter
    - Update function documentation
    - _Requirements: 1.1, 1.2, 4.1, 4.2_


  - [ ] 2.3 Update AuthService.login to pass RequestContext to generate_jwt
    - Update call to `token_service.generate_jwt` to pass `RequestContext`


    - Verify login flow compiles
    - _Requirements: 1.1, 1.2_


  - [ ] 2.4 Update AuthService.refresh to pass RequestContext to generate_jwt
    - Update call to `token_service.generate_jwt` to pass `RequestContext`
    - Verify refresh flow compiles


    - _Requirements: 1.1, 1.2_
  - [ ] 2.5 Update any other callers of generate_jwt
    - Search codebase for other calls to `generate_jwt`
    - Update them to pass `RequestContext`
    - Verify all changes compile
    - _Requirements: 1.1, 1.2_
  - [ ] 2.6 Verify and test JWT issuance
    - Run `cargo build` to ensure no compilation errors
    - Run `cargo test --lib` to ensure tests pass
    - Start server and test login via API
    - Check audit database to verify JWT issuance logs show correct actor/target
    - _Requirements: 1.1, 1.2, 4.1, 4.2_

- [x] 3. Refresh Token Issuance - Update refresh token logging



  - [x] 3.1 Update log_refresh_token_issued


    - Update `log_refresh_token_issued` to accept `RequestContext` and `target_user_id`
    - Extract `actor_id` from `RequestContext` for `user_id` field
    - Extract `jwt_id` from `RequestContext.claims` for `jwt_id` field (if authenticated)
    - Store `target_user_id` in event details with key "target_user_id"
    - Update function documentation
    - _Requirements: 1.1, 1.2, 3.1, 3.2_
  - [x] 3.2 Update CredentialStore.store_refresh_token


    - Add `RequestContext` parameter to `store_refresh_token` method
    - Pass `RequestContext` to `log_refresh_token_issued`
    - Pass token owner (`user_id`) as `target_user_id` parameter
    - Update function documentation
    - _Requirements: 1.1, 1.2, 3.1, 3.2_
  - [x] 3.3 Update AuthService.login to pass RequestContext to store_refresh_token


    - Update call to `credential_store.store_refresh_token` to pass `RequestContext`
    - Verify login flow compiles
    - _Requirements: 1.1, 1.2_
  - [x] 3.4 Update any other callers of store_refresh_token


    - Search codebase for other calls to `store_refresh_token`
    - Update them to pass `RequestContext`
    - Verify all changes compile
    - _Requirements: 1.1, 1.2_
  - [x] 3.5 Verify and test refresh token issuance


    - Run `cargo build` to ensure no compilation errors
    - Run `cargo test --lib` to ensure tests pass
    - Start server and test login via API
    - Check audit database to verify refresh token issuance logs show correct actor/target
    - _Requirements: 1.1, 1.2, 3.1, 3.2_

- [x] 4. Refresh Token Validation - Update token validation logging



  - [x] 4.1 Update log_refresh_token_validation_failure


    - Update `log_refresh_token_validation_failure` to accept `RequestContext`
    - Extract `actor_id` from `RequestContext` for `user_id` field
    - Extract `jwt_id` from `RequestContext.claims` for `jwt_id` field (if authenticated)
    - Update function documentation
    - _Requirements: 1.1, 3.3_
  - [x] 4.2 Update CredentialStore.validate_refresh_token


    - Add `RequestContext` parameter to `validate_refresh_token` method
    - Pass `RequestContext` to `log_refresh_token_validation_failure`
    - Update function documentation
    - _Requirements: 1.1, 3.3_
  - [x] 4.3 Update AuthService.refresh to pass RequestContext to validate_refresh_token


    - Update call to `credential_store.validate_refresh_token` to pass `RequestContext`
    - Verify refresh flow compiles
    - _Requirements: 1.1, 1.2_
  - [x] 4.4 Update any other callers of validate_refresh_token


    - Search codebase for other calls to `validate_refresh_token`
    - Update them to pass `RequestContext`
    - Verify all changes compile
    - _Requirements: 1.1_
  - [x] 4.5 Verify and test refresh token validation


    - Run `cargo build` to ensure no compilation errors
    - Run `cargo test --lib` to ensure tests pass
    - Start server and test token refresh via API
    - Check audit database to verify validation logs show correct actor
    - _Requirements: 1.1, 3.3_

- [x] 5. Refresh Token Revocation - Update token revocation logging



  - [x] 5.1 Update log_refresh_token_revoked


    - Update `log_refresh_token_revoked` to accept `RequestContext` and `target_user_id`
    - Extract `actor_id` from `RequestContext` for `user_id` field
    - Extract `jwt_id` from `RequestContext.claims` for `jwt_id` field (if authenticated)
    - Store `target_user_id` in event details with key "target_user_id"
    - Update function documentation
    - _Requirements: 1.1, 1.2, 3.4, 3.5_
  - [x] 5.2 Update CredentialStore.revoke_refresh_token


    - Update `revoke_refresh_token` to accept `RequestContext` instead of just `jwt_id`
    - Pass `RequestContext` to `log_refresh_token_revoked`
    - Pass token owner as `target_user_id` parameter
    - Update function documentation
    - _Requirements: 1.1, 1.2, 3.4, 3.5_
  - [x] 5.3 Update AuthService.logout to pass RequestContext


    - Update call to `credential_store.revoke_refresh_token` to pass `RequestContext`
    - Verify logout flow compiles
    - _Requirements: 1.1, 1.2_
  - [x] 5.4 Update any other callers of revoke_refresh_token


    - Search codebase for other calls to `revoke_refresh_token`
    - Update them to pass `RequestContext`
    - Verify all changes compile
    - _Requirements: 1.1, 1.2_
  - [x] 5.5 Verify and test refresh token revocation


    - Run `cargo build` to ensure no compilation errors
    - Run `cargo test --lib` to ensure tests pass
    - Start server and test logout via API
    - Check audit database to verify revocation logs show correct actor/target
    - _Requirements: 1.1, 1.2, 3.4, 3.5_

- [x] 6. JWT Validation Failures - Update JWT validation logging



  - [x] 6.1 Update log_jwt_validation_failure and log_jwt_tampered


    - Update `log_jwt_validation_failure` to accept `RequestContext`
    - Update `log_jwt_tampered` to accept `RequestContext`
    - Extract `actor_id` from `RequestContext` for `user_id` field
    - Extract `jwt_id` from `RequestContext.claims` for `jwt_id` field (if authenticated)
    - Update function documentation
    - _Requirements: 4.3, 4.4_
  - [x] 6.2 Update TokenService.validate_jwt


    - Create temporary `RequestContext` from JWT claims for audit logging
    - Pass `RequestContext` to `log_jwt_validation_failure`
    - Pass `RequestContext` to `log_jwt_tampered`
    - Update function documentation
    - _Requirements: 4.3, 4.4_
  - [x] 6.3 Verify and test JWT validation failures


    - Run `cargo build` to ensure no compilation errors
    - Run `cargo test --lib` to ensure tests pass
    - Start server and test with expired/tampered JWT
    - Check audit database to verify validation failure logs show correct actor
    - _Requirements: 4.3, 4.4_

- [ ] 7. Integration Testing and Verification
  - [ ] 7.1 Full end-to-end testing - Login flow
    - Start the server with `controlPwshProcess`
    - Test unauthenticated login via API
    - Check audit database to verify:
      - Login success: `user_id` = "unknown", `target_user_id` in details
      - JWT issued: `user_id` = "unknown", `target_user_id` in details
      - Refresh token issued: `user_id` = "unknown", `target_user_id` in details
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 3.1, 3.2, 4.1, 4.2_
  - [ ] 7.2 Full end-to-end testing - Refresh flow
    - Test token refresh via API with valid refresh token
    - Check audit database to verify:
      - JWT issued: `user_id` = actor from original JWT, `target_user_id` in details
    - _Requirements: 1.1, 1.2, 3.3, 4.1, 4.2_
  - [ ] 7.3 Full end-to-end testing - Logout flow
    - Test logout via API with valid JWT
    - Check audit database to verify:
      - Token revoked: `user_id` = actor from JWT, `target_user_id` in details
    - _Requirements: 1.1, 1.2, 3.4, 3.5_
  - [ ] 7.4 Full end-to-end testing - Error cases
    - Test with expired JWT
    - Test with tampered JWT
    - Test with invalid refresh token
    - Check audit database to verify all error cases log correct actor
    - _Requirements: 4.3, 4.4_
  - [ ] 7.5 Verify no regressions
    - Test all existing authentication flows still work
    - Verify no unexpected errors in logs
    - Check that all audit events are being logged
    - Run full test suite: `cargo test --lib`

- [ ] 8. Documentation
  - [x] 8.1 Update extending-audit-logs.md
    - Update function signature examples for all modified functions
    - Add examples showing actor/target separation
    - Update usage patterns to show RequestContext usage
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  - [x] 8.2 Update logging.md steering file



    - Update audit logging patterns to show RequestContext
    - Update examples to demonstrate actor/target separation
    - Update "Log at Point of Action" section
    - _Requirements: 5.1, 5.2_
  - [x] 8.3 Final verification




    - Review all documentation changes for accuracy
    - Ensure all examples compile and work
    - Run final `cargo build` and `cargo test --lib`
    - Confirm all manual tests pass

- [x] 9. Add test cases for optional authentication audit logging





  - [x] 9.1 Add tests for login endpoint with optional auth


    - Write test for login WITH auth header - verify audit log has actor_id from JWT and jwt_id
    - Write test for login WITHOUT auth header - verify audit log has actor_id = "unknown" and jwt_id = None
    - Verify both tests check target_user_id is in event details
    - _Requirements: 1.1, 1.2, 2.1_


  - [x] 9.2 Add tests for refresh endpoint with optional auth
    - Write test for refresh WITH auth header - verify audit log has actor_id from JWT and jwt_id
    - Write test for refresh WITHOUT auth header - verify audit log has actor_id = "unknown" and jwt_id = None


    - Verify both tests check target_user_id is in event details
    - _Requirements: 1.1, 1.2, 3.1_
  - [x] 9.3 Add tests for logout endpoint with optional auth


    - Write test for logout WITH auth header - verify audit log has actor_id from JWT and jwt_id
    - Write test for logout WITHOUT auth header - verify audit log has actor_id = "unknown" and jwt_id = None
    - Verify both tests check target_user_id is in event details (for token revocation)
    - _Requirements: 1.1, 1.2, 3.4_
  - [x] 9.4 Run all new tests and verify they pass
    - Run `cargo test --lib` to ensure all new tests pass
    - Verify audit logs are correctly populated in all scenarios
    - Check that existing tests still pass

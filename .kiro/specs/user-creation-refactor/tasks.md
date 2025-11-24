# Implementation Plan

- [x] 1. Extend RequestContext to support CLI and System sources





  - Add `RequestSource` enum with API, CLI, and System variants
  - Add `source` field to `RequestContext`
  - Add `actor_id` field to `RequestContext`
  - Implement `for_cli()` constructor for CLI operations
  - Implement `for_system()` constructor for system operations
  - Update existing `RequestContext::new()` to default to API source
  - _Requirements: 4.1, 6.1_

- [x] 2. Add new audit event types




  - Add `CliSessionStart` variant to `EventType`
  - Add `CliSessionEnd` variant to `EventType`
  - Add `UserCreated` variant to `EventType`
  - Add `PrivilegesChanged` variant to `EventType`
  - Add `OperationRolledBack` variant to `EventType`
  - Update `EventType::as_str()` to handle new variants
  - _Requirements: 5.1, 5.2, 5.3, 2.2, 2.3_

- [x] 3. Implement audit logging functions for new events





- [x] 3.1 Implement CLI session logging


  - Implement `log_cli_session_start()` function
  - Implement `log_cli_session_end()` function
  - Include command name, sanitized args, and success status
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 3.2 Implement user management logging

  - Implement `log_user_created()` function
  - Implement `log_privileges_changed()` function (logs before/after state)
  - Implement `log_operation_rolled_back()` function
  - Include source and actor_id in all events
  - _Requirements: 1.5, 2.2, 2.3, 4.5_

- [ ]* 3.3 Write property test for audit logging
  - **Property 2: User creation is audited**
  - **Validates: Requirements 1.5**

- [ ]* 3.4 Write property test for privilege change auditing
  - **Property 3: Privilege changes are audited with before/after state**
  - **Validates: Requirements 2.2, 2.3**

- [x] 4. Implement primitive user creation method




- [x] 4.1 Implement `create_user()` primitive


  - Accept `RequestContext`, username, and password_hash parameters
  - Generate UUID for user_id
  - Create user with all privilege flags set to false
  - Insert user into database
  - Log user creation event immediately (at point of action)
  - Handle duplicate username errors
  - _Requirements: 1.1, 1.2, 1.4, 1.5_

- [ ]* 4.2 Write property test for primitive user creation
  - **Property 1: Primitive user creation never assigns privileges**
  - **Validates: Requirements 1.1, 1.2**

- [ ]* 4.3 Write unit tests for create_user
  - Test successful user creation
  - Test duplicate username handling
  - Test audit logging occurs
  - Test all privilege flags are false
  - _Requirements: 1.1, 1.2, 1.5_

- [x] 5. Implement privilege assignment primitive method




- [x] 5.1 Implement `set_privileges()`


  - Accept `RequestContext`, user_id, and new_privileges (AdminFlags) parameters
  - Fetch current user to get old privileges
  - Update all privilege flags atomically
  - Update updated_at timestamp
  - Log privilege change event with before/after state immediately
  - Return old privileges on success
  - Handle user not found errors
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [ ]* 5.2 Write property test for privilege atomicity
  - **Property 4: Privilege changes are atomic**
  - **Validates: Requirements 2.5**

- [ ]* 5.3 Write unit tests for set_privileges
  - Test setting various privilege combinations
  - Test audit logging includes before/after state
  - Test return value contains old privileges
  - Test user not found errors
  - _Requirements: 2.1, 2.2, 2.3, 2.5_

- [x] 6. Refactor existing `create_admin_user()` to use primitives






- [x] 6.1 Update method signature

  - Change to accept `RequestContext` instead of individual parameters
  - Keep username, password_hash, and admin_flags parameters
  - _Requirements: 3.3_

- [x] 6.2 Implement using transaction and primitives


  - Start database transaction
  - Call `create_user()` primitive within transaction
  - Call `set_privileges()` primitive within transaction
  - Log rollback event if privilege assignment fails
  - Commit transaction if all operations succeed
  - _Requirements: 3.1, 3.2_

- [ ]* 6.3 Write unit tests for refactored create_admin_user
  - Test successful creation with owner privileges
  - Test successful creation with system_admin privileges
  - Test successful creation with role_admin privileges
  - Test rollback on privilege assignment failure
  - Test separate audit events for creation and privilege assignment
  - _Requirements: 3.1, 3.2, 3.5_

- [x] 7. Update existing privilege assignment methods





- [x] 7.1 Refactor `set_system_admin()`


  - Update to call `set_privileges()` internally
  - Maintain backward compatibility by accepting old parameters
  - Create RequestContext from old parameters
  - Build AdminFlags with only is_system_admin changed
  - Mark as deprecated in documentation
  - _Requirements: 2.4_

- [x] 7.2 Refactor `set_role_admin()`


  - Update to call `set_privileges()` internally
  - Maintain backward compatibility by accepting old parameters
  - Create RequestContext from old parameters
  - Build AdminFlags with only is_role_admin changed
  - Mark as deprecated in documentation
  - _Requirements: 2.4_

- [x] 8. Update CLI bootstrap command





- [x] 8.1 Add CLI session lifecycle logging


  - Create RequestContext using `for_cli("bootstrap")`
  - Log CLI session start at beginning of bootstrap
  - Log CLI session end with success/failure status
  - Include command name and sanitized arguments
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 8.2 Update user creation calls


  - Pass RequestContext to `create_admin_user()`
  - Ensure context has CLI source and appropriate actor_id
  - _Requirements: 3.3, 4.2, 6.2_

- [ ]* 8.3 Write property test for CLI context
  - **Property 6: CLI operations have CLI source**
  - **Validates: Requirements 4.2, 6.2**

- [ ]* 8.4 Write property test for CLI session auditing
  - **Property 10: CLI session start is audited**
  - **Property 11: CLI session end is audited with correct status**
  - **Property 12: CLI session events have correct context**
  - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5**

- [x] 9. Update CLI owner management commands





- [x] 9.1 Add CLI session logging to owner activate


  - Create RequestContext using `for_cli("owner_activate")`
  - Log CLI session start and end
  - _Requirements: 5.1, 5.2, 5.3_

- [x] 9.2 Add CLI session logging to owner deactivate


  - Create RequestContext using `for_cli("owner_deactivate")`
  - Log CLI session start and end
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 10. Update API endpoints to use new RequestContext fields
- [ ] 10.1 Update `create_request_context()` helper
  - Set source to `RequestSource::API`
  - Set actor_id from JWT claims (sub field)
  - Ensure backward compatibility
  - _Requirements: 4.3, 6.3_

- [ ]* 10.2 Write property test for API context
  - **Property 7: API operations have API source**
  - **Validates: Requirements 4.3, 6.3**

- [ ]* 10.3 Write property test for audit log source field
  - **Property 9: Audit logs include request source**
  - **Validates: Requirements 4.5**

- [ ] 11. Add system operation context support
- [ ] 11.1 Identify system operations
  - Review codebase for automated operations
  - Document operations that need System source
  - _Requirements: 4.4, 6.4_

- [ ] 11.2 Update system operations to use System context
  - Create RequestContext using `for_system(operation_name)`
  - Pass context to user management operations
  - _Requirements: 4.4, 6.4_

- [ ]* 11.3 Write property test for system context
  - **Property 8: System operations have System source**
  - **Validates: Requirements 4.4, 6.4**

- [ ] 12. Update documentation
- [ ] 12.1 Create user-management.md
  - Document the user creation and privilege management architecture
  - Explain primitive operations (`create_user`, `set_privileges`) and their usage
  - Provide examples for creating users with different privilege levels
  - Document RequestContext creation for different sources (API/CLI/System)
  - Explain when to use primitives vs helper methods
  - Include code examples for common scenarios
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 12.2 Update existing documentation
  - Update request-context.md with source and actor_id fields
  - Update logging.md with new audit events (UserCreated, PrivilegesChanged, CLI session events)
  - Add references to user-management.md
  - _Requirements: 7.1, 7.4_

- [ ] 13. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

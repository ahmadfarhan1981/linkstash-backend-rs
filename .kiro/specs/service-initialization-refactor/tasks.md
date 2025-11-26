# Implementation Plan - Incremental Testing Approach

**Note:** This refactor changes service initialization from service-owned stores to main-owned stores. No deprecation needed since there are no deployed users.

**Strategy:** Test after each component is refactored to ensure no regressions.

---

## Phase 1: Create AppData Struct and Implementation

### Task 1.1: Create AppData struct
- [x] Create src/app_data.rs file
- [x] Define AppData struct with db audit_db secret_manager stores and token_service fields
- [x] Add pub visibility to all fields
- [x] Export from src/lib.rs or create mod.rs
- [x] Requirements 1.1 1.2 8.1
- [x] Testable AppData struct compiles

### Task 1.2: Implement AppData init method
- [x] Add async init method to AppData
- [x] Initialize databases using init_database and init_audit_database
- [x] Initialize SecretManager
- [x] Create AuditStore with audit_db
- [x] Create CredentialStore with db pepper audit_store
- [x] Create SystemConfigStore with db audit_store
- [x] Create TokenService with jwt_secret refresh_secret audit_store
- [x] Return Ok Self with all fields
- [x] Requirements 1.1 1.2 1.3 4.1 4.2 4.3
- [x] Testable AppData init creates all dependencies

### Task 1.3: Update main.rs to use AppData
- [x] After logging initialization call AppData init
- [x] Wrap result in Arc
- [x] Remove individual store creation code
- [x] Keep existing AuthService init call for now
- [x] Keep existing CLI execute_command signature for now
- [x] Requirements 1.3 4.4
- [x] Testable main.rs creates AppData successfully

### Task 1.4: Test AppData initialization
- [ ]* Write test AppData init creates all stores
- [ ]* Write test AppData init wraps stores in Arc
- [ ]* Write test AppData init handles database errors
- [ ]* Write test AppData init handles secret manager errors
- [ ]* PHASE 1 COMPLETE AppData struct exists and initializes correctly

---

## Phase 2: Extract Test User Seeding

### Task 2.1: Create seed_test_user function
- [x] Create seed_test_user function in main.rs
- [x] Accept credential_store parameter
- [x] Move test user creation logic from AuthService
- [x] Add cfg debug_assertions attribute
- [x] Log success duplicate and error cases
- [x] Requirements 6.1 6.2 6.3
- [x] Testable Function can seed test user

### Task 2.2: Test seed_test_user function
- [ ]* Write test Function creates test user successfully
- [ ]* Write test Function handles duplicate username gracefully
- [ ]* Write test Function logs appropriate messages
- [ ]* PHASE 2 COMPLETE Test user seeding is extracted

---

## Phase 3: Update AuthService to Use AppData

### Task 3.1: Add system_config_store field to AuthService
- [x] Add system_config_store field to AuthService struct
- [x] Update all field references in methods
- [x] Requirements 2.1 2.3
- [x] Testable AuthService struct compiles with new field

### Task 3.2: Create new constructor accepting AppData
- [x] Add new method accepting Arc AppData parameter
- [x] Extract credential_store from app_data
- [x] Extract system_config_store from app_data
- [x] Extract token_service from app_data
- [x] Extract audit_store from app_data
- [x] Return Self with extracted fields
- [x] Make constructor synchronous no async
- [x] Keep init method for now to avoid breaking main.rs
- [x] Requirements 2.1 2.2 2.3 2.4 3.1 3.3 3.4 8.2
- [ ] Testable AuthService can be instantiated with new app_data

### Task 3.3: Update AuthService instantiation in main.rs
- [x] Replace AuthService init call with AuthService new
- [x] Pass app_data clone to new
- [x] Wrap in Arc
- [x] After AuthService creation call seed_test_user with app_data credential_store
- [x] Ensure seed_test_user only called in debug mode
- [x] Requirements 2.1 4.2 6.1 6.2 8.3
- [x] Testable AuthService is created with new app_data in main.rs

### Task 3.4: Remove init method from AuthService
- [x] Delete init method now that main.rs uses new
- [x] Remove internal store creation logic
- [x] Remove seed_test_user method
- [x] Requirements 3.3 3.4
- [x] Testable AuthService no longer has init method

### Task 3.5: Test AuthService refactor
- [ ]* Write test new creates AuthService from AppData
- [ ]* Write test AuthService extracts only needed dependencies
- [ ]* Write test AuthService methods work with extracted stores
- [ ]* Write test Can create AuthService with mock AppData
- [ ]* Write test Server starts successfully with new initialization
- [ ]* Write test Test user is seeded in debug mode only
- [ ]* PHASE 3 COMPLETE AuthService uses AppData pattern

---

## Phase 4: Update CLI Mode to Use AppData

### Task 4.1: Update execute_command signature
- [x] Change signature to accept app_data reference
- [x] Remove db audit_db secret_manager parameters
- [x] Requirements 5.1 5.2 5.3
- [x] Testable execute_command accepts AppData parameter

### Task 4.2: Update CLI command handlers to extract from AppData
- [x] Update bootstrap command to extract credential_store and system_config_store from app_data
- [x] Update owner activate command to extract system_config_store from app_data
- [x] Update owner deactivate command to extract system_config_store from app_data
- [x] Update owner status command to extract system_config_store from app_data
- [x] Remove any service creation from CLI commands
- [x] Requirements 5.2 5.3
- [x] Testable CLI commands extract what they need from AppData

### Task 4.3: Update main.rs CLI branch
- [x] Update execute_command call to pass app_data reference
- [x] Remove individual parameter passing
- [x] Requirements 5.1 5.2
- [x] Testable CLI mode uses AppData

### Task 4.4: Test CLI mode with AppData
- [ ]* Write test CLI mode receives AppData
- [ ]* Write test bootstrap command works with AppData
- [ ]* Write test owner commands work with AppData
- [ ]* Write test CLI commands can access any store from AppData
- [ ]* Write test Adding new store to AppData doesnt break CLI signatures
- [ ]* PHASE 4 COMPLETE CLI mode uses AppData pattern

---

## Phase 5: Verification and Cleanup

### Task 5.1: Run all existing tests
- [ ] Run cargo test and verify all tests pass
- [ ] Fix any test failures related to initialization changes
- [ ] Requirements 7.1 7.2 7.3
- [ ] Testable All tests pass

### Task 5.2: Verify server functionality
- [ ] Start server with cargo run
- [ ] Verify server starts without errors
- [ ] Check Swagger UI at swagger
- [ ] Test login endpoint
- [ ] Test whoami endpoint
- [ ] Test refresh endpoint
- [ ] Test logout endpoint
- [ ] Requirements 7.1 7.2
- [ ] Testable All API endpoints work

### Task 5.3: Verify CLI functionality
- [ ] Test cargo run bootstrap
- [ ] Test cargo run owner activate
- [ ] Test cargo run owner deactivate
- [ ] Test cargo run owner status
- [ ] Requirements 5.1 5.2 5.3
- [ ] Testable All CLI commands work

### Task 5.4: Code cleanup
- [ ] Remove any unused imports
- [ ] Remove any dead code
- [ ] Run cargo clippy and fix warnings
- [ ] Run cargo fmt
- [ ] Requirements All
- [ ] Testable Code compiles without warnings

### Task 5.5: Create developer documentation for AppData pattern
- [x] Create docs/appdata-pattern.md
- [x] Document AppData struct purpose and contents
- [x] Document how to add new stores to AppData
- [x] Document how to create new services that use AppData
- [x] Document explicit extraction pattern with code examples
- [x] Document what should and should not go in AppData
- [x] Document testing with AppData mock AppData example
- [ ] Document CLI command pattern for accessing AppData
- [ ] Requirements All
- [ ] Testable Documentation exists and is clear

### Task 5.6: Final integration test
- [ ]* Write test Full server startup and shutdown
- [ ]* Write test Multiple services can share same stores
- [ ]* Write test Store instances are identical same Arc
- [ ]* Write test AppData can be mocked for testing
- [ ]* PHASE 5 COMPLETE Refactor is complete and verified

---

## Testing Checkpoints

After each phase verify:
- [ ] All tests in that phase pass
- [ ] No regressions in previous phases
- [ ] Code compiles without warnings
- [ ] Server can start if applicable
- [ ] CLI commands work if applicable

## Estimated Timeline

- Phase 1: 1-2 hours (create AppData struct and init)
- Phase 2: 30 minutes (extract test user seeding)
- Phase 3: 1-2 hours (update AuthService to use AppData)
- Phase 4: 1 hour (update CLI mode to use AppData)
- Phase 5: 1-2 hours (verification and cleanup)

Total: 4.5-8 hours

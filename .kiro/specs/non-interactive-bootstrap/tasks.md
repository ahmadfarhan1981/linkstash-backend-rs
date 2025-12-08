# Implementation Plan

- [x] 1. Add test-utils feature flag to Cargo.toml
  - Add `[features]` section with `test-utils = []`
  - _Requirements: 2.1, 2.2, 2.3, 6.1, 6.2, 6.3_

- [x] 2. Define fixed credentials constants in bootstrap.rs
  - Add `TEST_OWNER_USERNAME` constant with value "test-owner"
  - Add `TEST_OWNER_PASSWORD` constant with value "test-owner-password-do-not-use-in-production"
  - Both constants guarded with `#[cfg(any(debug_assertions, feature = "test-utils"))]`
  - _Requirements: 1.2, 4.3, 4.4, 7.1, 7.2_

- [x] 3. Implement bootstrap_system_non_interactive function
  - Create new function in `src/cli/bootstrap.rs`
  - Guard with `#[cfg(any(debug_assertions, feature = "test-utils"))]`
  - Display test-only warning banner
  - Create RequestContext for CLI operation ("bootstrap_test")
  - Log CLI session start
  - Check if owner already exists (return error if yes)
  - Use `TEST_OWNER_USERNAME` and `TEST_OWNER_PASSWORD` constants
  - Hash password using existing `hash_password()` helper
  - Create owner account using `credential_store.create_admin_user()` with `AdminFlags::owner()`
  - Display credentials to console (username and password)
  - Display test-only credentials warning
  - Display owner activation warning
  - Log bootstrap completion (0 system admins, 0 role admins)
  - Log CLI session end
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 5.2, 5.3, 7.3_

- [x] 4. Modify Bootstrap command to accept --non-interactive flag
  - Update `Commands::Bootstrap` enum variant in `src/cli/mod.rs`
  - Add `non_interactive: bool` field with `#[arg(long)]` attribute
  - Guard field with `#[cfg(any(debug_assertions, feature = "test-utils"))]`
  - Add help text: "Non-interactive mode (TEST ONLY - creates owner with fixed password, no prompts)"
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 5.1_

- [x] 5. Update command routing to handle --non-interactive flag
  - Modify `execute_command()` in `src/cli/mod.rs`
  - Add conditional logic to check `non_interactive` flag
  - Route to `bootstrap_system_non_interactive()` if flag is true
  - Route to `bootstrap_system()` if flag is false
  - Handle both cfg scenarios (with and without test-utils feature)
  - _Requirements: 1.1, 2.1, 2.2, 2.3_

- [ ]* 6. Write unit tests for fixed credentials constants
  - Test `TEST_OWNER_USERNAME` equals "test-owner"
  - Test `TEST_OWNER_PASSWORD` length >= 15 characters
  - Test password contains "test" substring
  - Test password contains "do-not-use-in-production" substring

- [ ]* 7. Write integration test for bootstrap and login workflow
  - Setup fresh test databases
  - Execute non-interactive bootstrap
  - Login via API with fixed credentials
  - Assert login succeeds and JWT is issued

- [ ]* 8. Write integration test for owner activation workflow
  - Setup fresh test databases
  - Execute non-interactive bootstrap
  - Execute owner activate command
  - Login via API with fixed credentials
  - Assert login succeeds

- [ ]* 9. Write compilation tests
  - Test debug build includes --non-interactive flag in help
  - Test release build excludes --non-interactive flag in help
  - Test release build with test-utils feature includes flag in help

- [x] 10. Update tech.md steering file with usage documentation
  - Add section on non-interactive bootstrap
  - Document command usage: `cargo run -- bootstrap --non-interactive`
  - Document fixed credentials
  - Add warning about test-only nature
  - Include compilation examples for different build modes
  - _Requirements: 5.1_

- [ ] 11. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

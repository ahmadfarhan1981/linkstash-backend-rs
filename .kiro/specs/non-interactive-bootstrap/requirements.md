# Requirements Document

## Introduction

This feature adds a non-interactive bootstrap command for automated testing and CI/CD environments. The standard `bootstrap` command requires interactive user input for password generation and admin account creation, which prevents automated testing workflows. This feature provides a test-only variant that creates a minimal owner account with auto-generated credentials, enabling AI agents and automated tests to set up fresh test environments without manual intervention.

## Glossary

- **Bootstrap**: The process of creating the initial owner account and optional admin accounts during system setup
- **Owner Account**: The highest-privilege administrative account in the system, created during bootstrap
- **Non-Interactive Mode**: A command execution mode that requires no user input and uses sensible defaults
- **Test-Utils Feature**: A Cargo feature flag that enables test-only functionality
- **Debug Build**: A Rust compilation mode with `debug_assertions` enabled (default for `cargo build`)
- **Release Build**: A Rust compilation mode optimized for production (enabled with `--release` flag)

## Requirements

### Requirement 1

**User Story:** As a developer running automated tests, I want to bootstrap a test system without interactive prompts, so that I can set up fresh test databases programmatically.

#### Acceptance Criteria

1. WHEN a developer runs the non-interactive bootstrap command in a debug build, THEN the system SHALL create an owner account without prompting for input
2. WHEN the non-interactive bootstrap command executes, THEN the system SHALL use a fixed, well-known password for the owner account
3. WHEN the non-interactive bootstrap command completes, THEN the system SHALL output the owner username and fixed password to the console
4. WHEN the non-interactive bootstrap command is invoked and an owner already exists, THEN the system SHALL return an error indicating the system is already bootstrapped
5. WHEN the non-interactive bootstrap command completes successfully, THEN the system SHALL log the bootstrap event to the audit database

### Requirement 2

**User Story:** As a security-conscious developer, I want the non-interactive bootstrap command to be unavailable in production builds, so that it cannot be accidentally used in production environments.

#### Acceptance Criteria

1. WHEN the application is compiled in debug mode, THEN the non-interactive bootstrap command SHALL be available
2. WHEN the application is compiled in release mode without the test-utils feature, THEN the non-interactive bootstrap command SHALL NOT be available
3. WHEN the application is compiled in release mode with the test-utils feature enabled, THEN the non-interactive bootstrap command SHALL be available
4. WHEN a user attempts to run the non-interactive bootstrap command in a build where it is not available, THEN the system SHALL display an error message indicating the command does not exist

### Requirement 3

**User Story:** As a developer, I want the non-interactive bootstrap to create only the owner account, so that test setup is minimal and fast.

#### Acceptance Criteria

1. WHEN the non-interactive bootstrap command executes, THEN the system SHALL create exactly one owner account
2. WHEN the non-interactive bootstrap command executes, THEN the system SHALL NOT create any System Admin accounts
3. WHEN the non-interactive bootstrap command executes, THEN the system SHALL NOT create any Role Admin accounts
4. WHEN the non-interactive bootstrap command executes, THEN the system SHALL NOT prompt for the number of admin accounts to create

### Requirement 4

**User Story:** As a developer, I want the non-interactive bootstrap to use the same security standards as interactive bootstrap, so that test environments are realistic.

#### Acceptance Criteria

1. WHEN the non-interactive bootstrap uses the fixed password, THEN the system SHALL hash the password using Argon2id with the configured password pepper (same as interactive bootstrap)
2. WHEN the non-interactive bootstrap creates an owner account, THEN the system SHALL set the owner_active flag to false (inactive by default)
3. WHEN the non-interactive bootstrap creates an owner account, THEN the system SHALL use a fixed username "test-owner" for predictability in automated testing
4. WHEN the fixed password is defined, THEN the password SHALL be at least 15 characters to pass validation requirements

### Requirement 5

**User Story:** As a developer, I want clear documentation on when to use non-interactive bootstrap, so that I understand its purpose and limitations.

#### Acceptance Criteria

1. WHEN a developer views the command help, THEN the system SHALL display a description indicating the command is for testing only
2. WHEN the non-interactive bootstrap command executes, THEN the system SHALL display a warning that this is a test-only command
3. WHEN the non-interactive bootstrap command completes, THEN the system SHALL display the same owner activation warning as the interactive bootstrap

### Requirement 6

**User Story:** As a CI/CD pipeline, I want to enable the non-interactive bootstrap in release builds for staging environments, so that I can test production-like builds without interactive input.

#### Acceptance Criteria

1. WHEN the application is compiled with `cargo build --release --features test-utils`, THEN the non-interactive bootstrap command SHALL be available
2. WHEN the test-utils feature is enabled, THEN the system SHALL include the non-interactive bootstrap command in the CLI
3. WHEN the test-utils feature is not enabled in a release build, THEN the non-interactive bootstrap command SHALL be completely removed from the binary

### Requirement 7

**User Story:** As a developer, I want the fixed test password to be clearly identifiable as test-only, so that it is never accidentally used in production contexts.

#### Acceptance Criteria

1. WHEN the fixed password is defined in code, THEN the password string SHALL contain the word "test" to clearly indicate its purpose
2. WHEN the fixed password is defined in code, THEN the password SHALL include a warning phrase such as "do-not-use-in-production"
3. WHEN the non-interactive bootstrap outputs the password, THEN the system SHALL display a warning that this is a test-only password

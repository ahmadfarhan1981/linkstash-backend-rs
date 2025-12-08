# Design Document

## Overview

This feature adds a non-interactive bootstrap command (`bootstrap-test`) that creates a minimal owner account without user prompts. The command is conditionally compiled based on build configuration: always available in debug builds, and available in release builds only when the `test-utils` feature flag is enabled. This ensures the command cannot accidentally be used in production while remaining available for automated testing, CI/CD pipelines, and AI-assisted development workflows.

The implementation reuses existing bootstrap infrastructure (password hashing, audit logging) but bypasses all interactive prompts and creates only the owner account with a fixed, well-known password. This fixed password approach enables automated tests and AI agents to know the credentials without parsing command output.

## Architecture

### Conditional Compilation Strategy

The feature uses Rust's conditional compilation attributes to control availability:

```rust
#[cfg(any(debug_assertions, feature = "test-utils"))]
Commands::BootstrapTest => {
    // Non-interactive bootstrap implementation
}
```

**Compilation Scenarios:**
- **Debug builds** (`cargo build`): Command always available
- **Release builds** (`cargo build --release`): Command NOT available
- **Release with feature** (`cargo build --release --features test-utils`): Command available

### Code Reuse

The implementation maximizes code reuse from the existing `bootstrap.rs` module:
- Password hashing: `hash_password()` helper function
- Owner creation: `credential_store.create_admin_user()` with `AdminFlags::owner()`
- Audit logging: `audit_logger::log_bootstrap_completed()`
- Request context: `RequestContext::for_cli("bootstrap_test")`

### Fixed Credentials Constants

The implementation defines fixed credentials constants for test use:

```rust
#[cfg(any(debug_assertions, feature = "test-utils"))]
const TEST_OWNER_USERNAME: &str = "test-owner";

#[cfg(any(debug_assertions, feature = "test-utils"))]
const TEST_OWNER_PASSWORD: &str = "test-owner-password-do-not-use-in-production";
```

**Rationale:**
- **Predictable:** Automated tests and AI agents know both username and password without parsing output
- **Clearly marked:** Username contains "test", password contains "test" and "do-not-use-in-production"
- **Meets validation:** Password is 46 characters, exceeds 15-character minimum requirement
- **Simple for automation:** No need to parse UUID from output or remember generated values
- **Conditionally compiled:** Only exists in debug builds or with `test-utils` feature

**Trade-offs:**
- **Not a UUID:** Breaks the pattern of UUID usernames, but acceptable for test-only functionality
- **Conflict risk:** Minimal - interactive bootstrap only creates UUID usernames, and this is test-only

## Components and Interfaces

### CLI Command Structure

**Location:** `src/cli/mod.rs`

Modify the existing `Bootstrap` command to accept an optional flag:

```rust
#[derive(Subcommand)]
pub enum Commands {
    // ... existing commands ...
    
    /// Bootstrap the system by creating owner and initial admin accounts
    Bootstrap {
        /// Non-interactive mode (TEST ONLY - creates owner with fixed password, no prompts)
        #[cfg(any(debug_assertions, feature = "test-utils"))]
        #[arg(long)]
        non_interactive: bool,
    },
}
```

**Command Routing:** `src/cli/mod.rs` - `execute_command()`

```rust
Commands::Bootstrap { 
    #[cfg(any(debug_assertions, feature = "test-utils"))]
    non_interactive 
} => {
    #[cfg(any(debug_assertions, feature = "test-utils"))]
    if non_interactive {
        bootstrap::bootstrap_system_non_interactive(
            &app_data.credential_store,
            &app_data.system_config_store,
            &app_data.audit_store,
            &app_data.secret_manager,
        ).await?;
    } else {
        bootstrap::bootstrap_system(
            &app_data.credential_store,
            &app_data.system_config_store,
            &app_data.audit_store,
            &app_data.secret_manager,
        ).await?;
    }
    
    #[cfg(not(any(debug_assertions, feature = "test-utils")))]
    {
        bootstrap::bootstrap_system(
            &app_data.credential_store,
            &app_data.system_config_store,
            &app_data.audit_store,
            &app_data.secret_manager,
        ).await?;
    }
}
```

### Bootstrap Implementation

**Location:** `src/cli/bootstrap.rs`

Add new public function:

```rust
#[cfg(any(debug_assertions, feature = "test-utils"))]
pub async fn bootstrap_system_non_interactive(
    credential_store: &CredentialStore,
    system_config_store: &SystemConfigStore,
    audit_store: &Arc<AuditStore>,
    secret_manager: &SecretManager,
) -> Result<(), Box<dyn std::error::Error>>
```

**Implementation Flow:**
1. Display test-only warning banner
2. Create RequestContext with `RequestContext::for_cli("bootstrap_test")`
3. Log CLI session start
4. Check if owner already exists (error if yes)
5. Use fixed username constant `TEST_OWNER_USERNAME` ("test-owner")
6. Use fixed password constant `TEST_OWNER_PASSWORD`
7. Hash password using `hash_password()` with pepper
8. Create owner account with `AdminFlags::owner()`
9. Display credentials to console (fixed username and fixed password)
10. Display test-only credentials warning
11. Display owner activation warning
12. Log bootstrap completion (0 system admins, 0 role admins)
13. Log CLI session end

### Cargo Feature Configuration

**Location:** `Cargo.toml`

Add feature flag definition:

```toml
[features]
# Test utilities - enables non-interactive bootstrap and other test-only commands
test-utils = []
```

## Data Models

No new data models required. Uses existing:
- `User` entity (from `types::db::user`)
- `AdminFlags` (from `types::internal::auth`)
- `RequestContext` (from `types::internal::context`)
- `AuditEvent` (from `types::internal::audit`)

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Flag availability in debug builds
*For any* debug build of the application, the `--non-interactive` flag should be available in the `bootstrap` command help output and functional
**Validates: Requirements 2.1**

### Property 2: Flag unavailability in release builds without feature
*For any* release build compiled without the `test-utils` feature, the `--non-interactive` flag should not appear in the `bootstrap` command help output and should not be accepted
**Validates: Requirements 2.2**

### Property 3: Flag availability with feature flag
*For any* release build compiled with the `test-utils` feature enabled, the `--non-interactive` flag should be available in the `bootstrap` command help output and functional
**Validates: Requirements 2.3**

### Property 4: Owner account creation
*For any* execution of `bootstrap --non-interactive` on a system without an existing owner, exactly one owner account should be created with the fixed username "test-owner" and the fixed test password
**Validates: Requirements 1.1, 1.2, 3.1, 4.3**

### Property 5: Duplicate bootstrap prevention
*For any* execution of `bootstrap --non-interactive` on a system with an existing owner, the command should fail with an error indicating the system is already bootstrapped
**Validates: Requirements 1.4**

### Property 6: No additional admin accounts
*For any* execution of `bootstrap --non-interactive`, zero System Admin accounts and zero Role Admin accounts should be created
**Validates: Requirements 3.2, 3.3**

### Property 7: Password hashing equivalence
*For any* execution of the non-interactive bootstrap, the fixed password should be hashed using Argon2id with the configured pepper, matching the security standards of the interactive bootstrap
**Validates: Requirements 4.1**

### Property 8: Owner inactive by default
*For any* owner account created by `bootstrap --non-interactive`, the `owner_active` system flag should be set to false
**Validates: Requirements 4.2**

### Property 9: Audit logging completeness
*For any* successful execution of `bootstrap --non-interactive`, an audit event should be logged with the owner username, zero system admins, and zero role admins
**Validates: Requirements 1.5**

### Property 10: Credentials output
*For any* successful execution of `bootstrap --non-interactive`, the owner username and fixed password should be written to stdout
**Validates: Requirements 1.3**

### Property 11: Fixed password validation
*For any* build where `bootstrap --non-interactive` is available, the fixed password constant should be at least 15 characters long
**Validates: Requirements 4.4**

### Property 12: Test-only password marking
*For any* execution of `bootstrap --non-interactive`, the output should include a warning that the password is for testing only
**Validates: Requirements 7.1, 7.2, 7.3**

## Error Handling

### Error Scenarios

1. **Owner Already Exists**
   - Detection: Query `credential_store.get_owner()` returns `Some(owner)`
   - Response: Return error "System already bootstrapped"
   - Audit: Log CLI session end with failure

2. **Database Connection Failure**
   - Detection: Database operations return `DbErr`
   - Response: Propagate error with context
   - Audit: Log CLI session end with failure

3. **Password Hashing Failure**
   - Detection: `hash_password()` returns error
   - Response: Return error "Failed to hash password: {reason}"
   - Audit: Log CLI session end with failure

4. **Owner Creation Failure**
   - Detection: `create_admin_user()` returns error
   - Response: Return error "Failed to create owner account: {reason}"
   - Audit: Log CLI session end with failure

### Error Propagation

All errors use `Result<(), Box<dyn std::error::Error>>` for simplicity in CLI context. Errors bubble up to the CLI executor which displays them to the user.

## Testing Strategy

### Unit Tests

Unit tests verify the non-interactive bootstrap wrapper logic (not the underlying bootstrap functionality which is already tested):

1. **Test: Fixed credentials constants**
   - Test: Verify `TEST_OWNER_USERNAME` equals "test-owner"
   - Test: Verify `TEST_OWNER_PASSWORD` length >= 15 characters
   - Test: Verify password contains "test" and "do-not-use-in-production"

2. **Test: Conditional compilation**
   - Test: Verify constants only exist in debug or with test-utils feature
   - Test: Verify function only exists in debug or with test-utils feature

### Property-Based Tests

No property-based tests needed - the non-interactive bootstrap is a thin wrapper that calls existing tested functions with fixed values.

### Integration Tests

Integration tests verify end-to-end workflows with the fixed credentials:

1. **Test: Full bootstrap and login workflow**
   - Setup: Fresh test databases
   - Execute: Run `cargo run -- bootstrap --non-interactive`
   - Execute: Login via API with username `test-owner` and password `test-owner-password-do-not-use-in-production`
   - Assert: Login succeeds, JWT issued

2. **Test: Owner activation workflow**
   - Setup: Run non-interactive bootstrap
   - Execute: Run `cargo run -- owner activate`
   - Execute: Login via API with fixed credentials
   - Assert: Login succeeds (owner is now active)

### Compilation Tests

Verify conditional compilation works correctly:

1. **Test: Debug build includes flag**
   - Build: `cargo build`
   - Execute: `cargo run -- bootstrap --help`
   - Assert: "--non-interactive" flag appears in help

2. **Test: Release build excludes flag**
   - Build: `cargo build --release`
   - Execute: `cargo run --release -- bootstrap --help`
   - Assert: "--non-interactive" flag does NOT appear in help

3. **Test: Release with feature includes flag**
   - Build: `cargo build --release --features test-utils`
   - Execute: `cargo run --release --features test-utils -- bootstrap --help`
   - Assert: "--non-interactive" flag appears in help

## Security Considerations

### Threat Model

**Threat:** Accidental use of non-interactive bootstrap in production
- **Mitigation:** Conditional compilation removes command from production builds
- **Residual Risk:** Developer could accidentally compile with `test-utils` feature

**Threat:** Fixed password is too weak or predictable
- **Mitigation:** Password is 46 characters long and clearly marked as test-only
- **Residual Risk:** Low - command only available in test builds, password meets validation requirements

**Threat:** Credentials exposed in logs
- **Mitigation:** Credentials only written to stdout, never logged to audit database or application logs
- **Residual Risk:** Stdout could be captured by CI/CD systems - acceptable for test environments

### Security Standards Maintained

1. **Password Hashing:** Argon2id with pepper (same as interactive bootstrap)
2. **Owner Inactive:** Default to inactive (same as interactive bootstrap)
3. **Audit Logging:** Full audit trail of bootstrap operation

**Note:** Username is not a UUID (unlike interactive bootstrap) for test predictability, but this is acceptable as the feature is test-only and conditionally compiled.

## Implementation Notes

### Code Organization

- **Minimal duplication:** Reuse existing helper functions (`hash_password`)
- **Clear separation:** Non-interactive function and constants clearly marked with `#[cfg]` attribute
- **Consistent naming:** `bootstrap_system_non_interactive` mirrors `bootstrap_system`
- **Fixed credentials constants:** `TEST_OWNER_USERNAME` and `TEST_OWNER_PASSWORD` defined at module level with `#[cfg]` guards

### Output Format

The command outputs credentials in a clear, parseable format:

```
=== Linkstash Bootstrap (TEST MODE) ===

⚠️  WARNING: This is a TEST-ONLY command
⚠️  For production use, run: cargo run bootstrap

No owner account found. Creating owner account...

✓ Owner account created
  Username: test-owner
  Password: test-owner-password-do-not-use-in-production

⚠️  WARNING: These are FIXED TEST CREDENTIALS
⚠️  Both username and password are hardcoded for testing purposes only
⚠️  Never use this command or these credentials in production environments

⚠️  WARNING: Owner account is INACTIVE (system flag owner_active=false)
⚠️  The owner account cannot be used until activated via CLI:
⚠️  cargo run -- owner activate

=== Bootstrap Complete ===
Total accounts created:
  - 1 Owner (INACTIVE)
  - 0 System Admin(s)
  - 0 Role Admin(s)
```

### Future Enhancements

1. **JSON output mode:** Add `--json` flag for machine-readable output
2. **Credential file export:** Add `--output-file` flag to write credentials to file
3. **Custom password via env var:** Add `TEST_OWNER_PASSWORD` environment variable override
4. **Multiple owners:** Support creating multiple test owner accounts (edge case testing)

## Documentation Updates

### Files to Update

1. **`.kiro/steering/tech.md`**
   - Add section on non-interactive bootstrap
   - Document when to use vs interactive bootstrap
   - Include compilation examples

2. **`README.md`** (if exists)
   - Add to CLI commands section
   - Note test-only nature

3. **`.env.example`**
   - No changes needed (uses same environment variables)

### Documentation Content

```markdown
## Non-Interactive Bootstrap (Test Only)

For automated testing and CI/CD environments, use the non-interactive bootstrap flag:

```bash
# Debug builds (always available)
cargo run -- bootstrap --non-interactive

# Release builds (requires feature flag)
cargo run --release --features test-utils -- bootstrap --non-interactive
```

This mode:
- Creates only the owner account (no System Admin or Role Admin accounts)
- Uses a fixed, well-known password
- Outputs credentials to stdout
- Sets owner_active=false (requires activation)

**WARNING:** This mode is for testing only. For production setup, use the interactive bootstrap:
```bash
cargo run -- bootstrap
```
```

## Dependencies

No new dependencies required. Uses existing:
- `clap` - CLI argument parsing (already in use)
- `uuid` - UUID generation (already in use)
- `argon2` - Password hashing (already in use)
- `rand` - Secure random generation (already in use)

## Rollout Plan

### Phase 1: Implementation
1. Add `test-utils` feature to `Cargo.toml`
2. Modify `Bootstrap` command to accept `--non-interactive` flag with `#[cfg]` attribute
3. Implement `bootstrap_system_non_interactive()` function
4. Update command routing in `execute_command()` to handle flag

### Phase 2: Testing
1. Write unit tests for fixed credentials constants
2. Write integration tests for full workflow (bootstrap → login)
3. Write compilation tests for conditional compilation

### Phase 3: Documentation
1. Update `.kiro/steering/tech.md` with usage instructions
2. Add inline documentation to new functions
3. Update CLI help text

### Phase 4: Validation
1. Test in debug build
2. Test in release build (verify command absent)
3. Test in release build with feature (verify command present)
4. Test full workflow: bootstrap → activate → login

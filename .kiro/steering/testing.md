# Testing Principles

## Core Testing Philosophy

**Test the contract, not the implementation.** Focus on what the code promises to do, not how it does it.

## What to Test

### ✅ Test These

- **Business logic** - Domain-specific calculations, validations, workflows
- **Public contracts** - Function signatures, return values, error conditions
- **Integration points** - How your code interacts with external systems
- **Edge cases** - Boundary conditions, error scenarios, invalid inputs
- **Configuration requirements** - Required parameters, length constraints, format requirements

### ❌ Don't Test These

- **Library/framework behavior** - Don't test that `rand` generates random numbers or `hmac` computes correct hashes
- **Implementation details** - Internal data structures, private methods, specific algorithms
- **Trivial wrappers** - Thin adapters that just call library functions
- **Language features** - Don't test that Rust's `Option` works correctly
- **External services** - Mock them instead of testing the actual service

## Testing Patterns

### Minimal Test Coverage

Only write tests that provide value:

```rust
// ✅ GOOD - Tests business logic
#[test]
fn test_password_meets_length_requirement() {
    let password = generate_password();
    assert_eq!(password.len(), 20);  // Our requirement
}

// ❌ BAD - Tests library behavior
#[test]
fn test_hmac_produces_different_hashes_for_different_inputs() {
    // This tests the HMAC library, not our code
}

// ❌ BAD - Tests implementation detail
#[test]
fn test_password_contains_valid_characters() {
    // Character set is implementation detail
}
```

### Focus on Contracts

Test what callers depend on:

```rust
// ✅ GOOD - Tests the contract
#[test]
fn test_validate_jwt_returns_claims_for_valid_token() {
    let result = validate_jwt(&valid_token);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().sub, "user123");
}

// ❌ BAD - Tests internal JWT library behavior
#[test]
fn test_jwt_signature_validation_algorithm() {
    // This tests the JWT library's signature validation
}
```

### Test Helpers

Keep test setup minimal:

```rust
// ✅ GOOD - Simple, direct
#[test]
fn test_something() {
    let provider = MyProvider::new();
    // Test the provider...
}

// ❌ BAD - Unnecessary abstraction
fn create_test_provider() -> MyProvider {
    MyProvider::new()  // No value added
}
```

## When NOT to Write Tests

### Thin Wrappers

Don't test code that just calls library functions:

```rust
// This doesn't need tests - it's just a library wrapper
pub fn hmac_sha256(key: &str, data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}
```

### Configuration Structs

Don't test simple data structures:

```rust
// This doesn't need tests - it's just data
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}
```

### Obvious Behavior

Don't test things that would break compilation if wrong:

```rust
// Don't test that this compiles and returns the right type
pub fn get_user_id(&self) -> &str {
    &self.user_id
}
```

## Test Organization

### File Structure

- Keep tests in the same file as the code (`#[cfg(test)] mod tests`)
- Use descriptive test names that explain the scenario
- Group related tests logically

### Test Naming

Use descriptive names that explain the scenario:

```rust
// ✅ GOOD - Explains what's being tested
#[test]
fn test_login_fails_with_invalid_password() { }

#[test]
fn test_jwt_validation_fails_when_token_expired() { }

// ❌ BAD - Generic names
#[test]
fn test_login() { }

#[test]
fn test_jwt() { }
```

## Integration vs Unit Tests

### Unit Tests (Preferred)

- Test individual functions/methods in isolation
- Fast execution
- Easy to debug
- Focus on business logic

### Integration Tests (When Needed)

- Test complete workflows end-to-end
- Verify layer interactions
- Use for complex scenarios that span multiple components
- Keep minimal - prefer unit tests

## Testing Anti-Patterns

### ❌ Testing Everything

Don't aim for 100% coverage. Aim for testing what matters.

### ❌ Testing Implementation Details

Don't test how something works, test what it produces.

### ❌ Brittle Tests

Don't write tests that break when you refactor internal implementation.

### ❌ Testing Libraries

Don't test that third-party libraries work correctly.

### ❌ Redundant Tests

Don't write multiple tests for the same behavior.

## Verification During Development

Instead of comprehensive test suites, verify your work:

- **Compilation**: `cargo build` - ensure code compiles
- **Existing tests**: `cargo test --lib` - ensure you didn't break anything
- **Manual testing**: Use Swagger UI or curl for API endpoints
- **Integration**: Verify the complete flow works end-to-end

## When to Add Comprehensive Tests

Add strategic test coverage AFTER implementation when:

- User explicitly requests it
- Code is complex with many edge cases
- Code handles critical security operations
- Code has been causing bugs in production

## Summary

**Write fewer, better tests.** Focus on business logic and contracts. Don't test libraries or implementation details. Verify your work through compilation and manual testing rather than comprehensive test suites.
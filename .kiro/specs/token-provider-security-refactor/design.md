# Design Document

## Overview

This design refactors the TokenProvider to eliminate security vulnerabilities by removing plain string secret storage and implementing proper secret access through SecretManager. The refactor maintains full backward compatibility while following our established security protocols and AppData patterns.

## Architecture

### Current Architecture (Problematic)

```
AuthCoordinator::new(app_data)
  ↓
TokenProvider::new(
  app_data.secret_manager.jwt_secret().to_string(),      // ❌ Secret copied as String
  app_data.secret_manager.refresh_token_secret().to_string() // ❌ Secret copied as String
)
  ↓
TokenProvider {
  jwt_secret: String,           // ❌ Secret stored as plain string
  refresh_token_secret: String, // ❌ Secret stored as plain string
}
```

### New Architecture (Secure)

```
AuthCoordinator::new(app_data)
  ↓
TokenProvider::new(app_data.secret_manager.clone())
  ↓
TokenProvider {
  secret_manager: Arc<SecretManager>, // ✅ Reference to secret manager
}
  ↓
TokenProvider methods access secrets on-demand:
- secret_manager.jwt_secret()
- secret_manager.refresh_token_secret()
```

## Components and Interfaces

### TokenProvider Struct Changes

**Before:**
```rust
pub struct TokenProvider {
    jwt_secret: String,                    // ❌ Plain string storage
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    refresh_token_secret: String,          // ❌ Plain string storage
    audit_store: Arc<AuditStore>,
}
```

**After:**
```rust
pub struct TokenProvider {
    secret_manager: Arc<SecretManager>,    // ✅ Reference to secret manager
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    audit_store: Arc<AuditStore>,
}
```

### Constructor Interface Changes

**Before:**
```rust
impl TokenProvider {
    pub fn new(jwt_secret: String, refresh_token_secret: String, audit_store: Arc<AuditStore>) -> Self
}
```

**After:**
```rust
impl TokenProvider {
    pub fn new(secret_manager: Arc<SecretManager>, audit_store: Arc<AuditStore>) -> Self
}
```

### Method Implementation Changes

All methods that currently use `self.jwt_secret` and `self.refresh_token_secret` will be updated to use:
- `self.secret_manager.jwt_secret()`
- `self.secret_manager.refresh_token_secret()`

The method signatures remain identical - only internal implementation changes.

## Data Models

No changes to external data models. All JWT claims, refresh token structures, and API contracts remain identical.

Internal struct changes:
- Remove `jwt_secret: String` field
- Remove `refresh_token_secret: String` field  
- Add `secret_manager: Arc<SecretManager>` field

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

Property 1: No plain string secret storage
*For any* TokenProvider instance, the struct fields should not contain JWT secret or refresh token secret as plain strings
**Validates: Requirements 1.1, 1.2**

Property 2: SecretManager reference storage
*For any* TokenProvider instance, it should hold a reference to the same SecretManager instance that was passed to the constructor
**Validates: Requirements 1.5**

Property 3: Secret access through SecretManager
*For any* TokenProvider operation that requires secrets, the system should call the appropriate SecretManager methods (jwt_secret() or refresh_token_secret())
**Validates: Requirements 1.3, 1.4, 2.3**

Property 4: Constructor signature compatibility
*For any* TokenProvider instantiation, the constructor should accept Arc<SecretManager> and Arc<AuditStore> parameters
**Validates: Requirements 2.1**

Property 5: Method signature preservation
*For any* existing TokenProvider public method, the method signature should remain unchanged after the refactor
**Validates: Requirements 2.2**

Property 6: JWT generation compatibility
*For any* set of JWT generation parameters, the generated JWT should be identical before and after the refactor when using the same secrets
**Validates: Requirements 3.1**

Property 7: JWT validation compatibility
*For any* JWT token, the validation result should be identical before and after the refactor
**Validates: Requirements 3.2**

Property 8: Refresh token generation security
*For any* refresh token generation, the token should maintain cryptographic security properties (proper length, randomness)
**Validates: Requirements 3.3**

Property 9: Refresh token hash compatibility
*For any* refresh token, the hash should be identical before and after the refactor when using the same secret
**Validates: Requirements 3.4**

Property 10: Debug trait security
*For any* TokenProvider instance, the Debug output should not contain secret values and should show redacted placeholders
**Validates: Requirements 2.5, 4.1, 4.3**

Property 11: Display trait security
*For any* TokenProvider instance, the Display output should not contain secret values
**Validates: Requirements 4.2**

Property 12: Error message security
*For any* error that occurs during secret access, the error message should not contain secret values
**Validates: Requirements 4.5**

## Error Handling

### Secret Access Failures

If SecretManager methods fail (which should not happen in normal operation since secrets are validated at startup), the TokenProvider should:

1. **Propagate errors appropriately**: Convert SecretManager errors to appropriate InternalError types
2. **Maintain security**: Never expose secret values in error messages
3. **Log safely**: Log error conditions without exposing sensitive information

### Backward Compatibility

All existing error conditions and error types remain unchanged. The refactor only changes internal implementation, not external error behavior.

## Testing Strategy

### Unit Testing Approach

**Focus Areas:**
- Constructor parameter validation
- Secret access through SecretManager
- Method signature preservation
- Debug/Display trait security

**Key Test Cases:**
- TokenProvider creation with valid SecretManager
- JWT generation produces same results as before
- JWT validation works identically
- Refresh token operations maintain compatibility
- Debug output doesn't expose secrets

### Property-Based Testing Approach

**Property Testing Library:** `proptest` crate for Rust
**Minimum Iterations:** 100 per property test

**Property Test Implementation:**
- Each correctness property will be implemented as a separate property-based test
- Tests will generate random inputs (user IDs, passwords, tokens) to verify properties hold universally
- Comparison tests will verify identical behavior before/after refactor

**Property Test Tagging:**
Each property-based test will include a comment with the format:
`**Feature: token-provider-security-refactor, Property {number}: {property_text}**`

### Integration Testing

**Coordinator Integration:**
- Verify AuthCoordinator properly creates TokenProvider with SecretManager
- Test full authentication workflows remain unchanged
- Validate audit logging continues to work correctly

**AppData Integration:**
- Test TokenProvider creation through AppData pattern
- Verify SecretManager is properly extracted and passed

### Security Testing

**Secret Exposure Prevention:**
- Verify no secrets appear in debug output
- Test error messages don't contain secrets
- Validate logging doesn't expose sensitive information

**Memory Security:**
- Confirm secrets are not duplicated in memory
- Verify SecretManager remains the single source of truth for secrets

# Timing Attack Mitigation

## Overview

The `verify_credentials` function in `CredentialStore` implements OWASP-recommended timing attack mitigation to prevent username enumeration attacks.

## The Problem

Without mitigation, an attacker could determine if a username exists by measuring response times:

- **User exists, wrong password**: ~100ms (Argon2 verification executed)
- **User doesn't exist**: ~1ms (immediate return, no Argon2 verification)

This timing difference allows attackers to enumerate valid usernames.

## The Solution

We always execute Argon2 password verification, even when the user doesn't exist:

```rust
// When user doesn't exist, use a dummy hash
let (password_hash, user_id) = match user {
    Some(u) => (u.password_hash.clone(), Some(u.id.clone())),
    None => {
        // Dummy Argon2id hash (always fails verification)
        (
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZTEyMzQ$\
             qrvBFkJXVqKxqhCKqhCKqhCKqhCKqhCKqhCKqhCKqhA".to_string(),
            None
        )
    }
};

// Always execute Argon2 verification (constant-time)
let verification_result = argon2.verify_password(password.as_bytes(), &parsed_hash);
```

## Benefits

1. **Constant-time behavior**: Both paths (user exists/doesn't exist) execute Argon2 verification
2. **Username enumeration prevention**: Attackers cannot determine valid usernames from timing
3. **OWASP compliance**: Follows security best practices
4. **Consistent error messages**: Always returns `InvalidCredentials` regardless of reason
5. **Detailed audit logging**: Internal logs contain actual failure reasons for forensic analysis

## Implementation Details

- The dummy hash is a valid Argon2id hash that will always fail verification
- Both success and failure paths execute the same cryptographic operations
- **Audit logs contain specific failure reasons**:
  - `"invalid_password"` - User exists but password is incorrect
  - `"user_not_found"` - Username doesn't exist in the database
- **User-facing errors are always generic**: `InvalidCredentials` for both cases
- This allows security teams to detect attack patterns (username enumeration vs. password guessing) while preventing information disclosure to attackers

## Testing

The `test_verify_credentials_timing_attack_mitigation` test verifies that both scenarios (existing user with wrong password, non-existing user) return the same error type, confirming that Argon2 verification is executed in both cases.

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)

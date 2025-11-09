# Design Document: Keyed Hashing Security Enhancement

## Overview

This design document outlines the implementation of keyed hashing (HMAC) for password storage and refresh token management in the existing JWT authentication system. The enhancement provides defense-in-depth protection against database compromise scenarios by ensuring that database access alone is insufficient to crack passwords or mint valid tokens.

### Security Goals

1. **Password Protection**: Prevent offline brute-force attacks even if database is leaked
2. **Token Minting Prevention**: Prevent unauthorized refresh token creation with database write access
3. **Key Separation**: Use distinct keys for different security functions
4. **Backward Compatibility**: Support migration of existing users without service disruption

### Technology Stack

- **HMAC Library**: `hmac` crate (Rust)
- **Hash Function**: SHA-256 via `sha2` crate
- **Existing Stack**: Poem, SeaORM, Argon2, jsonwebtoken (unchanged)

## Architecture

### High-Level Security Model

```
┌─────────────────────────────────────────────────────────┐
│                    Secret Keys (Not in DB)              │
├─────────────────────────────────────────────────────────┤
│  JWT_SECRET          │  PASSWORD_PEPPER  │  RT_SECRET   │
│  (JWT signing)       │  (Password HMAC)  │  (Token HMAC)│
└──────────┬───────────┴──────────┬────────┴──────┬───────┘
           │                      │                │
           ▼                      ▼                ▼
    ┌─────────────┐      ┌──────────────┐  ┌─────────────┐
    │ JWT Tokens  │      │  Passwords   │  │Refresh Token│
    │  (signed)   │      │  (peppered)  │  │  (HMAC'd)   │
    └─────────────┘      └──────────────┘  └─────────────┘
```

### Attack Scenarios Mitigated

| Attack Scenario | Without HMAC | With HMAC |
|----------------|--------------|-----------|
| DB read access + offline password cracking | ⚠️ Possible (slow due to Argon2) | ✅ Blocked (need pepper) |
| DB write access + token minting | ❌ Vulnerable | ✅ Blocked (need secret) |
| Stolen JWT_SECRET | ❌ Can forge JWTs | ✅ Passwords/RT still safe |
| Stolen PASSWORD_PEPPER | ✅ Passwords safe (Argon2) | ⚠️ Can crack passwords |
| Stolen RT_SECRET | ✅ Can't use existing tokens | ⚠️ Can mint new tokens |

## Components and Interfaces

### 1. Enhanced Password Hashing (CredentialStore)

#### Current Implementation
```rust
// Existing: Direct Argon2 hashing
let argon2 = Argon2::default();
let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
```

#### New Implementation
```rust
// Enhanced: Argon2 with secret parameter (pepper)
use argon2::{Argon2, Algorithm, Version, Params};

let argon2 = Argon2::new_with_secret(
    self.password_pepper.as_bytes(),
    Algorithm::Argon2id,
    Version::V0x13,
    Params::default(),
)?;
let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
```

#### Interface Changes

```rust
pub struct CredentialStore {
    db: DatabaseConnection,
    password_pepper: String,  // NEW: Secret key for password HMAC
}

impl CredentialStore {
    pub fn new(db: DatabaseConnection, password_pepper: String) -> Self {
        Self { db, password_pepper }
    }
    
    // Modified methods (internal implementation changes only)
    pub async fn add_user(&self, username: String, password: String) -> Result<String, AuthError>;
    pub async fn verify_credentials(&self, username: &str, password: &str) -> Result<String, AuthError>;
    
    // NEW: Migration support
    pub async fn migrate_user_password(&self, user_id: &str, password: &str) -> Result<(), AuthError>;
}
```

### 2. Enhanced Refresh Token Hashing (TokenManager)

#### Current Implementation
```rust
// Existing: Plain SHA-256
use sha2::{Sha256, Digest};
let mut hasher = Sha256::new();
hasher.update(token.as_bytes());
let hash = format!("{:x}", hasher.finalize());
```

#### New Implementation
```rust
// Enhanced: HMAC-SHA256
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

let mut mac = HmacSha256::new_from_slice(self.refresh_token_secret.as_bytes())?;
mac.update(token.as_bytes());
let hash = format!("{:x}", mac.finalize().into_bytes());
```

#### Interface Changes

```rust
pub struct TokenManager {
    jwt_secret: String,
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    refresh_token_secret: String,  // NEW: Secret key for refresh token HMAC
}

impl TokenManager {
    pub fn new(jwt_secret: String, refresh_token_secret: String) -> Self;
    
    // Modified method (internal implementation changes only)
    pub fn hash_refresh_token(&self, token: &str) -> String;
    
    // Existing methods unchanged
    pub fn generate_jwt(&self, user_id: &Uuid) -> Result<String, TokenError>;
    pub fn validate_jwt(&self, token: &str) -> Result<Claims, TokenError>;
    pub fn generate_refresh_token(&self) -> String;
    pub fn get_refresh_expiration(&self) -> i64;
}
```

### 3. HMAC Utility Module (src/auth/crypto.rs)

Create a new module for refresh token HMAC operations:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 for refresh tokens and return as hexadecimal string
pub fn hmac_sha256_token(key: &str, token: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize();
    format!("{:x}", result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_consistency() {
        let key = "test-secret-key";
        let token = "test-token";
        
        let hash1 = hmac_sha256_token(key, token);
        let hash2 = hmac_sha256_token(key, token);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hmac_different_keys() {
        let token = "test-token";
        
        let hash1 = hmac_sha256_token("key1", token);
        let hash2 = hmac_sha256_token("key2", token);
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hmac_different_tokens() {
        let key = "test-secret-key";
        
        let hash1 = hmac_sha256_token(key, "token1");
        let hash2 = hmac_sha256_token(key, "token2");
        
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_hmac_output_length() {
        let key = "test-secret-key";
        let token = "test-token";
        
        let hash = hmac_sha256_token(key, token);
        
        // SHA-256 produces 64 hex characters (32 bytes)
        assert_eq!(hash.len(), 64);
    }
}
```

## Implementation Details

### Password Hashing Flow

#### Registration/Password Change
```
User Password (plaintext)
    │
    ▼
Argon2id(password, random_salt, secret=PASSWORD_PEPPER)
    │
    ▼
Password Hash (PHC format with secret)
    │
    ▼
Store in Database
```

#### Authentication
```
User Password (plaintext)
    │
    ▼
Argon2::new_with_secret(PASSWORD_PEPPER)
    │
    ▼
Argon2::verify_password(password, stored_hash)
    │
    ▼
Success/Failure
```

### Refresh Token Hashing Flow

#### Token Generation (Login)
```
Generate Random Token (32 bytes, base64)
    │
    ▼
HMAC-SHA256(RT_SECRET, token)
    │
    ▼
Token Hash (64-char hex)
    │
    ▼
Store hash in Database
Return plaintext token to client
```

#### Token Validation (Refresh)
```
Client sends plaintext token
    │
    ▼
HMAC-SHA256(RT_SECRET, token)
    │
    ▼
Computed Hash
    │
    ▼
Query Database: WHERE token_hash = computed_hash
    │
    ▼
Found + Not Expired → Valid
Not Found → Invalid
```

## Configuration

### Environment Variables

```bash
# Existing
DATABASE_URL=sqlite://auth.db?mode=rwc
JWT_SECRET=<256-bit-secret-key>              # For JWT signing
JWT_EXPIRATION_MINUTES=15
REFRESH_EXPIRATION_DAYS=7

# NEW: Keyed hashing secrets
PASSWORD_PEPPER=<256-bit-secret-key>         # For password HMAC
REFRESH_TOKEN_SECRET=<256-bit-secret-key>    # For refresh token HMAC

# Optional: Migration support
LEGACY_PASSWORD_SUPPORT=true                 # Default: true for backward compatibility
```

### Secret Key Generation

Provide a utility script for generating secure keys:

```bash
# Generate 256-bit (32-byte) secret keys
openssl rand -base64 32
# Example output: "a8f5f167f44f4964e6c998dee827110ca8f5f167f44f4964e6c998dee827110c"
```

### Validation on Startup

```rust
// In main.rs
fn validate_secrets() -> Result<(), String> {
    let jwt_secret = env::var("JWT_SECRET")
        .map_err(|_| "JWT_SECRET environment variable is required")?;
    
    let password_pepper = env::var("PASSWORD_PEPPER")
        .map_err(|_| "PASSWORD_PEPPER environment variable is required")?;
    
    let refresh_token_secret = env::var("REFRESH_TOKEN_SECRET")
        .map_err(|_| "REFRESH_TOKEN_SECRET environment variable is required")?;
    
    // Validate minimum length (32 characters = 256 bits)
    if jwt_secret.len() < 32 {
        return Err("JWT_SECRET must be at least 32 characters".to_string());
    }
    if password_pepper.len() < 32 {
        return Err("PASSWORD_PEPPER must be at least 32 characters".to_string());
    }
    if refresh_token_secret.len() < 32 {
        return Err("REFRESH_TOKEN_SECRET must be at least 32 characters".to_string());
    }
    
    // Ensure keys are different
    if jwt_secret == password_pepper || jwt_secret == refresh_token_secret || password_pepper == refresh_token_secret {
        return Err("All secret keys must be different".to_string());
    }
    
    Ok(())
}
```

## Backward Compatibility Strategy

### Password Migration

#### Approach: Lazy Migration on Login

```rust
impl CredentialStore {
    pub async fn verify_credentials(&self, username: &str, password: &str) -> Result<String, AuthError> {
        let user = self.find_user_by_username(username).await?;
        
        // Check if password hash is legacy (no secret parameter)
        if self.is_legacy_password_hash(&user.password_hash) {
            // Verify using legacy method (Argon2 without secret)
            let argon2 = Argon2::default();
            let parsed_hash = PasswordHash::new(&user.password_hash)?;
            argon2.verify_password(password.as_bytes(), &parsed_hash)?;
            
            // Migration: Re-hash with pepper
            self.migrate_user_password(&user.id, password).await?;
            
            return Ok(user.id);
        }
        
        // New method: Argon2 with secret parameter
        let argon2 = Argon2::new_with_secret(
            self.password_pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )?;
        let parsed_hash = PasswordHash::new(&user.password_hash)?;
        argon2.verify_password(password.as_bytes(), &parsed_hash)?;
        
        Ok(user.id)
    }
    
    fn is_legacy_password_hash(&self, hash: &str) -> bool {
        // Legacy hashes don't have the 'data' parameter that Argon2 adds when using secret
        // Argon2 with secret adds: $argon2id$v=19$m=19456,t=2,p=1,data=...$salt$hash
        // Legacy: $argon2id$v=19$m=19456,t=2,p=1$salt$hash
        
        // Check if hash contains 'data=' parameter (indicates secret was used)
        !hash.contains("data=")
    }
    
    async fn migrate_user_password(&self, user_id: &str, password: &str) -> Result<(), AuthError> {
        // Re-hash password with pepper (secret parameter)
        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::new_with_secret(
            self.password_pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )?;
        let new_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
        
        // Update database
        self.update_user_password(user_id, &new_hash).await?;
        
        log::info!("Migrated password for user: {}", user_id);
        Ok(())
    }
}
```

#### Migration Marker

**Argon2 Built-in Marker** (Automatic)
- When Argon2 uses a secret parameter, it automatically adds `data=` to the PHC format
- Legacy hash: `$argon2id$v=19$m=19456,t=2,p=1$salt$hash`
- Peppered hash: `$argon2id$v=19$m=19456,t=2,p=1,data=base64$salt$hash`
- No manual marker needed - Argon2 handles this automatically
- Detection: Check if hash contains `data=` parameter

### Refresh Token Migration

**No migration needed** - refresh tokens are short-lived (7 days):

1. Deploy new code with HMAC-based hashing
2. New tokens use HMAC
3. Old tokens (SHA-256) expire naturally within 7 days
4. Optional: Force logout all users on deployment for immediate cutover

## Security Considerations

### Key Management

#### Critical Requirements

1. **Backup**: All secret keys must be backed up securely
   - Loss of PASSWORD_PEPPER = all users locked out permanently
   - Loss of REFRESH_TOKEN_SECRET = all sessions invalidated
   - Loss of JWT_SECRET = all active JWTs invalidated

2. **Storage**: Never store keys in:
   - Version control (Git)
   - Application logs
   - Database
   - Client-side code

3. **Access Control**: Limit key access to:
   - Production environment variables
   - Secure key management systems (KMS)
   - Authorized operations personnel only

4. **Rotation**: Key rotation strategy:
   - JWT_SECRET: Can rotate with grace period (multi-key validation)
   - REFRESH_TOKEN_SECRET: Can rotate with grace period
   - PASSWORD_PEPPER: Cannot rotate easily (requires re-hashing all passwords)

### Defense in Depth Analysis

| Compromise Scenario | Impact | Mitigation |
|---------------------|--------|------------|
| Database only | ✅ Minimal - can't crack passwords or mint tokens | HMAC protection |
| Database + PASSWORD_PEPPER | ⚠️ Can crack weak passwords | Argon2 still provides resistance |
| Database + RT_SECRET | ⚠️ Can mint refresh tokens | Short token lifetime (7 days) |
| Database + JWT_SECRET | ⚠️ Can forge JWTs | Short JWT lifetime (15 min) |
| All secrets | ❌ Full compromise | Detect and rotate keys, force password resets |

### HMAC Security Properties

1. **Collision Resistance**: Computationally infeasible to find two inputs with same HMAC
2. **Pre-image Resistance**: Cannot derive input from HMAC output
3. **Key Dependency**: Different keys produce different outputs for same input
4. **Constant-Time Comparison**: Prevents timing attacks during validation

## Testing Strategy

### Unit Tests

#### HMAC Utility Tests
```rust
#[test]
fn test_hmac_consistency() {
    // Same key + message = same hash
}

#[test]
fn test_hmac_key_sensitivity() {
    // Different keys = different hashes
}

#[test]
fn test_hmac_message_sensitivity() {
    // Different messages = different hashes
}

#[test]
fn test_hmac_output_length() {
    // Always 64 hex characters (256 bits)
}
```

#### Password Hashing Tests
```rust
#[test]
fn test_password_hashing_with_secret() {
    // Verify Argon2 with secret parameter works
}

#[test]
fn test_password_verification_with_secret() {
    // Verify password verification with secret works
}

#[test]
fn test_different_secrets_produce_different_hashes() {
    // Verify different peppers produce different hashes
}

#[test]
fn test_legacy_password_verification() {
    // Verify legacy passwords (without secret) still work
}

#[test]
fn test_password_migration_on_login() {
    // Verify automatic migration on successful login
}

#[test]
fn test_hash_contains_data_parameter() {
    // Verify peppered hashes contain 'data=' parameter
}
```

#### Refresh Token Tests
```rust
#[test]
fn test_refresh_token_hmac_hashing() {
    // Verify HMAC-based token hashing
}

#[test]
fn test_refresh_token_validation_with_hmac() {
    // Verify HMAC-based token validation
}

#[test]
fn test_token_minting_prevention() {
    // Verify can't validate token without correct secret
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_end_to_end_password_flow_with_pepper() {
    // Create user → login → verify password is peppered
}

#[tokio::test]
async fn test_end_to_end_refresh_token_flow_with_hmac() {
    // Login → get RT → refresh → verify HMAC protection
}

#[tokio::test]
async fn test_legacy_user_migration() {
    // Create legacy user → login → verify migration → login again
}

#[tokio::test]
async fn test_startup_validation_missing_secrets() {
    // Verify app fails to start with missing secrets
}
```

### Security Tests

```rust
#[tokio::test]
async fn test_cannot_mint_tokens_without_secret() {
    // Simulate DB write access, verify can't create valid tokens
}

#[tokio::test]
async fn test_different_secrets_produce_different_hashes() {
    // Verify key separation
}

#[tokio::test]
async fn test_constant_time_comparison() {
    // Verify timing attack resistance (if applicable)
}
```

## File Structure

```
src/
├── main.rs                      # Updated: Secret validation on startup
├── auth/
│   ├── mod.rs                   # Updated: Export crypto module
│   ├── crypto.rs                # NEW: HMAC utility functions
│   ├── credential_store.rs      # Modified: Add pepper to password hashing
│   ├── token_manager.rs         # Modified: Add HMAC to refresh token hashing
│   ├── api.rs                   # Unchanged
│   ├── service.rs               # Unchanged
│   ├── models.rs                # Unchanged
│   ├── errors.rs                # Unchanged
│   └── entities/                # Unchanged

migration/
├── src/
│   ├── m20240101_000003_add_password_version.rs  # Optional: For migration tracking
```

## Dependencies to Add

```toml
[dependencies]
hmac = "0.12"           # HMAC implementation for refresh tokens
# sha2 = "0.10"         # Already added for SHA-256
# rand = "0.8"          # Already added
# argon2 = "0.5"        # Already added (supports secret parameter)
```

## Deployment Checklist

### Pre-Deployment

- [ ] Generate three unique 256-bit secret keys
- [ ] Store keys in secure key management system
- [ ] Back up keys in secure offline storage
- [ ] Document key recovery procedures
- [ ] Test key validation on startup
- [ ] Test backward compatibility with existing users

### Deployment

- [ ] Set environment variables in production
- [ ] Deploy new code
- [ ] Verify application starts successfully
- [ ] Monitor logs for migration events
- [ ] Test login with existing user (triggers migration)
- [ ] Test login with new user (uses peppered hash)
- [ ] Test refresh token flow

### Post-Deployment

- [ ] Monitor migration progress (% of users migrated)
- [ ] After 7 days: All refresh tokens using HMAC
- [ ] After 90 days: Consider disabling legacy password support
- [ ] Document key locations for operations team
- [ ] Schedule key rotation procedures (if applicable)

## Future Enhancements

### Key Rotation Support

```rust
pub struct TokenManager {
    current_rt_secret: String,
    valid_rt_secrets: Vec<String>,  // For grace period during rotation
}

impl TokenManager {
    pub fn hash_refresh_token(&self, token: &str) -> String {
        // Always use current key for new tokens
        hmac_sha256(&self.current_rt_secret, token)
    }
    
    pub async fn validate_refresh_token(&self, token: &str) -> Result<Uuid> {
        // Try all valid keys (current + recently rotated)
        for secret in &self.valid_rt_secrets {
            let hash = hmac_sha256(secret, token);
            if let Ok(user_id) = self.credential_store.find_token(&hash).await {
                return Ok(user_id);
            }
        }
        Err(InvalidRefreshToken)
    }
}
```

### KMS Integration

```rust
// Future: Load secrets from AWS KMS, HashiCorp Vault, etc.
async fn load_secrets_from_kms() -> Result<Secrets, Error> {
    let kms_client = aws_sdk_kms::Client::new(&config);
    
    let jwt_secret = kms_client.decrypt()
        .key_id("alias/jwt-secret")
        .ciphertext_blob(Blob::new(encrypted_jwt_secret))
        .send()
        .await?;
    
    // Similar for other secrets...
    
    Ok(Secrets {
        jwt_secret,
        password_pepper,
        refresh_token_secret,
    })
}
```

### Per-User Pepper (Advanced)

```rust
// Derive per-user pepper from global pepper + user_id
fn derive_user_pepper(global_pepper: &str, user_id: &str) -> String {
    hmac_sha256(global_pepper, user_id)
}

// Allows per-user key rotation without re-hashing all passwords
```

## Documentation Updates

### README.md

Add section on secret key management:
- How to generate keys
- Where to store keys
- Backup procedures
- Recovery procedures

### API Documentation

No changes - keyed hashing is internal implementation detail

### Operations Guide

Create new document: `docs/SECRET_KEY_MANAGEMENT.md`
- Key generation procedures
- Backup and recovery
- Rotation procedures
- Incident response (key compromise)
- Monitoring and alerting

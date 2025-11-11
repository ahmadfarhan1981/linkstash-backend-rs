# Design Document: Secret Manager

## Overview

The Secret Manager provides a centralized abstraction layer for accessing application secrets. It currently loads secrets from environment variables but is designed to support future migration to external secret management services (AWS Secrets Manager, Azure Key Vault, etc.) without requiring changes to consuming code.

The design follows the Repository pattern, treating secrets as a data source that can be swapped out. All secret access goes through a single `SecretManager` struct that validates, caches, and provides type-safe access to secrets.

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                       │
│  (main.rs, services/*, stores/*, api/*)                     │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        │ get_jwt_secret()
                        │ get_pepper()
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                      SecretManager                           │
│  - Validates secrets at initialization                       │
│  - Caches secrets in memory                                  │
│  - Provides type-safe access methods                         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        │ load_from_env()
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                   Environment Variables                      │
│  (Currently: std::env::var)                                  │
│  (Future: AWS Secrets Manager, Azure Key Vault, etc.)       │
└─────────────────────────────────────────────────────────────┘
```

### Module Location

Following the project's layer-based architecture, the Secret Manager will be placed in a new module:

- **`src/config/`** - Configuration and secret management
  - `mod.rs` - Public exports
  - `secret_manager.rs` - SecretManager implementation
  - `secret_config.rs` - Secret configuration and validation rules

This separates configuration concerns from business logic (services) and data access (stores).

## Components and Interfaces

### 1. SecretType

Defines where and how to load a secret.

```rust
/// Defines the source type for a secret
#[derive(Debug, Clone)]
pub enum SecretType {
    /// Load from environment variable
    EnvVar { name: String },
    // Future variants:
    // AwsSecretsManager { secret_id: String, region: String },
    // AzureKeyVault { vault_url: String, secret_name: String },
    // File { path: PathBuf },
}
```

### 2. SecretConfig

Defines validation rules and loading configuration for each secret.

```rust
/// Configuration for a single secret
pub struct SecretConfig {
    /// Secret type (where to load from)
    pub secret_type: SecretType,
    /// Whether this secret is required
    pub required: bool,
    /// Minimum length (None = no minimum)
    pub min_length: Option<usize>,
}

impl SecretConfig {
    pub fn new(secret_type: SecretType) -> Self {
        Self {
            secret_type,
            required: true,
            min_length: None,
        }
    }
    
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
    
    pub fn min_length(mut self, length: usize) -> Self {
        self.min_length = Some(length);
        self
    }
}
```

### 3. SecretManager

Main struct that manages secret loading, validation, and access.

```rust
/// Centralized manager for application secrets
pub struct SecretManager {
    jwt_secret: String,
    pepper: String,
}

impl SecretManager {
    /// Initialize the SecretManager by loading and validating all secrets
    /// 
    /// # Errors
    /// Returns `SecretError` if any required secret is missing or fails validation
    pub fn init() -> Result<Self, SecretError> {
        // Load secrets with validation rules
        let jwt_secret = Self::load_secret(&Self::jwt_config())?;
        let pepper = Self::load_secret(&Self::pepper_config())?;
        
        Ok(Self {
            jwt_secret,
            pepper,
        })
    }
    
    /// Get the JWT secret
    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }
    
    /// Get the pepper for password hashing
    pub fn pepper(&self) -> &str {
        &self.pepper
    }
    
    // Private helper methods
    
    fn jwt_config() -> SecretConfig {
        SecretConfig::new(SecretType::EnvVar {
            name: "JWT_SECRET".to_string(),
        })
        .required(true)
        .min_length(32)
    }
    
    fn pepper_config() -> SecretConfig {
        SecretConfig::new(SecretType::EnvVar {
            name: "PEPPER".to_string(),
        })
        .required(true)
        .min_length(16)
    }
    
    fn load_secret(config: &SecretConfig) -> Result<String, SecretError> {
        // Match on secret type to determine loading strategy
        let value = match &config.secret_type {
            SecretType::EnvVar { name } => {
                match std::env::var(name) {
                    Ok(v) => v,
                    Err(_) if !config.required => return Ok(String::new()),
                    Err(_) => return Err(SecretError::missing(name)),
                }
            }
            // Future implementations:
            // SecretType::AwsSecretsManager { secret_id, region } => {
            //     load_from_aws(secret_id, region).await?
            // }
        };
        
        // Validate minimum length
        if let Some(min_len) = config.min_length {
            if value.len() < min_len {
                let name = match &config.secret_type {
                    SecretType::EnvVar { name } => name,
                };
                return Err(SecretError::invalid_length(
                    name,
                    min_len,
                    value.len(),
                ));
            }
        }
        
        Ok(value)
    }
}
```

### 4. SecretError

Custom error type for secret-related failures.

```rust
use std::fmt;

#[derive(Debug)]
pub enum SecretError {
    Missing { secret_name: String },
    InvalidLength { secret_name: String, expected: usize, actual: usize },
}

impl SecretError {
    pub fn missing(secret_name: &str) -> Self {
        Self::Missing {
            secret_name: secret_name.to_string(),
        }
    }
    
    pub fn invalid_length(secret_name: &str, expected: usize, actual: usize) -> Self {
        Self::InvalidLength {
            secret_name: secret_name.to_string(),
            expected,
            actual,
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { secret_name } => {
                write!(f, "Required secret '{}' is missing", secret_name)
            }
            Self::InvalidLength { secret_name, expected, actual } => {
                write!(
                    f,
                    "Secret '{}' must be at least {} characters, got {}",
                    secret_name, expected, actual
                )
            }
        }
    }
}

impl std::error::Error for SecretError {}
```

### 5. Debug and Display Implementations

For security and debugging purposes:

```rust
impl fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretManager")
            .field("jwt_secret", &"<redacted>")
            .field("pepper", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretManager {{ secrets_loaded: 2 }}")
    }
}
```

## Data Models

### Secret Storage

Secrets are stored as `String` values in the `SecretManager` struct. This design choice supports:

1. **Environment variables** - Native string format
2. **Cloud secret managers** - Return strings by default
3. **Easy conversion** - Can call `.as_bytes()` when needed for cryptographic operations
4. **Type safety** - Rust's ownership system prevents accidental exposure

### Memory Management

- Secrets are loaded once at application startup
- Stored in an `Arc<SecretManager>` for shared access across async tasks
- Dropped when the application terminates
- No explicit zeroing (Rust doesn't guarantee memory zeroing on drop)

## Integration Points

### 1. Application Initialization (main.rs)

```rust
// Current code:
let jwt_secret = std::env::var("JWT_SECRET")
    .expect("JWT_SECRET environment variable must be set");
let token_manager = Arc::new(TokenService::new(jwt_secret));

// After migration:
let secret_manager = Arc::new(
    SecretManager::init()
        .expect("Failed to initialize secrets")
);
let token_manager = Arc::new(TokenService::new(
    secret_manager.jwt_secret().to_string()
));
```

### 2. TokenService

```rust
// Current: Stores jwt_secret as String
pub struct TokenService {
    jwt_secret: String,
    // ...
}

// After migration: Can accept &str and convert to bytes when needed
impl TokenService {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret, /* ... */ }
    }
    
    pub fn generate_jwt(&self, user_id: &Uuid) -> Result<String, AuthError> {
        // Uses self.jwt_secret.as_bytes() for encoding
        // ...
    }
}
```

### 3. Future: Password Hashing with Pepper

When pepper is implemented:

```rust
// In credential_store.rs or a new password_service.rs
pub fn hash_password_with_pepper(
    password: &str,
    pepper: &str,
) -> Result<String, AuthError> {
    let peppered = format!("{}{}", password, pepper);
    // Hash with argon2...
}
```

## Error Handling

### Initialization Errors

The `SecretManager::init()` method returns `Result<SecretManager, SecretError>`:

- **Missing required secret** - Application panics at startup (fail-fast)
- **Invalid length** - Application panics at startup with clear error message
- **Optional secret missing** - Continues with empty string (future use case)

### Runtime Errors

Once initialized, the SecretManager never fails:
- All secrets are validated at startup
- Methods return `&str`, not `Result`
- No runtime validation needed

### Error Messages

Clear, actionable error messages:
```
Required secret 'JWT_SECRET' is missing from environment
Secret 'JWT_SECRET' must be at least 32 characters, got 16
Secret 'PEPPER' must be at least 16 characters, got 8
```

## Testing Strategy

### Unit Tests

1. **Secret loading**
   - Test loading valid secrets
   - Test missing required secrets
   - Test missing optional secrets
   - Test secrets below minimum length

2. **Validation**
   - Test minimum length validation
   - Test required vs optional secrets
   - Test error messages

3. **Access methods**
   - Test `jwt_secret()` returns correct value
   - Test `pepper()` returns correct value

4. **Debug/Display**
   - Test Debug doesn't expose secrets
   - Test Display shows metadata only

### Integration Tests

1. **Application startup**
   - Test app starts with valid secrets
   - Test app fails with missing secrets
   - Test app fails with invalid secrets

2. **Service integration**
   - Test TokenService works with SecretManager
   - Test JWT generation uses correct secret
   - Test JWT validation uses correct secret

### Test Environment Setup

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    fn setup_test_env() {
        std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
        std::env::set_var("PEPPER", "test-pepper-16ch");
    }
    
    fn cleanup_test_env() {
        std::env::remove_var("JWT_SECRET");
        std::env::remove_var("PEPPER");
    }
}
```

## Future Extensibility

### Adding New Secrets

To add a new secret (e.g., API key):

1. Add field to `SecretManager` struct
2. Add config method (e.g., `api_key_config()`)
3. Load in `init()` method
4. Add getter method (e.g., `api_key()`)
5. Update `.env.example` with new variable

### Adding New Secret Types

To add a new secret type (e.g., AWS Secrets Manager):

1. Add new variant to `SecretType` enum with required fields:
   ```rust
   SecretType::AwsSecretsManager { 
       secret_id: String, 
       region: String 
   }
   ```

2. Add match arm in `load_secret()` method:
   ```rust
   SecretType::AwsSecretsManager { secret_id, region } => {
       load_from_aws(secret_id, region).await?
   }
   ```

3. Implement the loading function (e.g., `load_from_aws()`)

4. Update error handling to extract secret name from new type

5. Keep same public API - no changes to consuming code

**Note:** Adding async secret types (like AWS SDK) will require making `load_secret()` and `init()` async, which impacts application startup.

## Security Considerations

1. **No logging** - Debug/Display implementations never expose secret values
2. **Fail-fast** - Invalid secrets cause startup failure, not runtime errors
3. **Immutable** - No methods to modify secrets after initialization
4. **Type safety** - Rust's ownership prevents accidental copying
5. **Clear validation** - Minimum length requirements enforced at startup
6. **Future-proof** - Design supports migration to secure secret stores

## Performance Considerations

1. **One-time load** - Secrets loaded once at startup, no repeated I/O
2. **In-memory cache** - O(1) access time for all secret retrievals
3. **Zero-copy** - Returns `&str` references, no allocations
4. **Shared ownership** - `Arc<SecretManager>` allows cheap cloning across threads
5. **No locks** - Immutable after initialization, no synchronization overhead

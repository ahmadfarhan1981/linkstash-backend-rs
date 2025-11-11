# Adding New Secrets to SecretManager

This guide explains how to add new secrets to the SecretManager system. The SecretManager provides centralized, validated access to application secrets with support for multiple secret sources.

## Table of Contents

1. [Quick Start: Adding a New Secret](#quick-start-adding-a-new-secret)
2. [Understanding SecretConfig](#understanding-secretconfig)
3. [Validation Rules](#validation-rules)
4. [Updating Environment Files](#updating-environment-files)
5. [Adding New Secret Types](#adding-new-secret-types)
6. [Security Best Practices](#security-best-practices)

---

## Quick Start: Adding a New Secret

Let's walk through adding a new secret called `API_KEY` to the SecretManager.

### Step 1: Add the Field to SecretManager

Open `src/config/secret_manager.rs` and add a new field to the `SecretManager` struct:

```rust
pub struct SecretManager {
    jwt_secret: String,
    pepper: String,
    api_key: String,  // Add your new secret field
}
```

### Step 2: Create a Configuration Method

Add a private configuration method that defines how to load and validate the secret:

```rust
impl SecretManager {
    // ... existing methods ...

    /// Configuration for API key
    fn api_key_config() -> SecretConfig {
        SecretConfig::new(SecretType::EnvVar {
            name: "API_KEY".to_string(),
        })
        .required(true)      // Make it required
        .min_length(20)      // Minimum 20 characters
    }
}
```

### Step 3: Load the Secret in `init()`

Update the `init()` method to load your new secret:

```rust
pub fn init() -> Result<Self, SecretError> {
    let jwt_secret = Self::load_secret(&Self::jwt_config())?;
    let pepper = Self::load_secret(&Self::pepper_config())?;
    let api_key = Self::load_secret(&Self::api_key_config())?;  // Add this line
    
    Ok(Self {
        jwt_secret,
        pepper,
        api_key,  // Add this field
    })
}
```

### Step 4: Add a Getter Method

Add a public getter method to access the secret:

```rust
impl SecretManager {
    // ... existing methods ...

    /// Get the API key
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}
```

### Step 5: Update Debug and Display Implementations

Update the `Debug` implementation to redact the new secret:

```rust
impl fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretManager")
            .field("jwt_secret", &"<redacted>")
            .field("pepper", &"<redacted>")
            .field("api_key", &"<redacted>")  // Add this line
            .finish()
    }
}
```

Update the `Display` implementation to reflect the new secret count:

```rust
impl fmt::Display for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretManager {{ secrets_loaded: 3 }}")  // Update count
    }
}
```

### Step 6: Update Environment Files

Add the new secret to `.env.example`:

```bash
# API Configuration
# External API key (REQUIRED - minimum 20 characters)
API_KEY=your-api-key-at-least-20-chars-long
```

Add the actual value to your local `.env` file (never commit this):

```bash
API_KEY=actual-production-api-key-value-here
```

### Step 7: Use the Secret

Now you can access the secret anywhere you have a reference to `SecretManager`:

```rust
let secret_manager = Arc::new(SecretManager::init().expect("Failed to load secrets"));
let api_key = secret_manager.api_key();
// Use api_key for API calls...
```

---

## Understanding SecretConfig

`SecretConfig` defines how a secret should be loaded and validated. It consists of three components:

### 1. SecretType

Defines where the secret comes from:

```rust
pub enum SecretType {
    /// Load from environment variable
    EnvVar { name: String },
    // Future: AwsSecretsManager, AzureKeyVault, File, etc.
}
```

**Example:**
```rust
SecretType::EnvVar { name: "DATABASE_PASSWORD".to_string() }
```

### 2. Required Flag

Determines if the secret must be present:

```rust
SecretConfig::new(secret_type)
    .required(true)   // Application fails if missing
    .required(false)  // Returns empty string if missing
```

### 3. Minimum Length

Enforces a minimum character length:

```rust
SecretConfig::new(secret_type)
    .min_length(32)  // Must be at least 32 characters
```

---

## Validation Rules

The SecretManager validates secrets at application startup. If validation fails, the application will not start.

### Common Validation Patterns

#### Strong Cryptographic Keys
```rust
fn encryption_key_config() -> SecretConfig {
    SecretConfig::new(SecretType::EnvVar {
        name: "ENCRYPTION_KEY".to_string(),
    })
    .required(true)
    .min_length(32)  // 256-bit key minimum
}
```

#### API Keys
```rust
fn api_key_config() -> SecretConfig {
    SecretConfig::new(SecretType::EnvVar {
        name: "THIRD_PARTY_API_KEY".to_string(),
    })
    .required(true)
    .min_length(20)  // Typical API key length
}
```

#### Optional Secrets
```rust
fn optional_webhook_secret_config() -> SecretConfig {
    SecretConfig::new(SecretType::EnvVar {
        name: "WEBHOOK_SECRET".to_string(),
    })
    .required(false)  // Application works without it
    .min_length(16)   // But if provided, must be at least 16 chars
}
```

#### No Length Requirement
```rust
fn username_config() -> SecretConfig {
    SecretConfig::new(SecretType::EnvVar {
        name: "DB_USERNAME".to_string(),
    })
    .required(true)
    // No min_length() call - any length accepted
}
```

### Error Messages

When validation fails, you'll see clear error messages:

```
Required secret 'API_KEY' is missing
Secret 'JWT_SECRET' must be at least 32 characters, got 16
```

---

## Updating Environment Files

### .env.example (Committed to Git)

This file serves as a template for developers. Always include:

1. **Descriptive comments** explaining what the secret is for
2. **Requirement status** (REQUIRED or OPTIONAL)
3. **Minimum length** if applicable
4. **Example values** that meet validation rules

**Example:**
```bash
# JWT Configuration
# Secret key for signing JWT tokens (REQUIRED - minimum 32 characters)
JWT_SECRET=your-secret-key-min-32-chars-long-change-this-in-production

# External Services
# API key for payment processor (REQUIRED - minimum 20 characters)
PAYMENT_API_KEY=example-api-key-at-least-20-characters

# Optional Features
# Webhook secret for GitHub integration (OPTIONAL - minimum 16 characters if provided)
# GITHUB_WEBHOOK_SECRET=optional-webhook-secret-16ch
```

### .env (Local Development - Never Commit)

This file contains actual secret values for local development:

```bash
JWT_SECRET=dev-jwt-secret-key-32-characters-long-for-local-testing
PAYMENT_API_KEY=sk_test_actual_stripe_key_here
GITHUB_WEBHOOK_SECRET=actual-webhook-secret-value
```

**Important:** The `.env` file should be in `.gitignore` to prevent accidental commits.

---

## Adding New Secret Types

The SecretManager is designed to support multiple secret sources beyond environment variables. Here's how to add a new `SecretType`.

### High-Level Steps

#### 1. Add New Variant to SecretType Enum

Open `src/config/secret_config.rs` and add your new variant:

```rust
#[derive(Debug, Clone)]
pub enum SecretType {
    EnvVar { name: String },
    
    // Add new variant with required fields
    AwsSecretsManager { 
        secret_id: String, 
        region: String 
    },
}
```

#### 2. Update load_secret() Method

In `src/config/secret_manager.rs`, add a match arm for your new type:

```rust
fn load_secret(config: &SecretConfig) -> Result<String, SecretError> {
    let value = match &config.secret_type {
        SecretType::EnvVar { name } => {
            match std::env::var(name) {
                Ok(v) => v,
                Err(_) if !config.required => return Ok(String::new()),
                Err(_) => return Err(SecretError::missing(name)),
            }
        }
        
        // Add new match arm
        SecretType::AwsSecretsManager { secret_id, region } => {
            load_from_aws(secret_id, region)?
        }
    };
    
    // Validation continues as before...
}
```

#### 3. Implement Loading Function

Create a helper function to load from the new source:

```rust
fn load_from_aws(secret_id: &str, region: &str) -> Result<String, SecretError> {
    // Implementation using AWS SDK
    // This would typically be async and require tokio
    todo!("Implement AWS Secrets Manager integration")
}
```

#### 4. Update Error Handling

Ensure error messages can extract the secret name from your new type:

```rust
// In load_secret(), when creating errors:
let name = match &config.secret_type {
    SecretType::EnvVar { name } => name,
    SecretType::AwsSecretsManager { secret_id, .. } => secret_id,
};
```

#### 5. Update Dependencies

Add required dependencies to `Cargo.toml`:

```toml
[dependencies]
aws-sdk-secretsmanager = "1.0"  # Example
```

### Example: Using AWS Secrets Manager

```rust
fn database_password_config() -> SecretConfig {
    SecretConfig::new(SecretType::AwsSecretsManager {
        secret_id: "prod/database/password".to_string(),
        region: "us-east-1".to_string(),
    })
    .required(true)
    .min_length(16)
}
```

### Considerations for Async Secret Types

If your new secret type requires async operations (like AWS SDK calls):

1. Make `load_secret()` async: `async fn load_secret(...)`
2. Make `init()` async: `pub async fn init()`
3. Update `main.rs` to await initialization: `SecretManager::init().await`
4. Consider caching strategies for remote secrets

---

## Security Best Practices

### 1. Never Log or Print Secrets

The `Debug` and `Display` implementations are designed to prevent accidental exposure:

```rust
// ✅ Safe - secrets are redacted
println!("{:?}", secret_manager);  // Shows "<redacted>"

// ❌ Dangerous - exposes secret
println!("{}", secret_manager.jwt_secret());  // Shows actual value
```

### 2. Minimum Length Requirements

Set appropriate minimum lengths based on secret type:

- **Cryptographic keys (JWT, encryption):** 32+ characters (256 bits)
- **Passwords/peppers:** 16+ characters
- **API keys:** 20+ characters (varies by provider)
- **Tokens:** 32+ characters

### 3. Required vs Optional

Mark secrets as required unless there's a clear fallback:

```rust
// ✅ Good - critical for security
.required(true)

// ⚠️ Use carefully - only for truly optional features
.required(false)
```

### 4. Fail Fast

The SecretManager validates all secrets at startup. This ensures:
- Configuration errors are caught immediately
- Application doesn't start in an insecure state
- Clear error messages guide developers

### 5. Environment File Management

- **Never commit `.env`** - Add to `.gitignore`
- **Always update `.env.example`** - Helps other developers
- **Document requirements** - Include comments about minimum lengths
- **Use different secrets per environment** - Dev, staging, production

### 6. Secret Rotation

When rotating secrets:

1. Update the value in your secret source (environment variable, AWS, etc.)
2. Restart the application to reload secrets
3. The SecretManager loads secrets once at startup - no runtime updates

---

## Complete Example: Adding Database Password

Here's a complete example of adding a database password secret:

### 1. Update SecretManager struct
```rust
pub struct SecretManager {
    jwt_secret: String,
    pepper: String,
    db_password: String,
}
```

### 2. Add configuration method
```rust
fn db_password_config() -> SecretConfig {
    SecretConfig::new(SecretType::EnvVar {
        name: "DATABASE_PASSWORD".to_string(),
    })
    .required(true)
    .min_length(16)
}
```

### 3. Load in init()
```rust
pub fn init() -> Result<Self, SecretError> {
    let jwt_secret = Self::load_secret(&Self::jwt_config())?;
    let pepper = Self::load_secret(&Self::pepper_config())?;
    let db_password = Self::load_secret(&Self::db_password_config())?;
    
    Ok(Self {
        jwt_secret,
        pepper,
        db_password,
    })
}
```

### 4. Add getter
```rust
pub fn db_password(&self) -> &str {
    &self.db_password
}
```

### 5. Update Debug
```rust
impl fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretManager")
            .field("jwt_secret", &"<redacted>")
            .field("pepper", &"<redacted>")
            .field("db_password", &"<redacted>")
            .finish()
    }
}
```

### 6. Update Display
```rust
impl fmt::Display for SecretManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretManager {{ secrets_loaded: 3 }}")
    }
}
```

### 7. Update .env.example
```bash
# Database Configuration
# Database password (REQUIRED - minimum 16 characters)
DATABASE_PASSWORD=secure-db-password-at-least-16-chars
```

### 8. Use in application
```rust
let secret_manager = Arc::new(SecretManager::init()?);
let db_url = format!(
    "postgresql://user:{}@localhost/mydb",
    secret_manager.db_password()
);
```

---

## Troubleshooting

### "Required secret 'X' is missing"

**Solution:** Add the secret to your `.env` file or set it as an environment variable.

### "Secret 'X' must be at least Y characters, got Z"

**Solution:** Ensure your secret value meets the minimum length requirement.

### Secrets not loading after changes

**Solution:** Restart the application. Secrets are loaded once at startup.

### Tests failing with secret errors

**Solution:** Tests should use `std::env::set_var()` to set test secrets:

```rust
#[test]
fn test_with_secrets() {
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-32-characters-long");
        std::env::set_var("PEPPER", "test-pepper-16ch");
    }
    
    let manager = SecretManager::init().unwrap();
    // ... test code ...
}
```

---

## Summary

Adding a new secret requires:

1. ✅ Add field to `SecretManager` struct
2. ✅ Create configuration method with validation rules
3. ✅ Load secret in `init()` method
4. ✅ Add public getter method
5. ✅ Update `Debug` implementation (redact secret)
6. ✅ Update `Display` implementation (update count)
7. ✅ Add to `.env.example` with documentation
8. ✅ Add actual value to `.env` (local development)

The SecretManager ensures all secrets are validated at startup, providing a secure and maintainable approach to secret management.

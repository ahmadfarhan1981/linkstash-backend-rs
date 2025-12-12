# Design Document

## Overview

The centralized settings management system introduces a `SettingsManager` that mirrors the existing `SecretManager` architecture while handling non-secret configuration values. The design maintains clear separation between secrets and settings, provides type-safe access patterns, and enables future migration from environment variables to database storage through a flexible `ConfigSource` abstraction.

## Architecture

The system follows the same architectural patterns as the existing `SecretManager`:

```
┌─────────────────┐    ┌─────────────────┐
│  SecretManager  │    │ SettingsManager │
│   (secrets)     │    │   (settings)    │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────┬───────────────┘
                 │
         ┌───────▼───────┐
         │  ConfigSource │
         │  Abstraction  │
         └───────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───▼───┐   ┌────▼────┐   ┌───▼────┐
│EnvVar │   │Database │   │ File   │
│Source │   │ Source  │   │ Source │
└───────┘   └─────────┘   └────────┘
```

Both managers share the same configuration loading patterns but handle their values differently:
- **SecretManager**: Redacts values, never logs sensitive data
- **SettingsManager**: Normal logging, can display values for debugging

## Components and Interfaces

### ConfigSource Enum

Shared between both managers to define configuration sources:

```rust
#[derive(Debug, Clone)]
pub enum ConfigSource {
    /// Load from environment variable
    EnvVar { name: String },
    /// Load from database key-value table
    Database { key: String },
    // Future variants:
    // File { path: PathBuf },
}
```

### ConfigSpec Struct

Shared configuration specification pattern with fallback chain support:

```rust
pub struct ConfigSpec {
    /// Environment variable override (highest priority)
    pub env_override: Option<String>,
    /// Database key (fallback from env var)
    pub database_key: Option<String>,
    /// Default value (lowest priority)
    pub default_value: Option<String>,
    /// Whether this configuration is required (no default allowed)
    pub required: bool,
    /// Minimum length validation (for strings)
    pub min_length: Option<usize>,
    /// Maximum length validation (for strings)
    pub max_length: Option<usize>,
    /// Custom validation function
    pub validator: Option<fn(&str) -> Result<(), String>>,
}

impl ConfigSpec {
    pub fn new() -> Self;
    pub fn env_override(mut self, name: &str) -> Self;
    pub fn database(mut self, key: &str) -> Self;
    pub fn default_value(mut self, value: &str) -> Self;
    pub fn required(mut self, required: bool) -> Self;
    pub fn min_length(mut self, length: usize) -> Self;
    pub fn validator(mut self, f: fn(&str) -> Result<(), String>) -> Self;
}
```

### SettingsManager

The main settings management component with three distinct layers:

```rust
pub struct SettingsManager {
    pub bootstrap_settings: BootstrapSettings,
    pub secrets: Option<SecretManager>,
    pub application_settings: Option<ApplicationSettings>,
}

impl SettingsManager {
    // Full initialization (for server startup)
    pub async fn init_full() -> Result<Self, SettingsError>;
    
    // Bootstrap only (for CLI operations)
    pub fn init_bootstrap_only() -> Result<Self, SettingsError>;
    
    // Lazy initialization methods
    pub async fn ensure_secrets(&mut self) -> Result<&SecretManager, SettingsError>;
    pub async fn ensure_application_settings(&mut self) -> Result<&ApplicationSettings, SettingsError>;
    
    // Convenience methods that delegate to appropriate layer
    pub fn server_host(&self) -> &str;
    pub fn server_port(&self) -> u16;
    pub fn server_address(&self) -> String;
    
    // These require the respective components to be initialized
    pub fn jwt_secret(&self) -> Result<&str, SettingsError>;
    pub fn jwt_expiration(&self) -> Result<Duration, SettingsError>;
    pub fn refresh_token_expiration(&self) -> Result<Duration, SettingsError>;
}
```

### BootstrapSettings

Connectivity and infrastructure configuration (always from environment variables):

```rust
pub struct BootstrapSettings {
    // Database connectivity
    database_url: String,
    
    // External service connectivity (future)
    vault_addr: Option<String>,
    redis_url: Option<String>,
    
    // Basic server binding
    server_host: String,
    server_port: u16,
}

impl BootstrapSettings {
    pub fn from_env() -> Result<Self, BootstrapError>;
    
    // Getters
    pub fn database_url(&self) -> &str;
    pub fn server_host(&self) -> &str;
    pub fn server_port(&self) -> u16;
    pub fn vault_addr(&self) -> Option<&str>;
}
```

### ApplicationSettings

Business logic configuration (environment variable override → database → defaults):

```rust
pub struct ApplicationSettings {
    // Authentication timing
    jwt_expiration_minutes: u32,
    refresh_token_expiration_days: u32,
    
    // Feature flags (future)
    rate_limiting_enabled: bool,
    audit_retention_days: u32,
}

impl ApplicationSettings {
    pub async fn init(bootstrap: &BootstrapSettings) -> Result<Self, SettingsError>;
    
    // Getters
    pub fn jwt_expiration(&self) -> Duration;
    pub fn refresh_token_expiration(&self) -> Duration;
    pub fn rate_limiting_enabled(&self) -> bool;
    pub fn audit_retention_days(&self) -> u32;
    
    // Configuration specifications
    fn jwt_expiration_config() -> ConfigSpec;
    fn refresh_token_expiration_config() -> ConfigSpec;
    fn rate_limiting_enabled_config() -> ConfigSpec;
    fn audit_retention_days_config() -> ConfigSpec;
    
    // Internal loading methods
    async fn load_setting(spec: &ConfigSpec, db: &Database) -> Result<String, SettingsError>;
    fn parse_duration_minutes(value: &str) -> Result<u32, SettingsError>;
    fn parse_duration_days(value: &str) -> Result<u32, SettingsError>;
    fn parse_bool(value: &str) -> Result<bool, SettingsError>;
}

### Error Types

Separate error types for each configuration layer:

```rust
#[derive(Debug)]
pub enum BootstrapError {
    MissingDatabaseUrl,
    InvalidDatabaseUrl(String),
    MissingRequiredSetting { setting_name: String },
    InvalidFormat { setting_name: String, expected: String, actual: String },
}

#[derive(Debug)]
pub enum SettingsError {
    Bootstrap(BootstrapError),
    Secret(SecretError),
    Application(ApplicationError),
}

#[derive(Debug)]
pub enum ApplicationError {
    DatabaseConnection(String),
    InvalidSetting { setting_name: String, reason: String },
    ParseError { setting_name: String, error: String },
}
```

## Data Models

### Configuration Values by Layer

**Bootstrap Settings (Always Environment Variables):**
- `DATABASE_URL` (String, required)
- `HOST` (String, default: "0.0.0.0")
- `PORT` (u16, default: 3000)
- `VAULT_ADDR` (String, optional, future)
- `REDIS_URL` (String, optional, future)

**Application Settings (Env Override → Database → Default):**
- `JWT_EXPIRATION_MINUTES` (u32, default: 15)
- `REFRESH_TOKEN_EXPIRATION_DAYS` (u32, default: 7)
- `RATE_LIMITING_ENABLED` (bool, default: true, future)
- `AUDIT_RETENTION_DAYS` (u32, default: 90, future)

**Secrets (Always SecretManager):**
- Handled by existing SecretManager (JWT_SECRET, etc.)

### Database Schema

**System Settings Table:**
```sql
CREATE TABLE system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    category TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Example data
INSERT INTO system_settings (key, value, description, category) VALUES
  ('jwt_expiration_minutes', '15', 'JWT token expiration in minutes', 'auth'),
  ('refresh_token_expiration_days', '7', 'Refresh token expiration in days', 'auth'),
  ('rate_limiting_enabled', 'true', 'Enable rate limiting', 'security'),
  ('audit_retention_days', '90', 'Audit log retention period in days', 'audit');
```

### Configuration Loading Priority

For application settings, the loading priority is:

1. **Environment Variable Override** (highest priority)
   - `JWT_EXPIRATION_MINUTES=30` overrides database value
   
2. **Database Value** (middle priority)
   - `SELECT value FROM system_settings WHERE key = 'jwt_expiration_minutes'`
   
3. **Default Value** (lowest priority)
   - Hardcoded in ConfigSpec: `default_value("15")`

### Type Parsing

The system will support parsing from string environment variables to typed values:

```rust
// String parsing utilities
fn parse_duration_minutes(value: &str) -> Result<Duration, String>;
fn parse_duration_days(value: &str) -> Result<Duration, String>;
fn parse_port(value: &str) -> Result<u16, String>;
fn parse_host(value: &str) -> Result<String, String>;
```

## Error Handling

The settings system follows the same error handling patterns as `SecretManager`:

1. **Fail Fast**: All configuration errors are detected at startup
2. **Clear Messages**: Error messages include setting name, expected format, and actual value
3. **Typed Errors**: Different error types for missing vs invalid vs parse errors
4. **Logging**: Configuration loading is logged for troubleshooting

Error scenarios:
- Missing required environment variable
- Invalid format (e.g., non-numeric port)
- Out of range values (e.g., port > 65535)
- Invalid host format

## Testing Strategy

The testing approach mirrors `SecretManager` with environment variable isolation:

### Unit Tests
- Test successful initialization with valid settings
- Test error cases for missing required settings
- Test error cases for invalid formats
- Test type parsing for all supported types
- Test default value handling
- Test getter methods return correct values
- Test Debug/Display traits show values (not redacted)

### Property-Based Tests
- Generate random valid configuration values and verify parsing
- Generate random invalid values and verify appropriate errors
- Test that all valid port numbers parse correctly
- Test that all valid duration formats parse correctly

The testing framework will use the same `EnvGuard` pattern to ensure test isolation and cleanup.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

After analyzing the acceptance criteria, several properties emerge that can be validated through property-based testing. Some criteria were identified as redundant or architectural concerns that don't require separate properties.

**Property Reflection:**
- Properties 1.1 and 2.1 are redundant (both about typed getters) - combined into Property 1
- Properties 1.3 and 2.4 overlap significantly (interface abstraction) - combined into Property 1  
- Properties 6.2 and 2.5 both address error message quality - combined into Property 6
- Several criteria about architecture and code organization don't require separate properties

**Property 1: Typed getter interface consistency**
*For any* SettingsManager instance, all getter methods should return strongly typed values from the appropriate layer (bootstrap, secrets, or application) without requiring caller-side type conversion
**Validates: Requirements 1.1, 1.3, 2.1, 2.4**

**Property 2: Layer-specific initialization validation**  
*For any* configuration layer (bootstrap, secrets, application), when required settings are invalid or missing, initialization should fail with layer-specific errors, and when all required settings are valid, initialization should succeed
**Validates: Requirements 1.4, 1.5**

**Property 3: Type parsing correctness**
*For any* valid string representation of a supported type (string, integer, duration, boolean), the SettingsManager should parse it correctly to the expected type during initialization
**Validates: Requirements 2.2, 2.3**

**Property 4: Configuration source priority**
*For any* application setting, when both environment variable and database value are present, the environment variable should take priority, and when only database value is present, it should be used, and when neither is present, the default value should be used
**Validates: Requirements 3.2, 3.3**

**Property 5: Validation rule consistency**
*For any* ConfigSpec with validation rules (required flags, length limits, custom validators), the SettingsManager should apply the same validation patterns as SecretManager
**Validates: Requirements 5.3, 5.4**

**Property 6: Error message informativeness**
*For any* configuration loading failure, the SettingsManager should provide error messages containing the setting name, expected format, and failure reason
**Validates: Requirements 2.5, 6.2, 6.5**

**Property 7: Debug transparency**
*For any* SettingsManager instance, Debug and Display formatting should show actual configuration values without redaction, and logging should safely include setting values
**Validates: Requirements 4.3, 4.4**

**Property 8: Layer-appropriate default value handling**
*For any* optional setting with a defined default value, when the setting is not provided in its configuration source (environment variables for bootstrap, database for application), the appropriate layer should use the default value
**Validates: Requirements 7.3, 8.5**

**Property 9: Range validation enforcement**
*For any* setting with defined valid ranges (port numbers, duration limits), the SettingsManager should reject values outside those ranges during initialization
**Validates: Requirements 7.4, 8.4**

**Property 10: Format support completeness**
*For any* supported configuration format (IPv4/IPv6 hosts, duration strings), the SettingsManager should correctly parse and validate all valid representations
**Validates: Requirements 7.5, 8.3**

**Property 11: Initialization logging consistency**
*For any* SettingsManager initialization, the system should log configuration loading progress and completion with appropriate detail levels
**Validates: Requirements 6.1, 6.3, 6.4**

## Integration Points

### AppData Integration

The `SettingsManager` will be integrated into the existing `AppData` structure:

```rust
pub struct AppData {
    // Existing fields...
    pub settings_manager: Arc<SettingsManager>,  // New unified manager
    // Other stores...
}

impl AppData {
    pub async fn init() -> Result<Self, Box<dyn std::error::Error>> {
        // Load all configuration layers for server startup
        let settings_manager = Arc::new(SettingsManager::init_full().await?);
        
        // Initialize database using bootstrap settings
        let db = init_database(settings_manager.bootstrap_settings.database_url()).await?;
        
        // Initialize other components...
        
        Ok(Self {
            settings_manager,
            // ...
        })
    }
}
```

### Usage Patterns

**Server Startup:**
```rust
// Full initialization
let settings = SettingsManager::init_full().await?;
let app_data = AppData::init().await?;
```

**CLI Operations:**
```rust
// Bootstrap only
let mut settings = SettingsManager::init_bootstrap_only()?;

// Connect to database using bootstrap settings
let db = connect(settings.bootstrap_settings.database_url()).await?;

// Lazy load secrets only if needed
if needs_secrets {
    let secrets = settings.ensure_secrets().await?;
    let jwt_secret = secrets.jwt_secret();
}
```

**Migration Commands:**
```rust
// Only need database connection
let settings = SettingsManager::init_bootstrap_only()?;
run_migrations(settings.bootstrap_settings.database_url()).await?;
```

### Initialization Flows

```rust
impl SettingsManager {
    // Full initialization for server startup
    pub async fn init_full() -> Result<Self, SettingsError> {
        // Step 1: Load bootstrap settings (always required)
        let bootstrap_settings = BootstrapSettings::from_env()
            .map_err(SettingsError::Bootstrap)?;
        
        // Step 2: Load secrets
        let secrets = Some(SecretManager::init()
            .map_err(SettingsError::Secret)?);
        
        // Step 3: Load application settings
        let application_settings = Some(ApplicationSettings::init(&bootstrap_settings).await
            .map_err(SettingsError::Application)?);
        
        Ok(Self {
            bootstrap_settings,
            secrets,
            application_settings,
        })
    }
    
    // Bootstrap-only initialization for CLI operations
    pub fn init_bootstrap_only() -> Result<Self, SettingsError> {
        let bootstrap_settings = BootstrapSettings::from_env()
            .map_err(SettingsError::Bootstrap)?;
        
        Ok(Self {
            bootstrap_settings,
            secrets: None,
            application_settings: None,
        })
    }
    
    // Lazy initialization methods
    pub async fn ensure_secrets(&mut self) -> Result<&SecretManager, SettingsError> {
        if self.secrets.is_none() {
            self.secrets = Some(SecretManager::init()
                .map_err(SettingsError::Secret)?);
        }
        Ok(self.secrets.as_ref().unwrap())
    }
    
    pub async fn ensure_application_settings(&mut self) -> Result<&ApplicationSettings, SettingsError> {
        if self.application_settings.is_none() {
            self.application_settings = Some(ApplicationSettings::init(&self.bootstrap_settings).await
                .map_err(SettingsError::Application)?);
        }
        Ok(self.application_settings.as_ref().unwrap())
    }
}
```

### Coordinator Integration

Coordinators will access settings through the AppData pattern:

```rust
impl AuthCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self {
        // Access settings during coordinator creation
        let jwt_expiration = app_data.settings_manager.jwt_expiration();
        
        let token_provider = Arc::new(TokenProvider::new(
            app_data.secret_manager.jwt_secret().to_string(),
            app_data.secret_manager.refresh_token_secret().to_string(),
            jwt_expiration,  // Use setting instead of hardcoded value
            app_data.audit_store.clone(),
        ));
        
        // ...
    }
}
```

### Migration Strategy

The implementation will follow a phased approach:

1. **Phase 1**: Implement SettingsManager with environment variable support
2. **Phase 2**: Migrate existing hardcoded configuration to use SettingsManager
3. **Phase 3**: Add database ConfigSource support for runtime-changeable settings

## Future Extensions

The design supports several future enhancements:

### Database Configuration Storage

Future implementation will add database support:

```rust
pub enum ConfigSource {
    EnvVar { name: String },
    DatabaseSetting { 
        key: String,
        table: String,  // e.g., "system_config"
        cache_ttl: Option<Duration>,
    },
}
```

### Runtime Configuration Updates

Future implementation will support runtime updates:

```rust
impl SettingsManager {
    pub async fn reload_setting(&mut self, setting_name: &str) -> Result<(), SettingsError>;
    pub async fn update_setting(&mut self, setting_name: &str, value: String) -> Result<(), SettingsError>;
}
```

### Configuration Validation Hooks

For complex validation scenarios:

```rust
pub struct ConfigSpec {
    // Existing fields...
    pub validator: Option<Box<dyn Fn(&str) -> Result<(), String>>>,
    pub post_load_hook: Option<Box<dyn Fn(&str) -> Result<String, String>>>,
}
```

### Example Configuration Specifications

```rust
impl ApplicationSettings {
    fn jwt_expiration_config() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("JWT_EXPIRATION_MINUTES")
            .database("jwt_expiration_minutes")
            .default_value("15")
            .validator(|value| {
                let minutes = value.parse::<u32>()
                    .map_err(|_| "must be a positive integer")?;
                if minutes == 0 || minutes > 1440 {
                    return Err("must be between 1 and 1440 minutes".to_string());
                }
                Ok(())
            })
    }
    
    fn refresh_token_expiration_config() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("REFRESH_TOKEN_EXPIRATION_DAYS")
            .database("refresh_token_expiration_days")
            .default_value("7")
            .validator(|value| {
                let days = value.parse::<u32>()
                    .map_err(|_| "must be a positive integer")?;
                if days == 0 || days > 365 {
                    return Err("must be between 1 and 365 days".to_string());
                }
                Ok(())
            })
    }
    
    fn rate_limiting_enabled_config() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("RATE_LIMITING_ENABLED")
            .database("rate_limiting_enabled")
            .default_value("true")
            .validator(|value| {
                match value.to_lowercase().as_str() {
                    "true" | "false" | "1" | "0" | "yes" | "no" => Ok(()),
                    _ => Err("must be true, false, 1, 0, yes, or no".to_string()),
                }
            })
    }
}
```

### Database Operations

```rust
impl ApplicationSettings {
    async fn load_setting(spec: &ConfigSpec, db: &Database) -> Result<String, SettingsError> {
        // 1. Check environment variable override (highest priority)
        if let Some(env_var) = &spec.env_override {
            if let Ok(value) = std::env::var(env_var) {
                Self::validate_setting(&value, spec)?;
                return Ok(value);
            }
        }
        
        // 2. Check database value (middle priority)
        if let Some(db_key) = &spec.database_key {
            let db_value: Option<String> = sqlx::query_scalar(
                "SELECT value FROM system_settings WHERE key = ?"
            )
            .bind(db_key)
            .fetch_optional(db)
            .await
            .map_err(|e| SettingsError::DatabaseError(e.to_string()))?;
            
            if let Some(value) = db_value {
                Self::validate_setting(&value, spec)?;
                return Ok(value);
            }
        }
        
        // 3. Use default value (lowest priority)
        if let Some(default) = &spec.default_value {
            Self::validate_setting(default, spec)?;
            return Ok(default.clone());
        }
        
        // 4. Required setting with no value found
        if spec.required {
            let setting_name = spec.env_override
                .as_ref()
                .or(spec.database_key.as_ref())
                .unwrap_or(&"unknown".to_string());
            return Err(SettingsError::MissingSetting {
                setting_name: setting_name.clone(),
            });
        }
        
        Ok(String::new())
    }
    
    fn validate_setting(value: &str, spec: &ConfigSpec) -> Result<(), SettingsError> {
        // Length validation
        if let Some(min_len) = spec.min_length {
            if value.len() < min_len {
                return Err(SettingsError::InvalidLength {
                    setting_name: "setting".to_string(), // TODO: pass setting name
                    expected: min_len,
                    actual: value.len(),
                });
            }
        }
        
        // Custom validation
        if let Some(validator) = spec.validator {
            validator(value).map_err(|reason| SettingsError::ValidationFailed {
                setting_name: "setting".to_string(), // TODO: pass setting name
                reason,
            })?;
        }
        
        Ok(())
    }
}
```
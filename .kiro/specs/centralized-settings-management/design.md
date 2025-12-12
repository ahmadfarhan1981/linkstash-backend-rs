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

Defines the single persistent source for configuration values:

```rust
#[derive(Debug, Clone)]
pub enum ConfigSource {
    /// Load from database key-value table
    Database { key: String },
    /// Load from configuration file
    File { path: PathBuf, key: String },
    // Future variants:
    // Vault { path: String },
}
```

### Configuration Value Tracking

Track configuration sources and mutability for runtime management:

```rust
#[derive(Debug, Clone)]
pub struct ConfigValue {
    pub value: String,
    pub source: ConfigValueSource,
    pub is_mutable: bool,
}

#[derive(Debug, Clone)]
pub enum ConfigValueSource {
    EnvironmentVariable { name: String },
    Database { key: String },
    File { path: PathBuf, key: String },
    Default,
}
```

### ConfigSpec Struct

Configuration specification with environment override → single persistent source → default priority:

```rust
pub struct ConfigSpec {
    /// Environment variable override (always highest priority)
    pub env_override: Option<String>,
    /// Single persistent source (middle priority)
    pub persistent_source: Option<ConfigSource>,
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
    pub fn persistent_source(mut self, source: ConfigSource) -> Self;
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
    
    // Configuration management methods
    pub fn list_all_settings(&self) -> Vec<(String, ConfigValue)>;
    pub fn get_setting_info(&self, setting_name: &str) -> Result<ConfigValue, SettingsError>;
    pub fn can_update_setting(&self, setting_name: &str) -> bool;
    pub async fn update_setting(&mut self, setting_name: &str, value: String) -> Result<(), SettingsError>;
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

Business logic configuration with in-memory caching and runtime updates:

```rust
pub struct ApplicationSettings {
    // Cached values for fast access (thread-safe)
    jwt_expiration_minutes: Arc<RwLock<u32>>,
    refresh_token_expiration_days: Arc<RwLock<u32>>,
    rate_limiting_enabled: Arc<RwLock<bool>>,
    audit_retention_days: Arc<RwLock<u32>>,
    
    // Database connection for updates
    db: Arc<Database>,
    
    // Configuration specifications for validation and source tracking
    specs: HashMap<String, ConfigSpec>,
}

impl ApplicationSettings {
    pub async fn init(bootstrap: &BootstrapSettings) -> Result<Self, SettingsError>;
    
    // Fast cached getters
    pub fn jwt_expiration(&self) -> Duration;
    pub fn refresh_token_expiration(&self) -> Duration;
    pub fn rate_limiting_enabled(&self) -> bool;
    pub fn audit_retention_days(&self) -> u32;
    
    // Configuration management methods
    pub fn get_setting_info(&self, setting_name: &str) -> Result<ConfigValue, SettingsError>;
    pub fn list_all_settings(&self) -> Vec<(String, ConfigValue)>;
    pub async fn update_setting(&self, setting_name: &str, value: String) -> Result<(), SettingsError>;
    
    // Configuration specifications
    fn jwt_expiration_config() -> ConfigSpec;
    fn refresh_token_expiration_config() -> ConfigSpec;
    fn rate_limiting_enabled_config() -> ConfigSpec;
    fn audit_retention_days_config() -> ConfigSpec;
    
    // Internal methods
    async fn load_setting_with_source(spec: &ConfigSpec, db: &Database) -> Result<ConfigValue, SettingsError>;
    fn update_cache(&self, setting_name: &str, value: &str) -> Result<(), SettingsError>;
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
    UnknownSetting { name: String },
    ReadOnlyFromEnvironment { setting_name: String },
    NoWritableSource { setting_name: String },
    FileUpdatesNotSupported,
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

**Application Settings (Env Override → Persistent Source → Default):**
- `JWT_EXPIRATION_MINUTES` (u32, env: JWT_EXPIRATION_MINUTES, persistent: none, default: 15)
- `REFRESH_TOKEN_EXPIRATION_DAYS` (u32, env: REFRESH_TOKEN_EXPIRATION_DAYS, persistent: none, default: 7)
- `RATE_LIMITING_ENABLED` (bool, env: RATE_LIMITING_ENABLED, persistent: Database{rate_limiting_enabled}, default: true, future)
- `AUDIT_RETENTION_DAYS` (u32, env: AUDIT_RETENTION_DAYS, persistent: Database{audit_retention_days}, default: 90, future)

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
   - `JWT_EXPIRATION_MINUTES=30` always wins if set
   
2. **Single Persistent Source** (middle priority)
   - Database: `SELECT value FROM system_settings WHERE key = 'rate_limiting_enabled'`
   - File: Load from specified file path and key
   - No cascading fallbacks between persistent sources
   
3. **Default Value** (lowest priority)
   - Hardcoded in ConfigSpec: `default_value("15")`

**Key Principle**: Each setting has exactly one persistent source, not a fallback chain.

### Caching and Runtime Update Strategy

The system uses an in-memory cache with update-on-write strategy:

**Initialization:**
- All settings are loaded once during startup and cached in memory
- Values are stored in thread-safe `Arc<RwLock<T>>` for concurrent access
- Configuration source information is tracked for each setting

**Runtime Behavior:**
- **Reads**: Fast access from in-memory cache (no database queries)
- **Updates**: Write to persistent storage, then update cache immediately
- **Environment Variables**: Always require restart (read-only at runtime)
- **Database Settings**: Can be updated at runtime via API
- **External Changes**: Out-of-band database changes require restart (acceptable limitation)

**Thread Safety:**
- Multiple concurrent reads supported via `RwLock`
- Single writer for updates ensures consistency
- Cache updates are atomic per setting

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
*For any* application setting, when both environment variable and persistent source are present, the environment variable should take priority, and when only persistent source is present, it should be used, and when neither is present, the default value should be used
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

**Property 12: Runtime update consistency**
*For any* mutable setting, when updated via API, the new value should be immediately reflected in both persistent storage and in-memory cache, and subsequent reads should return the updated value
**Validates: Requirements 9.1, 9.2**

**Property 13: Environment variable immutability**
*For any* setting overridden by an environment variable, runtime update attempts should be rejected with appropriate error messages indicating the setting is read-only
**Validates: Requirements 9.3**

**Property 14: Configuration source transparency**
*For any* setting, the system should accurately report its current source (environment variable, database, file, or default) and whether it can be updated at runtime
**Validates: Requirements 9.4**

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

### Configuration API Integration

The SettingsManager is designed to support future configuration management APIs:

```rust
// Example configuration API usage
#[OpenApi]
impl ConfigApi {
    /// List all configuration settings with their sources and mutability
    #[oai(path = "/config", method = "get")]
    async fn list_config(&self) -> Result<ConfigListResponse> {
        let settings = self.settings_manager.list_all_settings();
        
        let config_items: Vec<ConfigItem> = settings
            .into_iter()
            .map(|(name, config_value)| ConfigItem {
                name,
                value: config_value.value,
                source: format!("{:?}", config_value.source),
                is_mutable: config_value.is_mutable,
            })
            .collect();
            
        Ok(ConfigListResponse { items: config_items })
    }
    
    /// Update a configuration setting
    #[oai(path = "/config/{setting_name}", method = "put")]
    async fn update_config(
        &self, 
        setting_name: Path<String>,
        request: Json<UpdateConfigRequest>
    ) -> Result<UpdateConfigResponse> {
        // Validation and update handled by SettingsManager
        self.settings_manager
            .update_setting(&setting_name, request.value.clone())
            .await?;
            
        Ok(UpdateConfigResponse { 
            message: "Setting updated successfully".to_string() 
        })
    }
}
```

### Migration Strategy

The implementation will follow a phased approach:

1. **Phase 1**: Implement SettingsManager with environment variable support and in-memory caching
2. **Phase 2**: Migrate existing hardcoded configuration to use SettingsManager
3. **Phase 3**: Add database ConfigSource support for runtime-changeable settings
4. **Phase 4**: Implement configuration management API endpoints

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
            .persistent_source(ConfigSource::Database { 
                key: "rate_limiting_enabled".to_string() 
            })
            .default_value("true")
            .validator(|value| {
                match value.to_lowercase().as_str() {
                    "true" | "false" | "1" | "0" | "yes" | "no" => Ok(()),
                    _ => Err("must be true, false, 1, 0, yes, or no".to_string()),
                }
            })
    }
    
    fn server_config_from_file() -> ConfigSpec {
        ConfigSpec::new()
            .env_override("SERVER_PORT")
            .persistent_source(ConfigSource::File { 
                path: "/etc/linkstash/server.toml".into(), 
                key: "port".to_string() 
            })
            .default_value("3000")
    }
}
```

### Configuration Loading and Caching Operations

```rust
impl ApplicationSettings {
    pub async fn init(bootstrap: &BootstrapSettings) -> Result<Self, SettingsError> {
        let db = Arc::new(connect_database(bootstrap.database_url()).await?);
        let specs = Self::build_specs();
        
        // Load all values once and cache them
        let jwt_expiration_minutes = Arc::new(RwLock::new(
            Self::load_jwt_expiration(&db).await?
        ));
        let rate_limiting_enabled = Arc::new(RwLock::new(
            Self::load_rate_limiting_enabled(&db).await?
        ));
        // ... load other settings
        
        Ok(Self {
            jwt_expiration_minutes,
            rate_limiting_enabled,
            db,
            specs,
        })
    }
    
    async fn load_setting_with_source(spec: &ConfigSpec, db: &Database) -> Result<ConfigValue, SettingsError> {
        // 1. Check environment variable override (highest priority)
        if let Some(env_var) = &spec.env_override {
            if let Ok(value) = std::env::var(env_var) {
                Self::validate_setting(&value, spec)?;
                return Ok(ConfigValue {
                    value,
                    source: ConfigValueSource::EnvironmentVariable { 
                        name: env_var.clone() 
                    },
                    is_mutable: false, // Environment variables are read-only
                });
            }
        }
        
        // 2. Check single persistent source (middle priority)
        if let Some(source) = &spec.persistent_source {
            let value = match source {
                ConfigSource::Database { key } => {
                    sqlx::query_scalar("SELECT value FROM system_settings WHERE key = ?")
                        .bind(key)
                        .fetch_optional(db)
                        .await
                        .map_err(|e| SettingsError::DatabaseError(e.to_string()))?
                }
                ConfigSource::File { path, key } => {
                    // Future implementation: load from file
                    None
                }
            };
            
            if let Some(value) = value {
                Self::validate_setting(&value, spec)?;
                return Ok(ConfigValue {
                    value,
                    source: match source {
                        ConfigSource::Database { key } => ConfigValueSource::Database { 
                            key: key.clone() 
                        },
                        ConfigSource::File { path, key } => ConfigValueSource::File { 
                            path: path.clone(), 
                            key: key.clone() 
                        },
                    },
                    is_mutable: true, // Persistent sources are mutable
                });
            }
        }
        
        // 3. Use default value (lowest priority)
        if let Some(default) = &spec.default_value {
            Self::validate_setting(default, spec)?;
            return Ok(ConfigValue {
                value: default.clone(),
                source: ConfigValueSource::Default,
                is_mutable: spec.persistent_source.is_some(), // Mutable if has persistent source
            });
        }
        
        // 4. Required setting with no value found
        if spec.required {
            let setting_name = spec.env_override
                .as_ref()
                .or_else(|| match &spec.persistent_source {
                    Some(ConfigSource::Database { key }) => Some(key),
                    Some(ConfigSource::File { key, .. }) => Some(key),
                    None => None,
                })
                .unwrap_or(&"unknown".to_string());
            return Err(SettingsError::MissingSetting {
                setting_name: setting_name.clone(),
            });
        }
        
        Ok(ConfigValue {
            value: String::new(),
            source: ConfigValueSource::Default,
            is_mutable: false,
        })
    }
    
    pub async fn update_setting(&self, setting_name: &str, value: String) -> Result<(), SettingsError> {
        let spec = self.specs.get(setting_name)
            .ok_or_else(|| SettingsError::UnknownSetting { name: setting_name.to_string() })?;
        
        // Validate the new value
        Self::validate_setting(&value, spec)?;
        
        // Check if setting is mutable (not from env var)
        let current_info = self.get_setting_info(setting_name)?;
        if !current_info.is_mutable {
            return Err(SettingsError::ReadOnlyFromEnvironment { 
                setting_name: setting_name.to_string() 
            });
        }
        
        // Update persistent storage
        match &spec.persistent_source {
            Some(ConfigSource::Database { key }) => {
                sqlx::query("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)")
                    .bind(key)
                    .bind(&value)
                    .execute(&*self.db)
                    .await?;
            }
            Some(ConfigSource::File { .. }) => {
                return Err(SettingsError::FileUpdatesNotSupported);
            }
            None => {
                return Err(SettingsError::NoWritableSource { 
                    setting_name: setting_name.to_string() 
                });
            }
        }
        
        // Update in-memory cache
        self.update_cache(setting_name, &value)?;
        
        Ok(())
    }
    
    fn update_cache(&self, setting_name: &str, value: &str) -> Result<(), SettingsError> {
        match setting_name {
            "jwt_expiration_minutes" => {
                let parsed = value.parse::<u32>()?;
                *self.jwt_expiration_minutes.write().unwrap() = parsed;
            }
            "rate_limiting_enabled" => {
                let parsed = Self::parse_bool(value)?;
                *self.rate_limiting_enabled.write().unwrap() = parsed;
            }
            // ... other settings
            _ => return Err(SettingsError::UnknownSetting { name: setting_name.to_string() }),
        }
        Ok(())
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
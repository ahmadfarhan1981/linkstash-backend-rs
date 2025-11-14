# Design Document: Structured Audit Logging

## Overview

This design implements a dual-logging architecture that separates ephemeral application logs from persistent security audit logs. The system provides type-safe helper functions for common authentication events and an extensible builder pattern for custom audit events, ensuring consistent formatting and preventing accidental exposure of sensitive data.

### Key Design Decisions

1. **Separate Database for Audit Logs** - Using a dedicated SQLite database (`audit.db`) separate from the application database (`auth.db`) enables independent lifecycle management, archival, and compliance workflows without impacting application data operations.

2. **Hybrid Schema Design** - Combining indexed columns for common queryable fields with a JSON column for event-specific data provides both query performance and extensibility without requiring schema migrations for new event types.

3. **Builder Pattern for Extensibility** - The `AuditBuilder` API allows developers to create custom audit events while enforcing required fields (user identification) and providing optional sensitive data redaction.

4. **Tracing Framework Integration** - Using the `tracing` crate with `tracing-subscriber` for application logs provides structured logging, async support, and ecosystem compatibility while keeping audit logs in a separate system.

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Code                         │
│  (API handlers, Services, Stores)                           │
└────────────┬────────────────────────────────┬───────────────┘
             │                                │
             │ Application Logs               │ Audit Events
             │ (tracing macros)               │ (helper fns/builder)
             ▼                                ▼
┌────────────────────────────┐  ┌──────────────────────────────┐
│   Tracing Subscriber        │  │   Audit Logger Module        │
│   - Console Layer           │  │   - Helper Functions         │
│   - File Layer (optional)   │  │   - AuditBuilder API         │
│   - Formatting              │  │   - Validation Logic         │
└────────────────────────────┘  └──────────┬───────────────────┘
                                           │
                                           ▼
                                ┌──────────────────────────┐
                                │   Audit Store            │
                                │   (Repository Pattern)   │
                                └──────────┬───────────────┘
                                           │
                                           ▼
                                ┌──────────────────────────┐
                                │   audit.db (SQLite)      │
                                │   - audit_events table   │
                                │   - Indexes              │
                                └──────────────────────────┘
```

### Module Structure

```
src/
├── config/
│   └── logging.rs              # Logging configuration from env vars
│
├── services/
│   └── audit_logger.rs         # Helper functions + AuditBuilder
│
├── stores/
│   └── audit_store.rs          # Database operations for audit events
│
├── types/
│   ├── db/
│   │   └── audit_event.rs      # SeaORM entity for audit_events table
│   └── internal/
│       └── audit.rs            # AuditEvent struct, EventType enum
│
└── main.rs                     # Initialize logging + audit DB pool
```

## Components and Interfaces

### 1. Logging Configuration (`config/logging.rs`)

**Purpose**: Load environment variables and initialize both application logging and audit database connection.

**Configuration Structure**:
```rust
pub struct LoggingConfig {
    pub log_level: String,              // Default: "INFO"
    pub app_log_file: Option<String>,   // Optional file output
    pub app_log_retention_days: u32,    // Default: 7
}

pub struct AuditConfig {
    pub audit_db_path: String,          // Default: "audit.db"
    pub retention_days: u32,            // Default: 90
}
```

**Initialization Function**:
```rust
pub fn init_logging(config: &LoggingConfig) -> Result<(), LoggingError>
```
- Configures `tracing_subscriber` with console and optional file layers
- Sets log level filter from environment
- Configures file rotation if enabled

**Rationale**: Centralizing configuration logic ensures consistent environment variable handling and provides clear validation/default behavior.

### 2. Audit Event Entity (`types/db/audit_event.rs`)

**SeaORM Entity Definition**:
```rust
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_events")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    
    pub timestamp: DateTime<Utc>,      // Indexed
    pub event_type: String,            // Indexed (e.g., "login_success")
    pub user_id: i64,                  // Indexed, required
    pub ip_address: Option<String>,
    pub jwt_id: Option<String>,        // Indexed, JWT identifier (jti claim)
    
    // Event-specific fields as JSON
    pub data: String,                  // JSON serialized HashMap<String, Value>
}
```

**Migration**:
```sql
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    ip_address TEXT,
    jwt_id TEXT,
    data TEXT NOT NULL
);

CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_jwt_id ON audit_events(jwt_id);
```

**Rationale**: 
- Hybrid schema balances query performance (indexed common fields) with extensibility (JSON data column)
- user_id is required for all audit events, simplifying the schema and queries
- jwt_id as indexed field enables tracking token lifecycle across events (issuance, validation, revocation)
- Separate indexes enable efficient filtering by time range, event type, user, or specific token

### 3. Internal Audit Types (`types/internal/audit.rs`)

**Event Type Enum**:
```rust
pub enum EventType {
    LoginSuccess,
    LoginFailure,
    JwtIssued,
    JwtValidationFailure,
    JwtTampered,                // Signature invalid or malformed
    RefreshTokenIssued,
    RefreshTokenRevoked,
    Custom(String),
}

impl EventType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::LoginSuccess => "login_success",
            Self::LoginFailure => "login_failure",
            Self::JwtIssued => "jwt_issued",
            Self::JwtValidationFailure => "jwt_validation_failure",
            Self::JwtTampered => "jwt_tampered",
            Self::RefreshTokenIssued => "refresh_token_issued",
            Self::RefreshTokenRevoked => "refresh_token_revoked",
            Self::Custom(s) => s.as_str(),
        }
    }
}
```

**Audit Event Builder State**:
```rust
pub struct AuditEvent {
    event_type: EventType,
    user_id: Option<i64>,
    ip_address: Option<String>,
    jwt_id: Option<String>,
    data: HashMap<String, serde_json::Value>,
}
```

**Rationale**: Type-safe enum for common events prevents typos while allowing custom event types for extensibility.

### 4. Audit Store (`stores/audit_store.rs`)

**Repository Interface**:
```rust
pub struct AuditStore {
    db: DatabaseConnection,
}

impl AuditStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
    
    pub async fn write_event(&self, event: AuditEvent) -> Result<(), AuditError> {
        // Validate user_id is present
        // Serialize data to JSON
        // Insert into database
    }
}
```

**Rationale**: Repository pattern encapsulates all database operations, making it easy to test and swap implementations if needed.

### 5. Audit Logger Service (`services/audit_logger.rs`)

**Helper Functions** (pre-defined for common events):
```rust
pub async fn log_login_success(
    store: &AuditStore,
    user_id: i64,
    ip_address: Option<String>,
) -> Result<(), AuditError>

pub async fn log_login_failure(
    store: &AuditStore,
    user_id: Option<i64>,
    failure_reason: String,
    ip_address: Option<String>,
) -> Result<(), AuditError>

pub async fn log_jwt_issued(
    store: &AuditStore,
    user_id: i64,
    jwt_id: String,
    expiration: DateTime<Utc>,
) -> Result<(), AuditError>

pub async fn log_jwt_validation_failure(
    store: &AuditStore,
    user_id: i64,
    jwt_id: Option<String>,
    failure_reason: String,
) -> Result<(), AuditError>

pub async fn log_jwt_tampered(
    store: &AuditStore,
    user_id: i64,
    jwt_id: Option<String>,
    full_jwt: String,
    failure_reason: String,
) -> Result<(), AuditError>

pub async fn log_refresh_token_issued(
    store: &AuditStore,
    user_id: i64,
    jwt_id: String,
    token_id: String,
) -> Result<(), AuditError>

pub async fn log_refresh_token_revoked(
    store: &AuditStore,
    user_id: i64,
    jwt_id: Option<String>,
    token_id: String,
) -> Result<(), AuditError>
```

**AuditBuilder API** (for custom events):
```rust
pub struct AuditBuilder {
    event: AuditEvent,
    store: Arc<AuditStore>,
}

impl AuditBuilder {
    pub fn new(store: Arc<AuditStore>, event_type: impl Into<EventType>) -> Self
    
    pub fn user_id(mut self, id: i64) -> Self
    
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self
    
    pub fn jwt_id(mut self, id: impl Into<String>) -> Self
    
    pub fn add_field(mut self, key: impl Into<String>, value: impl Serialize) -> Self
    
    pub fn add_sensitive(mut self, key: impl Into<String>, _value: impl Serialize) -> Self {
        // Redact the value, store "[REDACTED]" instead
        self.event.data.insert(key.into(), json!("[REDACTED]"));
        self
    }
    
    pub async fn write(self) -> Result<(), AuditError> {
        // Validate user_id exists
        if self.event.user_id.is_none() {
            return Err(AuditError::MissingUserId);
        }
        self.store.write_event(self.event).await
    }
}
```

**Usage Examples**:
```rust
// Using helper function
audit::log_login_success(&audit_store, user.id, Some(ip_addr)).await?;

// Using builder for custom event
AuditBuilder::new(audit_store.clone(), "password_reset_requested")
    .user_id(user.id)
    .jwt_id(jwt_id)  // Optional, if JWT context available
    .ip_address(ip_addr)
    .add_field("reset_token_id", token_id)
    .add_field("expiration", expiration_time)
    .write()
    .await?;
```

**Rationale**: 
- Helper functions provide convenience and consistency for common events
- Builder pattern enforces compile-time safety while allowing runtime flexibility
- `add_sensitive` method provides explicit API for redaction, preventing accidental exposure

## Data Models

### Audit Event Data Flow

```
Application Code
    ↓
Helper Function / AuditBuilder
    ↓
AuditEvent (internal struct)
    ↓ (validation + serialization)
AuditStore
    ↓
audit_event::ActiveModel (SeaORM)
    ↓
SQLite audit.db
```

### JSON Data Column Schema

Event-specific fields stored in the `data` column as JSON:

**Login Events**:
```json
{
  "failure_reason": "invalid_password"  // login_failure only
}
```

**JWT Events**:
```json
{
  "expiration": "2025-11-14T12:00:00Z",  // jwt_issued only
  "failure_reason": "expired"             // jwt_validation_failure only
}
```

**JWT Tampered Events**:
```json
{
  "full_jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",  // Full token for forensics
  "failure_reason": "invalid_signature"
}
```

**Refresh Token Events**:
```json
{
  "token_id": "uuid-v4-string"
}
```

**Custom Events**:
```json
{
  "custom_field_1": "value",
  "custom_field_2": 123,
  "nested": { "data": "allowed" }
}
```

## Error Handling

### Audit Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Missing user_id: user_id is required for all audit events")]
    MissingUserId,
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
```

**Error Handling Strategy**:
- Audit logging failures should NOT crash the application
- Log audit errors to application logs (ERROR level)
- Return errors to callers for optional handling
- Consider implementing a fallback mechanism (e.g., write to file if DB unavailable)

**Rationale**: Audit logging is critical but should not prevent core application functionality. Graceful degradation ensures system availability.

## Testing Strategy

### Unit Tests

1. **AuditBuilder Validation**
   - Test that `write()` fails without user_id
   - Test `add_sensitive()` redacts values correctly
   - Test field serialization for various types

2. **Helper Functions**
   - Verify correct event_type and field mapping
   - Test with optional parameters (None cases)

3. **Configuration Loading**
   - Test default values
   - Test environment variable parsing
   - Test invalid configuration handling

### Integration Tests

1. **Audit Store Operations**
   - Write events and verify database contents
   - Test concurrent writes (connection pool behavior)
   - Verify indexes are used in queries

2. **End-to-End Audit Flow**
   - Trigger authentication events in test environment
   - Verify audit events are written correctly
   - Query audit database and validate results

3. **Sensitive Data Protection**
   - Verify tokens/passwords never appear in audit logs
   - Test `add_sensitive()` redaction in database

### Query Performance Tests

- Benchmark common forensic queries:
  - Filter by time range
  - Filter by event_type
  - Filter by user_id
  - Filter by jwt_id (track token lifecycle)
  - Combined filters with JSON field extraction

## Security Considerations

### Sensitive Data Protection

**Never Log**:
- Passwords (plaintext or hashed)
- Valid JWT tokens (full token strings)
- Refresh tokens (full token strings)
- API keys
- Cryptographic secrets

**Safe to Log**:
- JWT identifiers (jti claim from token)
- Token identifiers (UUIDs for refresh tokens)
- User IDs
- IP addresses
- Timestamps
- Event types and outcomes

**Log for Security Investigation**:
- Full JWT when signature validation fails (tampering suspected)
- Full JWT when token is malformed (manipulation suspected)
- Rationale: Invalid tokens cannot be used for replay attacks but provide forensic value

**Implementation**:
- Helper functions automatically handle sensitive data correctly
- `add_sensitive()` method provides explicit redaction for custom events
- Documentation clearly defines what constitutes sensitive data

### Database Security

- Audit database file should have restricted permissions (read/write for application user only)
- Consider encryption at rest for compliance requirements
- Separate connection pool prevents audit operations from blocking application queries
- Append-only design (no UPDATE or DELETE operations exposed)

### Audit Integrity

- Immutable records (no updates/deletes via API)
- Timestamps in UTC to prevent timezone manipulation
- Database-level NOT NULL constraint enforces user_id requirement
- Consider adding cryptographic signatures for tamper detection (future enhancement)

## Configuration

### Environment Variables

```bash
# Application Logging
LOG_LEVEL=INFO                          # DEBUG, INFO, WARN, ERROR
APP_LOG_FILE=/var/log/linkstash/app.log # Optional file output
APP_LOG_RETENTION_DAYS=7                # File rotation

# Audit Logging
AUDIT_DB_PATH=/var/lib/linkstash/audit.db
AUDIT_LOG_RETENTION_DAYS=90
```

### Initialization in main.rs

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    
    // Initialize application logging
    let log_config = LoggingConfig::from_env();
    init_logging(&log_config)?;
    
    // Initialize audit database
    let audit_config = AuditConfig::from_env();
    let audit_db = Database::connect(&audit_config.audit_db_path).await?;
    let audit_store = Arc::new(AuditStore::new(audit_db));
    
    // Initialize application database
    let app_db = Database::connect(&database_url).await?;
    
    // Build server with both database connections
    // ...
}
```

## Archival and Retention

### Archival Strategy

1. **File-Based Archival**:
   - SQLite database is a single file
   - Can be safely copied while application is running (SQLite supports concurrent readers)
   - Recommended: Use `VACUUM INTO` for consistent snapshots

2. **Retention Implementation**:
   - Background task (Tokio task) runs daily
   - Deletes audit events older than `AUDIT_LOG_RETENTION_DAYS`
   - Runs during low-traffic periods (configurable schedule)

3. **Archive Procedure**:
   ```bash
   # Copy current audit database
   sqlite3 audit.db "VACUUM INTO 'audit_archive_2025-11.db'"
   
   # Compress for long-term storage
   gzip audit_archive_2025-11.db
   
   # Move to archive location
   mv audit_archive_2025-11.db.gz /archive/audit/
   ```

### Compliance Considerations

- Separate database enables independent backup schedules
- Archive files can be moved to cold storage
- Retention period configurable per compliance requirements (GDPR, SOC2, etc.)
- Consider implementing export to immutable storage (S3 Glacier, etc.)

## Future Enhancements

1. **Structured Query API**: Provide helper functions for common forensic queries
2. **Audit Event Streaming**: Publish events to message queue for real-time monitoring
3. **Cryptographic Signatures**: Sign audit events for tamper detection
4. **Compression**: Compress old audit events to reduce storage
5. **Multi-Database Support**: PostgreSQL backend for high-volume deployments
6. **Audit Dashboard**: Web UI for querying and visualizing audit events


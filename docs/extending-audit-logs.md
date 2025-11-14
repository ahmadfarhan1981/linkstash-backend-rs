# Extending Audit Logs

## Overview

The Linkstash audit logging system provides a dual-logging architecture that separates ephemeral application logs from persistent security audit logs. This document explains how to extend the audit logging system with custom events while maintaining security and consistency.

### Key Features

- **Separate Audit Database**: Dedicated SQLite database (`audit.db`) for long-term security event storage
- **Hybrid Schema**: Indexed columns for common queryable fields + JSON column for event-specific data
- **Type-Safe Helper Functions**: Pre-defined functions for common authentication events
- **Extensible Builder API**: Fluent API for creating custom audit events
- **Automatic Sensitive Data Protection**: SHA-256 hashing for sensitive fields

### Architecture

```
Application Code
    ↓
Helper Functions / AuditBuilder
    ↓
AuditStore (Repository)
    ↓
audit.db (SQLite)
```

## Helper Functions

The audit logging system provides pre-defined helper functions for common authentication events. These functions ensure consistent formatting and field naming across the application.

### log_login_success

Logs a successful user login event.

**Parameters:**
- `store: &AuditStore` - Reference to the audit store
- `user_id: String` - ID of the user who logged in
- `ip_address: Option<String>` - Optional IP address of the client

**Usage:**
```rust
use crate::services::audit_logger;

audit_logger::log_login_success(
    &audit_store,
    user.id.to_string(),
    Some("192.168.1.1".to_string()),
).await?;
```

**Event Type:** `login_success`

**Indexed Fields:** `user_id`, `ip_address`

---

### log_login_failure

Logs a failed login attempt with the reason for failure.

**Parameters:**
- `store: &AuditStore` - Reference to the audit store
- `user_id: Option<String>` - Optional user ID (if username was valid but password incorrect)
- `failure_reason: String` - Reason for the login failure (e.g., "invalid_password", "user_not_found")
- `ip_address: Option<String>` - Optional IP address of the client

**Usage:**
```rust
audit_logger::log_login_failure(
    &audit_store,
    Some(user.id.to_string()),
    "invalid_password".to_string(),
    Some("192.168.1.1".to_string()),
).await?;
```

**Event Type:** `login_failure`

**Indexed Fields:** `user_id`, `ip_address`

**JSON Data Fields:** `failure_reason`

---

### log_jwt_issued

Logs the issuance of a new JWT access token.

**Parameters:**
- `store: &AuditStore` - Reference to the audit store
- `user_id: String` - ID of the user for whom the JWT was issued
- `jwt_id: String` - JWT identifier (jti claim)
- `expiration: DateTime<Utc>` - Expiration timestamp of the JWT
- `ip_address: Option<String>` - Optional IP address of the client

**Usage:**
```rust
use chrono::{Duration, Utc};

let expiration = Utc::now() + Duration::minutes(15);
audit_logger::log_jwt_issued(
    &audit_store,
    user.id.to_string(),
    jwt_id.clone(),
    expiration,
    Some("192.168.1.1".to_string()),
).await?;
```

**Event Type:** `jwt_issued`

**Indexed Fields:** `user_id`, `jwt_id`, `ip_address`

**JSON Data Fields:** `expiration` (RFC3339 format)

---

### log_jwt_validation_failure

Logs a JWT validation failure (expired, invalid signature, etc.).

**Parameters:**
- `store: &AuditStore` - Reference to the audit store
- `user_id: String` - ID of the user from the JWT claims
- `jwt_id: Option<String>` - Optional JWT identifier (jti claim)
- `failure_reason: String` - Reason for validation failure (e.g., "expired", "invalid_signature")

**Usage:**
```rust
audit_logger::log_jwt_validation_failure(
    &audit_store,
    claims.user_id.clone(),
    Some(claims.jti.clone()),
    "token_expired".to_string(),
).await?;
```

**Event Type:** `jwt_validation_failure`

**Indexed Fields:** `user_id`, `jwt_id`

**JSON Data Fields:** `failure_reason`

---

### log_jwt_tampered

Logs detection of a tampered JWT for forensic analysis.

**Parameters:**
- `store: &AuditStore` - Reference to the audit store
- `user_id: String` - ID of the user from the JWT claims (if extractable)
- `jwt_id: Option<String>` - Optional JWT identifier (jti claim)
- `full_jwt: String` - Full JWT string for forensic analysis
- `failure_reason: String` - Reason for tampering detection

**Usage:**
```rust
audit_logger::log_jwt_tampered(
    &audit_store,
    "unknown".to_string(),
    None,
    token.clone(),
    "invalid_signature".to_string(),
).await?;
```

**Event Type:** `jwt_tampered`

**Indexed Fields:** `user_id`, `jwt_id`

**JSON Data Fields:** `full_jwt`, `failure_reason`

---

### log_refresh_token_issued

Logs the issuance of a new refresh token.

**Parameters:**
- `store: &AuditStore` - Reference to the audit store
- `user_id: String` - ID of the user for whom the refresh token was issued
- `jwt_id: String` - JWT identifier associated with this refresh token
- `token_id: String` - Unique identifier for the refresh token
- `ip_address: Option<String>` - Optional IP address of the client

**Usage:**
```rust
audit_logger::log_refresh_token_issued(
    &audit_store,
    user.id.to_string(),
    jwt_id.clone(),
    token_id.clone(),
    Some("192.168.1.1".to_string()),
).await?;
```

**Event Type:** `refresh_token_issued`

**Indexed Fields:** `user_id`, `jwt_id`, `ip_address`

**JSON Data Fields:** `token_id`

---

### log_refresh_token_revoked

Logs the revocation of a refresh token (logout, token rotation, etc.).

**Parameters:**
- `store: &AuditStore` - Reference to the audit store
- `user_id: String` - ID of the user whose refresh token was revoked
- `jwt_id: Option<String>` - Optional JWT identifier associated with this refresh token
- `token_id: String` - Unique identifier for the refresh token

**Usage:**
```rust
audit_logger::log_refresh_token_revoked(
    &audit_store,
    user.id.to_string(),
    Some(jwt_id.clone()),
    token_id.clone(),
).await?;
```

**Event Type:** `refresh_token_revoked`

**Indexed Fields:** `user_id`, `jwt_id`

**JSON Data Fields:** `token_id`

---

## AuditBuilder API

For custom events not covered by the helper functions, use the `AuditBuilder` fluent API. This provides type-safe construction of audit events with automatic sensitive data protection.

### Creating Custom Events

**Basic Pattern:**
```rust
use std::sync::Arc;
use crate::services::audit_logger::AuditBuilder;

AuditBuilder::new(audit_store.clone(), "custom_event_type")
    .user_id("user123")
    .ip_address("192.168.1.1")
    .jwt_id("jwt_abc123")
    .add_field("custom_field", "value")
    .write()
    .await?;
```

### Builder Methods

#### new(store, event_type)

Creates a new AuditBuilder instance.

**Parameters:**
- `store: Arc<AuditStore>` - Arc reference to the audit store
- `event_type: impl Into<EventType>` - Event type (string for custom events, or EventType enum)

**Returns:** `AuditBuilder`

---

#### user_id(id)

Sets the user ID for the audit event. **Required** - calling `write()` without setting user_id will return an error.

**Parameters:**
- `id: impl Into<String>` - User identifier

**Returns:** `Self` (for chaining)

---

#### ip_address(ip)

Sets the IP address for the audit event.

**Parameters:**
- `ip: impl Into<String>` - IP address

**Returns:** `Self` (for chaining)

---

#### jwt_id(id)

Sets the JWT identifier for the audit event.

**Parameters:**
- `id: impl Into<String>` - JWT identifier (jti claim)

**Returns:** `Self` (for chaining)

---

#### add_field(key, value)

Adds an arbitrary field to the audit event's JSON data.

**Parameters:**
- `key: impl Into<String>` - Field name
- `value: impl Serialize` - Field value (will be serialized to JSON)

**Returns:** `Self` (for chaining)

**Example:**
```rust
.add_field("action", "password_reset_requested")
.add_field("reset_token_id", "abc123")
.add_field("attempts", 3)
```

---

#### add_sensitive(key, value)

Adds a sensitive field with automatic SHA-256 hashing. The value is hashed before storage to prevent exposure while maintaining correlation capability.

**Parameters:**
- `key: impl Into<String>` - Field name
- `value: impl Serialize` - Field value (will be hashed)

**Returns:** `Self` (for chaining)

**Stored Format:** `sha256:<hex_hash>`

**Example:**
```rust
.add_sensitive("email", "user@example.com")
.add_sensitive("phone", "+1234567890")
```

**Use Cases:**
- Email addresses (correlate password reset requests)
- Phone numbers (track verification attempts)
- Session identifiers (correlate related events)

---

#### write()

Writes the audit event to the database. Validates that user_id is set.

**Returns:** `Result<(), AuditError>`

**Errors:**
- `AuditError::MissingUserId` - If user_id was not set
- `AuditError::DatabaseError` - If database operation fails

---

### Complete Example: Password Reset Flow

```rust
use std::sync::Arc;
use crate::services::audit_logger::AuditBuilder;
use crate::stores::audit_store::AuditStore;

async fn log_password_reset_requested(
    audit_store: Arc<AuditStore>,
    user_id: String,
    email: String,
    reset_token_id: String,
    ip_address: Option<String>,
) -> Result<(), AuditError> {
    let mut builder = AuditBuilder::new(audit_store, "password_reset_requested")
        .user_id(user_id)
        .add_field("reset_token_id", reset_token_id)
        .add_sensitive("email", email);
    
    if let Some(ip) = ip_address {
        builder = builder.ip_address(ip);
    }
    
    builder.write().await
}
```

---

## Security Guidelines

### Sensitive Data Types - NEVER LOG IN PLAINTEXT

The following data types MUST NEVER be logged in plaintext:

- **Passwords** (plaintext or hashed) - Never log passwords in any form
- **Full JWT Tokens** - Exception: `jwt_tampered` events for forensic analysis only
- **Refresh Tokens** (plaintext) - Log only token IDs or hashes
- **API Keys** - Never log API keys
- **Secrets** (JWT_SECRET, encryption keys, etc.) - Never log secrets
- **Credit Card Numbers** - Never log payment information
- **Social Security Numbers** - Never log PII identifiers
- **Private Keys** - Never log cryptographic keys

### When to Use add_sensitive()

Use `add_sensitive()` for data that needs correlation but should not be exposed:

**✅ Use add_sensitive() for:**
- Email addresses (correlate password reset requests across time)
- Phone numbers (track verification attempts)
- Session identifiers (correlate related events)
- Device identifiers (track device-specific patterns)
- IP addresses when privacy is a concern (though typically logged in plaintext for security monitoring)

**❌ Do NOT use add_sensitive() for:**
- Passwords (never log passwords at all)
- Full tokens (use token IDs instead)
- Data that doesn't need correlation (just omit it)
- Non-sensitive data (use `add_field()` instead)

### Correlation vs. Exposure

SHA-256 hashing allows correlation without exposure:
- Same input always produces the same hash
- Enables pattern detection (e.g., multiple password reset requests for same email)
- Cannot reverse the hash to recover the original value
- Protects user privacy while maintaining security monitoring capability

**Example:**
```rust
// ✅ CORRECT: Hash email for correlation
.add_sensitive("email", user.email)

// ❌ WRONG: Never log passwords
.add_field("password", password) // NEVER DO THIS

// ✅ CORRECT: Log token ID, not full token
.add_field("token_id", token_id)

// ❌ WRONG: Don't log full refresh token
.add_field("refresh_token", refresh_token) // NEVER DO THIS
```

---

## Database Schema

The audit logging system uses a hybrid schema with indexed columns for common queryable fields and a JSON column for event-specific data.

### Table: audit_events

```sql
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,           -- RFC3339 format (e.g., "2025-11-14T10:30:00Z")
    event_type TEXT NOT NULL,          -- Event type identifier
    user_id TEXT NOT NULL,             -- User identifier (or "unknown")
    ip_address TEXT,                   -- Optional IP address
    jwt_id TEXT,                       -- Optional JWT identifier (jti claim)
    data TEXT NOT NULL                 -- JSON object with event-specific fields
);

CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_jwt_id ON audit_events(jwt_id);
```

### Schema Design Rationale

**Indexed Columns:**
- `timestamp` - Fast time-range queries for security investigations
- `event_type` - Filter by specific event types (e.g., all login failures)
- `user_id` - Track all events for a specific user
- `jwt_id` - Correlate all events related to a specific JWT

**JSON Data Column:**
- Flexible storage for event-specific fields
- No schema changes needed for new event types
- SQLite JSON functions enable querying nested data

---

## Query Examples

### Filter by Time Range

```sql
-- Events in the last 24 hours
SELECT * FROM audit_events
WHERE timestamp >= datetime('now', '-1 day')
ORDER BY timestamp DESC;

-- Events between specific dates
SELECT * FROM audit_events
WHERE timestamp BETWEEN '2025-11-01T00:00:00Z' AND '2025-11-30T23:59:59Z'
ORDER BY timestamp DESC;
```

### Filter by Event Type

```sql
-- All login failures
SELECT * FROM audit_events
WHERE event_type = 'login_failure'
ORDER BY timestamp DESC;

-- All JWT-related events
SELECT * FROM audit_events
WHERE event_type LIKE 'jwt_%'
ORDER BY timestamp DESC;
```

### Filter by User ID

```sql
-- All events for a specific user
SELECT * FROM audit_events
WHERE user_id = 'user123'
ORDER BY timestamp DESC;

-- Login attempts for a specific user
SELECT * FROM audit_events
WHERE user_id = 'user123'
  AND event_type IN ('login_success', 'login_failure')
ORDER BY timestamp DESC;
```

### Filter by JWT ID

```sql
-- All events related to a specific JWT
SELECT * FROM audit_events
WHERE jwt_id = 'jwt_abc123'
ORDER BY timestamp DESC;
```

### Extract JSON Fields

```sql
-- Login failures with failure reasons
SELECT 
    timestamp,
    user_id,
    ip_address,
    json_extract(data, '$.failure_reason') as failure_reason
FROM audit_events
WHERE event_type = 'login_failure'
ORDER BY timestamp DESC;

-- JWT issuance with expiration times
SELECT 
    timestamp,
    user_id,
    jwt_id,
    json_extract(data, '$.expiration') as expiration
FROM audit_events
WHERE event_type = 'jwt_issued'
ORDER BY timestamp DESC;
```

### Complex Queries

```sql
-- Failed login attempts from same IP in last hour
SELECT 
    ip_address,
    COUNT(*) as attempt_count,
    GROUP_CONCAT(user_id) as attempted_users
FROM audit_events
WHERE event_type = 'login_failure'
  AND timestamp >= datetime('now', '-1 hour')
  AND ip_address IS NOT NULL
GROUP BY ip_address
HAVING attempt_count > 3
ORDER BY attempt_count DESC;

-- Users with multiple JWT validation failures (potential attack)
SELECT 
    user_id,
    COUNT(*) as failure_count,
    MIN(timestamp) as first_failure,
    MAX(timestamp) as last_failure
FROM audit_events
WHERE event_type = 'jwt_validation_failure'
  AND timestamp >= datetime('now', '-1 day')
GROUP BY user_id
HAVING failure_count > 5
ORDER BY failure_count DESC;
```

---

## Archival Procedures

The audit database grows over time and should be archived periodically for long-term storage and compliance.

### Manual Archival

**Step 1: Stop the application** (ensures no writes during copy)

**Step 2: Copy the audit database file**
```bash
# Windows (cmd)
copy audit.db audit_archive_2025-11-14.db

# Windows (PowerShell)
Copy-Item audit.db audit_archive_2025-11-14.db
```

**Step 3: Compress the archive** (optional)
```bash
# Windows (PowerShell with 7-Zip)
7z a audit_archive_2025-11-14.7z audit_archive_2025-11-14.db
```

**Step 4: Move to long-term storage**
```bash
# Move to archive directory
move audit_archive_2025-11-14.db C:\archives\audit\
```

**Step 5: Restart the application**

### Automated Archival (Future Enhancement)

Consider implementing automated archival with:
- Scheduled task to copy audit.db monthly
- Automatic compression and upload to cloud storage
- Retention policy (e.g., keep 90 days in active database, archive older events)
- Vacuum operation after archival to reclaim space

### Querying Archived Data

Archived audit databases can be queried directly using SQLite:

```bash
# Windows (cmd)
sqlite3 audit_archive_2025-11-14.db "SELECT * FROM audit_events WHERE user_id = 'user123';"
```

Or attach the archive to the active database for combined queries:

```sql
ATTACH DATABASE 'audit_archive_2025-11-14.db' AS archive;

SELECT * FROM archive.audit_events
WHERE user_id = 'user123'
UNION ALL
SELECT * FROM main.audit_events
WHERE user_id = 'user123'
ORDER BY timestamp DESC;
```

---

## Best Practices

1. **Always set user_id** - Required for all audit events (use "unknown" if truly unavailable)
2. **Use helper functions** - Prefer pre-defined helpers over AuditBuilder for common events
3. **Hash sensitive data** - Use `add_sensitive()` for data that needs correlation but not exposure
4. **Never log secrets** - Passwords, tokens, API keys, etc. should never be logged
5. **Include context** - Add relevant fields (IP address, JWT ID) to enable correlation
6. **Use descriptive event types** - Clear, consistent naming (e.g., "password_reset_requested")
7. **Archive regularly** - Prevent unbounded database growth
8. **Monitor for patterns** - Query audit logs regularly for security anomalies
9. **Test audit logging** - Verify events are written correctly in integration tests
10. **Document custom events** - Update this document when adding new event types

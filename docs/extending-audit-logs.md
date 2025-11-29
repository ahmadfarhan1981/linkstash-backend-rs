# Extending Audit Logs

## Overview

The audit logging system separates security-relevant events (audit logs) from operational logs. This document explains the design principles and patterns for extending the system with custom audit events.

**When to use this guide:** You're adding new features that need security audit trails (authentication, authorization, data access, privilege changes, etc.)

## Architecture

```
Application Code
    ↓
Helper Functions (log_login_success, log_jwt_issued, etc.)
    OR
AuditBuilder (for custom events)
    ↓
AuditStore (Repository)
    ↓
audit.db (SQLite)
```

**Key Design:**
- Dedicated SQLite database for long-term security event storage
- Indexed columns for common queryable fields (user_id, event_type, timestamp, jwt_id, ip_address)
- JSON data column for event-specific fields
- Pre-built helper functions for standard auth events (see `src/services/audit_logger.rs`)
- Builder API for custom events

---

## Core Design Principles

### 1. Actor/Target Separation

**The Problem:** Original audit logs stored the target user (who was affected) in the `user_id` field, making it impossible to distinguish between:
- A user logging in themselves (actor = target)
- An admin generating a token for another user (actor ≠ target)

**The Solution:** All audit events now separate:
- **Actor** (`user_id` field): Who performed the action
- **Target** (`target_user_id` in JSON data): Who was affected

**Example:**
```rust
// User logs in themselves
audit_logger::log_login_success(
    &audit_store,
    &ctx,  // ctx.actor_id = "unknown" (unauthenticated)
    user.id.to_string(),  // target = user who logged in
).await?;

// Future: Admin generates token for another user
audit_logger::log_jwt_issued(
    &audit_store,
    &ctx,  // ctx.actor_id = admin's user_id
    target_user.id.to_string(),  // target = user receiving token
    jwt_id,
    expiration,
).await?;
```

### 2. RequestContext Pattern

All audit logging functions accept a `RequestContext` that flows through all layers (API → Service → Store):

```rust
pub struct RequestContext {
    pub actor_id: String,        // Who is performing the action
    pub ip_address: Option<String>,
    pub request_id: String,      // For tracing across layers
    pub authenticated: bool,
    pub claims: Option<Claims>,  // Full JWT claims if authenticated
    pub source: RequestSource,   // API, CLI, or System
}
```

**Actor ID values:**
- Unauthenticated API: `"unknown"`
- Authenticated API: User ID from JWT (e.g., `"123"`)
- CLI operations: `"cli:command_name"` (e.g., `"cli:bootstrap"`)
- System operations: `"system:operation_name"` (e.g., `"system:cleanup"`)

**Creating RequestContext:**
```rust
// API endpoints (use helper)
let ctx = self.create_request_context(req, Some(auth)).await;

// CLI operations
let ctx = RequestContext::for_cli("bootstrap");

// System operations
let ctx = RequestContext::for_system("token_cleanup");
```

### 3. Log at Point of Action

The layer where an action occurs is responsible for logging it. Typically this is the **store layer** because:
- It has the most context about what actually happened
- Higher layers may fail before logging
- Creates complete audit trails even if higher layers fail

**Example:**
```rust
// Store layer (credential_store.rs)
pub async fn verify_credentials(&self, ctx: &RequestContext, ...) -> Result<...> {
    // Perform database operation
    let user = self.find_user_by_username(username).await?;
    
    // Log at point of action
    if password_valid {
        audit_logger::log_login_success(&self.audit_store, ctx, user.id).await?;
    } else {
        audit_logger::log_login_failure(&self.audit_store, ctx, "invalid_password", Some(username)).await?;
    }
}
```

### 4. Pre-built Helpers vs. Custom Events

**Use pre-built helpers for standard auth events:**

The system provides helper functions for common authentication and authorization events. See `src/services/audit_logger.rs` for the complete list, including:
- Login/logout events
- JWT issuance and validation
- Refresh token operations
- User creation and privilege changes
- Bootstrap and owner management

All helpers follow the same pattern: accept `RequestContext` and separate actor from target.

**Use AuditBuilder for custom events:**

When you need to log events not covered by the helpers, use the builder API:

```rust
AuditBuilder::new(audit_store.clone(), "password_reset_requested")
    .user_id(ctx.actor_id.clone())  // Actor who requested
    .ip_address(ctx.ip_address.clone().unwrap_or_default())
    .add_field("target_user_id", target_user_id)  // Who is affected
    .add_field("reset_token_id", reset_token_id)
    .add_sensitive("email", email)  // SHA-256 hashed
    .write()
    .await?;
```

---

## Security Guidelines

### Never Log in Plaintext

- **Passwords** (plaintext or hashed)
- **Full JWT Tokens** (exception: `jwt_tampered` events for forensics)
- **Refresh Tokens** (log only token IDs or hashes)
- **API Keys, Secrets, Private Keys**
- **Credit Card Numbers, SSNs, or other PII**

### When to Use add_sensitive()

Use `add_sensitive()` for data that needs correlation but should not be exposed. The value is SHA-256 hashed before storage:

**✅ Use for:**
- Email addresses (correlate password reset requests)
- Phone numbers (track verification attempts)
- Session identifiers (correlate related events)

**❌ Don't use for:**
- Passwords (never log at all)
- Full tokens (use token IDs)
- Non-sensitive data (use `add_field()`)

**Why it works:** Same input always produces the same hash, enabling pattern detection without exposing the original value.

---

## Database Schema

```sql
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,           -- RFC3339 format
    event_type TEXT NOT NULL,          -- Event type identifier
    user_id TEXT NOT NULL,             -- Actor ID (who performed action)
    ip_address TEXT,                   -- Optional IP address
    jwt_id TEXT,                       -- Optional JWT identifier
    data TEXT NOT NULL                 -- JSON object with event-specific fields
);

-- Indexes for fast queries
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_jwt_id ON audit_events(jwt_id);
```

**Design rationale:**
- Indexed columns for common queries (timestamp, event_type, user_id, jwt_id)
- JSON data column for flexibility (no schema changes for new event types)
- SQLite JSON functions enable querying nested data

---

## Query Patterns

### Actor vs. Target Queries

```sql
-- All actions performed BY a specific user (actor perspective)
SELECT event_type, timestamp, json_extract(data, '$.target_user_id') as target
FROM audit_events
WHERE user_id = '123'  -- Actor ID
ORDER BY timestamp DESC;

-- All actions performed ON a specific user (target perspective)
SELECT event_type, timestamp, user_id as actor
FROM audit_events
WHERE json_extract(data, '$.target_user_id') = '456'  -- Target user ID
ORDER BY timestamp DESC;

-- Distinguish self-actions from admin actions
SELECT 
    event_type,
    user_id as actor,
    json_extract(data, '$.target_user_id') as target,
    CASE 
        WHEN user_id = json_extract(data, '$.target_user_id') THEN 'self'
        WHEN user_id LIKE 'cli:%' THEN 'cli'
        WHEN user_id LIKE 'system:%' THEN 'system'
        ELSE 'admin'
    END as action_type
FROM audit_events
WHERE json_extract(data, '$.target_user_id') IS NOT NULL
ORDER BY timestamp DESC;
```

### Security Monitoring

```sql
-- Failed login attempts from same IP
SELECT ip_address, COUNT(*) as attempts
FROM audit_events
WHERE event_type = 'login_failure'
  AND timestamp >= datetime('now', '-1 hour')
GROUP BY ip_address
HAVING attempts > 3;

-- Users with multiple JWT validation failures
SELECT user_id, COUNT(*) as failures
FROM audit_events
WHERE event_type = 'jwt_validation_failure'
  AND timestamp >= datetime('now', '-1 day')
GROUP BY user_id
HAVING failures > 5;
```

---

## Best Practices

1. **Always pass RequestContext** - Captures actor, IP, request ID automatically
2. **Separate actor from target** - Use `ctx.actor_id` for who performed, `target_user_id` for who was affected
3. **Use helper functions first** - Check `src/services/audit_logger.rs` before building custom events
4. **Log at point of action** - Store layer typically logs (has most context, ensures logging even if higher layers fail)
5. **Hash sensitive data** - Use `add_sensitive()` for correlation without exposure
6. **Never log secrets** - Passwords, tokens, keys should never appear in logs
7. **Use descriptive event types** - Clear naming like `"password_reset_requested"`
8. **Archive regularly** - Prevent unbounded database growth
9. **Monitor for patterns** - Query logs regularly for security anomalies
10. **Test audit logging** - Verify events are written correctly

---

## Archival

The audit database grows over time. Archive periodically:

```bash
# Stop application, copy database
copy audit.db audit_archive_2025-11-14.db

# Compress (optional)
7z a audit_archive_2025-11-14.7z audit_archive_2025-11-14.db

# Move to long-term storage
move audit_archive_2025-11-14.db C:\archives\audit\
```

Query archived data by attaching to active database:

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

## Adding Custom Events

When adding new features that need audit logging:

1. **Check existing helpers** - See if `src/services/audit_logger.rs` has what you need
2. **If not, use AuditBuilder** - Follow the pattern above
3. **Follow actor/target separation** - Actor in `user_id`, target in JSON data
4. **Pass RequestContext** - Captures actor, IP, request ID
5. **Log at point of action** - Typically in store layer
6. **Hash sensitive data** - Use `add_sensitive()` for correlation
7. **Test it** - Verify events are written correctly
8. **Document it** - Add to this guide if it's a common pattern

**Example: Adding password reset logging**

```rust
// In password_reset_store.rs
pub async fn create_reset_token(&self, ctx: &RequestContext, user_id: &str, email: &str) -> Result<String> {
    let token_id = generate_token_id();
    
    // Store token in database
    self.store_token(user_id, &token_id).await?;
    
    // Log at point of action
    AuditBuilder::new(self.audit_store.clone(), "password_reset_requested")
        .user_id(ctx.actor_id.clone())  // Actor (who requested)
        .ip_address(ctx.ip_address.clone().unwrap_or_default())
        .add_field("target_user_id", user_id)  // Target (whose password)
        .add_field("reset_token_id", &token_id)
        .add_sensitive("email", email)  // Hashed for correlation
        .write()
        .await?;
    
    Ok(token_id)
}
```

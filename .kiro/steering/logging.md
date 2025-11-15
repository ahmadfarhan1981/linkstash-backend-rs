# Logging Approach

## Dual Logging System

The application uses two separate logging systems with distinct purposes:

1. **Application Logs** - Ephemeral operational logs for debugging and monitoring
   - Framework: `tracing` with `tracing-subscriber`
   - Output: Console and optional file rotation
   - Levels: DEBUG, INFO, WARN, ERROR
   - Purpose: Development, debugging, operational monitoring

2. **Audit Logs** - Long-term security event records
   - Storage: Dedicated SQLite database (`audit.db`)
   - Purpose: Security forensics, compliance, incident investigation
   - Retention: Configurable (default 90 days)
   - See: `.kiro/specs/structured-audit-logging/` for full specification

## Core Logging Principle: Log at the Point of Action

**Rule: The layer where an action occurs is responsible for logging it.**

### Rationale

- The layer closest to the action has the most context about what happened
- Higher layers may or may not log (defensive logging)
- Errors bubble up, but logging happens at the source
- Creates complete audit trails even if higher layers fail

### Example Flow

```
API Layer (auth.rs)
  ↓ calls
Service Layer (auth_service.rs)
  ↓ calls
Store Layer (credential_store.rs)
  ↓ DB write fails here
  ✓ Store logs the failure (with full context)
  ↓ returns error
Service Layer
  ↓ bubbles error up (may add additional logging)
API Layer
  ↓ returns error response (may add additional logging)
```

**Key Point:** The store MUST log because we cannot assume the API will. The API MAY also log for additional context, but the store's log is the source of truth.

## Request Context Pattern

To avoid parameter drilling (passing user_id, ip_address, jwt_id through every function), use a **RequestContext struct**.

### RequestContext Definition

```rust
pub struct RequestContext {
    pub user_id: Option<i64>,
    pub ip_address: Option<String>,
    pub jwt_id: Option<String>,
    pub request_id: String,  // UUID for tracing across layers
}
```

### Usage Pattern

```rust
// API layer creates context from request
let ctx = RequestContext {
    user_id: Some(claims.user_id),
    ip_address: Some(extract_ip(&req)),
    jwt_id: claims.jti.clone(),
    request_id: Uuid::new_v4().to_string(),
};

// Pass context through all layers
let result = auth_service.login(&ctx, credentials).await?;
  ↓
let user = credential_store.verify_credentials(&ctx, username, password).await?;
  ↓
// Store logs with full context
audit::log_login_success(&audit_store, &ctx).await?;
```

### Benefits

- Single parameter instead of 3-4 individual fields
- Easy to extend (add correlation IDs, trace IDs, tenant IDs, etc.)
- Cheap to clone (all fields are small)
- Clear ownership of contextual data
- Enables request tracing across layers

## When to Use Application Logs vs Audit Logs

### Application Logs (tracing macros)

Use for operational and debugging information:

```rust
tracing::info!("Starting server on {}", addr);
tracing::debug!("Processing request {}", request_id);
tracing::warn!("Database connection pool at 90% capacity");
tracing::error!("Failed to connect to database: {}", err);
```

**Characteristics:**
- Ephemeral (short retention)
- High volume acceptable
- For developers and operators
- Not for compliance

### Audit Logs (audit_logger service)

Use for security-relevant events:

```rust
audit::log_login_success(&audit_store, &ctx).await?;
audit::log_login_failure(&audit_store, &ctx, "invalid_password").await?;
audit::log_jwt_issued(&audit_store, &ctx, expiration).await?;
audit::log_jwt_tampered(&audit_store, &ctx, full_jwt, reason).await?;
```

**Characteristics:**
- Long-term retention (90+ days)
- Lower volume (security events only)
- For security auditors and compliance
- Immutable, append-only

**Rule of Thumb:** If it involves authentication, authorization, or data access, it's an audit event.

## Security Rules

### Never Log in Plaintext

- Passwords (plaintext or hashed)
- Valid JWT tokens (full token strings)
- Refresh tokens (full token strings)
- API keys
- Cryptographic secrets

### Safe to Log

- JWT identifiers (jti claim)
- Token identifiers (UUIDs)
- User IDs
- IP addresses
- Timestamps
- Event types and outcomes

### Exception: Forensic Logging

**Log full JWT when signature validation fails** - Invalid tokens cannot be used for replay attacks but provide forensic value for investigating tampering attempts.

```rust
// When JWT signature is invalid or token is malformed
audit::log_jwt_tampered(&audit_store, &ctx, full_jwt, "invalid_signature").await?;
```

## Layer Responsibilities

### API Layer (api/*)

- Create RequestContext from incoming request
- Extract user_id, ip_address, jwt_id from JWT claims
- Generate request_id for tracing
- Pass context to service layer
- MAY log high-level request/response info (application logs)
- MAY log API-specific audit events (rate limiting, etc.)

### Service Layer (services/*)

- Receive RequestContext from API
- Pass context to stores
- Orchestrate business logic
- MAY log business logic events (application logs)
- MAY log service-specific audit events

### Store Layer (stores/*)

- Receive RequestContext from service
- MUST log data access events (audit logs)
- MUST log database errors (application logs)
- Log at the point where DB operations occur

## Configuration

Logging is configured via environment variables:

```bash
# Application Logging
LOG_LEVEL=INFO                          # DEBUG, INFO, WARN, ERROR
APP_LOG_FILE=/var/log/linkstash/app.log # Optional file output
APP_LOG_RETENTION_DAYS=7                # File rotation

# Audit Logging
AUDIT_DB_PATH=/var/lib/linkstash/audit.db
AUDIT_LOG_RETENTION_DAYS=90
```

See `.env.example` for all available configuration options.

## Implementation Reference

For complete implementation details, see:
- Requirements: `.kiro/specs/structured-audit-logging/requirements.md`
- Design: `.kiro/specs/structured-audit-logging/design.md`
- Tasks: `.kiro/specs/structured-audit-logging/tasks.md`

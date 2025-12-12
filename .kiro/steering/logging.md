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

## Actor/Target Separation in Audit Logs

**CRITICAL RULE: Audit logs MUST separate WHO performed an action (actor) from WHO was affected (target).**

### The Pattern

- **Actor** (`ctx.actor_id`): Stored in `user_id` field (indexed) - WHO performed the action
- **Target** (`target_user_id` parameter): Stored in JSON data - WHO was affected by the action

### Why This Matters

Without separation, you cannot distinguish:
- User logging in themselves (actor = target)
- Admin generating token for another user (actor ≠ target)
- System operation affecting a user (actor = "system:...", target = user)

### Implementation

```rust
// CORRECT: Separate actor from target
audit::log_login_success(
    &audit_store,
    &ctx,                    // Contains actor_id ("unknown" or user_id from JWT)
    user.id.to_string(),     // Target user who logged in
).await?;

// CORRECT: Admin action on another user (future)
audit::log_jwt_issued(
    &audit_store,
    &ctx,                    // Contains actor_id (admin's user_id)
    target_user.id,          // Target user receiving JWT
    jwt_id,
    expiration,
).await?;

// WRONG: Don't pass target as actor
audit::log_login_success(&audit_store, user.id, ip).await?;  // OLD PATTERN - DON'T USE
```

### Query Implications

With actor/target separation, you can query:
- All actions performed BY a user (filter by `user_id`)
- All actions performed ON a user (filter by `json_extract(data, '$.target_user_id')`)
- Distinguish self-actions from admin actions

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
Coordinator Layer (auth_coordinator.rs)
  ↓ calls
Provider Layer (token_provider.rs, audit_logger_provider.rs)
  ↓ calls
Store Layer (credential_store.rs)
  ↓ DB write fails here
  ✓ Store logs the failure (with full context)
  ↓ returns error
Provider Layer
  ↓ bubbles error up (may add additional logging)
Coordinator Layer
  ↓ bubbles error up (may add additional logging)
API Layer
  ↓ returns error response (may add additional logging)
```

**Key Point:** The store MUST log because we cannot assume the API will. The API MAY also log for additional context, but the store's log is the source of truth.

## RequestContext Pattern

**CRITICAL: All audit logging MUST use RequestContext to capture actor information.**

### RequestContext Structure

```rust
pub struct RequestContext {
    pub actor_id: String,              // WHO performed the action
    pub ip_address: Option<String>,
    pub request_id: String,            // UUID for tracing across layers
    pub authenticated: bool,
    pub claims: Option<Claims>,        // Full JWT claims if authenticated
    pub source: RequestSource,         // API, CLI, or System
}
```

### Actor ID Values

The `actor_id` field identifies WHO performed the action:

- **Unauthenticated API requests**: `"unknown"`
- **Authenticated API requests**: User ID from JWT claims (e.g., `"123"`)
- **CLI operations**: `"cli:command_name"` (e.g., `"cli:bootstrap"`)
- **System operations**: `"system:operation_name"` (e.g., `"system:cleanup"`)

### Creating RequestContext

**API endpoints (use helper):**
```rust
// Authenticated endpoint
let ctx = self.create_request_context(req, Some(auth)).await;

// Unauthenticated endpoint
let ctx = self.create_request_context(req, None).await;
```

**CLI operations:**
```rust
let ctx = RequestContext::for_cli("bootstrap");
// ctx.actor_id = "cli:bootstrap"
```

**System operations:**
```rust
let ctx = RequestContext::for_system("token_cleanup");
// ctx.actor_id = "system:token_cleanup"
```

### Usage Pattern

```rust
// API layer creates context from request
let ctx = self.create_request_context(req, Some(auth)).await;

// Pass context through all layers
let result = auth_coordinator.login(&ctx, credentials).await?;
  ↓
let user = credential_store.verify_credentials(&ctx, username, password).await?;
  ↓
// Store logs with full context - actor_id extracted automatically
audit_logger_provider.log_login_success(&ctx, user.id).await?;
```

### Benefits

- Single parameter captures actor, IP, request ID, authentication state
- Actor/target separation (actor in ctx, target as separate parameter)
- Easy to extend (add correlation IDs, trace IDs, tenant IDs)
- Cheap to clone (all fields are small)
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

### Audit Logs (AuditLoggerProvider)

Use for security-relevant events:

```rust
// Login events - separate actor from target
audit::log_login_success(&audit_store, &ctx, target_user_id).await?;
audit::log_login_failure(&audit_store, &ctx, "invalid_password", Some(username)).await?;

// JWT events - actor issues JWT for target
audit::log_jwt_issued(&audit_store, &ctx, target_user_id, jwt_id, expiration).await?;
audit::log_jwt_validation_failure(&audit_store, &ctx, "expired").await?;
audit::log_jwt_tampered(&audit_store, &ctx, full_jwt, reason).await?;

// Refresh token events - actor operates on target's token
audit::log_refresh_token_issued(&audit_store, &ctx, target_user_id, jwt_id, token_id).await?;
audit::log_refresh_token_revoked(&audit_store, &ctx, target_user_id, token_id).await?;
```

**Characteristics:**
- Long-term retention (90+ days)
- Lower volume (security events only)
- For security auditors and compliance
- Immutable, append-only

**Rule of Thumb:** If it involves authentication, authorization, or data access, it's an audit event.

**Actor/Target Separation:** All audit functions accept `RequestContext` (contains actor) and separate `target_user_id` parameter (who was affected). This enables distinguishing between self-actions and admin actions.

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

**Rationale:** Tampered or malformed JWTs are safe to log in full because:
- They cannot be used for authentication (invalid signature/format)
- They provide forensic evidence of tampering attempts
- They help identify attack patterns and sources
- No replay attack risk since they're already invalid

**When to log full tokens:**
- JWT signature validation fails
- JWT is malformed or unparseable
- JWT claims are structurally invalid

**When NOT to log full tokens:**
- JWT is valid but expired (log only jti and expiration)
- JWT is valid but user is disabled (log only jti and user_id)
- Any scenario where the token could potentially be reused

## Layer Responsibilities

### API Layer (api/*)

**Responsibilities:**
- Create RequestContext using `create_request_context(req, auth)` helper
- Pass context to coordinator layer
- MAY log high-level request/response info (application logs)
- MAY log API-specific audit events (rate limiting, etc.)

**DO NOT:**
- Manually extract actor_id, ip_address, jwt_id (helper does this)
- Call coordinators or providers directly (use coordinators only)
- Call audit logging directly (let provider/store layers handle it)

### Coordinator Layer (coordinators/*)

**Responsibilities:**
- Receive RequestContext from API
- Pass context to providers and stores unchanged
- Orchestrate workflows by composing provider operations
- MAY log coordination events (application logs)

**DO NOT:**
- Modify RequestContext
- Skip passing context to providers/stores
- Contain business logic (pure orchestration only)
- Call other coordinators

### Provider Layer (providers/*)

**Responsibilities:**
- Receive RequestContext from coordinators
- Pass context to stores and other providers
- Contain business logic and domain operations
- MAY log business logic events (application logs)
- MAY perform audit logging through AuditLoggerProvider

**DO NOT:**
- Modify RequestContext
- Skip passing context to stores
- Call coordinators (upward calls prohibited)

### Store Layer (stores/*)

**Responsibilities:**
- Receive RequestContext from coordinator or provider
- MUST log data access events (audit logs) at point of action
- MUST log database errors (application logs)
- Pass RequestContext to audit logging functions

**Pattern:**
```rust
pub async fn verify_credentials(&self, ctx: &RequestContext, username: &str, password: &str) -> Result<User> {
    let user = self.find_user(username).await?;
    
    if verify_password(password, &user.password_hash) {
        // Log success at point of action
        audit::log_login_success(&self.audit_store, ctx, user.id.to_string()).await?;
        Ok(user)
    } else {
        // Log failure at point of action
        audit::log_login_failure(&self.audit_store, ctx, "invalid_password", Some(username)).await?;
        Err(AuthError::InvalidCredentials)
    }
}
```

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

## Quick Reference for AI Agents

### When Writing Audit Logging Code

**✅ DO:**
```rust
// 1. Accept RequestContext parameter
pub async fn my_store_function(&self, ctx: &RequestContext, ...) -> Result<...> {
    
    // 2. Perform database operation
    let result = self.db_operation().await?;
    
    // 3. Log at point of action with actor/target separation
    audit::log_event(
        &self.audit_store,
        ctx,                    // Actor information
        target_user_id,         // Who was affected
        // ... other params
    ).await?;
    
    Ok(result)
}
```

**❌ DON'T:**
```rust
// Don't pass target as actor
audit::log_event(&audit_store, user_id, ip).await?;

// Don't skip RequestContext
audit::log_event(&audit_store, "unknown").await?;

// Don't log in API layer (let store handle it)
// API should create context and pass it down
```

### Available Audit Functions

See `src/providers/audit_logger_provider.rs` for complete list:
- `log_login_success(ctx, target_user_id)`
- `log_login_failure(ctx, reason, username)`
- `log_jwt_issued(ctx, target_user_id, jwt_id, expiration)`
- `log_jwt_validation_failure(ctx, reason)`
- `log_refresh_token_issued(ctx, target_user_id, jwt_id, token_id)`
- `log_refresh_token_revoked(ctx, target_user_id, token_id)`
- And more...

All follow the pattern: `(ctx, target_params...)` - the AuditLoggerProvider handles the audit store internally

### Creating RequestContext

**API endpoints:**
```rust
let ctx = self.create_request_context(req, Some(auth)).await;  // Authenticated
let ctx = self.create_request_context(req, None).await;        // Unauthenticated
```

**CLI operations:**
```rust
let ctx = RequestContext::for_cli("command_name");
```

**System operations:**
```rust
let ctx = RequestContext::for_system("operation_name");
```

## Implementation Reference

For complete implementation details, see:
- Requirements: `.kiro/specs/structured-audit-logging/requirements.md`
- Design: `.kiro/specs/structured-audit-logging/design.md`
- Actor/Target Separation: `.kiro/specs/audit-actor-separation/`
- Extension Guide: `docs/extending-audit-logs.md`

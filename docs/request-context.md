# Request Context Pattern

## Overview

The Request Context pattern provides a consistent way to handle request metadata and authentication state across all API endpoints. Every request creates a `RequestContext` that flows through the API, service, and store layers.

## What is RequestContext?

`RequestContext` is a struct that contains:

```rust
pub struct RequestContext {
    pub actor_id: String,              // WHO performed the action
    pub ip_address: Option<String>,    // Client IP address
    pub request_id: String,            // UUID for tracing
    pub authenticated: bool,           // Authentication state
    pub claims: Option<Claims>,        // Full JWT claims if authenticated
    pub source: RequestSource,         // API, CLI, or System
}
```

**Key Fields:**

- **actor_id** - Identifies WHO performed the action (user ID, "unknown", "cli:command", "system:operation")
- **IP Address** - The client's IP address (extracted from X-Forwarded-For, X-Real-IP, or remote address)
- **Request ID** - A unique UUID for tracing this specific request through logs
- **Authentication State** - A boolean flag indicating if the request is authenticated
- **JWT Claims** - Full JWT claims (user ID, expiration, JWT ID) if authenticated
- **Source** - Where the request originated (API, CLI, or System)

## Why Use Request Context?

### 1. Single Source of Truth for Authentication

Instead of validating JWTs multiple times throughout your code, validation happens once when creating the context. All subsequent code simply checks the `authenticated` flag.

### 2. Request Tracing

The `request_id` field allows you to trace a single request across all log entries (application logs and audit logs), making debugging much easier.

### 3. Audit Logging

The context provides all the information needed for audit logs:
- **Who performed the action** (actor_id field)
- **Where they came from** (IP address)
- **When it happened** (timestamp + request_id for correlation)
- **Authentication state** (authenticated flag and claims)

**Actor/Target Separation:** The context contains the actor (who performed the action), while audit logging functions accept a separate `target_user_id` parameter (who was affected). This enables distinguishing between self-actions and admin actions.

### 4. Consistent Pattern

All endpoints follow the same pattern: create context first, check authentication, then proceed. This makes the codebase easier to understand and maintain.

### 5. No Parameter Drilling

Instead of passing `user_id`, `ip_address`, `jwt_id`, and `request_id` as separate parameters through every function, you pass one `RequestContext` object.

## How to Use Request Context

### In API Endpoints

Every endpoint should create a context as the first operation using the `create_request_context` helper:

**For authenticated endpoints:**
- Pass the `BearerAuth` token to the helper
- Check `ctx.authenticated` before proceeding
- Access user info from `ctx.claims`

**For unauthenticated endpoints:**
- Pass `None` to the helper
- Context will have IP address and request_id but no authentication

### In Service Layer

Services receive the context from the API layer and pass it to stores. Services can:
- Check authentication state if needed
- Access user information from claims
- Pass context to stores for audit logging

### In Store Layer

Stores receive the context and use it for:
- **Audit logging** (log at the point where database operations occur)
- **Application logging** (include request_id for tracing)
- **Authorization checks** (verify user owns the resource)

**Example with actor/target separation:**
```rust
pub async fn verify_credentials(
    &self, 
    ctx: &RequestContext,
    username: &str, 
    password: &str
) -> Result<String, InternalError> {
    let user = self.find_user_by_username(username).await?;
    
    if verify_password(password, &user.password_hash) {
        // Log success: actor from ctx, target is user who logged in
        audit::log_login_success(&self.audit_store, ctx, user.id.to_string()).await?;
        Ok(user.id.to_string())
    } else {
        // Log failure: actor from ctx, attempted username in details
        audit::log_login_failure(&self.audit_store, ctx, "invalid_password", Some(username)).await?;
        Err(CredentialError::InvalidCredentials.into())
    }
}
```

## Actor ID Values

The `actor_id` field identifies WHO performed the action. It varies based on the request source:

| Request Source | actor_id Value | Example |
|----------------|----------------|---------|
| Unauthenticated API | `"unknown"` | User not logged in |
| Authenticated API | User ID from JWT | `"123"` |
| CLI operations | `"cli:command_name"` | `"cli:bootstrap"` |
| System operations | `"system:operation_name"` | `"system:cleanup"` |

**Creating RequestContext:**

```rust
// API endpoints (use helper)
let ctx = self.create_request_context(req, Some(auth)).await;  // Authenticated
let ctx = self.create_request_context(req, None).await;        // Unauthenticated

// CLI operations
let ctx = RequestContext::for_cli("bootstrap");
// ctx.actor_id = "cli:bootstrap"

// System operations
let ctx = RequestContext::for_system("token_cleanup");
// ctx.actor_id = "system:token_cleanup"
```

## Authentication Flow

When you create a context with authentication:

1. Helper extracts IP address from request headers
2. Helper generates a unique request_id (UUID)
3. Helper validates the JWT token
4. If valid: sets `authenticated = true`, populates `claims`, sets `actor_id` from JWT subject
5. If invalid: sets `authenticated = false`, sets `actor_id = "unknown"`, logs failure to audit database

The validation uses the `validate_jwt` function which:
- Checks JWT signature
- Checks expiration
- Detects tampering
- Logs all failures to the audit database
- Extracts actor_id from JWT claims for audit logging

## What Endpoints Don't Need to Know

Endpoints don't need to know:
- **Why** authentication failed (expired, invalid signature, tampered)
- **How** to validate JWTs (helper handles it)
- **When** to log audit events (happens automatically)

Endpoints only need to know:
- **Is this request authenticated?** (check `ctx.authenticated`)
- **Who is the user?** (read `ctx.claims.sub`)

## Benefits for Developers

### Simpler Endpoint Code

Your endpoint code becomes simpler because you don't need to:
- Manually validate JWTs
- Extract user IDs from tokens
- Handle different JWT validation errors
- Manually log authentication failures

### Easier Testing

Testing is easier because:
- You can create mock contexts with specific authentication states
- You don't need to generate valid JWTs for every test
- You can test authenticated and unauthenticated paths easily

### Better Debugging

Debugging is easier because:
- Every log entry includes the request_id
- You can trace a request through all layers
- Audit logs automatically capture authentication failures

### Consistent Security

Security is more consistent because:
- All endpoints use the same authentication validation
- Audit logging happens automatically
- No risk of forgetting to validate authentication

## Actor/Target Separation in Audit Logs

**Critical Pattern:** Audit logs separate WHO performed an action (actor) from WHO was affected (target).

### The Pattern

- **Actor** (`ctx.actor_id`): Stored in `user_id` field - WHO performed the action
- **Target** (`target_user_id` parameter): Stored in JSON data - WHO was affected

### Why This Matters

Without separation, you cannot distinguish:
- User logging in themselves (actor = target)
- Admin generating token for another user (actor ≠ target)
- System operation affecting a user (actor = "system:...", target = user)

### Example

```rust
// User logs in themselves
audit::log_login_success(
    &audit_store,
    &ctx,                    // ctx.actor_id = "unknown" (unauthenticated)
    user.id.to_string(),     // target_user_id = user who logged in
).await?;

// Future: Admin generates token for another user
audit::log_jwt_issued(
    &audit_store,
    &ctx,                    // ctx.actor_id = admin's user_id
    target_user.id,          // target_user_id = user receiving token
    jwt_id,
    expiration,
).await?;
```

## Design Principles

This pattern follows our core logging principle: **log at the point of action**

- JWT validation happens in the helper → helper logs validation failures
- Database operations happen in stores → stores log data access
- Business logic happens in services → services log business events

The context provides the information needed for logging at each layer without requiring higher layers to handle it.

**Actor/Target Separation:** The context always contains the actor (who performed the action). Audit logging functions accept a separate `target_user_id` parameter when an action affects a specific user. This enables clear audit trails distinguishing between the actor and the target of each action.

## Future Enhancements

The RequestContext pattern is designed to be extensible. Future additions might include:

- Tenant ID for multi-tenant applications
- Correlation ID for distributed tracing
- User agent and device information
- Rate limiting metadata
- Feature flags or permissions

These can be added to the context without changing the pattern or breaking existing code.

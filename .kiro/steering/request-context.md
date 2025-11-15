# Request Context Pattern

## Overview

Every API endpoint MUST create a `RequestContext` at the beginning of the request using the `create_request_context` helper function. This context flows through all layers (API → Service → Store) carrying request metadata and authentication state.

**For detailed explanation of concepts and benefits, see `docs/request-context.md`**

## RequestContext Fields

- `ip_address` - Client IP from headers
- `request_id` - Unique UUID for tracing
- `authenticated` - Boolean auth state
- `claims` - Full JWT claims if authenticated

## Usage Pattern

### Creating Context

Every endpoint MUST call `create_request_context` as the first operation:

```rust
async fn my_endpoint(&self, req: &Request, auth: BearerAuth) -> Response {
    // ALWAYS call this first
    let ctx = self.create_request_context(req, Some(auth)).await;
    
    // Then check authentication if required
    if !ctx.authenticated {
        return Response::Unauthorized(...);
    }
    
    // Continue with business logic...
}
```

### For Authenticated Endpoints

Pass `Some(auth)` to validate JWT and populate claims:
- If JWT is valid: `ctx.authenticated = true`, `ctx.claims = Some(...)`
- If JWT is invalid/expired/tampered: `ctx.authenticated = false`, `ctx.claims = None`
- Validation failures are automatically logged to audit database

### For Unauthenticated Endpoints

Pass `None` for endpoints that don't require authentication:
- Context will have `authenticated = false`, `claims = None`
- Still captures IP address and request_id for logging

### Passing Context Through Layers

The context MUST be passed to service and store layers:

```rust
// API layer
let ctx = self.create_request_context(req, Some(auth)).await;
self.service.do_something(&ctx, other_params).await

// Service layer
pub async fn do_something(&self, ctx: &RequestContext, ...) -> Result<...> {
    self.store.write_data(ctx, data).await
}

// Store layer
pub async fn write_data(&self, ctx: &RequestContext, ...) -> Result<...> {
    // Log at point of action with full context
    audit::log_event(&self.audit_store, ctx, event_type).await
}
```

## Authentication State

Endpoints should check `ctx.authenticated` rather than validating JWT themselves:

- **DO**: `if !ctx.authenticated { return Unauthorized; }`
- **DON'T**: Call `validate_jwt` again in the endpoint

The helper function already validated the JWT using `validate_jwt`, which:
- Validates JWT signature and expiration
- Logs validation failures to audit database (expired, invalid signature, tampered)
- Returns claims on success

## Accessing User Information

When `ctx.authenticated = true`, access user info from claims:

```rust
let claims = ctx.claims.unwrap(); // Safe because authenticated=true
let user_id = claims.sub;
let jwt_id = claims.jti;
let expires_at = claims.exp;
```

## Critical Rules

1. **ALWAYS** create context first in every endpoint
2. **NEVER** validate JWT manually - use `ctx.authenticated` flag
3. **ALWAYS** pass context to service and store layers
4. **NEVER** call `validate_jwt` again after creating context
5. **ALWAYS** log at point of action using context

## Implementation Notes

- Helper reuses `validate_jwt` for all validation and audit logging
- Validation failures are logged automatically - endpoints don't handle this
- Context is cheap to clone (all small fields)
- See `docs/request-context.md` for rationale and detailed explanation

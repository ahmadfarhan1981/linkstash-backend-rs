# Request Context Pattern

## Overview

The Request Context pattern provides a consistent way to handle request metadata and authentication state across all API endpoints. Every request creates a `RequestContext` that flows through the API, service, and store layers.

## What is RequestContext?

`RequestContext` is a struct that contains:

- **IP Address** - The client's IP address (extracted from X-Forwarded-For, X-Real-IP, or remote address)
- **Request ID** - A unique UUID for tracing this specific request through logs
- **Authentication State** - A boolean flag indicating if the request is authenticated
- **JWT Claims** - Full JWT claims (user ID, expiration, JWT ID) if authenticated

## Why Use Request Context?

### 1. Single Source of Truth for Authentication

Instead of validating JWTs multiple times throughout your code, validation happens once when creating the context. All subsequent code simply checks the `authenticated` flag.

### 2. Request Tracing

The `request_id` field allows you to trace a single request across all log entries (application logs and audit logs), making debugging much easier.

### 3. Audit Logging

The context provides all the information needed for audit logs:
- Who made the request (from JWT claims)
- Where they came from (IP address)
- When it happened (timestamp + request_id for correlation)

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
- Audit logging (log at the point where database operations occur)
- Application logging (include request_id for tracing)
- Authorization checks (verify user owns the resource)

## Authentication Flow

When you create a context with authentication:

1. Helper extracts IP address from request headers
2. Helper generates a unique request_id (UUID)
3. Helper validates the JWT token
4. If valid: sets `authenticated = true` and populates `claims`
5. If invalid: sets `authenticated = false`, logs failure to audit database

The validation uses the `validate_jwt` function which:
- Checks JWT signature
- Checks expiration
- Detects tampering
- Logs all failures to the audit database

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

## Design Principles

This pattern follows our core logging principle: **log at the point of action**

- JWT validation happens in the helper → helper logs validation failures
- Database operations happen in stores → stores log data access
- Business logic happens in services → services log business events

The context provides the information needed for logging at each layer without requiring higher layers to handle it.

## Future Enhancements

The RequestContext pattern is designed to be extensible. Future additions might include:

- Tenant ID for multi-tenant applications
- Correlation ID for distributed tracing
- User agent and device information
- Rate limiting metadata
- Feature flags or permissions

These can be added to the context without changing the pattern or breaking existing code.

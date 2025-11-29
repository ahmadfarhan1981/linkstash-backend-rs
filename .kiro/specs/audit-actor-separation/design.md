# Design Document

## Overview

This design refactors the audit logging architecture to properly separate **actor** (who performs the action) from **target user** (who is affected by the action). Currently, audit events incorrectly use the target user as the `user_id`, making it impossible to trace who actually performed security-sensitive operations.

The fix involves:
1. Updating all audit logging functions to accept `RequestContext` as the primary source of actor information
2. Moving target user information into event details
3. Ensuring backward compatibility during the transition
4. Updating all call sites to pass RequestContext

## Architecture

### Current Architecture (Flawed)

```
API Layer
  ↓ extracts user_id from JWT claims
Service Layer  
  ↓ passes target_user_id as "user_id"
Audit Logger
  ↓ logs target_user_id in user_id field
Audit Database
  ✗ Cannot distinguish actor from target
```

### New Architecture (Correct)

```
API Layer
  ↓ creates RequestContext with actor_id
Service Layer
  ↓ passes RequestContext + target_user_id
Audit Logger
  ↓ extracts actor_id from ctx → user_id field
  ↓ puts target_user_id → event details
Audit Database
  ✓ Clear separation of actor and target
```

## Components and Interfaces

### RequestContext (Existing)

The `RequestContext` struct already contains the necessary fields:

```rust
pub struct RequestContext {
    pub ip_address: Option<String>,
    pub request_id: String,
    pub authenticated: bool,
    pub claims: Option<Claims>,
    pub source: RequestSource,
    pub actor_id: String,  // ← This is the key field
}
```

The `actor_id` field represents:
- For unauthenticated API requests: `"unknown"`
- For authenticated API requests: User ID from JWT claims
- For CLI operations: `"cli:command_name"`
- For system operations: `"system:operation_name"`

### Audit Logger Function Signatures

#### Before (Current - Incorrect)

```rust
pub async fn log_login_success(
    store: &AuditStore,
    user_id: String,  // ← This is the TARGET user, not the actor!
    ip_address: Option<String>,
) -> Result<(), InternalError>

pub async fn log_jwt_issued(
    store: &AuditStore,
    user_id: String,  // ← This is the TARGET user, not the actor!
    jwt_id: String,
    expiration: DateTime<Utc>,
    ip_address: Option<String>,
) -> Result<(), InternalError>

pub async fn log_refresh_token_issued(
    store: &AuditStore,
    user_id: String,  // ← This is the TARGET user, not the actor!
    jwt_id: String,
    token_id: String,
    ip_address: Option<String>,
) -> Result<(), InternalError>
```

#### After (New - Correct)

```rust
pub async fn log_login_success(
    store: &AuditStore,
    ctx: &RequestContext,  // ← Actor information
    target_user_id: String,  // ← Explicit target user
) -> Result<(), InternalError>

pub async fn log_jwt_issued(
    store: &AuditStore,
    ctx: &RequestContext,  // ← Actor information
    target_user_id: String,  // ← Explicit target user (JWT subject)
    jwt_id: String,
    expiration: DateTime<Utc>,
) -> Result<(), InternalError>

pub async fn log_refresh_token_issued(
    store: &AuditStore,
    ctx: &RequestContext,  // ← Actor information
    target_user_id: String,  // ← Explicit target user (token owner)
    jwt_id: String,
    token_id: String,
) -> Result<(), InternalError>
```

### Event Structure

#### Before (Current - Incorrect)

```json
{
  "event_type": "login_success",
  "user_id": "user-123",  // ← Target user (who logged in)
  "ip_address": "192.168.1.1",
  "timestamp": "2025-11-29T10:00:00Z"
}
```

**Problem**: Cannot tell if this was:
- An unauthenticated login by user-123
- An admin impersonating user-123
- A system operation creating a session for user-123

#### After (New - Correct)

```json
{
  "event_type": "login_success",
  "user_id": "unknown",  // ← Actor (unauthenticated)
  "ip_address": "192.168.1.1",
  "timestamp": "2025-11-29T10:00:00Z",
  "data": {
    "target_user_id": "user-123",  // ← Target user
    "request_id": "req-abc-123"
  }
}
```

**Benefit**: Clear distinction between actor and target.

## Data Models

### AuditEvent Structure (No Changes Required)

The existing `AuditEvent` structure already supports this pattern:

```rust
pub struct AuditEvent {
    pub event_type: EventType,
    pub user_id: Option<String>,  // ← Will contain actor_id
    pub ip_address: Option<String>,
    pub jwt_id: Option<String>,
    pub data: HashMap<String, serde_json::Value>,  // ← Will contain target_user_id
    pub timestamp: i64,
}
```

The `data` field is a flexible HashMap that can store additional context like `target_user_id`.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Actor identification consistency

*For any* audit event logged through the audit_logger module, the user_id field should always contain the actor_id from the RequestContext, never the target user ID.

**Validates: Requirements 1.1, 2.1, 2.2, 3.1, 3.3, 3.4, 4.1, 5.2**

### Property 2: Target user preservation

*For any* audit event where an action affects a specific user, the event details should contain a target_user_id field with the affected user's ID.

**Validates: Requirements 1.2, 2.3, 2.5, 3.2, 3.5, 4.2, 5.4**

### Property 3: Unauthenticated request identification

*For any* audit event originating from an unauthenticated request (RequestContext.authenticated = false), the user_id field should be "unknown" or a system identifier, never a user ID from the action target.

**Validates: Requirements 1.3, 2.1**

### Property 4: Authenticated request traceability

*For any* audit event originating from an authenticated request (RequestContext.authenticated = true), the user_id field should match the sub claim from the JWT in RequestContext.claims.

**Validates: Requirements 1.4, 2.2**

### Property 5: System operation identification

*For any* audit event originating from a system operation (RequestContext.source = System), the user_id field should have a "system:" prefix.

**Validates: Requirements 1.5**

### Property 6: Failed login username preservation

*For any* failed login audit event, the event details should contain the attempted username.

**Validates: Requirements 2.4**

### Property 7: JWT validation failure actor extraction

*For any* JWT validation failure audit event, the user_id field should contain the sub claim from the JWT claims (even if the JWT is invalid), allowing tracing of who attempted to use the invalid token.

**Validates: Requirements 4.3**

### Property 8: JWT tampering actor extraction

*For any* JWT tampering audit event, the user_id field should contain the sub claim from the unverified JWT claims, allowing forensic analysis of tampering attempts.

**Validates: Requirements 4.4**

### Property 9: No redundant validation success events

*For any* successful JWT validation, the system should NOT create a separate audit event, as validation success is implicit in subsequent authenticated actions.

**Validates: Requirements 4.5**

## Error Handling

### Backward Compatibility

During the transition, we need to handle:

1. **Function Signature Changes**: All audit logging functions will change signatures
   - Old signatures will be removed
   - All call sites must be updated atomically
   - Compilation will fail if any call site is missed (type safety)

2. **Event Structure Changes**: Event details will include new fields
   - Old events (without target_user_id) remain valid
   - New events will have target_user_id in details
   - Audit queries should handle both formats

### Error Scenarios

1. **Missing RequestContext**: Compilation error (required parameter)
2. **Missing actor_id in RequestContext**: Should never happen (always set in constructors)
3. **Audit logging failure**: Already handled - errors are logged but don't fail the operation

## Testing Strategy

### Unit Tests

1. **Test audit event structure**:
   - Verify user_id contains actor_id from RequestContext
   - Verify target_user_id is in event details
   - Test with authenticated and unauthenticated contexts

2. **Test each audit logging function**:
   - `log_login_success`: actor_id → user_id, target → details
   - `log_jwt_issued`: actor_id → user_id, JWT subject → details
   - `log_refresh_token_issued`: actor_id → user_id, token owner → details

3. **Test RequestContext scenarios**:
   - Unauthenticated request (actor_id = "unknown")
   - Authenticated request (actor_id from JWT)
   - CLI operation (actor_id = "cli:command")
   - System operation (actor_id = "system:operation")

### Integration Tests

1. **End-to-end login flow**:
   - Unauthenticated user logs in
   - Verify audit event has actor_id = "unknown"
   - Verify audit event has target_user_id in details

2. **Admin impersonation scenario** (future):
   - Admin generates JWT for another user
   - Verify audit event has actor_id = admin's user_id
   - Verify audit event has target_user_id = target user's ID

3. **Token refresh flow**:
   - User refreshes token
   - Verify audit event has actor_id from JWT
   - Verify audit event has target_user_id in details

### Property-Based Tests

Property-based testing will be used to verify the correctness properties defined above. We'll use the `proptest` crate for Rust.

**Test Strategy**:
- Generate random RequestContext instances with various actor_id values
- Generate random target_user_id values
- Call audit logging functions
- Verify properties hold across all generated inputs

## Implementation Plan

### Phase 1: Update Audit Logger Functions

1. Update function signatures to accept `RequestContext`
2. Extract `actor_id` from context for `user_id` field
3. Add `target_user_id` parameter where applicable
4. Store `target_user_id` in event details
5. Update function documentation

### Phase 2: Update Call Sites

1. **TokenService.generate_jwt**:
   - Accept `RequestContext` parameter
   - Pass context to `log_jwt_issued`
   - Pass JWT subject as `target_user_id`

2. **CredentialStore.verify_credentials**:
   - Accept `RequestContext` parameter
   - Pass context to `log_login_success`
   - Pass authenticated user as `target_user_id`

3. **CredentialStore.store_refresh_token**:
   - Accept `RequestContext` parameter
   - Pass context to `log_refresh_token_issued`
   - Pass token owner as `target_user_id`

4. **AuthService.login**:
   - Already has `RequestContext`
   - Pass context through to stores and services

5. **AuthService.refresh**:
   - Already has `RequestContext`
   - Pass context through to stores and services

### Phase 3: Update API Layer

1. Ensure all API endpoints create proper `RequestContext`
2. Set `actor_id` based on authentication state:
   - Unauthenticated: `"unknown"`
   - Authenticated: User ID from JWT claims
3. Pass context through to service layer

### Phase 4: Testing and Validation

1. Run all unit tests
2. Run integration tests
3. Manually verify audit logs show correct actor/target separation
4. Update documentation

## Migration Strategy

This is a breaking change to internal APIs but not to external APIs. The migration is straightforward:

1. **Compile-time safety**: Type system ensures all call sites are updated
2. **No data migration**: Existing audit events remain valid
3. **Immediate benefit**: New events immediately show correct actor/target separation

## Documentation Updates

The following documentation needs updates:

1. **docs/extending-audit-logs.md**: Update examples to show new signatures
2. **.kiro/steering/logging.md**: Update audit logging patterns
3. **Function doc comments**: Update all affected functions

## Security Considerations

### Benefits

1. **Accountability**: Clear attribution of actions to actors
2. **Forensics**: Easier to trace unauthorized access attempts
3. **Compliance**: Meets audit requirements for "who did what"
4. **Attack Detection**: Can identify impersonation or privilege escalation

### Risks

None. This change improves security by fixing a fundamental flaw in the audit logging architecture.

## Performance Considerations

**Impact**: Negligible

- `RequestContext` is already created and passed through layers
- Extracting `actor_id` is a simple field access
- Adding `target_user_id` to event details is a HashMap insert

## Future Enhancements

1. **Audit Query API**: Build queries that filter by actor or target
2. **Admin Impersonation**: When implemented, will automatically log correctly
3. **Audit Dashboard**: Visualize actor/target relationships
4. **Anomaly Detection**: Detect unusual actor/target patterns

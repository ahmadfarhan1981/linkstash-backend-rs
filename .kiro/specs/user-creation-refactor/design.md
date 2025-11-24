# Design Document

## Overview

This document describes the user creation and privilege management system architecture. The system provides clear separation of concerns between user creation and privilege assignment, comprehensive audit logging for all operations, and consistent request context across all operation sources (API, CLI, System).

The architecture uses a composition-based approach where user creation and privilege assignment are separate, atomic operations that can be combined as needed for different workflows.

## Architecture

The system is organized into three layers:

1. **Primitive Operations Layer**: Atomic operations for user creation and privilege management
2. **Helper Methods Layer**: Convenience methods that compose primitives for common workflows
3. **Application Layer**: API endpoints and CLI commands that use helpers or primitives

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│                  (API Endpoints, CLI Commands)               │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Creates RequestContext
                            │ (with source: API/CLI/System)
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     Helper Methods Layer                     │
│         (create_admin_user, create_owner_user, etc.)        │
│                                                              │
│  Composes primitive operations for common workflows         │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Calls primitives
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  Primitive Operations Layer                  │
│                                                              │
│  • create_user(ctx, username, password_hash)                │
│  • set_privileges(ctx, user_id, new_privileges)             │
│                                                              │
│  Each primitive logs to audit database at point of action   │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Database operations
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      Database Layer                          │
│                  (Users table, Audit table)                  │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### RequestContext

```rust
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// IP address of the client (optional for CLI operations)
    pub ip_address: Option<String>,
    
    /// Unique identifier for this request
    pub request_id: String,
    
    /// Whether the request is authenticated
    pub authenticated: bool,
    
    /// Full JWT claims if authenticated
    pub claims: Option<Claims>,
    
    /// Source of the request
    pub source: RequestSource,
    
    /// Actor who initiated the operation
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSource {
    /// Request originated from API endpoint
    API,
    
    /// Request originated from CLI command
    CLI,
    
    /// Request originated from system (automated operations)
    System,
}
```

### CredentialStore Primitive Methods

```rust
impl CredentialStore {
    /// Create a new user with no administrative privileges
    /// 
    /// This is the primitive operation for user creation. All user creation
    /// paths must ultimately call this method.
    /// 
    /// Audit logging occurs AFTER the database transaction commits to ensure
    /// consistency between the database state and audit logs.
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `username` - Username for the new user
    /// * `password_hash` - Pre-hashed password (caller is responsible for hashing)
    /// 
    /// # Returns
    /// * `Ok(user_id)` - User created successfully and audit logged
    /// * `Err(AuthError)` - Duplicate username, database error, or transaction failed
    pub async fn create_user(
        &self,
        ctx: &RequestContext,
        username: String,
        password_hash: String,
    ) -> Result<String, AuthError>;
    
    /// Set privileges for a user
    /// 
    /// This is the primitive operation for privilege assignment. It updates
    /// all privilege flags atomically and logs the before/after state.
    /// This design makes it easy to add new privilege flags in the future
    /// and provides a complete audit trail of privilege changes.
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `user_id` - User ID to modify
    /// * `new_privileges` - New privilege flags to set
    /// 
    /// # Returns
    /// * `Ok(old_privileges)` - Privileges updated successfully, returns previous state
    /// * `Err(AuthError)` - User not found or database error
    pub async fn set_privileges(
        &self,
        ctx: &RequestContext,
        user_id: &str,
        new_privileges: AdminFlags,
    ) -> Result<AdminFlags, AuthError>;
}
```

### CredentialStore Helper Methods

```rust
impl CredentialStore {
    /// Create a user with administrative privileges (helper method)
    /// 
    /// This is a convenience method that composes the primitive operations
    /// within a single transaction. The entire operation (user creation +
    /// privilege assignment) is atomic - if any step fails, everything rolls back.
    /// 
    /// Audit logging occurs AFTER the transaction commits successfully, ensuring
    /// audit logs accurately reflect the committed database state.
    /// 
    /// # Arguments
    /// * `ctx` - Request context for audit logging
    /// * `username` - Username for the new user
    /// * `password_hash` - Pre-hashed password
    /// * `admin_flags` - Administrative privileges to assign
    /// 
    /// # Returns
    /// * `Ok(user_model)` - User created, privileges assigned, and all operations audited
    /// * `Err(AuthError)` - Creation or privilege assignment failed (transaction rolled back)
    /// 
    /// # Implementation
    /// 
    /// 1. Begin transaction
    /// 2. Call create_user() primitive (logs user creation immediately)
    /// 3. Call set_privileges() primitive (logs privilege change with before/after state)
    /// 4. Commit transaction
    /// 5. If commit fails, log rollback event
    /// 
    /// Audit logging occurs at point of action (steps 2-3), not deferred.
    /// If transaction rolls back, a rollback event is logged.
    pub async fn create_admin_user(
        &self,
        ctx: &RequestContext,
        username: String,
        password_hash: String,
        admin_flags: AdminFlags,
    ) -> Result<user::Model, AuthError>;
}
```

### CLI Context Creation

```rust
impl RequestContext {
    /// Create a RequestContext for CLI operations
    /// 
    /// # Arguments
    /// * `command_name` - Name of the CLI command being executed
    /// 
    /// # Returns
    /// * RequestContext configured for CLI source
    pub fn for_cli(command_name: &str) -> Self {
        Self {
            ip_address: Some("localhost".to_string()),
            request_id: Uuid::new_v4().to_string(),
            authenticated: false,
            claims: None,
            source: RequestSource::CLI,
            actor_id: format!("cli:{}", command_name),
        }
    }
    
    /// Create a RequestContext for system operations
    pub fn for_system(operation_name: &str) -> Self {
        Self {
            ip_address: None,
            request_id: Uuid::new_v4().to_string(),
            authenticated: false,
            claims: None,
            source: RequestSource::System,
            actor_id: format!("system:{}", operation_name),
        }
    }
}
```

### Audit Logger Extensions

```rust
/// Log CLI session start
pub async fn log_cli_session_start(
    store: &AuditStore,
    ctx: &RequestContext,
    command_name: &str,
    args: Vec<String>,
) -> Result<(), AuditError>;

/// Log CLI session end
pub async fn log_cli_session_end(
    store: &AuditStore,
    ctx: &RequestContext,
    command_name: &str,
    success: bool,
    error_message: Option<String>,
) -> Result<(), AuditError>;

/// Log user creation (primitive operation)
pub async fn log_user_created(
    store: &AuditStore,
    ctx: &RequestContext,
    user_id: &str,
    username: &str,
) -> Result<(), AuditError>;

/// Log privilege change (assignment/removal)
/// 
/// Logs the before and after state of all privilege flags.
/// This provides a complete audit trail of what changed.
pub async fn log_privileges_changed(
    store: &AuditStore,
    ctx: &RequestContext,
    target_user_id: &str,
    old_privileges: &AdminFlags,
    new_privileges: &AdminFlags,
) -> Result<(), AuditError>;

/// Log operation rollback
pub async fn log_operation_rolled_back(
    store: &AuditStore,
    ctx: &RequestContext,
    operation_type: &str,
    reason: &str,
    affected_user_id: Option<&str>,
) -> Result<(), AuditError>;
```

## Data Models

### EventType Extensions

```rust
pub enum EventType {
    // ... existing variants ...
    
    // CLI session events
    CliSessionStart,
    CliSessionEnd,
    
    // User management events
    UserCreated,
    PrivilegesChanged,
    OperationRolledBack,
}
```

### Audit Event Data Fields

For user creation events:
- `user_id`: ID of the created user
- `username`: Username of the created user
- `source`: Request source (API/CLI/System)
- `actor_id`: Who initiated the operation

For privilege change events:
- `target_user_id`: ID of the user whose privileges changed
- `old_is_owner`: Previous owner flag value
- `new_is_owner`: New owner flag value
- `old_is_system_admin`: Previous system admin flag value
- `new_is_system_admin`: New system admin flag value
- `old_is_role_admin`: Previous role admin flag value
- `new_is_role_admin`: New role admin flag value
- `source`: Request source
- `actor_id`: Who initiated the operation

For CLI session events:
- `command_name`: Name of the CLI command
- `args`: Command arguments (sanitized, no sensitive data)
- `success`: Whether the command succeeded
- `error_message`: Error message if failed

For operation rollback events:
- `operation_type`: Type of operation that was rolled back (e.g., "user_creation_with_privileges")
- `reason`: Reason for rollback (e.g., "privilege_assignment_failed")
- `affected_user_id`: User ID involved in the rolled-back operation (if applicable)
- `source`: Request source
- `actor_id`: Who initiated the operation

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Primitive user creation never assigns privileges

*For any* username and password hash, when creating a user via the primitive `create_user` method, the created user should have all privilege flags (is_owner, is_system_admin, is_role_admin) set to false.

**Validates: Requirements 1.1, 1.2**

### Property 2: User creation is audited

*For any* user creation operation, the audit database should contain a user creation event with the correct user_id, username, and request source.

**Validates: Requirements 1.5**

### Property 3: Privilege changes are audited with before/after state

*For any* privilege change operation, the audit database should contain a privileges_changed event with the correct target user_id, old privilege flags, and new privilege flags.

**Validates: Requirements 2.2, 2.3**

### Property 4: Privilege changes are atomic

*For any* call to `set_privileges()`, either all privilege flags are updated together or none are updated (transaction atomicity).

**Validates: Requirements 2.5**

### Property 5: CLI operations have CLI source

*For any* operation initiated from a CLI command, the RequestContext should have source set to RequestSource::CLI and actor_id should be prefixed with "cli:".

**Validates: Requirements 4.2, 6.2**

### Property 6: API operations have API source

*For any* operation initiated from an API endpoint with valid JWT, the RequestContext should have source set to RequestSource::API and actor_id should match the JWT subject.

**Validates: Requirements 4.3, 6.3**

### Property 7: System operations have System source

*For any* automated system operation, the RequestContext should have source set to RequestSource::System and actor_id should be prefixed with "system:".

**Validates: Requirements 4.4, 6.4**

### Property 8: Audit logs include request source

*For any* user creation or privilege change event in the audit log, the event data should include the request source field.

**Validates: Requirements 4.5**

### Property 9: CLI session start is audited

*For any* CLI command execution, the audit database should contain a CLI session start event with the command name and sanitized arguments.

**Validates: Requirements 5.1, 5.4**

### Property 10: CLI session end is audited with correct status

*For any* CLI command execution, the audit database should contain a CLI session end event with success status matching the actual outcome (true for success, false for failure).

**Validates: Requirements 5.2, 5.3**

### Property 11: CLI session events have correct context

*For any* CLI session event (start or end), the event should be logged with a RequestContext having CLI source and appropriate actor identification.

**Validates: Requirements 5.5**

## Error Handling

### Partial Creation Handling

When a helper method fails during privilege assignment after successfully creating a user, use database transactions to ensure atomicity. If privilege assignment fails, the entire operation (user creation + privilege assignment) is rolled back.

**Implementation**: Use SeaORM's `TransactionTrait` to wrap the entire operation in a transaction.

### Audit Logging at Point of Action

Following the existing pattern in the codebase, audit logs are written **at the point of action** (when the database operation occurs), not deferred until after transaction commit.

**Rationale**:
- Maintains consistency with existing codebase patterns
- Provides immediate audit trail even if subsequent operations fail
- Allows tracking of partial operations and rollbacks

**Handling Rollbacks**:

When a transaction rolls back after audit logs have been written, we log an additional rollback event:

```rust
// Start transaction
let txn = self.db.begin().await?;

// Create user and log immediately
let user_id = create_user_in_db(&txn, username, password_hash).await?;
log_user_created(&audit_store, ctx, user_id, username).await
    .unwrap_or_else(|e| tracing::error!("Failed to log user creation: {:?}", e));

// Attempt privilege assignment and log immediately
match set_privilege_in_db(&txn, user_id, privilege).await {
    Ok(_) => {
        log_privilege_assigned(&audit_store, ctx, user_id, privilege_type).await
            .unwrap_or_else(|e| tracing::error!("Failed to log privilege assignment: {:?}", e));
        
        // Commit transaction
        txn.commit().await?;
    }
    Err(e) => {
        // Log the rollback event
        log_operation_rolled_back(&audit_store, ctx, "privilege_assignment_failed", user_id).await
            .unwrap_or_else(|e| tracing::error!("Failed to log rollback: {:?}", e));
        
        // Transaction automatically rolls back when dropped
        return Err(e);
    }
}
```

**Key Principles**:

1. **Log at Point of Action**: Write audit logs immediately when operations occur, not deferred
2. **Log Rollbacks**: When a transaction rolls back, log an additional rollback event to the audit database
3. **Never Block on Audit Failures**: If audit logging fails, log to application logs (tracing) but continue with the operation
4. **Loud Failures**: Audit logging failures should be highly visible in application logs for monitoring and alerting

**Benefits**:

- **Immediate Audit Trail**: Audit events are available immediately, even for operations that later fail
- **Rollback Visibility**: Explicit rollback events provide forensic value for understanding failures
- **Operation Continuity**: Application continues functioning even if audit database has issues
- **Consistent Pattern**: Matches existing codebase behavior

**Trade-offs**:

- **Orphaned Events**: Audit logs may contain events for operations that were rolled back (mitigated by rollback events)
- **Best Effort**: Audit logging is best-effort, not guaranteed (acceptable for audit logs, which are for forensics not correctness)

### Error Types

- `AuthError::DuplicateUsername`: Username already exists
- `AuthError::UserNotFound`: User ID not found when assigning privileges
- `AuthError::InternalError`: Database or other internal errors
- `AuthError::TransactionFailed`: Transaction commit failed

### Audit Logging Failures

Following the existing pattern in the codebase, if audit logging fails:

1. Log the failure using application logs (tracing) with ERROR level
2. Include the operation details (user_id, operation type, error) in the error log
3. **Continue with the operation** - do NOT fail the database transaction due to audit logging failures
4. Operations team can detect audit logging issues via application log monitoring

**Example Pattern** (already used in codebase):

```rust
if let Err(audit_err) = audit_logger::log_user_created(
    &self.audit_store,
    ctx,
    user_id,
    username,
).await {
    tracing::error!("Failed to log user creation: {:?}", audit_err);
}
// Continue with operation regardless of audit logging result
```

**Rationale**: Audit logs are for forensics and compliance, not for application correctness. The application should remain functional even if the audit database is temporarily unavailable.

## Testing Strategy

### Unit Tests

Unit tests will verify:
- `create_user` sets all privilege flags to false
- Each privilege assignment method updates only the specified flag
- Helper methods call primitives in the correct order
- RequestContext is correctly populated for different sources
- Duplicate username detection works correctly
- User not found errors are returned appropriately

### Property-Based Tests

Property-based tests will use the `proptest` crate (Rust's property testing library) with a minimum of 100 iterations per test.

Each property-based test will be tagged with a comment explicitly referencing the correctness property from the design document using this format: `// Feature: user-creation-refactor, Property {number}: {property_text}`

Property tests will verify:
- Property 1: Generated users never have privileges after `create_user`
- Property 3: Audit logs contain separate events for creation and privilege assignment
- Property 5: All operations receive and use RequestContext
- Property 6-7: Source field matches operation origin
- Property 9: Actor identification is consistent with source

### Integration Tests

Integration tests will verify:
- End-to-end user creation with privilege assignment
- CLI command execution with proper audit logging
- Backward compatibility with existing code
- Transaction rollback on privilege assignment failure

### Test Data Generation

For property-based tests, generators will produce:
- Random usernames (valid format)
- Random password hashes (valid Argon2 format)
- Random privilege combinations
- Random RequestContext configurations with different sources

## Migration Strategy

### Phase 1: Add New Methods (Non-Breaking)

1. Add `RequestSource` enum and extend `RequestContext`
2. Add primitive methods (`create_user`, `set_*_privilege`)
3. Add new audit logging functions
4. Add helper method constructors for RequestContext

### Phase 2: Update Existing Methods (Breaking)

1. Update `create_admin_user` to accept `RequestContext` instead of individual parameters
2. Refactor `create_admin_user` to use primitives internally
3. Update `set_system_admin` and `set_role_admin` to accept `RequestContext`
4. Rename existing methods to `set_system_admin_privilege` and `set_role_admin_privilege`

### Phase 3: Update Callers

1. Update CLI commands to create RequestContext
2. Update API endpoints to pass RequestContext
3. Add CLI session lifecycle logging
4. Update bootstrap process to use new methods

### Phase 4: Deprecate Old Methods

1. Mark old method signatures as deprecated
2. Provide migration guide in documentation
3. Remove old methods in next major version

### Backward Compatibility

During migration, maintain backward compatibility by:
- Keeping old method signatures that internally create a default RequestContext
- Providing adapter methods that convert old parameter lists to RequestContext
- Documenting the migration path clearly

## Documentation

Documentation will be added to `docs/user-creation-refactor.md` covering:

1. **Overview**: Explanation of the refactoring and its benefits
2. **Primitive Operations**: Detailed description of each primitive method
3. **Helper Methods**: When to use helpers vs. primitives
4. **RequestContext**: How to create context for different sources
5. **Migration Guide**: Step-by-step guide for updating existing code
6. **Examples**: Code examples for common scenarios
   - Creating a regular user
   - Creating an admin user
   - Assigning privileges to existing users
   - CLI command implementation
   - API endpoint implementation

# Authorization and User Levels

## Overview

This document provides a comprehensive overview of the authorization model in the Linkstash authentication backend. It explains the different user levels, their capabilities, and the design rationale behind the hierarchical permission structure.

## Table of Contents

1. [User Levels](#user-levels)
2. [Authorization Matrix](#authorization-matrix)
3. [Design Rationale](#design-rationale)
4. [Self-Modification Prevention](#self-modification-prevention)
5. [Token Invalidation](#token-invalidation)
6. [API Reference](#api-reference)

---

## User Levels

The system implements a four-tier user hierarchy, each with distinct capabilities and use cases.

### Understanding Admin Flags

User levels are determined by **three independent boolean flags** in the database and JWT claims:
- `is_owner` - Grants owner privileges
- `is_system_admin` - Grants system admin privileges  
- `is_role_admin` - Grants role admin privileges

**Key Points:**
- **Flags are independent** - Each flag can be true or false regardless of the others
- **Multiple roles possible** - A user can have multiple flags set to true simultaneously (e.g., both System Admin and Role Admin)
- **Single flag defines role** - A user is a System Admin if `is_system_admin=true`, regardless of other flags
- **Regular User = all false** - A user is a Regular User only when all three flags are false

**Example combinations:**
```
is_owner=false, is_system_admin=true,  is_role_admin=false  → System Admin
is_owner=false, is_system_admin=true,  is_role_admin=true   → System Admin + Role Admin
is_owner=true,  is_system_admin=false, is_role_admin=false  → Owner only
is_owner=true,  is_system_admin=true,  is_role_admin=false  → Owner + System Admin (impractical)
```

**Note on Owner combinations:** While technically possible to combine Owner with other admin roles, it's impractical because the Owner account is frequently deactivated and cannot log in when inactive.

### Regular User

**Purpose:** Standard authenticated user with basic access

**Capabilities:**
- Authenticate via `/auth/login` endpoint
- Refresh access tokens via `/auth/refresh` endpoint
- View own user information via `/auth/whoami` endpoint
- Logout and revoke tokens via `/auth/logout` endpoint

**Admin Flags:**
- `is_owner`: false
- `is_system_admin`: false
- `is_role_admin`: false

**Note:** These flags are independent. A user is a Regular User when **all three flags are false**.

**Status:** ACTIVE by default

**Quantity:** Unlimited

**Use Case:** Regular application users who need authentication but no administrative privileges

**JWT Claims:**
```json
{
  "sub": "user-id-uuid",
  "exp": 1234567890,
  "iat": 1234567000,
  "jti": "jwt-id-uuid",
  "is_owner": false,
  "is_system_admin": false,
  "is_role_admin": false,
  "app_roles": []
}
```

---

### Role Admin

**Purpose:** Reserved for future application role management functionality

**Capabilities:**
- All Regular User capabilities
- Future: Manage application-specific roles (not yet implemented)

**Admin Flags:**
- `is_owner`: false (not required)
- `is_system_admin`: false (not required)
- `is_role_admin`: **true** (this flag defines the role)

**Note:** A user is a Role Admin when `is_role_admin=true`. The other flags can be any value.

**Status:** ACTIVE by default

**Quantity:** Multiple allowed

**Use Case:** Future application role management (separate spec)

**Current State:** Flag exists in database and JWT claims, but no additional endpoints are currently available. This role is reserved for future expansion when application-specific role management is implemented.

---

### System Admin

**Purpose:** Day-to-day system operations and administrative tasks

**Capabilities:**
- All Regular User capabilities
- Assign Role Admin role via `POST /api/admin/roles/role-admin`
- Remove Role Admin role via `DELETE /api/admin/roles/role-admin`
- Future: User management, system configuration, token revocation (not yet implemented)

**Admin Flags:**
- `is_owner`: false (not required)
- `is_system_admin`: **true** (this flag defines the role)
- `is_role_admin`: false (not required, can also be true)

**Note:** A user is a System Admin when `is_system_admin=true`. The other flags can be any value - a user can be both System Admin and Role Admin simultaneously.

**Note:** Admin flags are **independent and can be combined**. A user can be System Admin AND Role Admin simultaneously. When assigning/removing roles, other flags are preserved.

**Status:** ACTIVE by default

**Quantity:** Multiple allowed (recommended: 2-5)

**Use Case:** Regular administrative tasks, managing Role Admin assignments

**Authorization Pattern:**
```rust
// System Admin can perform action if:
claims.is_system_admin == true || claims.is_owner == true
```

---

### Owner

**Purpose:** Emergency administrative management and system bootstrap

**Capabilities:**
- All Regular User capabilities
- Assign System Admin role via `POST /api/admin/roles/system-admin`
- Remove System Admin role via `DELETE /api/admin/roles/system-admin`
- Assign Role Admin role via `POST /api/admin/roles/role-admin`
- Remove Role Admin role via `DELETE /api/admin/roles/role-admin`
- Deactivate own account via `POST /api/admin/owner/deactivate`

**Admin Flags:**
- `is_owner`: **true** (this flag defines the role)
- `is_system_admin`: false (not required, can also be true)
- `is_role_admin`: false (not required, can also be true)

**Note:** A user is an Owner when `is_owner=true`. The other flags can be any value. However, combining Owner with other admin roles is impractical since the Owner account is frequently deactivated and cannot log in when inactive.

**Note:** Admin flags are **independent and can be combined**. The owner can also have System Admin and/or Role Admin flags. When assigning/removing roles, other flags are preserved.

**Status:** INACTIVE by default (must be explicitly activated via CLI - see [Bootstrap and Owner Management](bootstrap-and-owner-management.md))

**Quantity:** Only one per system

**Use Case:** Initial system setup, emergency situations, recovering from compromised System Admin accounts

**CLI Management:** For bootstrap process and owner activation/deactivation commands, see [Bootstrap and Owner Management](bootstrap-and-owner-management.md)

**Authorization Pattern:**
```rust
// Owner can perform action if:
claims.is_owner == true
```

**Important:** Owner cannot authenticate when `owner_active=false` in system configuration. The login endpoint checks this flag and rejects owner login attempts when inactive.

---

## Admin Flag Combinations

**Important:** Admin flags are **independent boolean values** that can be combined in any way. A user can have multiple admin flags set to `true` simultaneously.

### Common Combinations

**Owner + System Admin:**
```json
{
  "is_owner": true,
  "is_system_admin": true,
  "is_role_admin": false
}
```
- Has all Owner privileges (assign/remove System Admin and Role Admin)
- Also has System Admin privileges (future user management capabilities)
- Useful for a single administrator managing everything

**System Admin + Role Admin:**
```json
{
  "is_owner": false,
  "is_system_admin": true,
  "is_role_admin": true
}
```
- Can assign/remove Role Admin roles
- Has future System Admin capabilities (user management, etc.)
- Has future Role Admin capabilities (application role management)
- Common for senior administrators

**All Flags:**
```json
{
  "is_owner": true,
  "is_system_admin": true,
  "is_role_admin": true
}
```
- Has all possible privileges
- Rare but valid configuration

### Flag Preservation

When assigning or removing a role, **other flags are preserved**:

**Example:** User has `is_system_admin=true, is_role_admin=true`
- Assign System Admin → No change (already has it)
- Remove System Admin → `is_system_admin=false, is_role_admin=true` (Role Admin preserved)
- Remove Role Admin → `is_system_admin=true, is_role_admin=false` (System Admin preserved)

**Implementation:**
```rust
// When updating one flag, others are preserved
let new_privileges = AdminFlags {
    is_owner: user.is_owner,           // Preserved
    is_system_admin: true,              // Updated
    is_role_admin: user.is_role_admin, // Preserved
};
```

---

## Authorization Matrix

This table shows which user levels can perform which operations:

| Operation | Regular User | Role Admin | System Admin | Owner |
|-----------|--------------|------------|--------------|-------|
| **Authentication** |
| Login | ✅ | ✅ | ✅ | ✅ (if active) |
| Refresh token | ✅ | ✅ | ✅ | ✅ |
| Logout | ✅ | ✅ | ✅ | ✅ |
| View own info (whoami) | ✅ | ✅ | ✅ | ✅ |
| **Admin Role Management** |
| Assign System Admin | ❌ | ❌ | ❌ | ✅ |
| Remove System Admin | ❌ | ❌ | ❌ | ✅ |
| Assign Role Admin | ❌ | ❌ | ✅ | ✅ |
| Remove Role Admin | ❌ | ❌ | ✅ | ✅ |
| Deactivate Owner | ❌ | ❌ | ❌ | ✅ (self only) |
| **CLI Operations (requires server access)** |
| Bootstrap system | N/A | N/A | N/A | N/A |
| Activate Owner | N/A | N/A | N/A | N/A |
| Deactivate Owner (CLI) | N/A | N/A | N/A | N/A |

**Legend:**
- ✅ = Allowed
- ❌ = Forbidden (returns 403 Forbidden)
- N/A = Not applicable (CLI operations require server/SSH access, not user role)

**Note on CLI Operations:**

CLI commands (`cargo run -- bootstrap`, `cargo run -- owner activate`, etc.) do **not** use the authorization system. They operate directly on the database and require **physical or SSH access to the server**. The barrier is server access, not user role. Anyone with server access can run these commands regardless of their user account privileges.

This is why owner activation requires CLI access - it provides an additional security layer beyond just having owner credentials.

---

## Design Rationale

### Hierarchical Permission Model

The four-tier structure provides clear separation of concerns:

1. **Regular Users** - Application consumers with no administrative access
2. **Role Admin** - Future application-specific role management (extensibility)
3. **System Admin** - Day-to-day operations without emergency powers
4. **Owner** - Emergency access with highest privileges

This hierarchy allows for:
- **Principle of Least Privilege**: Users only get permissions they need
- **Separation of Duties**: Different admin levels for different responsibilities
- **Defense in Depth**: Compromising one admin level doesn't grant full system access

### Owner Inactive by Default

The Owner account is kept **INACTIVE by default** to minimize attack surface:

**Security Benefits:**
- Reduces exposure time of highest-privilege account
- Prevents accidental use of owner credentials for routine tasks
- Forces deliberate activation for emergency operations
- Provides audit trail of when owner access was needed

**Workflow:**
1. Owner created during bootstrap (INACTIVE)
2. System Admins handle day-to-day operations
3. Emergency occurs (e.g., all System Admins compromised)
4. Owner activated via CLI: `cargo run -- owner activate`
5. Owner logs in and resolves emergency
6. Owner deactivates via API or CLI
7. System returns to normal operations

**Why require CLI for activation?**
- Requires physical/SSH access to server (not just stolen owner credentials)
- Provides additional security layer beyond username/password
- Ensures owner activation is intentional and requires server access
- CLI operations are audited in application logs

**For CLI activation commands and bootstrap process**, see [Bootstrap and Owner Management](bootstrap-and-owner-management.md)

### Multiple System Admins

The system supports multiple System Admin accounts (recommended: 2-5):

**Benefits:**
- **Availability**: If one admin is unavailable, others can handle operations
- **Redundancy**: System doesn't depend on single admin account
- **Separation of Duties**: Different admins for different responsibilities
- **Compromise Recovery**: If one admin is compromised, others can revoke access

**Best Practice:** Create 2-5 System Admin accounts during bootstrap, distribute credentials securely to different administrators.

### Role Admin for Future Expansion

The Role Admin level exists but has no current functionality:

**Purpose:** Reserved for future application-specific role management

**Why pre-allocate?**
- Database schema stability (no migration needed later)
- JWT claims structure remains consistent
- Clear extensibility path for future features

**Future Use Case:** When application roles are implemented (e.g., "editor", "viewer", "moderator"), Role Admins will manage these assignments without needing System Admin privileges.

---

## Self-Modification Prevention

All admin role management endpoints enforce **self-modification prevention**: users cannot assign or remove admin roles to/from their own account.

### Why Prevent Self-Modification?

**Security Rationale:**
1. **Privilege Escalation Prevention**: Compromised session cannot grant itself higher privileges
2. **Audit Trail Integrity**: Role changes require two parties (actor and target)
3. **Accountability**: Forces admin actions to be performed by another admin
4. **Mistake Prevention**: Prevents accidental self-demotion

### Implementation

Service layer checks before any role modification:

```rust
// Extract claims from authenticated context
let claims = ctx.claims.as_ref()
    .ok_or_else(|| AdminError::internal_error("Unauthenticated"))?;

// Check for self-modification
if claims.sub == target_user_id {
    return Err(AdminError::self_modification_denied());
}
```

### Error Response

Attempting self-modification returns:
- **Status Code:** 403 Forbidden
- **Error Message:** "Cannot modify your own admin roles"
- **Audit Log:** Self-modification attempt is logged with actor user_id and attempted action

### Exception: Owner Self-Deactivation

The **only exception** to self-modification prevention is owner self-deactivation via `POST /api/admin/owner/deactivate`:

**Why allow this?**
- Owner needs to lock account after emergency use
- No privilege escalation risk (only removes access)
- Provides self-service security control
- Can be done via API without requiring CLI access

---

## Token Invalidation

When admin roles change, all active refresh tokens for the target user are **immediately invalidated**.

### Why Invalidate Tokens?

**Security Rationale:**
1. **Immediate Enforcement**: New permissions take effect immediately
2. **Stale Claims Prevention**: Old JWTs contain outdated admin flags
3. **Compromise Mitigation**: Revokes all sessions when privileges change
4. **Audit Trail**: Forces re-authentication with updated claims

### Implementation

After role modification:

```rust
// Invalidate all refresh tokens for target user
self.credential_store
    .invalidate_all_tokens(target_user_id)
    .await?;
```

This deletes all refresh tokens from the database. The user must:
1. Re-authenticate via `/auth/login`
2. Receive new JWT with updated admin flags
3. Receive new refresh token

### JWT Staleness

**Important:** Existing JWTs remain valid until expiration (15 minutes), but contain **stale claims**. The system does not maintain a JWT revocation list.

**Implications:**
- User can continue using old JWT for up to 15 minutes
- Old JWT contains outdated `is_owner`, `is_system_admin`, `is_role_admin` flags
- Authorization checks use JWT claims (not database state)

**Mitigation:**
- Short JWT expiration (15 minutes) limits exposure window
- Refresh token invalidation prevents obtaining new JWTs with stale claims
- Critical operations should verify database state if needed

---

## API Reference

For detailed API endpoint documentation, including request/response schemas, authentication requirements, and error codes, visit the **Swagger UI** at:

```
http://localhost:3000/swagger
```

### Authentication Endpoints

**Base Path:** `/auth`

- `POST /auth/login` - Authenticate and obtain tokens
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Revoke refresh token
- `GET /auth/whoami` - Get current user information

**Authorization:** None required for login, JWT required for others

### Admin Role Management Endpoints

**Base Path:** `/api/admin`

- `POST /api/admin/roles/system-admin` - Assign System Admin role
- `DELETE /api/admin/roles/system-admin` - Remove System Admin role
- `POST /api/admin/roles/role-admin` - Assign Role Admin role
- `DELETE /api/admin/roles/role-admin` - Remove Role Admin role
- `POST /api/admin/owner/deactivate` - Deactivate owner account

**Authorization:** JWT required, specific admin level required per endpoint (see Authorization Matrix)

### CLI Commands

**Important:** CLI commands do **not** use the authorization system described in this document. They operate directly on the database and require **server/SSH access**, not user credentials or roles.

The security barrier is server access, not user role. This is intentional - it provides an additional security layer for owner activation beyond just having owner credentials.

**For detailed CLI command documentation**, including bootstrap process, owner activation/deactivation, and troubleshooting, see:

**→ [Bootstrap and Owner Management](bootstrap-and-owner-management.md)**

---

## Related Documentation

- **Bootstrap Process:** See `docs/bootstrap-and-owner-management.md` for detailed bootstrap workflow
- **Request Context Pattern:** See `docs/request-context.md` for how authentication flows through the system
- **AppData Pattern:** See `docs/appdata-pattern.md` for service initialization architecture
- **Audit Logging:** See `.kiro/specs/structured-audit-logging/` for audit log specification

---

## Security Best Practices

### For Administrators

**Owner Account:**
- Store credentials securely in password manager
- Limit access to senior administrators only
- Activate only for emergencies, deactivate immediately after
- Monitor audit logs for owner activation events

**System Admin Accounts:**
- Create 2-5 accounts during bootstrap for redundancy
- Each admin should have unique credentials
- Monitor audit logs for unusual patterns
- Rotate credentials periodically

**For bootstrap security practices** including credential export and distribution, see [Bootstrap and Owner Management](bootstrap-and-owner-management.md)

### For Developers

**Authorization Patterns:**
1. **Check authorization** - Always verify user has required admin flags in JWT claims
2. **Prevent self-modification** - Enforce for all role management operations (except owner self-deactivation)
3. **Invalidate tokens** - When privileges change, revoke all refresh tokens
4. **Log admin actions** - Comprehensive audit trail for all security events
5. **Use RequestContext** - Pass authentication state through all layers (see [Request Context Pattern](request-context.md))

**Code Examples:**
```rust
// Check owner authorization
if !claims.is_owner {
    return Err(AdminError::owner_required());
}

// Check system admin or owner authorization
if !claims.is_owner && !claims.is_system_admin {
    return Err(AdminError::owner_or_system_admin_required());
}

// Prevent self-modification
if claims.sub == target_user_id {
    return Err(AdminError::self_modification_denied());
}

// Invalidate tokens after role change
credential_store.invalidate_all_tokens(target_user_id).await?;
```

---

## Future Enhancements

### Planned Features

1. **Application Role Management** - Role Admin functionality implementation
2. **User Management API** - System Admin endpoints for user CRUD operations
3. **Token Revocation List** - Immediate JWT invalidation (not just refresh tokens)
4. **Multi-Factor Authentication** - Additional security layer for admin accounts
5. **Rate Limiting** - Per-user, per-IP, per-action rate limits

### Extensibility

The authorization model is designed for extension:

- **New admin levels** - Add new flags to `users` table and JWT claims
- **New endpoints** - Follow existing authorization patterns
- **Custom permissions** - Use `app_roles` array for application-specific permissions
- **External auth** - OAuth 2.0 / OIDC integration (future spec)

For questions or suggestions, refer to the project documentation or open an issue.

# Service Layer Refactor Vision

## Problem Statement

The current `src/services/` directory contains two fundamentally different types of code that serve distinct purposes:

1. **Workflow Coordination** (`AuthService`, `AdminService`) - Orchestrate API-specific workflows by composing multiple operations
2. **Work Providers** (`TokenService`, `PasswordValidator`, `crypto`, `audit_logger`) - Perform actual work (calculations, validations, database operations)

This mixing creates confusion because these serve completely different roles:

- **Coordinators** answer: "What steps do I need for this API endpoint?"
- **Providers** answer: "How do I actually do this work?"

Bundling them under the generic term "Service" obscures this fundamental distinction and creates several issues:

- **Unclear Boundaries**: Difficult to determine when code belongs in coordination vs work provision
- **Responsibility Blur**: Risk of work providers growing coordination logic or coordinators doing actual work
- **Architectural Drift**: No clear guidelines about what calls what
- **Cognitive Load**: Developers must mentally categorize each "service's" true purpose

## Solution: Three-Layer Architecture

### Layer 1: API Layer (`src/api/`)
**Purpose**: Handle HTTP concerns and translate between external world and internal system

**Responsibilities**:
- HTTP request/response handling
- Input validation and sanitization
- Data serialization/deserialization
- Error formatting for external consumption
- OpenAPI documentation generation

**What it does**: Translates HTTP requests into internal operations and internal results back to HTTP responses.

### Layer 2: Coordinator Layer (`src/coordinators/`)
**Purpose**: Coordinate API-specific workflows by composing provider operations

**Responsibilities**:
- Map API endpoints to specific sequences of operations
- Determine "what calls what and pass the result to whom"
- Handle transaction boundaries and rollback logic
- Coordinate operations across multiple domains
- Pure orchestration with no business logic

**What it does**: Implements the specific workflow each API endpoint needs by calling the right providers in the right order.

**Key Insight**: Coordinators contain no business logic - they're just workflow recipes.

### Layer 3: Provider Layer (`src/providers/`)
**Purpose**: Provide work products - calculations, validations, database operations

**Responsibilities**:
- Perform actual work (compute, validate, store, retrieve)
- Contain domain-specific business logic
- Provide composable operations that coordinators can use
- Handle single-domain concerns

**What it does**: Does the real work that coordinators orchestrate.

**Key Insight**: Providers can call other providers when it makes business sense - they compose into larger operations.

## The Real Distinction

### Coordinators (Category 1)
- **Nature**: Thin coordination layer
- **Content**: Workflow recipes ("do A, then B, pass result to C")
- **Granularity**: Defined by API endpoints and business workflows
- **Business Logic**: None - pure orchestration

**Examples**:
- Login workflow = verify_credentials + generate_jwt + generate_refresh + store_refresh
- Change password = verify_credentials + validate_new_password + update_password + revoke_all_tokens + generate_new_tokens

### Providers (Category 2)  
- **Nature**: Work performers
- **Content**: Actual business logic and operations
- **Granularity**: Defined by:
  1. **Domain boundaries** (token operations, password operations, crypto operations)
  2. **Composability needs** (separate when they have independent business value)
- **Business Logic**: All of it

**Examples**:
- `verify_credentials()` - standalone because sometimes you just need to verify
- `generate_jwt()` - standalone because used in login, refresh, password change
- `revoke_token()` - standalone because used in logout, password change, admin actions

## Dependency Flow

```
API Layer
    ↓ (calls)
Coordinator Layer  
    ↓ (calls)
Provider Layer
    ↓ (calls)
Store Layer
```

**Rules**:
- APIs call Coordinators (never Providers directly)
- Coordinators call Providers (and Stores when no provider abstraction needed)
- Providers call other Providers (when business logic requires composition)
- Providers call Stores for persistence
- No upward calls (Provider cannot call Coordinator)

## Naming Convention

To make the architecture self-documenting and prevent ambiguity:

### Coordinators
- **File**: `{domain}_coordinator.rs`
- **Struct**: `{Domain}Coordinator`
- **Example**: `auth_coordinator.rs` → `AuthCoordinator`

### Providers
- **File**: `{name}_provider.rs`
- **Struct**: `{Name}Provider`
- **Example**: `token_provider.rs` → `TokenProvider`

### Rationale for Consistent Suffixes
- **Zero Ambiguity**: No judgment calls about when to use suffixes
- **Self-Documenting**: Architecture is immediately clear from names
- **Future-Proof**: New modules follow obvious pattern
- **Tooling-Friendly**: Easy to search, grep, and categorize
- **Clear Distinction**: Impossible to confuse coordination with work provision

## Proposed Folder Structure

```
src/
├── api/                              # HTTP Layer
│   ├── mod.rs
│   ├── auth.rs                       # HTTP handlers for auth endpoints
│   └── admin.rs                      # HTTP handlers for admin endpoints
│
├── coordinators/                     # Workflow Coordination Layer
│   ├── mod.rs
│   ├── auth_coordinator.rs           # AuthCoordinator (from current AuthService)
│   └── admin_coordinator.rs          # AdminCoordinator (from current AdminService)
│
├── providers/                        # Work Provider Layer
│   ├── mod.rs
│   ├── token_provider.rs             # TokenProvider (from TokenService)
│   ├── password_validator_provider.rs # PasswordValidatorProvider (from PasswordValidator)
│   ├── crypto_provider.rs            # CryptoProvider (from crypto functions)
│   └── audit_logger_provider.rs      # AuditLoggerProvider (from audit_logger functions)
│
└── stores/                           # Persistence Layer
    └── ...                           # (unchanged)
```

## Current Code Mapping

### Coordinators (Category 1) - Pure Orchestration
**Current Location** → **New Location**

- `AuthService::login()` → `AuthCoordinator::login()`
- `AuthService::refresh()` → `AuthCoordinator::refresh()`  
- `AuthService::logout()` → `AuthCoordinator::logout()`
- `AuthService::change_password()` → `AuthCoordinator::change_password()`
- `AdminService::assign_system_admin()` → `AdminCoordinator::assign_system_admin()`
- `AdminService::remove_system_admin()` → `AdminCoordinator::remove_system_admin()`
- `AdminService::assign_role_admin()` → `AdminCoordinator::assign_role_admin()`
- `AdminService::remove_role_admin()` → `AdminCoordinator::remove_role_admin()`
- `AdminService::deactivate_owner()` → `AdminCoordinator::deactivate_owner()`

### Providers (Category 2) - Work Performers
**Current Location** → **New Location**

- `TokenService` → `TokenProvider`
- `PasswordValidator` → `PasswordValidatorProvider`
- `crypto::*` functions → `CryptoProvider`
- `audit_logger::*` functions → `AuditLoggerProvider`

## Migration Strategy

### Phase 1: Create New Structure
1. Create `src/coordinators/` directory
2. Create `src/providers/` directory  
3. Create mod.rs files with proper exports

### Phase 2: Move Coordination Logic
1. Move `AuthService` → `AuthCoordinator` in `coordinators/auth_coordinator.rs`
2. Move `AdminService` → `AdminCoordinator` in `coordinators/admin_coordinator.rs`
3. Update struct names and method signatures

### Phase 3: Move Work Providers
1. Move `TokenService` → `TokenProvider` in `providers/token_provider.rs`
2. Move `PasswordValidator` → `PasswordValidatorProvider` in `providers/password_validator_provider.rs`
3. Convert `crypto` functions → `CryptoProvider` struct in `providers/crypto_provider.rs`
4. Convert `audit_logger` functions → `AuditLoggerProvider` struct in `providers/audit_logger_provider.rs`

### Phase 4: Update Dependencies
1. Update coordinators to import and use providers
2. Update API layer to import and use coordinators
3. Verify no API directly calls providers
4. Update all imports throughout codebase

### Phase 5: Validation
1. Verify dependency flow: API → Coordinator → Provider → Store
2. Check no coordinator calls other coordinators
3. Verify providers can call other providers when needed
4. Ensure all naming follows conventions

## Key Principles

### 1. **Granularity is Business-Driven**
Provider functions are split when they have independent business value, not for architectural purity.

**Example**: `revoke_token()` is separate from `change_password()` because there are business cases where tokens are revoked without password changes (admin actions, logout, etc.).

### 2. **Providers Can Compose**
Providers can call other providers to build larger operations when the business logic requires it.

**Example**: `validate_password()` might call `check_common_passwords()` and `check_hibp()` - all providers, perfectly acceptable.

### 3. **Coordinators Are Pure Orchestration**
Coordinators contain no business logic - they're just recipes that determine "call A, then B, pass result to C."

**Example**: `AuthCoordinator::login()` doesn't know how to verify credentials or generate JWTs - it just knows the sequence needed for a login workflow.

### 4. **One Coordinator Per API Domain**
Each coordinator maps 1:1 with an API module, handling all workflows for that domain.

**Example**: `AuthCoordinator` handles all auth workflows (login, refresh, logout, change_password) that `api/auth.rs` exposes.

## Benefits

### Conceptual Clarity
- **Clear Mental Model**: Coordinators orchestrate, providers work
- **Obvious Purpose**: Names immediately indicate whether something coordinates or provides
- **Natural Boundaries**: Easy to determine where new code belongs

### Architectural Benefits
- **Flexible Composition**: Providers can be reused across different workflows
- **Clean Dependencies**: Clear flow from coordination to work to persistence
- **Testable Units**: Coordinators test workflows, providers test business logic

### Development Experience
- **Reduced Cognitive Load**: No more guessing what type of "service" something is
- **Clear Guidelines**: Unambiguous rules about what calls what
- **Maintainable Growth**: New features follow obvious patterns

### Team Collaboration
- **Shared Vocabulary**: "Coordinator" and "Provider" have clear, distinct meanings
- **Code Reviews**: Easy to spot when coordination logic creeps into providers
- **Onboarding**: Architecture is self-explanatory from folder structure

## Success Criteria

1. **Clean Dependency Flow**: API → Coordinator → Provider → Store (no violations)
2. **Consistent Naming**: All coordinators end in `Coordinator`, all providers end in `Provider`
3. **Clear Responsibilities**: No business logic in coordinators, no workflow orchestration in providers
4. **Flexible Composition**: Providers can call other providers when business logic requires it
5. **Maintainable Structure**: Easy to determine whether new code coordinates or provides work
6. **Zero Breaking Changes**: All existing functionality preserved during migration
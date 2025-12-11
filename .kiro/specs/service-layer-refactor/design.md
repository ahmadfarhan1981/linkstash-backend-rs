# Design Document

## Overview

This design document outlines the refactoring of the current service layer architecture to establish clear separation between workflow coordination and work provision. The current `src/services/` directory contains two fundamentally different types of code that serve distinct purposes, creating confusion and architectural drift. This refactor will implement a three-layer architecture with distinct responsibilities and clear dependency flows.

The refactor addresses the core problem that the current "Service" abstraction bundles workflow coordinators (AuthService, AdminService) with work providers (TokenService, PasswordValidator, crypto, audit_logger) under a generic term, obscuring their fundamental differences and creating unclear boundaries.

## Architecture

### Three-Layer Architecture

The new architecture establishes three distinct layers with clear responsibilities:

#### Layer 1: API Layer (`src/api/`)
**Purpose**: Handle HTTP concerns and translate between external world and internal system

**Responsibilities**:
- HTTP request/response handling
- Input validation and sanitization  
- Data serialization/deserialization
- Error formatting for external consumption
- OpenAPI documentation generation

#### Layer 2: Coordinator Layer (`src/coordinators/`)
**Purpose**: Coordinate API-specific workflows by composing provider operations

**Responsibilities**:
- Map API endpoints to specific sequences of operations
- Determine "what calls what and pass the result to whom"
- Handle transaction boundaries and rollback logic
- Coordinate operations across multiple domains
- Pure orchestration with no business logic

#### Layer 3: Provider Layer (`src/providers/`)
**Purpose**: Provide work products - calculations, validations, database operations

**Responsibilities**:
- Perform actual work (compute, validate, store, retrieve)
- Contain domain-specific business logic
- Provide composable operations that coordinators can use
- Handle single-domain concerns

### Dependency Flow

The architecture enforces a strict dependency flow:

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

## Components and Interfaces

### Coordinators

Coordinators implement pure workflow orchestration for API endpoints:

#### AuthCoordinator
Migrated from `AuthService`, handles authentication workflows:
- `login()` - Orchestrates credential verification, JWT generation, refresh token creation
- `refresh()` - Orchestrates refresh token validation and new JWT generation
- `logout()` - Orchestrates refresh token revocation
- `change_password()` - Orchestrates password validation, update, and token regeneration

#### AdminCoordinator  
Migrated from `AdminService`, handles admin role management workflows:
- `assign_system_admin()` - Orchestrates authorization, privilege updates, token invalidation
- `remove_system_admin()` - Orchestrates authorization, privilege updates, token invalidation
- `assign_role_admin()` - Orchestrates authorization, privilege updates, token invalidation
- `remove_role_admin()` - Orchestrates authorization, privilege updates, token invalidation
- `deactivate_owner()` - Orchestrates owner deactivation and token invalidation

### Providers

Providers implement business logic and work operations:

#### TokenProvider
Migrated from `TokenService`, handles JWT and refresh token operations:
- `generate_jwt()` - Creates JWT with claims and audit logging
- `validate_jwt()` - Validates JWT and logs failures
- `generate_refresh_token()` - Creates cryptographically secure refresh tokens
- `hash_refresh_token()` - HMAC-SHA256 hashing for refresh tokens
- `get_refresh_expiration()` - Calculates refresh token expiration

#### PasswordValidatorProvider
Migrated from `PasswordValidator`, handles password validation:
- `validate()` - Comprehensive password validation against all policies
- `generate_secure_password()` - Generates cryptographically secure passwords
- `check_hibp()` - HaveIBeenPwned API integration with k-anonymity

#### CryptoProvider
Migrated from `crypto` module functions, handles cryptographic operations:
- `hmac_sha256_token()` - HMAC-SHA256 for token hashing
- `generate_secure_password()` - Secure password generation

#### AuditLoggerProvider
Migrated from `audit_logger` module functions, handles audit logging:
- All existing audit logging functions converted to methods
- Maintains actor/target separation pattern
- Provides AuditBuilder for custom events

### Naming Conventions

To ensure architectural clarity and prevent ambiguity:

#### Coordinators
- **File**: `{domain}_coordinator.rs`
- **Struct**: `{Domain}Coordinator`
- **Example**: `auth_coordinator.rs` → `AuthCoordinator`

#### Providers
- **File**: `{name}_provider.rs`
- **Struct**: `{Name}Provider`
- **Example**: `token_provider.rs` → `TokenProvider`

## Data Models

The refactor preserves all existing data models and types:

### Existing Types Preserved
- All `src/types/db/` entities remain unchanged
- All `src/types/dto/` request/response models remain unchanged
- All `src/types/internal/` types remain unchanged
- `RequestContext` pattern continues unchanged

### New Module Organization
- Coordinators organized in `src/coordinators/mod.rs`
- Providers organized in `src/providers/mod.rs`
- Clean public interfaces without exposing implementation details

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property Reflection

After analyzing all acceptance criteria, several properties can be consolidated:
- Properties 1.1-1.4 all relate to architectural organization and can be combined into a comprehensive structural property
- Properties 5.1-5.5 all relate to naming conventions and can be combined into a naming consistency property
- Properties 4.1-4.4 all relate to dependency flow and can be combined into a dependency enforcement property
- Properties 6.1-6.5 all relate to functional preservation and can be combined into a migration correctness property

### Property 1: Architectural Layer Separation
*For any* code module in the system, it should be organized in the correct architectural layer (coordinators/, providers/, api/, stores/) and contain only the responsibilities appropriate to that layer
**Validates: Requirements 1.1, 1.2, 1.4, 2.1, 3.1, 8.1, 8.2**

### Property 2: Naming Convention Consistency  
*For any* coordinator or provider module, the file name and struct name should follow the established patterns ({domain}_coordinator.rs/{Domain}Coordinator for coordinators, {name}_provider.rs/{Name}Provider for providers)
**Validates: Requirements 1.3, 5.1, 5.2, 5.3, 5.4, 5.5**

### Property 3: Dependency Flow Enforcement
*For any* module in the system, it should only import and call modules from appropriate layers according to the dependency rules (API→Coordinator→Provider→Store, no upward calls)
**Validates: Requirements 4.1, 4.2, 4.3, 4.4, 8.3, 8.4, 8.5**

### Property 4: Coordinator Orchestration Purity
*For any* coordinator method, it should contain only orchestration logic (calling providers in sequence, handling transactions) and no business logic implementation
**Validates: Requirements 2.1, 2.2, 2.3, 2.4**

### Property 5: Provider Business Logic Containment
*For any* provider method, it should contain business logic and domain operations while allowing composition with other providers but never coordinating multi-domain workflows
**Validates: Requirements 3.1, 3.2, 3.3, 3.4**

### Property 6: Functional Preservation During Migration
*For any* existing service method, the migrated coordinator or provider should preserve identical functionality, method signatures, and external behavior
**Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**

### Property 7: Module Export Consistency
*For any* coordinator or provider, it should be properly exported through its respective mod.rs file and provide clean import interfaces without exposing implementation details
**Validates: Requirements 7.1, 7.2, 7.3, 7.4**

## Error Handling

The refactor preserves all existing error handling patterns:

### Error Flow Preservation
- All existing `InternalError` types and variants remain unchanged
- Error propagation from Provider → Coordinator → API maintains current patterns
- Audit logging of errors continues at point of action (in providers/stores)

### Transaction Error Handling
- Coordinators handle transaction rollback logic
- Providers log transaction failures at point of action
- Error context preserved through all layers

## Testing Strategy

### Dual Testing Approach

The refactor requires both unit testing and property-based testing:

#### Unit Tests
- Verify specific examples and edge cases work correctly
- Test integration points between layers
- Validate error conditions and rollback scenarios
- Test individual coordinator workflows and provider operations

#### Property-Based Tests

Property-based tests will use **QuickCheck for Rust** (quickcheck crate) to verify universal properties across all inputs. Each property-based test will run a minimum of 100 iterations to ensure comprehensive coverage.

**Property-Based Test Requirements**:
- Each correctness property must be implemented by a single property-based test
- Tests must be tagged with comments referencing the design document property
- Tag format: `**Feature: service-layer-refactor, Property {number}: {property_text}**`
- Tests should generate random valid inputs to verify properties hold universally

#### Migration Testing Strategy

**Critical**: All existing functionality must be preserved during migration:

1. **Baseline Tests**: Capture current behavior before migration
2. **Incremental Migration**: Test each component migration individually  
3. **Integration Tests**: Verify end-to-end workflows continue working
4. **API Compatibility**: Ensure external API behavior remains identical

#### Test Organization

- Unit tests co-located with source files using `.test.rs` suffix
- Property-based tests in dedicated test modules
- Integration tests verify cross-layer interactions
- Migration tests validate functional preservation

### Testing Framework Configuration

- **Unit Testing**: Standard Rust `#[cfg(test)]` modules
- **Property-Based Testing**: `quickcheck` crate with 100+ iterations per property
- **Integration Testing**: `tests/` directory for cross-component validation
- **Test Utilities**: Preserve existing test utilities and patterns
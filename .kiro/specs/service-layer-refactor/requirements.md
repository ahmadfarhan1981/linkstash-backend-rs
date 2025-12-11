# Requirements Document

## Introduction

This specification defines the refactoring of the current service layer architecture to establish clear separation between workflow coordination and work provision. The current `src/services/` directory mixes two fundamentally different types of code: workflow coordinators (AuthService, AdminService) and work providers (TokenService, PasswordValidator, crypto, audit_logger). This refactor will create a three-layer architecture with distinct responsibilities and clear dependency flows.

## Glossary

- **API Layer**: HTTP request/response handling and external interface management
- **Coordinator Layer**: Workflow orchestration that composes provider operations for specific API endpoints
- **Provider Layer**: Work performers that contain business logic and provide composable operations
- **Store Layer**: Data persistence and retrieval operations
- **Workflow Coordination**: Orchestrating sequences of operations without containing business logic
- **Work Provider**: Components that perform actual business operations, calculations, or validations
- **Business Logic**: Domain-specific rules and operations that define how the system works
- **Orchestration**: Determining the sequence and flow of operations without implementing the operations themselves

## Requirements

### Requirement 1

**User Story:** As a developer, I want clear architectural boundaries between coordination and work provision, so that I can easily understand where new code belongs and maintain consistent system design.

#### Acceptance Criteria

1. WHEN examining the codebase structure, THE System SHALL separate coordination logic from work provision logic into distinct layers
2. WHEN adding new functionality, THE System SHALL provide clear guidelines for determining whether code coordinates workflows or provides work
3. WHEN reviewing code, THE System SHALL make architectural roles immediately apparent through naming conventions
4. WHEN navigating the codebase, THE System SHALL organize modules by their architectural purpose rather than generic categorization
5. WHEN onboarding new developers, THE System SHALL provide self-documenting architecture through folder structure and naming

### Requirement 2

**User Story:** As a developer, I want coordinators to handle pure workflow orchestration, so that API endpoint logic is separated from business operations and workflows are easily testable.

#### Acceptance Criteria

1. WHEN implementing API workflows, THE Coordinator_Layer SHALL orchestrate sequences of provider operations without containing business logic
2. WHEN processing API requests, THE Coordinator_Layer SHALL determine the correct sequence of operations for each endpoint workflow
3. WHEN coordinating operations, THE Coordinator_Layer SHALL pass results between providers without modifying or interpreting the data
4. WHEN handling transactions, THE Coordinator_Layer SHALL manage transaction boundaries and rollback logic across multiple operations
5. WHERE workflow requirements change, THE Coordinator_Layer SHALL allow modification of operation sequences without affecting business logic

### Requirement 3

**User Story:** As a developer, I want providers to contain all business logic and work operations, so that domain expertise is centralized and operations are composable across different workflows.

#### Acceptance Criteria

1. WHEN performing business operations, THE Provider_Layer SHALL contain all domain-specific logic and calculations
2. WHEN validating data, THE Provider_Layer SHALL implement validation rules and business constraints
3. WHEN providers need complex operations, THE Provider_Layer SHALL allow providers to call other providers for composition
4. WHEN accessing data, THE Provider_Layer SHALL handle all database operations through the store layer
5. WHEN implementing new business features, THE Provider_Layer SHALL provide composable operations that coordinators can orchestrate

### Requirement 4

**User Story:** As a developer, I want a clear dependency flow between layers, so that the system maintains architectural integrity and prevents circular dependencies.

#### Acceptance Criteria

1. WHEN API endpoints need workflows, THE API_Layer SHALL call coordinators and never call providers directly
2. WHEN coordinators need operations, THE Coordinator_Layer SHALL call providers and stores without calling other coordinators
3. WHEN providers need data, THE Provider_Layer SHALL call stores and other providers but never call coordinators
4. WHEN stores need operations, THE Store_Layer SHALL only call other stores and never call higher layers
5. IF any layer attempts upward calls, THEN THE System SHALL prevent compilation or runtime execution

### Requirement 5

**User Story:** As a developer, I want consistent naming conventions that reflect architectural roles, so that I can immediately understand component purposes and maintain consistency across the codebase.

#### Acceptance Criteria

1. WHEN creating coordinator modules, THE System SHALL use the naming pattern `{domain}_coordinator.rs` with struct `{Domain}Coordinator`
2. WHEN creating provider modules, THE System SHALL use the naming pattern `{name}_provider.rs` with struct `{Name}Provider`
3. WHEN organizing code, THE System SHALL place coordinators in `src/coordinators/` directory
4. WHEN organizing code, THE System SHALL place providers in `src/providers/` directory
5. WHEN examining any module, THE System SHALL make architectural role immediately apparent through consistent naming

### Requirement 6

**User Story:** As a developer, I want to migrate existing services without breaking functionality, so that the refactor maintains system stability while improving architecture.

#### Acceptance Criteria

1. WHEN migrating AuthService, THE System SHALL preserve all existing login, refresh, logout, and password change workflows
2. WHEN migrating AdminService, THE System SHALL preserve all existing admin role assignment and management workflows
3. WHEN migrating TokenService, THE System SHALL preserve all JWT generation, validation, and management operations
4. WHEN migrating other services, THE System SHALL preserve all existing functionality including PasswordValidator, crypto operations, and audit logging
5. WHEN migration is complete, THE System SHALL maintain identical external API behavior and responses

### Requirement 7

**User Story:** As a developer, I want proper module organization and exports, so that the new architecture is accessible and maintainable through clear public interfaces.

#### Acceptance Criteria

1. WHEN accessing coordinators, THE System SHALL provide proper module exports through `src/coordinators/mod.rs`
2. WHEN accessing providers, THE System SHALL provide proper module exports through `src/providers/mod.rs`
3. WHEN importing components, THE System SHALL allow clean imports without exposing internal implementation details
4. WHEN using the architecture, THE System SHALL provide consistent interfaces across all coordinators and providers
5. WHEN extending the system, THE System SHALL support adding new coordinators and providers following established patterns

### Requirement 8

**User Story:** As a developer, I want validation that the new architecture maintains proper separation of concerns, so that architectural integrity is preserved as the system evolves.

#### Acceptance Criteria

1. WHEN reviewing coordinators, THE System SHALL contain no business logic implementation, only workflow orchestration
2. WHEN reviewing providers, THE System SHALL contain business logic but no workflow coordination across multiple domains
3. WHEN checking dependencies, THE System SHALL enforce that API layer only calls coordinators
4. WHEN checking dependencies, THE System SHALL enforce that coordinators only call providers and stores
5. WHEN validating architecture, THE System SHALL ensure no circular dependencies exist between layers
# Service Initialization Refactor - Requirements

## Introduction

This refactor changes the service initialization pattern from service-owned stores to main-owned stores. This eliminates store duplication, follows Rust ecosystem conventions, and makes dependencies explicit.

## Glossary

- **Store** - Data access layer component (CredentialStore, AuditStore, SystemConfigStore)
- **Service** - Business logic layer component (AuthService, TokenService)
- **Service-Owned Stores** - Current pattern where each service creates its own store instances
- **Main-Owned Stores** - New pattern where main.rs creates stores once and passes to services
- **Dependency Injection** - Pattern of passing dependencies via constructor rather than creating them internally

## Requirements

### Requirement 1: AppData Centralized Initialization

**User Story:** As a developer, I want all application data (databases, stores, services) initialized in one place via an AppData struct, so that initialization is centralized and consistent.

#### Acceptance Criteria

1. WHEN the application starts, THE System SHALL create an AppData struct containing all databases, stores, and stateless services
2. WHEN AppData is initialized, THE System SHALL create exactly one instance of each store
3. WHEN AppData is initialized, THE System SHALL wrap the struct in Arc for sharing
4. WHEN multiple services need the same store, THE System SHALL access it from the same AppData instance

### Requirement 2: Explicit Dependency Extraction

**User Story:** As a developer, I want services to explicitly extract their dependencies from AppData in the constructor, so that I can see what each service uses by looking at its struct fields.

#### Acceptance Criteria

1. WHEN creating a service, THE System SHALL accept AppData as the constructor parameter
2. WHEN creating a service, THE constructor SHALL extract only needed dependencies from AppData
3. WHEN reviewing service code, THE developer SHALL be able to see all dependencies in the service struct fields
4. WHEN a service needs a new dependency, THE System SHALL only require updating the constructor body, not the signature

### Requirement 3: Simplified Service Constructors

**User Story:** As a developer, I want services to have simple constructors that accept dependencies, so that services are easy to instantiate and test.

#### Acceptance Criteria

1. WHEN creating AuthService, THE System SHALL use a synchronous `new()` constructor
2. WHEN creating TokenService, THE System SHALL use a synchronous `new()` constructor
3. WHEN creating any service, THE constructor SHALL NOT perform async operations
4. WHEN creating any service, THE constructor SHALL NOT create internal dependencies

### Requirement 4: AppData Initialization Method

**User Story:** As a developer, I want all initialization logic in AppData::init(), so that main.rs is clean and initialization is encapsulated.

#### Acceptance Criteria

1. WHEN the application starts, THE System SHALL call AppData::init() to create all dependencies
2. WHEN AppData::init() runs, THE System SHALL initialize databases, stores, and stateless services
3. WHEN reviewing AppData::init(), THE developer SHALL be able to see the complete initialization order
4. WHEN reviewing main.rs, THE developer SHALL see only AppData::init() call, not individual store creation

### Requirement 5: CLI Mode Compatibility

**User Story:** As a developer, I want CLI commands to receive AppData, so that they can access any needed stores without signature changes.

#### Acceptance Criteria

1. WHEN running CLI commands, THE System SHALL create AppData using the same AppData::init() method
2. WHEN running CLI commands, THE System SHALL pass AppData reference to CLI command handlers
3. WHEN CLI commands need additional stores, THE System SHALL NOT require updating CLI command signatures

### Requirement 6: Test User Seeding

**User Story:** As a developer, I want test user seeding to be explicit in main.rs, so that it's clear when and how test data is created.

#### Acceptance Criteria

1. WHEN running in debug mode, THE System SHALL seed test user after creating stores
2. WHEN running in release mode, THE System SHALL NOT seed test user
3. WHEN seeding test user, THE System SHALL call a standalone function with credential_store parameter

### Requirement 7: No Breaking Changes to API

**User Story:** As a developer, I want the API layer to remain unchanged, so that existing API code continues to work without modification.

#### Acceptance Criteria

1. WHEN the refactor is complete, THE AuthApi SHALL continue to work without changes
2. WHEN the refactor is complete, THE API endpoints SHALL continue to function identically
3. WHEN the refactor is complete, THE API tests SHALL continue to pass without modification

### Requirement 8: Stable Service Signatures

**User Story:** As a developer, I want service constructors to have stable signatures, so that adding new stores doesn't require updating all service instantiation code.

#### Acceptance Criteria

1. WHEN a new store is added to AppData, THE System SHALL NOT require changing service constructor signatures
2. WHEN a service needs a new dependency, THE System SHALL only require updating the service constructor body
3. WHEN reviewing code, THE developer SHALL see that all services accept Arc AppData as their only parameter

---
inclusion: always
---

# Code Structure & Conventions

## Module Organization

**Layer-Based Architecture** - Organize by technical layer, not by feature:

```
src/
├── main.rs                    # Server setup + route registration ONLY
│
├── api/                       # HTTP endpoints layer
│   ├── mod.rs                 # Public exports
│   ├── health.rs              # Health check endpoints
│   ├── auth.rs                # Authentication endpoints
│   └── admin.rs               # Admin management endpoints
│
├── types/                     # All data structures
│   ├── mod.rs
│   ├── db/                    # Database entities (SeaORM)
│   │   ├── mod.rs
│   │   ├── user.rs            # User entity with DeriveEntityModel
│   │   └── refresh_token.rs   # RefreshToken entity
│   │
│   ├── dto/                   # Data Transfer Objects (API contracts)
│   │   ├── mod.rs
│   │   ├── auth.rs            # LoginRequest, TokenResponse, RefreshRequest
│   │   └── common.rs          # HealthResponse, ErrorResponse
│   │
│   └── internal/              # Internal-only types
│       ├── mod.rs
│       └── auth.rs            # Claims (JWT payload)
│
├── coordinators/              # Workflow coordination layer
│   ├── mod.rs
│   ├── auth_coordinator.rs    # Auth workflow orchestration (login/refresh flows)
│   └── admin_coordinator.rs   # Admin workflow orchestration (role management)
│
├── providers/                 # Business logic and work provider layer
│   ├── mod.rs
│   ├── token_provider.rs      # JWT generation/validation
│   ├── password_validator_provider.rs  # Password validation and HIBP integration
│   ├── crypto_provider.rs     # Cryptographic operations
│   └── audit_logger_provider.rs  # Audit logging operations
│
├── stores/                    # Data access layer (Repository pattern)
│   ├── mod.rs
│   ├── credential_store.rs    # User credential DB operations
│   ├── audit_store.rs         # Audit log DB operations
│   ├── system_config_store.rs # System configuration DB operations
│   ├── common_password_store.rs # Common password validation DB operations
│   └── hibp_cache_store.rs    # HaveIBeenPwned cache DB operations
│
├── config/                    # Configuration management
│   ├── mod.rs
│   ├── secret_manager.rs      # Secret management and loading
│   ├── database.rs            # Database configuration
│   └── logging.rs             # Logging configuration
│
├── cli/                       # Command-line interface
│   ├── mod.rs
│   ├── bootstrap.rs           # System bootstrap commands
│   ├── migrate.rs             # Database migration commands
│   └── owner.rs               # Owner management commands
│
└── errors/                    # Error types
    ├── mod.rs
    ├── internal.rs            # Internal error types for stores/providers
    └── api/                   # API-specific error types
        ├── mod.rs
        ├── auth.rs            # AuthError with ResponseError impl
        └── admin.rs           # AdminError with ResponseError impl
```

## Layer Responsibilities

- **api/** - HTTP endpoints, request handling, OpenAPI tags, status codes
- **types/db/** - SeaORM entities representing database schema
- **types/dto/** - API request/response models with poem-openapi decorators
- **types/internal/** - Internal data structures not exposed via API or DB
- **coordinators/** - Workflow orchestration, composing provider operations for API endpoints
- **providers/** - Business logic, work operations, domain-specific calculations and validations
- **stores/** - Database operations, query encapsulation (Repository pattern)
- **errors/** - Custom error types implementing ResponseError

## API Patterns

- All endpoint structs use `#[OpenApi]` macro with `tags` parameter
- Endpoints return `poem::Result<T>` with proper status codes (200, 201, 401, 404)
- All routes under `/api` base path
- Request types: `poem_openapi::Object` with validation
- Response types: `poem_openapi::Object` or `poem_openapi::ApiResponse`
- JWT authentication via Authorization header: `Bearer <token>`
- Extract JWT from header, validate, and use claims for authorization

## Naming

### General Conventions
- Files: `snake_case.rs`
- Types: `PascalCase` with pattern `{Action}{Resource}{Request|Response}` (e.g., `LoginRequest`, `CreateItemResponse`)
- Functions/variables: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Endpoints: RESTful (`/auth/login`, `/items/{id}`)

### Architectural Naming Patterns

**Coordinators:**
- **File**: `{domain}_coordinator.rs`
- **Struct**: `{Domain}Coordinator`
- **Example**: `auth_coordinator.rs` → `AuthCoordinator`

**Providers:**
- **File**: `{name}_provider.rs`
- **Struct**: `{Name}Provider`
- **Example**: `token_provider.rs` → `TokenProvider`

**Rationale**: Consistent suffixes make architectural roles immediately apparent and prevent ambiguity about whether code coordinates workflows or provides work.

## Architectural Layers

### Coordinators vs Providers

**Coordinators** (Pure Orchestration):
- Handle workflow coordination for API endpoints
- Compose provider operations in specific sequences
- Contain no business logic - only orchestration
- One coordinator per API domain (AuthCoordinator, AdminCoordinator)
- Call providers and stores, never other coordinators

**Providers** (Work Performers):
- Contain all business logic and domain operations
- Perform actual work (calculations, validations, database operations)
- Composable - providers can call other providers when business logic requires it
- Examples: TokenProvider, PasswordValidatorProvider, CryptoProvider, AuditLoggerProvider

### Dependency Flow Rules

```
API Layer
    ↓ (calls)
Coordinator Layer  
    ↓ (calls)
Provider Layer
    ↓ (calls)
Store Layer
```

- APIs call Coordinators (never Providers directly)
- Coordinators call Providers and Stores
- Providers call other Providers and Stores
- No upward calls (Provider cannot call Coordinator)

## Error Handling

- Custom error enums implement `poem::error::ResponseError`
- Coordinator and provider functions return `Result<T, CustomError>`
- Consistent JSON format: `{ "error": "message" }`
- Never log/expose passwords or tokens

## Database

- Entities use `DeriveEntityModel` in `types/db/`
- Migrations in `migration/src/` with descriptive names
- Connection pool managed in `main.rs`
- Always use SeaORM's async API
- Stores encapsulate all database queries (no SeaORM usage outside stores)

## Code Comments

### Inline Comments

- **DO NOT** comment what the code is doing (the code should be self-explanatory)
- **DO** comment WHY something is done a certain way (reasoning, trade-offs, non-obvious decisions)
- **DO** comment unusual patterns or workarounds
- **DO NOT** use inline comments for obvious operations

**Examples:**

```rust
// ❌ BAD - Commenting what the code does
// Extract IP address from request
let ip = extract_ip_address(req);

// ✅ GOOD - No comment needed, code is clear
let ip = extract_ip_address(req);

// ✅ GOOD - Explaining WHY
// Always return 200 to avoid leaking token validity information
let _ = self.auth_coordinator.logout(&ctx, refresh_token).await;
return Ok("Logged out successfully");

// ✅ GOOD - Explaining unusual pattern
// Manual header extraction because poem-openapi doesn't support Option<BearerAuth>
let auth = req.header("Authorization")
    .and_then(|h| h.strip_prefix("Bearer "))
    .map(|token| BearerAuth(Bearer { token: token.to_string() }));
```

### Doc Comments (Public APIs)

Use structured doc comments for public functions with `# Arguments`, `# Returns`, and `# Errors` sections:

```rust
/// Brief one-line description of what the function does
/// 
/// More detailed explanation if needed, including important behavior,
/// edge cases, or non-obvious aspects.
/// 
/// # Arguments
/// * `param_name` - Description (only if not obvious from name/type)
/// 
/// # Returns
/// * `Ok(value)` - Success case description
/// * `Err(error)` - Error case description
/// 
/// # Errors
/// Returns `ErrorType` when specific condition occurs (if not covered in Returns)
pub fn function_name(param_name: Type) -> Result<ReturnType, ErrorType>
```

**When to document parameters:**
- ✅ Parameter has constraints or special meaning
- ✅ Parameter purpose is not obvious from name/type
- ❌ Name and type make it obvious (e.g., `user_id: &str`)

**When to document returns:**
- ✅ Return value meaning is not obvious
- ✅ Multiple success/error cases need explanation
- ❌ `Result<T, E>` is self-explanatory from context

**Example:**

```rust
/// Revoke a refresh token by deleting it from the database
/// 
/// Does not verify user ownership - the refresh token itself is the authority.
/// 
/// # Arguments
/// * `token_hash` - SHA-256 hash of the refresh token to revoke
/// 
/// # Returns
/// * `Ok(user_id)` - Token revoked successfully, returns the user_id for audit logging
/// * `Err(AuthError)` - Token not found or database error
pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<String, AuthError>
```

## Security Rules

- Hash ALL passwords with argon2 (Argon2id variant) before storage
- Validate all user input in request models
- Use JWT for stateless auth (HS256 algorithm, 15 min expiration)
- Refresh tokens: 32 random bytes, base64-encoded, SHA-256 hashed for storage (7 day expiration)
- Never expose sensitive data in logs or responses
- Never log or expose passwords, tokens, or hashes
- Store only hashed refresh tokens in database, never plaintext

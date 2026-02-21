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

Four-layer architecture separating HTTP concerns, orchestration, business logic, and data access.

```
API Layer
    ↓
Coordinator Layer
    ↓
Provider Layer
    ↓
Store Layer
```

### API Layer

**Purpose**: HTTP endpoint handling only

**Responsibilities**:
- Extract data from HTTP request (headers, query params, body)
- Create RequestContext from HTTP request details
- Call coordinator with RequestContext and clean parameters
- Return HTTP responses with appropriate status codes
- **NO business logic**

**Principles**:

1. **HTTP Extraction Only**
   - Parse headers, query params, request body
   - Extract authentication tokens
   - Get client IP address
   - Generate request ID

2. **RequestContext Creation**
   - API layer creates RequestContext from HTTP details
   - RequestContext contains: actor_id, ip_address, request_id, authentication state
   - Pass complete RequestContext to coordinator (coordinator should NOT create it)

3. **Clean Parameters**
   - Extract business data from HTTP (username, password, etc.)
   - Pass as simple parameters to coordinator
   - Coordinator receives clean data, no HTTP awareness

**Example** (from `src/api/auth.rs`):
```rust
#[oai(path = "/login", method = "post")]
async fn login(&self, req: &Request, body: Json<LoginRequest>) -> LoginApiResponse {
    // Create RequestContext from HTTP request
    let ctx = self.create_request_context(req, None).await;
    
    // Call coordinator with RequestContext and clean parameters
    let response = self
        .auth_coordinator
        .login(ctx, body.username.clone(), body.password.clone())
        .await
        .unwrap_or(LoginApiResponse::Unauthorized(Json(ErrorResponse {
            message: "Unauthorized".to_owned(),
            error: "Error".to_owned(),
            status_code: 401,
        })));
    
    response
}
```

### Coordinator Layer

**Purpose**: Thin orchestration layer

**Responsibilities**:
- Compose provider actions in sequence to fulfill API requests
- Manage database transaction boundaries
- Decide which operations share a transaction
- Unwrap/transform data between provider calls
- **NO business logic** - pure orchestration only
- **NO HTTP awareness** - receives clean data from API layer

**What Coordination Means**:
- Call provider actions: `provider.do_stuff()`
- Unwrap results from one provider and pass to next provider
- Manage transaction boundaries
- Handle provider outcomes that were already decided by providers
- **Coordinate and compose, not enforce rules**

**The Key Distinction**:
- ✅ **Handling decisions made by providers** (OK): Provider returns Success/Failure, coordinator handles the outcome
- ❌ **Making business decisions** (NOT OK): Coordinator checks conditions and enforces rules

**Examples**:
```rust
// ✅ CORRECT - Handling provider's decision
match verify_result {
    Success { user } => { /* continue with next provider */ }
    Failure { reason } => Err(ApplicationError::Unauthorized)
}
// Provider decided Success/Failure, coordinator just handles the outcome

// ❌ WRONG - Coordinator making business decisions
if password.len() < 8 {  // Coordinator enforcing validation rule
    return Err(ApplicationError::InvalidPassword);
}

// ❌ WRONG - Coordinator enforcing business rule
if user.login_attempts > 3 {  // Coordinator making business decision
    return Err(ApplicationError::AccountLocked);
}
```

**Principle**: If the coordinator is checking a condition to enforce a rule, it's wrong. If the coordinator is unwrapping a result that a provider already decided, it's correct.

**Principles**:

1. **No HTTP Awareness**
   - Coordinator receives `RequestContext` (already created by API)
   - Coordinator receives clean parameters (username, password, etc.)
   - Coordinator does NOT know about headers, query params, or HTTP details
   - API layer handles all HTTP extraction and creates RequestContext

2. **Pure Orchestration**
   - Chain provider calls: `result1 = provider1.action()`, `result2 = provider2.action(result1)`
   - Unwrap data: Extract fields from provider results to pass to next provider
   - Handle outcomes: Match on provider results to continue flow or return error
   - **Coordinate and compose, not enforce rules**
   - If coordinator is checking a condition to enforce a rule → WRONG (belongs in provider)
   - If coordinator is unwrapping a result already decided by provider → CORRECT

3. **Transaction Management**
   - Begin transactions: `connections.begin_auth_transaction()`
   - Decide transaction boundaries: Same connection = same transaction
   - Pass connection to all provider/store calls within transaction
   - If work can be split into multiple transactions, it's likely multiple provider actions

**Example** (from `src/coordinators/login_coordinator.rs`):
```rust
pub async fn login(
    &self,
    ctx: RequestContext,  // Already created by API layer
    username: String,     // Clean parameters, no HTTP details
    password: String,
) -> Result<LoginApiResponse, ApplicationError> {
    // Begin transaction
    let conn = self.connections.begin_auth_transaction().await?;
    
    // Orchestrate provider actions - just call and unwrap
    let verify_result = self.authentication_provider
        .verify_credential(&conn, LoginRequest { username, password })
        .await?;
    
    // Unwrap result to get data for next provider
    match verify_result {
        Success { user } => {
            // Get data needed for JWT
            let user_for_jwt = self.authentication_store
                .get_user_roles_for_jwt(&conn, &user.id)
                .await?;
            
            // Generate tokens
            let jwt = self.token_provider.generate_jwt(&user_for_jwt).await?;
            let rt = self.token_provider.generate_refresh_token()?;
            
            // Save refresh token
            self.authentication_store
                .save_refresh_token_for_user(&conn, &user.id, &rt.token_hash, 
                                            rt.created_at, rt.expires_at)
                .await?;
            
            // Return response
            Ok(LoginApiResponse::Ok(Json(TokenResponse { ... })))
        }
        Failure { reason } => Err(ApplicationError::UnknownServerError { ... })
    }
}
```

### Provider Layer

**Purpose**: Domain-specific work performers

**Responsibilities**:
- Perform actual business logic
- Domain operations (authentication, token generation, cryptography, etc.)
- Make business decisions (control flow, validation, etc.)
- Composable - designed to be called by coordinators
- Can call other providers (especially cross-cutting providers)
- Can call stores (passing connection through)

**Principles**:

1. **Business Logic Lives Here**
   - All if/else decisions based on business rules
   - Validation logic
   - Calculations and transformations
   - Domain-specific workflows

2. **Composability**
   - Providers are split by what needs to be composable by API actions
   - Domain providers: Split by business domain (AuthenticationProvider, UserProvider)
   - Cross-cutting providers: Shared utilities (CryptoProvider, TokenProvider)
   - Providers can call other providers when business logic requires it

3. **Connection Handling**
   - Receive connection from coordinator: `conn: &impl ConnectionTrait`
   - Pass connection to stores
   - Pass connection to other providers if needed
   - Do NOT begin transactions (coordinator's responsibility)

**Provider Types**:
- **Domain Providers**: Split by business domain (AuthenticationProvider, UserProvider)
  - Called by coordinators
  - Generally don't call each other (domains are separate)
- **Cross-cutting Providers**: Utility/infrastructure (CryptoProvider, TokenProvider)
  - Called by domain providers and coordinators
  - Shared across domains

**Example** (from `src/providers/authentication_provider.rs`):
```rust
pub async fn verify_credential(
    &self,
    conn: &impl ConnectionTrait,
    creds: LoginRequest,
) -> ProviderResult<VerifyCredentialResult> {
    // Call store to get user
    let user = self.authentication_store
        .get_user_from_username_for_auth(conn, &creds.username)
        .await?;
    
    // Call cross-cutting provider for crypto work
    let authenticated = self.crypto_provider
        .verify_password(&user.password_hash, &creds.password)
        .await?;
    
    // Business logic decision
    match authenticated {
        true => ProviderResult::new(VerifyCredentialResult::Success { user }),
        false => Ok(ActionOutcome::new(VerifyCredentialResult::Failure {
            reason: LoginFailureReason::InvalidCredentials,
        })),
    }
}
```

### Store Layer

**Purpose**: Database query abstraction

**Responsibilities**:
- Execute database queries
- Abstract away complex query logic
- Data access only
- **NO business logic**

**Principles**:

1. **Stateless Pattern**
   - Stores have no database connection field
   - Stores are empty structs or have no fields: `pub struct AuthenticationStore;`
   - Constructor returns `Self`: `pub fn new() -> Self { Self }`

2. **Connection as Parameter**
   - All methods receive connection: `conn: &impl ConnectionTrait`
   - Connection passed from coordinator (who manages transactions)
   - `ConnectionTrait` works for both regular connections and transactions

3. **Query Abstraction**
   - Encapsulate complex SeaORM queries
   - Return domain-appropriate types (not raw database entities)
   - Handle query errors and convert to internal errors

4. **No Business Logic**
   - Just execute queries
   - No validation, no calculations, no decisions
   - Business logic belongs in providers

**Example** (from `src/stores/authentication_store.rs`):
```rust
pub struct AuthenticationStore;  // Stateless - no fields

impl AuthenticationStore {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn get_user_from_username_for_auth(
        &self,
        conn: &impl ConnectionTrait,  // Connection passed as parameter
        username: &str,
    ) -> Result<UserForAuth, InternalError> {
        let user = crate::types::db::user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .filter(user::Column::IsOwner.eq(false))
            .select_only()
            .column(user::Column::Id)
            .column(user::Column::Username)
            .column(user::Column::PasswordHash)
            .into_model::<UserForAuth>()
            .one(conn)  // Use passed connection
            .await
            .map_err(|e| InternalError::Database(DatabaseError::Operation {
                operation: "get_user_from_username_for_auth",
                source: e,
            }))?;
        
        match user {
            Some(u) => Ok(u),
            None => Err(InternalError::Login(UsernameNotFound {
                username: username.to_owned(),
            })),
        }
    }
}
```

### Dependency Flow

```
API Layer
    ↓ calls
Coordinator Layer
    ↓ calls (manages transactions)
    ├─ Domain Provider
    │   ↓ calls
    │   ├─ Cross-cutting Provider
    │   │   ↓ calls
    │   │   └─ Store
    │   └─ Store
    └─ Store
```

**Rules**:
- APIs call Coordinators only
- Coordinators call Providers and Stores
- Providers call other Providers (especially cross-cutting) and Stores
- Stores call nothing (just execute queries)
- No upward calls (Provider cannot call Coordinator)

### Transaction Management

**Coordinator Controls Boundaries**:
- Coordinator decides what operations share a transaction
- Coordinator begins transaction: `let conn = self.connections.begin_auth_transaction().await?`
- Coordinator passes same connection to all operations that should be atomic
- If operations should be in separate transactions, coordinator manages multiple connections

**Connection Passing**:
```rust
// Coordinator begins transaction
let conn = self.connections.begin_auth_transaction().await?;

// Pass to provider
self.provider.do_work(&conn, data).await?;

// Provider passes to store
pub async fn do_work(&self, conn: &impl ConnectionTrait, data: Data) -> Result<...> {
    self.store.query(conn, data).await?;
}

// Store uses connection
pub async fn query(&self, conn: &impl ConnectionTrait, data: Data) -> Result<...> {
    Entity::find().one(conn).await?;
}
```

**ConnectionTrait**:
- SeaORM trait that abstracts both connections and transactions
- All database parameters use `conn: &impl ConnectionTrait`
- Works for regular connections and transaction connections

### Key Principles

1. **Separation of Concerns**:
   - API = HTTP handling
   - Coordinator = Orchestration + Transaction boundaries
   - Provider = Business logic
   - Store = Data access

2. **Stateless Stores**:
   - No database connection fields
   - Connections passed as parameters
   - Coordinator controls transaction scope

3. **Composable Providers**:
   - Split by domain and composability needs
   - Cross-cutting providers shared across domains
   - Providers can call other providers

4. **Transaction Control**:
   - Coordinator decides transaction boundaries
   - Same connection = same transaction
   - Different connections = different transactions

### Reference Implementation

See the auth flow for the canonical example:
- API: `src/api/auth.rs`
- Coordinator: `src/coordinators/login_coordinator.rs`
- Providers: `src/providers/authentication_provider.rs`, `src/providers/token_provider.rs`, `src/providers/crypto_provider.rs`
- Stores: `src/stores/authentication_store.rs`, `src/stores/user_store.rs`

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

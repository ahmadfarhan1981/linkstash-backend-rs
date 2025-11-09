# Design Document

## Overview

This document outlines the design for refactoring the Linkstash backend from a feature-based architecture to a layer-based architecture. The refactoring will reorganize code by technical responsibility while preserving all existing functionality, tests, and API contracts.

### Current Structure (Feature-Based)

```
src/
├── main.rs
├── api.rs              # Health and items endpoints
├── models.rs           # Shared DTOs
└── auth/               # Auth feature module
    ├── mod.rs
    ├── api.rs          # Auth endpoints
    ├── models.rs       # Auth DTOs
    ├── errors.rs       # Auth errors
    ├── credential_store.rs
    ├── token_manager.rs
    └── entities/
        ├── user.rs
        └── refresh_token.rs
```

### Target Structure (Layer-Based)

```
src/
├── main.rs
├── api/                # All HTTP endpoints
│   ├── mod.rs
│   ├── health.rs
│   ├── items.rs
│   └── auth.rs
├── types/              # All data structures
│   ├── mod.rs
│   ├── db/             # Database entities
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   └── refresh_token.rs
│   ├── dto/            # API contracts
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── items.rs
│   │   └── common.rs
│   └── internal/       # Internal types
│       ├── mod.rs
│       └── auth.rs
├── services/           # Business logic
│   ├── mod.rs
│   └── token_service.rs
├── stores/             # Data access
│   ├── mod.rs
│   └── credential_store.rs
└── errors/             # Error types
    ├── mod.rs
    └── auth.rs
```

## Architecture

### Layer Dependency Flow

```
┌─────────────────────────────────────────┐
│              main.rs                    │
│  (Server setup, DI, route registration) │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│              api/                       │
│  (HTTP endpoints, request/response)     │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│           services/                     │
│  (Business logic, orchestration)        │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│            stores/                      │
│  (Database operations, queries)         │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│           types/db/                     │
│  (SeaORM entities, schema)              │
└─────────────────────────────────────────┘

Cross-cutting:
- types/dto/     (used by api/)
- types/internal/ (used by services/, stores/)
- errors/        (used by all layers)
```

### Design Principles

1. **Single Responsibility**: Each layer has one clear purpose
2. **Dependency Direction**: Dependencies flow downward (API → Services → Stores → Entities)
3. **Encapsulation**: Lower layers don't know about upper layers
4. **Testability**: Each layer can be tested independently with mocks
5. **Zero Regression**: All existing functionality and tests must pass

## Components and Interfaces

### 1. API Layer (`src/api/`)

**Responsibility**: HTTP endpoint handling, request/response serialization, status codes

#### Files

**`api/mod.rs`**
```rust
pub mod health;
pub mod items;
pub mod auth;

pub use health::*;
pub use items::*;
pub use auth::*;
```

**`api/health.rs`**
- Struct: `HealthApi`
- Endpoints: `GET /health`
- Dependencies: None
- Returns: `types::dto::common::HealthResponse`

**`api/items.rs`**
- Struct: `ItemsApi`
- Endpoints: `POST /items`
- Dependencies: None (currently mock implementation)
- Uses: `types::dto::items::{CreateItemRequest, Item}`

**`api/auth.rs`**
- Struct: `AuthApi`
- Endpoints: `POST /auth/login`, `GET /auth/whoami`, `POST /auth/refresh`
- Dependencies: `Arc<CredentialStore>`, `Arc<TokenService>`
- Uses: `types::dto::auth::*`, `errors::auth::AuthError`

### 2. Types Layer (`src/types/`)

**Responsibility**: Data structure definitions

#### Database Entities (`types/db/`)

**`types/db/user.rs`**
```rust
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub created_at: i64,
}
```

**`types/db/refresh_token.rs`**
```rust
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
    pub id: i32,
    pub token_hash: String,
    pub user_id: String,
    pub expires_at: i64,
    pub created_at: i64,
}
```

#### DTOs (`types/dto/`)

**`types/dto/auth.rs`**
- `LoginRequest` - username, password
- `TokenResponse` - access_token, refresh_token, token_type, expires_in
- `WhoAmIResponse` - user_id, expires_at
- `RefreshRequest` - refresh_token
- `RefreshResponse` - access_token, token_type, expires_in

**`types/dto/items.rs`**
- `CreateItemRequest` - name, description
- `Item` - id, name, description, created_at

**`types/dto/common.rs`**
- `HealthResponse` - status, timestamp
- `ErrorResponse` - error, message, status_code

#### Internal Types (`types/internal/`)

**`types/internal/auth.rs`**
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user_id
    pub exp: i64,     // expiration
    pub iat: i64,     // issued at
}
```

### 3. Services Layer (`src/services/`)

**Responsibility**: Business logic, orchestration

**`services/token_service.rs`** (renamed from `token_manager.rs`)
- `TokenService::new(jwt_secret: String) -> Self`
- `generate_jwt(&self, user_id: &Uuid) -> Result<String, AuthError>`
- `validate_jwt(&self, token: &str) -> Result<Claims, AuthError>`
- `generate_refresh_token(&self) -> String`
- `hash_refresh_token(&self, token: &str) -> String`
- `get_refresh_expiration(&self) -> i64`

**Future**: `services/auth_service.rs` could orchestrate login/refresh flows

### 4. Stores Layer (`src/stores/`)

**Responsibility**: Database operations, query encapsulation

**`stores/credential_store.rs`**
- `CredentialStore::new(db: DatabaseConnection) -> Self`
- `add_user(&self, username: String, password: String) -> Result<String, AuthError>`
- `verify_credentials(&self, username: &str, password: &str) -> Result<String, AuthError>`
- `store_refresh_token(&self, token_hash: String, user_id: String, expires_at: i64) -> Result<(), AuthError>`
- `validate_refresh_token(&self, token_hash: &str) -> Result<String, AuthError>`

### 5. Errors Layer (`src/errors/`)

**Responsibility**: Error type definitions

**`errors/auth.rs`**
```rust
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials(String),
    DuplicateUsername(String),
    InvalidToken(String),
    ExpiredToken(String),
    InvalidRefreshToken(String),
    ExpiredRefreshToken(String),
    MissingAuthHeader(String),
    InvalidAuthHeader(String),
    InternalError(String),
}

impl poem::error::ResponseError for AuthError { ... }
```

## Data Models

### Entity Relationships

```
┌─────────────────┐
│     users       │
│─────────────────│
│ id (PK)         │◄──┐
│ username        │   │
│ password_hash   │   │
│ created_at      │   │
└─────────────────┘   │
                      │
                      │ FK
                      │
┌─────────────────┐   │
│ refresh_tokens  │   │
│─────────────────│   │
│ id (PK)         │   │
│ token_hash      │   │
│ user_id (FK)    │───┘
│ expires_at      │
│ created_at      │
└─────────────────┘
```

### Data Flow Example: Login

```
1. Client → POST /auth/login {username, password}
2. api/auth.rs → AuthApi::login()
3. stores/credential_store.rs → verify_credentials()
4. types/db/user.rs → Query User entity
5. stores/credential_store.rs → Return user_id
6. services/token_service.rs → generate_jwt(user_id)
7. services/token_service.rs → generate_refresh_token()
8. stores/credential_store.rs → store_refresh_token()
9. api/auth.rs → Return TokenResponse
10. Client ← 200 OK {access_token, refresh_token}
```

## Error Handling

### Error Propagation

```
Store Error → AuthError → HTTP Status Code
─────────────────────────────────────────
Database error → InternalError → 500
User not found → InvalidCredentials → 401
Expired JWT → ExpiredToken → 401
Missing header → MissingAuthHeader → 401
```

### Error Response Format

All errors return consistent JSON:
```json
{
  "error": "InvalidCredentials",
  "message": "Invalid username or password"
}
```

## Testing Strategy

### Unit Tests

**Stores** (`stores/credential_store.rs`)
- Test with in-memory SQLite database
- Verify password hashing
- Test duplicate username handling
- Test token storage and validation

**Services** (`services/token_service.rs`)
- Test JWT generation and validation
- Test refresh token generation
- Test token hashing
- Mock-free (pure logic)

**API** (`api/auth.rs`)
- Test with mocked stores and services
- Verify HTTP status codes
- Test header parsing
- Test request/response serialization

### Integration Tests

- Full flow tests with real database
- Test login → whoami → refresh flows
- Verify Swagger UI generation
- Test server startup

### Migration Testing

After each migration step:
1. Run `cargo build` - must succeed
2. Run `cargo test` - all tests must pass
3. Verify no broken imports
4. Check Swagger UI still generates

## Migration Strategy

### Phase 1: Create New Structure

1. Create all new directories:
   - `src/api/`
   - `src/types/db/`
   - `src/types/dto/`
   - `src/types/internal/`
   - `src/services/`
   - `src/stores/`
   - `src/errors/`

2. Create placeholder `mod.rs` files in each directory

### Phase 2: Move Types

1. Move entities:
   - `src/auth/entities/user.rs` → `src/types/db/user.rs`
   - `src/auth/entities/refresh_token.rs` → `src/types/db/refresh_token.rs`

2. Move DTOs:
   - Extract from `src/auth/models.rs` → `src/types/dto/auth.rs`
   - Extract from `src/models.rs` → `src/types/dto/items.rs` and `src/types/dto/common.rs`

3. Move internal types:
   - Extract `Claims` from `src/auth/models.rs` → `src/types/internal/auth.rs`

4. Update `types/mod.rs` to export all submodules

5. Update imports in stores and services

6. Verify: `cargo build`

### Phase 3: Move Errors

1. Move `src/auth/errors.rs` → `src/errors/auth.rs`

2. Update `errors/mod.rs`

3. Update imports throughout codebase

4. Verify: `cargo build`

### Phase 4: Move Stores

1. Move `src/auth/credential_store.rs` → `src/stores/credential_store.rs`

2. Update imports to use `types::db::*`

3. Update `stores/mod.rs`

4. Verify: `cargo build && cargo test`

### Phase 5: Move Services

1. Move `src/auth/token_manager.rs` → `src/services/token_service.rs`

2. Rename struct `TokenManager` → `TokenService`

3. Update imports to use `types::internal::*`

4. Update `services/mod.rs`

5. Update references in `main.rs` and `api/auth.rs`

6. Verify: `cargo build && cargo test`

### Phase 6: Move API

1. Split `src/api.rs`:
   - Health endpoint → `src/api/health.rs`
   - Items endpoint → `src/api/items.rs`

2. Move `src/auth/api.rs` → `src/api/auth.rs`

3. Update imports to use `types::dto::*`, `services::*`, `stores::*`, `errors::*`

4. Update `api/mod.rs`

5. Update `main.rs` to import from `api::*`

6. Verify: `cargo build && cargo test`

### Phase 7: Cleanup

1. Delete old directories:
   - `src/auth/`
   - `src/models.rs`
   - `src/api.rs`

2. Update `main.rs` module declarations

3. Final verification:
   - `cargo build --release`
   - `cargo test`
   - Start server and check Swagger UI
   - Test all endpoints manually

## Risk Mitigation

### Risks

1. **Import Path Breakage**: Many files reference moved modules
   - Mitigation: Move one layer at a time, compile after each step

2. **Test Failures**: Tests may break due to import changes
   - Mitigation: Update test imports immediately after moving files

3. **Circular Dependencies**: Incorrect layer dependencies
   - Mitigation: Follow strict dependency flow (API → Services → Stores → Entities)

4. **Lost Functionality**: Features may break during refactoring
   - Mitigation: Run full test suite after each phase

5. **Merge Conflicts**: If working on active codebase
   - Mitigation: Complete refactoring in a single session, or use feature branch

### Rollback Plan

If issues arise:
1. Revert to previous commit (use git)
2. Complete current phase before stopping
3. Never leave codebase in non-compiling state

## Success Criteria

1. ✅ All files organized by layer
2. ✅ `cargo build` succeeds
3. ✅ `cargo test` passes (all existing tests)
4. ✅ Server starts successfully
5. ✅ Swagger UI accessible at `/swagger`
6. ✅ All API endpoints functional
7. ✅ No SeaORM imports outside `stores/` and `types/db/`
8. ✅ Clear layer separation maintained
9. ✅ All imports use new module paths
10. ✅ Old feature-based directories removed

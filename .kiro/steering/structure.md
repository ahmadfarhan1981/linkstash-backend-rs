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
│   ├── items.rs               # Item management endpoints
│   └── auth.rs                # Authentication endpoints
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
│   │   ├── items.rs           # CreateItemRequest, Item
│   │   └── common.rs          # HealthResponse, ErrorResponse
│   │
│   └── internal/              # Internal-only types
│       ├── mod.rs
│       └── auth.rs            # Claims (JWT payload)
│
├── services/                  # Business logic layer
│   ├── mod.rs
│   ├── auth_service.rs        # Auth orchestration (login/refresh flows)
│   └── token_service.rs       # JWT generation/validation
│
├── stores/                    # Data access layer (Repository pattern)
│   ├── mod.rs
│   └── credential_store.rs    # User credential DB operations
│
└── errors/                    # Error types
    ├── mod.rs
    └── auth.rs                # AuthError with ResponseError impl
```

## Layer Responsibilities

- **api/** - HTTP endpoints, request handling, OpenAPI tags, status codes
- **types/db/** - SeaORM entities representing database schema
- **types/dto/** - API request/response models with poem-openapi decorators
- **types/internal/** - Internal data structures not exposed via API or DB
- **services/** - Business logic, orchestration between stores
- **stores/** - Database operations, query encapsulation (Repository pattern)
- **errors/** - Custom error types implementing ResponseError

## API Patterns

- All endpoint structs use `#[OpenApi]` macro with `tags` parameter
- Endpoints return `poem::Result<T>` with proper status codes (200, 201, 401, 404)
- All routes under `/api` base path
- Request types: `poem_openapi::Object` with validation
- Response types: `poem_openapi::Object` or `poem_openapi::ApiResponse`

## Naming

- Files: `snake_case.rs`
- Types: `PascalCase` with pattern `{Action}{Resource}{Request|Response}` (e.g., `LoginRequest`, `CreateItemResponse`)
- Functions/variables: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Endpoints: RESTful (`/auth/login`, `/items/{id}`)

## Error Handling

- Custom error enums implement `poem::error::ResponseError`
- Service functions return `Result<T, CustomError>`
- Consistent JSON format: `{ "error": "message" }`
- Never log/expose passwords or tokens

## Database

- Entities use `DeriveEntityModel` in `types/db/`
- Migrations in `migration/src/` with descriptive names
- Connection pool managed in `main.rs`
- Always use SeaORM's async API
- Stores encapsulate all database queries (no SeaORM usage outside stores)

## Security Rules

- Hash ALL passwords with argon2 before storage
- Validate all user input in request models
- Use JWT for stateless auth
- Never expose sensitive data in logs or responses

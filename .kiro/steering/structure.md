---
inclusion: always
---

# Code Structure & Conventions

## Module Organization

```
src/
├── main.rs              # Server setup + route registration ONLY
├── api.rs               # Root endpoints (health, items)
├── models.rs            # Shared types
└── {feature}/           # Feature modules (e.g., auth/)
    ├── mod.rs           # Public exports only
    ├── api.rs           # Endpoints with #[OpenApi]
    ├── models.rs        # Request/response types
    ├── service.rs       # Business logic
    └── entities/        # SeaORM entities
```

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

- Entities use `DeriveEntityModel` in `{module}/entities/`
- Migrations in `migration/src/` with descriptive names
- Connection pool managed in `main.rs`
- Always use SeaORM's async API

## Security Rules

- Hash ALL passwords with argon2 before storage
- Validate all user input in request models
- Use JWT for stateless auth
- Never expose sensitive data in logs or responses

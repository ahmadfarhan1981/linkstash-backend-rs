# Project Structure

## Organization

```
linkstash-backend-rs/
├── src/
│   ├── main.rs              # Application entry point, server setup
│   ├── api.rs               # API endpoint definitions
│   ├── models.rs            # Request/response models
│   └── auth/                # Authentication module (planned)
│       ├── mod.rs
│       ├── api.rs
│       ├── models.rs
│       ├── service.rs
│       ├── token_manager.rs
│       ├── credential_store.rs
│       ├── errors.rs
│       └── entities/
├── migration/               # Database migrations (SeaORM)
├── .kiro/
│   ├── specs/              # Feature specifications
│   └── steering/           # Project guidelines
├── Cargo.toml
└── .gitignore
```

## Conventions

### Code Organization
- **Modules**: Group related functionality (e.g., `auth/`, `api/`)
- **Models**: Define request/response types with `poem_openapi::Object`
- **Entities**: Database models using SeaORM's `DeriveEntityModel`

### API Endpoints
- All endpoints use `#[OpenApi]` macro for automatic documentation
- Endpoints grouped by feature using tags
- Base path: `/api`
- Versioning: Consider `/api/v1` for future versions

### Naming
- **Endpoints**: RESTful conventions (`/items`, `/auth/login`)
- **Models**: Descriptive names (`CreateItemRequest`, `TokenResponse`)
- **Files**: Snake case (`token_manager.rs`, `credential_store.rs`)

### Error Handling
- Return `Result` types from endpoints
- Use custom error types that convert to HTTP responses
- Consistent error response format across all endpoints

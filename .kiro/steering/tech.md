# Technology Stack

## Platform

- Operating System: Windows
- Shell: cmd

## Tech Stack

### Backend Framework
- **Poem** - Async web framework for Rust
- **poem-openapi** - OpenAPI 3.0 integration with automatic Swagger UI generation
- **Tokio** - Async runtime

### API Documentation
- OpenAPI 3.0 specification (auto-generated at compile time)
- Swagger UI served at `/swagger`
- Type-safe API definitions using macros

### Database & ORM
- **SeaORM** - Async ORM with migration support
- **SQLite** - Development and production database (can migrate to PostgreSQL)

### Authentication
- **jsonwebtoken** - JWT generation and validation
- **argon2** - Password hashing

### Dependencies
```toml
poem = "3.1"
poem-openapi = { version = "5.1", features = ["swagger-ui"] }
tokio = { version = "1.42", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.0", features = ["v4", "serde"] }
sea-orm = { version = "0.12", features = ["sqlx-sqlite", "runtime-tokio-native-tls", "macros"] }
jsonwebtoken = "9.2"
argon2 = "0.5"
```

## Server Configuration

- **Host**: 0.0.0.0 (all interfaces)
- **Port**: 3000
- **API Base Path**: `/api`
- **Swagger UI**: `/swagger`

## Common Commands

### Development
```bash
# Run the application
cargo run

# Run with hot reload (requires cargo-watch)
cargo watch -x run

# Run tests
cargo test

# Build for release
cargo build --release
```

### Database
```bash
# Run migrations
sea-orm-cli migrate up

# Create new migration
sea-orm-cli migrate generate <migration_name>
```

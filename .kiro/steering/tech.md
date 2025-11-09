---
inclusion: always
---

# Technology Stack

## Critical Rules

- This is a BINARY application with `main.rs` entry point
- Use `cargo run`, `cargo test`, `cargo build` (NOT `cargo test --lib`)
- Platform: Windows with cmd shell
- All code must be fully async using Tokio runtime

## Core Stack

- **Poem 3.1** - Web framework with `#[OpenApi]` macro for endpoints
- **poem-openapi 5.1** - Auto-generates OpenAPI 3.0 specs and Swagger UI at `/swagger`
- **SeaORM 0.12** - Async ORM with SQLite (features: `sqlx-sqlite`, `runtime-tokio-native-tls`, `macros`)
- **jsonwebtoken 9.2** - JWT generation/validation
- **argon2 0.5** - Password hashing (use for all password storage)

## Server Config

- Host: `0.0.0.0:3000`
- API base: `/api`
- Swagger UI: `/swagger`

## Commands

```bash
cargo run              # Start server
cargo test             # Run tests
cargo build --release  # Production build
sea-orm-cli migrate up # Run migrations
```

## Manual Testing

- **ALWAYS** use `controlPwshProcess` with action "start" to run the server in the background for manual testing
- **NEVER** use `executePwsh` with `cargo run` during manual tests (it blocks execution)
- Set JWT_SECRET environment variable before starting: `$env:JWT_SECRET="test-secret-key-minimum-32-characters-long"`
- Use `getProcessOutput` to check server logs
- Use `controlPwshProcess` with action "stop" to stop the server when done
- Test endpoints via curl or by checking Swagger UI at http://localhost:3000/swagger

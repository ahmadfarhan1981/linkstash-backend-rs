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
- **jsonwebtoken 9.2** - JWT generation/validation (HS256 algorithm)
- **argon2 0.5** - Password hashing with Argon2id (use for all password storage)
- **rand 0.8** - Cryptographically secure random number generation
- **sha2 0.10** - SHA-256 hashing for refresh tokens
- **base64 0.21** - Base64 encoding for refresh tokens
- **dotenv 0.15** - Load environment variables from `.env` file for local development

## Environment Configuration

- **ALWAYS** use `.env` file for local environment variables (never commit this file)
- `.env.example` contains template with example values (commit this)
- `dotenv::dotenv().ok()` loads `.env` at startup in `main.rs`
- In production, use actual environment variables (dotenv silently skips if `.env` doesn't exist)
- Required variables: `JWT_SECRET` (minimum 32 characters)
- Optional variables: `DATABASE_URL` (defaults to `sqlite://auth.db?mode=rwc`)

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
- Environment variables are loaded from `.env` file automatically (no need to set manually)
- Ensure `.env` file exists with required variables before starting server
- Use `getProcessOutput` to check server logs
- Use `controlPwshProcess` with action "stop" to stop the server when done
- Test endpoints via curl or by checking Swagger UI at http://localhost:3000/swagger

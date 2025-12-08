---
inclusion: always
---

# Technology Stack

## Critical Rules

- This is a BINARY application with `main.rs` entry point
- Use `cargo run`, `cargo test --lib`, `cargo build` for development
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

- Host/Port: Configured via `HOST` and `PORT` environment variables (defaults: `0.0.0.0:3000`)
- Check `.env` file for actual server address
- API base: `/api`
- Swagger UI: `/swagger`

## Commands

```bash
cargo run                      # Start server (migrations run automatically on startup)
cargo run migrate              # Run database migrations only (does not start server)
cargo test --lib               # Run library tests
cargo build --release          # Production build
```

## Database Migrations

- Migrations run automatically on server startup and before CLI commands
- Use `cargo run migrate` to run migrations independently without starting the server

## Manual Testing

- **ALWAYS** use `controlPwshProcess` with action "start" to run the server in the background for manual testing
- **NEVER** use `executePwsh` with `cargo run` during manual tests (it blocks execution)
- Environment variables are loaded from `.env` file automatically (no need to set manually)
- **ALWAYS** modify `.env` file for environment variable changes during manual testing (never set via shell)
- Ensure `.env` file exists with required variables before starting server
- Use `getProcessOutput` to check server logs
- Use `controlPwshProcess` with action "stop" to stop the server when done
- Test endpoints via curl or by checking Swagger UI (check `.env` for HOST/PORT, default: http://localhost:3000/swagger)

## Testing Workflow for AI Agents

**WHEN TO USE:** Testing requires a clean database with known credentials. Existing development data causes unexpected test behavior.

**REQUIRED STEPS:**

1. **Delete existing test databases:**
```bash
del test-auth.db test-audit.db
```

2. **Bootstrap with fixed credentials using test.env:**
```bash
cargo run -- --env-file test.env bootstrap --non-interactive
```
Creates: 1 owner (inactive), 0 admins

3. **Activate owner:**
```bash
cargo run -- --env-file test.env owner activate
```

**FIXED TEST CREDENTIALS:**
- Username: `test-owner`
- Password: `test-owner-password-do-not-use-in-production`

**CRITICAL RULES:**
- ALWAYS delete database files before bootstrap (ensures clean state)
- ALWAYS use `--env-file test.env` flag for all test commands
- Owner account starts INACTIVE - must run `owner activate` before use
- Non-interactive bootstrap only available in debug builds or with `--features test-utils`
- The `--env-file` flag must come BEFORE the subcommand (e.g., `cargo run -- --env-file test.env bootstrap`)

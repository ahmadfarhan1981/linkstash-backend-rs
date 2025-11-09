---
inclusion: always
---

# Product: Linkstash Backend

Rust REST API with JWT authentication, auto-generated OpenAPI docs, and Swagger UI.

## Architecture Principles

- **Type Safety First** - Leverage Rust's compile-time guarantees
- **Documentation from Code** - OpenAPI specs auto-generated via macros
- **Security by Default** - JWT auth, argon2 hashing, input validation
- **Fully Async** - Tokio runtime throughout
- **Minimal Complexity** - Clear structure, essential dependencies only

## Feature Status

**Implemented:**
- Poem web framework with async support
- Auto-generated Swagger UI at `/swagger`
- Type-safe API definitions
- Health check endpoint
- JWT authentication (access + refresh tokens)
- User credential management with argon2 password hashing
- SQLite with SeaORM
- Login endpoint with database-backed authentication
- JWT generation and validation (15 min expiration)
- Refresh token generation and storage (7 day expiration, SHA-256 hashed)
- Token refresh endpoint
- WhoAmI endpoint for JWT validation

**Planned:**
- Logout endpoint with token revocation
- Expired token cleanup (background task)
- Token rotation
- Multi-device sessions
- Rate limiting
- Password reset
- User registration

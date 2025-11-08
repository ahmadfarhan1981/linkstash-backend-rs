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

**In Progress:**
- JWT authentication (access + refresh tokens)
- User credential management
- SQLite with SeaORM

**Planned:**
- Token rotation
- Multi-device sessions
- Rate limiting
- Password reset
- User registration

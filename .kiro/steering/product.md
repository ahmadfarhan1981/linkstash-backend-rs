# Product Overview

Linkstash Backend - A Rust-based REST API backend with JWT authentication.

## Purpose

Provide a secure, performant backend API with:
- RESTful endpoints with automatic OpenAPI documentation
- JWT-based authentication with refresh tokens
- Type-safe request/response handling
- Interactive API documentation via Swagger UI

## Key Features

### Current
- ✅ Poem web framework with async support
- ✅ Automatic Swagger UI generation
- ✅ Type-safe API definitions
- ✅ Health check endpoint
- ✅ Item management endpoints (example)

### In Development
- 🚧 JWT authentication system
- 🚧 User credential management
- 🚧 Refresh token support
- 🚧 SQLite database with SeaORM

### Planned
- Token rotation
- Multi-device session management
- Rate limiting
- Password reset
- OAuth2/OIDC integration
- Audit logging
- User registration

## Architecture Principles

- **Type Safety**: Leverage Rust's type system for compile-time guarantees
- **Documentation First**: Auto-generate OpenAPI specs from code
- **Security**: JWT tokens, password hashing, secure token storage
- **Simplicity**: Minimal dependencies, clear structure
- **Async**: Fully async using Tokio runtime

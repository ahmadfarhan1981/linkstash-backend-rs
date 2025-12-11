---
inclusion: always
---

# Product Context: Linkstash Backend (Rust)

## What This Project Is

An authentication and identity management service evolving toward a self-hostable OAuth 2.0 Identity Provider.

**Critical for AI agents:** This is a learning-focused hobby project. Features are added as interesting security challenges arise. The user explores side roads frequently but has a clear destination.

## Core Scope Boundaries

**IN SCOPE:**
- Authentication (who are you?)
- Identity management (user IDs, roles as arbitrary strings)
- Token management (JWT, refresh tokens, elevated tokens)
- Security infrastructure (audit logs, rate limiting, MFA)

**OUT OF SCOPE:**
- Authorization logic (downstream apps decide what roles mean)
- User data/profiles (only username, password hash, roles)
- Frontend/UI (REST API only, frontend-agnostic)
- Policy engines or permission systems

**Key architectural decision:** This system manages opaque user IDs and role strings. It says "user X has roles [A, B, C]" but doesn't interpret what those roles mean. Authorization is delegated to downstream applications.

## User's Guiding Principles (Apply These When Suggesting Features)

1. **Security First** - Apply production-grade security practices even at hobby scale
2. **Minimal User Information** - Privacy by design, opaque identifiers
3. **Frontend Agnostic** - Pure REST API, any client can integrate
4. **Standards-Based** - Follow OWASP, NIST, industry best practices
5. **Self-Hostable** - Design for easy deployment (future: Docker/binary)
6. **Build From Scratch** - Implement features directly using low-level primitives. Use cryptographic libraries (Argon2, JWT, SHA-256) and basic infrastructure (web framework, ORM), but avoid high-level frameworks that abstract away the implementation (no auth frameworks, OAuth libraries, rate-limiting crates, etc.). The goal is to learn by building

## Direction & Priorities

**Near Term Focus:** Full-featured user management
- TOTP multi-factor authentication
- Account lockout (admin review + time-based unlock)
- Sophisticated multi-dimensional rate limiting (per-user, per-action, per-IP-class, soft degradation)
- Complete admin role system

**Mid-to-Far Term Goal:** OAuth 2.0 / OIDC Identity Provider
- OAuth 2.0 authorization server
- OpenID Connect support
- Client application management

**Ongoing Interests (Likely Side Roads):**
- Token security patterns (families, rotation)
- Timing attack mitigation
- Advanced rate limiting strategies
- Audit logging and forensics
- Keyed hashing and cryptographic security

## How to Work With This Project

**When checking what exists:**
- Don't trust this doc for feature inventory (it drifts)
- Check `src/api/*.rs` for actual endpoint implementations
- Check `.kiro/specs/` for designed features and their status
- Check `src/types/db/` for data models
- Verify via code, not assumptions

**When suggesting features:**
- Align with security-first principle
- Keep user data minimal
- Assume downstream apps handle authorization
- Consider production-grade security even if overkill for hobby scale
- Check if it fits the "auth/identity only" scope

**When user explores a "side road":**
- Support the exploration (it's part of the learning process)
- Keep the core principles in mind
- Help connect it back to the main vision when appropriate

## Tech Stack

- Rust with Tokio (fully async)
- Poem web framework + poem-openapi (auto-generated Swagger)
- SeaORM + SQLite
- JWT (HS256), Argon2id password hashing
- Layer-based architecture (API → Coordinator → Provider → Store)

See tech.md and structure.md for detailed conventions.

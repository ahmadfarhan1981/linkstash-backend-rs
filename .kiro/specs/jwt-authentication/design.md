# Design Document: JWT Authentication System

## Overview

This design document outlines the implementation of a minimal authentication system for the existing Rust/Poem/OpenAPI application. The system provides JWT-based authentication with refresh token support, focusing solely on authentication without storing user profile data beyond GUIDs and credentials.

### Technology Stack
- **Framework**: Poem (async web framework)
- **API Documentation**: poem-openapi with Swagger UI
- **JWT Library**: jsonwebtoken
- **Password Hashing**: argon2
- **Database**: SQLite (via SeaORM)
- **ORM**: SeaORM (async ORM with migration support)
- **Async Runtime**: Tokio

## Architecture

### High-Level Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ├─── POST /api/auth/login (username, password)
       │    └──> Returns: JWT + Refresh Token
       │
       ├─── POST /api/auth/refresh (refresh_token)
       │    └──> Returns: New JWT
       │
       ├─── GET /api/auth/whoami (Authorization: Bearer JWT)
       │    └──> Returns: User GUID + expiration
       │
       └─── POST /api/auth/logout (refresh_token)
            └──> Returns: Success
       
┌──────────────────────────────────────────┐
│         Auth System Components           │
├──────────────────────────────────────────┤
│  ┌────────────────────────────────────┐  │
│  │      AuthApi (Endpoints)           │  │
│  └────────────┬───────────────────────┘  │
│               │                           │
│  ┌────────────▼───────────────────────┐  │
│  │      AuthService (Business Logic)  │  │
│  └────────────┬───────────────────────┘  │
│               │                           │
│  ┌────────────▼───────────────────────┐  │
│  │   TokenManager (JWT Operations)    │  │
│  └────────────────────────────────────┘  │
│               │                           │
│  ┌────────────▼───────────────────────┐  │
│  │  CredentialStore (Storage Layer)   │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

### Component Responsibilities

1. **AuthApi**: HTTP endpoint handlers, request/response mapping
2. **AuthService**: Business logic for authentication operations
3. **TokenManager**: JWT generation, validation, and refresh token management
4. **CredentialStore**: Storage and retrieval of user credentials and refresh tokens

## Components and Interfaces

### 1. Data Models (src/auth/models.rs)

```rust
// Request Models
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub struct RefreshRequest {
    pub refresh_token: String,
}

pub struct LogoutRequest {
    pub refresh_token: String,
}

// Response Models
pub struct TokenResponse {
    pub access_token: String,      // JWT
    pub refresh_token: String,      // Refresh token
    pub token_type: String,         // "Bearer"
    pub expires_in: i64,            // Seconds until JWT expires
}

pub struct RefreshResponse {
    pub access_token: String,       // New JWT
    pub token_type: String,         // "Bearer"
    pub expires_in: i64,            // Seconds until JWT expires
}

pub struct WhoAmIResponse {
    pub user_id: String,            // User GUID
    pub expires_at: i64,            // Unix timestamp
}

pub struct LogoutResponse {
    pub message: String,
}

// Internal Models
pub struct User {
    pub id: Uuid,                   // User GUID
    pub username: String,
    pub password_hash: String,      // Argon2 hash
}

pub struct RefreshTokenData {
    pub token_hash: String,         // SHA-256 hash of refresh token
    pub user_id: Uuid,
    pub expires_at: i64,            // Unix timestamp
}

pub struct Claims {
    pub sub: String,                // Subject (user_id)
    pub exp: i64,                   // Expiration time
    pub iat: i64,                   // Issued at
}
```

### 2. TokenManager (src/auth/token_manager.rs)

**Responsibilities:**
- Generate and validate JWTs
- Generate cryptographically secure refresh tokens
- Manage token expiration times

**Interface:**
```rust
pub struct TokenManager {
    jwt_secret: String,
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
}

impl TokenManager {
    pub fn new(jwt_secret: String) -> Self;
    
    pub fn generate_jwt(&self, user_id: &Uuid) -> Result<String, TokenError>;
    
    pub fn validate_jwt(&self, token: &str) -> Result<Claims, TokenError>;
    
    pub fn generate_refresh_token(&self) -> String;
    
    pub fn hash_refresh_token(&self, token: &str) -> String;
    
    pub fn get_refresh_expiration(&self) -> i64;
}
```

**Implementation Details:**
- JWT signing algorithm: HS256
- JWT expiration: 15 minutes (900 seconds)
- Refresh token expiration: 7 days (604800 seconds)
- Refresh token generation: 32 random bytes, base64-encoded
- Refresh token hashing: SHA-256

### 3. Database Models (src/auth/entities/)

**SeaORM Entity Definitions:**

```rust
// src/auth/entities/user.rs
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub username: String,
    pub password_hash: String,
    pub created_at: i64,
}

// src/auth/entities/refresh_token.rs
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub token_hash: String,
    pub user_id: Uuid,
    pub expires_at: i64,
    pub created_at: i64,
}
```

### 4. CredentialStore (src/auth/credential_store.rs)

**Responsibilities:**
- Store and retrieve user credentials from database
- Store and validate refresh tokens in database
- Manage database connections via SeaORM

**Interface:**
```rust
pub struct CredentialStore {
    db: DatabaseConnection,
}

impl CredentialStore {
    pub fn new(db: DatabaseConnection) -> Self;
    
    pub async fn verify_credentials(&self, username: &str, password: &str) 
        -> Result<Uuid, AuthError>;
    
    pub async fn store_refresh_token(&self, token_hash: String, user_id: Uuid, expires_at: i64) 
        -> Result<(), AuthError>;
    
    pub async fn validate_refresh_token(&self, token_hash: &str) 
        -> Result<Uuid, AuthError>;
    
    pub async fn revoke_refresh_token(&self, token_hash: &str) 
        -> Result<(), AuthError>;
    
    pub async fn add_user(&self, username: String, password: String) 
        -> Result<Uuid, AuthError>;
    
    pub async fn cleanup_expired_tokens(&self) 
        -> Result<u64, AuthError>;
}
```

**Implementation Details:**
- Database operations using SeaORM's ActiveModel pattern
- Password hashing using Argon2id with default parameters
- Automatic cleanup of expired refresh tokens via periodic task
- Database transactions for token operations
- Indexes on username and token_hash for fast lookups

### 5. AuthService (src/auth/service.rs)

**Responsibilities:**
- Orchestrate authentication operations
- Coordinate between TokenManager and CredentialStore
- Implement business logic for login, refresh, logout

**Interface:**
```rust
pub struct AuthService {
    token_manager: Arc<TokenManager>,
    credential_store: Arc<CredentialStore>,
}

impl AuthService {
    pub fn new(token_manager: Arc<TokenManager>, credential_store: Arc<CredentialStore>) -> Self;
    
    pub async fn login(&self, username: &str, password: &str) 
        -> Result<TokenResponse, AuthError>;
    
    pub async fn refresh(&self, refresh_token: &str) 
        -> Result<RefreshResponse, AuthError>;
    
    pub async fn whoami(&self, jwt: &str) 
        -> Result<WhoAmIResponse, AuthError>;
    
    pub async fn logout(&self, refresh_token: &str) 
        -> Result<LogoutResponse, AuthError>;
}
```

### 6. AuthApi (src/auth/api.rs)

**Responsibilities:**
- Define HTTP endpoints using poem-openapi
- Handle request/response serialization
- Extract and validate authentication headers
- Map service errors to HTTP responses

**Endpoints:**
```rust
#[OpenApi]
impl AuthApi {
    #[oai(path = "/auth/login", method = "post")]
    async fn login(&self, body: Json<LoginRequest>) -> Result<Json<TokenResponse>>;
    
    #[oai(path = "/auth/refresh", method = "post")]
    async fn refresh(&self, body: Json<RefreshRequest>) -> Result<Json<RefreshResponse>>;
    
    #[oai(path = "/auth/whoami", method = "get")]
    async fn whoami(&self, authorization: Header<String>) -> Result<Json<WhoAmIResponse>>;
    
    #[oai(path = "/auth/logout", method = "post")]
    async fn logout(&self, body: Json<LogoutRequest>) -> Result<Json<LogoutResponse>>;
}
```

## Data Models

### JWT Claims Structure
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iat": 1699564800,
  "exp": 1699565700
}
```

### Token Response Structure
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a8f5f167f44f4964e6c998dee827110c",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### WhoAmI Response Structure
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": 1699565700
}
```

## Error Handling

### Error Types

```rust
pub enum AuthError {
    InvalidCredentials,
    InvalidToken,
    ExpiredToken,
    InvalidRefreshToken,
    ExpiredRefreshToken,
    MissingAuthHeader,
    InvalidAuthHeader,
    InternalError(String),
}
```

### HTTP Status Code Mapping

| Error Type | HTTP Status | Error Code | Message |
|------------|-------------|------------|---------|
| InvalidCredentials | 401 | "invalid_credentials" | "Invalid username or password" |
| InvalidToken | 401 | "invalid_token" | "Invalid or malformed JWT" |
| ExpiredToken | 401 | "expired_token" | "JWT has expired" |
| InvalidRefreshToken | 401 | "invalid_refresh_token" | "Invalid refresh token" |
| ExpiredRefreshToken | 401 | "expired_refresh_token" | "Refresh token has expired" |
| MissingAuthHeader | 401 | "missing_auth_header" | "Authorization header is required" |
| InvalidAuthHeader | 401 | "invalid_auth_header" | "Invalid Authorization header format" |
| InternalError | 500 | "internal_error" | "An internal error occurred" |

### Error Response Format

```rust
pub struct AuthErrorResponse {
    pub error: String,
    pub message: String,
    pub status_code: u16,
}
```

## Security Considerations

### Password Security
- Use Argon2id for password hashing (memory-hard, resistant to GPU attacks)
- Default Argon2 parameters provide strong security
- Passwords never stored in plaintext or logged

### Token Security
- JWT secret must be at least 256 bits (32 bytes)
- JWT secret loaded from environment variable
- Refresh tokens generated using cryptographically secure random number generator
- Refresh tokens hashed (SHA-256) before storage
- Tokens transmitted only over HTTPS in production

### Timing Attack Prevention
- Use constant-time comparison for password verification (built into Argon2)
- Use constant-time comparison for token validation where applicable

### Token Expiration
- Short-lived JWTs (15 minutes) limit exposure window
- Refresh tokens expire after 7 days
- Expired refresh tokens automatically cleaned up

## Database Schema

### Migrations

SeaORM migrations will be created to define the schema:

**Migration 1: Create Users Table**
```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_users_username ON users(username);
```

**Migration 2: Create Refresh Tokens Table**
```sql
CREATE TABLE refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
```

## Configuration

### Environment Variables

```
DATABASE_URL=sqlite://auth.db?mode=rwc  # SQLite database file path
JWT_SECRET=<256-bit-secret-key>         # Required, minimum 32 characters
JWT_EXPIRATION_MINUTES=15               # Optional, default: 15
REFRESH_EXPIRATION_DAYS=7               # Optional, default: 7
```

### Initialization

```rust
// In main.rs
use sea_orm::{Database, DatabaseConnection};

// Connect to database
let database_url = std::env::var("DATABASE_URL")
    .unwrap_or_else(|_| "sqlite://auth.db?mode=rwc".to_string());
let db: DatabaseConnection = Database::connect(&database_url).await?;

// Run migrations
Migrator::up(&db, None).await?;

// Initialize components
let jwt_secret = std::env::var("JWT_SECRET")
    .expect("JWT_SECRET must be set");

let token_manager = Arc::new(TokenManager::new(jwt_secret));
let credential_store = Arc::new(CredentialStore::new(db));

// Seed with test user (only if not exists)
let _ = credential_store.add_user("testuser".to_string(), "testpass".to_string()).await;

let auth_service = Arc::new(AuthService::new(token_manager, credential_store));
let auth_api = AuthApi::new(auth_service);

// Start background task for token cleanup
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
    loop {
        interval.tick().await;
        let _ = credential_store.cleanup_expired_tokens().await;
    }
});
```

## Testing Strategy

### Unit Tests

1. **TokenManager Tests**
   - JWT generation produces valid tokens
   - JWT validation correctly verifies signatures
   - JWT validation detects expired tokens
   - Refresh token generation produces unique values
   - Token hashing produces consistent results

2. **CredentialStore Tests**
   - User creation stores credentials in database correctly
   - Password verification succeeds with correct password
   - Password verification fails with incorrect password
   - Refresh token storage and retrieval works correctly with database
   - Refresh token revocation removes tokens from database
   - Expired token cleanup removes expired tokens from database
   - Database transactions maintain consistency

3. **AuthService Tests**
   - Login with valid credentials returns token pair
   - Login with invalid credentials returns error
   - Refresh with valid token returns new JWT
   - Refresh with invalid token returns error
   - WhoAmI with valid JWT returns user info
   - WhoAmI with invalid JWT returns error
   - Logout revokes refresh token

### Integration Tests

1. **End-to-End Authentication Flow**
   - Complete login → use JWT → refresh → use new JWT → logout flow
   - Verify JWT cannot be used after expiration
   - Verify refresh token cannot be used after logout
   - Verify refresh token cannot be used after expiration

2. **API Endpoint Tests**
   - POST /auth/login with valid credentials returns 200
   - POST /auth/login with invalid credentials returns 401
   - POST /auth/refresh with valid token returns 200
   - POST /auth/refresh with invalid token returns 401
   - GET /auth/whoami with valid JWT returns 200
   - GET /auth/whoami without auth header returns 401
   - POST /auth/logout with valid token returns 200

### Test Data

- Test user: username="testuser", password="testpass"
- Test JWT secret: "test-secret-key-minimum-32-characters-long"

## File Structure

```
src/
├── main.rs                      # Application entry point, server setup
├── api.rs                       # Existing API endpoints
├── models.rs                    # Existing models
└── auth/
    ├── mod.rs                   # Auth module exports
    ├── models.rs                # Auth-specific request/response models
    ├── api.rs                   # Auth API endpoints
    ├── service.rs               # Auth business logic
    ├── token_manager.rs         # JWT and refresh token operations
    ├── credential_store.rs      # Database operations for users and tokens
    ├── errors.rs                # Auth error types and conversions
    └── entities/
        ├── mod.rs               # Entity module exports
        ├── user.rs              # User entity (SeaORM model)
        └── refresh_token.rs     # RefreshToken entity (SeaORM model)

migration/
├── src/
│   ├── lib.rs                   # Migration module
│   ├── m20240101_000001_create_users.rs
│   └── m20240101_000002_create_refresh_tokens.rs
└── Cargo.toml                   # Migration crate dependencies
```

## Dependencies to Add

```toml
[dependencies]
jsonwebtoken = "9.2"
argon2 = "0.5"
rand = "0.8"
sha2 = "0.10"
base64 = "0.21"
sea-orm = { version = "0.12", features = ["sqlx-sqlite", "runtime-tokio-native-tls", "macros"] }

[dev-dependencies]
sea-orm-migration = "0.12"
```

## Integration with Existing Application

The authentication system will be integrated into the existing Poem application as follows:

1. Create new `auth` module alongside existing modules
2. Register AuthApi with OpenApiService in main.rs
3. Auth endpoints will appear under `/api/auth/*`
4. Auth endpoints will be documented in Swagger UI
5. Existing endpoints remain unchanged
6. Future: Add authentication middleware to protect existing endpoints

## Database Performance Considerations

### Indexes
- `username` index on users table for fast login lookups
- `token_hash` index on refresh_tokens table for fast validation
- `expires_at` index on refresh_tokens table for efficient cleanup queries

### Connection Pooling
- SeaORM handles connection pooling automatically
- SQLite supports multiple readers, single writer
- For high concurrency, consider PostgreSQL migration path

### Cleanup Strategy
- Background task runs hourly to remove expired tokens
- Cleanup query: `DELETE FROM refresh_tokens WHERE expires_at < current_timestamp`
- Prevents unbounded table growth

## Migration Path to PostgreSQL

If scaling requires PostgreSQL:
1. Change `DATABASE_URL` to PostgreSQL connection string
2. Update SeaORM feature: `sqlx-postgres` instead of `sqlx-sqlite`
3. Migrations remain largely the same (SeaORM abstracts differences)
4. Update UUID handling (PostgreSQL has native UUID type)

## Future Enhancements (Out of Scope)

- Token rotation (issue new refresh token on each refresh)
- Multi-device session management
- Rate limiting on login attempts
- Password reset functionality
- OAuth2/OIDC integration
- Refresh token families for enhanced security
- Audit logging for authentication events
- User registration endpoint

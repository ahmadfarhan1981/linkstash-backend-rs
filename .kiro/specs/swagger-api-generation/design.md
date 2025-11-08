# Design Document

## Overview

This design implements automatic Swagger UI generation for a Rust web backend using the Poem web framework and its `poem-openapi` crate. The solution provides compile-time type safety while automatically generating OpenAPI 3.0 specifications and serving an interactive Swagger UI interface.

**Key Design Decisions:**
- **Poem + poem-openapi**: Chosen for its excellent OpenAPI integration, type-safe API definitions, and automatic schema generation from Rust types
- **Compile-time generation**: OpenAPI schemas are generated at compile time, ensuring documentation always matches the code
- **Macro-based API definitions**: Using `#[OpenApi]` and endpoint macros for clean, declarative API definitions

## Architecture

### High-Level Architecture

```
┌─────────────────┐
│   HTTP Client   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│      Poem HTTP Server           │
│  ┌───────────────────────────┐  │
│  │   OpenAPI Service         │  │
│  │  - API Endpoints          │  │
│  │  - Schema Generation      │  │
│  └───────────┬───────────────┘  │
│              │                   │
│  ┌───────────▼───────────────┐  │
│  │   Swagger UI Route        │  │
│  │  - Serves UI Assets       │  │
│  │  - Loads OpenAPI Spec     │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

### Request Flow

1. Client requests API endpoint → Poem routes to OpenAPI handler → Handler processes request → Response with auto-generated schema
2. Client requests `/swagger` → Poem serves Swagger UI → UI loads OpenAPI spec → Interactive documentation displayed

## Components and Interfaces

### 1. Main Application (`main.rs`)

**Responsibility**: Application entry point, server configuration, and route composition

```rust
// Pseudo-code structure
fn main() {
    // Create OpenAPI service with endpoints
    let api_service = OpenApiService::new(Api, "API Title", "1.0")
        .server("http://localhost:3000");
    
    // Create Swagger UI
    let ui = api_service.swagger_ui();
    
    // Compose routes
    let app = Route::new()
        .nest("/api", api_service)
        .nest("/swagger", ui);
    
    // Start server
    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await;
}
```

### 2. API Service (`api.rs`)

**Responsibility**: Define API structure and group endpoints

```rust
// Pseudo-code structure
struct Api;

#[OpenApi]
impl Api {
    // Endpoint definitions go here
    // Each endpoint is a method with OpenAPI attributes
}
```

### 3. API Endpoints

**Responsibility**: Handle HTTP requests with automatic OpenAPI documentation

**Example GET Endpoint:**
```rust
#[oai(path = "/health", method = "get")]
async fn health(&self) -> Json<HealthResponse> {
    // Implementation
}
```

**Example POST Endpoint:**
```rust
#[oai(path = "/items", method = "post")]
async fn create_item(&self, body: Json<CreateItemRequest>) -> Result<Json<Item>> {
    // Implementation with validation
}
```

### 4. Data Models (`models.rs`)

**Responsibility**: Define request/response schemas with OpenAPI attributes

```rust
// Pseudo-code structure
#[derive(Object)]
struct CreateItemRequest {
    #[oai(validator(min_length = 1, max_length = 100))]
    name: String,
    description: Option<String>,
}

#[derive(Object)]
struct Item {
    id: String,
    name: String,
    description: Option<String>,
    created_at: String,
}
```

## Data Models

### Core Types

All data models will derive `poem_openapi::Object` to enable automatic schema generation:

- **Request DTOs**: Input validation with `#[oai(validator(...))]` attributes
- **Response DTOs**: Output schemas with proper field documentation
- **Error Responses**: Standardized error format with status codes

### Validation

Poem-openapi provides built-in validators:
- String length: `min_length`, `max_length`
- Numeric ranges: `minimum`, `maximum`
- Pattern matching: `pattern`
- Custom validators: Implement `Validator` trait

## Error Handling

### Error Response Strategy

1. **Standard Error Format**: All errors return consistent JSON structure
2. **HTTP Status Codes**: Proper status codes (400, 404, 500, etc.)
3. **OpenAPI Documentation**: Error responses documented in schema

```rust
// Pseudo-code structure
#[derive(Object)]
struct ErrorResponse {
    error: String,
    message: String,
    status_code: u16,
}

// Endpoints return Result types
async fn endpoint() -> Result<Json<Response>, Error> {
    // Error handling with proper status codes
}
```

### Error Types

- **Validation Errors**: 400 Bad Request - Invalid input data
- **Not Found**: 404 Not Found - Resource doesn't exist
- **Server Errors**: 500 Internal Server Error - Unexpected failures

## Testing Strategy

### Unit Tests

- Test individual endpoint handlers with mock data
- Validate request/response serialization
- Test validation rules on data models

### Integration Tests

- Test full HTTP request/response cycle
- Verify OpenAPI spec generation
- Confirm Swagger UI accessibility

### Manual Testing

- Access Swagger UI in browser
- Test API endpoints through Swagger UI interface
- Verify documentation accuracy

## Dependencies

### Required Crates

```toml
[dependencies]
poem = "2.0"
poem-openapi = "4.0"
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

### Development Dependencies

```toml
[dev-dependencies]
poem = { version = "2.0", features = ["test"] }
```

## Configuration

### Server Configuration

- **Host**: 0.0.0.0 (all interfaces)
- **Port**: 3000 (configurable via environment variable)
- **Swagger UI Path**: `/swagger`
- **API Base Path**: `/api`

### OpenAPI Metadata

- **Title**: Configurable application name
- **Version**: Semantic versioning (e.g., "1.0.0")
- **Server URL**: Base URL for API requests

## Deployment Considerations

- Binary compilation produces single executable
- No runtime dependencies for OpenAPI generation (compile-time)
- Swagger UI assets embedded in binary
- Environment variables for configuration (port, host, etc.)

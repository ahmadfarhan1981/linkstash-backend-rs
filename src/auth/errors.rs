use poem_openapi::{payload::Json, ApiResponse, Object};

/// Standardized error response for authentication endpoints
#[derive(Object, Debug)]
pub struct AuthErrorResponse {
    /// Error code identifier
    pub error: String,
    
    /// Human-readable error message
    pub message: String,
    
    /// HTTP status code
    pub status_code: u16,
}

/// Authentication error types
#[derive(ApiResponse, Debug)]
pub enum AuthError {
    /// Invalid username or password
    #[oai(status = 401)]
    InvalidCredentials(Json<AuthErrorResponse>),
    
    /// Username already exists
    #[oai(status = 400)]
    DuplicateUsername(Json<AuthErrorResponse>),
    
    /// Internal server error
    #[oai(status = 500)]
    InternalError(Json<AuthErrorResponse>),
}

impl AuthError {
    /// Create an InvalidCredentials error
    pub fn invalid_credentials() -> Self {
        AuthError::InvalidCredentials(Json(AuthErrorResponse {
            error: "invalid_credentials".to_string(),
            message: "Invalid username or password".to_string(),
            status_code: 401,
        }))
    }
    
    /// Create a DuplicateUsername error
    pub fn duplicate_username() -> Self {
        AuthError::DuplicateUsername(Json(AuthErrorResponse {
            error: "duplicate_username".to_string(),
            message: "Username already exists".to_string(),
            status_code: 400,
        }))
    }
    
    /// Create an InternalError
    pub fn internal_error(message: String) -> Self {
        AuthError::InternalError(Json(AuthErrorResponse {
            error: "internal_error".to_string(),
            message,
            status_code: 500,
        }))
    }
}

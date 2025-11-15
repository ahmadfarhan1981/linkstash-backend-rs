use poem_openapi::{payload::Json, ApiResponse, Object};
use std::fmt;

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
    
    /// Invalid or malformed JWT
    #[oai(status = 401)]
    InvalidToken(Json<AuthErrorResponse>),
    
    /// JWT has expired
    #[oai(status = 401)]
    ExpiredToken(Json<AuthErrorResponse>),
    
    /// Authorization header is missing
    #[oai(status = 401)]
    MissingAuthHeader(Json<AuthErrorResponse>),
    
    /// Authorization header format is invalid
    #[oai(status = 401)]
    InvalidAuthHeader(Json<AuthErrorResponse>),
    
    /// Invalid refresh token
    #[oai(status = 401)]
    InvalidRefreshToken(Json<AuthErrorResponse>),
    
    /// Refresh token has expired
    #[oai(status = 401)]
    ExpiredRefreshToken(Json<AuthErrorResponse>),
    
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
    
    /// Create an InvalidToken error
    pub fn invalid_token() -> Self {
        AuthError::InvalidToken(Json(AuthErrorResponse {
            error: "invalid_token".to_string(),
            message: "Invalid or malformed JWT".to_string(),
            status_code: 401,
        }))
    }
    
    /// Create an ExpiredToken error
    pub fn expired_token() -> Self {
        AuthError::ExpiredToken(Json(AuthErrorResponse {
            error: "expired_token".to_string(),
            message: "JWT has expired".to_string(),
            status_code: 401,
        }))
    }
    
    /// Create a MissingAuthHeader error
    pub fn missing_auth_header() -> Self {
        AuthError::MissingAuthHeader(Json(AuthErrorResponse {
            error: "missing_auth_header".to_string(),
            message: "Authorization header is required".to_string(),
            status_code: 401,
        }))
    }
    
    /// Create an InvalidAuthHeader error
    pub fn invalid_auth_header() -> Self {
        AuthError::InvalidAuthHeader(Json(AuthErrorResponse {
            error: "invalid_auth_header".to_string(),
            message: "Invalid Authorization header format".to_string(),
            status_code: 401,
        }))
    }
    
    /// Create an InvalidRefreshToken error
    pub fn invalid_refresh_token() -> Self {
        AuthError::InvalidRefreshToken(Json(AuthErrorResponse {
            error: "invalid_refresh_token".to_string(),
            message: "Invalid refresh token".to_string(),
            status_code: 401,
        }))
    }
    
    /// Create an ExpiredRefreshToken error
    pub fn expired_refresh_token() -> Self {
        AuthError::ExpiredRefreshToken(Json(AuthErrorResponse {
            error: "expired_refresh_token".to_string(),
            message: "Refresh token has expired".to_string(),
            status_code: 401,
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
    
    /// Get the error message from the error variant
    pub fn message(&self) -> String {
        match self {
            AuthError::InvalidCredentials(json) => json.0.message.clone(),
            AuthError::DuplicateUsername(json) => json.0.message.clone(),
            AuthError::InvalidToken(json) => json.0.message.clone(),
            AuthError::ExpiredToken(json) => json.0.message.clone(),
            AuthError::MissingAuthHeader(json) => json.0.message.clone(),
            AuthError::InvalidAuthHeader(json) => json.0.message.clone(),
            AuthError::InvalidRefreshToken(json) => json.0.message.clone(),
            AuthError::ExpiredRefreshToken(json) => json.0.message.clone(),
            AuthError::InternalError(json) => json.0.message.clone(),
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

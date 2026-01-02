use crate::errors::internal::{CredentialError, InternalError};
use poem_openapi::{ApiResponse, Object, payload::Json};
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

    /// Current password is incorrect (for password change)
    #[oai(status = 401)]
    IncorrectPassword(Json<AuthErrorResponse>),

    /// Password validation failed
    #[oai(status = 400)]
    PasswordValidationFailed(Json<AuthErrorResponse>),

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

    /// Password change required - contains RequestContext for allowed endpoints
    #[oai(status = 403)]
    PasswordChangeRequired(Json<AuthErrorResponse>),

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

    /// Create an IncorrectPassword error
    pub fn incorrect_password() -> Self {
        AuthError::IncorrectPassword(Json(AuthErrorResponse {
            error: "incorrect_password".to_string(),
            message: "Current password is incorrect".to_string(),
            status_code: 401,
        }))
    }

    /// Create a PasswordValidationFailed error
    pub fn password_validation_failed(message: String) -> Self {
        AuthError::PasswordValidationFailed(Json(AuthErrorResponse {
            error: "password_validation_failed".to_string(),
            message,
            status_code: 400,
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

    /// Create a PasswordChangeRequired error
    pub fn password_change_required() -> Self {
        AuthError::PasswordChangeRequired(Json(AuthErrorResponse {
            error: "password_change_required".to_string(),
            message:
                "Password change required. Please change your password at /auth/change-password"
                    .to_string(),
            status_code: 403,
        }))
    }

    /// Convert InternalError to AuthError
    ///
    /// This is the explicit conversion point from internal errors to API errors.
    /// Internal error details are logged but not exposed to clients.
    pub fn from_internal_error(err: InternalError) -> Self {
        match &err {
            // Infrastructure errors - always log and return generic error
            // InternalError::Database { operation, .. } => {
            //     tracing::error!("Database error in {}: {}", operation, err);
            //     Self::internal_server_error()
            // }
            // InternalError::Transaction { operation, .. } => {
            //     tracing::error!("Transaction error in {}: {}", operation, err);
            //     Self::internal_server_error()
            // }
            InternalError::Parse { value_type, .. } => {
                tracing::error!("Parse error for {}: {}", value_type, err);
                Self::internal_server_error()
            }
            InternalError::Crypto { operation, .. } => {
                tracing::error!("Crypto error in {}: {}", operation, err);
                Self::internal_server_error()
            }

            // Domain errors - convert to specific API errors
            InternalError::Credential(CredentialError::InvalidCredentials) => {
                tracing::debug!("Invalid credentials attempt");
                Self::invalid_credentials()
            }
            InternalError::Credential(CredentialError::IncorrectPassword) => {
                tracing::debug!("Incorrect password for password change");
                Self::incorrect_password()
            }
            InternalError::Credential(CredentialError::PasswordValidationFailed(message)) => {
                tracing::debug!("Password validation failed: {}", message);
                Self::password_validation_failed(message.clone())
            }
            InternalError::Credential(CredentialError::DuplicateUsername(username)) => {
                tracing::warn!("Duplicate username attempt: {}", username);
                Self::duplicate_username()
            }
            InternalError::Credential(CredentialError::InvalidToken { token_type, reason }) => {
                tracing::debug!("Invalid token: {} - {}", token_type, reason);
                if token_type == "jwt" {
                    Self::invalid_token()
                } else if token_type == "refresh_token" {
                    Self::invalid_refresh_token()
                } else {
                    Self::invalid_token()
                }
            }
            InternalError::Credential(CredentialError::ExpiredToken(token_type)) => {
                tracing::debug!("Expired token: {}", token_type);
                if token_type == "jwt" {
                    Self::expired_token()
                } else if token_type == "refresh_token" {
                    Self::expired_refresh_token()
                } else {
                    Self::expired_token()
                }
            }

            // Other domain errors that shouldn't appear in auth context
            _ => {
                tracing::error!("Unexpected error in auth operation: {}", err);
                Self::internal_server_error()
            }
        }
    }

    /// Create a generic internal server error
    ///
    /// This replaces the old internal_error() method. It always returns
    /// a generic message without exposing internal details.
    fn internal_server_error() -> Self {
        AuthError::InternalError(Json(AuthErrorResponse {
            error: "internal_error".to_string(),
            message: "An internal error occurred".to_string(),
            status_code: 500,
        }))
    }

    /// Get the error message from the error variant
    pub fn message(&self) -> String {
        match self {
            AuthError::InvalidCredentials(json) => json.0.message.clone(),
            AuthError::IncorrectPassword(json) => json.0.message.clone(),
            AuthError::PasswordValidationFailed(json) => json.0.message.clone(),
            AuthError::DuplicateUsername(json) => json.0.message.clone(),
            AuthError::InvalidToken(json) => json.0.message.clone(),
            AuthError::ExpiredToken(json) => json.0.message.clone(),
            AuthError::MissingAuthHeader(json) => json.0.message.clone(),
            AuthError::InvalidAuthHeader(json) => json.0.message.clone(),
            AuthError::InvalidRefreshToken(json) => json.0.message.clone(),
            AuthError::ExpiredRefreshToken(json) => json.0.message.clone(),
            AuthError::PasswordChangeRequired(json) => json.0.message.clone(),
            AuthError::InternalError(json) => json.0.message.clone(),
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

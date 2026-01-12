use poem_openapi::{ApiResponse, Object};
use serde::{Deserialize, Serialize};

/// Request model for user login
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Username for authentication
    pub username: String,

    /// Password for authentication
    pub password: String,
}

/// Response model containing authentication tokens
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    /// JWT access token for API authentication
    pub access_token: String,

    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Number of seconds until the access token expires
    pub expires_in: i64,
}

/// Response model for whoami endpoint
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct WhoAmIResponse {
    /// User ID (UUID)
    pub user_id: String,

    /// Token expiration time (Unix timestamp)
    pub expires_at: i64,
}

/// Request model for token refresh
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// Refresh token to exchange for a new access token
    pub refresh_token: String,
}

/// Response model for token refresh
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct RefreshResponse {
    /// New JWT access token for API authentication
    pub access_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Number of seconds until the access token expires
    pub expires_in: i64,
}

/// Request model for logout
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct LogoutRequest {
    /// Refresh token to revoke
    pub refresh_token: String,
}

/// Response model for logout
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Success message
    pub message: String,
}

/// API response for login endpoint
#[derive(ApiResponse)]
pub enum LoginApiResponse {
    /// Authentication successful, tokens provided
    #[oai(status = 200)]
    Ok(Json<TokenResponse>),

    /// Invalid username or password
    #[oai(status = 401)]
    Unauthorized(Json<ErrorResponse>),
}

/// API response for whoami endpoint
#[derive(ApiResponse)]
pub enum WhoAmIApiResponse {
    /// User information retrieved
    #[oai(status = 200)]
    Ok(Json<WhoAmIResponse>),

    /// Invalid or expired JWT token
    #[oai(status = 401)]
    Unauthorized(Json<ErrorResponse>),
}

/// API response for refresh endpoint
#[derive(ApiResponse)]
pub enum RefreshApiResponse {
    /// New access token issued
    #[oai(status = 200)]
    Ok(Json<RefreshResponse>),

    /// Invalid or expired refresh token
    #[oai(status = 401)]
    Unauthorized(Json<ErrorResponse>),
}

/// API response for logout endpoint
#[derive(ApiResponse)]
pub enum LogoutApiResponse {
    /// Logout successful, session terminated
    #[oai(status = 200)]
    Ok(Json<LogoutResponse>),

    /// Invalid JWT token
    #[oai(status = 401)]
    Unauthorized(Json<ErrorResponse>),
}

/// Request model for password change
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    /// Current password for verification
    pub old_password: String,

    /// New password to set
    pub new_password: String,
}

/// Response model for password change
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ChangePasswordResponse {
    /// Success message
    pub message: String,

    /// New JWT access token for API authentication
    pub access_token: String,

    /// New refresh token for obtaining new access tokens
    pub refresh_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Number of seconds until the access token expires
    pub expires_in: i64,
}

/// API response for change password endpoint
#[derive(ApiResponse)]
pub enum ChangePasswordApiResponse {
    /// Password changed successfully, new tokens provided
    #[oai(status = 200)]
    Ok(Json<ChangePasswordResponse>),

    /// Invalid current password or validation failed
    #[oai(status = 401)]
    Unauthorized(Json<ErrorResponse>),

    /// Password validation failed
    #[oai(status = 400)]
    BadRequest(Json<ErrorResponse>),
}


use poem_openapi::payload::Json;

use crate::types::dto::common::ErrorResponse;


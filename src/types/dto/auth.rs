use poem_openapi::Object;
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

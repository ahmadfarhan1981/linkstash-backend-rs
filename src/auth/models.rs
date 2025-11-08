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
